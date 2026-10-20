import json
import sys
from datetime import timedelta

from hunter.config import ALERT_WEBHOOK_MIN_PROBABILITY, Config, smart_analysis_enabled
from hunter.db import Database, utcnow
from hunter.fixtures_io import load_fixture
from hunter.investigate import build_evidence, drain_investigations, drain_analyst, should_investigate
from hunter.models import Classification
from hunter.service import classify_job
from hunter.webhook import (
    DISCORD_SLACK_TEXT_LIMIT,
    build_analysis_payload,
    drain_outbox,
    enqueue_analysis,
    enqueue_classification,
    parse_verdict,
    should_deliver_analysis,
    should_notify,
    slack_analysis_text,
    slack_text,
)
from pathlib import Path
from hunter.fake_jev import KeywordJev


ROOT = Path(__file__).resolve().parents[1] / "fixtures"


class MemoryLoader:
    def __init__(self, meta, old_files, new_files):
        self.meta = meta
        self.old_files = old_files
        self.new_files = new_files

    def load(self, ecosystem, name, version, rank):
        return self.old_files, self.new_files, self.meta


def _command_runner(text: str):
    return Config(
        investigate_command=f"{sys.executable} -c \"import sys; sys.stdout.write('{text}')\"",
    )


def test_should_investigate_covers_alert_and_all_reviews():
    from hunter.models import Classification

    alert = Classification(
        ecosystem="npm",
        name="a",
        old_version="0",
        new_version="1",
        rank=1,
        registry_url="",
        band="alert",
        malice_probability=0.9,
        jev_model_id="jev-1.13.0",
    )
    review = Classification(
        ecosystem="npm",
        name="b",
        old_version="0",
        new_version="1",
        rank=1,
        registry_url="",
        band="review",
        malice_probability=0.42,
        jev_model_id="jev-1.13.0",
    )
    benign = Classification(
        ecosystem="npm",
        name="c",
        old_version="0",
        new_version="1",
        rank=1,
        registry_url="",
        band="benign",
        malice_probability=0.02,
        jev_model_id="jev-1.13.0",
    )
    assert should_investigate(alert)
    assert should_investigate(review)
    assert not should_investigate(benign)


def test_alert_sends_primary_webhook_and_enqueues_smart_analysis(tmp_path, monkeypatch):
    monkeypatch.setenv("TYPESAFE_API_KEY", "super-secret-key")
    meta, old_files, new_files, _label = load_fixture(ROOT / "npm_child_dropper.json")
    db = Database(tmp_path / "hunter.sqlite3")
    posts = []
    config = Config(
        db_path=db.path,
        webhook_url="https://alerts.example/hook",
        webhook_secret="alert-secret",
        inspect_dependencies=False,
        investigate_command=f"{sys.executable} -c \"import sys; sys.stdout.write('Verdict: malicious')\"",
        analyst_command=f"{sys.executable} -c \"import sys; sys.stdout.write('Verdict: malicious')\"",
    )
    assert smart_analysis_enabled(config)
    assert db.enqueue_job(meta.ecosystem, meta.name, meta.new_version, meta.rank)
    classify_job(
        db,
        config,
        db.pending_jobs()[0],
        jev=KeywordJev(),
        loader=MemoryLoader(meta, old_files, new_files),
    )
    assert db.investigation_depth() == 1
    assert drain_investigations(
        db,
        config=config,
        webhook_url=config.webhook_url,
        webhook_secret=config.webhook_secret,
    ) == 1
    assert db.due_outbox() == []
    assert drain_analyst(db, config=config) == 1
    assert drain_outbox(
        db,
        url=config.webhook_url,
        secret=config.webhook_secret,
        poster=lambda *args: posts.append(args),
    ) == 1
    assert len(posts) == 1
    payloads = [json.loads(body) for _url, body, _headers in posts]
    kinds = {item.get("kind") for item in payloads}
    assert kinds == {"smart_analysis"}
    analysis = payloads[0]
    assert analysis["primary_band"] == "alert"
    assert analysis["verdict"] == "malicious"
    assert analysis["idempotency_key"].endswith(":analysis")
    assert "Verdict: malicious" in analysis["analysis"]
    report = db.investigation_report(f"npm:{meta.name}:{meta.new_version}")
    assert "Verdict: malicious" in report
    assert "super-secret-key" not in report


def _run_review(tmp_path, verdict_line: str):
    meta, old_files, new_files, _label = load_fixture(ROOT / "npm_phantom_manifest.json")
    db = Database(tmp_path / "hunter.sqlite3")
    posts = []
    config = Config(
        db_path=db.path,
        webhook_url="https://alerts.example/hook",
        webhook_secret="alert-secret",
        inspect_dependencies=False,
        investigate_command=f"{sys.executable} -c \"import sys; sys.stdout.write('{verdict_line}')\"",
        analyst_command=f"{sys.executable} -c \"import sys; sys.stdout.write('Verdict: malicious')\"",
    )
    assert db.enqueue_job(meta.ecosystem, meta.name, meta.new_version, meta.rank)
    classify_job(
        db,
        config,
        db.pending_jobs()[0],
        jev=KeywordJev(),
        loader=MemoryLoader(meta, old_files, new_files),
    )
    assert db.due_outbox() == []
    assert db.investigation_depth() == 1
    assert drain_investigations(db, config=config) == 1
    drain_analyst(db, config=config)
    sent = drain_outbox(
        db,
        url=config.webhook_url,
        secret=config.webhook_secret,
        poster=lambda *args: posts.append(args),
    )
    stored = db._conn.execute(
        "SELECT body FROM investigations WHERE idempotency_key = ?",
        (f"npm:{meta.name}:{meta.new_version}",),
    ).fetchone()
    evidence = json.loads(stored["body"])
    report = db.investigation_report(f"npm:{meta.name}:{meta.new_version}")
    return posts, sent, evidence, report


def test_review_uncertain_stores_report_and_skips_discord(tmp_path):
    posts, sent, evidence, report = _run_review(tmp_path, "Verdict: uncertain")
    assert sent == 0
    assert posts == []
    assert report == "Verdict: uncertain"
    assert evidence["primary_band"] == "review"
    assert "SOP bar" in evidence["task"]
    assert "not sent onward" in evidence["task"]


def test_review_benign_verdict_does_not_discord(tmp_path):
    posts, sent, _evidence, report = _run_review(tmp_path, "Verdict: benign")
    assert sent == 0
    assert posts == []
    assert report == "Verdict: benign"


def test_review_malicious_verdict_posts_analysis(tmp_path):
    posts, sent, evidence, report = _run_review(tmp_path, "Verdict: malicious")
    assert sent == 1
    assert len(posts) == 1
    payload = json.loads(posts[0][1])
    assert payload["kind"] == "smart_analysis"
    assert payload["primary_band"] == "review"
    assert payload["verdict"] == "malicious"
    assert evidence["primary_band"] == "review"
    assert "Verdict: malicious" in report


def test_benign_does_not_investigate_or_webhook(tmp_path):
    meta, old_files, new_files, _label = load_fixture(ROOT / "npm_benign_import.json")
    db = Database(tmp_path / "hunter.sqlite3")
    config = Config(
        db_path=db.path,
        webhook_url="https://alerts.example/hook",
        investigate_command=f"{sys.executable} -c \"import sys; sys.stdout.write('noop')\"",
    )
    assert db.enqueue_job(meta.ecosystem, meta.name, meta.new_version, meta.rank)
    classify_job(
        db,
        config,
        db.pending_jobs()[0],
        jev=KeywordJev(),
        loader=MemoryLoader(meta, old_files, new_files),
    )
    assert db.investigation_depth() == 0
    assert db.due_outbox() == []


def test_investigation_retries_then_stores_the_report(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    when = utcnow().replace(microsecond=0)
    evidence = build_evidence(
        __import__("hunter.models", fromlist=["Classification"]).Classification(
            ecosystem="npm",
            name="widget",
            old_version="1",
            new_version="2",
            rank=1,
            registry_url="",
            band="alert",
            malice_probability=0.9,
            jev_model_id="jev-1.13.0",
            pass_d_ran=True,
        )
    )
    assert db.enqueue_investigation(evidence["idempotency_key"], json.dumps(evidence), when=when)
    calls = {"n": 0}

    def runner(_command, _body):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("analyst down")
        return "Verdict: benign\nLooks clean."

    config = Config(webhook_url="https://alerts.example/hook")
    assert drain_investigations(db, config=config, runner=runner, when=when) == 0
    assert db.due_investigations(when) == []
    later = when + timedelta(seconds=1)
    assert drain_investigations(db, config=config, runner=runner, when=later) == 1
    assert db.investigation_report("npm:widget:2") == "Verdict: benign\nLooks clean."
    assert db.due_outbox(later) == []


def _review_finding():
    return Classification(
        ecosystem="npm",
        name="widget",
        old_version="1",
        new_version="2",
        rank=1,
        registry_url="",
        band="review",
        malice_probability=0.5,
        jev_model_id="jev-1.13.0",
        pass_d_ran=True,
    )


def test_prompt_keeps_the_short_excerpt_and_points_at_the_diff_file():
    from hunter.investigate import build_analyst_prompt, build_triage_prompt

    evidence = build_evidence(
        _review_finding(),
        "opening summary only",
        manifest="[changed_files]\ncounts: added=0 deleted=0 modified=1 included=0 dropped=1\nmodified dropped README.md (docs)",
        full_diff="FULL_DIFF_SENTINEL\n" + ("x" * 50),
    )
    triage = build_triage_prompt(evidence, config=Config(db_path=":memory:"))
    analyst = build_analyst_prompt(evidence, config=Config(db_path=":memory:"))
    for prompt in (triage, analyst):
        assert prompt.find("Changed-file manifest") < prompt.find("Evidence JSON")
        assert "modified dropped README.md (docs)" in prompt
        assert "filtered-diff.txt" in prompt
        assert "opening summary only" in prompt
        assert "FULL_DIFF_SENTINEL" not in prompt
    assert len(evidence["diff_excerpt"]) <= 12_000


def test_cursor_agent_reads_full_diff_and_the_temp_dir_is_removed(monkeypatch):
    from hunter.investigate import run_smart_analysis

    seen = {}

    def fake_run(argv, **kwargs):
        cwd = Path(kwargs["cwd"])
        seen["cwd"] = cwd
        seen["argv"] = list(argv)
        seen["prompt"] = (cwd / "analysis-prompt.txt").read_text(encoding="utf-8")
        seen["text"] = (cwd / "filtered-diff.txt").read_text(encoding="utf-8")
        seen["existed"] = True

        class Result:
            returncode = 0
            stdout = b"Verdict: benign"
            stderr = b""

        return Result()

    monkeypatch.setattr("hunter.investigate.subprocess.run", fake_run)
    evidence = build_evidence(
        _review_finding(),
        "opening summary only",
        manifest="[changed_files]\ncounts: added=1 deleted=0 modified=0 included=1 dropped=0\nadded included lib/hook.js (suspicious_source)",
        full_diff="[dependency_delta]\nadded: codec-pad\n[added_file:lib/hook.js]\nexecSync('echo hi')\n",
    )
    text, model = run_smart_analysis(
        evidence,
        config=Config(smart_backend="cursor", smart_model="composer-2.5", investigate_timeout=30),
    )
    assert text == "Verdict: benign"
    assert model == "composer-2.5"
    assert seen["existed"] is True
    assert "execSync('echo hi')" in seen["text"]
    assert "filtered-diff.txt" in seen["prompt"]
    assert "opening summary only" in seen["prompt"]
    assert not seen["cwd"].exists()


def test_cursor_temp_dir_is_removed_when_the_agent_fails(monkeypatch):
    from hunter.investigate import run_analyst_analysis

    seen = {}

    def fake_run(_argv, **kwargs):
        cwd = Path(kwargs["cwd"])
        seen["cwd"] = cwd
        seen["existed"] = (cwd / "filtered-diff.txt").is_file()
        seen["prompt_existed"] = (cwd / "analysis-prompt.txt").is_file()

        class Result:
            returncode = 1
            stdout = b""
            stderr = b"agent failed"

        return Result()

    monkeypatch.setattr("hunter.investigate.subprocess.run", fake_run)
    evidence = build_evidence(
        _review_finding(),
        "opening summary only",
        manifest="[changed_files]\ncounts: added=0 deleted=0 modified=0 included=0 dropped=0",
        full_diff="filtered body\n",
    )
    evidence["triage_report"] = "Verdict: malicious"
    try:
        run_analyst_analysis(
            evidence,
            config=Config(analyst_model="grok-4.7-high", investigate_timeout=30),
        )
    except RuntimeError:
        pass
    else:
        raise AssertionError("agent failure should raise")
    assert seen["existed"] is True
    assert seen["prompt_existed"] is True
    assert not seen["cwd"].exists()


def test_excerpt_aligns_through_archives_when_that_function_exists(monkeypatch):
    from hunter.investigate import excerpt_for, triage_evidence_parts
    from hunter.models import ReleaseMeta

    seen = []

    def fake_align(old, new, **kwargs):
        seen.append(kwargs)
        return old, new

    monkeypatch.setattr("hunter.archives.aligned_release_trees", fake_align, raising=False)
    meta = ReleaseMeta(ecosystem="npm", name="sample", new_version="2", old_version="1")
    old = {"package/lib/hook.js": "exports.value = 1;\n"}
    new = {
        "package/lib/hook.js": "const { execSync } = require('child_process');\nexecSync('echo hi');\n",
    }
    excerpt_for(old, new, meta)
    _excerpt, manifest, _full = triage_evidence_parts(old, new, meta)
    assert len(seen) == 2
    assert seen[0]["ecosystem"] == "npm"
    assert seen[0]["name"] == "sample"
    assert seen[0]["old_version"] == "1"
    assert seen[0]["new_version"] == "2"
    assert "lib/hook.js" in manifest or "package/lib/hook.js" in manifest


def test_classify_job_stores_manifest_and_full_diff(tmp_path):
    from hunter.models import ReleaseMeta

    meta = ReleaseMeta(
        ecosystem="npm",
        name="sample",
        new_version="1.0.1",
        old_version="1.0.0",
        rank=1,
    )
    old_files = {
        "package.json": '{"name":"sample","version":"1.0.0"}\n',
        "README.md": "old notes\n",
        "lib/util.js": "exports.value = 1;\n",
    }
    new_files = {
        "package.json": '{"name":"sample","version":"1.0.1","scripts":{"postinstall":"node lib/hook.js"}}\n',
        "README.md": "new notes\n",
        "lib/util.js": "exports.value = 2;\n",
        "lib/hook.js": "const { execSync } = require('child_process');\nexecSync('echo hi');\n",
    }
    db = Database(tmp_path / "hunter.sqlite3")
    config = Config(
        db_path=db.path,
        inspect_dependencies=False,
        investigate_command=f"{sys.executable} -c \"import sys; sys.stdout.write('Verdict: benign')\"",
    )
    assert db.enqueue_job(meta.ecosystem, meta.name, meta.new_version, meta.rank)
    classify_job(
        db,
        config,
        db.pending_jobs()[0],
        jev=KeywordJev(),
        loader=MemoryLoader(meta, old_files, new_files),
    )
    assert db.investigation_depth() == 1
    stored = db._conn.execute("SELECT body FROM investigations").fetchone()
    evidence = json.loads(stored["body"])
    assert "modified dropped README.md (docs)" in evidence["changed_file_manifest"]
    assert "modified dropped lib/util.js (no suspicious pattern)" in evidence["changed_file_manifest"]
    assert "[added_file:lib/hook.js]" in evidence["full_diff"]
    assert "execSync('echo hi')" in evidence["full_diff"]
    assert len(evidence["diff_excerpt"]) <= 12_000
    assert evidence["diff_excerpt"].find("[dependency_delta]") < evidence["diff_excerpt"].find("package.json")


def test_run_agent_cli_passes_api_key_and_default_model(monkeypatch):
    from hunter.config import DEFAULT_SMART_MODEL
    from hunter.investigate import AGENT_LAUNCH_PROMPT, run_agent_cli

    monkeypatch.setenv("CURSOR_API_KEY", "cursor-test-key")
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = list(argv)
        captured["kwargs"] = kwargs
        captured["body"] = (Path(kwargs["cwd"]) / "analysis-prompt.txt").read_text(encoding="utf-8")

        class Result:
            returncode = 0
            stdout = b"Verdict: benign"
            stderr = b""

        return Result()

    monkeypatch.setattr("hunter.investigate.subprocess.run", fake_run)
    text = run_agent_cli("analyze this", model=DEFAULT_SMART_MODEL, timeout=30)
    assert text == "Verdict: benign"
    assert captured["body"] == "analyze this"
    assert "input" not in captured["kwargs"]
    assert captured["argv"] == [
        "agent",
        "-p",
        AGENT_LAUNCH_PROMPT,
        "--mode",
        "ask",
        "--trust",
        "--output-format",
        "text",
        "--model",
        "composer-2.5",
        "--api-key",
        "cursor-test-key",
    ]


def test_prompt_larger_than_128_kib_is_a_file_not_an_argument(monkeypatch):
    """Linux MAX_ARG_STRLEN is 128 KiB. A longer prompt must not be one argv element."""
    from hunter.investigate import AGENT_LAUNCH_PROMPT, run_agent_cli

    prompt = "BEGIN\n" + ("A" * (128 * 1024)) + "\nEND"
    assert len(prompt.encode("utf-8")) > 128 * 1024
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = list(argv)
        captured["kwargs"] = kwargs
        captured["body"] = (Path(kwargs["cwd"]) / "analysis-prompt.txt").read_bytes()

        class Result:
            returncode = 0
            stdout = b"Verdict: benign"
            stderr = b""

        return Result()

    monkeypatch.setattr("hunter.investigate.subprocess.run", fake_run)
    text = run_agent_cli(prompt, model="grok-4.7-high", timeout=30)
    assert text == "Verdict: benign"
    assert captured["body"] == prompt.encode("utf-8")
    assert "input" not in captured["kwargs"]
    assert AGENT_LAUNCH_PROMPT in captured["argv"]
    assert all(len(item.encode("utf-8")) < 128 * 1024 for item in captured["argv"])


def test_triage_and_analyst_share_the_prompt_file(monkeypatch):
    from hunter.investigate import AGENT_LAUNCH_PROMPT, run_analyst_analysis, run_smart_analysis

    seen = []

    def fake_run(argv, **kwargs):
        cwd = Path(kwargs["cwd"])
        seen.append(
            {
                "argv": list(argv),
                "prompt": (cwd / "analysis-prompt.txt").read_text(encoding="utf-8"),
            }
        )

        class Result:
            returncode = 0
            stdout = b"Verdict: malicious"
            stderr = b""

        return Result()

    monkeypatch.setattr("hunter.investigate.subprocess.run", fake_run)
    evidence = build_evidence(_review_finding(), "opening summary only")
    triage_text, triage_model = run_smart_analysis(
        evidence,
        config=Config(smart_backend="cursor", smart_model="composer-2.5", investigate_timeout=30),
    )
    evidence["triage_report"] = "Verdict: malicious"
    analyst_text, analyst_model = run_analyst_analysis(
        evidence,
        config=Config(analyst_model="grok-4.7-high", investigate_timeout=30),
    )
    assert triage_text == "Verdict: malicious"
    assert analyst_text == "Verdict: malicious"
    assert triage_model == "composer-2.5"
    assert analyst_model == "grok-4.7-high"
    assert len(seen) == 2
    assert "You are Triage" in seen[0]["prompt"]
    assert "You are Analyst" in seen[1]["prompt"]
    for call in seen:
        assert call["argv"][2] == AGENT_LAUNCH_PROMPT
        assert "You are Triage" not in " ".join(call["argv"])
        assert "You are Analyst" not in " ".join(call["argv"])
        assert all(len(item.encode("utf-8")) < 128 * 1024 for item in call["argv"])


def test_cursor_runner_is_used_when_backend_is_cursor(monkeypatch, tmp_path):
    monkeypatch.setenv("CURSOR_API_KEY", "cursor-test-key")
    db = Database(tmp_path / "hunter.sqlite3")
    when = utcnow().replace(microsecond=0)
    evidence = build_evidence(
        __import__("hunter.models", fromlist=["Classification"]).Classification(
            ecosystem="npm",
            name="widget",
            old_version="1",
            new_version="2",
            rank=1,
            registry_url="",
            band="review",
            malice_probability=0.5,
            jev_model_id="jev-1.13.0",
        )
    )
    assert db.enqueue_investigation(evidence["idempotency_key"], json.dumps(evidence), when=when)
    captured = {}

    def fake_cursor(prompt, *, model, timeout, workspace=None):
        captured["prompt"] = prompt
        captured["model"] = model
        return "Verdict: malicious\nSupply-chain risk."

    monkeypatch.setattr("hunter.investigate.run_agent_cli", fake_cursor)
    config = Config(
        smart_backend="cursor",
        smart_model="composer-2.5",
        webhook_url="https://alerts.example/hook",
    )
    assert drain_investigations(db, config=config, when=when) == 1
    assert captured["model"] == "composer-2.5"
    assert "You are Triage" in captured["prompt"]
    assert "version-line-restore" in captured["prompt"]
    assert "<SOP>" in captured["prompt"]


def test_slack_body_is_a_text_message():
    payload = {
        "band": "alert",
        "ecosystem": "npm",
        "package": "widget-http",
        "new_version": "1.14.1",
        "malice_probability": 0.86,
        "attack_family": "dependency_abuse",
        "subtype": "new_unrelated",
        "old_version": "1.14.0",
        "rank": 12,
        "registry_url": "https://example.test/widget-http",
        "signals": ["phantom_runtime_dependency:codec-pad"],
    }
    text = slack_text(payload)
    assert "widget-http" in text
    assert "1.14.1" in text
    body = json.dumps({"text": text})
    assert json.loads(body)["text"] == text


def test_analysis_payload_parses_verdict():
    evidence = {
        "ecosystem": "npm",
        "package": "widget",
        "new_version": "2",
        "primary_band": "review",
        "malice_probability": 0.5,
        "signals": [],
        "child_findings": [],
        "jev_model_id": "jev-1.13.0",
    }
    payload = build_analysis_payload(
        evidence,
        "Looks suspicious.\nVerdict: uncertain",
        analysis_model_id="composer-2.5",
    )
    assert payload["kind"] == "smart_analysis"
    assert payload["verdict"] == "uncertain"


def test_disabled_smart_analysis_stores_nothing(tmp_path, monkeypatch):
    monkeypatch.delenv("CURSOR_API_KEY", raising=False)
    meta, old_files, new_files, _label = load_fixture(ROOT / "npm_child_dropper.json")
    db = Database(tmp_path / "hunter.sqlite3")
    config = Config(db_path=db.path, inspect_dependencies=False, smart_analysis=False)
    assert not smart_analysis_enabled(config)
    assert db.enqueue_job(meta.ecosystem, meta.name, meta.new_version, meta.rank)
    classify_job(db, config, db.pending_jobs()[0], jev=KeywordJev(), loader=MemoryLoader(meta, old_files, new_files))
    assert db.investigation_depth() == 0


def _finding(band: str, probability: float, name: str = "widget") -> Classification:
    return Classification(
        ecosystem="npm",
        name=name,
        old_version="1.0.0",
        new_version="1.0.1",
        rank=4,
        registry_url="https://www.npmjs.com/package/widget/v/1.0.1",
        band=band,
        malice_probability=probability,
        jev_model_id="jev-1.13.0",
        attack_family="install_hook",
        subtype="lifecycle_script",
        signals=["compound_install_payload"],
        pass_d_ran=True,
        pass_d_agreed=True,
    )


def test_classification_webhook_never_fires():
    assert ALERT_WEBHOOK_MIN_PROBABILITY == 0.80
    assert not should_notify("alert", webhook_on_review=False, malice_probability=0.80)
    assert not should_notify("alert", webhook_on_review=False, malice_probability=0.91)
    assert not should_notify("alert", webhook_on_review=False, malice_probability=0.99)
    assert not should_notify("alert", webhook_on_review=True, malice_probability=0.70)
    assert not should_notify("benign", webhook_on_review=True, malice_probability=0.99)
    assert not should_notify("review", webhook_on_review=False, malice_probability=0.95)
    assert not should_notify("review", webhook_on_review=True, malice_probability=0.50)
    assert not should_notify(
        "review",
        webhook_on_review=False,
        webhook_on_phantom=True,
        signals=["phantom_runtime_dependency:codec-pad"],
        malice_probability=0.9,
    )
    assert not should_notify("deferred", webhook_on_review=True, malice_probability=0.86)


def test_subthreshold_alert_skips_primary_webhook_and_discord_only_if_malicious(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    finding = _finding("alert", 0.75)
    assert enqueue_classification(db, finding, webhook_on_review=False) is False
    assert db.due_outbox() == []
    assert should_investigate(finding)
    evidence = build_evidence(finding)
    assert db.enqueue_investigation(evidence["idempotency_key"], json.dumps(evidence))
    config = Config(
        webhook_url="https://alerts.example/hook",
        investigate_command=f"{sys.executable} -c \"import sys; sys.stdout.write('Verdict: benign')\"",
    )
    assert drain_investigations(db, config=config) == 1
    assert db.due_outbox() == []
    assert db.investigation_report("npm:widget:1.0.1") == "Verdict: benign"

    again = Database(tmp_path / "other.sqlite3")
    malicious = build_evidence(finding)
    assert again.enqueue_investigation(malicious["idempotency_key"], json.dumps(malicious))
    malicious_config = Config(
        webhook_url="https://alerts.example/hook",
        webhook_format="slack",
        investigate_command=(
            f"{sys.executable} -c \"import sys; sys.stdout.write('Notes\\nVerdict: malicious')\""
        ),
        analyst_command=f"{sys.executable} -c \"import sys; sys.stdout.write('Verdict: malicious')\"",
    )
    assert drain_investigations(again, config=malicious_config) == 1
    assert again.due_outbox() == []
    assert drain_analyst(again, config=malicious_config) == 1
    rows = again.due_outbox()
    assert len(rows) == 1
    body = json.loads(rows[0]["body"])
    assert set(body) == {"text"}
    assert len(body["text"]) <= DISCORD_SLACK_TEXT_LIMIT
    assert "npm/widget" in body["text"]
    assert "alert" in body["text"]
    assert "malicious" in body["text"]
    assert "https://www.npmjs.com/package/widget/v/1.0.1" in body["text"]
    assert "family_probabilities" not in rows[0]["body"]
    assert "child_findings" not in rows[0]["body"]


def test_clear_alert_followup_uses_slack_text_and_stays_short(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    finding = _finding("alert", 0.91, name="color-hex-pad")
    assert enqueue_classification(db, finding, webhook_on_review=False, webhook_format="slack") is False
    assert db.due_outbox() == []
    evidence = build_evidence(finding)
    essay = ("Obfuscated install hook.\n" * 400) + "Verdict: benign"
    assert enqueue_analysis(
        db,
        evidence,
        essay,
        analysis_model_id="composer-2.5",
        webhook_format="slack",
    ) is False
    assert db.due_outbox() == []
    malicious = ("Obfuscated install hook.\n" * 400) + "Verdict: malicious"
    assert enqueue_analysis(
        db,
        evidence,
        malicious,
        analysis_model_id="composer-2.5",
        webhook_format="slack",
        confirmed_by="analyst",
        analyst_model_id="grok-4.7",
    )
    bodies = [json.loads(row["body"]) for row in db.due_outbox()]
    assert len(bodies) == 1
    follow = bodies[0]
    assert set(follow) == {"text"}
    assert follow["text"].startswith("Smart analysis")
    assert len(follow["text"]) <= DISCORD_SLACK_TEXT_LIMIT
    assert "color-hex-pad" in follow["text"]
    assert "alert" in follow["text"]
    assert "malicious" in follow["text"]
    assert "https://www.npmjs.com/package/widget/v/1.0.1" in follow["text"]
    assert "family_probabilities" not in json.dumps(follow)


def _ready(band: str, probability: float, **extra) -> dict:
    payload = {
        "primary_band": band,
        "malice_probability": probability,
        "jev_complete": True,
        "signals": [],
    }
    payload.update(extra)
    return payload


def test_analysis_delivery_policy():
    review = _ready("review", 0.62)
    low_alert = _ready("alert", 0.79)
    clear_alert = _ready("alert", 0.80)
    assert not should_deliver_analysis(review, "uncertain", confirmed_by="analyst")
    assert not should_deliver_analysis(review, "benign", confirmed_by="analyst")
    assert not should_deliver_analysis(review, None, confirmed_by="analyst")
    assert not should_deliver_analysis(review, "malicious")
    assert should_deliver_analysis(review, "malicious", confirmed_by="analyst")
    assert not should_deliver_analysis(low_alert, "uncertain", confirmed_by="analyst")
    assert should_deliver_analysis(low_alert, "malicious", confirmed_by="analyst")
    assert not should_deliver_analysis(clear_alert, "benign", confirmed_by="analyst")
    assert should_deliver_analysis(clear_alert, "malicious", confirmed_by="analyst")
    benign = _ready("benign", 0.16)
    assert not should_deliver_analysis(benign, "uncertain", confirmed_by="analyst")
    assert not should_deliver_analysis(benign, "benign", confirmed_by="analyst")
    assert should_deliver_analysis(benign, "malicious", confirmed_by="analyst")
    assert not should_deliver_analysis(
        _ready("alert", 0.91, jev_complete=False), "malicious", confirmed_by="analyst"
    )
    assert not should_deliver_analysis(
        _ready("alert", 0.91, signals=["static_rule"]), "malicious", confirmed_by="analyst"
    )
    assert not should_deliver_analysis(
        _ready("alert", 0.91, signals=["jev_unavailable"]), "malicious", confirmed_by="analyst"
    )
    assert not should_deliver_analysis(
        _ready("alert", 0.91, signals=["ai_incomplete"]), "malicious", confirmed_by="analyst"
    )
    assert not should_deliver_analysis(_ready("deferred", 0.86), "malicious", confirmed_by="analyst")
    # Pass D is gone. A row without it, or with an old Pass C or Pass D signal, still qualifies.
    assert should_deliver_analysis(
        _ready("review", 0.5, pass_d_ran=False), "malicious", confirmed_by="analyst"
    )
    for signal in ("pass_d_not_run", "pass_c_unavailable", "pass_c_failed"):
        assert should_deliver_analysis(
            _ready("review", 0.5, signals=[signal]), "malicious", confirmed_by="analyst"
        )
    for signal in ("jev_retry", "jev_pass_b_failed", "gateway_503"):
        assert not should_deliver_analysis(
            _ready("alert", 0.91, signals=[signal]), "malicious", confirmed_by="analyst"
        )
    for signals in (["partial_read", "jev_unreadable"], ["jev_unreadable", "release_budget"]):
        assert should_deliver_analysis(
            _ready("review", 0.5, signals=signals), "malicious", confirmed_by="analyst"
        )


def test_parse_verdict_uses_the_concluding_line():
    text = "Mention only.\nVerdict: malicious\nMore notes.\nVerdict: benign"
    assert parse_verdict(text) == "benign"
    assert parse_verdict("Notes\n**Verdict: malicious**") == "malicious"
    assert parse_verdict("**Verdict: uncertain**\n**Verdict: benign**") == "benign"
    payload = build_analysis_payload(
        {"ecosystem": "npm", "package": "widget", "new_version": "2", "primary_band": "review"},
        text,
        analysis_model_id="composer-2.5",
    )
    assert payload["verdict"] == "benign"


def test_slack_analysis_text_keeps_header_inside_discord_limit():
    payload = {
        "primary_band": "review",
        "ecosystem": "npm",
        "package": "widget-http",
        "new_version": "1.14.1",
        "malice_probability": 0.62,
        "registry_url": "https://www.npmjs.com/package/widget-http/v/1.14.1",
        "analysis_model_id": "composer-2.5",
        "verdict": "malicious",
        "analysis": "A" * 8000,
        "signals": ["phantom_runtime_dependency:codec-pad"] * 40,
        "child_findings": [{"name": "codec-pad", "blob": "Z" * 5000}],
    }
    text = slack_analysis_text(payload)
    assert len(text) <= DISCORD_SLACK_TEXT_LIMIT
    assert text.startswith("Smart analysis (review) npm/widget-http 1.14.1")
    assert "verdict malicious" in text
    assert payload["registry_url"] in text
    assert "child_findings" not in text
    assert "family_probabilities" not in text


def test_discord_url_uses_slack_text_even_when_format_is_json(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    finding = _finding("alert", 0.91)
    url = "https://discord.com/api/webhooks/1/token/slack"
    assert enqueue_classification(
        db,
        finding,
        webhook_on_review=False,
        webhook_format="json",
        webhook_url=url,
    ) is False
    assert db.due_outbox() == []
    evidence = build_evidence(finding)
    assert enqueue_analysis(
        db,
        evidence,
        "A" * 5000 + "\n**Verdict: malicious**",
        analysis_model_id="composer-2.5",
        webhook_format="json",
        webhook_url=url,
        confirmed_by="analyst",
    )
    follow = json.loads(db.due_outbox()[0]["body"])
    assert set(follow) == {"text"}
    assert len(follow["text"]) <= DISCORD_SLACK_TEXT_LIMIT
    assert "npm/widget" in follow["text"]
    assert "malicious" in follow["text"]
    assert finding.registry_url in follow["text"]
    assert "family_probabilities" not in db.due_outbox()[0]["body"]


def test_min_probability_is_env_overridable(monkeypatch):
    monkeypatch.setenv("ALERT_WEBHOOK_MIN_PROBABILITY", "0.9")
    assert Config.from_env().webhook_min_probability == 0.9
    monkeypatch.setenv("ALERT_WEBHOOK_MIN_PROBABILITY", "nope")
    assert Config.from_env().webhook_min_probability == ALERT_WEBHOOK_MIN_PROBABILITY
    monkeypatch.setenv("ALERT_WEBHOOK_MIN_PROBABILITY", "1.5")
    assert Config.from_env().webhook_min_probability == ALERT_WEBHOOK_MIN_PROBABILITY
