"""Partial and unread Scout rows reach Analyst and Discord with a marker. All package text is inert."""

import hashlib
import json
import sys

from hunter.classify import classify_files
from hunter.config import Config
from hunter.db import Database
from hunter.head import load_head
from hunter.investigate import (
    build_analyst_prompt,
    build_evidence,
    build_triage_prompt,
    drain_analyst,
    drain_investigations,
    jev_passes_complete,
    run_analyst_analysis,
    run_smart_analysis,
)
from hunter.models import Classification, ReleaseMeta
from hunter.service import classify_job
from hunter.triage import BUNDLE_SUMMARY_BYTES, diff_was_cut, full_filtered_diff
from hunter.webhook import (
    build_analysis_payload,
    drain_outbox,
    jev_evidence_complete,
    should_deliver_analysis,
    slack_analysis_text,
)
from hunter.fake_jev import KeywordJev

MARKER = "decision model (Scout) did not read this whole release"


class MemoryLoader:
    def __init__(self, meta, old_files, new_files):
        self.meta = meta
        self.old_files = old_files
        self.new_files = new_files

    def load(self, ecosystem, name, version, rank):
        return self.old_files, self.new_files, self.meta


class PartialJev(KeywordJev):
    def system_one(self, state, questions):
        result = super().system_one(state, questions)
        result.partial = True
        return result


def _say(text: str) -> str:
    return f"{sys.executable} -c \"import sys; sys.stdout.write('{text}')\""


def _meta() -> ReleaseMeta:
    return ReleaseMeta(ecosystem="npm", name="widget", new_version="1.0.1", old_version="1.0.0", rank=3)


def _row(band: str = "review", signals: list[str] | None = None) -> Classification:
    return Classification(
        ecosystem="npm",
        name="widget",
        old_version="1.0.0",
        new_version="1.0.1",
        rank=3,
        registry_url="https://www.npmjs.com/package/widget/v/1.0.1",
        band=band,
        malice_probability=0.62,
        jev_model_id="jev-1.13.0",
        signals=list(signals or []),
    )


def test_partial_read_row_reaches_analyst_and_discord_with_the_marker(tmp_path):
    meta = _meta()
    old_files = {"index.js": "module.exports = 1;\n"}
    new_files = {"index.js": "require('child_process').execSync('id');\n"}
    db = Database(tmp_path / "hunter.sqlite3")
    config = Config(
        db_path=db.path,
        webhook_url="https://alerts.example/hook",
        inspect_dependencies=False,
        investigate_command=_say("Verdict: malicious"),
        analyst_command=_say("Verdict: malicious"),
    )
    assert db.enqueue_job(meta.ecosystem, meta.name, meta.new_version, meta.rank)
    classify_job(db, config, db.pending_jobs()[0], jev=PartialJev(), loader=MemoryLoader(meta, old_files, new_files))
    stored = json.loads(db.get_release("npm", "widget", "1.0.1")["payload_json"])
    assert stored["band"] == "review"
    assert "partial_read" in stored["signals"]
    assert stored["pass_d_ran"] is False
    assert db.investigation_depth() == 1
    assert drain_investigations(db, config=config) == 1
    assert db.due_outbox() == []
    assert drain_analyst(db, config=config) == 1
    posts = []
    assert drain_outbox(db, url=config.webhook_url, poster=lambda *args: posts.append(args)) == 1
    payload = json.loads(posts[0][1])
    assert payload["verdict"] == "malicious"
    assert payload["partial_read"] is True
    assert payload["partial_reasons"] == ["partial_read", "jev_unreadable"]
    assert "partial read: a file or chunk was only partly read" in slack_analysis_text(payload)


def test_unread_and_budget_rows_are_eligible_and_marked():
    for signals in (["jev_unreadable"], ["jev_unreadable", "release_budget"]):
        row = _row(signals=signals)
        assert jev_passes_complete(row)
        evidence = build_evidence(row)
        assert evidence["jev_complete"] is True
        assert should_deliver_analysis(evidence, "malicious", confirmed_by="analyst")
        assert not should_deliver_analysis(evidence, "malicious", confirmed_by="triage")
        evidence["triage_report"] = "Verdict: malicious"
        for prompt in (
            build_triage_prompt(evidence, config=Config(db_path=":memory:")),
            build_analyst_prompt(evidence, config=Config(db_path=":memory:")),
        ):
            assert MARKER in prompt
            assert "say what you could not see" in prompt
            assert prompt.find(MARKER) < prompt.find("<SOP>")
    payload = build_analysis_payload(
        build_evidence(_row(signals=["jev_unreadable", "release_budget"])),
        "Verdict: malicious",
        analysis_model_id="grok-4.7-high",
        analyst_model_id="grok-4.7-high",
    )
    assert payload["partial_reasons"] == ["jev_unreadable", "release_budget"]
    assert "the release was over the decision model (Scout) token cap" in slack_analysis_text(payload)


def test_finished_read_has_no_marker():
    evidence = build_evidence(_row(band="alert"))
    evidence["triage_report"] = "Verdict: malicious"
    assert MARKER not in build_triage_prompt(evidence, config=Config(db_path=":memory:"))
    assert MARKER not in build_analyst_prompt(evidence, config=Config(db_path=":memory:"))
    payload = build_analysis_payload(evidence, "Verdict: malicious", analysis_model_id="grok-4.7-high")
    assert payload["partial_read"] is False
    assert payload["partial_reasons"] == []
    assert "partial read" not in slack_analysis_text(payload)


def test_new_binary_row_is_eligible_for_analyst_and_discord():
    old = {"index.js": "module.exports = 1;\n", "package.json": '{"name":"widget","version":"1.0.0"}\n'}
    marker = "[binary-or-media-file]\nkind: binary\nbytes: 16\nsha256_prefix: abc\nextension: .node\nheader: elf\n"
    new = {**old, "build/addon.node": marker}
    jev = KeywordJev()
    result = classify_files(meta=_meta(), old_files=old, new_files=new, jev=jev, head=load_head())
    assert jev.calls == []
    assert result.band == "review"
    assert "new_binary" in result.signals
    assert jev_passes_complete(result)
    evidence = build_evidence(result)
    assert jev_evidence_complete(evidence)
    assert should_deliver_analysis(evidence, "malicious", confirmed_by="analyst")


def test_blocking_signals_still_block():
    for signal in ("ai_incomplete", "static_rule", "jev_unavailable", "jev_retry", "jev_pass_b_failed", "gateway_503"):
        row = _row(signals=[signal])
        assert not jev_passes_complete(row), signal
        evidence = build_evidence(row)
        assert not should_deliver_analysis(evidence, "malicious", confirmed_by="analyst"), signal
    deferred = _row(band="deferred")
    assert not jev_passes_complete(deferred)
    for signal in ("pass_c_failed", "pass_c_unavailable", "pass_d_not_run", "pass_d_failed"):
        evidence = build_evidence(_row(signals=[signal]))
        assert should_deliver_analysis(evidence, "malicious", confirmed_by="analyst"), signal


def test_triage_diff_cut_is_marked_and_still_eligible():
    old = {"index.js": "module.exports = 1;\n"}
    new = {
        "index.js": "module.exports = 2;\n",
        "lib/hook.js": "const { execSync } = require('child_process');\n" + "execSync('echo hi');\n" * 400,
    }
    cut = full_filtered_diff(old, new, limit_chars=600)
    assert diff_was_cut(cut)
    whole = full_filtered_diff(old, new)
    assert not diff_was_cut(whole)
    evidence = build_evidence(_row(), full_diff=cut)
    assert "triage_diff_cut" in evidence["signals"]
    assert jev_evidence_complete(evidence)
    evidence["triage_report"] = "Verdict: malicious"
    assert "the mid-tier, balanced model (Triage) diff was cut at its size cap" in build_analyst_prompt(
        evidence, config=Config(db_path=":memory:")
    )
    assert "triage_diff_cut" not in build_evidence(_row(), full_diff=whole)["signals"]
    # Package text that only mentions the note is not a cut.
    quoted = "line one\n[TRUNCATION]\nThe filtered diff was cut at 5 characters. Later content was omitted.\nmore\n"
    assert not diff_was_cut(quoted)


def _bundle(size: int) -> str:
    head = (
        "!function(e){var t={};"
        "var u='https://collect.evil-host.test/beacon';"
        "var k=process.env.NPM_TOKEN;var a=process.env.AWS_SECRET_ACCESS_KEY;"
        "var c=require('child_process');c.exec('id');"
        "var ip='203.0.113.7';var l='127.0.0.1';"
    )
    filler = "function n(r){return r*2+t[r]}var o=[1,2,3].map(n);"
    body = head
    while len(body) < size:
        body += filler
    return body + "}();\n"


def test_large_minified_added_file_is_summarized():
    bundle = _bundle(BUNDLE_SUMMARY_BYTES + 20_000)
    old = {"package.json": '{"name":"widget","version":"1.0.0","main":"index.js"}\n', "index.js": "module.exports = 1;\n"}
    new = {
        "package.json": '{"name":"widget","version":"1.0.1","main":"index.js"}\n',
        "index.js": "module.exports = require('./dist/app.min.js');\n",
        "dist/app.min.js": bundle,
    }
    text = full_filtered_diff(old, new)
    assert "[summarized_bundle:dist/app.min.js]" in text
    assert text.count("[summarized_bundle:dist/app.min.js]") == 1
    assert "summarized because of size" in text
    assert f"size_bytes: {len(bundle.encode('utf-8'))}" in text
    assert f"new_sha256: {hashlib.sha256(bundle.encode('utf-8')).hexdigest()[:16]}" in text
    assert "old_sha256: none" in text
    assert "old_version_had_file: no" in text
    assert "host collect.evil-host.test" in text
    assert "ipv4 203.0.113.7" in text
    assert "ipv4 127.0.0.1" not in text
    assert "process.env.NPM_TOKEN" in text
    assert "process.env.AWS_SECRET_ACCESS_KEY" in text
    assert "child_process" in text
    # The raw body is gone: the filler repeats far more often than any context window shows.
    assert text.count("var o=[1,2,3].map(n);") < 50
    assert len(text) < 40_000
    assert "[added_file:dist/app.min.js]" not in text


def test_changed_minified_file_records_the_old_hash_and_small_files_stay_raw():
    old_bundle = _bundle(BUNDLE_SUMMARY_BYTES + 1_000)
    new_bundle = old_bundle.replace("evil-host", "other-host")
    old = {"dist/app.min.js": old_bundle}
    new = {"dist/app.min.js": new_bundle}
    text = full_filtered_diff(old, new)
    assert "[summarized_bundle:dist/app.min.js]" in text
    assert f"old_sha256: {hashlib.sha256(old_bundle.encode('utf-8')).hexdigest()[:16]}" in text
    assert "old_version_had_file: yes" in text
    assert "host collect.other-host.test" in text
    assert "--- " not in text.split("[summarized_bundle:", 1)[1]
    small = _bundle(4_000)
    kept = full_filtered_diff({}, {"dist/small.min.js": small})
    assert "[summarized_bundle:" not in kept


def test_readable_large_file_is_not_summarized():
    readable = "".join(f"const value{i} = require('child_process');\n" for i in range(3_000))
    assert len(readable) > BUNDLE_SUMMARY_BYTES
    text = full_filtered_diff({}, {"lib/readable.js": readable})
    assert "[summarized_bundle:" not in text


def test_analyst_timeout_defaults_to_900_and_reads_the_env(monkeypatch):
    monkeypatch.delenv("HUNTER_ANALYST_TIMEOUT", raising=False)
    monkeypatch.delenv("HUNTER_INVESTIGATE_TIMEOUT", raising=False)
    config = Config.from_env()
    assert config.analyst_timeout == 900.0
    assert config.investigate_timeout == 300.0
    assert Config().analyst_timeout == 900.0
    monkeypatch.setenv("HUNTER_ANALYST_TIMEOUT", "1200")
    assert Config.from_env().analyst_timeout == 1200.0


def test_analyst_uses_its_timeout_and_triage_keeps_its_own(monkeypatch):
    seen = []

    def fake_cursor(prompt, *, model, timeout, evidence=None):
        seen.append(("cursor", model, timeout))
        return "Verdict: malicious"

    def fake_command(command, body, timeout):
        seen.append(("command", command, timeout))
        return "Verdict: malicious"

    monkeypatch.setattr("hunter.investigate.run_cursor_with_diff", fake_cursor)
    monkeypatch.setattr("hunter.investigate.run_override_command", fake_command)
    evidence = build_evidence(_row())
    config = Config(
        smart_backend="cursor",
        smart_model="composer-2.5",
        analyst_model="grok-4.7-high",
        investigate_timeout=300,
        analyst_timeout=900,
    )
    run_smart_analysis(evidence, config=config)
    run_analyst_analysis(evidence, config=config)
    config.analyst_command = "analyst-cmd"
    config.investigate_command = "triage-cmd"
    run_analyst_analysis(evidence, config=config)
    run_smart_analysis(evidence, config=config)
    assert seen == [
        ("cursor", "composer-2.5", 300),
        ("cursor", "grok-4.7-high", 900),
        ("command", "analyst-cmd", 900),
        ("command", "triage-cmd", 300),
    ]


def test_scout_teacher_uses_the_analyst_timeout(monkeypatch):
    from hunter.scout_mine import _run_teacher

    seen = []
    monkeypatch.setattr(
        "hunter.investigate.run_override_command",
        lambda command, body, timeout: seen.append(("command", timeout)) or "Verdict: uncertain",
    )
    monkeypatch.setattr(
        "hunter.investigate.run_agent_cli",
        lambda prompt, *, model, timeout, workspace=None: seen.append(("cursor", timeout)) or "Verdict: uncertain",
    )
    _run_teacher("prompt", Config(analyst_command="teach-cmd", analyst_timeout=901), None)
    _run_teacher("prompt", Config(analyst_model="grok-4.7-high", analyst_timeout=902), None)
    assert seen == [("command", 901), ("cursor", 902)]


def test_teach_loop_analyst_call_uses_the_analyst_timeout(tmp_path, monkeypatch):
    from hunter.teach import run_teach, write_axios_distillation

    for name in ("HUNTER_SMART_MODEL", "HUNTER_ANALYST_MODEL", "ALERT_WEBHOOK_URL", "HUNTER_SCOUT_LESSONS"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HUNTER_ANALYST_TIMEOUT", "777")
    monkeypatch.setenv("HUNTER_ANALYST_MODEL", "analyst-model")
    production = tmp_path / "scout-lessons.md"
    production.write_text("# Scout lessons\n", encoding="utf-8")
    monkeypatch.setenv("HUNTER_SCOUT_LESSONS", str(production))
    seen = []

    def fake_live(prompt, endpoint, evidence=None):
        seen.append(("Analyst" if "You are Analyst" in prompt else "Triage", endpoint.timeout))
        return "Verdict: malicious"

    monkeypatch.setattr("hunter.teach._live_ready", lambda endpoints: (True, ""))
    monkeypatch.setattr("hunter.teach._run_live", fake_live)
    root = write_axios_distillation(tmp_path / "trees")
    result = run_teach(root, max_rounds=1, out_dir=tmp_path / "out", mode="live", timeout=300)
    assert result["mode"] == "live"
    assert ("Triage", 300) in seen
    assert ("Analyst", 777.0) in seen
