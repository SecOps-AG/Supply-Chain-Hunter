"""Discord only after finished Jev passes and a Composer malicious verdict."""

import json
import sys
from datetime import timedelta

from hunter.bands import REVIEW_THRESHOLD
from hunter.classify import classification_incomplete, classify_files
from hunter.config import Config
from hunter.db import Database, utcnow
from hunter.fixtures_io import load_fixture
from hunter.head import load_head
from hunter.investigate import build_evidence, drain_investigations, drain_analyst, jev_passes_complete
from hunter.jev import GATEWAY_BASE_URL, GATEWAY_MODEL_ID, JevClient, JevUnavailable
from hunter.models import Classification
from hunter.questions import PASS_B_IDS
from hunter.service import classify_job, drain_until_idle
from hunter.webhook import enqueue_analysis, jev_evidence_complete, parse_verdict, should_deliver_analysis
from pathlib import Path
from hunter.fake_jev import KeywordJev, RaisingJev


ROOT = Path(__file__).resolve().parents[1] / "fixtures"


class MemoryLoader:
    def __init__(self, meta, old_files, new_files):
        self.meta = meta
        self.old_files = old_files
        self.new_files = new_files

    def load(self, ecosystem, name, version, rank):
        return self.old_files, self.new_files, self.meta


class ShortReaskDown(KeywordJev):
    """Fails a short re-ask of Pass B Nouls. Classify no longer makes one."""

    def __init__(self):
        super().__init__()
        self.reasks = 0

    def system_one(self, state, questions):
        if questions and set(questions) <= set(PASS_B_IDS) and len(questions) <= 3:
            self.reasks += 1
            raise JevUnavailable("HTTP 503")
        return super().system_one(state, questions)


class PassCDown(KeywordJev):
    def system_one(self, state, questions):
        if "attack_family" in questions:
            raise JevUnavailable("HTTP 503")
        return super().system_one(state, questions)


def test_no_pass_d_reask_is_made():
    meta, old_files, new_files, _label = load_fixture(ROOT / "npm_child_dropper.json")
    full = classify_files(
        meta=meta,
        old_files=old_files,
        new_files=new_files,
        jev=KeywordJev(),
        head=load_head(),
    )
    jev = ShortReaskDown()
    result = classify_files(
        meta=meta,
        old_files=old_files,
        new_files=new_files,
        jev=jev,
        head=load_head(),
    )
    assert jev.reasks == 0
    assert result.band == full.band
    assert result.band != "deferred"
    assert result.defer_reason == ""
    assert result.pass_d_ran is False
    assert result.malice_probability == full.malice_probability
    assert result.malice_probability >= REVIEW_THRESHOLD
    assert "pass_d_failed" not in result.signals
    assert "jev_retry" not in result.signals
    assert "ai_incomplete" not in result.signals
    assert classification_incomplete(result) is False
    assert "static_rule" not in result.signals


def test_pass_c_failure_keeps_the_pass_b_score():
    meta, old_files, new_files, _label = load_fixture(ROOT / "npm_child_dropper.json")
    full = classify_files(
        meta=meta,
        old_files=old_files,
        new_files=new_files,
        jev=KeywordJev(),
        head=load_head(),
    )
    result = classify_files(
        meta=meta,
        old_files=old_files,
        new_files=new_files,
        jev=PassCDown(),
        head=load_head(),
    )
    assert result.band != "deferred"
    assert result.defer_reason == ""
    assert result.malice_probability == full.malice_probability
    assert result.malice_probability >= REVIEW_THRESHOLD
    assert "pass_c_failed" in result.signals
    assert "jev_retry" not in result.signals
    assert classification_incomplete(result) is False
    assert "static_rule" not in result.signals


def test_pass_c_failure_does_not_block_analyst_or_discord():
    meta, old_files, new_files, _label = load_fixture(ROOT / "npm_child_dropper.json")
    result = classify_files(
        meta=meta,
        old_files=old_files,
        new_files=new_files,
        jev=PassCDown(),
        head=load_head(),
    )
    assert "pass_c_failed" in result.signals
    assert jev_passes_complete(result)
    evidence = build_evidence(result)
    assert evidence["jev_complete"] is True
    assert jev_evidence_complete(evidence)
    assert should_deliver_analysis(evidence, "malicious", confirmed_by="analyst")


def test_incomplete_jev_never_discords_and_is_retried(tmp_path):
    meta, old_files, new_files, _label = load_fixture(ROOT / "npm_child_dropper.json")
    db = Database(tmp_path / "hunter.sqlite3")
    config = Config(
        db_path=db.path,
        webhook_url="https://discord.com/api/webhooks/1/token/slack",
        webhook_format="slack",
        webhook_on_review=True,
        webhook_on_phantom=True,
        inspect_dependencies=False,
        investigate_command=f"{sys.executable} -c \"import sys; sys.stdout.write('Verdict: malicious')\"",
    )
    assert db.enqueue_job(meta.ecosystem, meta.name, meta.new_version, meta.rank)
    classify_job(
        db,
        config,
        db.pending_jobs()[0],
        jev=RaisingJev(),
        loader=MemoryLoader(meta, old_files, new_files),
    )
    stored = db.get_release(meta.ecosystem, meta.name, meta.new_version)
    assert stored["band"] == "deferred"
    assert "static_rule" not in stored["payload_json"]
    assert db.due_outbox() == []
    assert db.investigation_depth() == 0
    assert db.retry_depth() == 1


def test_composer_malicious_discords_and_uncertain_does_not(tmp_path):
    meta, old_files, new_files, _label = load_fixture(ROOT / "npm_child_dropper.json")
    db = Database(tmp_path / "hunter.sqlite3")
    command = f"{sys.executable} -c \"import sys; sys.stdout.write('Notes\\n**Verdict: malicious**')\""
    config = Config(
        db_path=db.path,
        webhook_url="https://discord.com/api/webhooks/9/token/slack",
        webhook_format="json",
        inspect_dependencies=False,
        investigate_command=command,
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
    assert drain_investigations(db, config=config) == 1
    assert db.due_outbox() == []
    assert drain_analyst(db, config=config) == 1
    rows = db.due_outbox()
    assert len(rows) == 1
    body = json.loads(rows[0]["body"])
    assert set(body) == {"text"}
    assert "malicious" in body["text"]
    assert meta.name in body["text"]
    assert "Verdict: malicious" in db.investigation_report(f"npm:{meta.name}:{meta.new_version}")

    other = Database(tmp_path / "other.sqlite3")
    finding = Classification(
        ecosystem="npm",
        name="widget",
        old_version="1",
        new_version="2",
        rank=1,
        registry_url="https://www.npmjs.com/package/widget/v/2",
        band="alert",
        malice_probability=0.91,
        jev_model_id="jev-1.13.0",
        signals=["compound_install_payload"],
    )
    evidence = build_evidence(finding)
    assert parse_verdict("**Verdict: uncertain**") == "uncertain"
    assert enqueue_analysis(
        other,
        evidence,
        "Could go either way.\n**Verdict: uncertain**",
        analysis_model_id="composer-2.5",
        webhook_url="https://discord.com/api/webhooks/9/token/slack",
    ) is False
    assert other.due_outbox() == []


def test_exhausted_classify_and_composer_land_in_the_human_queue(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    when = utcnow().replace(microsecond=0)
    status = ""
    for _ in range(4):
        status = db.note_classify_failure(
            "npm",
            "pkg",
            "1.2.3",
            4000,
            "gateway_503",
            reason="gateway_503",
            max_attempts=5,
            when=when,
        )
        assert status == "retrying"
    status = db.note_classify_failure(
        "npm",
        "pkg",
        "1.2.3",
        4000,
        "gateway_503",
        reason="gateway_503",
        max_attempts=5,
        when=when,
    )
    assert status == "exhausted"
    assert db.retry_depth() == 0
    assert db.due_classify_retries(when + timedelta(days=1)) == []
    assert db.note_classify_failure(
        "npm",
        "pkg",
        "1.2.3",
        4000,
        "gateway_503",
        reason="gateway_503",
        max_attempts=5,
        when=when,
    ) == "exhausted"

    finding = Classification(
        ecosystem="pypi",
        name="leftpad",
        old_version="1",
        new_version="2",
        rank=3,
        registry_url="https://pypi.org/project/leftpad/2/",
        band="review",
        malice_probability=0.62,
        jev_model_id="jev-1.13.0",
        signals=["literal_shell"],
    )
    evidence = build_evidence(finding)
    assert db.enqueue_investigation(evidence["idempotency_key"], json.dumps(evidence), when=when)

    def runner(_command, _body):
        raise RuntimeError("composer timeout")

    config = Config(
        webhook_url="https://discord.com/api/webhooks/1/token/slack",
        ai_max_attempts=2,
    )
    assert drain_investigations(db, config=config, runner=runner, when=when) == 0
    later = when + timedelta(seconds=2)
    assert drain_investigations(db, config=config, runner=runner, when=later) == 0
    assert db.due_outbox(later + timedelta(days=1)) == []
    assert db.investigation_depth() == 0
    rows = db.human_review_queue()
    kinds = {row["kind"] for row in rows}
    assert kinds == {"classify", "investigation"}
    classify = next(row for row in rows if row["kind"] == "classify")
    composer = next(row for row in rows if row["kind"] == "investigation")
    assert classify["name"] == "pkg"
    assert classify["version"] == "1.2.3"
    assert classify["attempts"] == 5
    assert classify["reason"] == "gateway_503"
    assert composer["name"] == "leftpad"
    assert composer["version"] == "2"
    assert composer["attempts"] == 2
    assert composer["last_error"] == "composer timeout"
    assert db.human_review_depth() == 2


def test_gateway_jev_uses_gateway_model_and_base_url(monkeypatch):
    monkeypatch.delenv("HUNTER_JEV_MODEL", raising=False)
    monkeypatch.setenv("TYPESAFE_BASE_URL", GATEWAY_BASE_URL)
    monkeypatch.setenv("AI_GATEWAY_API_KEY", "gw-key")
    monkeypatch.setenv("TYPESAFE_API_KEY", "direct-key")
    client = JevClient()
    assert client.model == GATEWAY_MODEL_ID
    assert client.base_url == GATEWAY_BASE_URL
    assert client.api_key == "gw-key"
    assert client.client_kwargs()["base_url"] == GATEWAY_BASE_URL
    assert client.client_kwargs()["model"] == "typesafe-ai/jev-1.13.0"
    direct = Config.from_env()
    assert direct.jev_model == "typesafe-ai/jev-1.13.0"
    assert direct.jev_base_url == GATEWAY_BASE_URL
    monkeypatch.setenv("HUNTER_JEV_MODEL", "jev-1.13.0")
    pinned = JevClient()
    assert pinned.model == "jev-1.13.0"
    assert pinned.base_url == GATEWAY_BASE_URL


def test_gateway_jev_model_is_pinned_to_the_calibrated_release():
    from hunter import JEV_MODEL_ID

    assert JEV_MODEL_ID == "jev-1.13.0"
    assert GATEWAY_MODEL_ID == "typesafe-ai/jev-1.13.0"
    assert GATEWAY_MODEL_ID.endswith("/" + JEV_MODEL_ID)
    assert GATEWAY_MODEL_ID != "typesafe-ai/jev"


def test_pipeline_interleaves_investigation_with_classify(monkeypatch):
    calls = []
    remaining = {"jobs": 2}

    def jobs(*_args, **_kwargs):
        calls.append("classify")
        if remaining["jobs"] <= 0:
            return 0
        remaining["jobs"] -= 1
        return 1

    def investigations(*_args, **_kwargs):
        calls.append("investigate")
        return 0

    def analyst(*_args, **_kwargs):
        calls.append("analyst")
        return 0

    def outbox(*_args, **_kwargs):
        calls.append("outbox")
        return 0

    monkeypatch.setattr("hunter.service.drain_jobs", jobs)
    monkeypatch.setattr("hunter.service.drain_investigations", investigations)
    monkeypatch.setattr("hunter.service.drain_analyst", analyst)
    monkeypatch.setattr("hunter.service.drain_outbox", outbox)
    config = Config(
        investigate_command="hunter-analysis",
        classify_batch=25,
        classify_cycle_cap=100,
    )
    drain_until_idle(None, config, jev=None, loader=None)
    assert calls == [
        "classify",
        "investigate",
        "analyst",
        "outbox",
        "classify",
        "investigate",
        "analyst",
        "outbox",
        "classify",
        "investigate",
        "analyst",
        "outbox",
    ]
