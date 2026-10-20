"""Backup decision model and the single outage webhook. Synthetic made-up text only."""

from __future__ import annotations

import json
from datetime import timedelta

import pytest

from hunter.classify import BACKUP_SIGNAL, MODEL_DOWN_SIGNAL, classify_files, decision_model_failed
from hunter.config import Config
from hunter.db import Database, utcnow
from hunter.fake_jev import KeywordJev, RaisingJev
from hunter.head import load_head
from hunter.jev import JevUnavailable
from hunter.models import Classification, ReleaseMeta
from hunter.scout_model import scout_backup_from_env
from hunter.service import OUTAGE_NOTIFY_FAILURES, note_decision_model_health

OLD = {"index.js": "module.exports = 1;\n"}
NEW = {"index.js": "module.exports = 2;\nrequire('child_process').exec('echo hi');\n"}


def _meta() -> ReleaseMeta:
    return ReleaseMeta(ecosystem="npm", name="widget", old_version="1.0.0", new_version="1.0.1", rank=4)


class DownJev(RaisingJev):
    def __init__(self, backup=None):
        self.backup = backup


class SpendStopJev:
    model = "jev-1.13.0"

    def system_one(self, state, questions):
        raise JevUnavailable("spend_cap_reached")


def _classify(jev):
    return classify_files(meta=_meta(), old_files=OLD, new_files=NEW, jev=jev, head=load_head())


def test_a_working_backup_answers_when_the_primary_fails():
    backup = KeywordJev()
    result = _classify(DownJev(backup=backup))
    assert backup.calls
    assert BACKUP_SIGNAL in result.signals
    assert MODEL_DOWN_SIGNAL not in result.signals
    assert not decision_model_failed(result)


def test_no_backup_and_a_failed_primary_marks_the_model_down():
    result = _classify(DownJev())
    assert result.band == "deferred"
    assert MODEL_DOWN_SIGNAL in result.signals


def test_both_failing_marks_the_model_down():
    result = _classify(DownJev(backup=RaisingJev()))
    assert BACKUP_SIGNAL in result.signals
    assert MODEL_DOWN_SIGNAL in result.signals


def test_a_spend_cap_stop_is_not_a_model_failure():
    backup = KeywordJev()
    jev = SpendStopJev()
    jev.backup = backup
    result = _classify(jev)
    assert result.band == "deferred"
    assert result.defer_reason == "spend_cap_reached"
    assert not backup.calls
    assert MODEL_DOWN_SIGNAL not in result.signals


def test_a_healthy_primary_never_touches_the_backup():
    backup = KeywordJev()
    jev = KeywordJev()
    jev.backup = backup
    result = _classify(jev)
    assert not backup.calls
    assert BACKUP_SIGNAL not in result.signals


def test_backup_setting():
    assert scout_backup_from_env("jev", "") == ""
    assert scout_backup_from_env("jev", "off") == ""
    assert scout_backup_from_env("jev", "jev") == ""
    assert scout_backup_from_env("jev", "Clef") == "clef"
    with pytest.raises(ValueError):
        scout_backup_from_env("jev", "some-chat-model")


def _row(down: bool) -> Classification:
    signals = [MODEL_DOWN_SIGNAL] if down else []
    return Classification(
        ecosystem="npm",
        name="widget",
        old_version="1.0.0",
        new_version="1.0.1",
        rank=4,
        registry_url="https://example.test/widget",
        band="deferred" if down else "benign",
        defer_reason="jev_unavailable" if down else "",
        malice_probability=0.0,
        jev_model_id="jev-1.13.0",
        signals=signals,
    )


def _outbox(db: Database) -> list[dict]:
    with db._lock:
        rows = db._conn.execute("SELECT idempotency_key, body FROM outbox").fetchall()
    return [dict(row) for row in rows]


def test_one_outage_webhook_after_enough_failures_and_never_twice(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = Config(db_path=db.path)
    start = utcnow()
    for index in range(OUTAGE_NOTIFY_FAILURES - 1):
        note_decision_model_health(db, config, _row(True), now=start + timedelta(seconds=index))
    assert _outbox(db) == []
    for index in range(10):
        note_decision_model_health(db, config, _row(True), now=start + timedelta(seconds=10 + index))
    sent = _outbox(db)
    assert len(sent) == 1
    assert sent[0]["idempotency_key"].startswith("decision-model-down:")
    body = json.loads(sent[0]["body"])
    assert body["kind"] == "decision_model_down"
    assert "widget" not in sent[0]["body"]
    # A restart reads the same DB and still does not resend.
    reopened = Database(tmp_path / "hunter.sqlite3")
    note_decision_model_health(reopened, config, _row(True), now=start + timedelta(minutes=30))
    assert len(_outbox(reopened)) == 1


def test_a_long_outage_notifies_even_with_few_failures(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = Config(db_path=db.path)
    start = utcnow()
    note_decision_model_health(db, config, _row(True), now=start)
    assert _outbox(db) == []
    note_decision_model_health(db, config, _row(True), now=start + timedelta(minutes=11))
    assert len(_outbox(db)) == 1


def test_an_answer_ends_the_outage_and_a_new_outage_can_notify_again(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = Config(db_path=db.path)
    start = utcnow()
    note_decision_model_health(db, config, _row(True), now=start)
    note_decision_model_health(db, config, _row(True), now=start + timedelta(minutes=11))
    note_decision_model_health(db, config, _row(False), now=start + timedelta(minutes=12))
    assert db.clear_decision_model_outage() is None
    note_decision_model_health(db, config, _row(True), now=start + timedelta(minutes=20))
    note_decision_model_health(db, config, _row(True), now=start + timedelta(minutes=31))
    assert len(_outbox(db)) == 2


def test_a_short_blip_sends_nothing(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = Config(db_path=db.path)
    start = utcnow()
    note_decision_model_health(db, config, _row(True), now=start)
    note_decision_model_health(db, config, _row(False), now=start + timedelta(minutes=1))
    assert _outbox(db) == []
