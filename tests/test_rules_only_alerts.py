"""Scout paused (spend cap): watched releases still get the free rule checks and a rules-only alert.

Synthetic, inert text only. The paused Scout fails the test if it is called. No network.
"""

from __future__ import annotations

import json

import pytest

import hunter.rules.engine as engine
from hunter.classify import RULES_ONLY_SIGNAL, classification_incomplete, classify_files
from hunter.config import Config
from hunter.db import Database
from hunter.fake_jev import KeywordJev
from hunter.head import load_head
from hunter.models import ReleaseMeta
from hunter.rules import load_pack
from hunter.rules.registry import RulePack
from hunter.scout_model import Usage
from hunter.service import classify_job
from hunter.spend import SpendMeter
from hunter.webhook import drain_outbox

HOOK = "https://alerts.example/hook"
ORDINARY = "function add(a, b) {\n  return a + b;\n}\nmodule.exports = add;\n"
HOSTILE_LINE = "eval(String.fromCharCode(99,111,110,115,111,108,101));\n"
PKG_OLD = '{"name":"widget","version":"1.0.0"}\n'
PKG_NEW = '{"name":"widget","version":"1.0.1"}\n'


class PausedScout(KeywordJev):
    """A Scout client whose spend cap is reached. Any model call is a test failure."""

    def system_one(self, state, questions):
        raise AssertionError("Scout was called while paused")


class MemoryLoader:
    def __init__(self, old_files, new_files, name="widget"):
        self.meta = ReleaseMeta(
            ecosystem="npm",
            name=name,
            old_version="1.0.0",
            new_version="1.0.1",
            rank=4,
            registry_url=f"https://example.test/{name}",
        )
        self.old_files = old_files
        self.new_files = new_files

    def load(self, ecosystem, name, version, rank):
        return self.old_files, self.new_files, self.meta


@pytest.fixture
def db(tmp_path):
    return Database(tmp_path / "hunter.sqlite3")


@pytest.fixture(autouse=True)
def rules_on(monkeypatch):
    monkeypatch.setenv("HUNTER_RULES", "on")
    pack = load_pack()
    strong = RulePack(pack.compiled, pack.specs, {"eval_fromcharcode_direct": "review"}, pack.version)
    monkeypatch.setattr(engine, "load_pack", lambda: strong)


def _paused(db) -> PausedScout:
    meter = SpendMeter(db, cap_usd=0.01)
    meter.record("jev", "jev-1.13.0", Usage(1_000_000, 0))
    assert meter.stopped()
    scout = PausedScout()
    scout.meter = meter
    return scout


def _bad():
    old = {"package.json": PKG_OLD, "lib/util.js": ORDINARY}
    new = {"package.json": PKG_NEW, "lib/util.js": ORDINARY + HOSTILE_LINE}
    return old, new


def _clean():
    old = {"package.json": PKG_OLD, "lib/util.js": ORDINARY}
    new = {"package.json": PKG_NEW, "lib/util.js": ORDINARY.replace("a + b", "b + a")}
    return old, new


def _run(db, scout, trees, *, name="widget", watched=True, **config):
    if watched:
        db.replace_user_watch_source("api/package-lock.json", "npm-lock", [("npm", name, "1.0.1", 1)])
    cfg = Config(db_path=db.path, webhook_url=HOOK, **config)
    job = {"ecosystem": "npm", "name": name, "version": "1.0.1", "rank": 4}
    classify_job(db, cfg, job, jev=scout, loader=MemoryLoader(*trees, name=name))
    return cfg


def _alerts(db) -> list[dict]:
    return [json.loads(row["body"]) for row in db.due_outbox()]


def test_known_bad_release_sends_a_rules_only_alert(db):
    _run(db, _paused(db), _bad())
    alerts = _alerts(db)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["kind"] == "rules_only_alert"
    assert alert["label"] == "rules-only"
    assert alert["model_reviewed"] is False
    assert "Scout" in alert["notice"]
    assert alert["idempotency_key"] == "npm:widget:1.0.1:rules-only"
    assert alert["watch"]["listed"]
    assert alert["top_rule"].startswith("eval_fromcharcode_direct lib/util.js")
    row = db.get_release("npm", "widget", "1.0.1")
    assert row["band"] in {"review", "alert"}
    assert RULES_ONLY_SIGNAL in json.loads(row["payload_json"])["signals"]
    assert db.public_feed_items(10) == []


def test_slack_format_says_rules_only_up_front(db):
    _run(db, _paused(db), _bad(), webhook_format="slack")
    body = json.loads(db.due_outbox()[0]["body"])
    assert body["text"].startswith("RULES-ONLY alert (not model-reviewed) npm/widget 1.0.1")


def test_clean_release_sends_nothing_and_waits_for_scout(db):
    _run(db, _paused(db), _clean())
    assert _alerts(db) == []
    row = db.get_release("npm", "widget", "1.0.1")
    assert row["band"] == "deferred"
    assert json.loads(row["payload_json"])["defer_reason"] == "spend_cap_reached"


def test_the_free_checks_make_no_scout_call_and_classify_as_incomplete():
    old, new = _bad()
    meta = MemoryLoader(old, new).meta

    class Stopped:
        def stopped(self):
            return True

    scout = PausedScout()
    scout.meter = Stopped()
    row = classify_files(meta=meta, old_files=old, new_files=new, jev=scout, head=load_head())
    assert RULES_ONLY_SIGNAL in row.signals
    assert row.jev_model_id == "rules-only"
    assert row.rule_verdict == "malicious"
    assert classification_incomplete(row)
    assert row.needs_llm_review is False


def test_unwatched_package_does_not_alert(db):
    _run(db, _paused(db), _bad(), watched=False)
    assert _alerts(db) == []


def test_no_webhook_url_means_no_alert(db):
    scout = _paused(db)
    db.replace_user_watch_source("api/package-lock.json", "npm-lock", [("npm", "widget", "1.0.1", 1)])
    job = {"ecosystem": "npm", "name": "widget", "version": "1.0.1", "rank": 4}
    classify_job(db, Config(db_path=db.path), job, jev=scout, loader=MemoryLoader(*_bad()))
    assert _alerts(db) == []


def test_a_second_classify_does_not_post_twice(db):
    scout = _paused(db)
    _run(db, scout, _bad())
    _run(db, scout, _bad())
    assert len(_alerts(db)) == 1


def test_paused_releases_do_not_run_out_of_retries(db):
    scout = _paused(db)
    for _ in range(4):
        _run(db, scout, _clean(), ai_max_attempts=2)
    assert db.get_release("npm", "widget", "1.0.1")["band"] == "deferred"
    retry = db._conn.execute("SELECT status FROM classify_retries WHERE name = 'widget'").fetchone()
    assert retry["status"] == "retrying"


def test_running_scout_takes_the_normal_path(db):
    scout = KeywordJev()
    scout.meter = SpendMeter(db, cap_usd=5.0)
    _run(db, scout, _bad())
    assert scout.calls
    row = db.get_release("npm", "widget", "1.0.1")
    assert RULES_ONLY_SIGNAL not in json.loads(row["payload_json"])["signals"]
    assert all(alert["kind"] != "rules_only_alert" for alert in _alerts(db))


def test_rules_only_alert_posts_through_the_outbox(db):
    _run(db, _paused(db), _bad())
    posts = []
    assert drain_outbox(db, url=HOOK, poster=lambda url, body, headers: posts.append(body)) == 1
    assert json.loads(posts[0])["label"] == "rules-only"
