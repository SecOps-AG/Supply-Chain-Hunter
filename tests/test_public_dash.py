"""Public dashboard JSON, R2 keys, and secret stripping."""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from hunter.config import Config
from hunter.dashboard import release_key
from hunter.db import Database, utcnow
from hunter.public_dash import (
    LIVE_JSON_KEY,
    PUBLIC_SNAPSHOT_TOP_KEYS,
    STREAM_FIELDS,
    STREAM_MAX_EVENTS,
    STREAM_WINDOW_S,
    build_live_document,
    build_live_stream,
    public_snapshot,
    publish_public_dash,
    release_object_key,
    scan_for_secrets,
    stable_live_digest,
)
from hunter.public_feed import allowed_public_object_key, put_feed_object
from tests.test_dashboard import SECRET_ERROR, _seed


@pytest.fixture()
def db(tmp_path):
    database = Database(tmp_path / "hunter.sqlite3")
    _seed(database, utcnow())
    return database


def _dash_config(**overrides):
    base = dict(
        feed_public_base_url="https://alerts.example.com",
        feed_r2_account_id="abc123def456",
        feed_r2_bucket="hunter-public",
        feed_r2_access_key_id="access-key-9f3a",
        feed_r2_secret_access_key="secret-key-9f3a",
        dash_publish=True,
        dash_public_base_url="https://dash-data.example.com",
    )
    base.update(overrides)
    return Config(**base)


def test_public_snapshot_key_set_is_pinned(db):
    config = _dash_config()
    snap = public_snapshot(db, config, started=time.monotonic(), meter=None, range_name="24h")
    assert set(snap.keys()) == PUBLIC_SNAPSHOT_TOP_KEYS
    assert snap["range"] == "24h"
    assert snap["scout"]["flagged"] == 3
    assert snap["confirmed"]["latest"]["name"] == "<b>demo-html</b>"


def test_public_snapshot_never_contains_secrets_or_raw_errors(db):
    config = _dash_config(webhook_url="https://hooks.example.invalid/secret-path", webhook_secret="whsec-abc123456789")
    snap = public_snapshot(db, config, started=time.monotonic(), meter=None, range_name="30d")
    text = json.dumps(snap, default=str)
    assert "secret-path" not in text
    assert "hooks.example.invalid" not in text
    assert "whsec-abc123456789" not in text
    assert SECRET_ERROR not in text
    assert SECRET_ERROR not in json.dumps(snap.get("feeds") or {}, default=str)


def test_public_snapshot_keeps_internals_off_the_public_page(db):
    config = _dash_config()
    for range_name in ("1h", "24h", "7d", "30d"):
        snap = public_snapshot(db, config, started=time.monotonic(), meter=None, range_name=range_name)
        assert set(snap["health"]) <= {"status", "last_successful_poll"}
        assert snap["health"]["status"] == "ok"
        assert "usage" not in snap
        for info in snap["models"].values():
            assert set(info) <= {"label", "role"}
        text = json.dumps({"health": snap["health"], "models": snap["models"]}, default=str)
        for word in (
            "uptime",
            "spend",
            "budget",
            "pending_jobs",
            "human_review",
            "outbox",
            "retries",
            "analyst_queue",
            "investigations",
            "model_id",
            "backend",
            "provider",
            config.scout_model_id(),
        ):
            assert word not in text, word


def test_public_models_keep_only_role_labels():
    from hunter.public_dash import public_health, public_models

    models = {
        "decision_model": {"label": "decision model", "role": "Scout", "provider": "demo", "model": "demo/model-1"},
        "frontier_model": {"label": "Frontier model", "role": "Analyst", "backend": "demo", "model": "demo-2"},
    }
    assert public_models(models) == {
        "decision_model": {"label": "decision model", "role": "Scout"},
        "frontier_model": {"label": "Frontier model", "role": "Analyst"},
    }
    assert public_models(None) == {}
    health = {
        "status": "ok",
        "uptime_seconds": 5.0,
        "pending_jobs": 9,
        "scout_spend_cap_usd": 0.4,
        "scout_spend_stopped": True,
        "triage_budget_limit": 10,
        "human_review_queue": 2,
        "last_successful_poll": {"npm": "2026-10-01T00:00:00Z"},
    }
    assert public_health(health) == {"status": "ok", "last_successful_poll": {"npm": "2026-10-01T00:00:00Z"}}
    assert public_health(None) == {}


def test_stable_digest_ignores_generated_at_and_uptime(db):
    config = _dash_config()
    started = time.monotonic()
    first = build_live_document(db, config, started=started, meter=None)
    second = build_live_document(db, config, started=started + 50, meter=None)
    second["published_at"] = "2099-01-01T00:00:00Z"
    second["snapshots"]["24h"]["generated_at"] = "2099-01-01T00:00:00Z"
    second["snapshots"]["24h"]["health"]["uptime_seconds"] = 99999
    assert stable_live_digest(first) == stable_live_digest(second)


def test_live_document_includes_stage_notes(db):
    config = _dash_config()
    live = build_live_document(db, config, started=time.monotonic(), meter=None)
    rows = live["findings"]["24h"]["triage"]["rows"]
    under_review = [row for row in rows if row.get("public_stage_note") == "under review, not a verdict"]
    assert under_review
    malicious = [row for row in rows if row.get("analyst_verdict") == "malicious"]
    assert malicious and malicious[0]["public_stage_note"].startswith("AI verdict (may be wrong):")


def test_allowed_public_object_keys():
    assert allowed_public_object_key("feed.json")
    assert allowed_public_object_key(LIVE_JSON_KEY)
    assert allowed_public_object_key("live/benchmark.json")
    assert allowed_public_object_key("live/history/2026-10-09.json")
    assert allowed_public_object_key("live/confirmed/2026-10-09.json")
    assert allowed_public_object_key("live/r/npm/demo-pkg/1.0.0.json")
    assert not allowed_public_object_key("live/other.json")
    assert not allowed_public_object_key("../live/live.json")


def test_publish_uploads_live_and_release_objects(db):
    config = _dash_config()
    client = MagicMock()
    moment = utcnow()
    started = time.monotonic()
    assert publish_public_dash(db, config, started=started, meter=None, client=client, now=moment) is True
    keys = {call.kwargs["Key"] for call in client.put_object.call_args_list}
    assert LIVE_JSON_KEY in keys
    assert "live/benchmark.json" in keys
    assert any(key.startswith("live/r/") for key in keys)
    client.put_object.reset_mock()
    assert publish_public_dash(db, config, started=started, meter=None, client=client, now=moment) is False


def test_failed_release_upload_is_retried_next_pass(db):
    config = _dash_config()
    client = MagicMock()
    moment = utcnow()
    started = time.monotonic()
    failed: list[str] = []

    def put_object(**kwargs):
        if kwargs["Key"].startswith("live/r/") and not failed:
            failed.append(kwargs["Key"])
            raise TimeoutError("read timed out")

    client.put_object.side_effect = put_object
    assert publish_public_dash(db, config, started=started, meter=None, client=client, now=moment) is False
    assert failed
    client.put_object.reset_mock()
    assert publish_public_dash(db, config, started=started, meter=None, client=client, now=moment) is True
    keys = [call.kwargs["Key"] for call in client.put_object.call_args_list]
    assert failed[0] in keys
    assert LIVE_JSON_KEY not in keys
    client.put_object.reset_mock()
    assert publish_public_dash(db, config, started=started, meter=None, client=client, now=moment) is False
    assert client.put_object.call_count == 0


def test_live_hash_kept_when_only_a_release_upload_fails(db):
    config = _dash_config()
    client = MagicMock()
    moment = utcnow()

    def put_object(**kwargs):
        if kwargs["Key"].startswith("live/r/"):
            raise TimeoutError("read timed out")

    client.put_object.side_effect = put_object
    assert publish_public_dash(db, config, started=time.monotonic(), meter=None, client=client, now=moment) is False
    state = db.public_dash_state()
    assert state["live_hash"]
    assert state["benchmark_hash"]
    assert "TimeoutError" in (state["last_error"] or "")


def test_release_objects_are_not_cached_as_immutable(db):
    config = _dash_config()
    client = MagicMock()
    assert publish_public_dash(db, config, started=time.monotonic(), meter=None, client=client, now=utcnow()) is True
    release_calls = [c.kwargs for c in client.put_object.call_args_list if c.kwargs["Key"].startswith("live/r/")]
    assert release_calls
    for call in release_calls:
        assert call["CacheControl"] == "public, max-age=60"
        assert "immutable" not in call["CacheControl"]


def test_put_feed_object_refuses_unknown_keys():
    client = MagicMock()
    with pytest.raises(ValueError, match="non-public"):
        put_feed_object(
            client,
            bucket="b",
            key="secrets.env",
            body=b"x",
            content_type="application/json",
            cache_control="public, max-age=0",
        )


def test_dash_configured_requires_feed_and_base_url():
    assert not Config(dash_publish=True).dash_configured()
    assert _dash_config().dash_configured()


def test_scan_for_secrets(db):
    config = _dash_config(webhook_secret="super-secret-token-value")
    live = build_live_document(db, config, started=time.monotonic(), meter=None)
    assert scan_for_secrets(live, config) == []


def test_release_object_key_matches_dashboard(db):
    key = release_key("npm", "<b>x</b>", "1.0.0")
    assert release_object_key("npm", "<b>x</b>", "1.0.0") == f"live/r/npm/{quote_name('<b>x</b>')}/1.0.0.json"


def test_release_keys_keep_unscoped_names_and_fold_slashes_into_one_segment():
    assert release_object_key("pypi", "tox", "4.64.10") == "live/r/pypi/tox/4.64.10.json"
    assert release_object_key("npm", "vite", "8.3.4") == "live/r/npm/vite/8.3.4.json"
    actions = release_object_key("github-actions", "actions/checkout", "v4@0123456789ab")
    scoped = release_object_key("npm", "@malloy-publisher/server", "0.9.5")
    assert actions.split("/") == [
        "live",
        "r",
        "github-actions",
        "actions~checkout",
        "v4%400123456789ab.json",
    ]
    assert scoped.split("/") == ["live", "r", "npm", "%40malloy-publisher~server", "0.9.5.json"]
    for key in (actions, scoped):
        assert "%2F" not in key and "%2f" not in key
        assert allowed_public_object_key(key)
    assert not allowed_public_object_key("live/r/github-actions")
    assert not allowed_public_object_key("../")


def quote_name(name: str) -> str:
    from urllib.parse import quote

    return quote(name.replace("/", "~"), safe="")


def _stream_db(tmp_path, now):
    """Invented releases moving through every stage inside the stream window."""
    database = Database(tmp_path / "stream.sqlite3")
    rows = [
        ("npm", "demo-left", "1.0.0", "benign", 50),
        ("pypi", "demo-right", "2.0.0", "benign", 40),
        ("npm", "demo-flag", "3.0.0", "alert", 30),
        ("npm", "demo-aged", "0.1.0", "benign", 4000),
    ]
    for eco, name, version, band, seconds_ago in rows:
        database.save_release(eco, name, version, band, 0.5, "malicious_intent", None, "{}", when=now - timedelta(seconds=seconds_ago))
    key = "npm:demo-flag:3.0.0"
    database.enqueue_investigation(key, "{}", when=now - timedelta(seconds=29))
    database.mark_investigation_reported(key, "bad\nVerdict: malicious", when=now - timedelta(seconds=20))
    database.enqueue_analyst(key, "{}", when=now - timedelta(seconds=19))
    database.mark_analyst_reported(key, "bad\nVerdict: malicious", "malicious", None, when=now - timedelta(seconds=10))
    database.enqueue(key + ":analysis", "{}", when=now - timedelta(seconds=9))
    database.enqueue("decision-model-down:2026-10-01", "{}", when=now - timedelta(seconds=9))
    for row in database.due_outbox(when=now):
        database.mark_sent(row["id"], when=now - timedelta(seconds=8))
    # Queued long ago, reported inside the window: the verdict still counts.
    old = "pypi:demo-slow:1.0.0"
    database.enqueue_investigation(old, "{}", when=now - timedelta(hours=2))
    database.mark_investigation_reported(old, "ok\nVerdict: benign", when=now - timedelta(seconds=5))
    database.mark_poll_success("npm", when=now - timedelta(seconds=15))
    database.mark_poll_success("pypi", when=now - timedelta(seconds=600))
    return database


def test_live_stream_lists_real_events_in_time_order(tmp_path):
    now = datetime(2026, 10, 11, 7, 30, tzinfo=timezone.utc)
    database = _stream_db(tmp_path, now)
    stream = build_live_stream(database, _dash_config(poll_interval=120.0), now=now)
    assert stream["v"] == 1
    assert stream["fields"] == list(STREAM_FIELDS)
    assert stream["until"] == "2026-10-11T07:30:00Z"
    assert stream["window_s"] == STREAM_WINDOW_S
    assert stream["poll_interval_s"] == 120
    assert stream["truncated"] is False
    base = int(now.timestamp())
    got = [(ev[0] - base, ev[1], ev[3], ev[5]) for ev in stream["events"]]
    assert got == [
        (-50, "scan", "demo-left", "benign"),
        (-40, "scan", "demo-right", "benign"),
        (-30, "scan", "demo-flag", "alert"),
        (-29, "triage_in", "demo-flag", None),
        (-20, "triage", "demo-flag", "malicious"),
        (-19, "analyst_in", "demo-flag", None),
        (-15, "poll", None, None),
        (-10, "analyst", "demo-flag", "malicious"),
        (-8, "alert", "demo-flag", "sent"),
        (-5, "triage", "demo-slow", "benign"),
    ]
    times = [ev[0] for ev in stream["events"]]
    assert times == sorted(times)


def test_live_stream_keeps_newest_events_when_capped(tmp_path, monkeypatch):
    now = datetime(2026, 10, 11, 7, 30, tzinfo=timezone.utc)
    database = Database(tmp_path / "cap.sqlite3")
    for index in range(12):
        database.save_release("npm", f"demo-{index:02d}", "1.0.0", "benign", 0.1, "none", None, "{}", when=now - timedelta(seconds=60 - index))
    monkeypatch.setattr("hunter.public_dash.STREAM_MAX_EVENTS", 5)
    stream = build_live_stream(database, _dash_config(), now=now)
    assert stream["truncated"] is True
    assert [ev[3] for ev in stream["events"]] == [f"demo-{index:02d}" for index in range(7, 12)]


def test_live_stream_stays_small_at_full_cap(tmp_path):
    now = datetime(2026, 10, 11, 7, 30, tzinfo=timezone.utc)
    database = Database(tmp_path / "size.sqlite3")
    for index in range(STREAM_MAX_EVENTS + 20):
        name = f"@demo-scope/synthetic-package-{index:04d}"
        database.save_release("npm", name, "10.20.30", "benign", 0.1, "none", None, "{}", when=now - timedelta(seconds=index % 170))
    stream = build_live_stream(database, _dash_config(), now=now)
    assert len(stream["events"]) == STREAM_MAX_EVENTS
    assert stream["truncated"] is True
    assert len(json.dumps(stream, separators=(",", ":"))) < 32_000


def test_live_document_stream_is_sanitized(tmp_path):
    now = utcnow()
    database = Database(tmp_path / "secret.sqlite3")
    database.save_release("npm", "leak-whsec-abc123456789", "1.0.0", "benign", 0.1, "none", None, "{}", when=now - timedelta(seconds=5))
    database.save_release("npm", "<img src=x>", "1.0.0", "benign", 0.1, "none", None, "{}", when=now - timedelta(seconds=4))
    config = _dash_config(webhook_secret="whsec-abc123456789")
    live = build_live_document(database, config, started=time.monotonic(), meter=None, now=now)
    names = [ev[3] for ev in live["stream"]["events"] if ev[1] == "scan"]
    assert names == ["[redacted]", "<img src=x>"]
    assert scan_for_secrets(live, config) == []


def test_live_stream_scans_match_snapshot_totals(tmp_path):
    now = datetime(2026, 10, 11, 7, 30, tzinfo=timezone.utc)
    database = _stream_db(tmp_path, now)
    live = build_live_document(database, _dash_config(), started=time.monotonic(), meter=None, now=now)
    scans = [ev for ev in live["stream"]["events"] if ev[1] == "scan"]
    snap = live["snapshots"]["1h"]
    # Everything in the 1h range is in the stream except the release outside the window.
    assert snap["scanned"]["total"] == len(scans)
    assert snap["triage"]["total"] == len([ev for ev in live["stream"]["events"] if ev[1] == "triage_in"])
    assert snap["analyst"]["total"] == len([ev for ev in live["stream"]["events"] if ev[1] == "analyst_in"])
    assert snap["webhook"]["alerts_sent"] == len([ev for ev in live["stream"]["events"] if ev[1] == "alert"])


def test_config_reads_dash_env(monkeypatch):
    monkeypatch.setenv("HUNTER_DASH_PUBLISH", "on")
    monkeypatch.setenv("HUNTER_DASH_PUBLIC_BASE_URL", "https://dash.example.com")
    config = Config.from_env()
    assert config.dash_publish is True
    assert config.dash_public_base_url == "https://dash.example.com"
