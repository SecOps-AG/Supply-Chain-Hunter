"""Public feed: allowlisted rows, JSON Feed, RSS, and R2 uploads."""

import json
import logging
import sys
import types
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from hunter.config import Config
from hunter.db import Database
from hunter.investigate import drain_analyst, drain_investigations
from hunter.public_dash import release_object_key
from hunter.public_feed import (
    FEED_DESCRIPTION,
    JSON_FEED_VERSION,
    allowed_public_object_key,
    make_r2_client,
    public_registry_url,
    publish_public_feed,
    put_feed_object,
    record_public_alert,
    render_json_feed,
    render_rss,
)
from hunter.service import drain_until_idle, health_payload
from hunter.teach import run_teach, write_axios_distillation

EARLY = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
LATE = datetime(2026, 3, 4, 5, 6, 7, tzinfo=timezone.utc)
PROMPT = "PROMPT-SENTINEL-do-not-publish"
DIFF = "DIFF-SENTINEL-ak_live_secret"
ESSAY = "ANALYSIS-SENTINEL-model-essay"
SIGNAL = "phantom_runtime_dependency:codec-pad"
CHILD = "CHILD-SENTINEL-dropper"
MODEL = "jev-secret-model-9f3a"
SCORE = "0.6180339887"
WEBHOOK = "https://hooks.example/super-secret-token"
PARTIAL = "triage_diff_cut"


def _evidence(**overrides) -> dict:
    evidence = {
        "idempotency_key": "npm:color-hex-pad:2.4.1",
        "task": PROMPT,
        "constraints": ["Do not include environment secrets in the report."],
        "primary_band": "review",
        "malice_probability": 0.6180339887,
        "jev_complete": True,
        "jev_model_id": MODEL,
        "ecosystem": "npm",
        "package": "color-hex-pad",
        "old_version": "2.4.0",
        "new_version": "2.4.1",
        "registry_url": "https://www.npmjs.com/package/color-hex-pad/v/2.4.1",
        "attack_family": "install_hook",
        "suspected_cause": "poisoned_install_script",
        "signals": [SIGNAL, "partial_read", PARTIAL],
        "child_findings": [{"detail": CHILD}],
        "diff_excerpt": DIFF,
        "full_diff": DIFF + " full",
        "rank": 424242,
        "analysis": ESSAY,
        "triage_report": ESSAY,
        "webhook": WEBHOOK,
    }
    evidence.update(overrides)
    return evidence


def _feed_config(**overrides) -> Config:
    values = dict(
        feed_public_base_url="https://alerts.example.com",
        feed_r2_account_id="abc123",
        feed_r2_bucket="hunter-alerts",
        feed_r2_access_key_id="access-key-9f3a",
        feed_r2_secret_access_key="secret-key-9f3a",
        feed_cache_max_age=60,
        feed_limit=200,
        feed_title="Supply Chain Hunter alerts",
    )
    values.update(overrides)
    return Config(**values)


class FakeR2:
    def __init__(self, fail_on: str = ""):
        self.calls = []
        self.fail_on = fail_on

    def put_object(self, **kwargs):
        if self.fail_on and kwargs.get("Key") == self.fail_on:
            raise RuntimeError(f"signature secret-key-9f3a rejected for {kwargs.get('Key')}")
        self.calls.append(kwargs)


def _bodies(client: FakeR2) -> dict[str, bytes]:
    return {call["Key"]: call["Body"] for call in client.calls}


def test_registry_url_allowlist():
    assert public_registry_url("npm", "https://www.npmjs.com/package/left-pad/v/1.0.0").endswith("1.0.0")
    assert public_registry_url("pypi", "https://pypi.org/project/requests/2.0.0/")
    assert public_registry_url("npm", "https://pypi.org/project/requests/2.0.0/") == ""
    assert public_registry_url("pypi", "https://www.npmjs.com/package/left-pad/v/1.0.0") == ""
    assert public_registry_url("npm", "https://www.npmjs.com.evil.example/package/left-pad") == ""
    assert public_registry_url("npm", "http://www.npmjs.com/package/left-pad/v/1.0.0") == ""
    assert public_registry_url("npm", "https://user:pass@www.npmjs.com/package/left-pad") == ""
    assert public_registry_url("npm", "https://www.npmjs.com/package/left-pad\nhttps://evil.example") == ""


def test_duplicate_version_keeps_the_first_confirmation_time(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    assert record_public_alert(db, _evidence(), when=EARLY) is True
    assert record_public_alert(db, _evidence(old_version="9.9.9"), when=LATE) is False
    rows = db.public_feed_items(10)
    assert len(rows) == 1
    assert rows[0]["first_seen_at"] == "2026-01-02T03:04:05Z"
    assert rows[0]["previous_version"] == "2.4.0"


def test_rendered_feeds_omit_private_evidence(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    nasty = _evidence(package="a&b<c>", new_version="1.0", registry_url="https://evil.example/pkg")
    assert record_public_alert(db, nasty, when=LATE)
    assert record_public_alert(
        db,
        _evidence(
            ecosystem="pypi",
            package="requests",
            new_version="2.0.0",
            old_version="1.9.0",
            registry_url="https://pypi.org/project/requests/2.0.0/",
            attack_family="made_up",
            suspected_cause="unknown",
            signals=[],
        ),
        when=EARLY,
    )
    rows = db.public_feed_items(10)
    json_body = render_json_feed(rows, base_url="https://alerts.example.com", title="Supply Chain Hunter alerts")
    xml_body = render_rss(rows, base_url="https://alerts.example.com", title="Supply Chain Hunter alerts")
    combined = json_body.decode() + xml_body.decode()
    for secret in (PROMPT, DIFF, ESSAY, SIGNAL, CHILD, MODEL, SCORE, WEBHOOK, PARTIAL, "partial_read", "424242"):
        assert secret not in combined
    assert "evil.example" not in combined
    document = json.loads(json_body)
    assert document["version"] == JSON_FEED_VERSION
    assert document["title"] == "Supply Chain Hunter alerts"
    assert document["home_page_url"].startswith("https://github.com/")
    assert document["feed_url"] == "https://alerts.example.com/feed.json"
    assert document["description"] == FEED_DESCRIPTION
    assert document["items"][0]["id"] == "npm:a&b<c>:1.0"
    assert document["items"][0]["date_published"] == "2026-03-04T05:06:07Z"
    assert "url" not in document["items"][0]
    assert "was marked malicious" in document["items"][0]["content_text"]
    assert "Behavior: A lifecycle script" in document["items"][0]["content_text"]
    assert "Cause: An install script" in document["items"][0]["content_text"]
    assert "Hunter did not read the entire release." in document["items"][0]["content_text"]
    assert "Behavior:" not in document["items"][1]["content_text"]
    assert document["items"][1]["id"] == "pypi:requests:2.0.0"
    assert document["items"][1]["url"] == "https://pypi.org/project/requests/2.0.0/"
    assert document["items"][1]["tags"] == ["pypi"]
    assert "install_hook" in document["items"][0]["tags"]
    root = ET.fromstring(xml_body)
    channel = root.find("channel")
    atom = "{http://www.w3.org/2005/Atom}link"
    self_link = channel.find(atom)
    assert self_link.attrib["href"] == "https://alerts.example.com/feed.xml"
    assert self_link.attrib["rel"] == "self"
    items = channel.findall("item")
    assert items[0].find("guid").attrib["isPermaLink"] == "false"
    assert items[0].find("guid").text == "npm:a&b<c>:1.0"
    assert items[0].find("link") is None
    assert "a&amp;b&lt;c&gt;" in xml_body.decode()
    assert items[1].find("link").text == "https://pypi.org/project/requests/2.0.0/"
    assert "Malicious PyPI package: requests 2.0.0" in items[1].find("title").text
    assert "Malicious npm package: a&b<c> 1.0" in items[0].find("title").text


def test_empty_feed_uploads_once_then_skips_until_the_bytes_change(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    client = FakeR2()
    config = _feed_config()
    assert publish_public_feed(db, config, client=client) is True
    assert [call["Key"] for call in client.calls] == ["feed.json", "feed.xml"]
    assert client.calls[0]["ContentType"] == "application/feed+json; charset=utf-8"
    assert client.calls[1]["ContentType"] == "application/rss+xml; charset=utf-8"
    assert client.calls[0]["CacheControl"] == "public, max-age=60"
    assert json.loads(client.calls[0]["Body"])["items"] == []
    ET.fromstring(client.calls[1]["Body"])
    assert publish_public_feed(db, config, client=client) is False
    assert len(client.calls) == 2
    record_public_alert(db, _evidence(), when=LATE)
    assert publish_public_feed(db, _feed_config(feed_cache_max_age=15, feed_title="Alerts"), client=client) is True
    assert len(client.calls) == 4
    assert client.calls[2]["CacheControl"] == "public, max-age=15"
    assert json.loads(client.calls[2]["Body"])["title"] == "Alerts"
    assert publish_public_feed(db, _feed_config(feed_cache_max_age=30, feed_title="Alerts"), client=client) is True
    assert client.calls[-1]["CacheControl"] == "public, max-age=30"
    state = db.public_feed_state()
    assert state["content_hash"]
    assert state["last_error"] is None
    assert state["published_at"]


def test_failed_upload_keeps_the_hash_unset_and_redacts_the_secret(tmp_path, caplog):
    db = Database(tmp_path / "hunter.sqlite3")
    config = _feed_config()
    record_public_alert(db, _evidence(), when=LATE)
    client = FakeR2(fail_on="feed.xml")
    with caplog.at_level(logging.WARNING, logger="hunter.public_feed"):
        assert publish_public_feed(db, config, client=client) is False
    assert [call["Key"] for call in client.calls] == ["feed.json"]
    state = db.public_feed_state()
    assert state["content_hash"] is None
    assert state["published_at"] is None
    assert "secret-key-9f3a" not in state["last_error"]
    assert "secret-key-9f3a" not in caplog.text
    assert "[redacted]" in state["last_error"]
    health = health_payload(db, 0.0, config=config)
    assert health["feed_last_published_at"] is None
    assert "secret-key-9f3a" not in (health["feed_last_error"] or "")
    client.fail_on = ""
    assert publish_public_feed(db, config, client=client) is True
    state = db.public_feed_state()
    assert state["content_hash"]
    assert state["last_error"] is None
    assert health_payload(db, 0.0, config=config)["feed_last_error"] is None


def test_incomplete_feed_env_does_not_upload(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    client = FakeR2()
    record_public_alert(db, _evidence(), when=LATE)
    assert publish_public_feed(db, Config(), client=client) is False
    assert publish_public_feed(db, _feed_config(feed_r2_secret_access_key=""), client=client) is False
    assert client.calls == []


def test_uploader_refuses_any_other_object_key():
    client = FakeR2()
    try:
        put_feed_object(
            client,
            bucket="hunter-alerts",
            key="notes.txt",
            body=b"secret",
            content_type="text/plain",
            cache_control="no-store",
        )
    except ValueError as exc:
        assert "non-public" in str(exc)
    else:
        raise AssertionError("expected a refusal")
    assert client.calls == []


def test_r2_client_uses_the_auto_region(monkeypatch):
    captured = {}
    module = types.ModuleType("boto3")

    def client(name, **kwargs):
        captured["name"] = name
        captured["kwargs"] = kwargs
        return object()

    module.client = client
    monkeypatch.setitem(sys.modules, "boto3", module)
    make_r2_client(_feed_config())
    assert captured["name"] == "s3"
    assert captured["kwargs"]["region_name"] == "auto"
    assert captured["kwargs"]["endpoint_url"] == "https://abc123.r2.cloudflarestorage.com"
    assert captured["kwargs"]["aws_secret_access_key"] == "secret-key-9f3a"


def test_r2_client_timeout_bounds_each_request(monkeypatch):
    captured = {}
    boto3 = types.ModuleType("boto3")
    boto3.client = lambda name, **kwargs: captured.update(kwargs) or object()
    botocore = types.ModuleType("botocore")
    botocore_config = types.ModuleType("botocore.config")
    botocore_config.Config = lambda **kwargs: kwargs
    monkeypatch.setitem(sys.modules, "boto3", boto3)
    monkeypatch.setitem(sys.modules, "botocore", botocore)
    monkeypatch.setitem(sys.modules, "botocore.config", botocore_config)
    make_r2_client(_feed_config(), timeout=5.0)
    assert captured["config"]["connect_timeout"] == 5.0
    assert captured["config"]["read_timeout"] == 5.0
    captured.clear()
    make_r2_client(_feed_config())
    assert "config" not in captured


def test_feed_limit_keeps_older_rows_in_sqlite_only(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    record_public_alert(db, _evidence(package="older", new_version="1"), when=EARLY)
    record_public_alert(db, _evidence(package="newer", new_version="2"), when=LATE)
    client = FakeR2()
    assert publish_public_feed(db, _feed_config(feed_limit=1), client=client) is True
    items = json.loads(_bodies(client)["feed.json"])["items"]
    assert [item["id"] for item in items] == ["npm:newer:2"]
    assert len(db.public_feed_items(10)) == 2


def test_analyst_confirmation_is_recorded_without_a_webhook_and_stays_out_of_the_essay(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    evidence = _evidence()
    assert db.enqueue_analyst(evidence["idempotency_key"], json.dumps(evidence))
    config = Config(db_path=db.path, analyst_model="m", webhook_url="")
    assert drain_analyst(db, config=config, runner=lambda _p, _b: ESSAY + "\nVerdict: malicious") == 1
    assert db.outbox_depth() == 0
    rows = db.public_feed_items(10)
    assert len(rows) == 1
    assert rows[0]["behavior"] == "install_hook"
    assert rows[0]["limited_review"] == 1
    rendered = render_json_feed(rows, base_url="https://alerts.example.com", title="Alerts").decode()
    xml = render_rss(rows, base_url="https://alerts.example.com", title="Alerts").decode()
    assert ESSAY not in rendered
    assert ESSAY not in xml
    assert SIGNAL not in rendered
    assert "Hunter did not read the entire release." in rendered


def test_analyst_confirmation_still_enqueues_the_private_webhook(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    evidence = _evidence()
    assert db.enqueue_analyst(evidence["idempotency_key"], json.dumps(evidence))
    config = Config(db_path=db.path, analyst_model="m", webhook_url="https://alerts.example/hook")
    assert drain_analyst(db, config=config, runner=lambda _p, _b: ESSAY + "\nVerdict: malicious") == 1
    assert len(db.public_feed_items(10)) == 1
    queued = db.due_outbox()
    assert len(queued) == 1
    assert ESSAY in queued[0]["body"]
    assert SIGNAL in queued[0]["body"]


def test_benign_and_unconfirmed_triage_do_not_record(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    evidence = _evidence()
    assert db.enqueue_analyst(evidence["idempotency_key"], json.dumps(evidence))
    assert drain_analyst(db, config=Config(db_path=db.path, analyst_model="m"), runner=lambda _p, _b: "Verdict: benign") == 1
    assert db.public_feed_items(10) == []

    blocked = _evidence(signals=["jev_unavailable"])
    assert db.enqueue_investigation(blocked["idempotency_key"], json.dumps(blocked))
    assert (
        drain_investigations(
            db,
            config=Config(db_path=db.path, analyst=False, webhook_url="https://alerts.example/hook"),
            runner=lambda _p, _b: "Verdict: malicious",
        )
        == 1
    )
    assert db.public_feed_items(10) == []
    assert db.outbox_depth() == 0


def test_triage_confirmation_records_when_analyst_is_off(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    waiting = _evidence(package="waits-for-analyst", new_version="1.0.0")
    assert db.enqueue_investigation(waiting["idempotency_key"], json.dumps(waiting))
    assert (
        drain_investigations(
            db,
            config=Config(db_path=db.path, analyst=True),
            runner=lambda _p, _b: ESSAY + "\nVerdict: malicious",
        )
        == 1
    )
    assert db.public_feed_items(10) == []

    confirmed = _evidence(package="triage-only", new_version="3.0.0")
    assert db.enqueue_investigation("npm:triage-only:3.0.0", json.dumps(confirmed))
    assert (
        drain_investigations(
            db,
            config=Config(db_path=db.path, analyst=False, webhook_url=""),
            runner=lambda _p, _b: ESSAY + "\nVerdict: malicious",
        )
        == 1
    )
    rows = db.public_feed_items(10)
    assert [row["name"] for row in rows] == ["triage-only"]
    assert db.outbox_depth() == 0
    rendered = render_json_feed(rows, base_url="https://alerts.example.com", title="Alerts").decode()
    assert ESSAY not in rendered


def test_idle_drain_asks_the_publisher_once(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr("hunter.service.publish_public_feed", lambda db, config: calls.append(1) or False)
    db = Database(tmp_path / "hunter.sqlite3")
    drain_until_idle(db, Config(), jev=None, loader=None)
    assert calls == [1]


def test_actions_release_key_is_allowlisted_without_an_encoded_slash():
    assert release_object_key("pypi", "tox", "4.64.10") == "live/r/pypi/tox/4.64.10.json"
    assert release_object_key("npm", "vite", "8.3.4") == "live/r/npm/vite/8.3.4.json"
    actions = release_object_key("github-actions", "actions/checkout", "v4@0123456789ab")
    scoped = release_object_key("npm", "@malloy-publisher/server", "0.9.5")
    assert actions.count("/") == 4
    assert "~" in actions and "%40" in actions
    assert "%2F" not in actions and "%2f" not in actions
    assert "%2F" not in scoped and "%2f" not in scoped
    assert scoped.split("/")[3] == "%40malloy-publisher~server"
    assert allowed_public_object_key(actions)
    assert allowed_public_object_key(scoped)
    assert not allowed_public_object_key("live/r/github-actions")
    assert not allowed_public_object_key("../")


def test_health_reports_an_unpublished_feed(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    body = health_payload(db, 0.0, config=Config())
    assert body["feed_last_published_at"] is None
    assert body["feed_last_error"] is None


def test_feed_settings_from_env(monkeypatch):
    for name in (
        "HUNTER_FEED_PUBLIC_BASE_URL",
        "HUNTER_FEED_R2_ACCOUNT_ID",
        "HUNTER_FEED_R2_BUCKET",
        "HUNTER_FEED_R2_ACCESS_KEY_ID",
        "HUNTER_FEED_R2_SECRET_ACCESS_KEY",
        "HUNTER_FEED_LIMIT",
        "HUNTER_FEED_CACHE_MAX_AGE",
        "HUNTER_FEED_TITLE",
    ):
        monkeypatch.delenv(name, raising=False)
    assert Config.from_env().feed_configured() is False
    monkeypatch.setenv("HUNTER_FEED_PUBLIC_BASE_URL", "https://alerts.example.com/")
    monkeypatch.setenv("HUNTER_FEED_R2_ACCOUNT_ID", "abc123")
    monkeypatch.setenv("HUNTER_FEED_R2_BUCKET", "hunter-alerts")
    monkeypatch.setenv("HUNTER_FEED_R2_ACCESS_KEY_ID", "access-key-9f3a")
    monkeypatch.setenv("HUNTER_FEED_R2_SECRET_ACCESS_KEY", "secret-key-9f3a")
    monkeypatch.setenv("HUNTER_FEED_LIMIT", "5000")
    monkeypatch.setenv("HUNTER_FEED_CACHE_MAX_AGE", "0")
    monkeypatch.setenv("HUNTER_FEED_TITLE", " Hunter\nfeed ")
    config = Config.from_env()
    assert config.feed_configured() is True
    assert config.feed_public_base_url == "https://alerts.example.com"
    assert config.feed_limit == 1000
    assert config.feed_cache_max_age == 0
    assert config.feed_title == "Hunter feed"
    assert "secret-key-9f3a" not in repr(config)
    assert "access-key-9f3a" not in repr(config)
    monkeypatch.setenv("HUNTER_FEED_PUBLIC_BASE_URL", "http://alerts.example.com")
    assert Config.from_env().feed_public_base_url == ""
    assert Config.from_env().feed_configured() is False
    monkeypatch.setenv("HUNTER_FEED_PUBLIC_BASE_URL", "https://alerts.example.com/feed.json")
    assert Config.from_env().feed_public_base_url == ""
    monkeypatch.setenv("HUNTER_FEED_PUBLIC_BASE_URL", "https://user:pass@alerts.example.com")
    assert Config.from_env().feed_public_base_url == ""
    monkeypatch.setenv("HUNTER_FEED_PUBLIC_BASE_URL", "https://abc123.r2.cloudflarestorage.com")
    assert Config.from_env().feed_public_base_url == ""
    monkeypatch.setenv("HUNTER_FEED_PUBLIC_BASE_URL", "https://alerts.example.com")
    monkeypatch.setenv("HUNTER_FEED_R2_ACCOUNT_ID", "abc/123")
    assert Config.from_env().feed_r2_account_id == ""
    assert Config.from_env().feed_configured() is False
    monkeypatch.setenv("HUNTER_FEED_R2_ACCOUNT_ID", "abc123")
    monkeypatch.setenv("HUNTER_FEED_R2_SECRET_ACCESS_KEY", "bad/secret+key=")
    assert Config.from_env().feed_r2_secret_access_key == "bad/secret+key="
    assert Config.from_env().feed_configured() is True
    monkeypatch.setenv("HUNTER_FEED_R2_SECRET_ACCESS_KEY", "secret-key-9f3a")
    monkeypatch.setenv("HUNTER_FEED_LIMIT", "0")
    monkeypatch.setenv("HUNTER_FEED_CACHE_MAX_AGE", "-5")
    config = Config.from_env()
    assert config.feed_limit == 200
    assert config.feed_cache_max_age == 60


def test_teach_does_not_record_a_public_feed_row(tmp_path, monkeypatch):
    recorded = []

    def _spy(*_args, **_kwargs):
        recorded.append(1)
        return False

    monkeypatch.setattr("hunter.investigate.record_public_alert", _spy)
    monkeypatch.setattr("hunter.public_feed.record_public_alert", _spy)
    monkeypatch.setattr("hunter.public_feed.publish_public_feed", _spy)
    monkeypatch.setattr("hunter.service.publish_public_feed", _spy)
    monkeypatch.setenv("HUNTER_DB", str(tmp_path / "hunter.sqlite3"))
    monkeypatch.setenv("HUNTER_FEED_PUBLIC_BASE_URL", "https://alerts.example.com")
    monkeypatch.setenv("HUNTER_FEED_R2_ACCOUNT_ID", "abc123")
    monkeypatch.setenv("HUNTER_FEED_R2_BUCKET", "hunter-alerts")
    monkeypatch.setenv("HUNTER_FEED_R2_ACCESS_KEY_ID", "access-key-9f3a")
    monkeypatch.setenv("HUNTER_FEED_R2_SECRET_ACCESS_KEY", "secret-key-9f3a")
    monkeypatch.setenv("ALERT_WEBHOOK_URL", "https://alerts.example/hook")
    monkeypatch.chdir(tmp_path)
    root = write_axios_distillation(tmp_path / "trees")
    result = run_teach(root, max_rounds=1, out_dir=tmp_path / "out", mode="mock")
    assert result["would_alert"] is True
    assert result["alert_sent"] is False
    assert recorded == []
    assert not (tmp_path / "hunter.sqlite3").exists()


def test_a_user_watchlist_blocks_the_public_feed(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    client = FakeR2()
    record_public_alert(db, _evidence(), when=LATE)
    db.add_user_watch("npm", "private-internal-lib")
    assert publish_public_feed(db, _feed_config(), client=client) is False
    assert client.calls == []
    assert db.public_feed_state()["last_error"] == "disabled: private watchlist present"
    assert health_payload(db, 0.0, config=_feed_config())["feed_last_error"] == "disabled: private watchlist present"
    db.remove_user_watch_name("npm", "private-internal-lib")
    assert publish_public_feed(db, _feed_config(), client=client) is True


def test_watched_mode_blocks_the_public_feed_even_with_an_empty_list(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    client = FakeR2()
    assert publish_public_feed(db, _feed_config(watch_mode="watched"), client=client) is False
    assert client.calls == []
    assert publish_public_feed(db, _feed_config(), client=client) is True
