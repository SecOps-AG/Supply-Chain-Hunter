import json
import time
import urllib.request

from hunter.config import Config
from hunter.db import Database
from hunter.service import start_health


def test_health_reports_uptime_poll_outbox_and_model(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    db.mark_poll_success("pypi")
    config = Config(bind="127.0.0.1", port=0, jev_model="jev-1.13.0")
    started = time.monotonic()
    server = start_health(config, db, started)
    try:
        port = server.server_address[1]
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=5) as response:
            body = json.load(response)
    finally:
        server.shutdown()
    assert body["status"] == "ok"
    assert body["jev_model_id"] == "jev-1.13.0"
    assert body["outbox_depth"] == 0
    assert body["uptime_seconds"] >= 0
    assert body["last_successful_poll"]["pypi"]
    assert body["last_successful_poll"]["npm"] is None
    assert body["feed_last_published_at"] is None
    assert body["feed_last_error"] is None
    assert body["dash_last_published_at"] is None
    assert body["dash_last_error"] is None
