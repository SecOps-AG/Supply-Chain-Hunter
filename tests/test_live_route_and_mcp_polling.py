"""Live route ecosystems, model outage tracking, and MCP polling bounds. Synthetic data only."""

from __future__ import annotations

import json
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from hunter.config import Config
from hunter.db import Database, utcnow
from hunter.mcp_risk import _registry_signals
from hunter.mcp_tools import extract_tools
from hunter.models import Classification
from hunter.public_feed import ECOSYSTEMS
from hunter.service import MODEL_DOWN_SIGNAL, note_decision_model_health, poll_mcp_and_catchup

ROOT = Path(__file__).resolve().parent.parent
LIVE_FN = ROOT / "public_dashboard" / "functions" / "live" / "[[path]].js"
REG = "https://registry.example"


def test_live_route_serves_every_public_ecosystem():
    src = LIVE_FN.read_text(encoding="utf-8")
    listed = re.search(r"r\\/\(\?:([a-z|-]+)\)", src).group(1).split("|")
    assert set(listed) == set(ECOSYSTEMS)


def _row(*, down: bool, model: str) -> Classification:
    return Classification(
        ecosystem="crates",
        name="widget",
        old_version="1.0.0",
        new_version="1.0.1",
        rank=None,
        registry_url="https://example.test/widget",
        band="deferred" if down else "benign",
        defer_reason="jev_unavailable" if down else "",
        malice_probability=0.0,
        jev_model_id=model,
        signals=[MODEL_DOWN_SIGNAL] if down else [],
    )


def test_a_deterministic_row_does_not_end_a_model_outage(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = Config(db_path=db.path)
    start = utcnow()
    note_decision_model_health(db, config, _row(down=True, model="jev-1"), now=start)
    note_decision_model_health(db, config, _row(down=False, model="deterministic"), now=start + timedelta(seconds=5))
    assert db.clear_decision_model_outage() is not None


class Http:
    def __init__(self, routes):
        self.routes = routes
        self.calls: list[str] = []

    def __call__(self, url, timeout=60.0):
        self.calls.append(url)
        return json.dumps(self.routes[url]).encode()


def test_mcp_risk_reads_only_two_version_documents():
    server = "io.example/s"
    entries = []
    routes = {}
    for minor in range(40):
        version = f"1.{minor}.0"
        doc = {
            "server": {
                "name": server,
                "version": version,
                "packages": [{"registryType": "npm", "identifier": "s", "version": version}],
            },
            "_meta": {"io.modelcontextprotocol.registry/official": {"publishedAt": f"2026-01-01T00:{minor:02d}:00Z"}},
        }
        entries.append(doc)
        routes[f"{REG}/v0.1/servers/io.example%2Fs/versions/{version}"] = doc
    routes[f"{REG}/v0.1/servers/io.example%2Fs/versions"] = {"servers": entries, "metadata": {}}
    http = Http(routes)
    config = SimpleNamespace(mcp_registry_url=REG)
    _registry_signals(config, SimpleNamespace(transport=http), "npm", "s", "1.39.0", server)
    assert len(http.calls) <= 3


def test_unbalanced_tool_calls_do_not_scan_quadratically():
    text = "registerTool( {" * 4000
    start = time.monotonic()
    extract_tools({"package/index.js": text})
    assert time.monotonic() - start < 2.0


def test_first_mcp_poll_does_not_read_every_package(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = Config(
        db_path=db.path,
        mcp_registry_url=REG,
        mcp_registry=True,
        npm_registry="https://npm.example",
        smart_analysis=False,
    )
    servers = [
        {
            "server": {"name": f"a/s{i}", "version": "1.0.0", "packages": [{"registryType": "npm", "identifier": f"mcp-{i}"}]},
            "_meta": {"io.modelcontextprotocol.registry/official": {"status": "active", "updatedAt": "2026-10-01T00:00:00Z"}},
        }
        for i in range(25)
    ]
    reads: list[str] = []

    def transport(url, timeout):
        if "/v0.1/servers" in url:
            return json.dumps({"servers": servers, "metadata": {}}).encode()
        reads.append(url)
        return json.dumps({"time": {"1.0.0": "2020-01-01T00:00:00.000Z"}}).encode()

    poll_mcp_and_catchup(db, config, transport)
    assert db.mcp_counts()["npm"] == 25
    assert reads == []
