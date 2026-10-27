"""MCP registry watchlist source and Open VSX monitoring. Every HTTP call is a fake."""

from __future__ import annotations

import io
import json
import zipfile
from urllib.parse import parse_qs, urlsplit

import pytest

from datetime import datetime, timedelta, timezone

from hunter.cli import main
from hunter.config import Config
from hunter.db import Database
from hunter.mcp_registry import package_name, poll_mcp_registry, server_packages
from hunter.openvsx import ECOSYSTEM, pick_platform, release_name
from hunter.openvsx.feed import CHECKPOINT, SINCE_PREFIX, poll_openvsx
from hunter.models import RuleHit, RuleReport
from hunter.openvsx.review import manifest_signals, predecessor, routes, scout_reads, version_api_url
from hunter.public_feed import PublicAlert, alert_title, public_registry_url
from hunter.registry import FeedError
from hunter.rules.registry import load_pack
from hunter.service import (
    ReleaseLoader,
    _poll_mcp_registry_safely,
    classify_job,
    health_payload,
    poll_mcp_and_catchup,
    poll_npm,
    poll_pypi,
    run_cycle,
)

MCP = "https://mcp.example"
VSX = "https://vsx.example"


def _config(tmp_path, **extra) -> Config:
    base = {
        "db_path": tmp_path / "hunter.sqlite3",
        "mcp_registry_url": MCP,
        "openvsx_url": VSX,
        "smart_analysis": False,
    }
    base.update(extra)
    return Config(**base)


def _query(url: str) -> dict[str, str]:
    return {key: values[0] for key, values in parse_qs(urlsplit(url).query).items()}


# --- config -------------------------------------------------------------------


def test_both_sources_are_off_by_default(monkeypatch):
    for name in ("HUNTER_MCP_REGISTRY", "HUNTER_OPENVSX", "HUNTER_OPENVSX_SCOUT"):
        monkeypatch.delenv(name, raising=False)
    config = Config.from_env()
    assert config.mcp_registry is False
    assert config.openvsx is False
    assert config.openvsx_scout is False
    assert config.mcp_poll_interval == 3600.0
    assert config.mcp_catchup_hours == 48.0


def test_flags_turn_each_source_on_separately(monkeypatch):
    monkeypatch.setenv("HUNTER_MCP_REGISTRY", "1")
    monkeypatch.setenv("HUNTER_OPENVSX", "0")
    monkeypatch.setenv("HUNTER_MCP_POLL_INTERVAL", "5")
    monkeypatch.setenv("HUNTER_MCP_CATCHUP_HOURS", "0.01")
    monkeypatch.setenv("HUNTER_OPENVSX_PAGE_SIZE", "5000")
    config = Config.from_env()
    assert config.mcp_registry is True and config.openvsx is False
    assert config.mcp_poll_interval == 300.0
    assert config.mcp_catchup_hours == pytest.approx(300 / 3600)
    assert config.openvsx_page_size == 1000


# --- MCP registry -------------------------------------------------------------


def _server(name: str, packages: list[dict], updated: str) -> dict:
    return {
        "server": {"name": name, "version": "1.0.0", "packages": packages},
        "_meta": {"io.modelcontextprotocol.registry/official": {"status": "active", "updatedAt": updated}},
    }


def test_only_public_npm_and_pypi_packages_are_kept():
    assert package_name({"registryType": "npm", "identifier": "@Scope/Server"}) == ("npm", "@scope/server")
    assert package_name(
        {"registryType": "pypi", "registryBaseUrl": "https://pypi.org", "identifier": "My_Server"}
    ) == ("pypi", "my-server")
    assert package_name({"registryType": "npm", "registryBaseUrl": "https://npm.corp.example", "identifier": "x"}) is None
    assert package_name({"registryType": "oci", "identifier": "docker.io/a/b"}) is None
    assert package_name({"registryType": "mcpb", "identifier": "https://x.example/a.mcpb"}) is None
    assert package_name({"registryType": "npm", "identifier": "../etc"}) is None
    entry = _server("io.example/s", [{"registryType": "npm", "identifier": "s"}] * 2, "2026-10-01T00:00:00Z")
    assert server_packages(entry) == [("npm", "s", "io.example/s")]


class McpRegistry:
    def __init__(self, pages: dict[str | None, dict]):
        self.pages = pages
        self.urls: list[str] = []

    def __call__(self, url: str, timeout: float) -> bytes:
        self.urls.append(url)
        assert url.startswith(f"{MCP}/v0.1/servers?")
        return json.dumps(self.pages[_query(url).get("cursor")]).encode()


def test_first_poll_reads_every_page_then_later_polls_ask_for_updates_only(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = _config(tmp_path, mcp_registry=True)
    feed = McpRegistry(
        {
            None: {
                "servers": [
                    _server("a/one", [{"registryType": "npm", "identifier": "mcp-one"}], "2026-10-01T00:00:00Z"),
                    _server("a/remote", [], "2026-10-02T00:00:00Z"),
                ],
                "metadata": {"nextCursor": "a/remote:1.0.0", "count": 2},
            },
            "a/remote:1.0.0": {
                "servers": [_server("b/py", [{"registryType": "pypi", "identifier": "Py_MCP"}], "2026-10-03T00:00:00Z")],
                "metadata": {"count": 1},
            },
        }
    )
    assert poll_mcp_registry(db, config, feed) == 2
    assert "updated_since" not in _query(feed.urls[0])
    assert _query(feed.urls[0])["version"] == "latest"
    assert _query(feed.urls[1])["cursor"] == "a/remote:1.0.0"
    assert _query(feed.urls[1])["version"] == "latest"
    first = db.get_checkpoint("mcp")
    assert first is not None and first.endswith("Z") and "." not in first
    assert first != "2026-10-03T00:00:00Z"
    assert db.mcp_counts() == {"npm": 1, "pypi": 1}
    assert db.last_poll()["mcp"]

    later = McpRegistry(
        {None: {"servers": [_server("a/one", [{"registryType": "npm", "identifier": "mcp-one"}], "2026-10-04T00:00:00Z")], "metadata": {}}}
    )
    assert poll_mcp_registry(db, config, later) == 0
    assert _query(later.urls[0])["updated_since"] == first
    assert _query(later.urls[0])["version"] == "latest"
    assert db.get_checkpoint("mcp") != "2026-10-04T00:00:00Z"


def test_a_failed_page_keeps_the_checkpoint(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    db.set_checkpoint("mcp", "2026-10-01T00:00:00Z")

    def broken(url, timeout):
        if "cursor=" in url:
            raise FeedError("reset")
        return json.dumps(
            {
                "servers": [_server("a/x", [{"registryType": "npm", "identifier": "x-mcp"}], "2026-10-09T00:00:00Z")],
                "metadata": {"nextCursor": "next"},
            }
        ).encode()

    with pytest.raises(FeedError):
        poll_mcp_registry(db, _config(tmp_path), broken)
    assert db.get_checkpoint("mcp") == "2026-10-01T00:00:00Z"
    # The first page's package is kept; reading it again next time is harmless.
    assert db.mcp_package_names("npm") == {"x-mcp"}


def test_mcp_packages_join_the_poll_watch_but_not_the_popular_names(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    db.replace_watchlist("pypi", [("requests", 1, 100)])
    db.add_mcp_packages([("pypi", "tiny-mcp", "a/t"), ("pypi", "requests", "a/r")])
    assert db.poll_watch("pypi") == {"requests": 1, "tiny-mcp": None}
    assert db.watch_names("pypi") == {"requests": 1}
    # A ranked refresh replaces the watchlist; MCP names stay.
    db.replace_watchlist("pypi", [("urllib3", 1, 100)])
    assert db.poll_watch("pypi") == {"urllib3": 1, "tiny-mcp": None, "requests": None}


class FakePypiFeed:
    def __init__(self, events):
        self.events = events

    def last_serial(self):
        return 1

    def since(self, serial):
        return self.events


def test_pypi_poll_queues_mcp_packages_only_when_the_flag_is_on(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    db.replace_watchlist("pypi", [("requests", 1, 100)])
    db.add_mcp_packages([("pypi", "tiny-mcp", "a/t")])
    db.set_checkpoint("pypi", "1")
    feed = FakePypiFeed([("tiny_mcp", "0.2.0", 0, "new release", 2)])
    assert poll_pypi(db, feed) == 0
    db.set_checkpoint("pypi", "1")
    assert poll_pypi(db, feed, include_mcp=True) == 1
    job = db.pending_jobs()[0]
    assert (job["ecosystem"], job["name"], job["version"], job["rank"]) == ("pypi", "tiny-mcp", "0.2.0", None)


def test_npm_poll_queues_an_mcp_package_release(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = _config(tmp_path, mcp_registry=True, npm_changes="https://replicate.example", npm_registry="https://npm.example")
    db.add_mcp_packages([("npm", "mcp-one", "a/one")])
    db.set_checkpoint("npm", "10")
    db.mark_poll_success("npm")
    packument = {
        "versions": {"1.0.0": {}, "1.1.0": {}},
        "time": {"1.0.0": "2020-01-01T00:00:00.000Z", "1.1.0": "2999-01-01T00:00:00.000Z"},
    }

    def transport(url, timeout):
        if url.startswith("https://replicate.example/_changes"):
            return json.dumps({"results": [{"seq": 11, "id": "mcp-one"}], "last_seq": 11}).encode()
        assert url == "https://npm.example/mcp-one"
        return json.dumps(packument).encode()

    assert poll_npm(db, config, transport) == 1
    assert [(job["name"], job["version"]) for job in db.pending_jobs()] == [("mcp-one", "1.1.0")]


def _freeze_clock(monkeypatch, clock: dict):
    monkeypatch.setattr("hunter.mcp_registry.utcnow", lambda: clock["now"])
    monkeypatch.setattr("hunter.service.utcnow", lambda: clock["now"])


def test_page_cap_does_not_move_the_checkpoint(tmp_path, monkeypatch):
    monkeypatch.setattr("hunter.mcp_registry.MAX_PAGES", 1)
    db = Database(tmp_path / "hunter.sqlite3")
    db.set_checkpoint("mcp", "2026-10-01T00:00:00Z")
    config = _config(tmp_path, mcp_registry=True)
    feed = McpRegistry(
        {
            None: {
                "servers": [_server("a/x", [{"registryType": "npm", "identifier": "x-mcp"}], "2026-10-09T00:00:00Z")],
                "metadata": {"nextCursor": "next"},
            },
            "next": {"servers": [], "metadata": {}},
        }
    )
    _poll_mcp_registry_safely(db, config, feed, None)
    assert db.get_checkpoint("mcp") == "2026-10-01T00:00:00Z"
    assert "stopped after 1 pages" in db.poll_last_error("mcp")
    assert db.mcp_package_names("npm") == {"x-mcp"}


def test_checkpoint_is_poll_start_minus_the_overlap(tmp_path, monkeypatch):
    # String order says the unzoned stamp is newer. Time order says the fractional one is.
    clock = {"now": datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)}
    _freeze_clock(monkeypatch, clock)
    db = Database(tmp_path / "hunter.sqlite3")
    db.set_checkpoint("mcp", "2099-01-01T00:00:00Z")
    config = _config(tmp_path, mcp_registry=True)
    feed = McpRegistry(
        {
            None: {
                "servers": [
                    _server("a/early", [{"registryType": "npm", "identifier": "early-mcp"}], "2026-10-26T00:00:00Z"),
                    _server("a/later", [{"registryType": "npm", "identifier": "later-mcp"}], "2026-10-26T00:00:00.5Z"),
                ],
                "metadata": {"nextCursor": "a/later:1.0.0"},
            },
            "a/later:1.0.0": {"servers": [], "metadata": {}},
        }
    )
    assert poll_mcp_registry(db, config, feed) == 2
    assert _query(feed.urls[0])["updated_since"] == "2099-01-01T00:00:00Z"
    assert _query(feed.urls[0])["version"] == "latest"
    assert _query(feed.urls[1])["version"] == "latest"
    assert db.get_checkpoint("mcp") == "2026-10-26T11:55:00Z"
    clock["now"] = clock["now"] + timedelta(hours=1)
    later = McpRegistry({None: {"servers": [], "metadata": {}}})
    assert poll_mcp_registry(db, config, later) == 0
    assert _query(later.urls[0])["updated_since"] == "2026-10-26T11:55:00Z"
    assert _query(later.urls[0])["version"] == "latest"
    assert db.get_checkpoint("mcp") == "2026-10-26T12:55:00Z"


def test_a_new_name_queues_only_the_newest_release_inside_the_lookback(tmp_path, monkeypatch):
    clock = {"now": datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)}
    _freeze_clock(monkeypatch, clock)
    db = Database(tmp_path / "hunter.sqlite3")
    config = _config(
        tmp_path,
        mcp_registry=True,
        npm_registry="https://npm.example",
        pypi_base="https://pypi.example",
    )
    packument = {
        "time": {
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2026-10-26T11:00:00.000Z",
            "0.1.0": "2020-01-01T00:00:00.000Z",
            "0.9.0": "2026-10-25T12:00:00.000Z",
            "1.2.0": "2026-10-26T11:00:00.000Z",
        }
    }
    project = {
        "releases": {
            "0.1.0": [{"upload_time_iso_8601": "2020-01-01T00:00:00Z"}],
            "0.9.0": [{"upload_time_iso_8601": "2026-10-25T12:00:00Z"}],
            "1.0.0": [{"upload_time_iso_8601": "2026-10-26T11:30:00Z"}],
        }
    }
    hits: list[str] = []

    def transport(url, timeout):
        hits.append(url)
        if "/v0.1/servers" in url:
            return json.dumps(
                {
                    "servers": [
                        _server("a/one", [{"registryType": "npm", "identifier": "mcp-one"}], "2026-10-26T11:00:00Z"),
                        _server("a/py", [{"registryType": "pypi", "identifier": "py-mcp"}], "2026-10-26T11:30:00Z"),
                    ],
                    "metadata": {},
                }
            ).encode()
        if url == "https://npm.example/mcp-one":
            return json.dumps(packument).encode()
        if url == "https://pypi.example/py-mcp/json":
            return json.dumps(project).encode()
        raise AssertionError(url)

    # A poll already ran, so names this poll adds are new.
    db.set_checkpoint("mcp", "2026-10-26T10:55:00Z")
    stats = poll_mcp_and_catchup(db, config, transport)
    assert stats["added"] == 2
    assert sorted((job["ecosystem"], job["name"], job["version"], job["rank"]) for job in db.pending_jobs()) == [
        ("npm", "mcp-one", "1.2.0", None),
        ("pypi", "py-mcp", "1.0.0", None),
    ]
    assert db.get_package_cursor("npm", "mcp-one")[0] == "1.2.0"
    assert db.get_package_cursor("pypi", "py-mcp")[0] == "1.0.0"
    seen = len(hits)
    again = poll_mcp_and_catchup(db, config, transport)
    assert again["added"] == 0
    assert sorted((job["name"], job["version"]) for job in db.pending_jobs()) == [("mcp-one", "1.2.0"), ("py-mcp", "1.0.0")]
    assert [url for url in hits[seen:] if "/v0.1/servers" not in url] == []


def test_a_failed_catchup_keeps_the_checkpoint_and_retries(tmp_path, monkeypatch):
    clock = {"now": datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)}
    _freeze_clock(monkeypatch, clock)
    db = Database(tmp_path / "hunter.sqlite3")
    config = _config(tmp_path, mcp_registry=True, npm_registry="https://npm.example")
    reads = {"n": 0}

    def transport(url, timeout):
        if "/v0.1/servers" in url:
            return json.dumps(
                {
                    "servers": [_server("a/one", [{"registryType": "npm", "identifier": "mcp-one"}], "2026-10-26T11:00:00Z")],
                    "metadata": {},
                }
            ).encode()
        reads["n"] += 1
        if reads["n"] == 1:
            raise FeedError("npm down")
        return json.dumps({"time": {"1.2.0": "2026-10-26T11:00:00.000Z"}}).encode()

    db.set_checkpoint("mcp", "2026-10-26T10:55:00Z")
    poll_mcp_and_catchup(db, config, transport)
    assert db.get_checkpoint("mcp") == "2026-10-26T11:55:00Z"
    assert db.pending_jobs() == []
    assert db.get_package_cursor("npm", "mcp-one") == (None, None)
    clock["now"] = clock["now"] + timedelta(hours=1)
    poll_mcp_and_catchup(db, config, transport)
    assert db.get_checkpoint("mcp") == "2026-10-26T12:55:00Z"
    assert [(job["name"], job["version"], job["rank"]) for job in db.pending_jobs()] == [("mcp-one", "1.2.0", None)]


def test_a_deleted_server_does_not_remove_a_package(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    db.add_mcp_packages([("npm", "kept", "a/kept")])

    def transport(url, timeout):
        return json.dumps(
            {
                "servers": [
                    {
                        "server": {"name": "a/kept", "packages": [{"registryType": "npm", "identifier": "kept"}]},
                        "_meta": {
                            "io.modelcontextprotocol.registry/official": {
                                "status": "deleted",
                                "updatedAt": "2026-10-02T00:00:00Z",
                            }
                        },
                    },
                    {
                        "server": {
                            "name": "a/new",
                            "packages": [{"registryType": "pypi", "identifier": "also-kept"}],
                        },
                        "_meta": {
                            "io.modelcontextprotocol.registry/official": {
                                "status": "deleted",
                                "updatedAt": "2026-10-02T00:00:00Z",
                            }
                        },
                    },
                ],
                "metadata": {},
            }
        ).encode()

    assert poll_mcp_registry(db, _config(tmp_path), transport) == 1
    assert "kept" in db.mcp_package_names("npm")
    assert db.mcp_package_names("pypi") == {"also-kept"}


def test_run_cycle_reads_the_registry_before_npm(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    db.replace_watchlist("npm", [("left-pad", 1, 10)])
    db.replace_watchlist("pypi", [("requests", 1, 10)])
    db.set_checkpoint("npm", "1")
    db.set_checkpoint("pypi", "1")
    order: list[str] = []

    class Feed:
        def last_serial(self):
            return 1

        def since(self, _serial):
            order.append("pypi")
            return []

    def transport(url, timeout):
        order.append(url)
        if "/v0.1/servers" in url:
            return json.dumps({"servers": [], "metadata": {}}).encode()
        return json.dumps({"results": [], "last_seq": "1"}).encode()

    config = _config(
        tmp_path,
        mcp_registry=True,
        npm_changes="https://replicate.example",
        npm_registry="https://npm.example",
        watchlist_refresh=1e12,
    )
    run_cycle(db, config, jev=object(), loader=object(), feed=Feed(), transport=transport)
    registry_at = next(i for i, item in enumerate(order) if "/v0.1/servers" in item)
    npm_at = next(i for i, item in enumerate(order) if "/_changes" in item)
    assert registry_at < npm_at
    assert _query(order[registry_at])["version"] == "latest"


def test_health_includes_last_error_after_a_failed_poll(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = _config(tmp_path, mcp_registry=True)

    def broken(url, timeout):
        raise FeedError("HTTP 400: updated_since")

    _poll_mcp_registry_safely(db, config, broken, None)
    block = health_payload(db, 0.0, config=config)["mcp_registry"]
    assert "HTTP 400: updated_since" in block["last_error"]
    assert block["last_success_at"] is None
    assert block["checkpoint"] is None
    assert block["npm"] == 0 and block["pypi"] == 0


def test_mcp_commands_print_the_poll_and_the_status(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HUNTER_DB", str(tmp_path / "hunter.sqlite3"))
    monkeypatch.setenv("HUNTER_LOG_DIR", str(tmp_path / "logs"))
    monkeypatch.setenv("HUNTER_MCP_REGISTRY_URL", MCP)

    def transport(url, timeout=60):
        assert url.startswith(f"{MCP}/v0.1/servers?")
        assert _query(url)["version"] == "latest"
        return json.dumps(
            {"servers": [_server("a/remote", [], "2026-10-01T00:00:00Z")], "metadata": {}}
        ).encode()

    monkeypatch.setattr("hunter.cli.http_get", transport)
    assert main(["mcp", "poll"]) == 0
    polled = capsys.readouterr().out
    line, body = polled.split("\n", 1)
    assert line.startswith("pages 1 added 0 npm 0 pypi 0 checkpoint ")
    payload = json.loads(body)
    assert payload["checkpoint"] == line.rsplit(" ", 1)[1]
    assert payload["npm"] == 0 and payload["pypi"] == 0
    assert payload["last_error"] is None
    assert payload["last_success_at"]
    assert main(["mcp", "status"]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["checkpoint"] == payload["checkpoint"]
    assert status["last_success_at"] == payload["last_success_at"]


# --- Open VSX feed ------------------------------------------------------------


def _change(ns, name, version, state="ACTIVE", platform="universal", stamp="2026-10-20T00:00:00Z"):
    return {
        "namespace": ns,
        "name": name,
        "version": version,
        "state": state,
        "targetPlatform": platform,
        "timestamp": stamp,
        "lastUpdated": stamp,
        "url": f"{VSX}/api/{ns}/{name}/{platform}/{version}",
    }


class ChangesFeed:
    def __init__(self, pages: dict[str, dict]):
        self.pages = pages
        self.urls: list[str] = []

    def __call__(self, url: str, timeout: float) -> bytes:
        self.urls.append(url)
        assert url.startswith(f"{VSX}/api/-/version-changes?")
        query = _query(url)
        key = f"since:{query['since']}" if "since" in query else query["after"]
        return json.dumps(self.pages[key]).encode()


def test_names_and_platform_choice():
    assert release_name("Pub", "My-Ext") == "pub.my-ext"
    assert release_name("a/b", "x") is None
    assert release_name("..", "x") is None
    assert pick_platform({"linux-arm64": "ACTIVE", "win32-x64": "ACTIVE"}) == "win32-x64"
    assert pick_platform({"universal": "REMOVED", "alpine-x64": "ACTIVE"}) == "alpine-x64"
    assert pick_platform({"universal": "REMOVED"}) is None


def test_first_poll_starts_at_now_then_pages_follow_the_cursor(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = _config(tmp_path, openvsx=True)
    assert poll_openvsx(db, config, ChangesFeed({})) == 0
    saved = db.get_checkpoint(CHECKPOINT)
    assert saved.startswith(SINCE_PREFIX)
    feed = ChangesFeed(
        {
            saved: {
                "changes": [
                    _change("Pub", "ext", "1.1.0", platform="linux-x64"),
                    _change("Pub", "ext", "1.1.0", platform="win32-x64"),
                    _change("pub", "gone", "0.3.0", state="REMOVED"),
                ],
                "hasMore": True,
                "nextCursor": "c1",
            },
            "c1": {"changes": [_change("other", "tool", "2.0.0")], "hasMore": False, "nextCursor": "c2"},
        }
    )
    assert poll_openvsx(db, config, feed) == 2
    assert "since=" in feed.urls[0] and "after=c1" in feed.urls[1]
    assert db.get_checkpoint(CHECKPOINT) == "c2"
    jobs = {(job["ecosystem"], job["name"], job["version"]) for job in db.pending_jobs()}
    assert jobs == {(ECOSYSTEM, "pub.ext", "1.1.0"), (ECOSYSTEM, "other.tool", "2.0.0")}
    assert db.openvsx_platforms("pub.ext", "1.1.0") == {"linux-x64": "ACTIVE", "win32-x64": "ACTIVE"}
    removed = db.openvsx_removed()
    assert [(row["name"], row["version"]) for row in removed] == [("pub.gone", "0.3.0")]
    assert db.openvsx_counts() == {"active": 3, "removed": 1, "other": 0}
    assert db.last_poll()["openvsx"]


def test_a_later_removal_updates_the_recorded_state(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = _config(tmp_path)
    db.set_checkpoint(CHECKPOINT, "c0")
    feed = ChangesFeed(
        {
            "c0": {"changes": [_change("p", "e", "1.0.0")], "hasMore": False, "nextCursor": "c1"},
            "c1": {"changes": [_change("p", "e", "1.0.0", state="REMOVED")], "hasMore": False, "nextCursor": "c2"},
        }
    )
    poll_openvsx(db, config, feed)
    poll_openvsx(db, config, feed)
    assert db.openvsx_platforms("p.e", "1.0.0") == {"universal": "REMOVED"}
    assert db.pending_count() == 1


def test_a_full_queue_leaves_the_page_for_the_next_poll(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = _config(tmp_path, max_pending=1)
    db.set_checkpoint(CHECKPOINT, "c0")
    page = {
        "changes": [_change("p", "a", "1.0.0"), _change("p", "b", "1.0.0")],
        "hasMore": False,
        "nextCursor": "c1",
    }
    assert poll_openvsx(db, config, ChangesFeed({"c0": page})) == 1
    assert db.get_checkpoint(CHECKPOINT) == "c0"
    for job in db.pending_jobs():
        db.finish_job(job["ecosystem"], job["name"], job["version"])
    assert poll_openvsx(db, config, ChangesFeed({"c0": page})) == 1
    assert db.get_checkpoint(CHECKPOINT) == "c1"


def test_a_last_page_without_a_cursor_moves_the_start_to_its_newest_change(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = _config(tmp_path)
    start = f"{SINCE_PREFIX}2026-10-20T00:00:00.000000Z"
    db.set_checkpoint(CHECKPOINT, start)
    page = {
        "changes": [
            _change("p", "a", "1.0.0", stamp="2026-10-20T01:00:00Z"),
            _change("p", "b", "1.0.0", stamp="2026-10-20T03:00:00Z"),
            _change("p", "c", "1.0.0", stamp="2026-10-20T02:00:00Z"),
        ],
        "hasMore": False,
    }
    assert poll_openvsx(db, config, ChangesFeed({start: page})) == 3
    assert db.get_checkpoint(CHECKPOINT) == f"{SINCE_PREFIX}2026-10-20T03:00:00Z"
    db.set_checkpoint(CHECKPOINT, start)
    poll_openvsx(db, config, ChangesFeed({start: {"changes": [], "hasMore": False}}))
    assert db.get_checkpoint(CHECKPOINT) == start


def test_a_feed_error_raises_and_keeps_the_checkpoint(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    db.set_checkpoint(CHECKPOINT, "c0")
    with pytest.raises(FeedError):
        poll_openvsx(db, _config(tmp_path), ChangesFeed({"c0": {"error": "Invalid 'after'", "hasMore": False}}))
    assert db.get_checkpoint(CHECKPOINT) == "c0"


def test_a_page_with_a_cursor_stores_that_cursor(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = _config(tmp_path)
    db.set_checkpoint(CHECKPOINT, "c0")
    feed = ChangesFeed(
        {
            "c0": {"changes": [_change("p", "a", "1.0.0")], "hasMore": True, "nextCursor": "c9"},
            "c9": {"changes": [], "hasMore": False},
        }
    )
    assert poll_openvsx(db, config, feed) == 1
    assert db.get_checkpoint(CHECKPOINT) == "c9"


def test_a_cursorless_boundary_is_not_queued_twice(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = _config(tmp_path)
    start = f"{SINCE_PREFIX}2026-10-20T00:00:00Z"
    boundary = f"{SINCE_PREFIX}2026-10-20T03:00:00Z"
    db.set_checkpoint(CHECKPOINT, start)
    page = {"changes": [_change("p", "a", "1.0.0", stamp="2026-10-20T03:00:00Z")], "hasMore": False}
    feed = ChangesFeed({start: page, boundary: page})
    assert poll_openvsx(db, config, feed) == 1
    assert db.get_checkpoint(CHECKPOINT) == boundary
    assert poll_openvsx(db, config, feed) == 0
    assert db.pending_count() == 1


def test_a_truncated_page_without_a_cursor_keeps_the_checkpoint(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    db.set_checkpoint(CHECKPOINT, "c0")
    page = {
        "changes": [_change("p", "a", "1.0.0", stamp="2026-10-20T03:00:00Z")],
        "hasMore": True,
    }
    with pytest.raises(FeedError):
        poll_openvsx(db, _config(tmp_path), ChangesFeed({"c0": page}))
    assert db.get_checkpoint(CHECKPOINT) == "c0"


def test_inactive_and_unpublished_are_labels_and_not_jobs(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = _config(tmp_path, openvsx=True)
    db.set_checkpoint(CHECKPOINT, "c0")
    page = {
        "changes": [
            _change("p", "sleep", "1.0.0", state="INACTIVE"),
            _change("p", "old", "2.0.0", state="UNPUBLISHED"),
        ],
        "hasMore": False,
        "nextCursor": "c1",
    }
    assert poll_openvsx(db, config, ChangesFeed({"c0": page})) == 0
    assert db.pending_count() == 0
    assert {(row["name"], row["state"]) for row in db.openvsx_labels()} == {
        ("p.old", "inactive"),
        ("p.sleep", "inactive"),
    }
    counts = db.openvsx_counts()
    assert counts == {"active": 0, "removed": 0, "other": 2}
    health = health_payload(db, 0.0, config=config)
    assert health["openvsx"] == counts


def test_a_removal_labels_the_version_at_last_updated(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    db.set_checkpoint(CHECKPOINT, "c0")
    change = _change("p", "gone", "1.2.3", state="REMOVED", stamp="2026-10-20T01:00:00Z")
    change["lastUpdated"] = "2026-10-21T05:06:07.000Z"
    page = {"changes": [change], "hasMore": False, "nextCursor": "c1"}
    assert poll_openvsx(db, _config(tmp_path), ChangesFeed({"c0": page})) == 0
    labels = db.openvsx_labels()
    assert len(labels) == 1
    assert labels[0]["name"] == "p.gone" and labels[0]["version"] == "1.2.3"
    assert labels[0]["state"] == "removed"
    assert labels[0]["changed_at"] == "2026-10-21T05:06:07.000Z"
    assert db.pending_count() == 0


def test_removed_then_active_reopens_unless_the_queue_is_full(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = _config(tmp_path)
    db.set_checkpoint(CHECKPOINT, "c0")
    removed = _change("p", "a", "1.0.0", state="REMOVED", stamp="2026-10-21T00:00:00Z")
    removed["lastUpdated"] = "2026-10-21T00:00:00Z"
    feed = ChangesFeed(
        {
            "c0": {"changes": [_change("p", "a", "1.0.0")], "hasMore": False, "nextCursor": "c1"},
            "c1": {"changes": [removed], "hasMore": False, "nextCursor": "c2"},
            "c2": {"changes": [_change("p", "a", "1.0.0", stamp="2026-10-22T00:00:00Z")], "hasMore": False, "nextCursor": "c3"},
        }
    )
    assert poll_openvsx(db, config, feed) == 1
    db.save_release(ECOSYSTEM, "p.a", "1.0.0", "benign", 0.0, "none", None, "{}")
    db.finish_job(ECOSYSTEM, "p.a", "1.0.0")
    assert poll_openvsx(db, config, feed) == 0
    assert db.openvsx_labels()[0]["state"] == "removed"
    assert db.get_release(ECOSYSTEM, "p.a", "1.0.0") is not None
    assert poll_openvsx(db, config, feed) == 1
    assert db.get_checkpoint(CHECKPOINT) == "c3"
    assert [(job["name"], job["version"]) for job in db.pending_jobs()] == [("p.a", "1.0.0")]
    assert db.get_release(ECOSYSTEM, "p.a", "1.0.0") is None
    assert db.openvsx_labels()[0]["changed_at"] == "2026-10-21T00:00:00Z"

    db.save_release(ECOSYSTEM, "p.a", "1.0.0", "benign", 0.0, "none", None, "{}")
    db.finish_job(ECOSYSTEM, "p.a", "1.0.0")
    db.enqueue_job("npm", "filler", "1.0.0", None)
    full = _config(tmp_path, max_pending=1)
    blocked = ChangesFeed(
        {
            "c3": {"changes": [removed], "hasMore": False, "nextCursor": "c4"},
            "c4": {
                "changes": [_change("p", "a", "1.0.0", stamp="2026-10-23T00:00:00Z")],
                "hasMore": False,
                "nextCursor": "c5",
            },
        }
    )
    assert poll_openvsx(db, full, blocked) == 0
    assert db.get_checkpoint(CHECKPOINT) == "c4"
    assert poll_openvsx(db, full, blocked) == 0
    assert db.get_checkpoint(CHECKPOINT) == "c4"
    assert db.get_release(ECOSYSTEM, "p.a", "1.0.0") is not None
    assert [(job["ecosystem"], job["name"]) for job in db.pending_jobs()] == [("npm", "filler")]
    assert db.openvsx_platforms("p.a", "1.0.0")["universal"] == "REMOVED"


# --- Open VSX review ----------------------------------------------------------


def _vsix(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("extension.vsixmanifest", "<PackageManifest/>")
        for path, text in files.items():
            archive.writestr(f"extension/{path}", text)
    return buffer.getvalue()


def _manifest(**extra) -> str:
    data = {"name": "ext", "publisher": "pub", "main": "./out/extension.js", "activationEvents": ["onCommand:x"]}
    data.update(extra)
    return json.dumps(data)


class OpenVsxApi:
    """Version metadata and .vsix downloads for one extension."""

    def __init__(
        self,
        versions: dict[str, dict[str, str]],
        publishers: dict[str, str] | None = None,
        platform="universal",
        builds: dict[str, str] | None = None,
    ):
        self.versions = versions
        self.publishers = publishers or {}
        self.platform = platform
        # Version -> its one build, when it differs from ``platform``.
        self.builds = builds or {}
        self.urls: list[str] = []

    def __call__(self, url: str, timeout: float) -> bytes:
        self.urls.append(url)
        prefix = f"{VSX}/api/pub/ext/"
        if url.startswith(prefix):
            platform, _sep, version = url[len(prefix) :].partition("/")
            if platform != self.builds.get(version, self.platform):
                raise FeedError("HTTP Error 404: Not Found")
            listed = {"latest": "x"}
            listed.update({key: "x" for key in sorted(self.versions, reverse=True)})
            return json.dumps(
                {
                    "version": version,
                    "allVersions": listed,
                    "timestamp": "2026-10-20T00:00:00Z",
                    "publishedBy": {"loginName": self.publishers.get(version, "alice")},
                    "files": {"download": f"https://cdn.example/pub.ext-{version}.vsix"},
                }
            ).encode()
        if url.startswith("https://cdn.example/pub.ext-"):
            version = url.rsplit("-", 1)[1][: -len(".vsix")]
            return _vsix(self.versions[version])
        raise AssertionError(url)


def _queue(db: Database, version: str, platform: str = "universal") -> None:
    db.record_openvsx_change("pub.ext", version, platform, "ACTIVE", None, None)
    db.enqueue_job(ECOSYSTEM, "pub.ext", version, None)


def _run(db, config, api):
    loader = ReleaseLoader(config, api)
    for job in db.pending_jobs():
        classify_job(db, config, job, jev=None, loader=loader, transport=api)


def _payload(db, version):
    return json.loads(db.get_release(ECOSYSTEM, "pub.ext", version)["payload_json"])


def test_predecessor_and_manifest_signals():
    document = {"allVersions": {"latest": "u", "pre-release": "u", "2.0.0": "u", "1.9.0": "u"}}
    assert predecessor(document, "2.0.0") == "1.9.0"
    assert predecessor(document, "1.9.0") is None
    old = {"extension/package.json": _manifest()}
    new = {"extension/package.json": _manifest(extensionPack=["evil.twin"], activationEvents=["*"])}
    assert manifest_signals(old, new) == [
        "vsx_extension_pack_added",
        "vsx_pulls:evil.twin",
        "vsx_activation_widened",
    ]
    # A first publish has no old manifest: the pack still signals, activation does not.
    assert manifest_signals({}, new) == ["vsx_extension_pack_added", "vsx_pulls:evil.twin"]
    assert predecessor({"allVersions": {"1.10.0": "u", "1.9.0": "u"}}, "1.10.0") == "1.9.0"


def test_a_bundler_move_of_main_is_not_a_medium_signal():
    old = {"extension/package.json": _manifest()}
    moved = {"extension/package.json": _manifest(main="./dist/extension.js")}
    assert manifest_signals(old, moved) == ["vsx_main_moved"]
    assert manifest_signals(old, {"extension/package.json": _manifest(main="dist/extension")}) == ["vsx_main_moved"]
    for main in ("./dist/run.sh", "../outside.js", "/tmp/x.js", "./bin/native.node"):
        assert manifest_signals(old, {"extension/package.json": _manifest(main=main)}) == ["vsx_main_changed"], main
    declarative = {"extension/package.json": json.dumps({"name": "ext", "publisher": "pub"})}
    assert manifest_signals(declarative, old) == ["vsx_main_changed"]


def test_one_medium_signal_with_a_weak_hit_does_not_route_to_triage():
    weak = RuleReport(verdict="unsure", hits=[RuleHit("h_shell", "weak", "extension/out/extension.js", 1, "child_process")])
    strong = RuleReport(verdict="malicious", hits=[RuleHit("x", "strong", "extension/out/extension.js", 1, "x")])
    assert not routes(["vsx_main_changed"], weak)
    assert not routes(["vsx_main_moved", "vsx_publisher_changed"], weak)
    assert routes(["vsx_main_changed", "vsx_publisher_changed"], RuleReport())
    assert routes([], strong)
    assert not scout_reads([], weak)
    assert not scout_reads(["vsx_main_moved"], weak)
    assert scout_reads(["vsx_main_changed"], weak)
    assert scout_reads([], strong)
    assert not scout_reads(["vsx_main_changed"], RuleReport())


def test_version_api_url_escapes_the_version():
    assert version_api_url(VSX, "pub.ext", "universal", "1.0.0?x#y") == f"{VSX}/api/pub/ext/universal/1.0.0%3Fx%23y"


def test_a_quiet_update_is_stored_benign_without_triage(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = _config(tmp_path, openvsx=True, investigate_command="unused")
    api = OpenVsxApi(
        {
            "1.0.0": {"package.json": _manifest(), "out/extension.js": "exports.activate = () => {};\n"},
            "1.1.0": {"package.json": _manifest(), "out/extension.js": "exports.activate = () => { log('hi'); };\n"},
        }
    )
    _queue(db, "1.1.0")
    _run(db, config, api)
    row = _payload(db, "1.1.0")
    assert row["band"] == "benign" and row["old_version"] == "1.0.0"
    assert row["registry_url"] == f"{VSX}/extension/pub/ext/1.1.0"
    assert db.investigation_depth() == 0 and db.pending_count() == 0


def test_a_sleeper_update_is_routed_to_triage(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = _config(tmp_path, openvsx=True, investigate_command="unused", smart_analysis=True)
    api = OpenVsxApi(
        {
            "1.0.0": {"package.json": _manifest(), "out/extension.js": "exports.activate = () => {};\n"},
            "1.1.0": {
                "package.json": _manifest(extensionPack=["evil.twin"], activationEvents=["*"]),
                "out/extension.js": "exports.activate = () => {};\n",
            },
        },
        publishers={"1.1.0": "mallory"},
    )
    _queue(db, "1.1.0")
    _run(db, config, api)
    row = _payload(db, "1.1.0")
    assert row["band"] == "review"
    assert {"vsx_extension_pack_added", "vsx_activation_widened", "vsx_publisher_changed"} <= set(row["signals"])
    assert db.investigation_depth() == 1


def test_a_platform_build_is_diffed_when_there_is_no_universal_one(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = _config(tmp_path, openvsx=True)
    api = OpenVsxApi(
        {"1.0.0": {"package.json": _manifest()}, "2.0.0": {"package.json": _manifest()}},
        platform="linux-x64",
    )
    _queue(db, "2.0.0", platform="linux-x64")
    _run(db, config, api)
    row = _payload(db, "2.0.0")
    assert "vsx_platform:linux-x64" in row["signals"]
    assert any("/linux-x64/2.0.0" in url for url in api.urls)


def test_the_predecessor_is_read_from_its_own_recorded_build(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = _config(tmp_path, openvsx=True)
    api = OpenVsxApi(
        {"1.0.0": {"package.json": _manifest()}, "2.0.0": {"package.json": _manifest()}},
        platform="linux-x64",
        builds={"1.0.0": "universal"},
    )
    db.record_openvsx_change("pub.ext", "1.0.0", "universal", "ACTIVE", None, None)
    _queue(db, "2.0.0", platform="linux-x64")
    _run(db, config, api)
    row = _payload(db, "2.0.0")
    assert row["band"] == "benign" and row["old_version"] == "1.0.0"
    assert not any("/linux-x64/1.0.0" in url for url in api.urls)


def test_an_unrecorded_predecessor_build_is_found_by_trying_the_others(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = _config(tmp_path, openvsx=True)
    api = OpenVsxApi(
        {"1.0.0": {"package.json": _manifest()}, "2.0.0": {"package.json": _manifest()}},
        builds={"1.0.0": "win32-x64"},
    )
    _queue(db, "2.0.0")
    _run(db, config, api)
    row = _payload(db, "2.0.0")
    assert row["band"] == "benign" and row["old_version"] == "1.0.0"
    assert any("/win32-x64/1.0.0" in url for url in api.urls)


def test_a_version_removed_before_review_is_not_downloaded(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = _config(tmp_path, openvsx=True)
    _queue(db, "1.0.0")
    db.record_openvsx_change("pub.ext", "1.0.0", "universal", "REMOVED", None, None)
    api = OpenVsxApi({})
    _run(db, config, api)
    assert api.urls == []
    assert _payload(db, "1.0.0")["signals"] == ["vsx_removed_before_review"]


def test_a_download_failure_is_deferred_for_retry(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = _config(tmp_path, openvsx=True)
    _queue(db, "1.0.0")

    def down(url, timeout):
        raise FeedError("timed out")

    _run(db, config, down)
    assert _payload(db, "1.0.0")["band"] == "deferred"
    assert db.retry_depth() == 1


def test_a_new_pack_id_routes_on_its_own(tmp_path):
    for key in ("extensionPack", "extensionDependencies"):
        db = Database(tmp_path / f"{key}.sqlite3")
        config = _config(tmp_path, openvsx=True, investigate_command="unused", smart_analysis=True)
        assert config.openvsx_scout is False
        api = OpenVsxApi(
            {
                "1.0.0": {"package.json": _manifest(), "out/extension.js": "exports.activate = () => {};\n"},
                "1.1.0": {
                    "package.json": _manifest(**{key: ["Evil.Twin"]}),
                    "out/extension.js": "exports.activate = () => {};\n",
                },
            }
        )
        _queue(db, "1.1.0")
        _run(db, config, api)
        row = _payload(db, "1.1.0")
        assert row["band"] == "review"
        assert row["jev_model_id"] == "deterministic"
        assert "vsx_extension_pack_added" in row["signals"]
        assert "vsx_pulls:evil.twin" in row["signals"]
        assert not any(signal.startswith("rule:") for signal in row["signals"])
        assert db.investigation_depth() == 1
        assert not any("evil.twin" in url for url in api.urls)


def test_pack_ids_signal_only_when_they_are_new():
    old = {"extension/package.json": _manifest(extensionPack=["Pub.Ext", "Other.Tool"])}
    same = {"extension/package.json": _manifest(extensionPack=["other.tool", "pub.ext"])}
    assert manifest_signals(old, same) == []
    removed = {"extension/package.json": _manifest(extensionPack=["pub.ext"])}
    assert manifest_signals(old, removed) == []
    added = {"extension/package.json": _manifest(extensionDependencies=["pub.ext", "Evil.Twin"])}
    base = {"extension/package.json": _manifest(extensionDependencies=["pub.ext"])}
    assert manifest_signals(base, added) == ["vsx_extension_pack_added", "vsx_pulls:evil.twin"]
    dropped = {"extension/package.json": _manifest(extensionPack=["ok.keep", "bad/name", "a..b", "../x"])}
    kept = {"extension/package.json": _manifest(extensionPack=["ok.keep"])}
    assert manifest_signals(kept, dropped) == ["vsx_extension_pack_added"]
    many = [f"p.{index:02d}" for index in range(21)]
    packed = {"extension/package.json": _manifest(extensionPack=many)}
    signals = manifest_signals(kept, packed)
    pulls = [signal for signal in signals if signal.startswith("vsx_pulls:")]
    assert signals[0] == "vsx_extension_pack_added"
    assert len(pulls) == 20
    assert "vsx_pulls:p.20" not in signals
    assert routes(["vsx_extension_pack_added"], RuleReport())
    assert routes(["vsx_extension_pack_added"], None)
    assert not routes(["vsx_pulls:evil.twin"], RuleReport())
    assert not routes(["vsx_activation_widened"], RuleReport())


def test_a_first_version_pack_signals_and_an_empty_one_stays_benign(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = _config(tmp_path, openvsx=True, investigate_command="unused", smart_analysis=True)
    packed = OpenVsxApi({"1.0.0": {"package.json": _manifest(extensionPack=["evil.twin"])}})
    _queue(db, "1.0.0")
    _run(db, config, packed)
    row = _payload(db, "1.0.0")
    assert row["band"] == "review"
    assert {"vsx_first_version", "vsx_extension_pack_added", "vsx_pulls:evil.twin"} <= set(row["signals"])
    assert "vsx_activation_widened" not in row["signals"]

    quiet_db = Database(tmp_path / "quiet.sqlite3")
    quiet = OpenVsxApi({"1.0.0": {"package.json": _manifest()}})
    _queue(quiet_db, "1.0.0")
    _run(quiet_db, config, quiet)
    quiet_row = _payload(quiet_db, "1.0.0")
    assert quiet_row["band"] == "benign"
    assert quiet_row["signals"] == ["vsx_first_version"]
    assert quiet_db.investigation_depth() == 0


def test_a_stored_predecessor_platform_is_tried_before_giving_up(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = _config(tmp_path, openvsx=True)
    api = OpenVsxApi(
        {"1.0.0": {"package.json": _manifest()}, "2.0.0": {"package.json": _manifest()}},
        builds={"1.0.0": "alpine-arm64"},
    )
    db.record_openvsx_change("pub.ext", "1.0.0", "alpine-arm64", "INACTIVE", None, None)
    _queue(db, "2.0.0")
    _run(db, config, api)
    row = _payload(db, "2.0.0")
    assert row["band"] == "benign" and row["old_version"] == "1.0.0"
    assert any("/alpine-arm64/1.0.0" in url for url in api.urls)


def test_inactive_before_review_is_not_downloaded(tmp_path):
    for state in ("INACTIVE", "UNPUBLISHED"):
        db = Database(tmp_path / f"{state}.sqlite3")
        config = _config(tmp_path, openvsx=True)
        _queue(db, "1.0.0")
        db.record_openvsx_change("pub.ext", "1.0.0", "universal", state, None, None)
        api = OpenVsxApi({})
        _run(db, config, api)
        assert api.urls == []
        row = _payload(db, "1.0.0")
        assert row["band"] == "benign"
        assert row["signals"] == ["vsx_inactive_before_review"]


def test_open_vsx_reads_npm_rules_and_not_pypi_only_rules():
    specs = list(load_pack().specs.values())
    npm = next(spec for spec in specs if spec.eco == "npm")
    pypi = next(spec for spec in specs if spec.eco == "pypi")
    assert npm.reads(npm.scope, ECOSYSTEM)
    assert not pypi.reads(pypi.scope, ECOSYSTEM)


# --- reporting ----------------------------------------------------------------


def test_public_feed_and_health_know_both_sources(tmp_path):
    assert public_registry_url("openvsx", "https://open-vsx.org/extension/pub/ext/1.0.0")
    assert public_registry_url("openvsx", "https://evil.example/extension/pub/ext/1.0.0") == ""
    alert = PublicAlert("openvsx", "pub.ext", "1.1.0", "1.0.0", "", "", "", False, "2026-10-20T00:00:00Z")
    assert alert_title(alert) == "Malicious Open VSX extension: pub.ext 1.1.0"
    db = Database(tmp_path / "hunter.sqlite3")
    db.add_mcp_packages([("npm", "mcp-one", "a/one")])
    off = health_payload(db, 0.0, config=_config(tmp_path))
    assert "mcp_registry" not in off and "openvsx" not in off
    on = health_payload(db, 0.0, config=_config(tmp_path, mcp_registry=True, openvsx=True))
    assert on["mcp_registry"] == {
        "npm": 1,
        "pypi": 0,
        "checkpoint": None,
        "last_success_at": None,
        "last_error": None,
    }
    assert on["openvsx"] == {"active": 0, "removed": 0, "other": 0}
