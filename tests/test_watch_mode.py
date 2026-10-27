"""HUNTER_WATCH_MODE=watched: polls queue only user-watchlist names. Every feed and registry is a fake."""

from __future__ import annotations

import io
import json

import pytest

from hunter.actions import ECOSYSTEM as ACTIONS
from hunter.actions.github import RefList
from hunter.actions.poller import poll_actions
from hunter.config import Config
from hunter.db import Database
from hunter.inventory.load import REFRESH_CHECKPOINT, import_paths
from hunter.openvsx.feed import CHECKPOINT as OPENVSX_CHECKPOINT
from hunter.openvsx.feed import poll_openvsx
from hunter.service import (
    _refresh_actions_watchlist_safely,
    _refresh_user_watchlist_safely,
    _refresh_watchlists_if_stale,
    health_payload,
    poll_npm,
    poll_pypi,
)

VSX = "https://vsx.example"


def _db(tmp_path) -> Database:
    return Database(tmp_path / "hunter.sqlite3")


def _user(db: Database, *rows: tuple[str, str]) -> None:
    db.replace_user_watch_source("test", "plain", [(eco, name, "", 1) for eco, name in rows])


# --- poll targets -------------------------------------------------------------


def test_poll_targets_combinations_and_poll_watch_is_unchanged(tmp_path):
    db = _db(tmp_path)
    db.replace_watchlist("pypi", [("requests", 1, 100)])
    db.add_mcp_packages([("pypi", "tiny-mcp", "a/t")])
    _user(db, ("pypi", "mine"), ("pypi", "requests"))
    assert db.poll_watch("pypi") == {"requests": 1, "tiny-mcp": None}
    assert db.poll_targets("pypi") == {"requests": 1}
    assert db.poll_targets("pypi", include_user=True) == {"requests": 1, "mine": None}
    assert db.poll_targets("pypi", include_ranked=False, include_user=True) == {"mine": None, "requests": None}
    assert db.poll_targets("pypi", include_ranked=False, include_mcp=True, include_user=True) == {
        "tiny-mcp": None,
        "mine": None,
        "requests": None,
    }
    assert db.poll_targets("pypi", include_ranked=False) == {}


# --- PyPI ---------------------------------------------------------------------


class FakePypiFeed:
    def __init__(self, events):
        self.events = events

    def last_serial(self):
        return 1

    def since(self, serial):
        return self.events


PYPI_EVENTS = [
    ("requests", "9.0.0", 0, "new release", 2),
    ("Mine_Lib", "0.2.0", 0, "new release", 3),
    ("requestss", "1.0.0", 0, "new release", 4),
]


def _queued(db: Database) -> set[tuple[str, str, str]]:
    return {(job["ecosystem"], job["name"], job["version"]) for job in db.pending_jobs()}


def test_pypi_watched_mode_queues_only_listed_names_and_no_lookalikes(tmp_path):
    db = _db(tmp_path)
    db.replace_watchlist("pypi", [("requests", 1, 100)])
    db.add_mcp_packages([("pypi", "tiny-mcp", "a/t")])
    _user(db, ("pypi", "mine-lib"))
    db.set_checkpoint("pypi", "1")
    feed = FakePypiFeed(PYPI_EVENTS + [("tiny_mcp", "1.0.0", 0, "new release", 5)])
    assert poll_pypi(db, feed, include_mcp=True, watch_mode="watched") == 1
    assert _queued(db) == {("pypi", "mine-lib", "0.2.0")}
    assert db.get_checkpoint("pypi") == "5"


def test_pypi_all_mode_adds_user_names_to_the_popular_list(tmp_path):
    db = _db(tmp_path)
    db.replace_watchlist("pypi", [("requests", 1, 100)])
    _user(db, ("pypi", "mine-lib"))
    db.set_checkpoint("pypi", "1")
    poll_pypi(db, FakePypiFeed(PYPI_EVENTS))
    queued = _queued(db)
    assert {("pypi", "requests", "9.0.0"), ("pypi", "mine-lib", "0.2.0")} <= queued


# --- npm ----------------------------------------------------------------------


def _npm_config(tmp_path, **extra) -> Config:
    return Config(
        db_path=tmp_path / "hunter.sqlite3",
        npm_changes="https://replicate.example",
        npm_registry="https://npm.example",
        smart_analysis=False,
        **extra,
    )


class NpmFake:
    def __init__(self, names: list[str], packuments: dict[str, dict]):
        self.names = names
        self.packuments = packuments
        self.fetched: list[str] = []

    def __call__(self, url, timeout):
        if url.startswith("https://replicate.example/_changes"):
            results = [{"seq": 11 + index, "id": name} for index, name in enumerate(self.names)]
            return json.dumps({"results": results, "last_seq": 10 + len(self.names)}).encode()
        name = url.removeprefix("https://npm.example/")
        self.fetched.append(name)
        return json.dumps(self.packuments[name]).encode()


def _packument(*pairs: tuple[str, str]) -> dict:
    return {"versions": {version: {} for version, _ in pairs}, "time": dict(pairs)}


def test_npm_watched_mode_fetches_and_queues_only_listed_names(tmp_path):
    db = _db(tmp_path)
    db.replace_watchlist("npm", [("react", 1, 100)])
    _user(db, ("npm", "mine-lib"))
    db.set_checkpoint("npm", "10")
    db.mark_poll_success("npm")
    fake = NpmFake(
        ["react", "reactt", "mine-lib"],
        {
            "react": _packument(("19.0.0", "2999-01-01T00:00:00.000Z")),
            "reactt": _packument(("1.0.0", "2999-01-01T00:00:00.000Z")),
            "mine-lib": _packument(("1.0.0", "2020-01-01T00:00:00.000Z"), ("1.1.0", "2999-01-01T00:00:00.000Z")),
        },
    )
    assert poll_npm(db, _npm_config(tmp_path, watch_mode="watched"), fake) == 1
    assert _queued(db) == {("npm", "mine-lib", "1.1.0")}
    assert fake.fetched == ["mine-lib"]


def test_readded_npm_name_does_not_queue_versions_from_while_it_was_off_the_list(tmp_path):
    db = _db(tmp_path)
    # The name was watched before; its cursor is months old.
    db.set_package_cursor("npm", "mine-lib", "1.0.0", "2026-01-01T00:00:00.000Z")
    db.set_checkpoint("npm", "10")
    db.mark_poll_success("npm")
    import_paths(db, ["-"], fmt="plain", source="again", stdin=io.StringIO("npm mine-lib\n"))
    fake = NpmFake(
        ["mine-lib"],
        {
            "mine-lib": _packument(
                ("1.0.0", "2025-12-01T00:00:00.000Z"),
                ("1.5.0", "2026-03-01T00:00:00.000Z"),
                ("2.0.0", "2999-01-01T00:00:00.000Z"),
            )
        },
    )
    poll_npm(db, _npm_config(tmp_path, watch_mode="watched"), fake)
    assert _queued(db) == {("npm", "mine-lib", "2.0.0")}


# --- GitHub Actions -----------------------------------------------------------


class FakeGitHub:
    has_token = False

    def __init__(self, tags: dict[str, dict[str, str]]):
        self.tags = tags
        self.read: list[str] = []

    def ls_refs(self, name, prefixes=None):
        self.read.append(name)
        return RefList(tags=dict(self.tags.get(name, {})), default_branch="main")


def test_actions_poll_sorts_unranked_user_names_and_honors_watched_mode(tmp_path):
    db = _db(tmp_path)
    db.replace_watchlist(ACTIONS, [("actions/checkout", 1, 0)])
    _user(db, (ACTIONS, "acme/deploy"))
    client = FakeGitHub({"actions/checkout": {"v4": "a" * 40}, "acme/deploy": {"v1": "b" * 40}})
    poll_actions(db, Config(db_path=db.path, actions=True), client)
    assert sorted(client.read) == ["acme/deploy", "actions/checkout"]
    client.read.clear()
    poll_actions(db, Config(db_path=db.path, actions=True, watch_mode="watched"), client)
    assert client.read == ["acme/deploy"]


# --- Open VSX -----------------------------------------------------------------


def _change(ns, name, version):
    stamp = "2026-10-20T00:00:00Z"
    return {"namespace": ns, "name": name, "version": version, "state": "ACTIVE", "targetPlatform": "universal", "timestamp": stamp, "lastUpdated": stamp}


def test_openvsx_watched_mode_skips_unlisted_extensions_but_moves_the_checkpoint(tmp_path):
    db = _db(tmp_path)
    _user(db, ("openvsx", "pub.mine"))
    db.set_checkpoint(OPENVSX_CHECKPOINT, "c0")
    page = {"changes": [_change("Pub", "Mine", "1.0.0"), _change("other", "tool", "2.0.0")], "hasMore": False, "nextCursor": "c1"}

    def transport(url, timeout):
        assert url.startswith(f"{VSX}/api/-/version-changes?")
        return json.dumps(page).encode()

    config = Config(db_path=db.path, openvsx=True, openvsx_url=VSX, watch_mode="watched")
    assert poll_openvsx(db, config, transport) == 1
    assert _queued(db) == {("openvsx", "pub.mine", "1.0.0")}
    assert db.get_checkpoint(OPENVSX_CHECKPOINT) == "c1"


# --- refreshes ----------------------------------------------------------------


def test_watched_mode_downloads_no_popular_lists(tmp_path, monkeypatch):
    db = _db(tmp_path)

    def refuse(*_args, **_kwargs):
        raise AssertionError("a popular list was downloaded in watched mode")

    monkeypatch.setattr("hunter.service.refresh_watchlists", refuse)
    monkeypatch.setattr("hunter.service.refresh_actions_watchlist", refuse)
    monkeypatch.setattr("hunter.service.check_ecosyste", refuse)
    config = Config(db_path=db.path, watch_mode="watched", actions=True)
    _refresh_watchlists_if_stale(db, config, refuse)
    _refresh_actions_watchlist_safely(db, config, refuse, client=None)
    with pytest.raises(AssertionError):
        _refresh_watchlists_if_stale(db, Config(db_path=db.path), refuse)


def test_user_watchlist_paths_are_reimported_when_stale(tmp_path):
    db = _db(tmp_path)
    listing = tmp_path / "watch.txt"
    listing.write_text("npm left-pad\n", encoding="utf-8")
    config = Config(db_path=db.path, watchlist_paths=(str(listing),), watchlist_refresh=3600)
    _refresh_user_watchlist_safely(db, config)
    assert db.user_watch_names("npm") == {"left-pad"}
    assert db.get_checkpoint(REFRESH_CHECKPOINT)
    listing.write_text("npm is-odd\n", encoding="utf-8")
    _refresh_user_watchlist_safely(db, config)  # not stale yet
    assert db.user_watch_names("npm") == {"left-pad"}
    _refresh_user_watchlist_safely(db, Config(db_path=db.path, watchlist_paths=(str(listing),), watchlist_refresh=0))
    assert db.user_watch_names("npm") == {"is-odd"}


def test_health_reports_counts_only(tmp_path):
    db = _db(tmp_path)
    _user(db, ("npm", "secret-internal-name"))
    payload = health_payload(db, 0.0, config=Config(db_path=db.path, watch_mode="watched", alert_scope="watched"))
    block = payload["user_watchlist"]
    assert block["npm"] == 1 and block["total"] == 1 and block["sources"] == 1
    assert block["mode"] == "watched" and block["alert_scope"] == "watched"
    assert block["oldest_import_at"]
    assert "secret-internal-name" not in json.dumps(payload, default=str)


# --- config -------------------------------------------------------------------


def _clear(monkeypatch):
    for name in ("HUNTER_WATCH_MODE", "HUNTER_ALERT_SCOPE", "HUNTER_WATCHLIST_PATHS", "HUNTER_WATCHLIST_MAX_FILE_MB", "HUNTER_WATCHLIST_MAX_FILES"):
        monkeypatch.delenv(name, raising=False)


def test_config_defaults(monkeypatch):
    _clear(monkeypatch)
    config = Config.from_env()
    assert (config.watch_mode, config.alert_scope, config.watchlist_paths) == ("all", "all", ())
    assert config.watchlist_max_file_bytes == 20 * 1024 * 1024
    assert config.watchlist_max_files == 2000


def test_config_alert_scope_follows_watched_mode_unless_set(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("HUNTER_WATCH_MODE", "Watched")
    assert Config.from_env().alert_scope == "watched"
    monkeypatch.setenv("HUNTER_ALERT_SCOPE", "all")
    assert Config.from_env().alert_scope == "all"
    monkeypatch.setenv("HUNTER_WATCH_MODE", "all")
    monkeypatch.setenv("HUNTER_ALERT_SCOPE", "watched")
    assert Config.from_env().alert_scope == "watched"
    monkeypatch.setenv("HUNTER_WATCHLIST_PATHS", "/srv/App Repo, /srv/other ,/srv/App Repo")
    assert Config.from_env().watchlist_paths == ("/srv/App Repo", "/srv/other")


@pytest.mark.parametrize("name, value", [("HUNTER_WATCH_MODE", "some"), ("HUNTER_ALERT_SCOPE", "everyone")])
def test_config_rejects_unknown_values(monkeypatch, name, value):
    _clear(monkeypatch)
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError):
        Config.from_env()
