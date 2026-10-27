"""RubyGems and crates.io on the user watchlist: import, alert scope and watched-mode polls."""

from __future__ import annotations

import inspect
import json

from hunter.config import Config
from hunter.crates.feed import poll_crates
from hunter.db import Database
from hunter.inventory.load import import_paths
from hunter.inventory.scope import alert_in_scope, watch_context
from hunter.rubygems.feed import CHECKPOINT as GEMS_CHECKPOINT
from hunter.rubygems.feed import poll_rubygems
from hunter.service import serve

GEM_BASE = "https://gems.test"
UPDATES = "https://static.test/rss/updates.xml"
NAMES = "https://static.test/rss/crates.xml"
API = "https://crates.test"


def _db(tmp_path) -> Database:
    return Database(tmp_path / "hunter.sqlite3")


def _user(db: Database, *rows: tuple[str, str]) -> None:
    db.replace_user_watch_source("test", "plain", [(eco, name, "", 1) for eco, name in rows])


def test_directory_import_finds_both_lockfiles(tmp_path):
    root = tmp_path / "repo"
    (root / "web").mkdir(parents=True)
    (root / "svc").mkdir()
    gems = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.4)\n    RedCloth (4.3.2)\n\nDEPENDENCIES\n  rails\n"
    crates = 'version = 3\n\n[[package]]\nname = "serde"\nversion = "1.0.150"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n'
    (root / "web" / "Gemfile.lock").write_text(gems)
    (root / "svc" / "Cargo.lock").write_text(crates)
    db = _db(tmp_path)
    report = import_paths(db, [str(root)], source="acme")
    assert set(item.format for item in report.files) == set(["gemfile-lock", "cargo-lock"])
    assert db.user_watch_names("rubygems") == set(["rails", "redcloth"])
    assert db.user_watch_names("crates") == set(["serde"])
    counts = db.user_watch_counts()
    assert (counts["rubygems"], counts["crates"], counts["total"]) == (2, 1, 3)


def test_alert_scope_and_watch_context_ignore_registry_case(tmp_path):
    db = _db(tmp_path)
    _user(db, ("rubygems", "redcloth"), ("crates", "inflector"))
    config = Config(db_path=db.path, alert_scope="watched")
    assert alert_in_scope(db, config, "rubygems", "RedCloth")
    assert alert_in_scope(db, config, "crates", "Inflector")
    assert not alert_in_scope(db, config, "crates", "serde")
    assert watch_context(db, "rubygems", "RedCloth", "4.3.2")["listed"]


# --- RubyGems watched mode ----------------------------------------------------


def _gem_row(name: str, version: str, stamp: str) -> dict:
    return dict(name=name, version=version, number=version, platform="ruby", version_created_at=stamp)


def _gem_transport(page: list):
    return lambda url, timeout: json.dumps(page if "page=1" in url else []).encode()


def _gem_queue(db: Database) -> set[tuple[str, str]]:
    return set((row["name"], row["version"]) for row in db.pending_jobs())


def test_rubygems_watched_mode_queues_listed_names_and_still_moves_the_checkpoint(tmp_path):
    db = _db(tmp_path)
    _user(db, ("rubygems", "redcloth"), ("rubygems", "rails"))
    db.set_checkpoint(GEMS_CHECKPOINT, "2026-10-26T15:00:00.000Z")
    page = [
        _gem_row("RedCloth", "4.3.3", "2026-10-26T16:01:00.000Z"),
        _gem_row("other", "1.0.0", "2026-10-26T16:02:00.000Z"),
    ]
    config = Config(db_path=db.path, rubygems=True, rubygems_url=GEM_BASE, watch_mode="watched")
    assert poll_rubygems(db, config, _gem_transport(page)) == 1
    assert _gem_queue(db) == set([("RedCloth", "4.3.3")])
    assert db.get_checkpoint(GEMS_CHECKPOINT) == "2026-10-26T16:02:00.000Z"


def test_rubygems_all_mode_ignores_the_user_list(tmp_path):
    db = _db(tmp_path)
    _user(db, ("rubygems", "rails"))
    db.set_checkpoint(GEMS_CHECKPOINT, "2026-10-26T15:00:00.000Z")
    page = [_gem_row("other", "1.0.0", "2026-10-26T16:02:00.000Z")]
    config = Config(db_path=db.path, rubygems=True, rubygems_url=GEM_BASE)
    assert poll_rubygems(db, config, _gem_transport(page)) == 1


def test_rubygems_watched_mode_with_an_empty_list_queues_nothing(tmp_path):
    db = _db(tmp_path)
    db.set_checkpoint(GEMS_CHECKPOINT, "2026-10-26T15:00:00.000Z")
    page = [_gem_row("other", "1.0.0", "2026-10-26T16:02:00.000Z")]
    config = Config(db_path=db.path, rubygems=True, rubygems_url=GEM_BASE, watch_mode="watched")
    assert poll_rubygems(db, config, _gem_transport(page)) == 0
    assert db.get_checkpoint(GEMS_CHECKPOINT) == "2026-10-26T16:02:00.000Z"


# --- crates.io watched mode ---------------------------------------------------


def _pub(hour: int) -> str:
    return "Thu, 01 Jan 2026 %02d:00:00 GMT" % hour


def _rss(*items: tuple[str, str, str]) -> bytes:
    body = ["<?xml version='1.0'?><rss version='2.0'><channel>"]
    for title, link, published in items:
        body.append("<item><title>%s</title><link>%s</link><pubDate>%s</pubDate></item>" % (title, link, published))
    body.append("</channel></rss>")
    return "".join(body).encode()


class _Web:
    def __init__(self, updates: bytes):
        self.routes = {UPDATES: updates, NAMES: _rss()}
        self.urls: list[str] = []

    def __call__(self, url: str, timeout: float = 60) -> bytes:
        self.urls.append(url)
        if url not in self.routes:
            raise AssertionError("unexpected fetch " + url)
        return self.routes[url]


def _crates_config(db: Database, **extra) -> Config:
    return Config(
        db_path=db.path,
        crates=True,
        crates_updates_rss=UPDATES,
        crates_crates_rss=NAMES,
        crates_api=API,
        max_pending=100,
        **extra,
    )


def _crate_updates() -> bytes:
    return _rss(
        ("old v0.9.0", "https://crates.io/crates/old/0.9.0", _pub(1)),
        ("serde v1.0.1", "https://crates.io/crates/serde/1.0.1", _pub(2)),
        ("Inflector v0.11.5", "https://crates.io/crates/Inflector/0.11.5", _pub(3)),
        ("tokio v1.0.1", "https://crates.io/crates/tokio/1.0.1", _pub(4)),
        ("seerde v1.0.0", "https://crates.io/crates/seerde/1.0.0", _pub(5)),
    )


def _crate_jobs(db: Database) -> dict[tuple[str, str], int | None]:
    return dict(((row["name"], row["version"]), row["rank"]) for row in db.pending_jobs(limit=200))


def test_crates_watched_mode_queues_listed_names_only_and_fetches_no_popular_list(tmp_path):
    db = _db(tmp_path)
    _user(db, ("crates", "serde"), ("crates", "inflector"))
    # A ranked name must not matter, and no lookalike of it is queued.
    db.replace_watchlist("crates", [("tokio", 1, 99)])
    db.set_checkpoint("crates", "2026-01-01T01:00:00Z")
    web = _Web(_crate_updates())
    config = _crates_config(db, watch_mode="watched")
    assert poll_crates(db, config, web) == 2
    assert set(_crate_jobs(db)) == set([("serde", "1.0.1"), ("inflector", "0.11.5")])
    assert web.urls == [UPDATES, NAMES]  # no API call for the download-rank list
    assert db.get_checkpoint("crates") == "2026-01-01T05:00:00Z"


def test_crates_watched_mode_backfill_reads_only_listed_crates(tmp_path):
    db = _db(tmp_path)
    _user(db, ("crates", "serde"))
    db.set_checkpoint("crates", "2026-01-01T00:00:00Z")
    web = _Web(_rss(("serde v1.0.1", "https://crates.io/crates/serde/1.0.1", _pub(10))))
    listing = dict(
        crates=[
            dict(name="tokio", updated_at="2026-01-01T05:00:00Z"),
            dict(name="serde", updated_at="2026-01-01T04:00:00Z"),
            dict(name="old", updated_at="2025-12-31T00:00:00Z"),
        ]
    )
    web.routes[API + "/api/v1/crates?sort=updated&per_page=100&page=1"] = json.dumps(listing).encode()
    line = json.dumps(dict(name="serde", vers="1.0.0", cksum="x", yanked=False)).encode() + b"\n"
    seen: list[str] = []

    def transport(url: str, timeout: float = 60) -> bytes:
        seen.append(url)
        if url.endswith("/se/rd/serde"):
            return line
        return web(url, timeout)

    config = _crates_config(db, watch_mode="watched", crates_index="https://index.test")
    poll_crates(db, config, transport)
    assert any(url.endswith("/se/rd/serde") for url in seen)
    assert not any(url.endswith("/to/ki/tokio") for url in seen)


def test_crates_watched_only_flag_also_queues_user_names(tmp_path):
    db = _db(tmp_path)
    _user(db, ("crates", "tokio"))
    db.replace_watchlist("crates", [("serde", 1, 99)])
    db.set_checkpoint("crates", "2026-01-01T01:00:00Z")
    config = _crates_config(db, crates_watched_only=True, watchlist_refresh=10**9)
    assert poll_crates(db, config, _Web(_crate_updates())) == 3
    jobs = _crate_jobs(db)
    assert set(jobs) == set([("serde", "1.0.1"), ("tokio", "1.0.1"), ("seerde", "1.0.0")])
    assert jobs[("tokio", "1.0.1")] is None  # listed by the user only, so it has no rank


def test_crates_all_mode_still_queues_the_whole_feed(tmp_path):
    db = _db(tmp_path)
    _user(db, ("crates", "serde"))
    db.replace_watchlist("crates", [("serde", 1, 99)])
    db.set_checkpoint("crates", "2026-01-01T01:00:00Z")
    config = _crates_config(db, watchlist_refresh=10**9)
    assert poll_crates(db, config, _Web(_crate_updates())) == 4


def test_serve_starts_the_gem_and_crate_polls_in_watched_mode():
    source = inspect.getsource(serve)
    assert "polls are not started" not in source
    assert "if config.rubygems:" in source and "if config.crates:" in source
