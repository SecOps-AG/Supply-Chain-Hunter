"""Ground-truth job: OSV MAL- records and npm takedowns against Hunter's scored releases.

Every OSV record, packument and git call is made up and faked. Nothing touches the
network, and no package code is downloaded or run.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from hunter import cli
from hunter.config import Config
from hunter.db import Database, iso
from hunter.ground_truth import (
    MAX_RECORD_BYTES,
    NPM_HOLDER_VERSION,
    REPORT_NAME,
    OsvApiSource,
    OsvGitSource,
    build_report,
    check_npm_takedowns,
    make_source,
    npm_takedown_time,
    parse_mal_record,
    report_is_fresh,
    run_ground_truth,
    ttd_stats,
)
from hunter.registry import FeedError

NOW = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
REGISTRY = "https://registry.example"


def mal(record_id, ecosystem, name, *, versions=(), ranges=None, published=NOW - timedelta(hours=10), **extra):
    affected = {"package": {"ecosystem": ecosystem, "name": name}}
    if versions:
        affected["versions"] = list(versions)
    if ranges is not None:
        affected["ranges"] = ranges
    return {
        "id": record_id,
        "published": iso(published),
        "modified": iso(published),
        "affected": [affected],
        **extra,
    }


def all_versions():
    return [{"type": "SEMVER", "events": [{"introduced": "0"}]}]


def make_config(tmp_path: Path, **overrides) -> Config:
    config = Config(db_path=tmp_path / "hunter.sqlite3", npm_registry=REGISTRY, osv_api="https://osv.example")
    for key, value in overrides.items():
        setattr(config, key, value)
    return config


def save(db, ecosystem, name, version, band, when):
    db.save_release(ecosystem, name, version, band, 0.5, "none", None, "{}", when=when)


def no_network(url, timeout=60, **_kw):
    raise AssertionError(f"unexpected fetch {url}")


# ---- record parsing and version matching -----------------------------------


def test_parse_skips_non_mal_withdrawn_and_other_ecosystems():
    assert parse_mal_record(mal("GHSA-1", "npm", "x", versions=["1.0.0"])) is None
    assert parse_mal_record(mal("MAL-1", "npm", "x", versions=["1.0.0"], withdrawn=iso(NOW))) is None
    assert parse_mal_record(mal("MAL-2", "Go", "x", versions=["1.0.0"])) is None
    crates = parse_mal_record(mal("MAL-2", "crates.io", "x", versions=["1.0.0"]))
    assert ("crates", "x") in crates.affected
    assert parse_mal_record(["not", "a", "record"]) is None
    record = parse_mal_record(mal("MAL-3", "PyPI", "Evil_Pkg", versions=["1.0"]))
    assert ("pypi", "evil-pkg") in record.affected


def test_explicit_versions_and_ranges():
    listed = parse_mal_record(mal("MAL-1", "npm", "x", versions=["1.2.3"]))
    assert listed.affects("npm", "x", "1.2.3")
    assert not listed.affects("npm", "x", "1.2.4")

    everything = parse_mal_record(mal("MAL-2", "npm", "x", ranges=all_versions()))
    assert everything.affects("npm", "x", "9.9.9")

    bounded = parse_mal_record(
        mal(
            "MAL-3",
            "npm",
            "x",
            ranges=[{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.0.5"}]}],
        )
    )
    assert bounded.affects("npm", "x", "1.0.2")
    assert not bounded.affects("npm", "x", "1.0.5")
    assert not bounded.affects("npm", "x", "0.9.0")
    assert bounded.affects("npm", "x", "1.0.5-beta.1")

    pypi = parse_mal_record(
        mal(
            "MAL-4",
            "PyPI",
            "x",
            ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}, {"last_affected": "2.1"}]}],
        )
    )
    assert pypi.affects("pypi", "x", "2.1")
    assert not pypi.affects("pypi", "x", "2.1.1")
    assert not pypi.affects("pypi", "x", "not a version")


def test_git_ranges_are_ignored():
    record = parse_mal_record(mal("MAL-1", "npm", "x", versions=["1.0.0"], ranges=[{"type": "GIT", "events": [{"introduced": "0"}]}]))
    assert not record.affects("npm", "x", "2.0.0")


# ---- report -----------------------------------------------------------------


def _row(ecosystem, name, version, band, created_at, confirmed_at=None):
    return {
        "ecosystem": ecosystem,
        "name": name,
        "version": version,
        "band": band,
        "created_at": iso(created_at),
        "confirmed_at": iso(confirmed_at) if confirmed_at else None,
    }


def test_build_report_recall_and_time_to_detect():
    records = [
        parse_mal_record(mal("MAL-1", "npm", "caught", versions=["1.0.1"], published=NOW - timedelta(hours=4))),
        parse_mal_record(mal("MAL-2", "npm", "missed", versions=["2.0.0"], published=NOW - timedelta(hours=4))),
        parse_mal_record(mal("MAL-3", "PyPI", "Late_One", ranges=all_versions(), published=NOW - timedelta(hours=1))),
        parse_mal_record(mal("MAL-4", "npm", "waiting", versions=["1.0.0"])),
    ]
    releases = [
        _row("npm", "caught", "1.0.1", "alert", NOW - timedelta(hours=6), confirmed_at=NOW - timedelta(hours=2)),
        _row("npm", "caught", "1.0.0", "benign", NOW - timedelta(days=3)),
        _row("npm", "missed", "2.0.0", "benign", NOW - timedelta(hours=5)),
        _row("pypi", "late-one", "0.1", "review", NOW + timedelta(hours=1)),
        _row("npm", "waiting", "1.0.0", "deferred", NOW),
        _row("npm", "clean", "3.0.0", "benign", NOW),
    ]
    report = build_report(releases, records, {}, now=NOW, meta={"source": "test"})
    summary = report["summary"]
    assert report["source"] == "test"
    assert summary["malicious_seen"] == 3
    assert summary["caught"] == 2
    assert summary["missed"] == 1
    assert summary["recall"] == pytest.approx(0.6667)
    assert summary["confirmed"] == 1
    assert summary["deferred"] == 1
    assert summary["by_ecosystem"]["npm"] == {
        "malicious_seen": 2,
        "caught": 1,
        "missed": 1,
        "recall": 0.5,
        "confirmed": 1,
        "confirmed_recall": 0.5,
    }
    ttd = summary["time_to_detect_hours"]
    # Hunter flagged npm/caught 2h before OSV; pypi/late-one 2h after.
    assert ttd["count"] == 2
    assert ttd["min"] == -2.0
    assert ttd["max"] == 2.0
    assert ttd["hunter_first"] == 1
    assert summary["confirmed_time_to_detect_hours"]["median"] == 2.0
    by_key = {(item["name"], item["version"]): item for item in report["items"]}
    assert by_key[("missed", "2.0.0")]["caught"] is False
    assert by_key[("missed", "2.0.0")]["time_to_detect_hours"] is None
    assert by_key[("caught", "1.0.1")]["osv_ids"] == ["MAL-1"]
    assert ("caught", "1.0.0") not in by_key


def test_takedown_marks_every_npm_version_and_uses_earliest_truth():
    records = [parse_mal_record(mal("MAL-1", "npm", "gone", versions=["1.0.0"], published=NOW))]
    releases = [
        _row("npm", "gone", "1.0.0", "alert", NOW - timedelta(hours=1)),
        _row("npm", "gone", "0.9.0", "benign", NOW - timedelta(days=1)),
        _row("npm", "gone", NPM_HOLDER_VERSION, "benign", NOW + timedelta(hours=1)),
    ]
    report = build_report(releases, records, {"gone": NOW - timedelta(hours=3)}, now=NOW)
    by_version = {item["version"]: item for item in report["items"]}
    assert set(by_version) == {"1.0.0", "0.9.0"}
    assert by_version["1.0.0"]["truth_sources"] == ["osv", "npm_takedown"]
    assert by_version["1.0.0"]["time_to_detect_hours"] == 2.0
    assert by_version["0.9.0"]["truth_sources"] == ["npm_takedown"]
    assert report["summary"]["by_source"] == {"osv": 1, "npm_takedown": 2}


def test_takedown_without_time_labels_but_skips_time_to_detect():
    releases = [_row("npm", "gone", "1.0.0", "alert", NOW - timedelta(hours=1))]
    report = build_report(releases, [], {"gone": None}, now=NOW)
    [item] = report["items"]
    assert item["caught"] is True
    assert item["truth_sources"] == ["npm_takedown"]
    assert item["truth_at"] is None
    assert item["time_to_detect_hours"] is None
    assert report["summary"]["time_to_detect_hours"]["count"] == 0
    assert report["summary"]["time_to_detect_hours"]["hunter_first"] == 0


def test_build_report_uses_scored_at_over_created_at():
    records = [parse_mal_record(mal("MAL-1", "npm", "late", versions=["1.0.0"], published=NOW))]
    row = _row("npm", "late", "1.0.0", "review", NOW - timedelta(hours=5))
    row["scored_at"] = iso(NOW + timedelta(hours=3))
    report = build_report([row], records, {}, now=NOW)
    [item] = report["items"]
    assert item["scored_at"] == iso(NOW + timedelta(hours=3))
    assert item["time_to_detect_hours"] == 3.0


def test_ttd_stats_empty_and_percentile():
    assert ttd_stats([])["median"] is None
    stats = ttd_stats([1.0, 2.0, 3.0, 4.0, 100.0])
    assert stats["median"] == 3.0
    assert stats["p90"] == 100.0


# ---- OSV API source ----------------------------------------------------------


class FakeOsv:
    def __init__(self, records: dict[str, dict], index: dict[tuple[str, str], list[str]]):
        self.records = records
        self.index = index
        self.posts: list[dict] = []
        self.gets: list[str] = []

    def post(self, url, body, timeout):
        assert url == "https://osv.example/v1/querybatch"
        payload = json.loads(body)
        self.posts.append(payload)
        results = []
        for query in payload["queries"]:
            package = query["package"]
            ids = self.index.get((package["ecosystem"], package["name"]), [])
            results.append({"vulns": [{"id": rid, "modified": self.records[rid]["modified"]} for rid in ids]})
        return json.dumps({"results": results}).encode()

    def get(self, url, timeout=60, **_kw):
        self.gets.append(url)
        prefix = "https://osv.example/v1/vulns/"
        assert url.startswith(prefix)
        return json.dumps(self.records[url[len(prefix):]]).encode()


def test_api_source_queries_names_fetches_mal_and_caches(tmp_path):
    records = {
        "MAL-2026-1": mal("MAL-2026-1", "npm", "bad", versions=["1.0.0"]),
        "GHSA-xxxx": {"id": "GHSA-xxxx", "modified": iso(NOW)},
    }
    fake = FakeOsv(records, {("npm", "bad"): ["MAL-2026-1", "GHSA-xxxx"], ("PyPI", "fine"): []})
    source = OsvApiSource(tmp_path, "https://osv.example", transport=fake.get, post=fake.post)
    found = source.records({("npm", "bad"), ("pypi", "fine")})
    assert [record.id for record in found] == ["MAL-2026-1"]
    assert fake.gets == ["https://osv.example/v1/vulns/MAL-2026-1"]
    assert {q["package"]["ecosystem"] for q in fake.posts[0]["queries"]} == {"npm", "PyPI"}

    # Unchanged modified time: served from the cache.
    source.records({("npm", "bad")})
    assert len(fake.gets) == 1
    # Offline reads only the cache.
    offline = OsvApiSource(tmp_path, "https://osv.example", transport=no_network, post=no_network)
    assert [record.id for record in offline.records(set(), fetch=False)] == ["MAL-2026-1"]


def test_api_source_follows_page_tokens(tmp_path):
    records = {rid: mal(rid, "npm", "bad", versions=["1.0.0"]) for rid in ("MAL-1", "MAL-2")}
    calls = []

    def post(url, body, timeout):
        query = json.loads(body)["queries"][0]
        calls.append(query)
        if "page_token" not in query:
            return json.dumps({"results": [{"vulns": [{"id": "MAL-1", "modified": records["MAL-1"]["modified"]}], "next_page_token": "p2"}]}).encode()
        return json.dumps({"results": [{"vulns": [{"id": "MAL-2", "modified": records["MAL-2"]["modified"]}]}]}).encode()

    def get(url, timeout=60, **_kw):
        return json.dumps(records[url.rsplit("/", 1)[1]]).encode()

    found = OsvApiSource(tmp_path, "https://osv.example", transport=get, post=post).records({("npm", "bad")})
    assert sorted(record.id for record in found) == ["MAL-1", "MAL-2"]
    assert calls[1]["page_token"] == "p2"


# ---- git source -------------------------------------------------------------


def _write_record(root: Path, ecosystem_dir: str, name: str, record: dict) -> None:
    folder = root / "malicious-packages" / "osv" / "malicious" / ecosystem_dir / name
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{record['id']}.json").write_text(json.dumps(record), encoding="utf-8")


def test_git_source_clones_then_fetches_and_reads_by_folder(tmp_path):
    calls = []

    def git(args, cwd):
        calls.append(args)
        if args[0] == "clone":
            (Path(args[-1]) / ".git").mkdir(parents=True)

    _write_record(tmp_path, "npm", "@scope/bad", mal("MAL-1", "npm", "@scope/bad", versions=["1.0.0"]))
    _write_record(tmp_path, "pypi", "Bad_Py", mal("MAL-2", "PyPI", "Bad_Py", versions=["0.1"]))
    _write_record(tmp_path, "npm", "unrelated", mal("MAL-3", "npm", "unrelated", versions=["1.0.0"]))

    source = OsvGitSource(tmp_path, "https://git.example/repo.git", git=git)
    found = source.records({("npm", "@scope/bad"), ("pypi", "bad-py"), ("npm", "../../etc")})
    assert sorted(record.id for record in found) == ["MAL-1", "MAL-2"]
    assert calls[0][:2] == ["clone", "--depth"]
    assert "--sparse" in calls[0]
    assert calls[1][:2] == ["sparse-checkout", "set"]

    calls.clear()
    source.records({("npm", "@scope/bad")})
    assert calls[0][0] == "fetch"
    assert calls[1] == ["reset", "--hard", "FETCH_HEAD"]

    calls.clear()
    source.records({("npm", "@scope/bad")}, fetch=False)
    assert calls == []


def test_git_source_reads_crates_from_the_crates_folder(tmp_path):
    _write_record(tmp_path, "crates.io", "badcrate", mal("MAL-9", "crates.io", "badcrate", versions=["0.1.0"]))
    _write_record(tmp_path, "npm", "badcrate", mal("MAL-8", "npm", "badcrate", versions=["0.1.0"]))
    source = OsvGitSource(tmp_path, "unused", git=lambda args, cwd: None)
    found = source.records({("crates", "badcrate")}, fetch=False)
    assert [record.id for record in found] == ["MAL-9"]


def test_git_source_skips_symlinked_and_oversized_files(tmp_path):
    folder = tmp_path / "malicious-packages" / "osv" / "malicious" / "npm" / "bad"
    folder.mkdir(parents=True)
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps(mal("MAL-9", "npm", "bad", versions=["1.0.0"])), encoding="utf-8")
    (folder / "MAL-9.json").symlink_to(outside)
    (folder / "MAL-10.json").write_text(" " * (3 * 1024 * 1024), encoding="utf-8")
    source = OsvGitSource(tmp_path, "unused", git=lambda args, cwd: None)
    assert source.records({("npm", "bad")}, fetch=False) == []


# ---- npm takedowns ----------------------------------------------------------


def npm_registry(holders: dict[str, str]):
    calls = []

    def get(url, timeout=60, **_kw):
        calls.append(url)
        name = url[len(REGISTRY) + 1 :]
        if name.endswith(f"/{NPM_HOLDER_VERSION}"):
            base = name[: -len(NPM_HOLDER_VERSION) - 1]
            if base in holders:
                return json.dumps({"name": base, "version": NPM_HOLDER_VERSION}).encode()
            raise FeedError("Not Found")
        if name in holders:
            times = {NPM_HOLDER_VERSION: holders[name]} if holders[name] else {}
            return json.dumps({"name": name, "time": times}).encode()
        raise FeedError("Not Found")

    get.calls = calls
    return get


def test_npm_takedown_time():
    get = npm_registry({"gone": "2026-09-30T08:00:00.000Z"})
    assert npm_takedown_time("gone", REGISTRY, get) == (True, datetime(2026, 9, 30, 8, tzinfo=timezone.utc))
    assert npm_takedown_time("alive", REGISTRY, get) == (False, None)

    def broken(url, timeout=60, **_kw):
        raise FeedError("timed out")

    with pytest.raises(FeedError):
        npm_takedown_time("x", REGISTRY, broken)


def test_npm_takedown_time_without_holder_time_is_unknown_not_now():
    assert npm_takedown_time("gone", REGISTRY, npm_registry({"gone": None})) == (True, None)

    def oversized(url, timeout=60, **_kw):
        if url.endswith(f"/{NPM_HOLDER_VERSION}"):
            return json.dumps({"name": "big", "version": NPM_HOLDER_VERSION}).encode()
        return b" " * (MAX_RECORD_BYTES + 1)

    assert npm_takedown_time("big", REGISTRY, oversized) == (True, None)


def test_check_npm_takedowns_keeps_takedown_with_unknown_time(tmp_path):
    cache = tmp_path / "takedowns.json"
    found, checked, _ = check_npm_takedowns(
        ["gone"], flagged=set(), cache_path=cache, registry=REGISTRY, limit=5, transport=npm_registry({"gone": None}), now=NOW
    )
    assert checked == 1 and found == {"gone": None}
    found, checked, _ = check_npm_takedowns(
        ["gone"], flagged=set(), cache_path=cache, registry=REGISTRY, limit=5, transport=no_network, now=NOW
    )
    assert checked == 0 and found == {"gone": None}


def test_check_npm_takedowns_drops_check_time_cached_as_takedown_time(tmp_path):
    cache = tmp_path / "takedowns.json"
    cache.write_text(
        json.dumps(
            {
                "faked": {"checked_at": iso(NOW), "takedown_at": iso(NOW + timedelta(seconds=1))},
                "real": {"checked_at": iso(NOW), "takedown_at": iso(NOW - timedelta(days=1))},
            }
        )
    )
    found, checked, _ = check_npm_takedowns(
        ["faked", "real"], flagged=set(), cache_path=cache, registry=REGISTRY, limit=5, transport=no_network, now=NOW
    )
    assert checked == 0
    assert found == {"faked": None, "real": NOW - timedelta(days=1)}


def test_check_npm_takedowns_limits_orders_and_caches(tmp_path):
    cache = tmp_path / "takedowns.json"
    get = npm_registry({"gone": "2026-09-30T08:00:00Z"})
    found, checked, errors = check_npm_takedowns(
        ["a", "b", "gone"], flagged={"gone"}, cache_path=cache, registry=REGISTRY, limit=1, transport=get, now=NOW
    )
    assert checked == 1 and errors == []
    assert set(found) == {"gone"}

    # The known takedown is not checked again; the next oldest names are.
    get.calls.clear()
    found, checked, _ = check_npm_takedowns(
        ["a", "b", "gone"], flagged={"gone"}, cache_path=cache, registry=REGISTRY, limit=5, transport=get, now=NOW
    )
    assert checked == 2
    assert not any("/gone" in url for url in get.calls)
    assert set(found) == {"gone"}

    found, checked, _ = check_npm_takedowns(
        ["gone"], flagged=set(), cache_path=cache, registry=REGISTRY, limit=5, transport=no_network, fetch=False
    )
    assert checked == 0 and set(found) == {"gone"}


def test_check_npm_takedowns_honours_stop(tmp_path):
    stop = threading.Event()
    stop.set()
    _found, checked, _ = check_npm_takedowns(
        ["a"], flagged=set(), cache_path=tmp_path / "c.json", registry=REGISTRY, limit=5, transport=no_network, stop=stop
    )
    assert checked == 0


# ---- end to end -------------------------------------------------------------


class StaticSource:
    name = "static"

    def __init__(self, records, fail=False):
        self._records = records
        self.fail = fail
        self.seen = None

    def records(self, packages, *, fetch=True):
        self.seen = set(packages)
        if fetch and self.fail:
            raise FeedError("osv down")
        return [parse_mal_record(record) for record in self._records]


def test_run_ground_truth_writes_report(tmp_path):
    config = make_config(tmp_path, ground_truth_npm_checks=10)
    db = Database(config.db_path)
    try:
        save(db, "npm", "evil", "1.0.0", "alert", NOW - timedelta(hours=12))
        save(db, "pypi", "sneaky", "2.0", "benign", NOW - timedelta(hours=12))
        save(db, "npm", "held", "1.0.0", "benign", NOW - timedelta(days=2))
        save(db, "npm", "held", NPM_HOLDER_VERSION, "benign", NOW - timedelta(days=1))
        save(db, "npm", "ancient", "1.0.0", "alert", NOW - timedelta(days=90))
        db.insert_public_feed_item(
            ecosystem="npm",
            name="evil",
            version="1.0.0",
            previous_version="0.9.0",
            registry_url="https://www.npmjs.com/package/evil",
            behavior="b",
            cause="c",
            limited_review=False,
            first_seen_at=iso(NOW - timedelta(hours=11)),
        )
        source = StaticSource(
            [
                mal("MAL-1", "npm", "evil", versions=["1.0.0"], published=NOW - timedelta(hours=10)),
                mal("MAL-2", "PyPI", "sneaky", versions=["2.0"]),
            ]
        )
        report = run_ground_truth(db, config, source=source, transport=npm_registry({}), now=NOW)
    finally:
        db.close()
    assert ("npm", "ancient") not in source.seen
    summary = report["summary"]
    assert summary["malicious_seen"] == 3
    assert summary["caught"] == 1
    assert summary["confirmed"] == 1
    assert summary["time_to_detect_hours"]["median"] == -2.0
    assert summary["confirmed_time_to_detect_hours"]["median"] == -1.0
    assert report["npm_checked"] == 1  # "held" came from Hunter's own feed and is not looked up
    written = json.loads((tmp_path / "ground-truth" / REPORT_NAME).read_text())
    assert written["summary"] == summary
    assert report_is_fresh(config)


def test_rescore_after_deferred_moves_scored_at(tmp_path):
    config = make_config(tmp_path)
    db = Database(config.db_path)
    try:
        save(db, "npm", "slow", "1.0.0", "deferred", NOW - timedelta(hours=10))
        db.save_release("npm", "slow", "1.0.0", "review", 0.9, "none", None, "{}", when=NOW - timedelta(hours=2), replace=True)
        # A re-save in the same band keeps the time it was first put there.
        db.save_release("npm", "slow", "1.0.0", "review", 0.9, "none", None, "{}", when=NOW, replace=True)
        [row] = db.ground_truth_releases("")
        assert row["created_at"] == iso(NOW - timedelta(hours=10))
        assert row["scored_at"] == iso(NOW - timedelta(hours=2))
        source = StaticSource([mal("MAL-1", "npm", "slow", versions=["1.0.0"], published=NOW - timedelta(hours=6))])
        report = run_ground_truth(db, config, source=source, transport=npm_registry({}), days=0, now=NOW)
    finally:
        db.close()
    # Flagged 4h after OSV, not 4h before it.
    assert report["summary"]["time_to_detect_hours"]["median"] == 4.0
    assert report["summary"]["time_to_detect_hours"]["hunter_first"] == 0


def test_scored_at_column_added_to_existing_db(tmp_path):
    path = tmp_path / "old.sqlite3"
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE releases (
            ecosystem TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL, band TEXT,
            malice_probability REAL, family TEXT, subtype TEXT, payload_json TEXT,
            created_at TEXT NOT NULL, PRIMARY KEY (ecosystem, name, version)
        )
        """
    )
    conn.execute(
        "INSERT INTO releases VALUES ('npm', 'old', '1.0.0', 'review', 0.9, 'none', NULL, '{}', ?)",
        (iso(NOW),),
    )
    conn.commit()
    conn.close()
    db = Database(path)
    try:
        [row] = db.ground_truth_releases("")
        assert row["scored_at"] == iso(NOW)
        db.save_release("npm", "old", "1.0.0", "alert", 0.9, "none", None, "{}", when=NOW + timedelta(hours=1), replace=True)
        [row] = db.ground_truth_releases("")
        assert row["scored_at"] == iso(NOW + timedelta(hours=1))
    finally:
        db.close()


def test_run_ground_truth_falls_back_to_cache_on_source_error(tmp_path):
    config = make_config(tmp_path, ground_truth_npm_checks=0)
    db = Database(config.db_path)
    try:
        save(db, "npm", "evil", "1.0.0", "benign", NOW - timedelta(hours=1))
        source = StaticSource([mal("MAL-1", "npm", "evil", versions=["1.0.0"])], fail=True)
        report = run_ground_truth(db, config, source=source, transport=no_network, now=NOW, out=tmp_path / "r.json")
    finally:
        db.close()
    assert report["errors"] == ["osv static: osv down"]
    assert report["summary"]["missed"] == 1
    assert (tmp_path / "r.json").exists()


# ---- config, CLI and service -----------------------------------------------


def test_config_off_by_default(monkeypatch, tmp_path):
    for name in ("HUNTER_GROUND_TRUTH", "HUNTER_GROUND_TRUTH_SOURCE", "HUNTER_GROUND_TRUTH_INTERVAL"):
        monkeypatch.delenv(name, raising=False)
    config = Config.from_env()
    assert config.ground_truth is False
    assert config.ground_truth_source == "api"
    assert config.ground_truth_interval == 24 * 3600

    monkeypatch.setenv("HUNTER_GROUND_TRUTH", "1")
    monkeypatch.setenv("HUNTER_GROUND_TRUTH_SOURCE", "git")
    monkeypatch.setenv("HUNTER_GROUND_TRUTH_INTERVAL", "60")
    monkeypatch.setenv("HUNTER_GROUND_TRUTH_DIR", str(tmp_path))
    config = Config.from_env()
    assert config.ground_truth is True
    assert config.ground_truth_interval == 3600
    assert isinstance(make_source(config), OsvGitSource)
    assert make_source(config).checkout == tmp_path / "malicious-packages"
    with pytest.raises(ValueError):
        make_source(config, "zip")


def test_cli_offline_prints_summary(tmp_path, monkeypatch, capsys):
    db_path = tmp_path / "hunter.sqlite3"
    monkeypatch.setenv("HUNTER_DB", str(db_path))
    monkeypatch.setenv("HUNTER_GROUND_TRUTH_DIR", str(tmp_path / "gt"))
    cache = tmp_path / "gt" / "osv"
    cache.mkdir(parents=True)
    (cache / "MAL-1.json").write_text(json.dumps(mal("MAL-1", "npm", "evil", versions=["1.0.0"])))
    db = Database(db_path)
    save(db, "npm", "evil", "1.0.0", "review", datetime.now(timezone.utc))
    db.close()
    monkeypatch.setattr("hunter.ground_truth.http_get", no_network)
    monkeypatch.setattr("hunter.ground_truth.http_post_json", no_network)

    assert cli.main(["ground-truth", "--offline", "--days", "0"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert "items" not in payload
    assert "openvsx_items" not in payload
    assert payload["summary"]["caught"] == 1
    assert payload["fetched"] is False
    assert (tmp_path / "gt" / REPORT_NAME).exists()

    assert cli.main(["ground-truth", "--offline", "--days", "0", "--full"]) == 0
    full = json.loads(capsys.readouterr().out)
    assert "items" in full and "openvsx_items" in full


def test_service_skips_fresh_report_and_logs_failures(tmp_path, monkeypatch, caplog):
    from hunter import service

    config = make_config(tmp_path, ground_truth=True)
    calls = []
    monkeypatch.setattr("hunter.ground_truth.run_ground_truth", lambda *a, **k: calls.append(k) or {})
    service._ground_truth_safely(None, config, no_network)
    assert len(calls) == 1

    report = tmp_path / "ground-truth" / REPORT_NAME
    report.parent.mkdir(parents=True)
    report.write_text("{}")
    service._ground_truth_safely(None, config, no_network)
    assert len(calls) == 1

    report.unlink()

    def boom(*_a, **_k):
        raise RuntimeError("broken")

    monkeypatch.setattr("hunter.ground_truth.run_ground_truth", boom)
    service._ground_truth_safely(None, config, no_network)
    assert "ground truth run failed" in caplog.text


def test_openvsx_labels_stay_out_of_recall_and_survive_a_later_active(tmp_path):
    config = make_config(tmp_path, ground_truth_npm_checks=0)
    db = Database(config.db_path)
    try:
        save(db, "npm", "evil", "1.0.0", "alert", NOW - timedelta(hours=2))
        save(db, "openvsx", "reviewed.ext", "1.0.0", "review", NOW - timedelta(hours=2))
        db.save_release(
            "openvsx",
            "removed.ext",
            "1.0.0",
            "benign",
            0.0,
            "none",
            None,
            json.dumps({"signals": ["vsx_removed_before_review"]}),
            when=NOW - timedelta(hours=2),
        )
        db.save_release(
            "openvsx",
            "idle.ext",
            "1.0.0",
            "benign",
            0.0,
            "none",
            None,
            json.dumps({"signals": ["vsx_inactive_before_review"]}),
            when=NOW - timedelta(hours=2),
        )
        db.record_openvsx_label("removed.ext", "1.0.0", "universal", "removed", "2026-10-01T00:00:00Z")
        db.record_openvsx_label("idle.ext", "1.0.0", "universal", "inactive", "2026-10-01T01:00:00Z")
        db.record_openvsx_label("redhat.java", "1.29.0", "universal", "removed", "2026-10-01T02:00:00Z")
        db.record_openvsx_change(
            "redhat.java",
            "1.29.0",
            "universal",
            "ACTIVE",
            "2026-10-01T03:00:00Z",
            "2026-10-01T03:00:00Z",
        )
        assert {(row["name"], row["state"]) for row in db.openvsx_labels()} == {
            ("idle.ext", "inactive"),
            ("redhat.java", "removed"),
            ("removed.ext", "removed"),
        }
        source = StaticSource([mal("MAL-1", "npm", "evil", versions=["1.0.0"])])
        report = run_ground_truth(db, config, source=source, transport=no_network, now=NOW)
    finally:
        db.close()
    summary = report["summary"]
    assert summary["malicious_seen"] == 1
    assert summary["caught"] == 1
    assert summary["missed"] == 0
    assert {item["ecosystem"] for item in report["items"]} == {"npm"}
    assert ("openvsx", "reviewed.ext") not in source.seen
    assert summary["openvsx_registry"] == {
        "removed": 2,
        "inactive": 1,
        "scored": 3,
        "caught": 1,
        "not_reviewed": 2,
    }
    by_key = {(item["name"], item["version"]): item for item in report["openvsx_items"]}
    assert by_key[("reviewed.ext", "1.0.0")]["caught"] is True
    assert by_key[("removed.ext", "1.0.0")]["not_reviewed"] is True
    assert by_key[("removed.ext", "1.0.0")]["caught"] is False
    assert by_key[("removed.ext", "1.0.0")]["labels"][0]["state"] == "removed"
    assert by_key[("idle.ext", "1.0.0")]["not_reviewed"] is True
    retirement = by_key[("redhat.java", "1.29.0")]
    assert retirement["band"] is None
    assert retirement["caught"] is False
    assert retirement["not_reviewed"] is False
    assert retirement["labels"] == [
        {"platform": "universal", "state": "removed", "changed_at": "2026-10-01T02:00:00Z"}
    ]
