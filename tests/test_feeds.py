import json
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

from hunter.archives import FILE_CUT_MARKER, extract_archive
from hunter.config import Config
from hunter.db import Database
from hunter.registry import bootstrap_npm, load_npm_watchlist, versions_after
from hunter.service import ReleaseLoader, poll_npm, poll_pypi
from tests.archives_factory import BENIGN_NEW, BENIGN_OLD, tar_bytes


class FakePypi:
    def __init__(self):
        self.since_calls = []

    def last_serial(self):
        return 100

    def since(self, serial):
        self.since_calls.append(serial)
        return [
            ("Requests", "2.0.0", 0, "new release", 11),
            ("not-watched", "9.0.0", 0, "new release", 12),
            ("requests", "2.0.0", 0, "add source file", 13),
            ("requests", "1.9.0", 0, "remove release", 14),
        ]


def test_pypi_serial_does_not_skip_or_replay_removals(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    db.replace_watchlist("pypi", [("requests", 3, 1000)])
    db.set_checkpoint("pypi", "10")
    feed = FakePypi()
    assert poll_pypi(db, feed) == 1
    jobs = db.pending_jobs()
    assert [(row["name"], row["version"]) for row in jobs] == [("requests", "2.0.0")]
    assert db.get_checkpoint("pypi") == "14"
    assert feed.since_calls == [10]


def test_pypi_bootstrap_starts_at_the_current_serial(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    feed = FakePypi()
    assert poll_pypi(db, feed) == 0
    assert db.get_checkpoint("pypi") == "100"
    assert feed.since_calls == []


def test_npm_gap_is_paged_and_not_skipped(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    db.replace_watchlist("npm", [("color-hex-pad", 4, 5000)])
    db.set_checkpoint("npm", "0")
    db.set_package_cursor("npm", "color-hex-pad", "1.0.0", "2026-01-01T00:00:00.000Z")
    changes = [
        {"seq": "1", "id": "other-pkg"},
        {"seq": "2", "id": "color-hex-pad"},
        {"seq": "3", "id": "another-pkg"},
        {"seq": "4", "id": "color-hex-pad"},
        {"seq": "5", "id": "color-hex-pad"},
    ]
    seen = []
    meta = {
        "time": {
            "created": "2025-01-01T00:00:00.000Z",
            "modified": "2026-03-01T00:00:00.000Z",
            "1.0.0": "2026-01-01T00:00:00.000Z",
            "1.0.1": "2026-02-01T00:00:00.000Z",
            "1.0.2": "2026-03-01T00:00:00.000Z",
        },
        "dist-tags": {"latest": "1.0.2"},
        "versions": {"1.0.0": {}, "1.0.1": {}, "1.0.2": {}},
    }

    def transport(url, timeout):
        parsed = urlparse(url)
        if parsed.path.endswith("/_changes"):
            query = parse_qs(parsed.query)
            since = query["since"][0]
            limit = int(query["limit"][0])
            seen.append(since)
            eligible = [row for row in changes if int(row["seq"]) > int(since)]
            page = eligible[:limit]
            last = page[-1]["seq"] if page else since
            return json.dumps({"results": page, "last_seq": last}).encode()
        return json.dumps(meta).encode()

    config = Config(npm_page_size=2, npm_changes="https://replicate.npmjs.com", npm_registry="https://registry.npmjs.org")
    queued = poll_npm(db, config, transport)
    assert queued == 2
    versions = sorted(row["version"] for row in db.pending_jobs())
    assert versions == ["1.0.1", "1.0.2"]
    assert db.get_checkpoint("npm") == "5"
    assert seen == ["0", "2", "4"]


def test_score_loader_fetches_the_named_versions():
    old_blob = tar_bytes(BENIGN_OLD)
    new_blob = tar_bytes(BENIGN_NEW)
    document = {
        "time": {
            "1.0.0": "2026-01-01T00:00:00.000Z",
            "1.0.1": "2026-02-01T00:00:00.000Z",
        },
        "versions": {
            "1.0.0": {"dist": {"tarball": "https://registry.example/old.tgz"}},
            "1.0.1": {"dist": {"tarball": "https://registry.example/new.tgz"}},
        },
    }

    def transport(url, _timeout):
        if url.endswith("old.tgz"):
            return old_blob
        if url.endswith("new.tgz"):
            return new_blob
        return json.dumps(document).encode()

    loader = ReleaseLoader(Config(npm_registry="https://registry.example"), transport)
    old_files, new_files, meta = loader.load_versions("npm", "widget", "1.0.0", "1.0.1")
    assert meta.old_version == "1.0.0"
    assert meta.new_version == "1.0.1"
    assert any(path.endswith("package.json") and '"1.0.0"' in text for path, text in old_files.items())
    assert any(path.endswith("package.json") and '"1.0.1"' in text for path, text in new_files.items())


def _counts_transport(blob: bytes):
    meta = {"dist": {"tarball": "https://registry.example/download-counts.tgz"}}

    def transport(url, _timeout):
        if url.endswith(".tgz"):
            return blob
        return json.dumps(meta).encode()

    return transport


def test_npm_watchlist_reads_package_prefixed_counts():
    blob = tar_bytes({"package/counts.json": json.dumps({"left-pad": 9, "express": 3})})
    rows = load_npm_watchlist(1, "https://registry.example", _counts_transport(blob))
    assert rows == [("left-pad", 1, 9)]


def test_npm_watchlist_parses_counts_larger_than_the_file_read_cap(monkeypatch):
    monkeypatch.setenv("HUNTER_FILE_READ_BYTES", "200000")
    counts = {f"pkg-{index:05d}": 20_000 - index for index in range(20_000)}
    raw = json.dumps(counts, separators=(",", ":"))
    assert len(raw.encode()) > 200_000
    blob = tar_bytes({"package/counts.json": raw, "package/readme.md": "short"})
    truncated = extract_archive(blob)["package/counts.json"]
    assert truncated.endswith(FILE_CUT_MARKER)
    assert len(truncated[: -len(FILE_CUT_MARKER)].encode()) == 200_000
    rows = load_npm_watchlist(1, "https://registry.example", _counts_transport(blob))
    assert rows == [("pkg-00000", 1, 20_000)]


def test_npm_watchlist_reads_root_counts():
    blob = tar_bytes({"counts.json": json.dumps({"express": 4, "left-pad": 1})})
    rows = load_npm_watchlist(2, "https://registry.example", _counts_transport(blob))
    assert rows == [("express", 1, 4), ("left-pad", 2, 1)]


def test_npm_bootstrap_uses_descending_head_not_since_now(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    seen = []

    def transport(url, _timeout):
        seen.append(url)
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        assert "since" not in query
        assert query["descending"] == ["true"]
        assert query["limit"] == ["1"]
        return json.dumps({"results": [{"seq": "9001", "id": "left-pad"}], "last_seq": "9001"}).encode()

    bootstrap_npm(db, "https://replicate.npmjs.com", transport)
    assert seen == ["https://replicate.npmjs.com/_changes?descending=true&limit=1"]
    assert db.get_checkpoint("npm") == "9001"


def test_npm_poll_bootstrap_sets_checkpoint_without_replaying(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    seen = []

    def transport(url, _timeout):
        seen.append(url)
        return json.dumps({"last_seq": "42"}).encode()

    config = Config(npm_changes="https://replicate.npmjs.com", npm_registry="https://registry.npmjs.org")
    assert poll_npm(db, config, transport) == 0
    assert db.get_checkpoint("npm") == "42"
    assert seen == ["https://replicate.npmjs.com/_changes?descending=true&limit=1"]
    assert "since=now" not in seen[0]


def _npm_changes_transport(changes, metas):
    def transport(url, _timeout):
        parsed = urlparse(url)
        if parsed.path.endswith("/_changes"):
            query = parse_qs(parsed.query)
            since = query["since"][0]
            limit = int(query["limit"][0])
            eligible = [row for row in changes if int(row["seq"]) > int(since)]
            page = eligible[:limit]
            last = page[-1]["seq"] if page else since
            return json.dumps({"results": page, "last_seq": last}).encode()
        name = parsed.path.rstrip("/").split("/")[-1]
        return json.dumps(metas[name]).encode()

    return transport


def _npm_config(**overrides):
    values = {
        "npm_page_size": 10,
        "npm_changes": "https://replicate.example",
        "npm_registry": "https://registry.example",
    }
    values.update(overrides)
    return Config(**values)


def test_versions_after_without_a_cutoff_returns_every_version():
    meta = {
        "time": {
            "created": "2019-01-01T00:00:00.000Z",
            "modified": "2021-01-01T00:00:00.000Z",
            "1.0.0": "2020-01-01T00:00:00.000Z",
            "2.0.0": "2021-01-01T00:00:00.000Z",
        }
    }
    assert versions_after(meta, None) == [
        ("1.0.0", "2020-01-01T00:00:00.000Z"),
        ("2.0.0", "2021-01-01T00:00:00.000Z"),
    ]


def test_first_seen_npm_package_queues_only_versions_since_last_poll(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    db.replace_watchlist("npm", [("widget", 4, 5000)])
    db.set_checkpoint("npm", "0")
    db.mark_poll_success("npm", datetime(2026, 3, 1, tzinfo=timezone.utc))
    changes = [{"seq": "1", "id": "widget"}]
    meta = {
        "time": {
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2026-04-01T00:00:00.000Z",
            "0.1.0": "2020-01-01T00:00:00.000Z",
            "0.2.0": "2026-03-01T00:00:00.000Z",
            "0.3.0": "2026-03-01T00:00:00.500Z",
            "0.4.0": "2026-04-01T00:00:00.000Z",
        },
        "dist-tags": {"latest": "0.4.0"},
        "versions": {"0.1.0": {}, "0.2.0": {}, "0.3.0": {}, "0.4.0": {}},
    }
    queued = poll_npm(db, _npm_config(), _npm_changes_transport(changes, {"widget": meta}))
    assert queued == 2
    assert sorted(row["version"] for row in db.pending_jobs()) == ["0.3.0", "0.4.0"]
    assert db.get_package_cursor("npm", "widget") == ("0.4.0", "2026-04-01T00:00:00.000Z")
    assert db.get_checkpoint("npm") == "1"


def test_first_seen_npm_without_a_poll_watermark_queues_only_the_newest(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    db.replace_watchlist("npm", [("widget", 4, 5000)])
    db.set_checkpoint("npm", "0")
    changes = [{"seq": "1", "id": "widget"}]
    meta = {
        "time": {
            "1.0.0": "2020-01-01T00:00:00.000Z",
            "1.0.1": "2024-01-01T00:00:00.000Z",
            "9.9.9": "2026-05-01T00:00:00.000Z",
        },
        "dist-tags": {"latest": "9.9.9"},
    }
    queued = poll_npm(db, _npm_config(), _npm_changes_transport(changes, {"widget": meta}))
    assert queued == 1
    assert [row["version"] for row in db.pending_jobs()] == ["9.9.9"]
    assert db.get_package_cursor("npm", "widget") == ("9.9.9", "2026-05-01T00:00:00.000Z")


def test_npm_cursor_stops_before_a_release_the_queue_refused(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    db.replace_watchlist("npm", [("widget", 1, 10)])
    db.set_checkpoint("npm", "0")
    db.set_package_cursor("npm", "widget", "1.0.0", "2026-01-01T00:00:00.000Z")
    db.mark_poll_success("npm", datetime(2026, 1, 1, tzinfo=timezone.utc))
    watermark = db.last_poll()["npm"]
    changes = [{"seq": "1", "id": "unrelated"}, {"seq": "2", "id": "widget"}]
    meta = {
        "time": {
            "1.0.0": "2026-01-01T00:00:00.000Z",
            "1.0.1": "2026-02-01T00:00:00.000Z",
            "1.0.2": "2026-03-01T00:00:00.000Z",
        },
        "dist-tags": {"latest": "1.0.2"},
    }
    transport = _npm_changes_transport(changes, {"widget": meta})
    queued = poll_npm(db, _npm_config(max_pending=1), transport)
    assert queued == 1
    assert [(row["name"], row["version"]) for row in db.pending_jobs()] == [("widget", "1.0.1")]
    assert db.get_package_cursor("npm", "widget") == ("1.0.1", "2026-02-01T00:00:00.000Z")
    assert db.get_checkpoint("npm") == "1"
    assert db.last_poll()["npm"] == watermark

    queued = poll_npm(db, _npm_config(max_pending=5), transport)
    assert queued == 1
    assert sorted(row["version"] for row in db.pending_jobs()) == ["1.0.1", "1.0.2"]
    assert db.get_package_cursor("npm", "widget") == ("1.0.2", "2026-03-01T00:00:00.000Z")
    assert db.get_checkpoint("npm") == "2"


def test_npm_cursor_moves_past_a_release_already_stored(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    db.replace_watchlist("npm", [("widget", 1, 10)])
    db.set_checkpoint("npm", "0")
    db.set_package_cursor("npm", "widget", "1.0.0", "2026-01-01T00:00:00.000Z")
    assert db.enqueue_job("npm", "widget", "1.0.1", 1)
    changes = [{"seq": "2", "id": "widget"}]
    meta = {
        "time": {
            "1.0.0": "2026-01-01T00:00:00.000Z",
            "1.0.1": "2026-02-01T00:00:00.000Z",
            "1.0.2": "2026-03-01T00:00:00.000Z",
        },
        "dist-tags": {"latest": "1.0.2"},
    }
    transport = _npm_changes_transport(changes, {"widget": meta})
    assert poll_npm(db, _npm_config(max_pending=1), transport) == 0
    assert db.get_package_cursor("npm", "widget") == ("1.0.1", "2026-02-01T00:00:00.000Z")
    assert db.get_checkpoint("npm") == "0"
    assert [row["version"] for row in db.pending_jobs()] == ["1.0.1"]

    assert poll_npm(db, _npm_config(max_pending=2), transport) == 1
    assert sorted(row["version"] for row in db.pending_jobs()) == ["1.0.1", "1.0.2"]
    assert db.get_package_cursor("npm", "widget") == ("1.0.2", "2026-03-01T00:00:00.000Z")
    assert db.get_checkpoint("npm") == "2"


def test_npm_typosquat_cursor_waits_when_the_queue_refuses(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    db.replace_watchlist("npm", [("left-pad", 4, 5000)])
    db.set_checkpoint("npm", "0")
    changes = [{"seq": "1", "id": "leftpad"}]
    meta = {
        "time": {"1.2.0": "2026-04-01T00:00:00.000Z"},
        "dist-tags": {"latest": "1.2.0"},
        "versions": {"1.2.0": {}},
    }
    transport = _npm_changes_transport(changes, {"leftpad": meta})
    assert poll_npm(db, _npm_config(max_pending=0), transport) == 0
    assert db.pending_jobs() == []
    assert db.get_package_cursor("npm", "leftpad") == (None, None)
    assert db.get_checkpoint("npm") == "0"

    assert poll_npm(db, _npm_config(max_pending=5), transport) == 1
    assert [(row["name"], row["version"]) for row in db.pending_jobs()] == [("leftpad", "1.2.0")]
    assert db.get_package_cursor("npm", "leftpad") == ("1.2.0", "2026-04-01T00:00:00.000Z")
    assert db.get_checkpoint("npm") == "1"


class _TwoReleasePypi:
    def __init__(self, rows):
        self.rows = rows
        self.since_calls = []

    def since(self, serial):
        self.since_calls.append(serial)
        return self.rows


def test_pypi_checkpoint_waits_when_the_queue_refuses_a_release(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    db.replace_watchlist("pypi", [("requests", 3, 1000), ("flask", 4, 900)])
    db.set_checkpoint("pypi", "10")
    feed = _TwoReleasePypi(
        [
            ("requests", "2.0.0", 0, "new release", 11),
            ("flask", "3.0.0", 0, "new release", 12),
        ]
    )
    assert poll_pypi(db, feed, max_pending=1) == 1
    assert db.get_checkpoint("pypi") == "10"
    assert [(row["name"], row["version"]) for row in db.pending_jobs()] == [("requests", "2.0.0")]
    assert feed.since_calls == [10]

    assert poll_pypi(db, feed, max_pending=5) == 1
    assert sorted((row["name"], row["version"]) for row in db.pending_jobs()) == [
        ("flask", "3.0.0"),
        ("requests", "2.0.0"),
    ]
    assert db.get_checkpoint("pypi") == "12"
    assert feed.since_calls == [10, 10]


def test_pypi_checkpoint_advances_past_a_release_already_stored(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    db.replace_watchlist("pypi", [("requests", 3, 1000)])
    db.set_checkpoint("pypi", "10")
    assert db.enqueue_job("pypi", "requests", "2.0.0", 3)
    feed = _TwoReleasePypi([("requests", "2.0.0", 0, "new release", 11)])
    assert poll_pypi(db, feed, max_pending=1) == 0
    assert db.get_checkpoint("pypi") == "11"
    assert [row["version"] for row in db.pending_jobs()] == ["2.0.0"]
