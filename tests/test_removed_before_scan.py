"""A watched PyPI release that is removed before Hunter scans it becomes its own review item."""

from __future__ import annotations

from hunter.db import Database
from hunter.registry import pypi_events_to_versions, pypi_removed_releases
from hunter.service import poll_pypi

T = 1_700_000_000


class _Feed:
    def __init__(self, events):
        self.events = list(events)

    def last_serial(self):
        return 10

    def since(self, serial):
        return [event for event in self.events if int(event[4]) > int(serial)]


def _db(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    db.replace_watchlist("pypi", [("demo-pkg", 50, 1000)])
    db.set_checkpoint("pypi", "10")
    return db


def _items(db, kind="removed_before_scan"):
    return [row for row in db.human_review_queue() if row["kind"] == kind]


def test_only_whole_release_removals_on_watched_names_count():
    events = [
        ("demo-pkg", "2.0", T, "new release", 11),
        ("demo-pkg", "2.0", T, "remove file demo_pkg-2.0.tar.gz", 12),
        ("demo-pkg", "1.9", T, "yank release", 13),
        ("demo-pkg", None, T, "remove Owner someone", 14),
        ("other-pkg", "3.0", T, "remove release", 15),
        ("Demo_Pkg", "2.1", T, "remove release", 16),
        ("demo-pkg", "2.1", T, "remove release", 17),
    ]
    assert pypi_removed_releases(events, {"demo-pkg": 50}) == [("demo-pkg", "2.1", 50)]
    # Queueing still ignores removals.
    assert pypi_events_to_versions(events, {"demo-pkg": 50}) == [("demo-pkg", "2.0", 50)]


def test_release_added_and_removed_in_one_poll_is_a_review_item_not_a_retry(tmp_path):
    db = _db(tmp_path)
    try:
        events = [
            ("demo-pkg", "2.0", T, "new release", 11),
            ("demo-pkg", "2.0", T, "add py3 file demo_pkg-2.0-py3-none-any.whl", 12),
            ("demo-pkg", "2.0", T, "remove release", 13),
        ]
        poll_pypi(db, _Feed(events))
        items = _items(db)
        assert [(row["ecosystem"], row["name"], row["version"]) for row in items] == [("pypi", "demo-pkg", "2.0")]
        assert "removed" in items[0]["reason"]
        assert db.pending_count() == 0
        assert db.has_release_job("pypi", "demo-pkg", "2.0")
        assert db.get_checkpoint("pypi") == "13"
    finally:
        db.close()


def test_release_already_scanned_is_not_flagged(tmp_path):
    db = _db(tmp_path)
    try:
        db.save_release("pypi", "demo-pkg", "2.0", "benign", 0.01, "none", None, '{"signals": []}')
        poll_pypi(db, _Feed([("demo-pkg", "2.0", T, "remove release", 11)]))
        assert _items(db) == []
    finally:
        db.close()


def test_retrying_release_is_flagged_and_its_retry_closed(tmp_path):
    db = _db(tmp_path)
    try:
        db.enqueue_job("pypi", "demo-pkg", "2.0", 50)
        db.save_release(
            "pypi", "demo-pkg", "2.0", "deferred", 0.0, "none", None,
            '{"signals": ["ai_incomplete", "jev_retry", "no archive for demo-pkg 2.0"]}',
        )
        assert db.note_classify_failure("pypi", "demo-pkg", "2.0", 50, "no archive") == "retrying"
        assert db.retry_depth() == 1
        poll_pypi(db, _Feed([("demo-pkg", "2.0", T, "remove release", 11)]))
        assert len(_items(db)) == 1
        assert db.retry_depth() == 0
        assert db.pending_count() == 0
        assert _items(db, kind="classify") == []
    finally:
        db.close()


def test_unwatched_removal_is_ignored(tmp_path):
    db = _db(tmp_path)
    try:
        poll_pypi(db, _Feed([("other-pkg", "1.0", T, "remove release", 11)]))
        assert _items(db) == []
    finally:
        db.close()
