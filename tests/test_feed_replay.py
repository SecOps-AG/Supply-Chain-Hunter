import json
import threading
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import pytest

from hunter.cli import build_parser, main
from hunter.config import Config
from hunter.db import Database
from hunter.service import (
    FeedStart,
    apply_feed_start,
    npm_checkpoint_for_time,
    poll_npm,
    pypi_checkpoint_for_time,
    run_cycle,
    serve,
)


class _Pypi:
    def __init__(self, events, head):
        self.events = list(events)
        self.head = head
        self.since_calls = []

    def last_serial(self):
        return self.head

    def since(self, serial):
        self.since_calls.append(serial)
        return [event for event in self.events if int(event[4]) > int(serial)]


def _config(tmp_path, **kwargs):
    values = dict(
        db_path=tmp_path / "hunter.sqlite3",
        poll_interval=0.05,
        port=0,
        watchlist_refresh=1e12,
        smart_analysis=False,
        analyst=False,
        workers=1,
        webhook_url="",
        npm_changes="https://replicate.example",
        npm_registry="https://registry.example",
        npm_page_size=2,
    )
    values.update(kwargs)
    return Config(**values)


def _ready(tmp_path, *, pypi="1", npm="1"):
    db = Database(tmp_path / "hunter.sqlite3")
    db.replace_watchlist("pypi", [("requests", 1, 10)])
    db.replace_watchlist("npm", [("left-pad", 1, 10)])
    if pypi is not None:
        db.set_checkpoint("pypi", pypi)
    if npm is not None:
        db.set_checkpoint("npm", npm)
    return db


def _empty_npm(_url, _timeout):
    return json.dumps({"results": [], "last_seq": "1"}).encode()


def test_pypi_checkpoint_for_time_includes_the_window_and_not_older_events():
    events = [
        ("alpha", "1", 1_000, "new release", 10),
        ("alpha", "2", 2_000, "new release", 20),
        ("alpha", "3", 3_000, "new release", 30),
    ]
    feed = _Pypi(events, 30)
    assert pypi_checkpoint_for_time(feed, datetime.fromtimestamp(1_000, timezone.utc)) == 9
    assert pypi_checkpoint_for_time(feed, datetime.fromtimestamp(1_500, timezone.utc)) == 19
    assert pypi_checkpoint_for_time(feed, datetime.fromtimestamp(3_000, timezone.utc)) == 29
    assert pypi_checkpoint_for_time(feed, datetime.fromtimestamp(4_000, timezone.utc)) == 30
    assert feed.since(9)[0][4] == 10
    assert feed.since(19)[0][4] == 20
    assert feed.since(29)[0][4] == 30
    assert feed.since(30) == []


def _npm_time_transport(modified):
    def transport(url, _timeout):
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        if query.get("descending") == ["true"]:
            head = max(modified)
            return json.dumps({"results": [{"seq": head}], "last_seq": head}).encode()
        since = int(query["since"][0])
        later = sorted(seq for seq in modified if seq > since)
        if not later:
            return json.dumps({"results": [], "last_seq": since}).encode()
        seq = later[0]
        stamp = modified[seq]
        if stamp is None:
            row = {"seq": seq, "id": "gone", "deleted": True}
        else:
            row = {"seq": seq, "id": "left-pad", "doc": {"time": {"modified": stamp}}}
        return json.dumps({"results": [row], "last_seq": seq}).encode()

    return transport


def test_npm_checkpoint_for_time_starts_just_before_the_window():
    modified = {
        10: "2026-10-02T00:00:00Z",
        20: "2026-10-02T06:00:00Z",
        30: "2026-10-02T10:00:00Z",
    }
    now = datetime(2026, 10, 2, 12, 0, tzinfo=timezone.utc)
    target = now - timedelta(hours=3)
    seq = npm_checkpoint_for_time("https://replicate.example", target, _npm_time_transport(modified))
    assert seq == "29"


def test_npm_checkpoint_for_time_skips_deletions_without_a_timestamp():
    modified = {10: None, 11: "2026-10-02T11:00:00Z"}
    target = datetime(2026, 10, 2, 10, 0, tzinfo=timezone.utc)
    seq = npm_checkpoint_for_time("https://replicate.example", target, _npm_time_transport(modified))
    assert seq == "10"


def test_since_hours_does_not_skip_an_older_checkpoint(tmp_path):
    db = _ready(tmp_path, pypi="5", npm="5")
    events = [("requests", "1", 1_000, "new release", 10), ("requests", "2", 5_000, "new release", 30)]
    feed = _Pypi(events, 30)
    now = datetime.fromtimestamp(5_000, timezone.utc)
    try:
        apply_feed_start(
            db,
            _config(tmp_path),
            feed,
            _npm_time_transport({10: "1970-01-01T00:16:40Z", 30: "1970-01-01T01:23:20Z"}),
            FeedStart(since_hours=0.5),
            now=now,
        )
        assert db.get_checkpoint("pypi") == "5"
        assert db.get_checkpoint("npm") == "5"
    finally:
        db.close()


def test_since_hours_rewinds_a_checkpoint_that_is_already_ahead(tmp_path):
    db = _ready(tmp_path, pypi="40", npm="40")
    events = [("requests", "1", 1_000, "new release", 10), ("requests", "2", 5_000, "new release", 30)]
    feed = _Pypi(events, 40)
    now = datetime.fromtimestamp(5_000, timezone.utc)
    try:
        apply_feed_start(
            db,
            _config(tmp_path),
            feed,
            _npm_time_transport({10: "1970-01-01T00:16:40Z", 30: "1970-01-01T01:23:20Z"}),
            FeedStart(since_hours=0.5),
            now=now,
        )
        assert int(db.get_checkpoint("pypi")) < 30
        assert int(db.get_checkpoint("npm")) < 30
        assert feed.since(int(db.get_checkpoint("pypi")))[0][4] == 30
    finally:
        db.close()


def test_since_hours_sets_a_missing_checkpoint_instead_of_the_feed_head(tmp_path):
    db = _ready(tmp_path, pypi=None, npm=None)
    events = [("requests", "1", 1_000, "new release", 10), ("requests", "2", 5_000, "new release", 30)]
    feed = _Pypi(events, 40)
    now = datetime.fromtimestamp(5_000, timezone.utc)
    try:
        apply_feed_start(
            db,
            _config(tmp_path),
            feed,
            _npm_time_transport({10: "1970-01-01T00:16:40Z", 30: "1970-01-01T01:23:20Z"}),
            FeedStart(since_hours=0.5),
            now=now,
        )
        assert db.get_checkpoint("pypi") not in {None, "40"}
        assert db.get_checkpoint("npm") not in {None, "30"}
        assert feed.since(int(db.get_checkpoint("pypi")))[0][4] == 30
    finally:
        db.close()


def test_explicit_cursors_replace_the_checkpoint_even_when_ahead(tmp_path):
    db = _ready(tmp_path, pypi="5", npm="5")
    feed = _Pypi([], 100)
    try:
        apply_feed_start(
            db,
            _config(tmp_path),
            feed,
            _empty_npm,
            FeedStart(pypi_serial=40, npm_seq="70", since_hours=1),
            now=datetime(2026, 10, 2, tzinfo=timezone.utc),
        )
        assert db.get_checkpoint("pypi") == "40"
        assert db.get_checkpoint("npm") == "70"
        assert feed.since_calls == []
    finally:
        db.close()


def test_replay_from_npm_seq_keeps_no_gap_paging(tmp_path):
    db = _ready(tmp_path, pypi="1", npm="5")
    db.set_package_cursor("npm", "left-pad", "1.0.0", "2026-01-01T00:00:00.000Z")
    changes = [
        {"seq": "1", "id": "other-pkg"},
        {"seq": "2", "id": "left-pad"},
        {"seq": "3", "id": "another-pkg"},
        {"seq": "4", "id": "left-pad"},
        {"seq": "5", "id": "left-pad"},
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

    def transport(url, _timeout):
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

    feed = _Pypi([], 1)
    try:
        apply_feed_start(db, _config(tmp_path), feed, transport, FeedStart(npm_seq="0"))
        queued = poll_npm(db, _config(tmp_path), transport)
        assert queued == 2
        assert seen == ["0", "2", "4"]
        assert db.get_checkpoint("npm") == "5"
    finally:
        db.close()


def test_run_cycle_polls_both_feeds_at_the_same_time(tmp_path):
    db = _ready(tmp_path)
    pypi_in = threading.Event()
    npm_in = threading.Event()
    saw = {}

    class Feed:
        def last_serial(self):
            return 5

        def since(self, _serial):
            pypi_in.set()
            saw["pypi"] = npm_in.wait(1.5)
            return []

    def transport(url, _timeout):
        if "/_changes" in url:
            npm_in.set()
            saw["npm"] = pypi_in.wait(1.5)
        return json.dumps({"results": [], "last_seq": "1"}).encode()

    try:
        run_cycle(db, _config(tmp_path), jev=object(), loader=object(), feed=Feed(), transport=transport)
    finally:
        db.close()
    assert saw.get("pypi") is True
    assert saw.get("npm") is True


def test_pypi_failure_still_polls_npm(tmp_path):
    db = _ready(tmp_path)

    class Feed:
        def last_serial(self):
            return 5

        def since(self, _serial):
            raise OSError("pypi down")

    try:
        run_cycle(db, _config(tmp_path), jev=object(), loader=object(), feed=Feed(), transport=_empty_npm)
        assert db.last_poll()["pypi"] is None
        assert db.last_poll()["npm"]
    finally:
        db.close()


def test_serve_keeps_polling_npm_while_pypi_is_blocked(tmp_path):
    db = _ready(tmp_path)
    db.close()
    entered = threading.Event()
    release = threading.Event()
    npm_calls = []
    stop = threading.Event()

    class Feed:
        def last_serial(self):
            return 5

        def since(self, _serial):
            entered.set()
            release.wait(3)
            return []

    def transport(url, _timeout):
        if "/_changes" in url:
            npm_calls.append(time.monotonic())
        return json.dumps({"results": [], "last_seq": "1"}).encode()

    def watcher():
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            if len(npm_calls) >= 2 and entered.is_set():
                break
            time.sleep(0.02)
        release.set()
        stop.set()

    threading.Thread(target=watcher, daemon=True).start()
    serve(
        _config(tmp_path),
        stop=stop,
        jev=object(),
        loader=object(),
        feed=Feed(),
        transport=transport,
    )
    assert entered.is_set()
    assert len(npm_calls) >= 2


def test_serve_start_position_is_what_the_first_poll_reads(tmp_path):
    db = _ready(tmp_path, pypi="90", npm="90")
    db.close()
    seen = []
    npm_since = []
    stop = threading.Event()
    release = threading.Event()

    class Feed:
        def last_serial(self):
            return 100

        def since(self, serial):
            seen.append(serial)
            release.set()
            return []

    def transport(url, _timeout):
        parsed = urlparse(url)
        if parsed.path.endswith("/_changes"):
            query = parse_qs(parsed.query)
            if "since" in query:
                npm_since.append(query["since"][0])
        return json.dumps({"results": [], "last_seq": "4"}).encode()

    def watcher():
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            if seen and npm_since:
                break
            time.sleep(0.02)
        release.set()
        stop.set()

    threading.Thread(target=watcher, daemon=True).start()
    serve(
        _config(tmp_path),
        stop=stop,
        jev=object(),
        loader=object(),
        feed=Feed(),
        transport=transport,
        start=FeedStart(pypi_serial=15, npm_seq="4"),
    )
    assert 15 in seen
    assert "4" in npm_since


def test_feed_start_flags_parse_and_reject_negatives():
    parser = build_parser()
    args = parser.parse_args(["scan", "--once", "--pypi-serial", "12", "--npm-seq", "34", "--since-hours", "1.5"])
    assert args.pypi_serial == 12
    assert args.npm_seq == "34"
    assert args.since_hours == 1.5
    serve_args = parser.parse_args(["serve", "--since-hours", "0"])
    assert serve_args.since_hours == 0
    with pytest.raises(SystemExit):
        parser.parse_args(["scan", "--once", "--since-hours", "-1"])
    with pytest.raises(SystemExit):
        parser.parse_args(["serve", "--pypi-serial", "-5"])
    with pytest.raises(SystemExit):
        parser.parse_args(["scan", "--once", "--npm-seq", "-1"])


def test_scan_once_sets_explicit_checkpoints(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTER_DB", str(tmp_path / "hunter.sqlite3"))
    monkeypatch.setenv("HUNTER_SKIP_PYPI", "1")
    monkeypatch.setenv("HUNTER_SKIP_NPM", "1")
    monkeypatch.delenv("ALERT_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("ALERT_WEBHOOK_SECRET", raising=False)
    assert main(["scan", "--once", "--pypi-serial", "40", "--npm-seq", "70"]) == 0
    db = Database(tmp_path / "hunter.sqlite3")
    try:
        assert db.get_checkpoint("pypi") == "40"
        assert db.get_checkpoint("npm") == "70"
    finally:
        db.close()
