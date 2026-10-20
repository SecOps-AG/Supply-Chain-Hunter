from hunter.db import Database
from hunter.jev import JevUnavailable, invoke_with_retry


def test_pending_queue_stops_at_the_cap(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    assert db.enqueue_job("npm", "one", "1.0.0", 1, max_pending=1)
    assert db.enqueue_job("npm", "two", "1.0.0", 2, max_pending=1) is False
    assert db.pending_count() == 1


def test_jev_call_retries_then_caches(tmp_path):
    calls = {"n": 0}
    sleeps = []

    def fn():
        calls["n"] += 1
        if calls["n"] < 2:
            raise JevUnavailable("timeout")
        return "ok"

    assert invoke_with_retry(fn, retries=3, sleep=sleeps.append) == "ok"
    assert calls["n"] == 2
    assert sleeps and sleeps[0] > 0
