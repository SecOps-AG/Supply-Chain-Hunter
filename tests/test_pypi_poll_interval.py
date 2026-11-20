"""PyPI polls on its own 60 second interval, like RubyGems; npm keeps HUNTER_POLL_INTERVAL."""

from __future__ import annotations

import threading

from hunter import service
from hunter.config import Config
from hunter.db import Database


def test_pypi_interval_defaults_to_60_and_is_floored(monkeypatch):
    monkeypatch.delenv("HUNTER_PYPI_POLL_INTERVAL", raising=False)
    monkeypatch.delenv("HUNTER_POLL_INTERVAL", raising=False)
    config = Config.from_env()
    assert config.pypi_poll_interval == 60.0
    assert config.poll_interval == 300.0
    monkeypatch.setenv("HUNTER_PYPI_POLL_INTERVAL", "10")
    assert Config.from_env().pypi_poll_interval == 60.0
    monkeypatch.setenv("HUNTER_PYPI_POLL_INTERVAL", "120")
    assert Config.from_env().pypi_poll_interval == 120.0


def test_poll_interval_no_longer_slows_pypi(monkeypatch):
    monkeypatch.delenv("HUNTER_PYPI_POLL_INTERVAL", raising=False)
    monkeypatch.setenv("HUNTER_POLL_INTERVAL", "900")
    config = Config.from_env()
    assert config.poll_interval == 900.0
    assert config.pypi_poll_interval == 60.0


def test_serve_runs_the_pypi_loop_on_the_pypi_interval(tmp_path, monkeypatch):
    db = Database(tmp_path / "hunter.sqlite3")
    db.set_checkpoint("pypi", "1")
    db.set_checkpoint("npm", "1")
    db.close()
    stop = threading.Event()
    seen: dict[str, float] = {}
    lock = threading.Lock()

    def fake_loop(stop, interval, fn):
        del fn
        with lock:
            seen[threading.current_thread().name] = interval
            if {"hunter-pypi", "hunter-npm"} <= set(seen):
                stop.set()

    monkeypatch.setattr(service, "_feed_loop", fake_loop)
    config = Config(
        db_path=tmp_path / "hunter.sqlite3",
        poll_interval=300.0,
        pypi_poll_interval=60.0,
        port=0,
        watchlist_refresh=1e12,
        smart_analysis=False,
        analyst=False,
        workers=1,
        webhook_url="",
    )
    service.serve(config, stop=stop, jev=object(), loader=object(), feed=object(), transport=lambda *_: b"{}")
    assert seen["hunter-pypi"] == 60.0
    assert seen["hunter-npm"] == 300.0
