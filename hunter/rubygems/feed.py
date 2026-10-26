"""RubyGems timeframe feed: ``GET /api/v1/timeframe_versions.json``.

Pages are oldest first, 30 versions each. The checkpoint is the timestamp of
the last version this poll stored. A gap longer than 7 days is clamped, because
the API rejects a longer span. Yanked rows and builds other than ``platform=ruby``
are skipped.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from hunter.db import Database, utcnow
from hunter.registry import FeedError, HttpGet, http_get, parse_time
from hunter.rubygems import ECOSYSTEM, valid_name, valid_version

log = logging.getLogger("hunter.rubygems.feed")

CHECKPOINT = "rubygems"
QUEUED_KEY = "rubygems_queued"
MAX_SPAN = timedelta(days=7)
CLAMP = timedelta(days=6)


def _stamp(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _row_stamp(row: dict) -> str | None:
    for key in ("version_created_at", "created_at", "built_at"):
        raw = row.get(key)
        if raw and parse_time(str(raw)) is not None:
            return str(raw)
    return None


def _sort_key(row: dict) -> tuple:
    raw = _row_stamp(row) or ""
    parsed = parse_time(raw) if raw else None
    if parsed is None:
        return ("", raw)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return (parsed.isoformat(), raw)


def timeframe_url(base: str, start: str, end: str, page: int) -> str:
    return (
        f"{base.rstrip('/')}/api/v1/timeframe_versions.json"
        f"?from={quote(start, safe='')}&to={quote(end, safe='')}&page={int(page)}"
    )


def fetch_timeframe(base: str, start: str, end: str, page: int, transport: HttpGet = http_get) -> list:
    data = json.loads(transport(timeframe_url(base, start, end, page), 60).decode("utf-8"))
    if isinstance(data, dict):
        raise FeedError(f"RubyGems timeframe: {str(data.get('error') or 'not a list')[:200]}")
    if not isinstance(data, list):
        raise FeedError("RubyGems timeframe is not a list")
    return data


def _yanked(row: dict) -> bool:
    return row.get("yanked") in (True, 1, "true", "True", "yes")


def _queue(db: Database, name: str, version: str, max_pending: int | None) -> str:
    """'queued', 'present' or 'refused', the same answers the npm and PyPI polls use."""
    if db.enqueue_job(ECOSYSTEM, name, version, None, max_pending=max_pending):
        return "queued"
    if db.has_release_job(ECOSYSTEM, name, version):
        return "present"
    return "refused"


def _consider(row: dict) -> tuple[str, str] | None:
    """A ruby-platform release to queue, or None when the row is skipped."""
    name = str(row.get("name") or "").strip()
    version = str(row.get("version") or row.get("number") or "").strip()
    platform = str(row.get("platform") or "").strip()
    if platform != "ruby" or _yanked(row) or not valid_name(name) or not valid_version(version):
        return None
    return name, version


def poll_rubygems(db: Database, config, transport: HttpGet = http_get, stop: threading.Event | None = None) -> int:
    """Queue new ruby-platform versions. The first poll only stores the checkpoint.

    Returns how many releases were queued. A version the pending cap refused is
    read again on the next poll; the checkpoint stays on the last stored row.
    """
    saved = db.get_checkpoint(CHECKPOINT)
    now = utcnow()
    if saved is None:
        db.set_checkpoint(CHECKPOINT, _stamp(now))
        db.set_checkpoint(QUEUED_KEY, "0")
        db.mark_poll_success(CHECKPOINT)
        return 0
    parsed = parse_time(saved)
    if parsed is not None and parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    start_text = saved
    if parsed is None:
        start_text = _stamp(now)
    elif now - parsed > MAX_SPAN:
        start_text = _stamp(now - CLAMP)
        log.warning(
            "RubyGems checkpoint %s is older than 7 days; skipping that gap and clamping from to %s",
            saved,
            start_text,
        )
    end_text = _stamp(now)
    queued = 0
    pages = max(1, int(getattr(config, "rubygems_max_pages", 20)))
    for page in range(1, pages + 1):
        if stop is not None and stop.is_set():
            break
        rows = fetch_timeframe(config.rubygems_url, start_text, end_text, page, transport)
        if not rows:
            break
        refused = False
        for row in sorted((item for item in rows if isinstance(item, dict)), key=_sort_key):
            kept = _consider(row)
            if kept is None:
                stamp = _row_stamp(row)
                if stamp:
                    db.set_checkpoint(CHECKPOINT, stamp)
                continue
            result = _queue(db, kept[0], kept[1], getattr(config, "max_pending", None))
            if result == "queued":
                queued += 1
            elif result == "refused":
                refused = True
                break
            stamp = _row_stamp(row)
            if stamp:
                db.set_checkpoint(CHECKPOINT, stamp)
        if refused:
            log.warning("RubyGems poll paused: pending queue is full")
            break
    db.set_checkpoint(QUEUED_KEY, str(queued))
    db.mark_poll_success(CHECKPOINT)
    if queued:
        log.info("RubyGems: %s releases queued", queued)
    return queued
