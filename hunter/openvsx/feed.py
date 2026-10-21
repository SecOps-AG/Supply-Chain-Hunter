"""Open VSX registry changes feed: ``GET /api/-/version-changes``.

The feed is an append-only log of publications, deactivations and removals,
oldest first. ``since=<ISO time>`` starts it at a moment and ``after=<cursor>``
continues from a page's ``nextCursor``. The checkpoint holds either form.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime
from urllib.parse import quote

from hunter.db import Database, utcnow
from hunter.openvsx import ECOSYSTEM, release_name
from hunter.registry import FeedError, HttpGet, http_get, parse_time

log = logging.getLogger("hunter.openvsx.feed")

CHECKPOINT = "openvsx"
SINCE_PREFIX = "since:"
# Pages read in one poll. The rest is read on the next poll.
MAX_PAGES_PER_POLL = 50


def changes_url(base: str, checkpoint: str, size: int) -> str:
    if checkpoint.startswith(SINCE_PREFIX):
        where = f"since={quote(checkpoint[len(SINCE_PREFIX):], safe='')}"
    else:
        where = f"after={quote(checkpoint, safe='')}"
    return f"{base.rstrip('/')}/api/-/version-changes?{where}&size={int(size)}"


def fetch_changes(base: str, checkpoint: str, size: int, transport: HttpGet = http_get) -> dict:
    data = json.loads(transport(changes_url(base, checkpoint, size), 60).decode("utf-8"))
    if not isinstance(data, dict):
        raise FeedError("Open VSX changes feed did not return a JSON object")
    if data.get("error"):
        raise FeedError(f"Open VSX changes feed: {str(data['error'])[:200]}")
    return data


def _latest_timestamp(changes: list) -> str | None:
    """The newest ``timestamp`` on a page, as the feed wrote it."""
    best: tuple[datetime, str] | None = None
    for change in changes:
        raw = str(change.get("timestamp") or "").strip() if isinstance(change, dict) else ""
        when = parse_time(raw)
        if when is not None and when.tzinfo is not None and (best is None or when > best[0]):
            best = (when, raw)
    return best[1] if best else None


def _queue(db: Database, name: str, version: str, max_pending: int | None) -> str:
    """'queued', 'present' or 'refused', the same answers the npm and PyPI polls use."""
    if db.enqueue_job(ECOSYSTEM, name, version, None, max_pending=max_pending):
        return "queued"
    if db.has_release_job(ECOSYSTEM, name, version):
        return "present"
    return "refused"


def poll_openvsx(db: Database, config, transport: HttpGet = http_get, stop: threading.Event | None = None) -> int:
    """Record every change, queue new active versions, and note removals. Returns releases queued.

    The first poll only sets the start to now. A page the pending cap refused is
    read again on the next poll; recording a change twice is harmless.
    """
    saved = db.get_checkpoint(CHECKPOINT)
    if saved is None:
        start = utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        db.set_checkpoint(CHECKPOINT, f"{SINCE_PREFIX}{start}")
        db.mark_poll_success(CHECKPOINT)
        return 0
    checkpoint = saved
    queued = 0
    removed = 0
    for _page in range(MAX_PAGES_PER_POLL):
        if stop is not None and stop.is_set():
            break
        page = fetch_changes(config.openvsx_url, checkpoint, config.openvsx_page_size, transport)
        changes = page.get("changes") or []
        if not isinstance(changes, list):
            raise FeedError("Open VSX changes is not a list")
        refused = False
        for change in changes:
            if not isinstance(change, dict):
                continue
            name = release_name(str(change.get("namespace") or ""), str(change.get("name") or ""))
            version = str(change.get("version") or "").strip()
            if name is None or not version or len(version) > 128 or "/" in version:
                continue
            platform = str(change.get("targetPlatform") or "universal").strip().lower() or "universal"
            state = str(change.get("state") or "").strip().upper() or "UNKNOWN"
            before = db.record_openvsx_change(
                name,
                version,
                platform,
                state,
                change.get("timestamp"),
                change.get("lastUpdated"),
            )
            if state == "ACTIVE":
                result = _queue(db, name, version, config.max_pending)
                if result == "queued":
                    queued += 1
                elif result == "refused":
                    refused = True
                    break
            elif state == "REMOVED" and before != "REMOVED":
                removed += 1
                log.info("Open VSX removed %s %s (%s)", name, version, platform)
        if refused:
            log.warning("Open VSX poll paused: pending queue is full")
            break
        following = page.get("nextCursor")
        if following and str(following) != checkpoint:
            checkpoint = str(following)
            db.set_checkpoint(CHECKPOINT, checkpoint)
        elif not following:
            # A last page with no cursor: start the next poll at its newest change, not the old start.
            latest = _latest_timestamp(changes)
            if latest and f"{SINCE_PREFIX}{latest}" != checkpoint:
                checkpoint = f"{SINCE_PREFIX}{latest}"
                db.set_checkpoint(CHECKPOINT, checkpoint)
        if not page.get("hasMore") or not changes or not following:
            break
    db.mark_poll_success(CHECKPOINT)
    if queued or removed:
        log.info("Open VSX: %s releases queued, %s removals recorded", queued, removed)
    return queued
