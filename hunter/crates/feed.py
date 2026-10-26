"""crates.io RSS intake: version updates, new crate names, and gap backfill.

``updates.xml`` is versions from the last hour. ``crates.xml`` is new names.
The first poll stores the newest ``pubDate`` and queues nothing. Later polls
queue items newer than that checkpoint. A full pending queue leaves the
checkpoint where it is; ``enqueue_job`` dedups a name and version seen again.

The download-rank walk and the gap backfill share one request per second on
the crates.io API. The sparse index is not paced. Watchlist refresh stays on
this thread and is not part of ``refresh_watchlists``.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from hunter.crates import ECOSYSTEM, parse_release_link, safe_segment, sparse_path, victim_name
from hunter.db import Database, iso, utcnow
from hunter.registry import FeedError, HttpGet, http_get, parse_time
from hunter.typosquat import TYPOSQUAT_QUEUE_LIMIT

log = logging.getLogger("hunter.crates.feed")

CHECKPOINT = "crates"
BACKFILL = "crates-backfill"
# crates.io API calls, shared by the rank walk and the gap backfill.
API_INTERVAL = 1.0
# API pages of sort=updated read in one poll. The next poll continues.
MAX_GAP_PAGES = 5
CRATES_USER_AGENT = "supply-chain-hunter/0.1 (+https://github.com/SecOps-AG/Supply-Chain-Hunter)"

_api_lock = threading.Lock()
_next_api = 0.0


@dataclass(frozen=True)
class FeedItem:
    name: str
    version: str
    published: datetime


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_pubdate(value: str) -> datetime | None:
    text = (value or "").strip()
    if not text:
        return None
    try:
        moment = parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError, OverflowError):
        moment = None
    if moment is None:
        moment = parse_time(text)
    if moment is None:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def parse_rss(blob: bytes) -> list[FeedItem]:
    """Items whose link or title yields a safe name and version."""
    try:
        root = ET.fromstring(blob)
    except ET.ParseError as exc:
        raise FeedError(f"crates RSS did not parse: {exc}") from exc
    found: list[FeedItem] = []
    for item in root.iter():
        if _local(item.tag) != "item":
            continue
        title = link = pub = ""
        for child in list(item):
            name = _local(child.tag)
            text = (child.text or "").strip()
            if name == "title":
                title = text
            elif name == "link":
                link = text
            elif name == "pubDate":
                pub = text
        parsed = parse_release_link(link, title)
        moment = parse_pubdate(pub)
        if parsed is None or moment is None:
            continue
        found.append(FeedItem(parsed[0], parsed[1], moment))
    return found


def _read_body(blob: bytes | object) -> bytes:
    if isinstance(blob, bytes):
        return blob
    path_read = getattr(blob, "read_bytes", None)
    if callable(path_read):
        return path_read()
    raise FeedError("crates response was not bytes")


def api_get(url: str, timeout: float, transport: HttpGet) -> bytes:
    """GET a crates.io API URL. The shared ``http_get`` User-Agent stays unchanged.

    The real transport sends the crates.io policy string. A test transport is
    called as given.
    """
    if transport is http_get:
        request = urllib.request.Request(url, headers={"User-Agent": CRATES_USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read()
        except urllib.error.URLError as exc:
            raise FeedError(str(exc.reason)) from exc
    return _read_body(transport(url, timeout))


def paced_api(url: str, timeout: float, transport: HttpGet, stop: threading.Event | None = None) -> bytes:
    """One crates.io API request per ``API_INTERVAL`` seconds, across this process."""
    global _next_api
    with _api_lock:
        delay = _next_api - time.monotonic()
        if delay > 0:
            if stop is not None and stop.wait(delay):
                raise FeedError("crates poll stopped")
            if stop is None:
                time.sleep(delay)
        _next_api = time.monotonic() + API_INTERVAL
    return api_get(url, timeout, transport)


def _json_object(blob: bytes) -> dict:
    data = json.loads(blob.decode("utf-8"))
    if not isinstance(data, dict):
        raise FeedError("crates.io API did not return a JSON object")
    return data


def index_lines(blob: bytes) -> list[dict]:
    """Newline-delimited index objects, in file order."""
    lines: list[dict] = []
    for raw in blob.decode("utf-8", "replace").splitlines():
        text = raw.strip()
        if not text or not text.startswith("{"):
            continue
        try:
            item = json.loads(text)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict) and item.get("vers"):
            lines.append(item)
    return lines


def _in_gap(line: dict, start: datetime, end: datetime) -> bool:
    moment = parse_time(str(line.get("pubtime") or ""))
    if moment is None:
        return False
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return start < moment.astimezone(timezone.utc) < end


def versions_in_gap(lines: list[dict], start: datetime, end: datetime) -> list[dict]:
    """Index lines published after ``start`` and before ``end``.

    A line without ``pubtime`` cannot be ordered against the others. Only the
    last line is queued, and the miss is logged.
    """
    if not lines:
        return []
    if any(not line.get("pubtime") for line in lines):
        log.warning("crate index missing pubtime; intermediates were not ordered")
        return [lines[-1]]
    return [line for line in lines if _in_gap(line, start, end)]


def _queue(db: Database, name: str, version: str, rank: int | None, max_pending: int | None) -> str:
    if db.enqueue_job(ECOSYSTEM, name, version, rank, max_pending=max_pending):
        return "queued"
    if db.has_release_job(ECOSYSTEM, name, version):
        return "present"
    return "refused"


def _admit(
    name: str,
    watch: dict[str, int],
    *,
    watched_only: bool,
    typo_left: int,
) -> tuple[bool, int | None, int]:
    """Whether to queue ``name``. The typosquat cap applies only in watched-only mode."""
    lowered = {str(key).lower(): int(rank) for key, rank in watch.items()}
    if name in lowered:
        return True, lowered[name], typo_left
    victim = victim_name(name, lowered)
    if not watched_only:
        rank = lowered.get(victim, 0) if victim else None
        return True, rank, typo_left
    if victim is None or typo_left <= 0:
        return False, None, typo_left
    return True, lowered.get(victim, 0), typo_left - 1


def _store_version(
    db: Database,
    config,
    name: str,
    version: str,
    watch: dict[str, int],
    typo_left: int,
) -> tuple[str, int]:
    if not safe_segment(name) or not safe_segment(version):
        return "skipped", typo_left
    allowed, rank, typo_left = _admit(
        name,
        watch,
        watched_only=bool(getattr(config, "crates_watched_only", False)),
        typo_left=typo_left,
    )
    if not allowed:
        return "skipped", typo_left
    state = _queue(db, name, version, rank, config.max_pending)
    if state == "queued" and rank is not None and name not in {key.lower() for key in watch}:
        log.info("queued typosquat candidate crates %s %s", name, version)
    return state, typo_left


def refresh_crates_watchlist(
    db: Database,
    config,
    transport: HttpGet = http_get,
    stop: threading.Event | None = None,
) -> int:
    """Top crates by downloads, paced at one API request per second.

    Runs from the crates thread on the same stale interval as the npm and PyPI
    watchlists. Returns the number of names stored, or 0 when the list is fresh
    or the API could not be read.
    """
    stamp = db.watch_refreshed_at(ECOSYSTEM)
    if stamp:
        parsed = parse_time(stamp)
        if parsed is not None and (utcnow() - parsed).total_seconds() < config.watchlist_refresh:
            return 0
    top_n = int(getattr(config, "crates_top_n", 0) or config.top_n)
    per_page = 100
    pages = max(1, (top_n + per_page - 1) // per_page)
    rows: list[tuple[str, int, int]] = []
    try:
        for page in range(1, pages + 1):
            if stop is not None and stop.is_set():
                break
            url = (
                f"{config.crates_api.rstrip('/')}/api/v1/crates"
                f"?sort=downloads&per_page={per_page}&page={page}"
            )
            data = _json_object(paced_api(url, 60, transport, stop))
            crates = data.get("crates") or []
            if not isinstance(crates, list) or not crates:
                break
            for item in crates:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name") or item.get("id") or "").strip().lower()
                if not safe_segment(name):
                    continue
                downloads = int(item.get("downloads") or 0)
                rows.append((name, len(rows) + 1, downloads))
                if len(rows) >= top_n:
                    break
            if len(rows) >= top_n:
                break
    except (FeedError, OSError, ValueError, json.JSONDecodeError, UnicodeError) as exc:
        log.warning("crates watchlist refresh failed: %s", exc)
        return 0
    if rows:
        db.replace_watchlist(ECOSYSTEM, rows)
        log.info("crates watchlist refreshed names=%s", len(rows))
    return len(rows)


def _fetch_index(config, name: str, transport: HttpGet) -> list[dict]:
    url = f"{config.crates_index.rstrip('/')}/{sparse_path(name)}"
    return index_lines(_read_body(transport(url, 60)))


def _newest_index_version(config, name: str, transport: HttpGet) -> str:
    """Last index ``vers`` for a crates.xml item whose title has no version.

    The live new-crate title is ``New crate created: {name}``. The sparse index
    is the version. A missing index is logged and the name is skipped.
    """
    try:
        lines = _fetch_index(config, name, transport)
    except (FeedError, OSError, ValueError, UnicodeError) as exc:
        log.warning("crates index read failed for %s: %s", name, exc)
        return ""
    for line in reversed(lines):
        version = str(line.get("vers") or "")
        if safe_segment(version):
            return version
    return ""


def _backfill(
    db: Database,
    config,
    transport: HttpGet,
    start: datetime,
    end: datetime,
    watch: dict[str, int],
    typo_left: int,
    stop: threading.Event | None,
) -> tuple[int, int, bool]:
    """Queue index versions published in ``(start, end)``.

    Returns ``(queued, typo_left, finished)``. ``finished`` is false when the
    page cap or the pending cap stopped the walk; the next page is kept.
    """
    saved = db.get_checkpoint(BACKFILL)
    page = int(saved) if saved and str(saved).isdigit() and int(saved) > 0 else 1
    queued = 0
    read = 0
    while read < MAX_GAP_PAGES:
        if stop is not None and stop.is_set():
            db.set_checkpoint(BACKFILL, str(page))
            return queued, typo_left, False
        url = f"{config.crates_api.rstrip('/')}/api/v1/crates?sort=updated&per_page=100&page={page}"
        data = _json_object(paced_api(url, 60, transport, stop))
        crates = data.get("crates") or []
        if not isinstance(crates, list) or not crates:
            db.set_checkpoint(BACKFILL, "")
            return queued, typo_left, True
        finished = False
        for item in crates:
            if not isinstance(item, dict):
                continue
            updated = parse_time(str(item.get("updated_at") or ""))
            if updated is not None and updated <= start:
                finished = True
                break
            name = str(item.get("name") or item.get("id") or "").strip().lower()
            if not safe_segment(name):
                continue
            try:
                lines = _fetch_index(config, name, transport)
            except (FeedError, OSError, ValueError, UnicodeError) as exc:
                log.warning("crates index read failed for %s: %s", name, exc)
                continue
            for line in versions_in_gap(lines, start, end):
                version = str(line.get("vers") or "")
                state, typo_left = _store_version(db, config, name, version, watch, typo_left)
                if state == "queued":
                    queued += 1
                elif state == "refused":
                    db.set_checkpoint(BACKFILL, str(page))
                    return queued, typo_left, False
        read += 1
        page += 1
        if finished:
            db.set_checkpoint(BACKFILL, "")
            return queued, typo_left, True
    db.set_checkpoint(BACKFILL, str(page))
    return queued, typo_left, False


def poll_crates(
    db: Database,
    config,
    transport: HttpGet = http_get,
    stop: threading.Event | None = None,
) -> int:
    """Queue crate versions newer than the checkpoint. Returns how many were queued.

    The first call only records the newest ``pubDate``. ``HUNTER_MAX_PENDING``
    leaves the checkpoint unchanged so the refused item is tried again.
    """
    try:
        refresh_crates_watchlist(db, config, transport, stop)
    except Exception:
        log.warning("crates watchlist refresh failed", exc_info=True)
    updates = parse_rss(_read_body(transport(config.crates_updates_rss, 60)))
    names = parse_rss(_read_body(transport(config.crates_crates_rss, 60)))
    items: dict[tuple[str, str], FeedItem] = {}
    for item in updates + names:
        key = (item.name, item.version)
        previous = items.get(key)
        if previous is None or item.published > previous.published:
            items[key] = item
    ordered = sorted(items.values(), key=lambda item: item.published)
    saved = db.get_checkpoint(CHECKPOINT)
    if saved is None:
        newest = max((item.published for item in ordered), default=utcnow())
        db.set_checkpoint(CHECKPOINT, iso(newest))
        db.mark_poll_success(CHECKPOINT)
        return 0
    checkpoint = parse_time(saved)
    if checkpoint is None:
        checkpoint = utcnow()
    watch = db.watch_names(ECOSYSTEM)
    typo_left = TYPOSQUAT_QUEUE_LIMIT
    queued = 0
    if ordered and min(item.published for item in ordered) > checkpoint:
        try:
            added, typo_left, finished = _backfill(
                db, config, transport, checkpoint, min(item.published for item in ordered), watch, typo_left, stop
            )
        except (FeedError, OSError, ValueError, json.JSONDecodeError, UnicodeError) as exc:
            log.warning("crates gap backfill failed: %s", exc)
            db.mark_poll_error(CHECKPOINT, str(exc))
            return queued
        queued += added
        if not finished:
            log.warning("crates gap backfill paused")
            return queued
    blocked = False
    versioned = {item.name for item in ordered if item.version}
    for item in ordered:
        if item.published <= checkpoint:
            continue
        version = item.version
        if not version:
            if item.name in versioned:
                continue
            version = _newest_index_version(config, item.name, transport)
            if not version:
                log.warning("crates new name %s had no index version", item.name)
                continue
        state, typo_left = _store_version(db, config, item.name, version, watch, typo_left)
        if state == "queued":
            queued += 1
        elif state == "refused":
            blocked = True
            break
    if blocked:
        log.warning("crates poll paused: pending queue is full")
        return queued
    if ordered:
        db.set_checkpoint(CHECKPOINT, iso(max(item.published for item in ordered)))
    db.mark_poll_success(CHECKPOINT)
    if queued:
        log.info("crates: %s releases queued", queued)
    return queued
