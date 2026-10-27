"""Public dashboard JSON on the same R2 bucket as the alert feed."""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import quote

from hunter.config import Config, active_role_models
from hunter.dashboard import RANGES, _since, _triage_verdict, findings, release, release_key, snapshot
from hunter.dashboard.benchmark import load_benchmarks
from hunter.db import Database, iso, utcnow
from hunter.inventory.scope import public_publish_blocked
from hunter.public_feed import (
    DASH_JSON_CONTENT_TYPE,
    LIVE_PREFIX,
    _public_error,
    make_r2_client,
    put_feed_object,
)
from hunter.rules import rules_enabled

log = logging.getLogger("hunter.public_dash")

LIVE_JSON_KEY = f"{LIVE_PREFIX}live.json"
BENCHMARK_KEY = f"{LIVE_PREFIX}benchmark.json"
FINDINGS_EXPORT_LIMIT = 5000
# Per-request connect/read timeout for each R2 PUT.
UPLOAD_TIMEOUT_S = 5.0
# One publish pass stops starting new release uploads after this long. The
# rest stay dirty and go up on the next pass, so the first pass after a deploy
# (every release body changed) cannot hold the publisher thread for minutes.
# A PUT already started can still run up to its own timeout and retry.
PUBLISH_BUDGET_S = 20.0
_clock = time.monotonic
DEBOUNCE_S = 2.0
CACHE_LIVE = "public, max-age=2"
CACHE_TODAY = "public, max-age=60"
# Release detail objects change as triage, analyst and alert results arrive, so they
# must revalidate like today's rollups rather than be cached as immutable.
CACHE_RELEASE = CACHE_TODAY
# Recent events the page replays at their real times. The window covers the page's
# playback delay plus the longest normal gap between uploads, with room to spare.
STREAM_WINDOW_S = 180
STREAM_MAX_EVENTS = 250
STREAM_FIELDS = ("t", "kind", "eco", "name", "version", "result")
STREAM_KINDS = ("poll", "scan", "triage_in", "triage", "analyst_in", "analyst", "alert")

PUBLIC_SNAPSHOT_TOP_KEYS = frozenset(
    {
        "generated_at",
        "range",
        "since",
        "bucket_seconds",
        "buckets",
        "health",
        "models",
        "feeds",
        "scanned",
        "scout",
        "rules",
        "triage",
        "analyst",
        "webhook",
        "confirmed",
        "detections",
        "activity",
        "not_tracked",
    }
)

# The public copy of the health block says only whether Hunter is running and when
# each feed was last read. Queue sizes, budgets, spend, model names, and uptime stay
# on the operator dashboard.
PUBLIC_HEALTH_KEYS = ("status", "last_successful_poll")
# Each pipeline role is published by its generic label only, never the model behind it.
PUBLIC_MODEL_KEYS = ("label", "role")

_INTERNAL_PATH = re.compile(r"(?<![:/])/(?:tmp|var|home|workspace|etc|private)(?:/|$)", re.I)
_STABLE_DROP_KEYS = frozenset({"generated_at", "published_at"})
_RAW_ERROR_KEYS = frozenset(
    {
        "last_error",
        "feed_last_error",
        "error",
        "dash_last_error",
    }
)


def public_snapshot(
    db: Database,
    config: Config,
    *,
    started: float,
    meter,
    range_name: str,
    now: datetime | None = None,
    health: dict | None = None,
) -> dict[str, Any]:
    """Explicit allowlist projection of ``dashboard.snapshot`` for one range."""
    if health is None:
        health = _snapshot_health(db, config, started=started, meter=meter)
    raw = snapshot(
        db,
        health=copy.deepcopy(health),
        models=active_role_models(config),
        range_name=range_name,
        now=now,
        rules_enabled=rules_enabled(),
    )
    row = {key: raw[key] for key in PUBLIC_SNAPSHOT_TOP_KEYS if key in raw}
    if "health" in row:
        row["health"] = public_health(row["health"])
    if "models" in row:
        row["models"] = public_models(row["models"])
    row = sanitize_public(row, config)
    return row


def _snapshot_health(db: Database, config: Config, *, started: float, meter) -> dict:
    from hunter.service import health_payload

    health = health_payload(db, started, config.scout_model_id(), config, meter)
    for meta in ("dash_last_published_at", "dash_last_error", "feed_last_published_at", "feed_last_error"):
        health.pop(meta, None)
    return health


class _CycleReader:
    """Read-through view of the database for one publish cycle.

    The four snapshots and eight findings blocks of a cycle ask for the same rows over
    nested time ranges. Each ``*_since`` list query is ordered newest first with the
    same limit, so a shorter range is a prefix of the widest one: it is read once for
    the widest range and filtered in memory. Other repeated reads with the same
    arguments are answered from a per-cycle memo. Every other method goes to the
    database unchanged.
    """

    _PREFIX_QUERIES = frozenset(
        {"flagged_releases_since", "investigations_since", "analyst_reviews_since", "outbox_since"}
    )
    _MEMO_QUERIES = frozenset({"last_poll", "poll_errors", "scout_usage_since"})
    _PREFIX_LIMIT = 5000

    def __init__(self, db: Database, *, widest_since: str) -> None:
        self._db = db
        self._widest_since = widest_since
        self._rows: dict[tuple, list[dict]] = {}
        self._memo: dict[tuple, Any] = {}

    def __getattr__(self, name: str) -> Any:
        target = getattr(self._db, name)
        if name in self._PREFIX_QUERIES:
            return lambda since, limit=self._PREFIX_LIMIT, **kwargs: self._prefix(name, target, since, limit, kwargs)
        if name in self._MEMO_QUERIES:
            return lambda *args: self._memoized(name, target, args)
        return target

    def _prefix(self, name: str, target, since: str, limit: int, kwargs: dict) -> list[dict]:
        if limit != self._PREFIX_LIMIT or since < self._widest_since:
            return target(since, limit, **kwargs)
        key = (name, tuple(sorted(kwargs.items())))
        if key not in self._rows:
            self._rows[key] = target(self._widest_since, self._PREFIX_LIMIT, **kwargs)
        return [dict(row) for row in self._rows[key] if str(row["created_at"]) >= since]

    def _memoized(self, name: str, target, args: tuple) -> Any:
        key = (name, args)
        if key not in self._memo:
            self._memo[key] = target(*args)
        return copy.deepcopy(self._memo[key])


def public_health(health: Any) -> dict[str, Any]:
    """Allowlist projection of the health block for the public page."""
    if not isinstance(health, dict):
        return {}
    return {key: copy.deepcopy(health[key]) for key in PUBLIC_HEALTH_KEYS if key in health}


def public_models(models: Any) -> dict[str, dict[str, Any]]:
    """Role labels only; no provider, backend, or model id."""
    if not isinstance(models, dict):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for slot, info in models.items():
        if isinstance(info, dict):
            out[slot] = {key: info[key] for key in PUBLIC_MODEL_KEYS if key in info}
    return out


def public_release(detail: dict[str, Any]) -> dict[str, Any]:
    """The release object for the public page, without the model id."""
    out = copy.deepcopy(detail)
    summary = out.get("release")
    if isinstance(summary, dict):
        summary.pop("scout_model_id", None)
        # The user watchlist never leaves the machine (publishing is also refused while one exists).
        summary.pop("watch", None)
    return out


def _release_segment(value: str) -> str:
    """One path segment. ``/`` becomes ``~`` so the key contains no ``%2F``.

    ``~`` is outside action names and npm names. Unscoped names have no slash,
    so they stay byte-for-byte. This encoder is only for release object keys.
    """
    return quote(str(value).replace("/", "~"), safe="")


def release_object_key(ecosystem: str, name: str, version: str) -> str:
    return (
        f"{LIVE_PREFIX}r/{_release_segment(ecosystem)}/"
        f"{_release_segment(name)}/{_release_segment(version)}.json"
    )


def _secret_fragments(config: Config) -> list[str]:
    from hunter.openrouter import resolve_openrouter_api_key

    candidates = [
        config.webhook_url,
        config.webhook_secret,
        config.dashboard_token,
        config.smart_api_key,
        config.analyst_api_key,
        config.feed_r2_access_key_id,
        config.feed_r2_secret_access_key,
        config.github_token,
        resolve_openrouter_api_key(),
        os.environ.get("CURSOR_API_KEY", ""),
        os.environ.get("ALERT_WEBHOOK_SECRET", ""),
        os.environ.get("HUNTER_INVESTIGATE_SECRET", ""),
    ]
    frags = [text for value in candidates if (text := (value or "").strip()) and len(text) >= 6]
    if config.webhook_url:
        host = config.webhook_url.split("://", 1)[-1].split("/", 1)[0]
        if len(host) >= 6:
            frags.append(host)
    frags.sort(key=len, reverse=True)
    unique: list[str] = []
    seen: set[str] = set()
    for frag in frags:
        if frag not in seen:
            seen.add(frag)
            unique.append(frag)
    return unique


def _scrub_errors(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned: dict[Any, Any] = {}
        for key, child in value.items():
            if str(key) in _RAW_ERROR_KEYS:
                if isinstance(child, dict):
                    cleaned[key] = {sub: None if item else None for sub, item in child.items()}
                else:
                    cleaned[key] = None if child else None
                continue
            cleaned[key] = _scrub_errors(child)
        return cleaned
    if isinstance(value, list):
        return [_scrub_errors(item) for item in value]
    return value


def sanitize_public(value: Any, config: Config, *, fragments: list[str] | None = None) -> Any:
    """Drop secrets, webhook hosts, internal paths, and raw error strings."""
    frags = fragments if fragments is not None else _secret_fragments(config)
    if isinstance(value, dict):
        cleaned: dict[Any, Any] = {}
        for key, child in value.items():
            key_text = str(key).lower()
            if key_text in {
                "webhook_url",
                "webhook_secret",
                "api_key",
                "smart_api_key",
                "analyst_api_key",
                "dashboard_token",
            }:
                continue
            cleaned[key] = sanitize_public(child, config, fragments=frags)
        return _scrub_errors(cleaned)
    if isinstance(value, list):
        return [sanitize_public(item, config, fragments=frags) for item in value]
    if isinstance(value, str):
        text = value
        for frag in frags:
            if frag and frag in text:
                return "[redacted]"
        if _INTERNAL_PATH.search(text):
            return "[redacted]"
        if text.startswith("/") and "://" not in text:
            if any(marker in text for marker in ("/tmp/", "/home/", "/workspace/", "/etc/", "/private/")):
                return "[redacted]"
        return text
    return value


def public_stage_note(item: dict) -> str:
    verdict = item.get("analyst_verdict")
    if verdict:
        return f"AI verdict (may be wrong): {verdict}"
    return "under review, not a verdict"


def _annotate_rows(block: dict) -> dict:
    out = copy.deepcopy(block)
    rows = out.get("rows")
    if isinstance(rows, list):
        for row in rows:
            if isinstance(row, dict):
                row["public_stage_note"] = public_stage_note(row)
    return out


def _encode(document: object) -> bytes:
    return (json.dumps(document, ensure_ascii=False, separators=(",", ":"), default=str) + "\n").encode("utf-8")


def _stable_json(document: object) -> bytes:
    """JSON for change detection; omits timestamps that always move."""

    def strip(node: object) -> object:
        if isinstance(node, dict):
            cleaned = {}
            for key, value in node.items():
                if key in _STABLE_DROP_KEYS:
                    continue
                if key == "health" and isinstance(value, dict):
                    health = {k: v for k, v in value.items() if k != "uptime_seconds"}
                    cleaned[key] = strip(health)
                    continue
                cleaned[key] = strip(value)
            return cleaned
        if isinstance(node, list):
            return [strip(item) for item in node]
        return node

    return _encode(strip(document))


def stable_live_digest(live_document: dict) -> str:
    return hashlib.sha256(_stable_json(live_document)).hexdigest()


def stable_benchmark_digest(benchmark: dict) -> str:
    return hashlib.sha256(_encode(benchmark)).hexdigest()


def build_findings_catalog(db: Database, *, now: datetime) -> dict[str, dict[str, dict]]:
    catalog: dict[str, dict[str, dict]] = {}
    for range_name in RANGES:
        catalog[range_name] = {}
        for scope in ("triage", "flagged"):
            block = findings(
                db,
                {
                    "range": range_name,
                    "scope": scope,
                    "limit": str(FINDINGS_EXPORT_LIMIT),
                    "offset": "0",
                },
                now=now,
            )
            catalog[range_name][scope] = _annotate_rows(block)
    return catalog


def _epoch(stamp: str | None) -> int | None:
    if not stamp:
        return None
    try:
        return int(datetime.fromisoformat(str(stamp).replace("Z", "+00:00")).timestamp())
    except ValueError:
        return None


def _split_key(key: str) -> tuple[str, str, str] | None:
    parts = str(key).split(":", 2)
    return (parts[0], parts[1], parts[2]) if len(parts) == 3 and all(parts) else None


def build_live_stream(db: Database, config: Config, *, now: datetime) -> dict[str, Any]:
    """Recent pipeline events with their real timestamps, oldest first.

    Each event is a row of ``STREAM_FIELDS``: epoch seconds, kind, ecosystem, name,
    version, and the band or verdict. ``poll`` rows are real registry checks. Only the
    newest ``STREAM_MAX_EVENTS`` are kept; ``truncated`` says older ones may be missing.
    """
    since = iso(now - timedelta(seconds=STREAM_WINDOW_S))
    cap = STREAM_MAX_EVENTS
    events: list[list[Any]] = []
    maybe_more = False

    def add(stamp: str | None, kind: str, eco: str, name: str | None, version: str | None, result: str | None) -> None:
        moment = _epoch(stamp)
        if moment is not None and str(stamp) >= since:
            events.append([moment, kind, eco, name, version, result])

    for eco, stamp in db.last_poll().items():
        add(stamp, "poll", eco, None, None, None)

    rows = db.releases_scored_since(since, limit=cap)
    maybe_more |= len(rows) >= cap
    for row in rows:
        add(row["created_at"], "scan", row["ecosystem"], row["name"], row["version"], row.get("band"))

    rows = db.investigations_touched_since(since, limit=cap)
    maybe_more |= len(rows) >= cap
    for row in rows:
        parts = _split_key(row["idempotency_key"])
        if parts is None:
            continue
        add(row["created_at"], "triage_in", *parts, None)
        if row["status"] == "reported":
            add(row["updated_at"], "triage", *parts, _triage_verdict(row))

    rows = db.analyst_reviews_touched_since(since, limit=cap)
    maybe_more |= len(rows) >= cap
    for row in rows:
        parts = _split_key(row["idempotency_key"])
        if parts is None:
            continue
        add(row["created_at"], "analyst_in", *parts, None)
        if row["status"] == "reported" and row.get("verdict"):
            add(row["updated_at"], "analyst", *parts, row["verdict"])

    rows = db.alerts_sent_since(since, limit=cap)
    maybe_more |= len(rows) >= cap
    for row in rows:
        key = str(row["idempotency_key"])
        if key.startswith("decision-model-down:"):
            continue
        base = key[: -len(":analysis")] if key.endswith(":analysis") else key
        parts = _split_key(base)
        if parts is not None:
            add(row["sent_at"], "alert", *parts, "sent")

    order = {kind: index for index, kind in enumerate(STREAM_KINDS)}
    events.sort(key=lambda ev: (ev[0], order[ev[1]], ev[2], ev[3] or "", ev[4] or ""))
    truncated = len(events) > cap
    if truncated:
        events = events[-cap:]
    return {
        "v": 1,
        "until": iso(now),
        "since": since,
        "window_s": STREAM_WINDOW_S,
        "max_events": cap,
        "truncated": truncated or (maybe_more and len(events) >= cap),
        "poll_interval_s": int(config.poll_interval),
        "fields": list(STREAM_FIELDS),
        "events": events,
    }


def build_live_document(
    db: Database,
    config: Config,
    *,
    started: float,
    meter,
    now: datetime | None = None,
) -> dict[str, Any]:
    now = now or utcnow()
    db = _CycleReader(db, widest_since=min(_since(now, range_name) for range_name in RANGES))
    health = _snapshot_health(db, config, started=started, meter=meter)
    snapshots = {
        range_name: public_snapshot(
            db, config, started=started, meter=meter, range_name=range_name, now=now, health=health
        )
        for range_name in RANGES
    }
    findings_catalog = build_findings_catalog(db, now=now)
    for snap in snapshots.values():
        for item in snap.get("detections") or []:
            if isinstance(item, dict):
                item["public_stage_note"] = public_stage_note(item)
        for event in snap.get("activity") or []:
            if isinstance(event, dict) and isinstance(event.get("item"), dict):
                event["public_stage_note"] = public_stage_note(event["item"])
    return sanitize_public(
        {
            "published_at": iso(now),
            "snapshots": snapshots,
            "findings": findings_catalog,
            "stream": build_live_stream(db, config, now=now),
            "disclaimers": {
                "scout_triage": "under review, not a verdict",
                "analyst": "AI verdict (may be wrong)",
            },
        },
        config,
    )


def build_benchmark_document(config: Config) -> dict:
    payload = load_benchmarks(config.bench_dir)
    payload["production_scout"] = config.scout_model
    return sanitize_public(payload, config)


def _day_key(stamp: str | None) -> str | None:
    if not stamp or len(stamp) < 10:
        return None
    return stamp[:10]


def build_daily_history(live_document: dict, *, day: str) -> dict:
    snap = (live_document.get("snapshots") or {}).get("24h") or {}
    return {
        "date": day,
        "scanned_total": (snap.get("scanned") or {}).get("total"),
        "scout_flagged": (snap.get("scout") or {}).get("flagged"),
        "triage_total": (snap.get("triage") or {}).get("total"),
        "analyst_total": (snap.get("analyst") or {}).get("total"),
        "alerts_sent": (snap.get("webhook") or {}).get("alerts_sent"),
        "confirmed_malicious": (snap.get("confirmed") or {}).get("count"),
    }


def build_daily_confirmed(findings_catalog: dict, *, day: str) -> dict:
    rows: list[dict] = []
    catalog = findings_catalog.get("30d") or findings_catalog.get("24h") or {}
    for scope in ("triage", "flagged"):
        block = catalog.get(scope) or {}
        for row in block.get("rows") or []:
            if not isinstance(row, dict):
                continue
            if _day_key(row.get("created_at")) == day:
                rows.append(row)
    rows.sort(key=lambda item: item.get("created_at") or "", reverse=True)
    return {"date": day, "findings": rows}


def collect_release_keys(findings_catalog: dict, snapshots: dict) -> set[str]:
    keys: set[str] = set()
    for catalog in findings_catalog.values():
        for scope in catalog.values():
            for row in scope.get("rows") or []:
                if isinstance(row, dict):
                    keys.add(release_key(row["ecosystem"], row["name"], row["version"]))
    for snap in snapshots.values():
        for item in snap.get("detections") or []:
            if isinstance(item, dict):
                keys.add(release_key(item["ecosystem"], item["name"], item["version"]))
    return keys


def _upload_objects(client, bucket: str, uploads: list[tuple[str, bytes, str]]) -> None:
    for key, body, cache_control in uploads:
        put_feed_object(
            client,
            bucket=bucket,
            key=key,
            body=body,
            content_type=DASH_JSON_CONTENT_TYPE,
            cache_control=cache_control,
        )


def publish_public_dash(
    db: Database,
    config: Config,
    *,
    started: float,
    meter=None,
    client=None,
    now: datetime | None = None,
) -> bool:
    if not config.dash_configured():
        return False
    blocked = public_publish_blocked(db, config)
    if blocked:
        # A user watchlist is private. The error shows on local /health; it is stored once, not every pass.
        state = db.public_dash_state()
        if state is None or state["last_error"] != blocked:
            db.mark_public_dash_error(blocked)
        return False
    now = now or utcnow()
    today = now.strftime("%Y-%m-%d")
    try:
        live_document = build_live_document(db, config, started=started, meter=meter, now=now)
        live_digest = stable_live_digest(live_document)
        benchmark = build_benchmark_document(config)
        bench_digest = stable_benchmark_digest(benchmark)
        state = db.public_dash_state()
        live_changed = state is None or state["live_hash"] != live_digest
        bench_changed = state is None or state["benchmark_hash"] != bench_digest
        uploader = client if client is not None else make_r2_client(config, timeout=UPLOAD_TIMEOUT_S)
        bucket = config.feed_r2_bucket
        live_uploads: list[tuple[str, bytes, str]] = []
        if live_changed:
            live_uploads.append((LIVE_JSON_KEY, _encode(live_document), CACHE_LIVE))
            history_key = f"{LIVE_PREFIX}history/{today}.json"
            confirmed_key = f"{LIVE_PREFIX}confirmed/{today}.json"
            live_uploads.append((history_key, _encode(build_daily_history(live_document, day=today)), CACHE_TODAY))
            live_uploads.append(
                (
                    confirmed_key,
                    _encode(build_daily_confirmed(live_document.get("findings") or {}, day=today)),
                    CACHE_TODAY,
                )
            )

        release_uploads: list[tuple[str, str, str, bytes]] = []
        release_keys = collect_release_keys(live_document.get("findings") or {}, live_document.get("snapshots") or {})
        # Only objects never published, or whose rows changed since, are rebuilt.
        to_check = db.public_dash_releases_to_check(sorted(release_keys))
        for key in sorted(to_check):
            eco, name, version = key.split(":", 2)
            detail = release(db, eco, name, version)
            if detail is None:
                continue
            obj_key = release_object_key(eco, name, version)
            body = _encode(sanitize_public(public_release(detail), config))
            digest = hashlib.sha256(body).hexdigest()
            if db.public_dash_release_hash(key) == digest:
                continue
            release_uploads.append((key, obj_key, digest, body))
        # A key with nothing to upload is current now; one waiting on an upload
        # stays dirty until that upload succeeds.
        pending = {key for key, _, _, _ in release_uploads}
        db.clear_public_dash_dirty({key: mark for key, mark in to_check.items() if key not in pending})

        if not live_uploads and not bench_changed and not release_uploads:
            return False

        # Each hash is stored only after its own objects are on R2, so a
        # failed or timed-out PUT is retried on the next pass.
        began = _clock()
        if live_uploads:
            _upload_objects(uploader, bucket, live_uploads)
            db.mark_public_dash_live_published(live_digest, when=now)
        if bench_changed:
            _upload_objects(uploader, bucket, [(BENCHMARK_KEY, _encode(benchmark), CACHE_TODAY)])
            db.mark_public_dash_benchmark_published(bench_digest, when=now)
        for done, (key, obj_key, digest, body) in enumerate(release_uploads):
            if done and _clock() - began >= PUBLISH_BUDGET_S:
                log.info("public dashboard: %d release objects left for the next pass", len(release_uploads) - done)
                break
            _upload_objects(uploader, bucket, [(obj_key, body, CACHE_RELEASE)])
            db.mark_public_dash_release(key, digest)
            db.clear_public_dash_dirty({key: to_check[key]})
        db.mark_public_dash_published_at(iso(now))
    except Exception as exc:
        message = _public_error(exc, config)
        log.warning("public dashboard upload failed: %s", message)
        try:
            db.mark_public_dash_error(message)
        except Exception:
            log.warning("public dashboard error could not be stored")
        return False
    log.info("public dashboard published")
    return True


class PublicDashPublisher:
    """Debounced change-triggered uploads in a background thread."""

    def __init__(
        self,
        db: Database,
        config: Config,
        *,
        started: float,
        meter,
        stop: threading.Event,
    ) -> None:
        self._db = db
        self._config = config
        self._started = started
        self._meter = meter
        self._stop = stop
        self._wake = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="hunter-public-dash", daemon=True)

    def notify(self) -> None:
        self._wake.set()

    def start(self) -> None:
        self._thread.start()

    def join(self, timeout: float | None = None) -> None:
        self._thread.join(timeout)

    def _loop(self) -> None:
        pending = False
        idle_ticks = 0
        while not self._stop.is_set():
            woke = self._wake.wait(1.0)
            if self._stop.is_set():
                return
            if woke:
                self._wake.clear()
                pending = True
            else:
                idle_ticks += 1
                if idle_ticks >= 30:
                    idle_ticks = 0
                    pending = True
            if not pending or not self._config.dash_configured():
                continue
            deadline = time.monotonic() + DEBOUNCE_S
            while time.monotonic() < deadline and not self._stop.is_set():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                if self._wake.wait(remaining):
                    self._wake.clear()
                    deadline = time.monotonic() + DEBOUNCE_S
            pending = False
            try:
                publish_public_dash(
                    self._db,
                    self._config,
                    started=self._started,
                    meter=self._meter,
                )
            except Exception:
                log.exception("public dashboard publisher failed")


def start_public_dash_publisher(
    db: Database,
    config: Config,
    *,
    started: float,
    meter,
    stop: threading.Event,
) -> PublicDashPublisher | None:
    if not config.dash_configured():
        return None
    publisher = PublicDashPublisher(db, config, started=started, meter=meter, stop=stop)
    publisher.start()
    return publisher


def scan_for_secrets(value: object, config: Config) -> list[str]:
    frags = _secret_fragments(config)
    hits: list[str] = []

    def walk(node: object, path: str) -> None:
        if isinstance(node, dict):
            for key, child in node.items():
                walk(child, f"{path}.{key}" if path else str(key))
        elif isinstance(node, list):
            for index, child in enumerate(node):
                walk(child, f"{path}[{index}]")
        elif isinstance(node, str):
            for frag in frags:
                if frag and frag in node:
                    hits.append(path or "<root>")
                    break

    walk(value, "")
    return hits
