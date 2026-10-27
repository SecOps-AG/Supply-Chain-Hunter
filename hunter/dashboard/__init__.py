"""Read-only dashboard API built from what serve already stores.

Every function here only reads. Package names, signals and model reports come from
package contents and are attacker-controlled; the page renders them as text only.
Webhook bodies, webhook errors, prompts, keys and environment values are never returned.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

from hunter.db import Database, iso, utcnow
from hunter.inventory.scope import is_stale, watch_context
from hunter.webhook import parse_verdict, partial_read_reasons

STATIC_DIR = Path(__file__).with_name("static")
STATIC_FILES = {
    "index.html": "text/html; charset=utf-8",
    "app.css": "text/css; charset=utf-8",
    "app.js": "text/javascript; charset=utf-8",
    "github_stars.js": "text/javascript; charset=utf-8",
}
# api.github.com is the header star count (one unauthenticated GET). Nothing else is fetched off-origin.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self' https://api.github.com; object-src 'none'; base-uri 'none'; "
    "frame-ancestors 'none'; form-action 'none'"
)

# Range key: (seconds, ISO prefix length of one bucket, bucket seconds).
RANGES = {
    "1h": (3600, 16, 60),
    "24h": (86400, 13, 3600),
    "7d": (7 * 86400, 13, 3600),
    "30d": (30 * 86400, 10, 86400),
}
DEFAULT_RANGE = "24h"
TRIAGE_VERDICTS = ("malicious", "benign", "uncertain")
MAX_REPORT_CHARS = 20_000
MAX_SIGNALS = 40
FINDINGS_PAGE_MAX = 100


def range_key(value: str | None) -> str:
    return value if value in RANGES else DEFAULT_RANGE


def _since(now: datetime, key: str) -> str:
    return iso(now - timedelta(seconds=RANGES[key][0]))


def _bucket_labels(now: datetime, key: str) -> list[str]:
    seconds, width, step = RANGES[key]
    count = seconds // step
    labels = []
    for index in range(count - 1, -1, -1):
        labels.append(iso(now - timedelta(seconds=index * step))[:width])
    return labels


def _series(labels: list[str], stamps: list[str | None], width: int) -> list[int]:
    slots = {label: 0 for label in labels}
    for stamp in stamps:
        if stamp and stamp[:width] in slots:
            slots[stamp[:width]] += 1
    return [slots[label] for label in labels]


def release_key(ecosystem: str, name: str, version: str) -> str:
    return f"{ecosystem}:{name}:{version}"


def _payload(text: str | None) -> dict:
    try:
        value = json.loads(text or "{}")
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def _signals(payload: dict) -> list[str]:
    raw = payload.get("signals")
    if not isinstance(raw, list):
        return []
    return [str(item)[:200] for item in raw]


def _rule_ids(payload: dict) -> list[str]:
    hits = payload.get("rule_hits")
    if not isinstance(hits, list):
        return []
    seen: list[str] = []
    for hit in hits:
        if isinstance(hit, dict) and hit.get("rule") and str(hit["rule"]) not in seen:
            seen.append(str(hit["rule"])[:80])
    return seen


def _triage_verdict(row: dict | None) -> str | None:
    if row is None:
        return None
    if row.get("status") == "reported":
        return parse_verdict(row.get("report_text") or "") or "no verdict line"
    return None


def _stage_status(row: dict | None) -> str | None:
    """pending, retrying, reported, exhausted or suppressed; None when the stage never ran."""
    return None if row is None else str(row.get("status") or "")


def _release_summary(row: dict) -> dict:
    payload = _payload(row.get("payload_json"))
    signals = _signals(payload)
    return {
        "key": release_key(row["ecosystem"], row["name"], row["version"]),
        "ecosystem": row["ecosystem"],
        "name": row["name"],
        "version": row["version"],
        "old_version": payload.get("old_version") if isinstance(payload.get("old_version"), str) else None,
        "band": row.get("band"),
        "p": row.get("malice_probability"),
        "family": row.get("family"),
        "subtype": row.get("subtype"),
        "created_at": row.get("created_at"),
        "signals": signals[:MAX_SIGNALS],
        "rules": _rule_ids(payload),
        "rule_verdict": payload.get("rule_verdict") if isinstance(payload.get("rule_verdict"), str) else None,
        "partial_reasons": partial_read_reasons(signals),
        "defer_reason": payload.get("defer_reason") if isinstance(payload.get("defer_reason"), str) else None,
    }


def _alert_status(outbox: list[dict]) -> str | None:
    for row in outbox:
        if row["status"] == "sent":
            return "sent"
    if outbox:
        return "retrying" if any(row.get("has_error") for row in outbox) else "pending"
    return None


def _join(flagged: list[dict], triage: list[dict], analyst: list[dict], outbox: list[dict]) -> list[dict]:
    triage_by = {row["idempotency_key"]: row for row in triage}
    analyst_by = {row["idempotency_key"]: row for row in analyst}
    outbox_by: dict[str, list[dict]] = {}
    for row in outbox:
        key = str(row["idempotency_key"])
        base = key[: -len(":analysis")] if key.endswith(":analysis") else key
        outbox_by.setdefault(base, []).append(row)
    joined = []
    for row in flagged:
        item = _release_summary(row)
        key = item["key"]
        t_row = triage_by.get(key)
        a_row = analyst_by.get(key)
        item["triage_status"] = _stage_status(t_row)
        item["triage_verdict"] = _triage_verdict(t_row)
        item["triage_at"] = None if t_row is None else t_row.get("updated_at")
        item["analyst_status"] = _stage_status(a_row)
        item["analyst_verdict"] = None if a_row is None else a_row.get("verdict")
        item["analyst_at"] = None if a_row is None else a_row.get("updated_at")
        item["alert_status"] = _alert_status(outbox_by.get(key, []))
        sent = [row["sent_at"] for row in outbox_by.get(key, []) if row.get("sent_at")]
        item["alert_sent_at"] = max(sent) if sent else None
        joined.append(item)
    return joined


def _listed_rows(rows: list[dict], listed: set[tuple[str, str]]) -> list[dict]:
    """Rows whose ``eco:name:version`` key names a package on the user watchlist."""
    kept = []
    for row in rows:
        ecosystem, _sep, rest = str(row.get("idempotency_key") or "").partition(":")
        name, _sep, _version = rest.partition(":")
        if (ecosystem, name) in listed:
            kept.append(row)
    return kept


def _listed_pairs(db: Database) -> set[tuple[str, str]]:
    return {(row["ecosystem"], row["name"]) for row in db.user_watch_rows()}


def watchlist_summary(db: Database, *, mode: str = "all", scope: str = "all", now: datetime | None = None) -> dict:
    """Counts and sources of the user watchlist, with a stale flag per source. No names."""
    moment = now or utcnow()
    sources = [
        {**row, "stale": is_stale(row.get("imported_at"), moment)} for row in db.user_watch_sources()
    ]
    counts = db.user_watch_counts()
    counts.pop("sources", None)
    return {
        **counts,
        "mode": mode,
        "alert_scope": scope,
        "sources": sources,
    }


def _stage_reached(item: dict) -> str:
    if item.get("alert_status") == "sent":
        return "webhook"
    if item.get("analyst_status"):
        return "analyst"
    if item.get("triage_status"):
        return "triage"
    return "scout"


def snapshot(
    db: Database,
    *,
    health: dict,
    models: dict | None,
    range_name: str | None = None,
    now: datetime | None = None,
    rules_enabled: bool | None = None,
    watched_only: bool = False,
    watch_mode: str = "all",
    alert_scope: str = "all",
) -> dict:
    """Everything the Dashboard tab needs for one range. ``watched_only`` keeps user-watchlist packages only."""
    now = now or utcnow()
    key = range_key(range_name)
    seconds, width, step = RANGES[key]
    since = _since(now, key)
    labels = _bucket_labels(now, key)

    buckets = db.release_bucket_counts(since, width, watched_only=watched_only)
    per_eco: dict[str, list[int]] = {}
    band_totals: Counter = Counter()
    eco_totals: Counter = Counter()
    for row in buckets:
        series = per_eco.setdefault(row["ecosystem"], [0] * len(labels))
        if row["bucket"] in labels:
            series[labels.index(row["bucket"])] += int(row["n"])
        band_totals[row["band"] or "unknown"] += int(row["n"])
        eco_totals[row["ecosystem"]] += int(row["n"])

    flagged = db.flagged_releases_since(since, watched_only=watched_only)
    triage = db.investigations_since(since)
    analyst = db.analyst_reviews_since(since)
    outbox = db.outbox_since(since)
    if watched_only:
        listed = _listed_pairs(db)
        triage = _listed_rows(triage, listed)
        analyst = _listed_rows(analyst, listed)
        outbox = _listed_rows(outbox, listed)
    joined = _join(flagged, triage, analyst, outbox)

    signal_counts: Counter = Counter()
    rule_counts: Counter = Counter()
    rule_releases = 0
    for item in joined:
        signal_counts.update(sig for sig in set(item["signals"]) if not sig.startswith("rule:"))
        if item["rules"]:
            rule_releases += 1
            rule_counts.update(item["rules"])

    triage_counts: Counter = Counter()
    for row in triage:
        verdict = _triage_verdict(row)
        triage_counts[verdict or row["status"]] += 1
    analyst_counts: Counter = Counter()
    for row in analyst:
        analyst_counts[row["verdict"] if row["status"] == "reported" and row["verdict"] else row["status"]] += 1

    alerts = [row for row in outbox if not str(row["idempotency_key"]).startswith("decision-model-down:")]
    outages = [row for row in outbox if str(row["idempotency_key"]).startswith("decision-model-down:")]
    sent = [row for row in alerts if row["status"] == "sent"]

    detections = [
        item
        for item in joined
        if item["analyst_verdict"] in ("malicious", "uncertain")
        or item["triage_verdict"] == "malicious"
    ]
    confirmed = [item for item in detections if item["analyst_verdict"] == "malicious"]
    confirmed.sort(key=lambda item: item.get("analyst_at") or "", reverse=True)

    activity = []
    for item in joined[:200]:
        activity.append({"ts": item["created_at"], "kind": "scout", "item": _slim(item), "text": item["band"]})
        if item["triage_verdict"]:
            activity.append({"ts": item["triage_at"], "kind": "triage", "item": _slim(item), "text": item["triage_verdict"]})
        if item["analyst_verdict"]:
            activity.append({"ts": item["analyst_at"], "kind": "analyst", "item": _slim(item), "text": item["analyst_verdict"]})
        if item["alert_sent_at"]:
            activity.append({"ts": item["alert_sent_at"], "kind": "alert", "item": _slim(item), "text": "sent"})
    activity.sort(key=lambda event: event["ts"] or "", reverse=True)

    usage_days = 7 if key != "30d" else 30
    usage_since_day = (now - timedelta(days=usage_days - 1)).strftime("%Y-%m-%d")
    scanned = sum(eco_totals.values())
    escalated = len(triage)
    return {
        "generated_at": iso(now),
        "range": key,
        "since": since,
        "watched_only": watched_only,
        "watchlist": watchlist_summary(db, mode=watch_mode, scope=alert_scope, now=now),
        "bucket_seconds": step,
        "buckets": labels,
        "health": health,
        "models": models,
        "feeds": {
            "last_success": db.last_poll(),
            "last_error": {eco: (err or None) and str(err)[:200] for eco, err in db.poll_errors().items()},
        },
        "scanned": {"total": scanned, "by_ecosystem": dict(eco_totals), "series": per_eco},
        "scout": {
            "bands": dict(band_totals),
            "flagged": len(flagged),
            "top_signals": signal_counts.most_common(12),
        },
        "rules": {
            "enabled": rules_enabled,
            "releases_with_hits": rule_releases,
            "top_rules": rule_counts.most_common(12),
        },
        "triage": {
            "total": escalated,
            "verdicts": dict(triage_counts),
            "series": _series(labels, [row["created_at"] for row in triage], width),
            "share_of_scanned": None if not scanned else round(escalated / scanned, 4),
        },
        "analyst": {
            "total": len(analyst),
            "verdicts": dict(analyst_counts),
            "series": _series(labels, [row["created_at"] for row in analyst], width),
        },
        "webhook": {
            "alerts_total": len(alerts),
            "alerts_sent": len(sent),
            "alerts_waiting": len([row for row in alerts if row["status"] != "sent"]),
            "outage_notices": len(outages),
            "series": _series(labels, [row["sent_at"] for row in sent], width),
            "last_sent_at": max((row["sent_at"] for row in sent if row["sent_at"]), default=None),
        },
        "confirmed": {
            "count": len(confirmed),
            "latest": _slim(confirmed[0]) if confirmed else None,
            "uncertain": len([item for item in detections if item["analyst_verdict"] == "uncertain"]),
            "cleared": len([item for item in joined if item["triage_verdict"] == "malicious" and item["analyst_verdict"] == "benign"]),
            "series": _series(labels, [item.get("analyst_at") for item in confirmed], width),
        },
        "detections": [_slim(item) for item in detections[:50]],
        "activity": activity[:40],
        "usage": {
            "since_day": usage_since_day,
            "scout": db.scout_usage_since(usage_since_day),
            "triage_calls": sum(1 for row in triage if row["status"] == "reported"),
            "analyst_calls": sum(1 for row in analyst if row["status"] == "reported"),
            "triage_tokens": None,
            "analyst_tokens": None,
        },
        # Not recorded by serve yet. The page says so instead of showing a number.
        "not_tracked": ["publish_to_verdict", "running_now", "filter_drops", "triage_analyst_tokens"],
    }


def _slim(item: dict) -> dict:
    return {
        "key": item["key"],
        "ecosystem": item["ecosystem"],
        "name": item["name"],
        "version": item["version"],
        "band": item["band"],
        "p": item["p"],
        "created_at": item["created_at"],
        "triage_verdict": item.get("triage_verdict"),
        "analyst_verdict": item.get("analyst_verdict"),
        "analyst_at": item.get("analyst_at"),
        "alert_status": item.get("alert_status"),
        "partial": bool(item.get("partial_reasons")),
        "signals": item["signals"][:8],
    }


def _num_param(value: str | None) -> float | None:
    try:
        return None if value in (None, "") else float(value)
    except ValueError:
        return None


def findings(db: Database, params: dict[str, str], *, now: datetime | None = None) -> dict:
    """Releases Scout flagged, joined with Triage, Analyst and webhook state, filtered and paged."""
    now = now or utcnow()
    key = range_key(params.get("range"))
    since = _since(now, key)
    watched_only = params.get("watched") == "1"
    triage = db.investigations_since(since)
    analyst = db.analyst_reviews_since(since)
    outbox = db.outbox_since(since)
    if watched_only:
        listed = _listed_pairs(db)
        triage = _listed_rows(triage, listed)
        analyst = _listed_rows(analyst, listed)
        outbox = _listed_rows(outbox, listed)
    joined = _join(db.flagged_releases_since(since, watched_only=watched_only), triage, analyst, outbox)
    scope = params.get("scope") or "triage"
    if scope == "triage":
        joined = [item for item in joined if item["triage_status"]]
    for item in joined:
        item["stage"] = _stage_reached(item)
    signal_facets = Counter(sig for item in joined for sig in set(item["signals"]) if not sig.startswith("rule:"))
    rule_facets = Counter(rule for item in joined for rule in item["rules"])

    query = (params.get("q") or "").strip().lower()
    min_p = _num_param(params.get("min_p"))
    rows = []
    for item in joined:
        if params.get("ecosystem") and item["ecosystem"] != params["ecosystem"]:
            continue
        if params.get("band") and item["band"] != params["band"]:
            continue
        if params.get("verdict") and _final_verdict(item) != params["verdict"]:
            continue
        if params.get("stage") and item["stage"] != params["stage"]:
            continue
        if params.get("signal") and params["signal"] not in item["signals"]:
            continue
        if params.get("rule") and params["rule"] not in item["rules"]:
            continue
        if params.get("partial") == "1" and not item["partial_reasons"]:
            continue
        if min_p is not None and (item["p"] is None or item["p"] < min_p):
            continue
        if query and query not in f"{item['name']}@{item['version']}".lower():
            continue
        item["final_verdict"] = _final_verdict(item)
        rows.append(item)
    if params.get("sort") == "probability":
        rows.sort(key=lambda item: item["p"] or 0.0, reverse=True)
    try:
        offset = max(0, int(params.get("offset") or 0))
        limit = min(FINDINGS_PAGE_MAX, max(1, int(params.get("limit") or 25)))
    except ValueError:
        offset, limit = 0, 25
    return {
        "range": key,
        "scope": scope,
        "total": len(rows),
        "offset": offset,
        "limit": limit,
        "rows": rows[offset : offset + limit],
        "facets": {"signals": signal_facets.most_common(40), "rules": rule_facets.most_common(40)},
    }


def _final_verdict(item: dict) -> str:
    if item.get("analyst_verdict"):
        return str(item["analyst_verdict"])
    if item.get("triage_verdict"):
        return f"triage {item['triage_verdict']}"
    if item.get("triage_status") in ("pending", "retrying"):
        return "in triage"
    if item.get("triage_status"):
        return f"triage {item['triage_status']}"
    return f"scout {item.get('band')}"


def release(db: Database, ecosystem: str, name: str, version: str) -> dict | None:
    detail = db.release_detail(ecosystem, name, version)
    if detail is None:
        return None
    row = detail["release"]
    summary = _release_summary(row)
    payload = _payload(row.get("payload_json"))
    hits = payload.get("rule_hits") if isinstance(payload.get("rule_hits"), list) else []
    summary["rule_hits"] = [
        {
            "rule": str(hit.get("rule", ""))[:80],
            "tier": str(hit.get("tier", ""))[:20],
            "path": str(hit.get("path", ""))[:300],
            "line": hit.get("line") if isinstance(hit.get("line"), int) else None,
            "matched": str(hit.get("matched", ""))[:300],
            "summary": str(hit.get("summary", ""))[:300],
        }
        for hit in hits[:50]
        if isinstance(hit, dict)
    ]
    summary["signals"] = _signals(payload)[:200]
    summary["registry_url"] = payload.get("registry_url") if isinstance(payload.get("registry_url"), str) else None
    summary["scout_model_id"] = payload.get("jev_model_id") if isinstance(payload.get("jev_model_id"), str) else None
    triage = detail["triage"]
    analyst = detail["analyst"]
    watch = watch_context(db, ecosystem, name, version)
    if watch is not None:
        summary["watch"] = watch
    return {
        "release": summary,
        "triage": None
        if triage is None
        else {
            "status": triage["status"],
            "attempts": triage["attempts"],
            "verdict": _triage_verdict(triage),
            "report": (triage.get("report_text") or "")[:MAX_REPORT_CHARS],
            "created_at": triage["created_at"],
            "updated_at": triage["updated_at"],
        },
        "analyst": None
        if analyst is None
        else {
            "status": analyst["status"],
            "attempts": analyst["attempts"],
            "verdict": analyst.get("verdict"),
            "report": (analyst.get("report_text") or "")[:MAX_REPORT_CHARS],
            "created_at": analyst["created_at"],
            "updated_at": analyst["updated_at"],
        },
        "webhook": [
            {
                "kind": "analysis" if str(row["idempotency_key"]).endswith(":analysis") else "classification",
                "status": row["status"],
                "attempts": row["attempts"],
                "created_at": row["created_at"],
                "sent_at": row["sent_at"],
                "had_error": bool(row["has_error"]),
            }
            for row in detail["outbox"]
        ],
    }


def static_file(name: str) -> tuple[bytes, str] | None:
    """One of the shipped page files, or None. Only names in STATIC_FILES are served."""
    content_type = STATIC_FILES.get(name)
    if content_type is None:
        return None
    try:
        return (STATIC_DIR / name).read_bytes(), content_type
    except OSError:
        return None
