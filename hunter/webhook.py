"""Optional alert webhook with a durable outbox.

Alerts go to any HTTP endpoint as JSON, or as a Slack-style `{"text": ...}` body
for chat tools that accept it (Slack, Discord, Mattermost, and others).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

from hunter.config import ALERT_WEBHOOK_MIN_PROBABILITY
from hunter.db import Database, iso, utcnow
from hunter.models import Classification

USER_AGENT = "supply-chain-hunter/0.1"

# Some chat webhooks (Discord's Slack-compatible one among them) return HTTP 400
# when `text` is longer than 2000 characters. Stay under that cap so package,
# band, verdict, and link survive.
SLACK_TEXT_LIMIT = 1900
DISCORD_SLACK_TEXT_LIMIT = SLACK_TEXT_LIMIT

# Accept a bare line and a markdown emphasis line such as **Verdict: malicious**.
VERDICT_RE = re.compile(
    r"(?im)^[\s>*_`-]*verdict\**\s*:\s*\**\s*(malicious|benign|uncertain)\b"
)
INCOMPLETE_SIGNALS = {
    "ai_incomplete",
    "static_rule",
    "jev_unavailable",
    "jev_retry",
}
# Scout or Triage did not see the whole release. The row still goes to Analyst and
# the alert webhook, with a note that names what was not read.
PARTIAL_READ_REASONS = {
    "partial_read": "a file or chunk was only partly read",
    "jev_unreadable": "the decision model (Scout) could not read the release text",
    "release_budget": "the release was over the decision model (Scout) token cap",
    "release_budget_partial": "the decision model (Scout) read only the riskiest files, within its token cap",
    "triage_diff_cut": "the mid-tier, balanced model (Triage) diff was cut at its size cap",
}
SLACK_TEXT_FORMATS = {"slack", "discord"}


def idempotency_key(ecosystem: str, name: str, version: str) -> str:
    return f"{ecosystem}:{name}:{version}"


def analysis_idempotency_key(ecosystem: str, name: str, version: str) -> str:
    return f"{ecosystem}:{name}:{version}:analysis"


def parse_verdict(text: str) -> str | None:
    """Return the concluding Verdict line. The last exact line wins."""
    matches = VERDICT_RE.findall(text or "")
    if not matches:
        return None
    return matches[-1].lower()


def partial_read_reasons(signals: object) -> list[str]:
    """Signals that mean part of the release was not read, in a fixed order."""
    if not isinstance(signals, list):
        return []
    present = {str(item) for item in signals}
    return [name for name in PARTIAL_READ_REASONS if name in present]


def partial_read_text(reasons: list[str]) -> str:
    return "; ".join(PARTIAL_READ_REASONS.get(name, name) for name in reasons)


def uses_slack_text(webhook_format: str) -> bool:
    return (webhook_format or "").strip().lower() in SLACK_TEXT_FORMATS


def is_discord_webhook(url: str) -> bool:
    host = (urllib.parse.urlparse(url or "").hostname or "").lower()
    return (
        host == "discord.com"
        or host.endswith(".discord.com")
        or host == "discordapp.com"
        or host.endswith(".discordapp.com")
    )


def delivery_format(webhook_format: str, webhook_url: str = "") -> str:
    """Slack text for ALERT_WEBHOOK_FORMAT=slack and for any Discord webhook URL."""
    if uses_slack_text(webhook_format) or is_discord_webhook(webhook_url):
        return "slack"
    normalized = (webhook_format or "json").strip().lower()
    return normalized or "json"


def clip_text(text: str, limit: int = SLACK_TEXT_LIMIT) -> str:
    """Clip to the Slack-style `text` limit. The start of the message is kept."""
    cleaned = (text or "").replace("\x00", "").strip()
    if len(cleaned) <= limit:
        return cleaned
    if limit <= 1:
        return "…"[:limit]
    return cleaned[: limit - 1].rstrip() + "…"


def slack_body(text: str) -> str:
    """Slack-style text body. Never a classification JSON blob."""
    return dump_body({"text": clip_text(text)}).decode("utf-8")


def build_payload(result: Classification, *, when: datetime | None = None) -> dict:
    moment = when or utcnow()
    return {
        "kind": "classification",
        "idempotency_key": idempotency_key(result.ecosystem, result.name, result.new_version),
        "timestamp": iso(moment),
        "jev_model_id": result.jev_model_id,
        "ecosystem": result.ecosystem,
        "package": result.name,
        "rank": result.rank,
        "old_version": result.old_version,
        "new_version": result.new_version,
        "registry_url": result.registry_url,
        "band": result.band,
        "malice_probability": result.malice_probability,
        "attack_family": result.attack_family,
        "subtype": result.subtype,
        "family_probabilities": result.family_probabilities,
        "subtype_probabilities": result.subtype_probabilities,
        "cause_probabilities": result.cause_probabilities,
        "suspected_cause": result.cause,
        "blast_radius_score": result.blast_radius_score,
        "blast_radius_label": result.blast_radius_label,
        "data_collection_score": result.data_collection_score,
        "capability_nouls": result.capability_nouls,
        "noul_probabilities": result.noul_probabilities,
        "signals": result.signals,
        "pass_d_agreed": result.pass_d_agreed,
        "pass_d_ran": result.pass_d_ran,
        "defer_reason": result.defer_reason,
        "child_findings": result.child_findings,
        **_rule_fields(result),
        **({"action": dict(result.action_ref)} if result.action_ref else {}),
    }


def _rule_fields(result: Classification) -> dict:
    """Rule verdict and hits for the stored row. Absent when the rule pack is off."""
    if not result.rule_verdict:
        return {}
    return {"rule_verdict": result.rule_verdict, "rule_hits": result.rule_hits, "rule_pack": result.rule_pack}


def top_strong_rule(findings: object) -> str:
    """First promoted rule finding as "rule path:line", or empty."""
    if not isinstance(findings, list):
        return ""
    for item in findings:
        if isinstance(item, dict) and item.get("tier") == "strong":
            return f"{item.get('rule')} {item.get('path')}:{item.get('line')}"
    return ""


def build_analysis_payload(
    evidence: dict,
    analysis_text: str,
    *,
    analysis_model_id: str,
    verdict: str | None = None,
    when: datetime | None = None,
    triage_model_id: str | None = None,
    triage_verdict: str | None = None,
    analyst_model_id: str | None = None,
) -> dict:
    moment = when or utcnow()
    ecosystem = str(evidence.get("ecosystem") or "")
    package = str(evidence.get("package") or "")
    new_version = str(evidence.get("new_version") or "")
    parsed_verdict = verdict if verdict is not None else parse_verdict(analysis_text)
    payload = {
        "kind": "smart_analysis",
        "idempotency_key": analysis_idempotency_key(ecosystem, package, new_version),
        "timestamp": iso(moment),
        "ecosystem": ecosystem,
        "package": package,
        "old_version": evidence.get("old_version"),
        "new_version": new_version,
        "registry_url": evidence.get("registry_url"),
        "primary_band": evidence.get("primary_band"),
        "malice_probability": evidence.get("malice_probability"),
        "signals": list(evidence.get("signals") or []),
        "child_findings": list(evidence.get("child_findings") or []),
        "jev_model_id": evidence.get("jev_model_id"),
        "analysis_model_id": analysis_model_id,
        "analysis": analysis_text,
        "verdict": parsed_verdict,
    }
    reasons = partial_read_reasons(payload["signals"])
    payload["partial_read"] = bool(reasons)
    payload["partial_reasons"] = reasons
    if triage_model_id:
        payload["triage_model_id"] = triage_model_id
    if triage_verdict:
        payload["triage_verdict"] = triage_verdict
    if analyst_model_id:
        payload["analyst_model_id"] = analyst_model_id
    top_rule = top_strong_rule(evidence.get("deterministic_findings"))
    if top_rule:
        payload["top_rule"] = top_rule
    action = evidence.get("action")
    if isinstance(action, dict) and action:
        payload["action"] = dict(action)
    return payload


def dump_body(payload: dict) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def signature_header(secret: str, body: bytes) -> str:
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def _signals_block_alert(signals: object) -> bool:
    if not isinstance(signals, list):
        return False
    for item in signals:
        text = str(item)
        if text in INCOMPLETE_SIGNALS or text.startswith("jev_pass_") or text.startswith("gateway_"):
            return True
    return False


def jev_evidence_complete(evidence: dict) -> bool:
    """True when Jev finished, or Scout marked the read partial or unread.

    Static rows, deferred rows, and failed Jev passes are never complete.
    """
    if evidence.get("jev_complete") is False:
        return False
    band = str(evidence.get("primary_band") or "")
    if band not in {"alert", "review", "benign"}:
        return False
    if _signals_block_alert(evidence.get("signals")):
        return False
    return True


def should_notify(
    band: str,
    *,
    webhook_on_review: bool,
    signals: list[str] | None = None,
    webhook_on_phantom: bool = False,
    malice_probability: float | None = None,
    min_alert_probability: float = ALERT_WEBHOOK_MIN_PROBABILITY,
) -> bool:
    """Classification rows never post.

    The probability floor, review override, and phantom override used to post
    before Triage. They are ignored. Only a confirmed analysis posts.
    """
    del (
        band,
        webhook_on_review,
        signals,
        webhook_on_phantom,
        malice_probability,
        min_alert_probability,
    )
    return False


def should_deliver_analysis(
    evidence: dict,
    verdict: str | None,
    *,
    min_alert_probability: float = ALERT_WEBHOOK_MIN_PROBABILITY,
    confirmed_by: str | None = None,
    analyst_required: bool = True,
) -> bool:
    """POST only a malicious verdict after Jev, confirmed by Analyst.

    Uncertain, benign, unknown, and error verdicts stay in SQLite. Incomplete
    Jev work never qualifies. Triage malicious is not enough while
    Analyst is required. `min_alert_probability` does not open another path.
    Pass `analyst_required=False` only for the HUNTER_ANALYST=0 rollback.
    """
    del min_alert_probability
    if (verdict or "").strip().lower() != "malicious":
        return False
    if not jev_evidence_complete(evidence):
        return False
    if analyst_required and confirmed_by != "analyst":
        return False
    return True


def slack_text(payload: dict) -> str:
    signals = ", ".join(str(item) for item in (payload.get("signals") or []))
    lines = [
        (
            f"Supply chain {payload.get('band')} "
            f"{payload.get('ecosystem')}/{payload.get('package')} {payload.get('new_version')}"
        ),
        (
            f"probability {payload.get('malice_probability')} "
            f"family {payload.get('attack_family')} subtype {payload.get('subtype')}"
        ),
        str(payload.get("registry_url") or ""),
        f"previous {payload.get('old_version')} rank {payload.get('rank')}",
    ]
    if signals:
        lines.append(signals)
    return clip_text("\n".join(lines))


def slack_analysis_text(payload: dict) -> str:
    verdict = payload.get("verdict") or "unknown"
    lines = [
        (
            f"Smart analysis ({payload.get('primary_band')}) "
            f"{payload.get('ecosystem')}/{payload.get('package')} {payload.get('new_version')}"
        ),
        f"verdict {verdict} probability {payload.get('malice_probability')}",
        str(payload.get("registry_url") or ""),
        f"model {payload.get('analysis_model_id')}",
    ]
    if payload.get("analyst_model_id"):
        lines.append("analyst confirmed")
    if payload.get("top_rule"):
        lines.append(f"rule {payload.get('top_rule')}")
    reasons = payload.get("partial_reasons")
    if reasons is None:
        reasons = partial_read_reasons(payload.get("signals"))
    if reasons:
        lines.append(f"partial read: {partial_read_text(list(reasons))}")
    analysis = str(payload.get("analysis") or "").strip()
    if analysis:
        lines.extend(["", analysis])
    return clip_text("\n".join(lines))


def enqueue_classification(
    db: Database,
    result: Classification,
    *,
    webhook_on_review: bool,
    when: datetime | None = None,
    webhook_on_phantom: bool = False,
    webhook_format: str = "json",
    min_alert_probability: float = ALERT_WEBHOOK_MIN_PROBABILITY,
    webhook_url: str = "",
) -> bool:
    """Classification never enters the alert outbox.

    Callers still pass the historical flags. The release is stored elsewhere
    and, when Jev finished, queued for Triage. Only `enqueue_analysis` posts.
    """
    del (
        db,
        result,
        webhook_on_review,
        when,
        webhook_on_phantom,
        webhook_format,
        min_alert_probability,
        webhook_url,
    )
    return False


def enqueue_analysis(
    db: Database,
    evidence: dict,
    analysis_text: str,
    *,
    analysis_model_id: str,
    verdict: str | None = None,
    webhook_format: str = "json",
    when: datetime | None = None,
    min_alert_probability: float = ALERT_WEBHOOK_MIN_PROBABILITY,
    webhook_url: str = "",
    confirmed_by: str | None = None,
    analyst_required: bool = True,
    triage_model_id: str | None = None,
    triage_verdict: str | None = None,
    analyst_model_id: str | None = None,
) -> bool:
    payload = build_analysis_payload(
        evidence,
        analysis_text,
        analysis_model_id=analysis_model_id,
        verdict=verdict,
        when=when,
        triage_model_id=triage_model_id,
        triage_verdict=triage_verdict,
        analyst_model_id=analyst_model_id,
    )
    if not should_deliver_analysis(
        evidence,
        payload.get("verdict"),
        min_alert_probability=min_alert_probability,
        confirmed_by=confirmed_by,
        analyst_required=analyst_required,
    ):
        return False
    if delivery_format(webhook_format, webhook_url) == "slack":
        body = slack_body(slack_analysis_text(payload))
    else:
        body = dump_body(payload).decode("utf-8")
    return db.enqueue(payload["idempotency_key"], body, when=when)


def enqueue_decision_model_down(
    db: Database,
    *,
    since: str,
    failures: int,
    waiting: int,
    waiting_strong: int,
    webhook_format: str = "json",
    webhook_url: str = "",
    when: datetime | None = None,
) -> bool:
    """The one webhook for a decision-model outage. Carries counts only, never a package or its text."""
    payload = {
        "kind": "decision_model_down",
        "idempotency_key": f"decision-model-down:{since}",
        "since": since,
        "failed_releases": failures,
        "releases_waiting": waiting,
        "releases_waiting_with_strong_rule": waiting_strong,
        "sent_at": iso(when or utcnow()),
    }
    if delivery_format(webhook_format, webhook_url) == "slack":
        text = (
            f"Decision model down since {since}. No decision model (primary or backup) could score "
            f"{failures} release(s). {waiting} release(s) are waiting, {waiting_strong} with a strong rule hit. "
            "They will be scored when a model answers. This is the only message for this outage."
        )
        body = slack_body(clip_text(text))
    else:
        body = dump_body(payload).decode("utf-8")
    return db.enqueue(payload["idempotency_key"], body, when=when)


class DeliveryError(Exception):
    pass


def post_json(url: str, body: bytes, headers: dict[str, str], timeout: float = 15.0) -> int:
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = int(response.status)
            response.read()
    except urllib.error.HTTPError as exc:
        raise DeliveryError(f"HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise DeliveryError(str(exc.reason)) from exc
    if status < 200 or status >= 300:
        raise DeliveryError(f"HTTP {status}")
    return status


def drain_outbox(
    db: Database,
    *,
    url: str,
    secret: str = "",
    poster=None,
    when: datetime | None = None,
    limit: int = 50,
    extra_headers: dict[str, str] | None = None,
) -> int:
    """POST due rows. Returns the number of successful deliveries.

    `extra_headers` (from ALERT_WEBHOOK_HEADERS) are added to every request, for
    endpoints that want an Authorization or routing header.
    """
    if not url and poster is None:
        return 0
    sent = 0
    moment = when or utcnow()
    for row in db.due_outbox(moment, limit=limit):
        body = row["body"].encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        }
        headers.update(extra_headers or {})
        if secret:
            headers["X-Hunter-Signature"] = signature_header(secret, body)
        try:
            if poster is not None:
                poster(url, body, headers)
            else:
                post_json(url, body, headers)
        except Exception as exc:
            attempts = int(row["attempts"]) + 1
            db.mark_retry(int(row["id"]), attempts, str(exc), when=moment)
            continue
        db.mark_sent(int(row["id"]), when=moment)
        sent += 1
    return sent


clip_discord_text = clip_text
