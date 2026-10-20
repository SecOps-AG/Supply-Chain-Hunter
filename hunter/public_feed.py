"""Public JSON Feed and RSS documents for confirmed malicious releases.

The webhook body and the analyst evidence stay in SQLite. This module copies
an allowlist of fields into ``public_feed_items`` and uploads only ``feed.json``
and ``feed.xml``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import format_datetime
from xml.sax.saxutils import escape

from hunter.config import Config
from hunter.db import Database, iso, utcnow
from hunter.taxonomy import FAMILY_CRITERIA
from hunter.webhook import partial_read_reasons

log = logging.getLogger("hunter.public_feed")

HOME_PAGE_URL = "https://github.com/SecOps-AG/Supply-Chain-Hunter"
FEED_DESCRIPTION = (
    "Confirmed malicious npm and PyPI releases and GitHub Actions tags. This feed lists "
    "package or action name, version or tag, and a short behavior label. It does not include analysis notes."
)
AUTHOR_NAME = "Supply Chain Hunter"
JSON_FEED_VERSION = "https://jsonfeed.org/version/1.1"
FEED_JSON_KEY = "feed.json"
FEED_XML_KEY = "feed.xml"
LIVE_PREFIX = "live/"
PUBLIC_KEYS = frozenset({FEED_JSON_KEY, FEED_XML_KEY})
JSON_CONTENT_TYPE = "application/feed+json; charset=utf-8"
DASH_JSON_CONTENT_TYPE = "application/json; charset=utf-8"
RSS_CONTENT_TYPE = "application/rss+xml; charset=utf-8"
_DATE = r"\d{4}-\d{2}-\d{2}"
_LIVE_OBJECT = (
    rf"^{LIVE_PREFIX}live\.json$|"
    rf"^{LIVE_PREFIX}benchmark\.json$|"
    rf"^{LIVE_PREFIX}history/{_DATE}\.json$|"
    rf"^{LIVE_PREFIX}confirmed/{_DATE}\.json$|"
    rf"^{LIVE_PREFIX}r/(npm|pypi|github-actions)/[^/]+/[^/]+\.json$"
)
LIMITED_REVIEW_TEXT = "Hunter did not read the entire release."
NPM_REGISTRY = "https://www.npmjs.com/"
PYPI_REGISTRY = "https://pypi.org/"
GITHUB_SITE = "https://github.com/"
ECOSYSTEMS = frozenset({"npm", "pypi", "github-actions"})

# Closed labels from the suspected-cause question. Unknown and free text stay out.
PUBLIC_CAUSES = {
    "compromised_publisher": "An existing publisher account appears to have been misused.",
    "malicious_new_dependency": "A newly added dependency carries the hostile behavior.",
    "typosquat_name": "The package name imitates a popular package.",
    "poisoned_install_script": "An install script or lifecycle hook was changed to run the behavior.",
}


@dataclass(frozen=True)
class PublicAlert:
    ecosystem: str
    name: str
    version: str
    previous_version: str
    registry_url: str
    behavior: str
    cause: str
    limited_review: bool
    first_seen_at: str

    @property
    def item_id(self) -> str:
        return f"{self.ecosystem}:{self.name}:{self.version}"


def _plain(value: object, limit: int) -> str:
    """Single-line text. Control characters in package names become spaces."""
    text = "".join(" " if ord(char) < 32 or ord(char) == 127 else char for char in str(value or ""))
    return " ".join(text.split())[:limit]


def public_registry_url(ecosystem: str, raw: object) -> str:
    """Keep a registry link only when it is the public npm or PyPI page for that ecosystem."""
    url = str(raw or "").strip()
    if not url or len(url) > 500:
        return ""
    if any(ord(char) <= 32 or ord(char) == 127 for char in url):
        return ""
    if ecosystem == "npm" and url.startswith(NPM_REGISTRY):
        return url
    if ecosystem == "pypi" and url.startswith(PYPI_REGISTRY):
        return url
    if ecosystem == "github-actions" and url.startswith(GITHUB_SITE):
        return url
    return ""


def _behavior(value: object) -> str:
    text = str(value or "")
    if text in FAMILY_CRITERIA and text != "none":
        return text
    return ""


def _cause(value: object) -> str:
    text = str(value or "")
    if text in PUBLIC_CAUSES:
        return text
    return ""


def public_alert_from_evidence(evidence: dict, *, when: datetime | None = None) -> PublicAlert | None:
    """Copy the public fields off an evidence dict. Everything else is ignored."""
    if not isinstance(evidence, dict):
        return None
    moment = when or utcnow()
    ecosystem = str(evidence.get("ecosystem") or "").strip().lower()
    if ecosystem not in ECOSYSTEMS:
        return None
    name = _plain(evidence.get("package"), limit=214)
    version = _plain(evidence.get("new_version"), limit=128)
    if not name or not version:
        return None
    return PublicAlert(
        ecosystem=ecosystem,
        name=name,
        version=version,
        previous_version=_plain(evidence.get("old_version"), limit=128),
        registry_url=public_registry_url(ecosystem, evidence.get("registry_url")),
        behavior=_behavior(evidence.get("attack_family")),
        cause=_cause(evidence.get("suspected_cause")),
        limited_review=bool(partial_read_reasons(evidence.get("signals"))),
        first_seen_at=iso(moment),
    )


def record_public_alert(db: Database, evidence: dict, *, when: datetime | None = None) -> bool:
    """Insert the public projection of a confirmed malicious release."""
    alert = public_alert_from_evidence(evidence, when=when)
    if alert is None:
        return False
    return db.insert_public_feed_item(
        ecosystem=alert.ecosystem,
        name=alert.name,
        version=alert.version,
        previous_version=alert.previous_version,
        registry_url=alert.registry_url,
        behavior=alert.behavior,
        cause=alert.cause,
        limited_review=alert.limited_review,
        first_seen_at=alert.first_seen_at,
    )


def alerts_from_rows(rows: object) -> list[PublicAlert]:
    """Drop stored rows that no longer match the public allowlist."""
    if not isinstance(rows, list):
        return []
    alerts: list[PublicAlert] = []
    for row in rows:
        try:
            ecosystem = str(row["ecosystem"] or "").strip().lower()
            name = _plain(row["name"], limit=214)
            version = _plain(row["version"], limit=128)
            seen = str(row["first_seen_at"] or "")
            datetime.strptime(seen, "%Y-%m-%dT%H:%M:%SZ")
        except (KeyError, TypeError, ValueError, IndexError):
            continue
        if ecosystem not in ECOSYSTEMS or not name or not version:
            continue
        alerts.append(
            PublicAlert(
                ecosystem=ecosystem,
                name=name,
                version=version,
                previous_version=_plain(row["previous_version"], limit=128),
                registry_url=public_registry_url(ecosystem, row["registry_url"]),
                behavior=_behavior(row["behavior"]),
                cause=_cause(row["cause"]),
                limited_review=bool(row["limited_review"]),
                first_seen_at=seen,
            )
        )
    return alerts


def ecosystem_label(ecosystem: str) -> str:
    if ecosystem == "pypi":
        return "PyPI"
    if ecosystem == "github-actions":
        return "GitHub Actions"
    return "npm"


def alert_title(alert: PublicAlert) -> str:
    if alert.ecosystem == "github-actions":
        return f"Malicious GitHub Action: {alert.name} {alert.version}"
    return f"Malicious {ecosystem_label(alert.ecosystem)} package: {alert.name} {alert.version}"


def alert_summary(alert: PublicAlert) -> str:
    if alert.ecosystem == "github-actions":
        tag, _sep, sha = alert.version.rpartition("@")
        parts = [f"GitHub Action {alert.name} tag {tag or alert.version} at commit {sha} was marked malicious."]
        if alert.previous_version:
            _old_tag, _sep, old_sha = alert.previous_version.rpartition("@")
            parts.append(f"Previous: {alert.previous_version}. Pin workflows to the previous commit ({old_sha}) or another reviewed sha.")
    else:
        parts = [
            f"{ecosystem_label(alert.ecosystem)} package {alert.name} {alert.version} was marked malicious."
        ]
        if alert.previous_version:
            parts.append(f"Previous version: {alert.previous_version}.")
    if alert.behavior:
        parts.append(f"Behavior: {FAMILY_CRITERIA[alert.behavior]}")
    if alert.cause:
        parts.append(f"Cause: {PUBLIC_CAUSES[alert.cause]}")
    if alert.limited_review:
        parts.append(LIMITED_REVIEW_TEXT)
    if alert.registry_url:
        parts.append(f"Registry: {alert.registry_url}")
    return " ".join(parts)


def alert_tags(alert: PublicAlert) -> list[str]:
    tags = [alert.ecosystem]
    if alert.behavior:
        tags.append(alert.behavior)
    if alert.cause:
        tags.append(alert.cause)
    return tags


def render_json_feed(rows: list, *, base_url: str, title: str) -> bytes:
    """JSON Feed 1.1. Item order is the order of ``rows``."""
    items = []
    for alert in alerts_from_rows(rows):
        item = {
            "id": alert.item_id,
            "title": alert_title(alert),
            "content_text": alert_summary(alert),
            "date_published": alert.first_seen_at,
            "tags": alert_tags(alert),
        }
        if alert.registry_url:
            item["url"] = alert.registry_url
        items.append(item)
    document = {
        "version": JSON_FEED_VERSION,
        "title": _plain(title, limit=200) or "Supply Chain Hunter alerts",
        "home_page_url": HOME_PAGE_URL,
        "feed_url": f"{base_url}/{FEED_JSON_KEY}",
        "description": FEED_DESCRIPTION,
        "authors": [{"name": AUTHOR_NAME}],
        "items": items,
    }
    return (json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _xml(value: str) -> str:
    return escape(value, {'"': "&quot;"})


def _rss_date(iso_text: str) -> str:
    moment = datetime.strptime(iso_text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return format_datetime(moment)


def render_rss(rows: list, *, base_url: str, title: str) -> bytes:
    """RSS 2.0. ``guid`` is the stable id, not a permalink."""
    alerts = alerts_from_rows(rows)
    safe_title = _plain(title, limit=200) or "Supply Chain Hunter alerts"
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">',
        "  <channel>",
        f"    <title>{_xml(safe_title)}</title>",
        f"    <link>{_xml(HOME_PAGE_URL)}</link>",
        f"    <description>{_xml(FEED_DESCRIPTION)}</description>",
        (
            "    <atom:link "
            f'href="{_xml(base_url + "/" + FEED_XML_KEY)}" '
            'rel="self" type="application/rss+xml"/>'
        ),
    ]
    if alerts:
        lines.append(f"    <lastBuildDate>{_xml(_rss_date(alerts[0].first_seen_at))}</lastBuildDate>")
    for alert in alerts:
        lines.append("    <item>")
        lines.append(f"      <title>{_xml(alert_title(alert))}</title>")
        if alert.registry_url:
            lines.append(f"      <link>{_xml(alert.registry_url)}</link>")
        lines.append(f'      <guid isPermaLink="false">{_xml(alert.item_id)}</guid>')
        lines.append(f"      <pubDate>{_xml(_rss_date(alert.first_seen_at))}</pubDate>")
        lines.append(f"      <description>{_xml(alert_summary(alert))}</description>")
        lines.append("    </item>")
    lines.extend(["  </channel>", "</rss>", ""])
    return "\n".join(lines).encode("utf-8")


def feed_digest(json_body: bytes, xml_body: bytes, base_url: str, cache_max_age: int) -> str:
    """Hash the public documents, their URL, and the cache lifetime.

    The cache lifetime is not inside the file bytes. Including it here means a
    change to ``HUNTER_FEED_CACHE_MAX_AGE`` is uploaded on the next pass.
    """
    digest = hashlib.sha256()
    digest.update(base_url.encode("utf-8"))
    digest.update(b"\0")
    digest.update(str(int(cache_max_age)).encode("utf-8"))
    digest.update(b"\0")
    digest.update(json_body)
    digest.update(b"\0")
    digest.update(xml_body)
    return digest.hexdigest()


def r2_endpoint(account_id: str) -> str:
    return f"https://{account_id}.r2.cloudflarestorage.com"


def make_r2_client(config: Config):
    """S3 client for the R2 bucket. ``region_name`` must be ``auto``."""
    import boto3

    return boto3.client(
        "s3",
        endpoint_url=r2_endpoint(config.feed_r2_account_id),
        aws_access_key_id=config.feed_r2_access_key_id,
        aws_secret_access_key=config.feed_r2_secret_access_key,
        region_name="auto",
    )


def allowed_public_object_key(key: str) -> bool:
    """Feed files plus public dashboard objects under ``live/``."""
    if key in PUBLIC_KEYS:
        return True
    return re.fullmatch(_LIVE_OBJECT, key) is not None


def put_feed_object(
    client,
    *,
    bucket: str,
    key: str,
    body: bytes,
    content_type: str,
    cache_control: str,
) -> None:
    """Upload one public bucket object. Any other key is refused."""
    if not allowed_public_object_key(key):
        raise ValueError("refusing to upload a non-public object")
    client.put_object(
        Bucket=bucket,
        Key=key,
        Body=body,
        ContentType=content_type,
        CacheControl=cache_control,
    )


def _public_error(exc: BaseException, config: Config) -> str:
    text = f"{type(exc).__name__}: {exc}"
    for secret in (
        config.feed_r2_secret_access_key,
        config.feed_r2_access_key_id,
        config.webhook_secret,
        config.webhook_url,
        config.dashboard_token,
        config.smart_api_key,
        config.analyst_api_key,
    ):
        if secret:
            text = text.replace(secret, "[redacted]")
    return " ".join(text.split())[:300]


def publish_public_feed(db: Database, config: Config, *, client=None) -> bool:
    """PUT both feed files when the rendered bytes changed.

    Returns True only after both uploads succeed. A failure leaves the stored
    hash alone so the next pass tries again. Publishing stays off until every
    required setting is present.
    """
    if not config.feed_configured():
        return False
    try:
        limit = config.feed_limit if isinstance(config.feed_limit, int) and config.feed_limit > 0 else 200
        rows = db.public_feed_items(limit)
        json_body = render_json_feed(rows, base_url=config.feed_public_base_url, title=config.feed_title)
        xml_body = render_rss(rows, base_url=config.feed_public_base_url, title=config.feed_title)
        digest = feed_digest(json_body, xml_body, config.feed_public_base_url, config.feed_cache_max_age)
        state = db.public_feed_state()
        if state is not None and state["content_hash"] == digest:
            return False
        uploader = client if client is not None else make_r2_client(config)
        cache_control = f"public, max-age={int(config.feed_cache_max_age)}"
        put_feed_object(
            uploader,
            bucket=config.feed_r2_bucket,
            key=FEED_JSON_KEY,
            body=json_body,
            content_type=JSON_CONTENT_TYPE,
            cache_control=cache_control,
        )
        put_feed_object(
            uploader,
            bucket=config.feed_r2_bucket,
            key=FEED_XML_KEY,
            body=xml_body,
            content_type=RSS_CONTENT_TYPE,
            cache_control=cache_control,
        )
        db.mark_public_feed_published(digest)
    except Exception as exc:
        message = _public_error(exc, config)
        log.warning("public feed upload failed: %s", message)
        try:
            db.mark_public_feed_error(message)
        except Exception:
            log.warning("public feed error could not be stored")
        return False
    log.info("public feed published")
    return True
