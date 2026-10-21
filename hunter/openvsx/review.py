"""Review one Open VSX extension release: download two ``.vsix`` files, rules first, then routing.

Called by ``service.classify_job`` for ``openvsx`` jobs. The rules read every
release. Scout reads it only when a rule hit and ``HUNTER_OPENVSX_SCOUT`` is on.
Nothing here alerts: a routed row goes to Triage, and only an Analyst-confirmed
verdict reaches the webhook and the public feed, as for npm and PyPI.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from hunter.archives import ArchiveError, DiskTree, aligned_release_trees, close_trees, extract_archive
from hunter.bands import REVIEW_THRESHOLD
from hunter.models import Classification, ReleaseMeta, RuleReport
from hunter.openvsx import ECOSYSTEM, UNIVERSAL, extension_url, pick_platform, split_name
from hunter.registry import PACKAGE_DOWNLOAD_MAX_BYTES, FeedError, HttpGet, fetch_capped, parse_time
from hunter.rules.engine import scan_release
from hunter.triage import changed_diffs

log = logging.getLogger("hunter.openvsx.review")

MODEL_ID = "deterministic"
STRONG_PROBABILITY = 0.55
MANIFEST = "extension/package.json"
# Each is one reason to read the release. Two of them, or one with a rule hit, route it to Triage.
MEDIUM = frozenset(
    {
        "vsx_extension_pack_added",
        "vsx_activation_widened",
        "vsx_main_changed",
        "vsx_publisher_changed",
    }
)
_ALIASES = {"latest", "pre-release", "prerelease"}
_EAGER_ACTIVATION = {"*", "onstartupfinished"}


def _json(blob: bytes) -> dict:
    data = json.loads(blob.decode("utf-8"))
    if not isinstance(data, dict):
        raise FeedError("Open VSX did not return a JSON object")
    if data.get("error"):
        raise FeedError(f"Open VSX: {str(data['error'])[:200]}")
    return data


def version_api_url(base: str, name: str, platform: str, version: str) -> str:
    namespace, extension = split_name(name)
    return f"{base.rstrip('/')}/api/{namespace}/{extension}/{platform}/{version}"


def predecessor(document: dict, version: str) -> str | None:
    """The version listed after ``version`` in ``allVersions`` (newest first), skipping aliases."""
    listed = [str(key) for key in (document.get("allVersions") or {}) if str(key).lower() not in _ALIASES]
    if version not in listed:
        return None
    index = listed.index(version)
    return listed[index + 1] if index + 1 < len(listed) else None


def _publisher(document: dict) -> frozenset[str]:
    person = document.get("publishedBy") or {}
    login = person.get("loginName") if isinstance(person, dict) else None
    return frozenset({str(login).strip().lower()}) if login and str(login).strip() else frozenset()


def _download_url(document: dict) -> str:
    url = str((document.get("files") or {}).get("download") or "").strip()
    if not url.startswith("https://"):
        raise ArchiveError("Open VSX version has no https download")
    return url


def _vsix_tree(transport: HttpGet, url: str) -> DiskTree:
    archive: Path = fetch_capped(transport, url, 120, PACKAGE_DOWNLOAD_MAX_BYTES)
    try:
        return extract_archive(archive)
    finally:
        archive.unlink(missing_ok=True)


def _manifest(files) -> dict:
    try:
        text = files[MANIFEST]
    except KeyError:
        return {}
    try:
        data = json.loads(text)
    except (TypeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _names(value) -> set[str]:
    if not isinstance(value, list):
        return set()
    return {str(item).strip().lower() for item in value if str(item).strip()}


def manifest_signals(old_files, new_files) -> list[str]:
    """Changes in ``extension/package.json`` that sleeper extensions use to turn hostile."""
    if not old_files:
        return []
    old = _manifest(old_files)
    new = _manifest(new_files)
    if not new:
        return []
    found: list[str] = []
    for key in ("extensionPack", "extensionDependencies"):
        if _names(new.get(key)) - _names(old.get(key)):
            found.append("vsx_extension_pack_added")
            break
    if (_names(new.get("activationEvents")) - _names(old.get("activationEvents"))) & _EAGER_ACTIVATION:
        found.append("vsx_activation_widened")
    if any(new.get(key) != old.get(key) for key in ("main", "browser")):
        found.append("vsx_main_changed")
    return found


def routes(signals: list[str], report: RuleReport | None) -> bool:
    """Send to Triage: a malicious rule verdict, two medium signals, or a rule hit with one."""
    medium = [sig for sig in signals if sig in MEDIUM]
    if report is not None and report.verdict == "malicious":
        return True
    if len(medium) >= 2:
        return True
    return bool(medium) and report is not None and bool(report.hits)


def _row(meta: ReleaseMeta, *, band: str, probability: float, signals: list[str]) -> Classification:
    return Classification(
        ecosystem=meta.ecosystem,
        name=meta.name,
        old_version=meta.old_version,
        new_version=meta.new_version,
        rank=meta.rank,
        registry_url=meta.registry_url,
        band=band,
        malice_probability=probability,
        jev_model_id=MODEL_ID,
        signals=signals,
    )


def review_trees(
    meta: ReleaseMeta,
    old_files,
    new_files,
    extra_signals: list[str],
    *,
    jev=None,
    popular_names: set[str] | None = None,
) -> Classification:
    """Rules and manifest signals on both trees; Scout only when given and a rule hit."""
    old_files, new_files = aligned_release_trees(
        old_files,
        new_files,
        ecosystem=meta.ecosystem,
        name=meta.name,
        old_version=meta.old_version,
        new_version=meta.new_version,
    )
    diffs = changed_diffs(old_files, new_files)
    try:
        report = scan_release(old_files, new_files, ecosystem=ECOSYSTEM, diffs=diffs)
    except Exception:
        log.exception("%s %s: rule scan failed", meta.name, meta.new_version)
        report = RuleReport(verdict="unsure", unscanned=[("", "unscanned:rule_error")])
    signals = list(dict.fromkeys(extra_signals + manifest_signals(old_files, new_files) + report.signals()))
    if jev is not None and (report.hits or report.verdict == "malicious"):
        from hunter.classify import classify_files

        scout = classify_files(
            meta=meta,
            old_files=old_files,
            new_files=new_files,
            jev=jev,
            popular_names=popular_names,
        )
        scout.signals = list(dict.fromkeys(signals + list(scout.signals)))
        if scout.band == "deferred" or scout.defer_reason:
            return scout
        if routes(scout.signals, report):
            scout.needs_llm_review = True
            if scout.band == "benign":
                scout.band = "review"
                scout.malice_probability = max(scout.malice_probability, REVIEW_THRESHOLD)
        return scout
    if routes(signals, report):
        strong = report.verdict == "malicious"
        row = _row(meta, band="review", probability=STRONG_PROBABILITY if strong else REVIEW_THRESHOLD, signals=signals)
        row.needs_llm_review = True
    else:
        row = _row(meta, band="benign", probability=0.05, signals=signals)
    row.rule_verdict = report.verdict
    row.rule_hits = report.hit_dicts()
    row.rule_pack = report.pack_version
    return row


def classify_extension(db, config, job, *, transport: HttpGet, jev=None):
    """Download, review and route one Open VSX job.

    Returns (result, old_files, new_files, meta). The trees are open DiskTrees
    (or None) that the caller closes after building Triage evidence.
    """
    name = str(job["name"])
    version = str(job["version"])
    rank = job["rank"]
    base = config.openvsx_url
    platforms = db.openvsx_platforms(name, version)
    platform = pick_platform(platforms) or UNIVERSAL
    meta = ReleaseMeta(
        ecosystem=ECOSYSTEM,
        name=name,
        new_version=version,
        old_version=None,
        rank=rank,
        registry_url=extension_url(base, name, version),
    )
    if platforms and all(state == "REMOVED" for state in platforms.values()):
        # Removed before Hunter read it. The removal is already recorded; there is nothing to download.
        return _row(meta, band="benign", probability=0.0, signals=["vsx_removed_before_review"]), None, None, meta
    document = _json(transport(version_api_url(base, name, platform, version), 60))
    previous = predecessor(document, version)
    old_document = _json(transport(version_api_url(base, name, platform, previous), 60)) if previous else {}
    meta = ReleaseMeta(
        ecosystem=ECOSYSTEM,
        name=name,
        new_version=version,
        old_version=previous,
        rank=rank,
        registry_url=meta.registry_url,
        old_publishers=_publisher(old_document),
        new_publishers=_publisher(document),
        old_time=parse_time(old_document.get("timestamp")),
        new_time=parse_time(document.get("timestamp")),
    )
    extra: list[str] = []
    if platform != UNIVERSAL:
        extra.append(f"vsx_platform:{platform}")
    if not previous:
        extra.append("vsx_first_version")
    if meta.old_publishers and meta.new_publishers and meta.old_publishers != meta.new_publishers:
        extra.append("vsx_publisher_changed")
    new_files = DiskTree.empty()
    old_files = DiskTree.empty()
    try:
        new_files = _vsix_tree(transport, _download_url(document))
        if previous:
            old_files = _vsix_tree(transport, _download_url(old_document))
        scout = jev if (jev is not None and getattr(config, "openvsx_scout", False)) else None
        result = review_trees(meta, old_files, new_files, extra, jev=scout)
    except Exception:
        close_trees(old_files, new_files)
        raise
    return result, old_files, new_files, meta
