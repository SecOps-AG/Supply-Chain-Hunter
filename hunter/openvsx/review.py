"""Review one Open VSX extension release: download two ``.vsix`` files, rules first, then routing.

Called by ``service.classify_job`` for ``openvsx`` jobs. The rules read every
release. A new ``extensionPack`` or ``extensionDependencies`` id routes to
Triage on its own. Scout reads a release only when ``HUNTER_OPENVSX_SCOUT`` is
on and the rule verdict is malicious or a rule hit comes with a manifest change.
``INACTIVE`` is the unpublished state: when every recorded platform is inactive,
nothing is downloaded. Nothing here alerts: a routed row goes to Triage, and
only an Analyst-confirmed verdict reaches the webhook and the public feed, as
for npm and PyPI.
"""

from __future__ import annotations

import json
import logging
import posixpath
from pathlib import Path
from urllib.parse import quote

from hunter.archives import ArchiveError, DiskTree, aligned_release_trees, close_trees, extract_archive
from hunter.bands import REVIEW_THRESHOLD
from hunter.models import Classification, ReleaseMeta, RuleReport
from hunter.openvsx import (
    ECOSYSTEM,
    PLATFORM_ORDER,
    UNIVERSAL,
    extension_url,
    pick_platform,
    release_name,
    split_name,
)
from hunter.registry import PACKAGE_DOWNLOAD_MAX_BYTES, FeedError, HttpGet, fetch_capped, parse_time
from hunter.rules.engine import scan_release
from hunter.triage import changed_diffs

log = logging.getLogger("hunter.openvsx.review")

MODEL_ID = "deterministic"
STRONG_PROBABILITY = 0.55
MANIFEST = "extension/package.json"
# Activation, entry point, and publisher count one each. Two of them route to Triage.
# A new extension pack routes on its own. ``vsx_pulls:`` ids stay out of this set.
# A rule hit with one of these lets Scout read the release.
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
_JS_SUFFIXES = {"", ".js", ".cjs", ".mjs"}
_INACTIVE_STATES = {"INACTIVE", "UNPUBLISHED"}
# Informational pack ids recorded on the host review. The pulled extension is not downloaded here.
PULL_CAP = 20


def _json(blob: bytes) -> dict:
    data = json.loads(blob.decode("utf-8"))
    if not isinstance(data, dict):
        raise FeedError("Open VSX did not return a JSON object")
    if data.get("error"):
        raise FeedError(f"Open VSX: {str(data['error'])[:200]}")
    return data


def version_api_url(base: str, name: str, platform: str, version: str) -> str:
    namespace, extension = split_name(name)
    return f"{base.rstrip('/')}/api/{namespace}/{extension}/{platform}/{quote(version, safe='')}"


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


def _listed(value) -> list[str]:
    """Manifest id list, lowercased, in the order written, without duplicates."""
    if not isinstance(value, list):
        return []
    found: list[str] = []
    seen: set[str] = set()
    for item in value:
        text = str(item).strip().lower()
        if text and text not in seen:
            seen.add(text)
            found.append(text)
    return found


def _pull_signal(item: str) -> str | None:
    """``vsx_pulls:namespace.extension`` when ``release_name`` accepts the id, else None."""
    if "/" in item or ".." in item:
        return None
    namespace, sep, extension = item.partition(".")
    if not sep:
        return None
    accepted = release_name(namespace, extension)
    if accepted is None:
        return None
    return f"vsx_pulls:{accepted}"


def _bundled_js(value) -> bool:
    """A relative JavaScript path inside the extension, such as ``./out/extension.js``."""
    if not isinstance(value, str) or not value.strip() or "\\" in value or ":" in value:
        return False
    path = posixpath.normpath(value.strip())
    if path.startswith("/") or path == ".." or path.startswith("../"):
        return False
    return posixpath.splitext(path)[1].lower() in _JS_SUFFIXES


def manifest_signals(old_files, new_files) -> list[str]:
    """Changes in ``extension/package.json`` that sleeper extensions use to turn hostile.

    A new pack or dependency id is compared with an empty set on a first publish.
    Activation and entry-point checks need the previous manifest.
    """
    new = _manifest(new_files) if new_files else {}
    if not new:
        return []
    old = _manifest(old_files) if old_files else {}
    found: list[str] = []
    added: list[str] = []
    seen: set[str] = set()
    for key in ("extensionPack", "extensionDependencies"):
        previous = set(_listed(old.get(key)))
        for item in _listed(new.get(key)):
            if item in previous or item in seen:
                continue
            seen.add(item)
            added.append(item)
    if added:
        found.append("vsx_extension_pack_added")
        pulls = 0
        for item in added:
            signal = _pull_signal(item)
            if signal is None or signal in found:
                continue
            found.append(signal)
            pulls += 1
            if pulls >= PULL_CAP:
                break
    if not old_files or MANIFEST not in old_files:
        return found
    if (_names(new.get("activationEvents")) - _names(old.get("activationEvents"))) & _EAGER_ACTIVATION:
        found.append("vsx_activation_widened")
    moved = [key for key in ("main", "browser") if new.get(key) != old.get(key)]
    if moved:
        # A bundler move (``./out/extension.js`` -> ``./dist/extension.js``) is routine; a new entry point is not.
        routine = all(_bundled_js(old.get(key)) and (key not in new or _bundled_js(new.get(key))) for key in moved)
        found.append("vsx_main_moved" if routine else "vsx_main_changed")
    return found


def routes(signals: list[str], report: RuleReport | None) -> bool:
    """Send to Triage: a malicious verdict, a new extension pack, or two other medium signals.

    Weak rule hits alone never do. ``vsx_pulls:`` ids do not count.
    """
    if report is not None and report.verdict == "malicious":
        return True
    if "vsx_extension_pack_added" in signals:
        return True
    return sum(1 for sig in signals if sig in MEDIUM and sig != "vsx_extension_pack_added") >= 2


def scout_reads(signals: list[str], report: RuleReport) -> bool:
    """Scout reads a malicious rule verdict, or a rule hit that comes with a medium signal."""
    if report.verdict == "malicious":
        return True
    return bool(report.hits) and any(sig in MEDIUM for sig in signals)


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
    """Rules and manifest signals on both trees; Scout only when given and ``scout_reads`` allows it."""
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
    if jev is not None and scout_reads(signals, report):
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


def _old_document(transport: HttpGet, base: str, name: str, version: str, platforms: dict[str, str], new_platform: str):
    """The predecessor's metadata. Its build can differ from the new one (universal <-> per-platform).

    Recorded platforms are tried before the usual list, including ones that are no longer active.
    """
    first = new_platform if platforms.get(new_platform) == "ACTIVE" else pick_platform(platforms)
    stored = [platform for platform in platforms if platform]
    error: FeedError | None = None
    for platform in dict.fromkeys([first or new_platform, new_platform, *stored, *PLATFORM_ORDER]):
        try:
            return _json(transport(version_api_url(base, name, platform, version), 60))
        except FeedError as exc:
            error = exc
    raise error


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
    if platforms and all(state in _INACTIVE_STATES for state in platforms.values()):
        # Unpublished before Hunter read it. The files stay on the registry; this review does not fetch them.
        return _row(meta, band="benign", probability=0.0, signals=["vsx_inactive_before_review"]), None, None, meta
    document = _json(transport(version_api_url(base, name, platform, version), 60))
    previous = predecessor(document, version)
    old_document = (
        _old_document(transport, base, name, previous, db.openvsx_platforms(name, previous), platform) if previous else {}
    )
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
