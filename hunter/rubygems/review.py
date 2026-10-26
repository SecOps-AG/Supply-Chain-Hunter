"""Review one RubyGems release: download two ``.gem`` files, rules first, then routing.

Called by ``service.classify_job`` for ``rubygems`` jobs. The rules read every
release. Scout reads it only when a rule hit and ``HUNTER_RUBYGEMS_SCOUT`` is on.
Nothing here alerts: a routed row goes to Triage, and only an Analyst-confirmed
verdict reaches the webhook and the public feed, as for npm and PyPI.

Nothing in the gem is installed or run.
"""

from __future__ import annotations

import json
import logging
import re
from urllib.parse import quote

from hunter.archives import ArchiveError, DiskTree, aligned_release_trees, close_trees
from hunter.bands import REVIEW_THRESHOLD
from hunter.models import Classification, ReleaseMeta, RuleReport
from hunter.registry import PACKAGE_DOWNLOAD_MAX_BYTES, FeedError, HttpGet, fetch_capped, http_get, parse_time
from hunter.rubygems import ECOSYSTEM, allowed_gem_url, registry_url, valid_name, valid_version
from hunter.rubygems.archive import extract_gem
from hunter.rules.engine import scan_release
from hunter.triage import changed_diffs

log = logging.getLogger("hunter.rubygems.review")

MODEL_ID = "deterministic"
STRONG_PROBABILITY = 0.55
ROUTE_RULES = frozenset({"rb_eval_fetch", "rb_extconf_fetch"})
_NORMAL_EXTCONF = re.compile(r"^ext(?:/[^/]+)*/extconf\.rb$")
_CURL = "curl"
_WGET = "wget"
_GEM_INSTALL = "gem install"


def _json_list(blob: bytes, label: str) -> list:
    data = json.loads(blob.decode("utf-8"))
    if isinstance(data, dict):
        raise FeedError(f"RubyGems {label}: {str(data.get('error') or 'not a list')[:200]}")
    if not isinstance(data, list):
        raise FeedError(f"RubyGems {label} is not a list")
    return data


def _number(row: dict | None) -> str:
    if not isinstance(row, dict):
        return ""
    return str(row.get("number") or row.get("version") or "").strip()


def _ruby_rows(rows: list) -> list[dict]:
    found = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if str(row.get("platform") or "ruby").strip() != "ruby":
            continue
        if not _number(row):
            continue
        found.append(row)
    return found


def _yanked(row: dict) -> bool:
    return row.get("yanked") in (True, 1, "true", "True", "yes")


def predecessor_row(rows: list, version: str) -> dict | None:
    """Newest older non-yanked ruby row. ``rows`` is newest first, as the versions API returns it."""
    seen = False
    for row in _ruby_rows(rows):
        number = _number(row)
        if number == version:
            seen = True
            continue
        if not seen or _yanked(row):
            continue
        return row
    return None


def gem_download_url(name: str, version: str, row: dict | None) -> str:
    """``gem_uri`` when it is a rubygems.org gem URL, otherwise the canonical ``/gems/`` URL.

    A ``gem_uri`` on any other host is refused and not downloaded.
    """
    if not valid_name(name) or not valid_version(version):
        raise ArchiveError("gem name or version is not safe to download")
    raw = str((row or {}).get("gem_uri") or "").strip()
    if raw:
        if not allowed_gem_url(raw):
            raise ArchiveError("gem URL is not a rubygems.org download")
        return raw
    url = f"https://rubygems.org/gems/{name}-{version}.gem"
    if not allowed_gem_url(url):
        raise ArchiveError("gem URL is not a rubygems.org download")
    return url


def _download(transport: HttpGet, url: str) -> tuple[DiskTree, dict]:
    if not allowed_gem_url(url):
        raise ArchiveError("gem URL is not a rubygems.org download")
    archive = fetch_capped(transport, url, 120, PACKAGE_DOWNLOAD_MAX_BYTES)
    try:
        return extract_gem(archive)
    finally:
        archive.unlink(missing_ok=True)


def _version_list(base: str, name: str, transport: HttpGet) -> list:
    if not valid_name(name):
        raise FeedError("gem name is not safe to request")
    url = f"{base.rstrip('/')}/api/v1/versions/{quote(name, safe='')}.json"
    return _json_list(transport(url, 60), "versions")


def _ruby_row(rows: list, version: str) -> dict | None:
    for row in _ruby_rows(rows):
        if _number(row) == version:
            return row
    return None


def _message(spec: dict) -> str:
    if not isinstance(spec, dict):
        return ""
    value = spec.get("post_install_message")
    return value if isinstance(value, str) else ""


def extension_paths(spec: dict) -> list[str]:
    if not isinstance(spec, dict):
        return []
    raw = spec.get("extensions")
    if isinstance(raw, str):
        raw = [raw] if raw.strip() else []
    if not isinstance(raw, list):
        return []
    found = []
    for item in raw:
        text = str(item).strip().replace("\\", "/")
        while text.startswith("./"):
            text = text[2:]
        if text:
            found.append(text)
    return found


def _normal_extconf(path: str) -> bool:
    if path.startswith("/") or ".." in path.split("/"):
        return False
    return _NORMAL_EXTCONF.fullmatch(path) is not None


def _shell_terms(text: str) -> set[str]:
    lowered = (text or "").lower()
    found = set()
    if _CURL in lowered:
        found.add(_CURL)
    if _WGET in lowered:
        found.add(_WGET)
    if re.search(r"\|\s*sh\b", lowered):
        found.add("pipe")
    if _GEM_INSTALL in lowered:
        found.add(_GEM_INSTALL)
    return found


def spec_signals(old_spec: dict, new_spec: dict) -> list[str]:
    """Install-hook changes. A normal new ``ext/**/extconf.rb`` is recorded and does not route."""
    found: list[str] = []
    old_paths = set(extension_paths(old_spec))
    added_bad = False
    for path in extension_paths(new_spec):
        if path in old_paths:
            continue
        found.append(f"gem_extension:{path}")
        if not _normal_extconf(path):
            added_bad = True
    if added_bad:
        found.append("gem_extension_added")
    if _shell_terms(_message(new_spec)) - _shell_terms(_message(old_spec)):
        found.append("gem_post_install_shell")
    return found


def routes(signals: list[str], report: RuleReport | None) -> bool:
    """Send to Triage only for a remote eval, a fetching extension, a stray extension path, or a shell post-install."""
    if "gem_extension_added" in signals or "gem_post_install_shell" in signals:
        return True
    if report is None:
        return False
    return bool({hit.rule for hit in report.hits} & ROUTE_RULES)


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
    old_spec: dict,
    new_spec: dict,
    *,
    jev=None,
    popular_names: set[str] | None = None,
) -> Classification:
    """Rules and spec signals on both trees. Scout only when given and a rule hit."""
    extra = spec_signals(old_spec if isinstance(old_spec, dict) else {}, new_spec if isinstance(new_spec, dict) else {})
    hooks = extension_paths(old_spec) + extension_paths(new_spec)
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
        report = scan_release(old_files, new_files, ecosystem=ECOSYSTEM, diffs=diffs, hook_paths=hooks)
    except Exception:
        log.exception("%s %s: rule scan failed", meta.name, meta.new_version)
        report = RuleReport(verdict="unsure", unscanned=[("", "unscanned:rule_error")])
    signals = list(dict.fromkeys(extra + report.signals()))
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
        row = _row(
            meta,
            band="review",
            probability=STRONG_PROBABILITY if strong else REVIEW_THRESHOLD,
            signals=signals,
        )
        row.needs_llm_review = True
    else:
        row = _row(meta, band="benign", probability=0.05, signals=signals)
    row.rule_verdict = report.verdict
    row.rule_hits = report.hit_dicts()
    row.rule_pack = report.pack_version
    return row


def open_release(config, name: str, version: str, rank, *, previous: str | None, transport: HttpGet):
    """Download the named version and its predecessor (or ``previous`` when given).

    Returns (old_files, new_files, meta, old_spec, new_spec). The caller closes the trees.
    """
    if not valid_name(name) or not valid_version(version):
        raise ArchiveError("gem name or version is not safe to download")
    if previous is not None and not valid_version(previous):
        raise ArchiveError("gem name or version is not safe to download")
    rows = _version_list(config.rubygems_url, name, transport)
    old_row = None
    if previous is None:
        old_row = predecessor_row(rows, version)
        previous = _number(old_row) or None
    else:
        old_row = _ruby_row(rows, previous)
    new_row = _ruby_row(rows, version)
    new_files = DiskTree.empty()
    old_files = DiskTree.empty()
    try:
        new_files, new_spec = _download(transport, gem_download_url(name, version, new_row))
        old_spec: dict = {}
        if previous:
            old_files, old_spec = _download(transport, gem_download_url(name, previous, old_row))
        meta = ReleaseMeta(
            ecosystem=ECOSYSTEM,
            name=name,
            new_version=version,
            old_version=previous,
            rank=rank,
            registry_url=registry_url(name, version),
            old_time=parse_time((old_row or {}).get("created_at") or (old_row or {}).get("version_created_at")),
            new_time=parse_time((new_row or {}).get("created_at") or (new_row or {}).get("version_created_at")),
        )
        return old_files, new_files, meta, old_spec, new_spec
    except Exception:
        close_trees(old_files, new_files)
        raise


def load_gem_release(config, name: str, version: str, rank, *, previous: str | None, transport: HttpGet):
    """The two trees and release meta. Used by ``ReleaseLoader``."""
    old_files, new_files, meta, _old_spec, _new_spec = open_release(
        config, name, version, rank, previous=previous, transport=transport
    )
    return old_files, new_files, meta


def score_versions(config, name: str, old: str, new: str, *, transport: HttpGet = http_get, jev=None):
    """Score two named versions without the poller. Scout runs only when ``jev`` is passed."""
    old_files = DiskTree.empty()
    new_files = DiskTree.empty()
    try:
        old_files, new_files, meta, old_spec, new_spec = open_release(
            config, name, new, None, previous=old, transport=transport
        )
        return review_trees(meta, old_files, new_files, old_spec, new_spec, jev=jev)
    finally:
        close_trees(old_files, new_files)


def classify_gem(db, config, job, *, transport: HttpGet, jev=None):
    """Download, review and route one RubyGems job.

    Returns (result, old_files, new_files, meta). The trees stay open for the caller.
    ``db`` is unused; the job is the whole identity. Scout is the caller's choice.
    """
    del db
    name = str(job["name"])
    version = str(job["version"])
    rank = job["rank"]
    new_files = DiskTree.empty()
    old_files = DiskTree.empty()
    try:
        old_files, new_files, meta, old_spec, new_spec = open_release(
            config, name, version, rank, previous=None, transport=transport
        )
        scout = jev if (jev is not None and getattr(config, "rubygems_scout", False)) else None
        result = review_trees(meta, old_files, new_files, old_spec, new_spec, jev=scout)
    except Exception:
        close_trees(old_files, new_files)
        raise
    return result, old_files, new_files, meta
