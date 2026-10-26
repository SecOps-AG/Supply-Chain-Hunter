"""Polling loop, worker pool, health endpoint, and shutdown."""

from __future__ import annotations

import hmac
import http.client
import json
import logging
import signal
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit

from hunter import JEV_MODEL_ID
from hunter.actions import ECOSYSTEM as ACTIONS_ECOSYSTEM
from hunter.actions.github import GitHubClient, RateLimited
from hunter.actions.poller import poll_actions
from hunter.actions.review import MODEL_ID as ACTIONS_RULES_MODEL, classify_action
from hunter.actions.watchlist import probe_ecosyste, refresh_actions_watchlist
from hunter.mcp_registry import POLL_NAME as MCP_POLL_NAME, poll_mcp_registry
from hunter.openvsx import ECOSYSTEM as OPENVSX_ECOSYSTEM
from hunter.openvsx.feed import poll_openvsx
from hunter.openvsx.review import classify_extension
from hunter.rubygems import ECOSYSTEM as RUBYGEMS_ECOSYSTEM
from hunter.rubygems.feed import CHECKPOINT as RUBYGEMS_CHECKPOINT
from hunter.rubygems.feed import QUEUED_KEY as RUBYGEMS_QUEUED
from hunter.rubygems.feed import poll_rubygems
from hunter.rubygems.review import classify_gem, load_gem_release
from hunter.crates import ECOSYSTEM as CRATES_ECOSYSTEM
from hunter.crates.feed import poll_crates
from hunter.crates.review import classify_crate, load_crate_trees
from hunter.archives import (
    ArchiveError,
    DiskTree,
    aligned_release_trees,
    close_trees,
    extract_archive,
    unpack_file,
)
from hunter.children import apply_children, inspect_children
from hunter.classify import MODEL_DOWN_SIGNAL, classification_incomplete, classify_files, decision_model_failed
from hunter.features import phantom_runtime_dependencies
from hunter.investigate import (
    drain_investigations,
    drain_analyst,
    enqueue_investigation,
    excerpt_for,
    should_investigate,
    triage_evidence_parts,
    warn_analyst_config,
    warn_smart_config,
)
from hunter.scout_lessons import scout_lesson_suppresses
from hunter.scout_model import DEFAULT_SCOUT_MODEL, make_scout_model, require_scoring_layer
from hunter.spend import SpendMeter
from hunter.config import Config, active_role_models, smart_analysis_enabled
from hunter.db import Database, iso, utcnow
from hunter.jev import JevUnavailable
from hunter.models import Classification, ReleaseMeta
from hunter.logging_setup import configure_logging
from hunter.registry import (
    PACKAGE_DOWNLOAD_MAX_BYTES,
    DownloadTooLarge,
    FeedError,
    HttpGet,
    fetch_npm_changes_head,
    PypiSerialFeed,
    bootstrap_npm,
    choose_pypi_artifacts,
    fetch_capped,
    http_get,
    max_serial,
    page_npm_changes,
    predecessor_version,
    publishers_npm,
    publishers_pypi,
    publishers_pypi_files,
    pypi_events_to_versions,
    newest_version,
    pypi_predecessor,
    pypi_version_events,
    refresh_watchlists,
    versions_after,
)
from hunter.mcp_risk import score_pending_jobs as score_mcp_jobs
from hunter.takeover import score_pending_jobs
from hunter.typosquat import TYPOSQUAT_QUEUE_LIMIT, NameIndex, typosquat_pairs
from hunter.registry import parse_time
from hunter.public_feed import publish_public_feed
from hunter.webhook import build_payload, drain_outbox, dump_body, enqueue_decision_model_down

log = logging.getLogger("hunter.service")

_dash_publisher = None
# Latest ecosyste.ms probe. /health reads it; the probe never runs inside /health.
_ecosyste_probe: dict[str, object] = {"ok": False, "checked_at": None, "error": None}
_ecosyste_lock = threading.Lock()


def ecosyste_probe_state() -> dict[str, object]:
    with _ecosyste_lock:
        return dict(_ecosyste_probe)


def _store_ecosyste_probe(result: dict[str, object]) -> None:
    with _ecosyste_lock:
        _ecosyste_probe.clear()
        _ecosyste_probe.update(result)


def _short_probe_error(exc: BaseException) -> str:
    text = str(exc).strip() or exc.__class__.__name__
    return " ".join(text.split())[:200]


def check_ecosyste(config: Config, transport: HttpGet = http_get) -> dict[str, object]:
    """Probe ecosyste.ms and store the result for /health.

    A failure is logged and stored. It does not raise and it does not stop serve.
    """
    try:
        result = probe_ecosyste(config, transport)
    except Exception as exc:
        log.warning("ecosyste.ms actions probe failed: %s", exc)
        result = {"ok": False, "checked_at": iso(utcnow()), "error": _short_probe_error(exc)}
    else:
        if not result.get("ok"):
            log.warning("ecosyste.ms actions probe failed: %s", result.get("error"))
    _store_ecosyste_probe(result)
    return result


def _json(blob: bytes) -> dict:
    return json.loads(blob.decode())


class ReleaseLoader:
    """Download two versions and return their text trees. Archives are not executed."""

    def __init__(self, config: Config, transport: HttpGet = http_get):
        self.config = config
        self.transport = transport
        # GitHub Actions jobs read tags and tarballs through this client.
        self.github = GitHubClient(getattr(config, "github_token", ""))

    def load(self, ecosystem: str, name: str, version: str, rank: int | None):
        if ecosystem == "pypi":
            return self._pypi(name, version, rank, previous=None)
        if ecosystem == "rubygems":
            return self._rubygems(name, version, rank, previous=None)
        if ecosystem == CRATES_ECOSYSTEM:
            return load_crate_trees(self.config, self.transport, name, version, rank, None)
        return self._npm(name, version, rank, previous=None)

    def load_versions(self, ecosystem: str, name: str, old: str, new: str):
        """Fetch two named versions. Used by `hunter score`, which picks both sides."""
        if ecosystem == "pypi":
            return self._pypi(name, new, None, previous=old)
        if ecosystem == "rubygems":
            return self._rubygems(name, new, None, previous=old)
        if ecosystem == CRATES_ECOSYSTEM:
            return load_crate_trees(self.config, self.transport, name, new, None, old or None)
        return self._npm(name, new, None, previous=old)

    def _rubygems(self, name: str, version: str, rank: int | None, previous: str | None):
        return load_gem_release(self.config, name, version, rank, previous=previous, transport=self.transport)

    def _package_file(self, url: str, timeout: float) -> Path:
        return fetch_capped(self.transport, url, timeout, PACKAGE_DOWNLOAD_MAX_BYTES)

    def _pypi_trees(self, files: list) -> DiskTree:
        """Extract sdist and wheel under one directory. File text stays on disk."""
        artifacts = choose_pypi_artifacts(files)
        if not artifacts:
            return DiskTree.empty()
        owner = tempfile.TemporaryDirectory(prefix="hunter-release-")
        root = Path(owner.name)
        try:
            for kind, chosen in artifacts:
                archive = self._package_file(str(chosen["url"]), 90)
                try:
                    unpack_file(archive, root / kind)
                finally:
                    archive.unlink(missing_ok=True)
            if len(artifacts) > 1:
                log.info("diffed %s", " and ".join(kind for kind, _item in artifacts))
            tree = DiskTree(root, own=owner)
            owner = None
            return tree
        finally:
            if owner is not None:
                owner.cleanup()

    def _pypi(self, name: str, version: str, rank: int | None, previous: str | None):
        document = _json(self.transport(f"{self.config.pypi_base}/{quote(name)}/json", 60))
        releases = document.get("releases") or {}
        new_files = DiskTree.empty()
        old_files = DiskTree.empty()
        try:
            new_files = self._pypi_trees(releases.get(version) or [])
            if not new_files:
                raise ArchiveError(f"no archive for {name} {version}")
            resolved = previous if previous is not None else pypi_predecessor(document, version)
            if resolved:
                old_files = self._pypi_trees(releases.get(resolved) or [])
                if previous is not None and not old_files:
                    raise ArchiveError(f"no archive for {name} {resolved}")
            info = document.get("info") or {}
            old_named = publishers_pypi_files(releases.get(resolved) or []) if resolved else frozenset()
            new_named = publishers_pypi_files(releases.get(version) or [])
            if old_named and new_named:
                old_publishers, new_publishers = old_named, new_named
            else:
                # One side, or both, omitted a per-version publisher. Keep the
                # old set empty so an unknown predecessor is not a change.
                old_publishers = frozenset()
                new_publishers = (old_named or new_named) or publishers_pypi(info)
            meta = ReleaseMeta(
                ecosystem="pypi",
                name=name,
                new_version=version,
                old_version=resolved,
                rank=rank,
                registry_url=f"https://pypi.org/project/{name}/{version}/",
                old_publishers=old_publishers,
                new_publishers=new_publishers,
                old_time=_pypi_time(document, resolved),
                new_time=_pypi_time(document, version),
            )
            return old_files, new_files, meta
        except Exception:
            close_trees(old_files, new_files)
            raise

    def _npm(self, name: str, version: str, rank: int | None, previous: str | None):
        document = _json(self.transport(f"{self.config.npm_registry}/{quote(name)}", 60))
        versions = document.get("versions") or {}
        current = versions.get(version) or {}
        tarball = (current.get("dist") or {}).get("tarball")
        new_files = DiskTree.empty()
        old_files = DiskTree.empty()
        try:
            if not tarball:
                raise ArchiveError(f"no tarball for {name} {version}")
            new_archive = self._package_file(str(tarball), 90)
            try:
                new_files = extract_archive(new_archive)
            finally:
                new_archive.unlink(missing_ok=True)
            resolved = previous if previous is not None else predecessor_version(document, version)
            if resolved:
                earlier = (versions.get(resolved) or {}).get("dist") or {}
                if earlier.get("tarball"):
                    old_archive = self._package_file(str(earlier["tarball"]), 90)
                    try:
                        old_files = extract_archive(old_archive)
                    finally:
                        old_archive.unlink(missing_ok=True)
                elif previous is not None:
                    raise ArchiveError(f"no tarball for {name} {resolved}")
            meta = ReleaseMeta(
                ecosystem="npm",
                name=name,
                new_version=version,
                old_version=resolved,
                rank=rank,
                registry_url=f"https://www.npmjs.com/package/{name}/v/{version}",
                old_publishers=publishers_npm(versions.get(resolved) or {}) if resolved else frozenset(),
                new_publishers=publishers_npm(current),
                old_time=parse_time((document.get("time") or {}).get(resolved or "")),
                new_time=parse_time((document.get("time") or {}).get(version)),
            )
            return old_files, new_files, meta
        except Exception:
            close_trees(old_files, new_files)
            raise


def _pypi_time(project: dict, version: str | None) -> datetime | None:
    if not version:
        return None
    files = (project.get("releases") or {}).get(version) or []
    if not files:
        return None
    return parse_time(files[0].get("upload_time_iso_8601"))


def _failure(ecosystem: str, name: str, version: str, rank: int | None, reason: str) -> Classification:
    return Classification(
        ecosystem=ecosystem,
        name=name,
        old_version=None,
        new_version=version,
        rank=rank,
        registry_url="",
        band="deferred",
        malice_probability=0.0,
        jev_model_id=JEV_MODEL_ID,
        signals=["ai_incomplete", "jev_retry", reason[:180]],
        defer_reason="load_failed",
        needs_llm_review=False,
    )


def _release_needs_retry(row) -> bool:
    if row is None:
        return False
    if str(row["band"] or "") == "deferred":
        return True
    payload = row["payload_json"] or ""
    return "ai_incomplete" in payload or "jev_retry" in payload


def _download_failure(exc: BaseException) -> bool:
    """True when the release body never arrived intact.

    `http_get` turns `URLError` into `FeedError`. Timeouts and resets raised
    from `response.read` stay `OSError`. `IncompleteRead` is an `HTTPException`
    and is not an `OSError`.
    """
    if isinstance(exc, (http.client.HTTPException, DownloadTooLarge)):
        return True
    if isinstance(exc, (TimeoutError, ConnectionError, BrokenPipeError)):
        return True
    return type(exc) is FeedError


def _retry_reason(result: Classification) -> str:
    if result.defer_reason:
        return result.defer_reason
    for signal in result.signals:
        if signal not in {"ai_incomplete", "jev_retry"} and (
            signal.startswith("jev_") or signal in {"pass_d_not_run", "gateway_503", "max_tokens", "load_failed"}
        ):
            return signal
    return "ai_incomplete"


def classify_observed(
    meta,
    old_files,
    new_files,
    *,
    jev,
    config: Config,
    transport: HttpGet,
    popular_names: set[str] | None = None,
):
    old_files, new_files = aligned_release_trees(
        old_files,
        new_files,
        ecosystem=meta.ecosystem,
        name=meta.name,
        old_version=meta.old_version,
        new_version=meta.new_version,
    )
    result = classify_files(
        meta=meta,
        old_files=old_files,
        new_files=new_files,
        jev=jev,
        popular_names=popular_names,
    )
    names = phantom_runtime_dependencies(old_files, new_files)
    if names and config.inspect_dependencies and meta.ecosystem == "npm":
        findings = inspect_children(
            meta,
            new_files,
            names,
            jev=jev,
            transport=transport,
            registry=config.npm_registry,
            limit=config.dep_inspect_limit,
        )
        result = apply_children(result, findings)
    if result.band in {"alert", "review"} and not classification_incomplete(result):
        result.needs_llm_review = True
    return result, excerpt_for(old_files, new_files, meta)


def classify_action_job(
    db: Database,
    config: Config,
    job,
    *,
    jev,
    loader: ReleaseLoader,
    transport: HttpGet = http_get,
) -> None:
    """One GitHub Actions tag event: signals, rules, and Triage when the signals or rules ask for it."""
    client = getattr(loader, "github", None) or GitHubClient(config.github_token)

    def _review():
        return classify_action(db, config, job, client=client, transport=transport, jev=jev)

    _classify_reviewed_job(db, config, job, review=_review)


def classify_rubygems_job(
    db: Database,
    config: Config,
    job,
    *,
    jev,
    loader: ReleaseLoader,
    transport: HttpGet = http_get,
) -> None:
    """One RubyGems release: rules first, Scout on rule hits when allowed, then Triage routing."""
    del loader

    def _review():
        return classify_gem(db, config, job, transport=transport, jev=jev)

    _classify_reviewed_job(db, config, job, review=_review)


def classify_openvsx_job(
    db: Database,
    config: Config,
    job,
    *,
    jev,
    loader: ReleaseLoader,
    transport: HttpGet = http_get,
) -> None:
    """One Open VSX extension release: rules first, Scout when allowed, then Triage routing."""

    def _review():
        return classify_extension(db, config, job, transport=transport, jev=jev)

    _classify_reviewed_job(db, config, job, review=_review)


def classify_crate_job(
    db: Database,
    config: Config,
    job,
    *,
    jev,
    loader: ReleaseLoader,
    transport: HttpGet = http_get,
) -> None:
    """One crates.io release: rules on every release, Scout only on a weak hit when allowed."""

    def _review():
        return classify_crate(db, config, job, transport=transport, jev=jev)

    _classify_reviewed_job(db, config, job, review=_review)


def _classify_reviewed_job(db: Database, config: Config, job, *, review) -> None:
    """Save the row a deterministic review returns, then queue Triage when it asks for it.

    ``review`` returns (result, old_files, new_files, meta), as ``classify_action`` does.
    """
    ecosystem = str(job["ecosystem"])
    name = str(job["name"])
    version = str(job["version"])
    rank = job["rank"]
    existing = db.get_release(ecosystem, name, version)
    if existing is not None and not _release_needs_retry(existing):
        db.finish_job(ecosystem, name, version)
        db.clear_classify_retry(ecosystem, name, version)
        return
    excerpt = ""
    manifest = ""
    full_diff = ""
    old_files = None
    new_files = None
    try:
        try:
            result, old_files, new_files, meta = review()
            if result.needs_llm_review and new_files is not None:
                excerpt, manifest, full_diff = triage_evidence_parts(old_files, new_files, meta)
        except RateLimited as exc:
            result = _failure(ecosystem, name, version, rank, str(exc))
            result.defer_reason = "github_rate_limited"
            log.warning("classify deferred %s %s: %s", name, version, exc)
        except (FeedError, ArchiveError, JevUnavailable, OSError, ValueError, http.client.HTTPException) as exc:
            result = _failure(ecosystem, name, version, rank, str(exc))
            if _download_failure(exc):
                result.defer_reason = "download_failed"
                result.signals.append("download_failed")
            log.warning("classify failed %s %s: %s", name, version, exc)
        payload = dump_body(build_payload(result)).decode()
        db.save_release(
            ecosystem,
            name,
            version,
            result.band,
            result.malice_probability,
            result.attack_family,
            result.subtype,
            payload,
            replace=existing is not None,
        )
        if classification_incomplete(result):
            reason = _retry_reason(result)
            db.note_classify_failure(
                ecosystem, name, version, rank, reason, reason=reason, max_attempts=config.ai_max_attempts
            )
        else:
            db.clear_classify_retry(ecosystem, name, version)
            if smart_analysis_enabled(config):
                enqueue_investigation(
                    db,
                    result,
                    enabled=True,
                    excerpt=excerpt,
                    manifest=manifest,
                    full_diff=full_diff,
                    config=config,
                )
        if result.jev_model_id != ACTIONS_RULES_MODEL:
            note_decision_model_health(db, config, result)
        log.info(
            "classified %s %s %s -> %s band=%s llm=%s signals=%s",
            ecosystem,
            name,
            result.old_version or "-",
            version,
            result.band,
            "yes" if should_investigate(result) else "no",
            ",".join(result.signals) or "-",
        )
        db.finish_job(ecosystem, name, version)
    finally:
        close_trees(old_files, new_files)


def classify_job(db: Database, config: Config, job, *, jev, loader: ReleaseLoader, transport: HttpGet = http_get) -> None:
    ecosystem = str(job["ecosystem"])
    if ecosystem == ACTIONS_ECOSYSTEM:
        classify_action_job(db, config, job, jev=jev, loader=loader, transport=transport)
        return
    if ecosystem == OPENVSX_ECOSYSTEM:
        classify_openvsx_job(db, config, job, jev=jev, loader=loader, transport=transport)
        return
    if ecosystem == RUBYGEMS_ECOSYSTEM:
        classify_rubygems_job(db, config, job, jev=jev, loader=loader, transport=transport)
        return
    if ecosystem == CRATES_ECOSYSTEM:
        classify_crate_job(db, config, job, jev=jev, loader=loader, transport=transport)
        return
    name = str(job["name"])
    version = str(job["version"])
    rank = job["rank"]
    existing = db.get_release(ecosystem, name, version)
    if existing is not None and not _release_needs_retry(existing):
        db.finish_job(ecosystem, name, version)
        db.clear_classify_retry(ecosystem, name, version)
        return
    excerpt = ""
    manifest = ""
    full_diff = ""
    old_files = None
    new_files = None
    try:
        try:
            old_files, new_files, meta = loader.load(ecosystem, name, version, rank)
            popular = {str(item).lower() for item in db.watch_names(ecosystem)}
            result, _observed_excerpt = classify_observed(
                meta,
                old_files,
                new_files,
                jev=jev,
                config=config,
                transport=transport,
                popular_names=popular,
            )
            excerpt, manifest, full_diff = triage_evidence_parts(old_files, new_files, meta)
        except (FeedError, ArchiveError, JevUnavailable, OSError, ValueError, http.client.HTTPException) as exc:
            result = _failure(ecosystem, name, version, rank, str(exc))
            if _download_failure(exc):
                result.defer_reason = "download_failed"
                result.signals.append("download_failed")
            result.signals.append("jev_retry")
            log.warning("classify failed %s %s: %s", name, version, exc)
        payload = dump_body(build_payload(result)).decode()
        db.save_release(
            ecosystem,
            name,
            version,
            result.band,
            result.malice_probability,
            result.attack_family,
            result.subtype,
            payload,
            replace=existing is not None,
        )
        if classification_incomplete(result):
            reason = _retry_reason(result)
            db.note_classify_failure(
                ecosystem,
                name,
                version,
                rank,
                reason,
                reason=reason,
                max_attempts=config.ai_max_attempts,
            )
        else:
            db.clear_classify_retry(ecosystem, name, version)
            if smart_analysis_enabled(config):
                enqueue_investigation(
                    db,
                    result,
                    enabled=True,
                    excerpt=excerpt,
                    manifest=manifest,
                    full_diff=full_diff,
                    config=config,
                )
        note_decision_model_health(db, config, result)
        lesson_id = scout_lesson_suppresses(config, result) if smart_analysis_enabled(config) else None
        signal_text = ",".join(result.signals) or "-"
        if lesson_id:
            signal_text = f"{signal_text} scout_lesson={lesson_id}"
        log.info(
            "classified %s %s %s -> %s band=%s probability=%.3f llm=%s signals=%s",
            ecosystem,
            name,
            result.old_version or "-",
            version,
            result.band,
            result.malice_probability,
            "yes" if should_investigate(result) and not lesson_id else "no",
            signal_text,
        )
        db.finish_job(ecosystem, name, version)
    finally:
        close_trees(old_files, new_files)


# One outage webhook, sent once the outage has lasted this long or failed this many releases.
OUTAGE_NOTIFY_SECONDS = 600
OUTAGE_NOTIFY_FAILURES = 5


def note_decision_model_health(db: Database, config: Config, result: Classification, now: datetime | None = None) -> None:
    """Track decision-model outages in the DB so a restart never sends the outage webhook twice."""
    if MODEL_DOWN_SIGNAL in result.signals:
        moment = now or utcnow()
        outage = db.note_decision_model_failure(moment)
        if outage.get("notified_at"):
            return
        started = parse_time(str(outage["started_at"]))
        lasted = (moment - started).total_seconds() if started is not None else 0.0
        if lasted < OUTAGE_NOTIFY_SECONDS and int(outage["failures"]) < OUTAGE_NOTIFY_FAILURES:
            return
        waiting, strong = db.deferred_release_counts()
        enqueue_decision_model_down(
            db,
            since=str(outage["started_at"]),
            failures=int(outage["failures"]),
            waiting=waiting,
            waiting_strong=strong,
            webhook_format=config.webhook_format,
            webhook_url=config.webhook_url,
            when=moment,
        )
        db.mark_decision_model_outage_notified(moment)
        log.error("decision model down since %s; outage webhook queued", outage["started_at"])
    elif not decision_model_failed(result) and result.band != "deferred":
        ended = db.clear_decision_model_outage()
        if ended is not None:
            log.warning("decision model answering again; outage since %s ended", ended["started_at"])


def watchlists_stale(db: Database, config: Config, now: datetime | None = None) -> bool:
    from hunter.db import utcnow

    moment = now or utcnow()
    for ecosystem in ("pypi", "npm"):
        stamp = db.watch_refreshed_at(ecosystem)
        if stamp is None:
            return True
        parsed = parse_time(stamp)
        if parsed is None or (moment - parsed).total_seconds() >= config.watchlist_refresh:
            return True
    return False


def _npm_time_cutoff(stamp: str) -> str:
    """Registry version times include fractional seconds. Poll times do not."""
    text = str(stamp)
    if text.endswith("Z") and "." not in text:
        return text[:-1] + ".000Z"
    return text


def _release_stored(
    db: Database,
    ecosystem: str,
    name: str,
    version: str,
    rank: int | None,
    max_pending: int | None,
) -> str:
    """'queued' if inserted, 'present' if that release is already stored, 'refused' if the cap blocked it."""
    if db.enqueue_job(ecosystem, name, version, rank, max_pending=max_pending):
        return "queued"
    if db.has_release_job(ecosystem, name, version):
        return "present"
    return "refused"


def _npm_version_cutoff(db: Database, name: str) -> str | None:
    """Per-package cursor, or the last successful npm poll when the package is new."""
    _version, last_time = db.get_package_cursor("npm", name)
    if last_time:
        return str(last_time)
    poll_at = db.last_poll().get("npm")
    if not poll_at:
        return None
    return _npm_time_cutoff(str(poll_at))


def _queue_npm_versions(
    db: Database,
    name: str,
    rank: int | None,
    versions: list[tuple[str, str]],
    *,
    max_pending: int | None,
    cutoff: str | None,
) -> tuple[int, str]:
    """Queue versions oldest-first. Leave the cursor on the last release that was stored."""
    queued = 0
    kept: tuple[str, str] | None = None
    for version, stamp in versions:
        state = _release_stored(db, "npm", name, version, rank, max_pending)
        if state == "refused":
            if kept is not None:
                db.set_package_cursor("npm", name, kept[0], kept[1])
            elif cutoff is not None and db.get_package_cursor("npm", name)[1] is None:
                db.set_package_cursor("npm", name, None, cutoff)
            return queued, "refused"
        if state == "queued":
            queued += 1
        kept = (version, stamp)
    if kept is not None:
        db.set_package_cursor("npm", name, kept[0], kept[1])
    elif cutoff is not None and db.get_package_cursor("npm", name)[1] is None:
        db.set_package_cursor("npm", name, None, cutoff)
    return queued, "ok"


def poll_pypi(db: Database, feed: PypiSerialFeed, *, max_pending: int | None = None, include_mcp: bool = False) -> int:
    saved = db.get_checkpoint("pypi")
    if saved is None:
        db.set_checkpoint("pypi", str(feed.last_serial()))
        db.mark_poll_success("pypi")
        return 0
    events = list(feed.since(int(saved)))
    watch = db.watch_names("pypi")
    targets = db.poll_watch("pypi") if include_mcp else watch
    queued = 0
    blocked = False
    for name, version, rank in pypi_events_to_versions(events, targets):
        state = _release_stored(db, "pypi", name, version, rank, max_pending)
        if state == "queued":
            queued += 1
        elif state == "refused":
            blocked = True
            break
    if not blocked:
        for name, version, rank in typosquat_pairs(
            pypi_version_events(events),
            watch,
            TYPOSQUAT_QUEUE_LIMIT,
        ):
            state = _release_stored(db, "pypi", name, version, rank, max_pending)
            if state == "queued":
                queued += 1
                log.info("queued typosquat candidate pypi %s %s", name, version)
            elif state == "refused":
                blocked = True
                break
    # A release the cap refused stays inside the feed window until a later poll can store it.
    if not blocked:
        serial = max_serial(events)
        if serial is not None:
            db.set_checkpoint("pypi", str(serial))
    db.mark_poll_success("pypi")
    return queued


def _advance_handled(handled_seq: str, seq: object) -> str:
    if seq is None:
        return handled_seq
    return str(seq)


def poll_npm(db: Database, config: Config, transport: HttpGet = http_get, stop: threading.Event | None = None) -> int:
    saved = db.get_checkpoint("npm")
    if saved is None:
        bootstrap_npm(db, config.npm_changes, transport)
        db.mark_poll_success("npm")
        return 0
    ranked = db.watch_names("npm")
    # MCP packages are watched for releases but are not popular names for the typosquat check.
    watch = db.poll_watch("npm") if getattr(config, "mcp_registry", False) else ranked
    popular = {str(name).lower(): int(rank) for name, rank in ranked.items()}
    name_index = NameIndex(popular)
    queued = 0
    typo_left = TYPOSQUAT_QUEUE_LIMIT
    seen: set[str] = set()
    blocked = False
    handled_seq = str(saved)
    for results, last, _done in page_npm_changes(
        config.npm_changes,
        saved,
        page_size=config.npm_page_size,
        transport=transport,
        stop=stop,
    ):
        for row in results:
            seq = row.get("seq")
            if row.get("deleted"):
                handled_seq = _advance_handled(handled_seq, seq)
                continue
            name = row.get("id")
            if not name or name in seen:
                handled_seq = _advance_handled(handled_seq, seq)
                continue
            watched = str(name) in watch
            rank = watch[str(name)] if watched else None
            if not watched:
                if typo_left <= 0:
                    handled_seq = _advance_handled(handled_seq, seq)
                    continue
                victim = name_index.match(str(name))
                if not victim:
                    handled_seq = _advance_handled(handled_seq, seq)
                    continue
                rank = popular.get(victim, 0)
                typo_left -= 1
                log.info("queued typosquat candidate npm %s similar to %s", name, victim)
            document = _json(transport(f"{config.npm_registry}/{quote(str(name))}", 60))
            if not watched:
                version, stamp = newest_version(document)
                if version:
                    state = _release_stored(db, "npm", str(name), version, rank, config.max_pending)
                    if state == "queued":
                        queued += 1
                    if state == "refused":
                        blocked = True
                        break
                    if stamp:
                        db.set_package_cursor("npm", str(name), version, stamp)
                seen.add(str(name))
                handled_seq = _advance_handled(handled_seq, seq)
                continue
            cutoff = _npm_version_cutoff(db, str(name))
            if cutoff is None:
                version, stamp = newest_version(document)
                if version and not stamp:
                    state = _release_stored(db, "npm", str(name), version, rank, config.max_pending)
                    if state == "queued":
                        queued += 1
                    if state == "refused":
                        blocked = True
                        break
                    seen.add(str(name))
                    handled_seq = _advance_handled(handled_seq, seq)
                    continue
                fresh = [(version, stamp)] if version and stamp else []
            else:
                fresh = versions_after(document, cutoff)
            added, state = _queue_npm_versions(
                db,
                str(name),
                rank,
                fresh,
                max_pending=config.max_pending,
                cutoff=cutoff,
            )
            queued += added
            if state == "refused":
                blocked = True
                break
            seen.add(str(name))
            handled_seq = _advance_handled(handled_seq, seq)
        if blocked:
            db.set_checkpoint("npm", handled_seq)
            break
        db.set_checkpoint("npm", last)
    if not blocked:
        db.mark_poll_success("npm")
    return queued


def drain_jobs(
    db: Database,
    config: Config,
    *,
    jev,
    loader: ReleaseLoader,
    workers: int,
    stop: threading.Event | None = None,
    limit: int | None = None,
) -> int:
    batch = config.classify_batch if limit is None else limit
    jobs = db.pending_jobs(
        limit=max(0, batch),
        prioritize=getattr(config, "takeover_signals", False),
        prioritize_mcp=getattr(config, "mcp_risk", False),
    )
    if not jobs:
        return 0
    if stop is not None and stop.is_set():
        return 0
    pool_size = max(1, workers)

    def _one(job):
        try:
            classify_job(db, config, job, jev=jev, loader=loader, transport=getattr(loader, "transport", http_get))
        except Exception as exc:
            _record_job_failure(db, config, job, exc)

    with ThreadPoolExecutor(max_workers=pool_size) as pool:
        list(pool.map(_one, jobs))
    return len(jobs)


def _record_job_failure(db: Database, config: Config, job, exc: BaseException) -> None:
    """Keep one crashed release from ending the worker pool."""
    ecosystem = str(job["ecosystem"])
    name = str(job["name"])
    version = str(job["version"])
    reason = "download_failed" if _download_failure(exc) else "classify_failed"
    log.exception("classify job crashed %s %s %s (%s)", ecosystem, name, version, reason)
    try:
        db.note_classify_failure(
            ecosystem,
            name,
            version,
            job["rank"],
            reason,
            reason=reason,
            max_attempts=config.ai_max_attempts,
        )
        db.finish_job(ecosystem, name, version)
    except Exception:
        log.exception("could not record a retry for %s %s %s", ecosystem, name, version)


def _score_takeover_safely(db: Database, config: Config, transport: HttpGet) -> None:
    """Account-takeover signals for the next pending jobs. A failure never blocks classify."""
    try:
        score_pending_jobs(db, config, transport)
    except Exception:
        log.exception("takeover signal pass failed")


def _score_mcp_safely(db: Database, config: Config, loader: ReleaseLoader) -> None:
    """MCP tool and server.json signals. A failure never blocks classify."""
    try:
        score_mcp_jobs(db, config, loader)
    except Exception:
        log.exception("mcp risk pass failed")


def drain_until_idle(
    db: Database,
    config: Config,
    *,
    jev,
    loader: ReleaseLoader,
    stop: threading.Event | None = None,
) -> None:
    """Interleave a limited classify batch, Triage, Analyst, and the outbox.

    A large classify backlog cannot run to completion before investigations.
    The cycle still stops after `classify_cycle_cap` classifications so a poll
    is not stuck behind the whole queue.
    """
    classified = 0
    cap = max(1, config.classify_cycle_cap)
    for _round in range(1000):
        if stop is not None and stop.is_set():
            return
        room = cap - classified
        n_jobs = 0
        if room > 0 and getattr(config, "takeover_signals", False):
            _score_takeover_safely(db, config, getattr(loader, "transport", http_get))
        if room > 0 and getattr(config, "mcp_risk", False):
            _score_mcp_safely(db, config, loader)
        if room > 0:
            n_jobs = drain_jobs(
                db,
                config,
                jev=jev,
                loader=loader,
                workers=config.workers,
                stop=stop,
                limit=min(config.classify_batch, room),
            )
            classified += n_jobs
        n_inv = 0
        if smart_analysis_enabled(config):
            n_inv = drain_investigations(
                db,
                config=config,
                webhook_url=config.webhook_url,
                webhook_secret=config.webhook_secret,
                webhook_format=config.webhook_format,
                limit=config.investigate_batch,
            )
        n_mag = 0
        if config.analyst:
            n_mag = drain_analyst(
                db,
                config=config,
                webhook_url=config.webhook_url,
                webhook_secret=config.webhook_secret,
                webhook_format=config.webhook_format,
                limit=config.investigate_batch,
            )
        n_out = drain_outbox(
            db,
            url=config.webhook_url,
            secret=config.webhook_secret,
            limit=config.outbox_batch,
            extra_headers=config.webhook_headers,
        )
        # A failed upload retries on the next serve pass. It does not keep this
        # loop spinning, and it does not change whether the webhook was sent.
        publish_public_feed(db, config)
        global _dash_publisher
        if _dash_publisher is not None:
            _dash_publisher.notify()
        if n_jobs == 0 and n_inv == 0 and n_mag == 0 and n_out == 0:
            return
        if classified >= cap and n_inv == 0 and n_mag == 0 and n_out == 0:
            return


@dataclass(frozen=True)
class FeedStart:
    """Where a scan or serve should begin reading the feeds.

    `pypi_serial` and `npm_seq` replace that feed's checkpoint. The next poll
    reads events after the value. `since_hours` rewinds each feed that was not
    given an explicit cursor. A checkpoint already older than that point stays
    put, so the replay does not skip a gap the poller has not read yet.
    """

    pypi_serial: int | None = None
    npm_seq: str | None = None
    since_hours: float | None = None


def _event_unix(value) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, datetime):
        return int(value.timestamp())
    parsed = parse_time(str(value))
    if parsed is None:
        return None
    return int(parsed.timestamp())


def _first_pypi_event_at_or_after(feed, serial: int) -> tuple[int, int] | None:
    since = serial - 1 if serial > 0 else 0
    for event in feed.since(since):
        if len(event) < 5:
            continue
        event_serial = int(event[4])
        if event_serial < serial:
            continue
        when = _event_unix(event[2])
        if when is None:
            continue
        return event_serial, when
    return None


def pypi_checkpoint_for_time(feed, target: datetime) -> int:
    """Serial just before the first changelog event at or after `target`.

    The next `since` call then includes that event. The current head is used
    when the feed has nothing in the window.
    """
    target_ts = int(target.timestamp())
    last = int(feed.last_serial())
    lo = 0
    hi = last
    candidate: int | None = None
    for _ in range(64):
        if lo > hi:
            break
        mid = (lo + hi) // 2
        found = _first_pypi_event_at_or_after(feed, mid)
        if found is None:
            hi = mid - 1
            continue
        serial, when = found
        if when >= target_ts:
            candidate = serial
            hi = min(serial, mid) - 1
        else:
            lo = max(serial + 1, mid + 1)
    if candidate is None:
        return last
    return max(0, candidate - 1)


def _npm_row_modified(row: dict) -> datetime | None:
    if row.get("deleted"):
        return None
    doc = row.get("doc") or {}
    if not isinstance(doc, dict) or doc.get("_deleted"):
        return None
    stamp = (doc.get("time") or {}).get("modified")
    if stamp is None:
        return None
    return parse_time(str(stamp))


def _npm_timed_change_after(base: str, since: str, transport: HttpGet) -> tuple[int, datetime] | None:
    """First change after `since` that carries doc.time.modified.

    Deletions have no publish time. A short walk skips them. This lookup is
    separate from the no-gap poller.
    """
    cursor = str(since)
    for _ in range(40):
        url = (
            f"{base.rstrip('/')}/_changes?since={quote(str(cursor), safe='')}"
            "&limit=1&include_docs=true"
        )
        page = _json(transport(url, 60))
        results = list(page.get("results") or [])
        if not results:
            return None
        row = results[0]
        seq = row.get("seq")
        if seq is None:
            return None
        seq_text = str(seq)
        try:
            seq_int = int(seq_text)
        except (TypeError, ValueError):
            return None
        when = _npm_row_modified(row)
        if when is not None:
            return seq_int, when
        if seq_text == cursor:
            return None
        cursor = seq_text
    return None


def npm_checkpoint_for_time(base: str, target: datetime, transport: HttpGet = http_get) -> str:
    """Sequence just before the first npm change at or after `target`.

    The current head is used when the feed has nothing in the window.
    """
    head = fetch_npm_changes_head(base, transport)
    last = head.get("last_seq")
    if last is None or str(last) == "":
        raise FeedError("npm changes feed did not return last_seq")
    try:
        head_seq = int(last)
    except (TypeError, ValueError) as exc:
        raise FeedError("npm changes sequence is not an integer") from exc
    lo = 0
    hi = head_seq
    candidate: int | None = None
    for _ in range(64):
        if lo > hi:
            break
        mid = (lo + hi) // 2
        since = str(mid - 1) if mid > 0 else "0"
        found = _npm_timed_change_after(base, since, transport)
        if found is None or found[0] < mid:
            hi = mid - 1
            continue
        seq, when = found
        if when >= target:
            candidate = seq
            hi = min(seq, mid) - 1
        else:
            lo = max(seq + 1, mid + 1)
    if candidate is None:
        return str(head_seq)
    if candidate <= 0:
        return "0"
    return str(candidate - 1)


def _cursor_int(value: str) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _rewind_checkpoint(db: Database, ecosystem: str, target: str) -> None:
    """Move a checkpoint backward. Leave an older checkpoint where it is.

    The older cursor still has unread events. Moving it forward would open a
    gap. Polling from the older cursor pages forward with no skip.
    """
    current = db.get_checkpoint(ecosystem)
    if current is None:
        db.set_checkpoint(ecosystem, target)
        return
    current_n = _cursor_int(current)
    target_n = _cursor_int(target)
    if current_n is None or target_n is None:
        if str(current) > str(target):
            db.set_checkpoint(ecosystem, target)
        return
    if current_n > target_n:
        db.set_checkpoint(ecosystem, target)


def apply_feed_start(
    db: Database,
    config: Config,
    feed,
    transport: HttpGet,
    start: FeedStart,
    now: datetime | None = None,
) -> None:
    """Set feed checkpoints before the next poll. Explicit cursors win."""
    if start.pypi_serial is None and start.npm_seq is None and start.since_hours is None:
        return
    if start.since_hours is not None:
        if start.since_hours < 0:
            raise ValueError("since-hours must be zero or greater")
        moment = now or utcnow()
        target = moment - timedelta(hours=float(start.since_hours))
        if start.pypi_serial is None and not config.skip_pypi:
            _rewind_checkpoint(db, "pypi", str(pypi_checkpoint_for_time(feed, target)))
        if start.npm_seq is None and not config.skip_npm:
            _rewind_checkpoint(db, "npm", npm_checkpoint_for_time(config.npm_changes, target, transport))
    if start.pypi_serial is not None:
        if start.pypi_serial < 0:
            raise ValueError("pypi serial must be zero or greater")
        db.set_checkpoint("pypi", str(int(start.pypi_serial)))
    if start.npm_seq is not None:
        text = str(start.npm_seq).strip()
        if not text:
            raise ValueError("npm sequence is empty")
        db.set_checkpoint("npm", text)


_refresh_lock = threading.Lock()


def _refresh_watchlists_if_stale(db: Database, config: Config, transport: HttpGet) -> None:
    if not watchlists_stale(db, config):
        return
    with _refresh_lock:
        if not watchlists_stale(db, config):
            return
        try:
            refresh_watchlists(db, config, transport)
        except (FeedError, OSError, ValueError, http.client.HTTPException) as exc:
            log.warning("watchlist refresh failed: %s", exc)


def _poll_pypi_safely(db: Database, config: Config, feed, transport: HttpGet) -> None:
    if config.skip_pypi:
        return
    _refresh_watchlists_if_stale(db, config, transport)
    try:
        poll_pypi(db, feed, max_pending=config.max_pending, include_mcp=getattr(config, "mcp_registry", False))
    except Exception as exc:
        db.mark_poll_error("pypi", str(exc))
        log.warning("pypi poll failed: %s", exc)


def _poll_npm_safely(
    db: Database,
    config: Config,
    transport: HttpGet,
    stop: threading.Event | None,
) -> None:
    if config.skip_npm:
        return
    _refresh_watchlists_if_stale(db, config, transport)
    try:
        poll_npm(db, config, transport, stop)
    except Exception as exc:
        db.mark_poll_error("npm", str(exc))
        log.warning("npm poll failed: %s", exc)


def actions_watchlist_stale(db: Database, config: Config, now: datetime | None = None) -> bool:
    stamp = db.watch_refreshed_at(ACTIONS_ECOSYSTEM)
    parsed = parse_time(stamp) if stamp else None
    moment = now or utcnow()
    return parsed is None or (moment - parsed).total_seconds() >= config.actions_watchlist_refresh


def _refresh_actions_watchlist_safely(db: Database, config: Config, transport: HttpGet, client: GitHubClient) -> None:
    if not actions_watchlist_stale(db, config):
        return
    # The startup probe already ran. Check again at the start of each refresh.
    check_ecosyste(config, transport)
    try:
        refresh_actions_watchlist(db, config, transport, client)
    except Exception as exc:
        log.warning("actions watchlist refresh failed: %s", exc)


def _poll_actions_safely(db: Database, config: Config, client: GitHubClient, stop: threading.Event | None) -> None:
    try:
        poll_actions(db, config, client, stop=stop)
        db.mark_poll_success(ACTIONS_ECOSYSTEM)
    except Exception as exc:
        db.mark_poll_error(ACTIONS_ECOSYSTEM, str(exc))
        log.warning("actions poll failed: %s", exc)


def _ground_truth_safely(
    db: Database, config: Config, transport: HttpGet, stop: threading.Event | None = None
) -> None:
    from hunter.ground_truth import report_is_fresh, run_ground_truth

    if report_is_fresh(config):
        return
    try:
        run_ground_truth(db, config, transport=transport, stop=stop)
    except Exception as exc:
        log.warning("ground truth run failed: %s", exc)


def _poll_mcp_registry_safely(db: Database, config: Config, transport: HttpGet, stop: threading.Event | None) -> None:
    try:
        poll_mcp_registry(db, config, transport, stop)
    except Exception as exc:
        db.mark_poll_error(MCP_POLL_NAME, str(exc))
        log.warning("MCP registry poll failed: %s", exc)


def _poll_openvsx_safely(db: Database, config: Config, transport: HttpGet, stop: threading.Event | None) -> None:
    try:
        poll_openvsx(db, config, transport, stop)
    except Exception as exc:
        db.mark_poll_error(OPENVSX_ECOSYSTEM, str(exc))
        log.warning("Open VSX poll failed: %s", exc)


def _poll_rubygems_safely(db: Database, config: Config, transport: HttpGet, stop: threading.Event | None) -> None:
    try:
        poll_rubygems(db, config, transport, stop)
    except Exception as exc:
        db.mark_poll_error(RUBYGEMS_ECOSYSTEM, str(exc))
        log.warning("RubyGems poll failed: %s", exc)


def _poll_crates_safely(db: Database, config: Config, transport: HttpGet, stop: threading.Event | None) -> None:
    try:
        poll_crates(db, config, transport, stop)
    except Exception as exc:
        db.mark_poll_error(CRATES_ECOSYSTEM, str(exc))
        log.warning("crates.io poll failed: %s", exc)


def _feed_loop(stop: threading.Event, interval: float, fn) -> None:
    while not stop.is_set():
        fn()
        if stop.wait(max(0.0, float(interval))):
            return


def _reopen_due_retries(db: Database, config: Config) -> None:
    for retry in db.due_classify_retries(limit=config.classify_batch):
        db.reopen_job(retry["ecosystem"], retry["name"], retry["version"], retry["rank"])


def _start_feed_polls(
    db: Database,
    config: Config,
    feed,
    transport: HttpGet,
    stop: threading.Event | None,
) -> list[threading.Thread]:
    threads: list[threading.Thread] = []
    if not config.skip_pypi:
        threads.append(
            threading.Thread(
                target=_poll_pypi_safely,
                args=(db, config, feed, transport),
                name="hunter-pypi",
                daemon=True,
            )
        )
    if not config.skip_npm:
        threads.append(
            threading.Thread(
                target=_poll_npm_safely,
                args=(db, config, transport, stop),
                name="hunter-npm",
                daemon=True,
            )
        )
    for thread in threads:
        thread.start()
    return threads


def run_cycle(db, config, *, jev, loader, feed, transport: HttpGet = http_get, stop: threading.Event | None = None) -> None:
    """Poll PyPI and npm together, then drain once.

    The two polls share one SQLite connection. Database methods take a lock
    around each statement, and the polls do not hold that lock during HTTP.
    """
    threads = _start_feed_polls(db, config, feed, transport, stop)
    for thread in threads:
        thread.join()
    _reopen_due_retries(db, config)
    drain_until_idle(db, config, jev=jev, loader=loader, stop=stop)


def health_payload(
    db: Database,
    started: float,
    model_id: str = JEV_MODEL_ID,
    config: Config | None = None,
    meter: SpendMeter | None = None,
) -> dict:
    payload = {
        "status": "ok",
        "uptime_seconds": max(0.0, round(time.monotonic() - started, 1)),
        "scout_model": DEFAULT_SCOUT_MODEL if config is None else config.scout_model,
        "models": None if config is None else active_role_models(config),
        "jev_model_id": model_id,
        "outbox_depth": db.outbox_depth(),
        "pending_jobs": db.pending_count(),
        "classify_retries": db.retry_depth(),
        "investigations": db.investigation_depth(),
        "analyst_queue": db.analyst_depth(),
        "triage_budget_used": db.budget_used("triage"),
        "triage_budget_limit": None if config is None else config.triage_budget,
        "analyst_budget_used": db.budget_used("analyst"),
        "analyst_budget_limit": None if config is None else config.analyst_budget,
        "exhausted": db.human_review_depth(),
        "human_review_queue": db.human_review_depth(),
        "last_successful_poll": db.last_poll(),
    }
    feed_state = db.public_feed_state()
    payload["feed_last_published_at"] = None if feed_state is None else feed_state["published_at"]
    payload["feed_last_error"] = None if feed_state is None else feed_state["last_error"]
    dash_state = db.public_dash_state()
    payload["dash_last_published_at"] = None if dash_state is None else dash_state["published_at"]
    payload["dash_last_error"] = None if dash_state is None else dash_state["last_error"]
    if config is not None and getattr(config, "takeover_signals", False):
        payload["takeover_signals"] = db.takeover_counts()
    if config is not None and getattr(config, "mcp_risk", False):
        payload["mcp_risk"] = db.mcp_risk_counts()
    if config is not None and config.actions:
        probe = ecosyste_probe_state()
        payload["github_actions"] = {
            **db.action_counts(),
            "token": bool(config.github_token),
            "ecosyste_ok": bool(probe.get("ok")),
            "ecosyste_checked_at": probe.get("checked_at"),
            "ecosyste_error": probe.get("error"),
        }
    if config is not None and getattr(config, "mcp_registry", False):
        payload["mcp_registry"] = db.mcp_counts()
    if config is not None and getattr(config, "openvsx", False):
        payload["openvsx"] = db.openvsx_counts()
    if config is not None and getattr(config, "rubygems", False):
        raw = db.get_checkpoint(RUBYGEMS_QUEUED)
        try:
            last_queued = int(raw) if raw is not None else 0
        except ValueError:
            last_queued = 0
        payload["rubygems"] = {
            "checkpoint": db.get_checkpoint(RUBYGEMS_CHECKPOINT),
            "last_queued": last_queued,
        }
    if config is not None and getattr(config, "crates", False):
        payload["crates"] = {
            "checkpoint": db.get_checkpoint(CRATES_ECOSYSTEM),
            "watchlist": len(db.watch_names(CRATES_ECOSYSTEM)),
        }
    if meter is not None:
        payload.update(meter.health())
    return payload


LOOPBACK_BINDS = ("127.0.0.1", "localhost", "::1")


def _loopback(bind: str) -> bool:
    return bind in LOOPBACK_BINDS or bind.startswith("127.")


def dashboard_access(config: Config, authorization: str | None) -> tuple[bool, str]:
    """May this request read /api/*? A token, when set, is required; a wide bind without one is refused."""
    token = config.dashboard_token
    if token:
        given = (authorization or "").removeprefix("Bearer ").strip()
        if hmac.compare_digest(given.encode(), token.encode()):
            return True, ""
        return False, "missing or wrong dashboard token"
    if _loopback(config.bind):
        return True, ""
    return False, "set HUNTER_DASHBOARD_TOKEN to read the dashboard API on a non-local bind"


def start_health(config: Config, db: Database, started: float, meter: SpendMeter | None = None) -> ThreadingHTTPServer:
    from hunter import dashboard
    from hunter.dashboard.benchmark import load_benchmarks
    from hunter.rules import rules_enabled

    def health() -> dict:
        return health_payload(db, started, config.scout_model_id(), config, meter)

    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, body: bytes, content_type: str, *, cache: str = "no-store") -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", cache)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", dashboard.CONTENT_SECURITY_POLICY)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, payload: object) -> None:
            self._send(status, json.dumps(payload, default=str).encode(), "application/json")

        def do_GET(self):  # noqa: N802
            parsed = urlsplit(self.path)
            path = parsed.path
            params = {key: values[-1] for key, values in parse_qs(parsed.query).items()}
            if path == "/health":
                self._json(200, health())
                return
            if path in ("/", "/dashboard", "/dashboard/") or path.startswith("/static/"):
                name = "index.html" if not path.startswith("/static/") else path.removeprefix("/static/")
                found = dashboard.static_file(name)
                if found is None:
                    self._json(404, {"error": "not found"})
                    return
                self._send(200, found[0], found[1], cache="no-cache")
                return
            if not path.startswith("/api/"):
                self._json(404, {"error": "not found"})
                return
            allowed, reason = dashboard_access(config, self.headers.get("Authorization"))
            if not allowed:
                self._json(403, {"error": reason})
                return
            try:
                if path == "/api/snapshot":
                    payload = dashboard.snapshot(
                        db,
                        health=health(),
                        models=active_role_models(config),
                        range_name=params.get("range"),
                        rules_enabled=rules_enabled(),
                    )
                elif path == "/api/findings":
                    payload = dashboard.findings(db, params)
                elif path == "/api/release":
                    payload = dashboard.release(
                        db, params.get("ecosystem", ""), params.get("name", ""), params.get("version", "")
                    )
                    if payload is None:
                        self._json(404, {"error": "release not found"})
                        return
                elif path == "/api/benchmark":
                    payload = load_benchmarks(config.bench_dir)
                    payload["production_scout"] = config.scout_model
                else:
                    self._json(404, {"error": "not found"})
                    return
            except Exception:
                log.exception("dashboard request failed: %s", path)
                self._json(500, {"error": "dashboard request failed"})
                return
            self._json(200, payload)

        def log_message(self, fmt, *args):
            return

    server = ThreadingHTTPServer((config.bind, config.port), Handler)
    thread = threading.Thread(target=server.serve_forever, name="hunter-health", daemon=True)
    thread.start()
    return server


def serve(
    config: Config,
    *,
    stop: threading.Event | None = None,
    jev=None,
    loader=None,
    feed=None,
    transport: HttpGet = http_get,
    start: FeedStart | None = None,
) -> None:
    if jev is None:
        require_scoring_layer(config)
    stop = stop or threading.Event()
    previous_term = signal.getsignal(signal.SIGTERM)
    previous_int = signal.getsignal(signal.SIGINT)

    def _stop(_signum, _frame):
        stop.set()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    configure_logging()
    warn_smart_config(config)
    warn_analyst_config(config)
    db = Database(config.db_path)
    meter = None
    if jev is None:
        meter = SpendMeter(db, cap_usd=config.scout_daily_usd_cap, prices=config.scout_prices, stop=stop)
    client = jev or make_scout_model(config, meter=meter)
    release_loader = loader or ReleaseLoader(config, transport)
    pypi_feed = feed or PypiSerialFeed(config.pypi_base)
    started = time.monotonic()
    server = start_health(config, db, started, meter)
    from hunter.public_dash import DEBOUNCE_S, UPLOAD_TIMEOUT_S, start_public_dash_publisher

    global _dash_publisher
    _dash_publisher = start_public_dash_publisher(db, config, started=started, meter=meter, stop=stop)
    dash_publisher = _dash_publisher
    log.info("hunter serving; health on %s:%s", config.bind, server.server_address[1])
    polls: list[threading.Thread] = []
    try:
        if start is not None:
            apply_feed_start(db, config, pypi_feed, transport, start)
        if not config.skip_pypi:
            polls.append(
                threading.Thread(
                    target=_feed_loop,
                    kwargs={
                        "stop": stop,
                        "interval": config.poll_interval,
                        "fn": lambda: _poll_pypi_safely(db, config, pypi_feed, transport),
                    },
                    name="hunter-pypi",
                    daemon=True,
                )
            )
        if not config.skip_npm:
            polls.append(
                threading.Thread(
                    target=_feed_loop,
                    kwargs={
                        "stop": stop,
                        "interval": config.poll_interval,
                        "fn": lambda: _poll_npm_safely(db, config, transport, stop),
                    },
                    name="hunter-npm",
                    daemon=True,
                )
            )
        if config.actions:
            actions_client = getattr(release_loader, "github", None) or GitHubClient(config.github_token)
            if not actions_client.has_token:
                log.info("GitHub Actions watcher: no HUNTER_GITHUB_TOKEN; reading tags over git, package repos skipped")
            polls.append(
                threading.Thread(
                    target=_feed_loop,
                    kwargs={
                        "stop": stop,
                        "interval": 3600.0,
                        "fn": lambda: _refresh_actions_watchlist_safely(db, config, transport, actions_client),
                    },
                    name="hunter-actions-watchlist",
                    daemon=True,
                )
            )
            polls.append(
                threading.Thread(
                    target=_feed_loop,
                    kwargs={
                        "stop": stop,
                        "interval": config.actions_poll_interval,
                        "fn": lambda: _poll_actions_safely(db, config, actions_client, stop),
                    },
                    name="hunter-actions",
                    daemon=True,
                )
            )
        if config.ground_truth:
            polls.append(
                threading.Thread(
                    target=_feed_loop,
                    kwargs={
                        "stop": stop,
                        "interval": config.ground_truth_interval,
                        "fn": lambda: _ground_truth_safely(db, config, transport, stop),
                    },
                    name="hunter-ground-truth",
                    daemon=True,
                )
            )
        if config.mcp_registry:
            if config.skip_pypi and config.skip_npm:
                log.warning("MCP registry is on but npm and PyPI are both skipped; its packages are not polled")
            polls.append(
                threading.Thread(
                    target=_feed_loop,
                    kwargs={
                        "stop": stop,
                        "interval": config.mcp_poll_interval,
                        "fn": lambda: _poll_mcp_registry_safely(db, config, transport, stop),
                    },
                    name="hunter-mcp-registry",
                    daemon=True,
                )
            )
        if config.openvsx:
            polls.append(
                threading.Thread(
                    target=_feed_loop,
                    kwargs={
                        "stop": stop,
                        "interval": config.openvsx_poll_interval,
                        "fn": lambda: _poll_openvsx_safely(db, config, transport, stop),
                    },
                    name="hunter-openvsx",
                    daemon=True,
                )
            )
        if config.rubygems:
            polls.append(
                threading.Thread(
                    target=_feed_loop,
                    kwargs={
                        "stop": stop,
                        "interval": config.rubygems_poll_interval,
                        "fn": lambda: _poll_rubygems_safely(db, config, transport, stop),
                    },
                    name="hunter-rubygems",
                    daemon=True,
                )
            )
        if config.crates:
            polls.append(
                threading.Thread(
                    target=_feed_loop,
                    kwargs={
                        "stop": stop,
                        "interval": config.crates_poll_interval,
                        "fn": lambda: _poll_crates_safely(db, config, transport, stop),
                    },
                    name="hunter-crates",
                    daemon=True,
                )
            )
        # Start PyPI and npm before the ecosyste.ms probe so that check cannot
        # delay those feeds. The probe still runs before the Actions poll threads.
        started: set[int] = set()
        for thread in polls:
            if thread.name in {"hunter-pypi", "hunter-npm"}:
                thread.start()
                started.add(id(thread))
        if config.actions:
            check_ecosyste(config, transport)
        for thread in polls:
            if id(thread) not in started:
                thread.start()
        while not stop.is_set():
            _reopen_due_retries(db, config)
            drain_until_idle(db, config, jev=client, loader=release_loader, stop=stop)
            if stop.wait(1.0):
                break
    finally:
        stop.set()
        if dash_publisher is not None:
            dash_publisher.join(timeout=UPLOAD_TIMEOUT_S + DEBOUNCE_S + 1)
        _dash_publisher = None
        for thread in polls:
            thread.join()
        server.shutdown()
        db.close()
        signal.signal(signal.SIGTERM, previous_term)
        signal.signal(signal.SIGINT, previous_int)
