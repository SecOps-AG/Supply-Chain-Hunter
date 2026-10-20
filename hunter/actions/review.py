"""Review one GitHub Actions tag event: signals, download, rules, routing.

Called by ``service.classify_job`` for ``github-actions`` jobs. Scout is not used
for moved tags. New tags run the rules, plus Scout when ``HUNTER_ACTIONS_SCOUT``
is on and today's Actions Scout limit has room. Nothing here alerts: a routed
row goes to Triage, and only an Analyst-confirmed verdict reaches the webhook
and the public feed, as for npm and PyPI.
"""

from __future__ import annotations

import logging
from pathlib import Path, PurePosixPath

from hunter.actions import ECOSYSTEM, release_url, release_version
from hunter.actions.github import GitHubClient
from hunter.actions.manifest import action_manifests
from hunter.actions.signals import MEDIUM, STRONG, EventFacts, event_facts
from hunter.archives import DiskTree, aligned_release_trees, close_trees, extract_archive
from hunter.bands import REVIEW_THRESHOLD
from hunter.db import utcnow
from hunter.models import Classification, ReleaseMeta, RuleReport
from hunter.registry import PACKAGE_DOWNLOAD_MAX_BYTES, HttpGet, fetch_capped
from hunter.rules.engine import scan_release
from hunter.triage import changed_diffs

log = logging.getLogger("hunter.actions.review")

MODEL_ID = "deterministic"
STRONG_PROBABILITY = 0.55
CONTENT_SIGNALS = frozenset(
    {
        "action_pre_post_added",
        "action_entry_changed",
        "action_docker_unpinned",
        "action_dist_without_source",
    }
)
CONTENT_WEAK = frozenset({"action_new_unpinned_use"})
_SOURCE_SUFFIXES = {".ts", ".mts", ".cts", ".js", ".mjs", ".cjs", ".py", ".sh", ".go", ".rs"}
_SOURCE_SKIP = {"dist", "node_modules", "lib", "build", "out", "test", "tests", "__tests__", "docs", ".github"}
# A rebuilt bundle is expected when the dependencies changed.
_DEPENDENCY_FILES = {
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "bun.lockb",
}


def load_action_trees(transport: HttpGet, client: GitHubClient, name: str, old_sha: str | None, new_sha: str):
    """Download the repository at both commits as tarballs and unpack them. Nothing is run."""

    def _tree(sha: str) -> DiskTree:
        archive: Path = fetch_capped(transport, client.tarball_url(name, sha), 120, PACKAGE_DOWNLOAD_MAX_BYTES)
        try:
            return extract_archive(archive)
        finally:
            archive.unlink(missing_ok=True)

    new_files = DiskTree.empty()
    old_files = DiskTree.empty()
    try:
        new_files = _tree(new_sha)
        if old_sha:
            old_files = _tree(old_sha)
        return old_files, new_files
    except Exception:
        close_trees(old_files, new_files)
        raise


def _is_source(path: str) -> bool:
    pure = PurePosixPath(path.lower())
    if pure.suffix not in _SOURCE_SUFFIXES or pure.name.endswith((".d.ts", ".min.js")):
        return False
    return not any(part in _SOURCE_SKIP for part in pure.parts[:-1])


def _is_dependency_file(path: str) -> bool:
    pure = PurePosixPath(path.lower())
    return pure.name in _DEPENDENCY_FILES and not any(part in {"node_modules", "dist"} for part in pure.parts[:-1])


def _runtime(using: str | None) -> str:
    """node20 and node24 are the same kind of action; a switch to docker or composite is not."""
    value = (using or "").strip().strip("'\"").lower()
    return "node" if value.startswith("node") else value


def _is_dist(path: str) -> bool:
    parts = PurePosixPath(path.lower()).parts
    return bool(parts) and parts[0] == "dist" and PurePosixPath(path).suffix.lower() in {".js", ".mjs", ".cjs"}


def content_signals(old_files, new_files, diffs: dict[str, str]) -> list[str]:
    """Signals read from action.yml and the shape of the change (phase 2)."""
    found: list[str] = []
    old_manifests = action_manifests(old_files)
    new_manifests = action_manifests(new_files)
    for path, new in new_manifests.items():
        old = old_manifests.get(path)
        if old is None:
            continue
        if (new.pre and not old.pre) or (new.post and not old.post):
            found.append("action_pre_post_added")
        if new.main != old.main or _runtime(new.using) != _runtime(old.using):
            found.append("action_entry_changed")
        if new.image != old.image and old.image_pinned() and not new.image_pinned():
            found.append("action_docker_unpinned")
        old_uses = set(old.uses)
        for ref in new.uses:
            if ref in old_uses or ref.startswith(("./", "docker://")) or "@" not in ref:
                continue
            target = ref.rsplit("@", 1)[1]
            if len(target) != 40:
                found.append("action_new_unpinned_use")
                break
    changed = list(diffs)
    dist_changed = [path for path in changed if _is_dist(path)]
    if dist_changed and not any(_is_dependency_file(path) for path in changed):
        has_source = any(_is_source(path) for path in new_files)
        source_changed = any(_is_source(path) for path in changed)
        if has_source and not source_changed:
            found.append("action_dist_without_source")
    return list(dict.fromkeys(found))


def _routes(signals: list[str], report: RuleReport | None) -> bool:
    """Send to Triage: a strong signal, a malicious rule verdict, two medium signals, or a rule hit with one."""
    strong = [sig for sig in signals if sig in STRONG]
    medium = [sig for sig in signals if sig in MEDIUM or sig in CONTENT_SIGNALS]
    if strong or (report is not None and report.verdict == "malicious"):
        return True
    if len(medium) >= 2:
        return True
    return bool(medium) and report is not None and bool(report.hits)


def action_ref(event, facts: EventFacts) -> dict:
    return {
        "tag": str(event["tag"]),
        "kind": str(event["kind"]),
        "old_tag": facts.old_tag,
        "old_sha": facts.old_sha,
        "new_sha": str(event["new_sha"]),
        "moves_in_poll": int(event["moves_in_poll"] or 0),
        "pin_advice": f"Pin to the previous commit {facts.old_sha}" if facts.old_sha else "",
    }


def _meta(name: str, version: str, rank: int | None, event, facts: EventFacts) -> ReleaseMeta:
    old_version = release_version(facts.old_tag or str(event["tag"]), facts.old_sha) if facts.old_sha else None
    old_login = {facts.old_commit.get("committer_login")} - {""} if facts.old_commit else set()
    new_login = {facts.new_commit.get("committer_login")} - {""} if facts.new_commit else set()
    return ReleaseMeta(
        ecosystem=ECOSYSTEM,
        name=name,
        new_version=version,
        old_version=old_version,
        rank=rank,
        registry_url=release_url(name, str(event["tag"])),
        old_publishers=frozenset(old_login),
        new_publishers=frozenset(new_login),
    )


def _row(meta: ReleaseMeta, *, band: str, probability: float, signals: list[str], ref: dict) -> Classification:
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
        action_ref=ref,
    )


def stored_row(meta: ReleaseMeta, facts: EventFacts, ref: dict) -> Classification:
    """Nothing to read (the ``store`` plan). Benign, no model call."""
    return _row(meta, band="benign", probability=0.0, signals=list(facts.signals), ref=ref)


def _scout_allowed(db, config, event) -> bool:
    if not config.actions_scout or str(event["kind"]) != "new" or config.actions_scout_per_day <= 0:
        return False
    return db.take_action_scout(utcnow().strftime("%Y-%m-%d"), config.actions_scout_per_day)


def review_trees(
    meta: ReleaseMeta,
    old_files,
    new_files,
    facts: EventFacts,
    ref: dict,
    *,
    jev=None,
    popular_names: set[str] | None = None,
) -> Classification:
    """Rules, content signals and (optionally) Scout on both trees, then the routing decision."""
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
    signals = list(facts.signals) + content_signals(old_files, new_files, diffs) + report.signals()
    signals = list(dict.fromkeys(signals))
    if jev is not None:
        from hunter.classify import classify_files

        scout = classify_files(
            meta=meta,
            old_files=old_files,
            new_files=new_files,
            jev=jev,
            popular_names=popular_names,
        )
        scout.signals = list(dict.fromkeys(signals + list(scout.signals)))
        scout.action_ref = ref
        scout.rule_verdict = report.verdict
        scout.rule_hits = report.hit_dicts()
        scout.rule_pack = report.pack_version
        if scout.band == "deferred" or scout.defer_reason:
            return scout
        if _routes(scout.signals, report):
            scout.needs_llm_review = True
            if scout.band == "benign":
                scout.band = "review"
                scout.malice_probability = max(scout.malice_probability, REVIEW_THRESHOLD)
        return scout
    routed = _routes(signals, report)
    strong = any(sig in STRONG for sig in signals) or report.verdict == "malicious"
    if routed:
        row = _row(
            meta,
            band="review",
            probability=STRONG_PROBABILITY if strong else REVIEW_THRESHOLD,
            signals=signals,
            ref=ref,
        )
        row.needs_llm_review = True
    else:
        row = _row(meta, band="benign", probability=0.05, signals=signals, ref=ref)
    row.rule_verdict = report.verdict
    row.rule_hits = report.hit_dicts()
    row.rule_pack = report.pack_version
    return row


def classify_action(
    db,
    config,
    job,
    *,
    client: GitHubClient,
    transport: HttpGet,
    jev=None,
):
    """Signals, trees and a Classification for one Actions job.

    Returns (result, old_files, new_files, meta). The trees are open DiskTrees
    (or empty) that the caller closes after building Triage evidence.
    """
    name = str(job["name"])
    version = str(job["version"])
    rank = job["rank"]
    event = db.action_event(name, version)
    if event is None:
        raise ValueError(f"no tag event recorded for {name} {version}")
    tags = db.action_tags(name)
    state = db.action_state(name)
    default_branch = state["default_branch"] if state is not None else None
    moved_with = frozenset(
        move["tag"]
        for move in db.action_moves(name, since=str(event["seen_at"]))
        if move["kind"] == "moved" and move["seen_at"] == event["seen_at"]
    )
    facts = event_facts(client, name, event, tags, default_branch, moved_with)
    ref = action_ref(event, facts)
    meta = _meta(name, version, rank, event, facts)
    if facts.plan == "store":
        return stored_row(meta, facts, ref), None, None, meta
    old_files, new_files = load_action_trees(transport, client, name, facts.old_sha, facts.new_sha)
    try:
        scout = jev if (jev is not None and _scout_allowed(db, config, event)) else None
        popular = {str(item).lower() for item in db.watch_names(ECOSYSTEM)}
        result = review_trees(meta, old_files, new_files, facts, ref, jev=scout, popular_names=popular)
    except Exception:
        close_trees(old_files, new_files)
        raise
    return result, old_files, new_files, meta

