"""Deterministic tag-move signals. No model calls.

Each event (a new tag or a moved tag) gets a list of signals and a plan:

* ``review``: a strong signal, or two medium ones. Download both sides, run the
  rules, and send the diff to Triage. Analyst confirms before anything alerts.
* ``read``: download both sides and run the rules (and Scout, when enabled for
  new tags). Triage only if the rules or Scout ask for it.
* ``store``: nothing to read. A major tag that followed a release, a tag on a
  commit another tag already names, or an action's first tag. Saved as benign.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import timedelta

from hunter.actions import floating_major, full_version, is_prerelease
from hunter.actions.github import GitHubClient
from hunter.registry import FeedError, parse_time

log = logging.getLogger("hunter.actions.signals")

STRONG = frozenset({"action_semver_tag_moved", "action_many_tags_moved", "action_tag_off_branch"})
MEDIUM = frozenset(
    {
        "action_semver_retagged_quickly",
        "action_major_tag_not_latest",
        "action_major_tag_not_release",
        "action_tag_not_release",
        "action_tag_moved_back",
        "action_tag_rewritten",
        "action_new_tag_off_branch",
    }
)
WEAK = frozenset({"action_signing_dropped", "action_committer_changed"})
BENIGN = frozenset({"action_major_tag_followed_release", "action_same_commit_as_tag", "action_first_release"})
ACTION_SIGNALS = STRONG | MEDIUM | WEAK | BENIGN

MANY_MOVES = 3
QUICK_RETAG = timedelta(hours=1)
RELEASE_BRANCH = re.compile(r"(^|/)(release|releases|stable|v\d+)", re.IGNORECASE)
MAX_RELEASE_BRANCHES = 5


@dataclass
class EventFacts:
    signals: list[str] = field(default_factory=list)
    plan: str = "read"
    old_sha: str | None = None
    old_tag: str | None = None
    new_sha: str = ""
    old_commit: dict | None = None
    new_commit: dict | None = None

    def strong(self) -> list[str]:
        return [sig for sig in self.signals if sig in STRONG]

    def medium(self) -> list[str]:
        return [sig for sig in self.signals if sig in MEDIUM]


def _version_key(tag: str) -> tuple:
    version = full_version(tag) or (0, 0, 0)
    return (*version, not is_prerelease(tag))


def predecessor(tag: str, tags: dict[str, tuple[str, str]]) -> str | None:
    """The newest recorded full version below ``tag``, preferring the same major."""
    target = full_version(tag)
    if target is None:
        return None
    lower = [
        other
        for other in tags
        if other != tag and full_version(other) is not None and full_version(other) < target
    ]
    if not lower:
        return None
    same_major = [other for other in lower if full_version(other)[0] == target[0]]
    pool = same_major or lower
    stable = [other for other in pool if not is_prerelease(other)] or pool
    return max(stable, key=_version_key)


def release_tags_at(sha: str, tags: dict[str, tuple[str, str]], *, major: int | None = None) -> list[str]:
    """Full version tags that point at ``sha`` (in one major when given)."""
    found = []
    for tag, (tag_sha, _seen) in tags.items():
        version = full_version(tag)
        if version is None or tag_sha != sha:
            continue
        if major is not None and version[0] != major:
            continue
        found.append(tag)
    return found


def newest_release(tags: dict[str, tuple[str, str]], major: int) -> str | None:
    candidates = [
        tag for tag in tags if full_version(tag) is not None and full_version(tag)[0] == major and not is_prerelease(tag)
    ]
    return max(candidates, key=_version_key) if candidates else None


def on_branch(client: GitHubClient, name: str, sha: str, default_branch: str | None) -> bool | None:
    """True when ``sha`` is on the default branch or a release branch. None when that could not be checked."""
    try:
        heads = client.ls_refs(name, ["refs/heads/"])
    except FeedError as exc:
        log.info("%s: branch list failed: %s", name, exc)
        heads = None
    branches = heads.branches if heads is not None else {}
    if sha in branches.values():
        return True
    candidates: list[str] = []
    if default_branch:
        candidates.append(default_branch)
    for branch in sorted(branches):
        if branch not in candidates and RELEASE_BRANCH.search(branch) and len(candidates) <= MAX_RELEASE_BRANCHES:
            candidates.append(branch)
    checked = False
    for branch in candidates:
        try:
            status = client.compare(name, branch, sha)
        except FeedError as exc:
            log.info("%s: compare %s...%s failed: %s", name, branch, sha[:12], exc)
            continue
        if status is None:
            continue
        checked = True
        if status in {"behind", "identical"}:
            return True
    return False if checked else None


def _commit(client: GitHubClient, name: str, sha: str | None) -> dict | None:
    if not sha:
        return None
    try:
        return client.commit(name, sha)
    except FeedError as exc:
        log.info("%s: commit %s lookup failed: %s", name, sha[:12], exc)
        return None


def _direction(client: GitHubClient, name: str, old_sha: str, new_sha: str) -> str | None:
    try:
        return client.compare(name, old_sha, new_sha)
    except FeedError as exc:
        log.info("%s: compare %s...%s failed: %s", name, old_sha[:12], new_sha[:12], exc)
        return None


def _plan(facts: EventFacts) -> str:
    if facts.strong() or len(facts.medium()) >= 2:
        return "review"
    if any(sig in BENIGN for sig in facts.signals) and not facts.medium():
        return "store"
    return "read"


def moved_tag_facts(
    client: GitHubClient,
    name: str,
    event,
    tags: dict[str, tuple[str, str]],
    default_branch: str | None,
    moved_with: frozenset[str] = frozenset(),
) -> EventFacts:
    """``moved_with`` names tags that moved in the same poll; a release tag among them proves nothing."""
    tag = str(event["tag"])
    tags = {other: value for other, value in tags.items() if other == tag or other not in moved_with}
    old_sha = str(event["old_sha"] or "")
    new_sha = str(event["new_sha"])
    facts = EventFacts(old_sha=old_sha or None, old_tag=tag, new_sha=new_sha)
    signals = facts.signals
    if int(event["moves_in_poll"] or 0) >= MANY_MOVES:
        signals.append("action_many_tags_moved")
    major = floating_major(tag)
    followed = False
    if full_version(tag) is not None:
        first = parse_time(event["tag_first_seen_at"]) if event["tag_first_seen_at"] else None
        seen = parse_time(event["seen_at"]) if event["seen_at"] else None
        if first is not None and seen is not None and seen - first <= QUICK_RETAG:
            signals.append("action_semver_retagged_quickly")
        else:
            signals.append("action_semver_tag_moved")
    elif major is not None:
        at_new = release_tags_at(new_sha, tags, major=major)
        newest = newest_release(tags, major)
        if at_new and newest in at_new:
            signals.append("action_major_tag_followed_release")
            followed = True
        elif at_new:
            signals.append("action_major_tag_not_latest")
        else:
            signals.append("action_major_tag_not_release")
    else:
        if release_tags_at(new_sha, tags):
            signals.append("action_major_tag_followed_release")
            followed = True
        else:
            signals.append("action_tag_not_release")
    if not followed:
        if old_sha:
            direction = _direction(client, name, old_sha, new_sha)
            if direction == "behind":
                signals.append("action_tag_moved_back")
            elif direction == "diverged":
                signals.append("action_tag_rewritten")
        if on_branch(client, name, new_sha, default_branch) is False:
            signals.append("action_tag_off_branch")
        if client.has_token:
            facts.old_commit = _commit(client, name, old_sha)
            facts.new_commit = _commit(client, name, new_sha)
            _commit_signals(facts)
    facts.plan = _plan(facts)
    return facts


def new_tag_facts(
    client: GitHubClient,
    name: str,
    event,
    tags: dict[str, tuple[str, str]],
    default_branch: str | None,
) -> EventFacts:
    tag = str(event["tag"])
    new_sha = str(event["new_sha"])
    facts = EventFacts(new_sha=new_sha)
    signals = facts.signals
    seen_at = str(event["seen_at"] or "")
    major = floating_major(tag)
    if full_version(tag) is None and release_tags_at(new_sha, tags, major=major):
        # A new floating tag on a release commit; that release is reviewed as its own event.
        signals.append("action_same_commit_as_tag")
    else:
        older = [
            other for other, (sha, first) in tags.items() if other != tag and sha == new_sha and first < seen_at
        ]
        if older:
            signals.append("action_same_commit_as_tag")
    previous = predecessor(tag, tags)
    if previous is not None:
        facts.old_tag = previous
        facts.old_sha = tags[previous][0]
    elif major is not None:
        lower = [other for other in tags if floating_major(other) is not None and floating_major(other) < major]
        if lower:
            best = max(lower, key=lambda other: (floating_major(other), other))
            facts.old_tag = best
            facts.old_sha = tags[best][0]
    if facts.old_sha is None and "action_same_commit_as_tag" not in signals:
        signals.append("action_first_release")
    if facts.old_sha == new_sha:
        signals.append("action_same_commit_as_tag")
    if "action_same_commit_as_tag" not in signals and "action_first_release" not in signals and client.has_token:
        if on_branch(client, name, new_sha, default_branch) is False:
            signals.append("action_new_tag_off_branch")
        facts.old_commit = _commit(client, name, facts.old_sha)
        facts.new_commit = _commit(client, name, new_sha)
        _commit_signals(facts)
    facts.signals = list(dict.fromkeys(signals))
    facts.plan = _plan(facts)
    return facts


def _commit_signals(facts: EventFacts) -> None:
    old, new = facts.old_commit, facts.new_commit
    if not old or not new:
        return
    if old.get("verified") and not new.get("verified"):
        facts.signals.append("action_signing_dropped")
    old_login = old.get("committer_login") or old.get("author_login")
    new_login = new.get("committer_login") or new.get("author_login")
    if old_login and new_login and old_login != new_login and new_login != "web-flow":
        facts.signals.append("action_committer_changed")


def event_facts(
    client: GitHubClient,
    name: str,
    event,
    tags: dict[str, tuple[str, str]],
    default_branch: str | None,
    moved_with: frozenset[str] = frozenset(),
) -> EventFacts:
    if str(event["kind"]) == "moved":
        return moved_tag_facts(client, name, event, tags, default_branch, moved_with)
    return new_tag_facts(client, name, event, tags, default_branch)
