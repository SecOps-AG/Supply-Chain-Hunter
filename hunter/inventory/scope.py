"""What the user watchlist changes downstream: which alerts send, what they say, and public publishing."""

from __future__ import annotations

from datetime import timedelta

from hunter.actions import ECOSYSTEM as ACTIONS_ECOSYSTEM
from hunter.actions import is_sha, split_version
from hunter.db import Database, utcnow
from hunter.inventory import CASE_FOLDED
from hunter.registry import parse_time

STALE_AFTER = timedelta(days=7)
MAX_PINNED_SHOWN = 10
MAX_SOURCES_SHOWN = 5
PUBLIC_BLOCKED = "disabled: private watchlist present"


def alert_in_scope(db: Database, config, ecosystem: str, name: str) -> bool:
    """True when the webhook may send for this package. Scope ``all`` always sends."""
    if getattr(config, "alert_scope", "all") != "watched":
        return True
    return (name.lower() if ecosystem in CASE_FOLDED else name) in db.user_watch_names(ecosystem)


def is_stale(stamp: str | None, now=None) -> bool:
    parsed = parse_time(stamp) if stamp else None
    return parsed is not None and (now or utcnow()) - parsed > STALE_AFTER


def watch_context(db: Database, ecosystem: str, name: str, version: str, now=None) -> dict | None:
    """How the imported files list this package, or None when it is not listed.

    For GitHub Actions the confirmed version is ``tag@sha12``. A listed 40-hex sha
    that starts with that sha is an exact match. A listed ref equal to the tag is
    also a match (``tag_ref``): the workflow's tag pointed at this commit.
    """
    entries = db.user_watch_entries(ecosystem, name.lower() if ecosystem in CASE_FOLDED else name)
    if not entries:
        return None
    pinned: list[str] = []
    sources: list[str] = []
    for entry in entries:
        listed = str(entry.get("version") or "")
        if listed and listed not in pinned:
            pinned.append(listed)
        source = str(entry.get("source") or "")
        if source and source not in sources:
            sources.append(source)
    stamps = [str(entry["imported_at"]) for entry in entries if entry.get("imported_at")]
    oldest = min(stamps) if stamps else None
    exact = False
    tag_ref = False
    if ecosystem == ACTIONS_ECOSYSTEM:
        tag, short = split_version(version)
        short = short.lower()
        for listed in pinned:
            if short and is_sha(listed) and listed.lower().startswith(short):
                exact = True
            elif tag and listed == tag:
                exact = True
                tag_ref = True
    else:
        exact = version in pinned
    context = {
        "listed": True,
        "direct": any(entry.get("direct") == 1 for entry in entries),
        "pinned_versions": pinned[:MAX_PINNED_SHOWN],
        "exact_match": exact,
        "sources": sources[:MAX_SOURCES_SHOWN],
        "oldest_import_at": oldest,
        "stale": is_stale(oldest, now),
    }
    if tag_ref:
        context["tag_ref"] = True
    return context


def public_publish_blocked(db: Database, config) -> str | None:
    """Why the public feed and dashboard must not publish, or None. Any user watchlist blocks both."""
    if getattr(config, "watch_mode", "all") == "watched" or db.has_user_watch():
        return PUBLIC_BLOCKED
    return None
