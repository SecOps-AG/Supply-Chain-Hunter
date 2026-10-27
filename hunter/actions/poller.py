"""Poll the tags of every watched action and record where each one points.

The record of tag -> commit sha is the baseline. Git keeps old commits but not
tag history, so once a tag moves, GitHub cannot say where it pointed before;
Hunter has to have written it down. With the old sha known, both sides of the
change can still be downloaded by sha when the job runs.

The first poll of an action records its tags and raises nothing. After that, a
tag Hunter has not seen is a ``new`` event and a known tag that points at a
different commit is a ``moved`` event. Each event becomes a release job.
"""

from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

from hunter.actions import ECOSYSTEM, floating_major, full_version, is_prerelease, release_version
from hunter.actions.github import GitHubClient, RateLimited, RefList
from hunter.db import Database, iso, utcnow
from hunter.registry import FeedError, parse_time

log = logging.getLogger("hunter.actions.poller")

SWEEP_CHECKPOINT = "github-actions-sweep"
# An action not polled for this long is recorded again from scratch, without events.
RESEED_AFTER = timedelta(days=2)
# Jobs per action per poll. The rest of a burst is still recorded in the baseline.
MAX_NEW_EVENTS = 20
MAX_MOVE_EVENTS = 5


def _tag_priority(tag: str) -> tuple:
    """Most-used tags first: floating majors, then full versions newest first, then the rest."""
    major = floating_major(tag)
    if major is not None:
        return (0, -major, tag)
    version = full_version(tag)
    if version is not None:
        return (1, is_prerelease(tag), tuple(-part for part in version), tag)
    return (2, tag)


def diff_tags(
    stored: dict[str, tuple[str, str]],
    refs: RefList,
) -> tuple[dict[str, str], dict[str, tuple[str, str]], dict[str, str]]:
    """(added, moved, deleted) between the recorded tags and this read."""
    added: dict[str, str] = {}
    moved: dict[str, tuple[str, str]] = {}
    for tag, sha in refs.tags.items():
        known = stored.get(tag)
        if known is None:
            added[tag] = sha
        elif known[0] != sha:
            moved[tag] = (known[0], sha)
    deleted: dict[str, str] = {}
    if refs.complete:
        deleted = {tag: sha for tag, (sha, _seen) in stored.items() if tag not in refs.tags}
    return added, moved, deleted


def events_for(
    stored: dict[str, tuple[str, str]],
    added: dict[str, str],
    moved: dict[str, tuple[str, str]],
) -> list[dict]:
    events: list[dict] = []
    for tag in sorted(moved, key=_tag_priority)[:MAX_MOVE_EVENTS]:
        old_sha, new_sha = moved[tag]
        events.append(
            {
                "version": release_version(tag, new_sha),
                "tag": tag,
                "kind": "moved",
                "old_sha": old_sha,
                "new_sha": new_sha,
                "moves_in_poll": len(moved),
                "tag_first_seen_at": stored[tag][1],
            }
        )
    for tag in sorted(added, key=_tag_priority)[:MAX_NEW_EVENTS]:
        events.append(
            {
                "version": release_version(tag, added[tag]),
                "tag": tag,
                "kind": "new",
                "old_sha": None,
                "new_sha": added[tag],
                "moves_in_poll": len(moved),
                "tag_first_seen_at": None,
            }
        )
    if len(moved) > MAX_MOVE_EVENTS or len(added) > MAX_NEW_EVENTS:
        log.warning(
            "tag burst: %d moved, %d new; queued %d jobs, the rest is recorded only",
            len(moved),
            len(added),
            len(events),
        )
    return events


def _needs_seed(state, now: datetime) -> bool:
    if state is None or not state["seeded_at"]:
        return True
    polled = parse_time(state["last_polled_at"]) if state["last_polled_at"] else None
    return polled is None or now - polled > RESEED_AFTER


def apply_refs(
    db: Database,
    name: str,
    refs: RefList | None,
    *,
    rank: int | None,
    state,
    sweep: bool,
    now: datetime | None = None,
    max_pending: int | None = None,
) -> int:
    """Record one action's tags and queue its events. Returns jobs queued."""
    moment = now or utcnow()
    if refs is None:
        db.mark_action_error(name, "repository not found or not public", when=moment)
        return 0
    seed = _needs_seed(state, moment)
    if seed and state is not None and state["seeded_at"]:
        log.info("%s was not polled for %s; recording its tags again", name, RESEED_AFTER)
        db.reseed_action(name)
    stored = {} if seed else db.action_tags(name)
    added, moved, deleted = diff_tags(stored, refs)
    events = [] if seed else events_for(stored, added, moved)
    for tag, (old_sha, new_sha) in moved.items():
        log.info("action tag moved %s %s %s -> %s", name, tag, old_sha[:12], new_sha[:12])
    return db.record_action_poll(
        name,
        seen=refs.tags,
        moved=moved,
        added=added,
        deleted=deleted,
        events=events,
        rank=rank,
        default_branch=refs.default_branch,
        seed=seed,
        sweep=sweep and refs.complete,
        when=moment,
        max_pending=max_pending,
    )


def sweep_due(db: Database, config, now: datetime | None = None) -> bool:
    stamp = db.get_checkpoint(SWEEP_CHECKPOINT)
    parsed = parse_time(stamp) if stamp else None
    moment = now or utcnow()
    return parsed is None or (moment - parsed).total_seconds() >= config.actions_sweep_interval


def poll_actions(
    db: Database,
    config,
    client: GitHubClient,
    *,
    stop: threading.Event | None = None,
    now: datetime | None = None,
) -> int:
    """One poll of every watched action. Returns jobs queued.

    With a token, one GraphQL query reads the newest tags of 50 actions, and a
    daily sweep reads every tag over git. Without a token every poll reads every
    tag over git. An action that has never been recorded is always read over git,
    so its whole baseline is written at once.
    """
    moment = now or utcnow()
    watch = db.poll_targets(
        ECOSYSTEM,
        include_ranked=getattr(config, "watch_mode", "all") != "watched",
        include_mcp=False,
        include_user=True,
    )
    if not watch:
        return 0
    states = db.action_states()
    sweep = not client.has_token or sweep_due(db, config, moment)
    # Names only on the user watchlist have no rank; they sort after the ranked ones.
    names = sorted(watch, key=lambda item: (watch[item] is None, watch[item] or 0, item))
    over_git = [name for name in names if sweep or _needs_seed(states.get(name), moment)]
    over_graphql = [name for name in names if name not in set(over_git)]
    queued = 0

    if over_graphql:
        try:
            read = client.tags_graphql(over_graphql)
        except RateLimited:
            raise
        except FeedError as exc:
            log.warning("GraphQL tag read failed (%s); reading over git this poll", exc)
            over_git.extend(over_graphql)
            read = {}
        for name, refs in read.items():
            if stop is not None and stop.is_set():
                return queued
            queued += apply_refs(
                db, name, refs, rank=watch.get(name), state=states.get(name), sweep=False,
                now=moment, max_pending=config.max_pending,
            )

    def _read(name: str) -> tuple[str, RefList | None, str]:
        if stop is not None and stop.is_set():
            return name, None, "stopped"
        try:
            return name, client.ls_refs(name), ""
        except RateLimited:
            raise
        except (FeedError, OSError) as exc:
            return name, None, str(exc) or exc.__class__.__name__

    if over_git:
        with ThreadPoolExecutor(max_workers=max(1, config.actions_poll_workers)) as pool:
            for name, refs, error in pool.map(_read, over_git):
                if error == "stopped":
                    return queued
                if error:
                    db.mark_action_error(name, error, when=moment)
                    continue
                queued += apply_refs(
                    db, name, refs, rank=watch.get(name), state=states.get(name), sweep=True,
                    now=moment, max_pending=config.max_pending,
                )
    if sweep and client.has_token and set(over_git) >= set(names):
        db.set_checkpoint(SWEEP_CHECKPOINT, iso(moment), when=moment)
    if queued:
        log.info("actions poll queued %d tag events", queued)
    return queued
