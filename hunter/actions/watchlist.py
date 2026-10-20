"""Which GitHub Actions to watch, refreshed weekly.

Actions have no download counts, so "popular" means how many repositories use
an action. The list is built from three sources and capped at ``actions_max``:

A. The most-used actions by dependent repositories, from ecosyste.ms.
B. Every action used in the workflows of the source repositories behind the
   npm and PyPI watchlists. A compromised publishing action poisons a package.
   Needs a GitHub token (GraphQL); skipped without one.
C. The actions those actions call one level down (composite ``uses:``).

Ranks: source A by dependent count, then B by how many watched packages use the
action, then C. ``HUNTER_ACTIONS_EXTRA`` names are always watched, first.
"""

from __future__ import annotations

import json
import logging
import re
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

from hunter.actions import ECOSYSTEM, normalize_name
from hunter.actions.github import GitHubClient
from hunter.actions.manifest import ACTION_FILES, parse_action, used_actions
from hunter.db import Database
from hunter.registry import FeedError, HttpGet, http_get

log = logging.getLogger("hunter.actions.watchlist")

TOP_PAGE_SIZE = 100
TOP_MAX_PAGES = 200
META_WORKERS = 8
_GITHUB_URL = re.compile(r"github\.com[/:]+([A-Za-z0-9][A-Za-z0-9-]*)/([A-Za-z0-9._-]+)", re.IGNORECASE)
_SHORTHAND = re.compile(r"^(?:github:)?([A-Za-z0-9][A-Za-z0-9-]*)/([A-Za-z0-9._-]+)$")


def github_repo_from_url(raw: object, *, shorthand: bool = False) -> str | None:
    """``owner/repo`` from a repository URL such as ``git+https://github.com/o/r.git``."""
    text = str(raw or "").strip()
    if not text:
        return None
    match = _GITHUB_URL.search(text)
    if match is None and shorthand:
        match = _SHORTHAND.match(text)
    if match is None:
        return None
    return normalize_name(f"{match.group(1)}/{match.group(2)}")


def _page_url(base: str, page: int) -> str:
    joiner = "&" if "?" in base else "?"
    return f"{base}{joiner}sort=dependent_repos_count&order=desc&per_page={TOP_PAGE_SIZE}&page={page}"


def load_top_actions(top_n: int, url: str, transport: HttpGet = http_get) -> tuple[list[tuple[str, int]], dict[str, set[str]]]:
    """Most-used actions as (owner/repo, dependent repos), best first, plus sub-paths seen per repo."""
    best: dict[str, int] = {}
    order: list[str] = []
    subpaths: dict[str, set[str]] = {}
    if top_n <= 0:
        return [], subpaths
    for page in range(1, TOP_MAX_PAGES + 1):
        blob = transport(_page_url(url, page), 60)
        try:
            rows = json.loads(blob.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FeedError("actions top list is not JSON") from exc
        if not isinstance(rows, list) or not rows:
            break
        for row in rows:
            if not isinstance(row, dict):
                continue
            raw_name = str(row.get("name") or "")
            name = github_repo_from_url(row.get("repository_url")) or normalize_name(raw_name)
            if name is None:
                continue
            count = int(row.get("dependent_repos_count") or 0)
            if name not in best:
                order.append(name)
                best[name] = count
            else:
                best[name] = max(best[name], count)
            parts = raw_name.strip("/").split("/")
            if len(parts) > 2:
                subpaths.setdefault(name, set()).add("/".join(parts[2:]))
        if len(order) >= top_n:
            break
    ranked = sorted(order, key=lambda item: best[item], reverse=True)[:top_n]
    return [(name, best[name]) for name in ranked], subpaths


def _npm_repo(name: str, registry: str, transport: HttpGet) -> str | None:
    blob = transport(f"{registry.rstrip('/')}/{quote(name, safe='@')}/latest", 30)
    document = json.loads(blob.decode("utf-8"))
    repository = document.get("repository") if isinstance(document, dict) else None
    if isinstance(repository, dict):
        repository = repository.get("url")
    return github_repo_from_url(repository, shorthand=True)


def _pypi_repo(name: str, base: str, transport: HttpGet) -> str | None:
    blob = transport(f"{base.rstrip('/')}/{quote(name)}/json", 30)
    document = json.loads(blob.decode("utf-8"))
    info = (document.get("info") or {}) if isinstance(document, dict) else {}
    urls = info.get("project_urls") or {}
    candidates = list(urls.values()) if isinstance(urls, dict) else []
    candidates += [info.get("home_page"), info.get("download_url")]
    for value in candidates:
        repo = github_repo_from_url(value)
        if repo:
            return repo
    return None


def package_source_repos(db: Database, config, transport: HttpGet = http_get) -> dict[str, int]:
    """GitHub source repositories of the watched npm and PyPI packages, with how many packages each backs."""
    jobs = [("npm", name) for name in db.watch_names("npm")] + [("pypi", name) for name in db.watch_names("pypi")]

    def _one(item: tuple[str, str]) -> str | None:
        ecosystem, name = item
        try:
            if ecosystem == "npm":
                return _npm_repo(name, config.npm_registry, transport)
            return _pypi_repo(name, config.pypi_base, transport)
        except Exception as exc:  # one bad package does not stop the list
            log.debug("no source repo for %s %s: %s", ecosystem, name, exc)
            return None

    counts: Counter = Counter()
    with ThreadPoolExecutor(max_workers=META_WORKERS) as pool:
        for repo in pool.map(_one, jobs):
            if repo:
                counts[repo] += 1
    return dict(counts)


def actions_used_by(client: GitHubClient, repos: list[str]) -> Counter:
    """How many of ``repos`` use each action in their workflows."""
    counts: Counter = Counter()
    for start in range(0, len(repos), 200):
        chunk = repos[start : start + 200]
        try:
            texts = client.workflow_uses(chunk)
        except FeedError as exc:
            log.warning("workflow read failed for %d repos: %s", len(chunk), exc)
            continue
        for _repo, files in texts.items():
            used: set[str] = set()
            for text in files:
                used.update(used_actions(text))
            counts.update(used)
    return counts


def nested_actions(client: GitHubClient, parents: list[str], subpaths: dict[str, set[str]]) -> list[str]:
    """Actions that the given actions call from their own ``action.yml`` (one level)."""

    def _one(name: str) -> list[str]:
        found: list[str] = []
        folders = [""] + sorted(subpaths.get(name, ()))
        for folder in folders[:6]:
            for file_name in ACTION_FILES:
                path = f"{folder}/{file_name}" if folder else file_name
                try:
                    text = client.raw_file(name, "HEAD", path)
                except FeedError:
                    text = None
                if text is None:
                    continue
                manifest = parse_action(path, text)
                for ref in manifest.uses:
                    if ref.startswith(("./", "docker://")) or "@" not in ref:
                        continue
                    child = normalize_name(ref.split("@", 1)[0])
                    if child and child != name and child not in found:
                        found.append(child)
                break
        return found

    children: list[str] = []
    with ThreadPoolExecutor(max_workers=META_WORKERS) as pool:
        for found in pool.map(_one, parents):
            for child in found:
                if child not in children:
                    children.append(child)
    return children


def build_actions_watchlist(
    db: Database,
    config,
    transport: HttpGet = http_get,
    client: GitHubClient | None = None,
) -> tuple[list[tuple[str, int, int]], list[tuple[str, str, int | None, int]]]:
    """Watchlist rows (name, rank, dependents) and meta rows (name, sources, dependents, used_by_packages)."""
    client = client or GitHubClient(config.github_token)
    sources: dict[str, set[str]] = {}
    dependents: dict[str, int] = {}
    used_by: Counter = Counter()
    order: list[str] = []

    def _add(name: str, source: str) -> None:
        if name not in sources:
            sources[name] = set()
            order.append(name)
        sources[name].add(source)

    for name in config.actions_extra:
        clean = normalize_name(name)
        if clean:
            _add(clean, "extra")

    subpaths: dict[str, set[str]] = {}
    try:
        top, subpaths = load_top_actions(config.actions_top_n, config.actions_top_url, transport)
        for name, count in top:
            dependents[name] = count
            _add(name, "top")
    except (FeedError, OSError, ValueError) as exc:
        log.warning("most-used actions list unavailable (%s); using the other sources", exc)

    if config.actions_from_packages and client.has_token:
        repos = package_source_repos(db, config, transport)
        log.info("actions watchlist: %d package source repos", len(repos))
        used_by = actions_used_by(client, sorted(repos))
        for name, _count in sorted(used_by.items(), key=lambda item: (-item[1], item[0])):
            _add(name, "packages")
    elif config.actions_from_packages:
        log.info("actions watchlist: no GitHub token, skipping the package source repos")

    parents = list(order)[: config.actions_max]
    for name in nested_actions(client, parents, subpaths):
        _add(name, "nested")

    names = order[: config.actions_max]
    rows = [(name, rank, dependents.get(name, 0)) for rank, name in enumerate(names, start=1)]
    meta = [
        (name, ",".join(sorted(sources[name])), dependents.get(name), int(used_by.get(name, 0)))
        for name in names
    ]
    return rows, meta


def refresh_actions_watchlist(
    db: Database,
    config,
    transport: HttpGet = http_get,
    client: GitHubClient | None = None,
) -> int:
    rows, meta = build_actions_watchlist(db, config, transport, client)
    if not rows:
        log.warning("actions watchlist is empty; keeping the previous list")
        return 0
    db.replace_watchlist(ECOSYSTEM, rows)
    db.replace_action_watch_meta(meta)
    log.info("actions watchlist refreshed: %d actions", len(rows))
    return len(rows)
