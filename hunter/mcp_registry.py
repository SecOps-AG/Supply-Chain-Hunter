"""Official MCP server registry as a watchlist source. Metadata only; nothing is installed.

Most MCP servers ship as an npm or PyPI package, and many are far below the
download rank the npm and PyPI watchlists keep. Each server entry's npm and PyPI
packages are added to the watch, so their new releases go through the same
rules, Scout, Triage and Analyst as any watched package.

The registry asks aggregators to poll about once an hour with ``updated_since``
and to follow ``metadata.nextCursor``. The first poll reads the whole registry.
"""

from __future__ import annotations

import json
import logging
import re
import threading
from urllib.parse import quote

from hunter.db import Database, iso, utcnow
from hunter.registry import FeedError, HttpGet, http_get, normalize_pypi_name

log = logging.getLogger("hunter.mcp_registry")

CHECKPOINT = "mcp"
POLL_NAME = "mcp"
PAGE_LIMIT = 100
# A full first read of the registry is a few hundred pages at most.
MAX_PAGES = 2000
_OFFICIAL_META = "io.modelcontextprotocol.registry/official"
# Packages hosted on another npm or PyPI instance are not on the public feeds Hunter reads.
_NPM_HOSTS = {"https://registry.npmjs.org", "https://registry.npmjs.com"}
_PYPI_HOSTS = {"https://pypi.org", "https://pypi.org/simple", "https://pypi.python.org"}
_NPM_NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$")
_PYPI_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$")


def servers_url(base: str, *, updated_since: str | None, cursor: str | None, limit: int = PAGE_LIMIT) -> str:
    query = [f"limit={int(limit)}"]
    if updated_since:
        query.append(f"updated_since={quote(updated_since, safe='')}")
    if cursor:
        query.append(f"cursor={quote(cursor, safe='')}")
    return f"{base.rstrip('/')}/v0.1/servers?{'&'.join(query)}"


def fetch_servers_page(base: str, *, updated_since: str | None, cursor: str | None, transport: HttpGet = http_get) -> dict:
    data = json.loads(transport(servers_url(base, updated_since=updated_since, cursor=cursor), 60).decode("utf-8"))
    if not isinstance(data, dict):
        raise FeedError("MCP registry did not return a JSON object")
    return data


def _host(raw: object) -> str:
    return str(raw or "").strip().rstrip("/").lower()


def package_name(package: object) -> tuple[str, str] | None:
    """(ecosystem, name) for an npm or PyPI package entry on the public registry, else None."""
    if not isinstance(package, dict):
        return None
    kind = str(package.get("registryType") or package.get("registry_type") or "").strip().lower()
    identifier = str(package.get("identifier") or package.get("name") or "").strip()
    host = _host(package.get("registryBaseUrl") or package.get("registry_base_url"))
    if not identifier:
        return None
    if kind == "npm":
        if host and host not in _NPM_HOSTS:
            return None
        name = identifier.lower()
        return ("npm", name) if _NPM_NAME.match(name) else None
    if kind == "pypi":
        if host and host not in _PYPI_HOSTS:
            return None
        name = normalize_pypi_name(identifier)
        return ("pypi", name) if _PYPI_NAME.match(name) else None
    return None


def server_packages(entry: object) -> list[tuple[str, str, str]]:
    """(ecosystem, name, server name) rows for one ``servers[]`` entry."""
    if not isinstance(entry, dict):
        return []
    server = entry.get("server") if isinstance(entry.get("server"), dict) else entry
    server_name = str(server.get("name") or "").strip()[:200]
    found: list[tuple[str, str, str]] = []
    for package in server.get("packages") or []:
        pair = package_name(package)
        if pair is not None and (*pair, server_name) not in found:
            found.append((*pair, server_name))
    return found


def entry_updated_at(entry: object) -> str | None:
    if not isinstance(entry, dict):
        return None
    meta = entry.get("_meta") or {}
    official = meta.get(_OFFICIAL_META) if isinstance(meta, dict) else None
    if not isinstance(official, dict):
        return None
    stamp = official.get("updatedAt") or official.get("publishedAt")
    return str(stamp) if stamp else None


def poll_mcp_registry(
    db: Database,
    config,
    transport: HttpGet = http_get,
    stop: threading.Event | None = None,
) -> int:
    """Read servers updated since the checkpoint and add their packages. Returns new package names.

    The checkpoint moves only after every page was read. A poll that fails part
    way reads the same window again next time; adding a package twice is harmless.
    """
    since = db.get_checkpoint(CHECKPOINT)
    started = iso(utcnow())
    newest = since or ""
    cursor: str | None = None
    added = 0
    servers = 0
    for _page in range(MAX_PAGES):
        if stop is not None and stop.is_set():
            return added
        page = fetch_servers_page(config.mcp_registry_url, updated_since=since, cursor=cursor, transport=transport)
        entries = page.get("servers") or []
        if not isinstance(entries, list):
            raise FeedError("MCP registry servers is not a list")
        rows: list[tuple[str, str, str]] = []
        for entry in entries:
            servers += 1
            rows.extend(server_packages(entry))
            stamp = entry_updated_at(entry)
            if stamp and stamp > newest:
                newest = stamp
        added += db.add_mcp_packages(rows)
        metadata = page.get("metadata") or {}
        following = (metadata.get("nextCursor") or metadata.get("next_cursor")) if isinstance(metadata, dict) else None
        if not entries or not following or following == cursor:
            break
        cursor = str(following)
    else:
        log.warning("MCP registry: stopped after %s pages", MAX_PAGES)
    # Without any updatedAt, fall back to the time this poll began.
    db.set_checkpoint(CHECKPOINT, newest or started)
    db.mark_poll_success(POLL_NAME)
    log.info("MCP registry: %s servers read, %s new packages watched", servers, added)
    return added
