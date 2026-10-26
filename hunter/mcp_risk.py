"""MCP tool and server.json signals for the classify queue, read before Scout.

Off unless HUNTER_MCP_RISK=on. Each pass scores a few pending npm and PyPI
jobs that are already on the MCP watchlist. The score only changes queue
order. It does not change a band, set a rule floor, or enter a model prompt.

A tool description is attacker-controlled text. The stored detail is a signal
id, the tool name, and a short escaped excerpt. That excerpt is not placed in
a Scout, Triage, or Analyst prompt.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from urllib.parse import quote

from hunter.archives import close_trees
from hunter.mcp_manifest import manifest_signals, select_versions, server_detail
from hunter.mcp_tools import diff_tools
from hunter.registry import FeedError, HttpGet, http_get

log = logging.getLogger("hunter.mcp_risk")

ECOSYSTEMS = ("npm", "pypi")
SCORE_CAP = 200
WEIGHTS: dict[str, int] = {
    "tool_instruction_added": 50,
    "tool_hidden_unicode": 40,
    "tool_bidi": 40,
    "capability_shell": 35,
    "capability_network": 25,
    "capability_file": 20,
    "unpinned_version": 30,
    "http_remote": 35,
    "many_required_secrets": 20,
    "many_required_env": 15,
    "missing_repository": 15,
    "repository_changed": 40,
}
_SIGNAL_ORDER = tuple(WEIGHTS)
_MAX_VERSION_PAGES = 20


class _RegistryMiss(Exception):
    """The registry answered 404."""


@dataclass
class McpRisk:
    ecosystem: str
    name: str
    version: str
    server: str = ""
    old_version: str | None = None
    signals: list[str] = field(default_factory=list)
    detail: dict = field(default_factory=dict)
    error: str = ""

    @property
    def score(self) -> int:
        total = sum(WEIGHTS.get(item, 0) for item in self.signals)
        return min(SCORE_CAP, total)


def score_pending_jobs(db, config, loader, limit: int | None = None) -> int:
    """Score pending MCP-watchlist jobs that have no row yet. Returns how many were scored.

    The flag gates the work: off, nothing is downloaded. One failure stores an
    error and score 0 and does not stop the rest of the batch. The job stays
    pending for classify.
    """
    if not getattr(config, "mcp_risk", False):
        return 0
    batch = int(getattr(config, "mcp_risk_batch", 8) if limit is None else limit)
    if batch <= 0:
        return 0
    jobs = db.unscored_mcp_jobs(limit=batch)
    for job in jobs:
        ecosystem, name, version = str(job["ecosystem"]), str(job["name"]), str(job["version"])
        try:
            found = _score_job(config, loader, job)
        except Exception as exc:
            log.exception("mcp risk failed %s %s %s", ecosystem, name, version)
            found = McpRisk(ecosystem, name, version, error=str(exc) or type(exc).__name__)
        try:
            db.save_mcp_risk(
                found.ecosystem,
                found.name,
                found.version,
                found.score,
                found.signals,
                found.detail,
                server=found.server,
                old_version=found.old_version,
                error=found.error,
            )
        except Exception:
            log.exception("mcp risk could not be stored %s %s %s", ecosystem, name, version)
            continue
        if found.signals:
            log.info(
                "mcp risk %s %s %s server=%s score=%s signals=%s",
                found.ecosystem,
                found.name,
                found.version,
                found.server or "-",
                found.score,
                ",".join(found.signals),
            )
    return len(jobs)


def _score_job(config, loader, job) -> McpRisk:
    ecosystem, name, version = str(job["ecosystem"]), str(job["name"]), str(job["version"])
    server = _server_name(job)
    try:
        old_files, new_files, meta = loader.load(ecosystem, name, version, job["rank"])
    except Exception as exc:
        log.exception("mcp risk download failed %s %s %s", ecosystem, name, version)
        return McpRisk(ecosystem, name, version, server=server, error=str(exc) or type(exc).__name__)
    try:
        signals, detail = diff_tools(old_files, new_files)
        old_version = getattr(meta, "old_version", None)
    finally:
        close_trees(old_files, new_files)
    error = ""
    try:
        manifest, manifest_detail, error = _registry_signals(config, loader, ecosystem, name, version, server)
    except Exception as exc:
        log.exception("mcp risk registry failed %s %s %s", ecosystem, name, version)
        manifest, manifest_detail = [], {}
        error = f"registry: {exc}"
    merged = _merge(signals, manifest)
    detail = {**detail, **manifest_detail}
    return McpRisk(
        ecosystem,
        name,
        version,
        server=server,
        old_version=None if old_version is None else str(old_version),
        signals=merged,
        detail=detail,
        error=error,
    )


def _registry_signals(config, loader, ecosystem: str, name: str, version: str, server: str):
    if not server:
        return [], {}, "registry: no server"
    transport = getattr(loader, "transport", None) or http_get
    base = str(getattr(config, "mcp_registry_url", "") or "").rstrip("/")
    try:
        documents = _version_documents(transport, base, server)
    except _RegistryMiss:
        return [], {}, "registry: not found"
    except FeedError as exc:
        return [], {}, f"registry: {exc}"
    if not documents:
        return [], {}, "registry: not found"
    current, previous = select_versions(documents, ecosystem, name, version)
    if current is None:
        return [], {}, "registry: not found"
    secret_min = int(getattr(config, "mcp_secret_min", 5))
    env_min = int(getattr(config, "mcp_env_min", 8))
    signals, detail = manifest_signals(
        server_detail(current),
        None if previous is None else server_detail(previous),
        secret_min=secret_min,
        env_min=env_min,
    )
    return signals, detail, ""


def _version_documents(transport: HttpGet, base: str, server: str) -> list[dict]:
    """GET the version list, then each version document. Order is applied later by publication time."""
    listed = _list_versions(transport, base, server)
    documents: list[dict] = []
    for entry in listed:
        version = str(server_detail(entry).get("version") or entry.get("version") or "")
        if not version:
            continue
        url = f"{base}/v0.1/servers/{quote(server, safe='')}/versions/{quote(version, safe='')}"
        try:
            document = _get_json(transport, url)
        except _RegistryMiss:
            document = entry
        if not isinstance(document.get("_meta"), dict) and isinstance(entry.get("_meta"), dict):
            document = dict(document)
            document["_meta"] = entry["_meta"]
        documents.append(document)
    return documents


def _list_versions(transport: HttpGet, base: str, server: str) -> list[dict]:
    url = f"{base}/v0.1/servers/{quote(server, safe='')}/versions"
    found: list[dict] = []
    cursor = ""
    seen: set[str] = set()
    for _page in range(_MAX_VERSION_PAGES):
        page_url = url if not cursor else f"{url}?cursor={quote(cursor, safe='')}"
        page = _get_json(transport, page_url)
        servers = page.get("servers") if isinstance(page, dict) else None
        if isinstance(servers, list):
            found.extend(item for item in servers if isinstance(item, dict))
        metadata = page.get("metadata") if isinstance(page, dict) else None
        nxt = ""
        if isinstance(metadata, dict):
            nxt = str(metadata.get("nextCursor") or metadata.get("next_cursor") or "")
        if not nxt or nxt in seen or nxt == cursor:
            break
        seen.add(nxt)
        cursor = nxt
    return found


def _get_json(transport: HttpGet, url: str, timeout: float = 30.0) -> dict:
    try:
        blob = transport(url, timeout)
    except Exception as exc:
        if _not_found(exc):
            raise _RegistryMiss(url) from None
        raise FeedError(str(exc) or type(exc).__name__) from exc
    try:
        data = json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FeedError(f"not json: {exc}") from exc
    if not isinstance(data, dict):
        raise FeedError("registry did not return an object")
    return data


def _not_found(exc: BaseException) -> bool:
    import urllib.error

    seen: BaseException | None = exc
    while seen is not None:
        if isinstance(seen, urllib.error.HTTPError) and seen.code == 404:
            return True
        text = str(seen).lower()
        if "404" in text or "not found" in text:
            return True
        seen = seen.__cause__ or seen.__context__
    return False


def _server_name(job) -> str:
    try:
        return str(job["server"] or "")
    except (KeyError, IndexError, TypeError):
        return ""


def _merge(tool_signals: list[str], manifest: list[str]) -> list[str]:
    found = set(tool_signals) | set(manifest)
    return [name for name in _SIGNAL_ORDER if name in found]
