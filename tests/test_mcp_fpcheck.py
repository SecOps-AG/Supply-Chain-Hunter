"""Static false-positive check for public MCP packages.

Skipped unless HUNTER_MCP_FPCHECK=1. Downloads registry tarballs and sdists
and reads them as text. No install, no interpreter. Instruction, hidden
character, and bidi signals must be empty. Capability diffs are printed.
Manifest signals are printed, except the negative-control server must not
show an unpinned version, a cleartext remote, or a repository move.
"""

import json
import os
from urllib.parse import quote

import pytest

from hunter.archives import close_trees, extract_archive
from hunter.config import MCP_REGISTRY_URL
from hunter.mcp_manifest import manifest_signals, order_versions, server_detail
from hunter.mcp_risk import _get_json
from hunter.mcp_tools import diff_tools
from hunter.registry import PACKAGE_DOWNLOAD_MAX_BYTES, fetch_capped, http_get

pytestmark = pytest.mark.skipif(
    os.environ.get("HUNTER_MCP_FPCHECK") != "1",
    reason="set HUNTER_MCP_FPCHECK=1 to download public MCP packages",
)

NPM = (
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-brave-search",
    "@modelcontextprotocol/server-everything",
    "@brave/brave-search-mcp-server",
    "@playwright/mcp",
)
PYPI = ("mcp-server-git", "mcp-server-fetch", "mcp-server-time")
MANIFEST_CONTROL = "io.github.brave/brave-search-mcp-server"
_QUIET = {"tool_instruction_added", "tool_hidden_unicode", "tool_bidi"}
_MANIFEST_QUIET = {"unpinned_version", "http_remote", "repository_changed"}


def test_public_packages_do_not_add_instruction_text():
    for name in NPM:
        _assert_package("npm", name, _npm_pair(name))
    for name in PYPI:
        _assert_package("pypi", name, _pypi_pair(name))
    _assert_manifest_control()
    for name in NPM:
        _print_manifest("npm", name)
    for name in PYPI:
        _print_manifest("pypi", name)


def _assert_package(ecosystem: str, name: str, pair: tuple[object, object, str, str]) -> None:
    old, new, old_version, new_version = pair
    try:
        signals, detail = diff_tools(old, new)
    finally:
        close_trees(old, new)
    print(f"{ecosystem} {name} {old_version} -> {new_version} signals={signals or '-'}")
    for signal, hits in detail.items():
        if signal.startswith("capability_"):
            print(f"  {signal}: {hits}")
    assert not (set(signals) & _QUIET), (name, signals, detail)


def _assert_manifest_control() -> None:
    current, previous = _registry_pair(MANIFEST_CONTROL)
    signals, detail = manifest_signals(server_detail(current), None if previous is None else server_detail(previous))
    print(f"manifest {MANIFEST_CONTROL} signals={signals or '-'} detail={detail}")
    assert not (set(signals) & _MANIFEST_QUIET), (MANIFEST_CONTROL, signals, detail)


def _print_manifest(ecosystem: str, package: str) -> None:
    try:
        server = _find_server(ecosystem, package)
    except Exception as exc:
        print(f"manifest {ecosystem} {package}: lookup failed ({exc})")
        return
    if not server:
        print(f"manifest {ecosystem} {package}: no registry server")
        return
    try:
        current, previous = _registry_pair(server)
    except Exception as exc:
        print(f"manifest {server}: {exc}")
        return
    signals, _detail = manifest_signals(server_detail(current), None if previous is None else server_detail(previous))
    print(f"manifest {server} for {package}: {signals or '-'}")


def _npm_pair(name: str):
    document = json.loads(http_get(f"https://registry.npmjs.org/{quote(name, safe='@')}", 60).decode())
    times = []
    for version, stamp in (document.get("time") or {}).items():
        if version in {"created", "modified"}:
            continue
        times.append((str(stamp), str(version)))
    times.sort()
    assert len(times) >= 2, name
    old_version, new_version = times[-2][1], times[-1][1]
    versions = document.get("versions") or {}
    return (
        _tarball((versions.get(old_version) or {}).get("dist") or {}),
        _tarball((versions.get(new_version) or {}).get("dist") or {}),
        old_version,
        new_version,
    )


def _pypi_pair(name: str):
    document = json.loads(http_get(f"https://pypi.org/pypi/{quote(name)}/json", 60).decode())
    releases = document.get("releases") or {}
    stamped = []
    for version, files in releases.items():
        sdists = [item for item in files or [] if item.get("packagetype") == "sdist" and item.get("url")]
        if not sdists:
            continue
        stamp = str(sdists[0].get("upload_time_iso_8601") or "")
        stamped.append((stamp, str(version), sdists[0]))
    stamped.sort()
    assert len(stamped) >= 2, name
    old, new = stamped[-2], stamped[-1]
    return _sdist(old[2]), _sdist(new[2]), old[1], new[1]


def _tarball(dist: dict):
    url = str(dist.get("tarball") or "")
    assert url
    path = fetch_capped(http_get, url, 90, PACKAGE_DOWNLOAD_MAX_BYTES)
    try:
        return extract_archive(path)
    finally:
        path.unlink(missing_ok=True)


def _sdist(chosen: dict):
    path = fetch_capped(http_get, str(chosen["url"]), 90, PACKAGE_DOWNLOAD_MAX_BYTES)
    try:
        return extract_archive(path)
    finally:
        path.unlink(missing_ok=True)


def _registry_pair(server: str) -> tuple[dict, dict | None]:
    quoted = quote(server, safe="")
    page = _get_json(http_get, f"{MCP_REGISTRY_URL}/v0.1/servers/{quoted}/versions")
    entries = [item for item in (page.get("servers") or []) if isinstance(item, dict)]
    ordered = order_versions(entries)
    assert ordered, server
    current = ordered[-1]
    previous = ordered[-2] if len(ordered) > 1 else None
    return current, previous


def _find_server(ecosystem: str, package: str) -> str:
    query = quote(package.split("/")[-1], safe="")
    page = _get_json(http_get, f"{MCP_REGISTRY_URL}/v0.1/servers?search={query}&version=latest&limit=100")
    for entry in page.get("servers") or []:
        body = server_detail(entry)
        for item in body.get("packages") or []:
            if not isinstance(item, dict):
                continue
            kind = str(item.get("registryType") or "").lower()
            identifier = str(item.get("identifier") or "")
            if kind == ecosystem and identifier.lower() == package.lower():
                return str(body.get("name") or "")
    return ""
