"""Pure checks on one MCP registry server document and the previous one.

A cleartext http URL and a missing repository are priority signals. They are
common on remote-only servers and are not a verdict. Nothing here is fetched
or executed.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from hunter.registry import normalize_pypi_name

OFFICIAL_META = "io.modelcontextprotocol.registry/official"

_MANIFEST_ORDER = (
    "unpinned_version",
    "http_remote",
    "many_required_secrets",
    "many_required_env",
    "missing_repository",
    "repository_changed",
)
_HTTP_TRANSPORTS = {"sse", "streamable-http"}
_WILDCARD = re.compile(r"(?i)(?:^|[.\-+])x(?:$|[.\-+])")


def server_detail(entry: dict | None) -> dict:
    """Server document inside a registry response, or the document itself."""
    if not isinstance(entry, dict):
        return {}
    inner = entry.get("server")
    if isinstance(inner, dict) and (isinstance(entry.get("_meta"), dict) or "version" not in entry):
        return inner
    return entry


def published_at(entry: dict | None) -> str:
    """`publishedAt`, else `updatedAt`, from the official registry meta. Empty when absent."""
    if not isinstance(entry, dict):
        return ""
    meta = entry.get("_meta")
    official = meta.get(OFFICIAL_META) if isinstance(meta, dict) else None
    if not isinstance(official, dict):
        return ""
    stamp = official.get("publishedAt") or official.get("updatedAt") or ""
    return str(stamp)


def order_versions(entries: list[dict]) -> list[dict]:
    """Oldest publication first. Version strings are not an order: `1.10.0` < `1.2.0` as text."""
    return sorted(
        [item for item in entries if isinstance(item, dict)],
        key=lambda item: (published_at(item), str(server_detail(item).get("version") or "")),
    )


def select_versions(
    entries: list[dict],
    ecosystem: str,
    package: str,
    release: str,
) -> tuple[dict | None, dict | None]:
    """`(current, previous)` by publication time.

    Prefer the server version whose matching package `version` equals this
    release. Otherwise use the latest by time. One version has no previous,
    so `repository_changed` does not run.
    """
    ordered = order_versions(entries)
    if not ordered:
        return None, None
    matched = [item for item in ordered if _package_release(item, ecosystem, package, release)]
    chosen = matched[-1] if matched else ordered[-1]
    index = ordered.index(chosen)
    previous = ordered[index - 1] if index else None
    return chosen, previous


def manifest_signals(
    current: dict | None,
    previous: dict | None = None,
    *,
    secret_min: int = 5,
    env_min: int = 8,
) -> tuple[list[str], dict]:
    """Signals for one server document. `previous` is required only for a repository move."""
    if not isinstance(current, dict):
        return [], {}
    hits: dict[str, dict] = {}
    unpinned = _unpinned(current)
    if unpinned:
        hits["unpinned_version"] = {"versions": unpinned}
    hosts = _http_hosts(current)
    if hosts:
        hits["http_remote"] = {"hosts": hosts}
    secrets, required = _input_counts(current)
    if secret_min > 0 and secrets >= secret_min:
        hits["many_required_secrets"] = {"count": secrets}
    if env_min > 0 and required >= env_min:
        hits["many_required_env"] = {"count": required}
    url = repository_url(current)
    if _missing_repository(url):
        hits["missing_repository"] = {"url": url}
    if previous is not None:
        old = repository_url(previous)
        if old and normalize_repository(old) != normalize_repository(url):
            hits["repository_changed"] = {"old": normalize_repository(old), "new": normalize_repository(url)}
    signals = [name for name in _MANIFEST_ORDER if name in hits]
    return signals, {name: hits[name] for name in signals}


def repository_url(entry: dict | None) -> str:
    repo = server_detail(entry).get("repository") if entry is not None else None
    if not isinstance(repo, dict):
        return ""
    url = repo.get("url")
    return url.strip() if isinstance(url, str) else ""


def normalize_repository(url: str) -> str:
    """Lowercase scheme and host, drop a trailing slash, `.git`, and a `www.` host prefix.

    The path, including a `subfolder` on the repository object, is not rewritten
    except for the suffix above. `http` and `https` stay different.
    """
    parsed = urlparse((url or "").strip())
    host = (parsed.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    path = parsed.path or ""
    if path.endswith("/"):
        path = path[:-1]
    if path.lower().endswith(".git"):
        path = path[:-4]
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme.lower()}://{host}{port}{path}"


def is_unpinned(version: object) -> bool:
    """Missing, empty, `latest`, or a range. `1.2.3` and `1.2.3-beta.1` are pinned."""
    if version is None:
        return True
    text = str(version).strip()
    if not text or text.lower() == "latest":
        return True
    if any(token in text for token in ("^", "~", ">", "<", "*", "||", ",")):
        return True
    return _WILDCARD.search(text) is not None


def _unpinned(entry: dict) -> list[str]:
    body = server_detail(entry)
    found: list[str] = []
    server_version = body.get("version") if isinstance(body, dict) else None
    if "version" not in body or is_unpinned(server_version):
        found.append("" if server_version is None else str(server_version))
    packages = body.get("packages") if isinstance(body, dict) else None
    if isinstance(packages, list):
        for package in packages:
            if not isinstance(package, dict) or "version" not in package or is_unpinned(package.get("version")):
                value = "" if not isinstance(package, dict) else package.get("version")
                found.append("" if value is None else str(value))
    # One signal per release. Keep the distinct bad strings for the operator.
    unique: list[str] = []
    for item in found:
        if item not in unique:
            unique.append(item)
    return unique


def _http_hosts(entry: dict) -> list[str]:
    hosts: list[str] = []
    body = server_detail(entry)
    for remote in body.get("remotes") or []:
        if isinstance(remote, dict):
            _add_host(hosts, remote.get("url"))
    for package in body.get("packages") or []:
        if not isinstance(package, dict):
            continue
        transport = package.get("transport")
        if not isinstance(transport, dict):
            continue
        if str(transport.get("type") or "") not in _HTTP_TRANSPORTS:
            continue
        _add_host(hosts, transport.get("url"))
    return hosts


def _add_host(hosts: list[str], url: object) -> None:
    if not isinstance(url, str):
        return
    parsed = urlparse(url.strip())
    if parsed.scheme.lower() != "http" or not parsed.hostname:
        return
    if parsed.hostname not in hosts:
        hosts.append(parsed.hostname)


def _input_counts(entry: dict) -> tuple[int, int]:
    secrets = 0
    required = 0
    body = server_detail(entry)
    inputs: list[dict] = []
    for package in body.get("packages") or []:
        if isinstance(package, dict):
            inputs.extend(_as_inputs(package.get("environmentVariables")))
    for remote in body.get("remotes") or []:
        if not isinstance(remote, dict):
            continue
        inputs.extend(_as_inputs(remote.get("headers")))
        inputs.extend(_as_inputs(remote.get("variables")))
    for item in inputs:
        if item.get("isRequired") is True:
            required += 1
            if item.get("isSecret") is True:
                secrets += 1
    return secrets, required


def _as_inputs(value: object) -> list[dict]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        if "isRequired" in value or "isSecret" in value:
            return [value]
        return [item for item in value.values() if isinstance(item, dict)]
    return []


def _missing_repository(url: str) -> bool:
    if not url:
        return True
    return urlparse(url).scheme.lower() not in {"http", "https"}


def _package_release(entry: dict, ecosystem: str, package: str, release: str) -> bool:
    body = server_detail(entry)
    packages = body.get("packages") or []
    if not isinstance(packages, list):
        return False
    for item in packages:
        if isinstance(item, dict) and _identifier_matches(item, ecosystem, package):
            if str(item.get("version") or "") == str(release):
                return True
    return False


def _identifier_matches(package: dict, ecosystem: str, name: str) -> bool:
    kind = str(package.get("registryType") or package.get("registry_type") or "").strip().lower()
    if kind and kind != ecosystem:
        return False
    identifier = str(package.get("identifier") or package.get("name") or "").strip()
    if not identifier:
        return False
    if ecosystem == "pypi":
        return normalize_pypi_name(identifier) == normalize_pypi_name(name)
    return identifier.lower() == name.lower()
