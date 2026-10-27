"""Package URLs (``pkg:type/namespace/name@version``) as found in SBOMs and plain lists."""

from __future__ import annotations

from urllib.parse import unquote

from hunter.actions import ECOSYSTEM as ACTIONS_ECOSYSTEM
from hunter.crates import ECOSYSTEM as CRATES_ECOSYSTEM
from hunter.inventory import Component, component
from hunter.openvsx import ECOSYSTEM as OPENVSX_ECOSYSTEM
from hunter.rubygems import ECOSYSTEM as RUBYGEMS_ECOSYSTEM

_TYPES = {
    "npm": "npm",
    "pypi": "pypi",
    "githubactions": ACTIONS_ECOSYSTEM,
    "github": ACTIONS_ECOSYSTEM,
    "openvsx": OPENVSX_ECOSYSTEM,
    "vscode-extension": OPENVSX_ECOSYSTEM,
    "gem": RUBYGEMS_ECOSYSTEM,
    "cargo": CRATES_ECOSYSTEM,
}


def parse_purl(text: str, direct: int | None = None) -> Component | None:
    """One component, or None for another package type or a malformed purl.

    Percent-encoding is decoded. Qualifiers (``?``) and the subpath (``#``) are dropped.
    """
    raw = (text or "").strip()
    if not raw.lower().startswith("pkg:"):
        return None
    body = raw[4:].lstrip("/").split("#", 1)[0].split("?", 1)[0]
    kind, sep, rest = body.partition("/")
    ecosystem = _TYPES.get(kind.lower())
    if not sep or ecosystem is None:
        return None
    # The version follows the last '@' after the last '/'; a scope written as '@' stays in the path.
    slash = rest.rfind("/")
    at = rest.rfind("@")
    version = ""
    if at > slash and at > 0:
        rest, version = rest[:at], unquote(rest[at + 1 :])
    parts = [unquote(part) for part in rest.split("/") if part]
    if not parts:
        return None
    if ecosystem == "npm":
        if len(parts) == 1:
            name = parts[0]
        elif len(parts) == 2:
            scope = parts[0] if parts[0].startswith("@") else f"@{parts[0]}"
            name = f"{scope}/{parts[1]}"
        else:
            return None
    elif ecosystem in {"pypi", RUBYGEMS_ECOSYSTEM, CRATES_ECOSYSTEM}:
        if len(parts) != 1:
            return None
        name = parts[0]
    elif ecosystem == ACTIONS_ECOSYSTEM:
        if len(parts) < 2:
            return None
        name = f"{parts[0]}/{parts[1]}"
    else:
        if len(parts) == 2:
            name = f"{parts[0]}.{parts[1]}"
        elif len(parts) == 1:
            name = parts[0]
        else:
            return None
    return component(ecosystem, name, version, direct)
