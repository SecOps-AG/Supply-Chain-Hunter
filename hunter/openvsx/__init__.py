"""Open VSX monitoring: read the registry changes feed and review each extension release.

Open VSX serves VS Code compatible extensions to Cursor, VSCodium, Windsurf and
others. A release is a ``.vsix`` file, a zip of the extension's JavaScript and
``package.json``. Hunter diffs it against the previous version with the same
rules used for npm. A new ``extensionPack`` or ``extensionDependencies`` id
routes to Triage on its own. Scout reads a release only when
``HUNTER_OPENVSX_SCOUT`` is on and the rule verdict is malicious or a rule hit
comes with a manifest change. ``REMOVED`` versions and ``INACTIVE`` versions
(the unpublished state) are labeled and not downloaded.

Release identity in the shared tables: ecosystem ``openvsx``, name
``namespace.extension`` (lower case) and the extension version.
"""

from __future__ import annotations

import re

ECOSYSTEM = "openvsx"
UNIVERSAL = "universal"
# Platform builds tried, in order, when a version has no universal build.
PLATFORM_ORDER = (UNIVERSAL, "linux-x64", "win32-x64", "darwin-arm64", "darwin-x64")

_PART = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")


def release_name(namespace: str, extension: str) -> str | None:
    """``Namespace``, ``ext`` -> ``namespace.ext``. None when either part is unsafe in a URL."""
    ns = (namespace or "").strip().lower()
    ext = (extension or "").strip().lower()
    if not _PART.match(ns) or not _PART.match(ext) or ".." in ns or ".." in ext:
        return None
    return f"{ns}.{ext}"


def split_name(name: str) -> tuple[str, str]:
    """``namespace.ext`` -> (``namespace``, ``ext``). Namespaces have no dot; extension names may."""
    namespace, _sep, extension = (name or "").partition(".")
    return namespace, extension


def pick_platform(platforms: dict[str, str]) -> str | None:
    """The build to diff: universal first, then a common platform, else the first active one."""
    active = sorted(platform for platform, state in platforms.items() if state == "ACTIVE")
    for platform in PLATFORM_ORDER:
        if platform in active:
            return platform
    return active[0] if active else None


def extension_url(base: str, name: str, version: str) -> str:
    namespace, extension = split_name(name)
    return f"{base.rstrip('/')}/extension/{namespace}/{extension}/{version}"
