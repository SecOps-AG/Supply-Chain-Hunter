"""User watchlist: the packages one deployment uses, read from its lockfiles, SBOMs and workflows.

Every reader here only parses text. Nothing is installed, imported, resolved or
fetched; a version range stays an empty version. Rows land in ``user_watch``,
grouped by the label of the file they came from (the "source").

Names are stored the way the polls compare them: PyPI through
``normalize_pypi_name``, npm exactly as written, GitHub Actions as lower case
``owner/repo`` and Open VSX as lower case ``publisher.extension``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from hunter.actions import ECOSYSTEM as ACTIONS_ECOSYSTEM
from hunter.actions import normalize_name as normalize_action_name
from hunter.openvsx import ECOSYSTEM as OPENVSX_ECOSYSTEM
from hunter.openvsx import release_name
from hunter.registry import normalize_pypi_name

ECOSYSTEMS = ("npm", "pypi", ACTIONS_ECOSYSTEM, OPENVSX_ECOSYSTEM)

# Names typed in a plain list or on the command line.
ECOSYSTEM_ALIASES = {
    "npm": "npm",
    "pypi": "pypi",
    "pip": "pypi",
    "github-actions": ACTIONS_ECOSYSTEM,
    "actions": ACTIONS_ECOSYSTEM,
    "gha": ACTIONS_ECOSYSTEM,
    "openvsx": OPENVSX_ECOSYSTEM,
    "vscode": OPENVSX_ECOSYSTEM,
}

_NPM_NAME = re.compile(r"^(?:@[a-z0-9~][a-z0-9._~-]*/)?[a-z0-9~][a-z0-9._~-]*$", re.IGNORECASE)
_PYPI_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$", re.IGNORECASE)
MAX_VERSION_CHARS = 128


@dataclass(frozen=True)
class Component:
    ecosystem: str
    name: str
    version: str = ""
    direct: int | None = None


def ecosystem_alias(text: str) -> str | None:
    return ECOSYSTEM_ALIASES.get((text or "").strip().lower())


def normalize(ecosystem: str, name: str) -> str | None:
    """The stored form of a name, or None when it is not a valid name for that ecosystem."""
    text = (name or "").strip()
    if not text or len(text) > 214:
        return None
    if ecosystem == "npm":
        return text if _NPM_NAME.match(text) else None
    if ecosystem == "pypi":
        return normalize_pypi_name(text) if _PYPI_NAME.match(text) else None
    if ecosystem == ACTIONS_ECOSYSTEM:
        return normalize_action_name(text)
    if ecosystem == OPENVSX_ECOSYSTEM:
        publisher, _sep, extension = text.partition(".")
        return release_name(publisher, extension) if extension else None
    return None


def clean_version(text: str | None) -> str:
    """A version as written, or '' when it is empty, too long, or holds whitespace."""
    value = (text or "").strip()
    if not value or len(value) > MAX_VERSION_CHARS or any(char.isspace() for char in value):
        return ""
    return value


def component(ecosystem: str, name: str, version: str | None = "", direct: int | None = None) -> Component | None:
    """A normalized component, or None when the name is not valid."""
    normalized = normalize(ecosystem, name)
    if normalized is None:
        return None
    return Component(ecosystem, normalized, clean_version(version), direct)
