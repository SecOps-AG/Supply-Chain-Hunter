"""crates.io monitoring: read the publish RSS feeds and review each crate release.

A release is a ``.crate`` file, a gzipped tar. Hunter diffs it against the previous
non-yanked index line. Nothing in the archive is executed: no ``cargo``, no
``rustc``, and no ``build.rs``. Scout reads a release only when a weak rule hit
and ``HUNTER_CRATES_SCOUT`` is on.

Release identity in the shared tables: ecosystem ``crates``, the crate name, and
the version. Names and versions must be one safe path segment.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from hunter.typosquat import NameIndex

ECOSYSTEM = "crates"
_SEGMENT = re.compile(r"^[A-Za-z0-9._+-]+$")


def safe_segment(value: str) -> bool:
    """True when ``value`` is a single path segment safe to put in a URL path."""
    text = value or ""
    if not text or text.strip() != text or text in {".", ".."} or ".." in text:
        return False
    return _SEGMENT.fullmatch(text) is not None


def sparse_prefix(name: str) -> str:
    """Cargo index directory for ``name``, without the final crate name.

    1 character ``1``, 2 characters ``2``, 3 characters ``3/{c1}``,
    4 or more ``{c1}{c2}/{c3}{c4}``.
    """
    text = (name or "").lower()
    length = len(text)
    if length <= 1:
        return "1"
    if length == 2:
        return "2"
    if length == 3:
        return f"3/{text[0]}"
    return f"{text[0:2]}/{text[2:4]}"


def sparse_path(name: str) -> str:
    """Sparse-index path. ``serde`` is ``se/rd/serde``."""
    text = (name or "").lower()
    return f"{sparse_prefix(text)}/{text}"


def _title_version(title: str, name: str) -> str:
    """Version from a title such as ``tree-sitter-cpp v0.22.0``.

    The token after `` v`` has to start with a digit, and the text before it has
    to name this crate. ``New crate created: veylog`` is a name, not version
    ``eylog``, and ``New crate created: v2`` is not version ``2``.
    """
    if " v" not in (title or ""):
        return ""
    left, right = title.rsplit(" v", 1)
    token = right.strip().split()[0] if right.strip() else ""
    if not token or not token[0].isdigit() or not safe_segment(token):
        return ""
    stem = left.strip().split(":")[-1].strip().lower()
    if stem != (name or "").lower():
        return ""
    return token


def parse_release_link(link: str, title: str = "") -> tuple[str, str] | None:
    """Name and version from ``https://crates.io/crates/{name}/{version}``.

    A crates-feed item whose link has no version uses the title, split on `` v``.
    A title with no version returns the name and an empty version. Unsafe names
    and versions are refused.
    """
    path = urlparse((link or "").strip()).path.strip("/")
    parts = [part for part in path.split("/") if part]
    if parts and parts[0] == "crates":
        parts = parts[1:]
    if not parts:
        return None
    name = parts[0].lower()
    version = parts[1] if len(parts) >= 2 else _title_version(title, name)
    if not safe_segment(name):
        return None
    if not version:
        return name, ""
    if not safe_segment(version):
        return None
    return name, version


def download_url(template: str, crate: str, version: str, checksum: str, static_host: str) -> str:
    """Fill Cargo's ``dl`` placeholders. An empty template uses the static CDN.

    Placeholders: ``{crate}``, ``{version}``, ``{prefix}``, ``{lowerprefix}``,
    ``{sha256-checksum}``. A template with none of ``{crate}`` or ``{version}``
    gets ``/{crate}/{version}/download`` appended, as Cargo does.
    """
    name = (crate or "").lower()
    prefix = sparse_prefix(name)
    fallback = f"{static_host.rstrip('/')}/crates/{{crate}}/{{crate}}-{{version}}.crate"
    pattern = template or fallback
    has_crate = "{crate}" in pattern
    has_version = "{version}" in pattern
    rendered = (
        pattern.replace("{crate}", name)
        .replace("{version}", version)
        .replace("{prefix}", prefix)
        .replace("{lowerprefix}", prefix.lower())
        .replace("{sha256-checksum}", (checksum or "").lower())
    )
    if not has_crate and not has_version:
        rendered = rendered.rstrip("/") + f"/{name}/{version}/download"
    return rendered


def _is_subsequence(short: str, long: str) -> bool:
    index = 0
    for char in long:
        if index < len(short) and char == short[index]:
            index += 1
    return index == len(short)


def _two_insert_victim(candidate: str, names: set[str]) -> str | None:
    """A watched name with exactly two letters inserted, such as ``fast_log`` to ``faster_log``.

    One-edit and separator checks miss that pair: the raw names differ by two
    characters. The shorter squashed name has to be the longer one with those
    two characters taken out.
    """
    text = candidate.strip().lower()
    squashed = _squash(text)
    if len(squashed) < 6:
        return None
    found: list[str] = []
    for other in names:
        if other == text:
            continue
        base = _squash(other)
        if len(base) < 6 or abs(len(squashed) - len(base)) != 2:
            continue
        short, long = (base, squashed) if len(base) < len(squashed) else (squashed, base)
        if _is_subsequence(short, long):
            found.append(other)
    if not found:
        return None
    found.sort(key=lambda item: (-len(_squash(item)), item))
    return found[0]


def _squash(name: str) -> str:
    from hunter.typosquat import squash

    return squash(name)


def victim_name(candidate: str, names) -> str | None:
    """Watched crate this name imitates, or None.

    Uses :class:`NameIndex` (separator, homoglyph, one edit). A two-letter
    insertion such as ``faster_log`` for ``fast_log`` is checked after that.
    An exact watchlist name is not a victim.
    """
    index = names if isinstance(names, NameIndex) else NameIndex(names)
    text = (candidate or "").strip().lower()
    if not text or text in index.names:
        return None
    found = index.match(text)
    if found:
        return found
    return _two_insert_victim(text, index.names)
