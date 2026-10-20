"""GitHub Actions monitoring: watch the tags of popular actions and review each change.

An action has no registry. A release is a git tag in a public repository, and a
tag can be moved to another commit at any time. Hunter records which commit each
tag of each watched action points at, turns a new tag or a moved tag into a
release job, and reviews the code change with the same rules, Triage and Analyst
used for npm and PyPI.

Release identity in the shared tables: ecosystem ``github-actions``, name
``owner/repo`` (lower case) and version ``<tag>@<first 12 of the commit sha>``.
The sha is part of the version because a moved tag is a new release under the
same tag name.
"""

from __future__ import annotations

import re

ECOSYSTEM = "github-actions"
SHA_SHOWN = 12

_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,38})/[a-z0-9._-]{1,100}$")
_FULL_VERSION = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:[-+.][0-9A-Za-z.+-]*)?$")
_MAJOR = re.compile(r"^v?(\d+)$")
_MINOR = re.compile(r"^v?(\d+)\.(\d+)$")
_SHA = re.compile(r"^[0-9a-f]{40}$")


def normalize_name(raw: str) -> str | None:
    """``Owner/Repo/sub/path`` -> ``owner/repo``. None when it is not a repository name."""
    text = (raw or "").strip().strip("'\"").lower()
    if text.startswith("https://github.com/"):
        text = text[len("https://github.com/") :]
    elif text.startswith("http://github.com/"):
        text = text[len("http://github.com/") :]
    elif text.startswith("github.com/"):
        text = text[len("github.com/") :]
    text = text.split("#", 1)[0].split("?", 1)[0].rstrip("/")
    if text.endswith(".git"):
        text = text[:-4]
    parts = [part for part in text.split("/") if part]
    if len(parts) < 2:
        return None
    name = f"{parts[0]}/{parts[1]}"
    if not _NAME.match(name) or parts[1] in {".", ".."}:
        return None
    return name


def is_sha(value: str) -> bool:
    return bool(_SHA.match((value or "").strip().lower()))


def release_version(tag: str, sha: str) -> str:
    return f"{tag}@{sha[:SHA_SHOWN]}"


def split_version(version: str) -> tuple[str, str]:
    """``v4@1a2b3c4d5e6f`` -> (``v4``, ``1a2b3c4d5e6f``). Tags may contain ``@``; the sha is last."""
    tag, _sep, short = (version or "").rpartition("@")
    return (tag, short) if tag else (version, "")


def full_version(tag: str) -> tuple[int, int, int] | None:
    """(major, minor, patch) for a full version tag such as ``v1.2.3`` or ``1.2.3-rc.1``."""
    match = _FULL_VERSION.match(tag or "")
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def is_prerelease(tag: str) -> bool:
    match = _FULL_VERSION.match(tag or "")
    if not match:
        return False
    rest = (tag or "")[match.end(3) :]
    return bool(rest) and not rest.startswith("+")


def floating_major(tag: str) -> int | None:
    """Major number of a floating tag such as ``v4`` or ``v4.2``. None for anything else."""
    match = _MAJOR.match(tag or "") or _MINOR.match(tag or "")
    return int(match.group(1)) if match else None


def is_full_version(tag: str) -> bool:
    return full_version(tag) is not None


def release_url(name: str, tag: str) -> str:
    return f"https://github.com/{name}/releases/tag/{tag}"


def tree_url(name: str, sha: str) -> str:
    return f"https://github.com/{name}/tree/{sha}"
