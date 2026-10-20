"""Name-similarity checks for packages and dependencies outside an exact watchlist hit."""

from __future__ import annotations

CONFUSABLES = str.maketrans({
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "@": "a",
    "$": "s",
})

# Used when a release is scored without a loaded watchlist. The live watcher
# unions this with the current top-package names.
COMMON_PACKAGES = frozenset({
    "requests",
    "urllib3",
    "numpy",
    "pandas",
    "setuptools",
    "pip",
    "wheel",
    "boto3",
    "botocore",
    "cryptography",
    "pyyaml",
    "click",
    "jinja2",
    "flask",
    "django",
    "react",
    "react-dom",
    "lodash",
    "express",
    "axios",
    "chalk",
    "colors",
    "debug",
    "commander",
    "moment",
    "webpack",
    "typescript",
    "vue",
    "next",
    "jquery",
    "left-pad",
    "ansi-styles",
    "minimist",
    "semver",
    "ws",
    "node-fetch",
})

TYPOSQUAT_QUEUE_LIMIT = 25


def squash(name: str) -> str:
    text = name.strip().lower().replace("_", "").replace("-", "").replace(".", "")
    return text.translate(CONFUSABLES)


def within_one(left: str, right: str) -> bool:
    """True for one insertion, deletion, substitution, or adjacent transposition."""
    if left == right:
        return False
    if abs(len(left) - len(right)) > 1:
        return False
    if len(left) == len(right):
        diffs = [index for index, (a, b) in enumerate(zip(left, right)) if a != b]
        if (
            len(diffs) == 2
            and diffs[1] == diffs[0] + 1
            and left[diffs[0]] == right[diffs[1]]
            and left[diffs[1]] == right[diffs[0]]
        ):
            return True
    if len(left) > len(right):
        left, right = right, left
    shorter, longer = left, right
    index_short = 0
    index_long = 0
    edits = 0
    while index_short < len(shorter) and index_long < len(longer):
        if shorter[index_short] == longer[index_long]:
            index_short += 1
            index_long += 1
            continue
        edits += 1
        if edits > 1:
            return False
        if len(shorter) == len(longer):
            index_short += 1
        index_long += 1
    if index_short < len(shorter) or index_long < len(longer):
        edits += 1
    return edits == 1


def _variants(name: str) -> list[str]:
    text = name.strip().lower()
    if not text:
        return []
    # A scoped name is compared whole. `@sentry/react` sits in its own scope and
    # does not imitate `react`; comparing the part after the slash sent most new
    # scoped packages to Triage. `@angulr/core` still matches `@angular/core`.
    return [text]


class NameIndex:
    """Watchlist names keyed for separator, homoglyph, and one-edit lookups."""

    def __init__(self, names):
        self.names: set[str] = set()
        self.by_squash: dict[str, str] = {}
        self.by_len: dict[int, list[str]] = {}
        for name in names:
            self._add(str(name))

    def _add(self, name: str) -> None:
        text = name.strip().lower()
        if not text or text in self.names:
            return
        self.names.add(text)
        self.by_squash.setdefault(squash(text), text)
        self.by_len.setdefault(len(text), []).append(text)

    def match(self, candidate: str) -> str | None:
        """Return the watched name this candidate imitates, if any."""
        text = candidate.strip().lower()
        if not text or text in self.names:
            return None
        for variant in _variants(text):
            if variant in self.names:
                continue
            found = self._match_one(variant)
            if found:
                return found
        return None

    def _match_one(self, name: str) -> str | None:
        if not name or name in self.names:
            return None
        if len(name) < 4:
            return None
        homoglyph = self.by_squash.get(squash(name))
        if homoglyph and homoglyph != name and len(homoglyph) >= 4:
            return homoglyph
        if len(name) < 5:
            return None
        for length in (len(name) - 1, len(name), len(name) + 1):
            for other in self.by_len.get(length, ()):
                if not within_one(name, other):
                    continue
                # `colors` should not imitate `color`. `request` should imitate `requests`.
                if name == other + "s":
                    continue
                return other
        return None


def typosquat_pairs(
    candidates: list[tuple[str, str]],
    popular: dict[str, int],
    limit: int = TYPOSQUAT_QUEUE_LIMIT,
) -> list[tuple[str, str, int]]:
    """(name, version, victim rank) for candidates that imitate a watched name."""
    lowered = {str(name).lower(): int(rank) for name, rank in popular.items()}
    index = NameIndex(lowered)
    found: list[tuple[str, str, int]] = []
    seen: set[str] = set()
    for name, version in candidates:
        key = str(name).strip().lower()
        if not key or key in lowered or key in seen:
            continue
        victim = index.match(key)
        if not victim:
            continue
        seen.add(key)
        found.append((str(name), str(version), lowered.get(victim, 0)))
        if len(found) >= limit:
            break
    return found
