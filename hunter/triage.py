"""Keep install scripts, entry points, workflows, and suspicious source. Drop noise."""

from __future__ import annotations

import difflib
import hashlib
import re
from collections.abc import Mapping
from pathlib import PurePosixPath

from hunter.archives import BINARY_MARKER, BINARY_SUFFIXES
from hunter.models import FileDiff
from hunter.patterns import (
    CREDENTIAL,
    DECODE_EXEC,
    ENCODED_IMPORT,
    ENV_TOKEN,
    HOST,
    LOOPBACK,
    RAW_IP,
    SHELL,
    actionable_literal,
    looks_suspicious,
    shannon_entropy,
    unexpected_hosts,
)

NOISE_DIRS = {
    "docs",
    "doc",
    "examples",
    "example",
    "changelog",
    "changes",
    ".changeset",
}
NOISE_STEMS = {
    "changelog",
    "change_log",
    "changes",
    "history",
    "news",
    "license",
    "licence",
    "copying",
    "readme",
    "authors",
    "contributing",
    "code_of_conduct",
}
LOCKFILES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "npm-shrinkwrap.json",
    "poetry.lock",
    "pipfile.lock",
    "cargo.lock",
    "composer.lock",
    "gemfile.lock",
    "uv.lock",
}
INSTALL_NAMES = {
    "setup.py",
    "setup.cfg",
    "pyproject.toml",
    "package.json",
    "binding.gyp",
    "install.sh",
}
SOURCE_EXT = {
    ".py",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".mts",
    ".cts",
    ".ts",
    ".tsx",
    ".sh",
    ".ps1",
    ".rb",
    ".php",
    ".pth",
    ".bat",
    ".cmd",
}
DOC_EXT = {".md", ".rst", ".txt", ".adoc", ".html"}


def _parts(path: str) -> tuple[str, ...]:
    return tuple(part.lower() for part in PurePosixPath(path).parts)


_DOC_CODE_DIRS = {"docs", "doc", "examples", "example"}


def is_doc_or_example_code(path: str) -> bool:
    """Source under docs or examples is code. It is not documentation noise."""
    if not is_source(path):
        return False
    return any(part in _DOC_CODE_DIRS for part in _parts(path)[:-1])


def is_noise(path: str) -> bool:
    parts = _parts(path)
    name = parts[-1] if parts else ""
    if name in LOCKFILES or name.endswith(".lock"):
        return True
    if is_doc_or_example_code(path):
        return False
    if any(part in NOISE_DIRS for part in parts[:-1]):
        return True
    stem = PurePosixPath(name).stem.lower()
    suffix = PurePosixPath(name).suffix.lower()
    if stem in NOISE_STEMS:
        return True
    if suffix in DOC_EXT and ".github" not in parts:
        return True
    return False


def is_source_map(path: str) -> bool:
    return PurePosixPath(path).suffix.lower() == ".map"


def is_type_declaration(path: str) -> bool:
    name = PurePosixPath(path).name.lower()
    return name.endswith(".d.ts") or name.endswith(".d.mts") or name.endswith(".d.cts")


def is_snapshot(path: str) -> bool:
    parts = _parts(path)
    name = parts[-1] if parts else ""
    return name.endswith(".snap") or "__snapshots__" in parts


_FIXTURE_DIRS = {"__fixtures__", "fixtures", "testdata", "__testdata__"}
_BUNDLE_DIRS = {"dist", "build", "out"}


def is_test_fixture(path: str) -> bool:
    parts = _parts(path)
    return any(part in _FIXTURE_DIRS for part in parts[:-1])


def _is_generated_noise(path: str) -> bool:
    return is_source_map(path) or is_type_declaration(path) or is_snapshot(path) or is_test_fixture(path)


def _encoded_payload(text: str) -> bool:
    """A payload hidden in a declaration or source map, not a type signature that names an API."""
    if not text or not text.strip():
        return False
    if DECODE_EXEC.search(text) or ENCODED_IMPORT.search(text):
        return True
    for line in text.splitlines():
        compact = "".join(line.split())
        if len(compact) >= 180 and _is_encoded_alphabet(compact) and not _has_code_punctuation(compact):
            return True
    return False


def is_workflow(path: str) -> bool:
    lowered = path.lower().replace("\\", "/")
    name = PurePosixPath(lowered).name
    if "/.github/workflows/" in f"/{lowered}":
        return True
    if name in {".gitlab-ci.yml", "jenkinsfile", "azure-pipelines.yml"}:
        return True
    if "/.circleci/" in f"/{lowered}":
        return True
    return False


def is_install_script(path: str) -> bool:
    return PurePosixPath(path).name.lower() in INSTALL_NAMES


def is_entry_point(path: str) -> bool:
    lowered = path.replace("\\", "/")
    parts = _parts(lowered)
    if parts and parts[0] == "bin":
        return True
    return PurePosixPath(lowered).name.lower() in {
        "setup.py",
        "setup.cfg",
        "pyproject.toml",
        "package.json",
        "action.yml",
        "action.yaml",
    }


def is_source(path: str) -> bool:
    return PurePosixPath(path).suffix.lower() in SOURCE_EXT


def is_shebang_script(path: str, text: str) -> bool:
    """An extensionless file whose first line is a shebang is a script."""
    if PurePosixPath(path).suffix:
        return False
    stripped = (text or "").lstrip("\ufeff")
    lines = stripped.splitlines()
    return bool(lines and lines[0].startswith("#!"))


def is_binary_media(path: str, text: str = "") -> bool:
    if text.startswith(BINARY_MARKER):
        return True
    return PurePosixPath(path).suffix.lower() in BINARY_SUFFIXES


def _diff_lines(text: str) -> list[str]:
    # difflib glues a last line with no newline to the next diff line, so a change
    # there would be lost from the added lines.
    lines = text.splitlines(keepends=True)
    if lines and not lines[-1].endswith(("\n", "\r")):
        lines[-1] += "\n"
    return lines


def unified_diff(path: str, old: str, new: str) -> str:
    old_lines = _diff_lines(old)
    new_lines = _diff_lines(new)
    return "".join(
        difflib.unified_diff(
            old_lines,
            new_lines,
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
            n=2,
        )
    )


def added_lines(diff_text: str) -> str:
    kept = []
    for line in diff_text.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            kept.append(line[1:])
    return "\n".join(kept)


def categorize(path: str, added: str, new_text: str, is_new_file: bool) -> str | None:
    """Return a triage category, or None when the path is noise or an ordinary edit."""
    sample = added if added.strip() else (new_text if is_new_file else "")
    if is_workflow(path):
        return "workflows"
    if is_install_script(path):
        return "install_scripts"
    if is_binary_media(path, new_text) or is_binary_media(path, added):
        return "binary_media"
    if _is_generated_noise(path):
        hostile = _encoded_payload(sample) if (is_source_map(path) or is_type_declaration(path)) else actionable_literal(sample)
        if hostile:
            return "suspicious_payload"
        return None
    if is_shebang_script(path, new_text) or is_shebang_script(path, sample):
        if looks_suspicious(sample) or (is_new_file and looks_suspicious(new_text)):
            return "suspicious_source"
        if is_new_file:
            return "entry_points"
        return None
    if is_noise(path):
        if actionable_literal(sample):
            return "suspicious_payload"
        return None
    if is_entry_point(path) and not is_source(path):
        return "entry_points"
    if is_source(path) or looks_suspicious(sample):
        if looks_suspicious(sample) or (is_new_file and looks_suspicious(new_text)):
            return "suspicious_source" if is_source(path) else "suspicious_payload"
        if is_entry_point(path):
            return "entry_points"
        return None
    return None


_ARTIFACT_ROOTS = {"sdist", "wheel"}
_VERSIONED_DIR = re.compile(r"^(?P<stem>.+)-(?P<version>\d+\.\d+(?:[A-Za-z0-9._+\-]*))$")


def _norm_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", (value or "").strip().lower())


def _version_key(value: str) -> str:
    text = (value or "").strip().lower()
    if len(text) > 1 and text[0] == "v" and text[1].isdigit():
        text = text[1:]
    if "!" in text:
        text = text.split("!", 1)[1]
    return text


def _stem_matches(stem: str, name: str) -> bool:
    if not name:
        return False
    return _norm_name(stem) == _norm_name(name)


def _is_versioned_release_dir(wrapper: str, *, name: str, version: str | None) -> bool:
    """True for a single sdist directory like ``name-1.2.3``."""
    if wrapper.endswith(".dist-info") or wrapper.endswith(".egg-info"):
        return False
    match = _VERSIONED_DIR.match(wrapper)
    if not match:
        return False
    stem = match.group("stem")
    found = match.group("version")
    if name and _stem_matches(stem, name):
        return True
    if not name and version and _version_key(found) == _version_key(version):
        return True
    return False


def _should_strip(wrapper: str, *, ecosystem: str, name: str, version: str | None) -> bool:
    if wrapper in _ARTIFACT_ROOTS:
        return False
    if wrapper.endswith(".dist-info") or wrapper.endswith(".egg-info"):
        return False
    if wrapper == "package" and (ecosystem or "").lower() != "pypi":
        return True
    if (ecosystem or "").lower() == "github-actions":
        # codeload tarballs unpack under ``<repo>-<sha>/``.
        return True
    return _is_versioned_release_dir(wrapper, name=name, version=version)


def _artifact_split(path: str) -> tuple[str, str]:
    if "/" not in path:
        return "", path
    top, rest = path.split("/", 1)
    if top in _ARTIFACT_ROOTS and rest:
        return top, rest
    return "", path


def _single_top(files: dict[str, str]) -> str | None:
    if not files:
        return None
    tops: set[str] = set()
    for path in files:
        if "/" not in path:
            return None
        top, rest = path.split("/", 1)
        if not top or not rest:
            return None
        tops.add(top)
        if len(tops) > 1:
            return None
    if len(tops) != 1:
        return None
    return next(iter(tops))


def _strip_wrapper(files: dict[str, str], wrapper: str) -> dict[str, str] | None:
    prefix = wrapper + "/"
    stripped: dict[str, str] = {}
    for path, text in files.items():
        if not path.startswith(prefix):
            return None
        rest = path[len(prefix) :]
        if not rest or rest in stripped:
            return None
        stripped[rest] = text
    return stripped or None


def _peel_group(
    files: dict[str, str],
    *,
    ecosystem: str,
    name: str,
    version: str | None,
) -> dict[str, str]:
    wrapper = _single_top(files)
    if wrapper is None or not _should_strip(wrapper, ecosystem=ecosystem, name=name, version=version):
        return files
    stripped = _strip_wrapper(files, wrapper)
    return files if stripped is None else stripped


def _align_one(
    files: dict[str, str],
    *,
    ecosystem: str,
    name: str,
    version: str | None,
) -> dict[str, str]:
    if not files:
        return files
    groups: dict[str, dict[str, str]] = {}
    for path, text in files.items():
        root, rest = _artifact_split(path)
        groups.setdefault(root, {})[rest] = text
    aligned: dict[str, str] = {}
    for root, group in groups.items():
        peeled = _peel_group(group, ecosystem=ecosystem, name=name, version=version)
        for path, text in peeled.items():
            key = f"{root}/{path}" if root else path
            aligned.setdefault(key, text)
    return aligned


def align_release_trees(
    old_files: dict[str, str],
    new_files: dict[str, str],
    *,
    ecosystem: str = "",
    name: str = "",
    old_version: str | None = None,
    new_version: str | None = None,
) -> tuple[dict[str, str], dict[str, str]]:
    """Drop one archive wrapper from each side so identical files share a path.

    PyPI sdists unpack under ``name-version/``. npm packs unpack under ``package/``.
    Loader trees keep their ``sdist/`` and ``wheel/`` prefixes. A directory is removed
    only when it is the single top-level directory on that side.
    """
    old_aligned = _align_one(old_files, ecosystem=ecosystem, name=name, version=old_version)
    new_aligned = _align_one(new_files, ecosystem=ecosystem, name=name, version=new_version)
    return old_aligned, new_aligned


def changed_diffs(old_files: Mapping[str, str], new_files: Mapping[str, str]) -> dict[str, str]:
    """Unified diff of every path whose text changed. The rule scan and diff_trees share them."""
    found: dict[str, str] = {}
    for path in sorted(set(old_files) | set(new_files)):
        old = old_files.get(path, "")
        new = new_files.get(path, "")
        if old != new:
            found[path] = unified_diff(path, old, new)
    return found


def _rule_hit_detail(hits) -> str:
    """Manifest reason for a path a rule kept. Without hits (Scout's copy) it names no rule."""
    if not hits:
        return "changed_code"
    rules: list[str] = []
    for hit in hits:
        if hit.rule not in rules:
            rules.append(hit.rule)
    return "rule_hit: " + ", ".join(rules)


def diff_trees(
    old_files: dict[str, str],
    new_files: dict[str, str],
    *,
    force_keep: Mapping[str, list] | None = None,
    known_diffs: Mapping[str, str] | None = None,
) -> list[FileDiff]:
    """Kept file diffs. A path in `force_keep` (a rule hit) is kept even when no category fits."""
    forced = force_keep or {}
    paths = sorted(set(old_files) | set(new_files))
    diffs: list[FileDiff] = []
    for path in paths:
        old = old_files.get(path, "")
        new = new_files.get(path, "")
        if old == new:
            continue
        diff_text = known_diffs[path] if known_diffs and path in known_diffs else unified_diff(path, old, new)
        added = added_lines(diff_text)
        category = categorize(path, added, new, path not in old_files)
        if category is None and path in forced:
            # Neutral name: Scout's input does not say a rule matched (decision 5 of the rule plan).
            category = "changed_code"
        if category is None:
            continue
        diffs.append(
            FileDiff(
                path=path,
                category=category,
                diff_text=diff_text,
                added_text=added,
                old_text=old,
                new_text=new,
            )
        )
    return _without_bundle_duplicates(diffs, forced=set(forced))


def added_before_removed(diff_text: str) -> str:
    """Put added lines before removed lines in each hunk.

    A unified diff writes the old line first. For a long changed line, a reader
    that only sees the start can then miss the new code entirely.
    """
    lines = diff_text.splitlines()
    out: list[str] = []
    context: list[str] = []
    added: list[str] = []
    removed: list[str] = []

    def flush() -> None:
        out.extend(context)
        out.extend(added)
        out.extend(removed)
        context.clear()
        added.clear()
        removed.clear()

    for line in lines:
        if line.startswith("--- a/") or line.startswith("+++ b/") or line.startswith("@@"):
            flush()
            out.append(line)
            continue
        if line.startswith("+"):
            added.append(line)
            continue
        if line.startswith("-"):
            removed.append(line)
            continue
        context.append(line)
    flush()
    return "\n".join(out)


def render_excerpt(diffs: list[FileDiff], *, limit_chars: int | None = None) -> str:
    if not diffs:
        text = "(no install scripts, entry points, workflows, or suspicious source in this release diff)"
        return text if limit_chars is None else text[:limit_chars]
    chunks = []
    for item in diffs:
        body = added_before_removed(item.diff_text).strip() or item.added_text
        chunks.append(f"--- {item.category}:{item.path}\n{body}")
    text = "\n".join(chunks)
    if limit_chars is not None and len(text) > limit_chars:
        return text[:limit_chars] + "\n[truncated]"
    return text


MANIFEST_NAMES = {"package.json", "pyproject.toml", "setup.py", "setup.cfg"}
DOC_WINDOW_CAP = 800
_CATEGORY_RANK = {
    "install_scripts": 0,
    "changed_code": 0.5,
    "entry_points": 1,
    "suspicious_source": 2,
    "suspicious_payload": 3,
    "workflows": 4,
    "binary_media": 6,
}


def _base_name(path: str) -> str:
    return PurePosixPath(path).name.lower()


def _is_doc_path(path: str) -> bool:
    if is_noise(path):
        return True
    return PurePosixPath(path).suffix.lower() in DOC_EXT


def rank_diffs(diffs: list[FileDiff]) -> list[FileDiff]:
    """Manifests and install scripts first. Docs and changelogs last."""

    def key(item: FileDiff) -> tuple:
        name = _base_name(item.path)
        return (
            1 if _is_doc_path(item.path) else 0,
            0 if name in MANIFEST_NAMES else 1,
            _CATEGORY_RANK.get(item.category, 5),
            item.path,
        )

    return sorted(diffs, key=key)


def _manifest_name_sets(files: dict[str, str]) -> set[str]:
    from hunter.features import npm_dependency_names, python_dependency_names

    names: set[str] = set()
    for path, text in files.items():
        if _base_name(path) not in MANIFEST_NAMES:
            continue
        names.update(npm_dependency_names(text))
        names.update(python_dependency_names(text))
    return names


def dependency_delta_block(old_files: dict[str, str], new_files: dict[str, str]) -> str:
    """Short manifest preface so a changelog cannot push a new dependency out of the window."""
    from hunter.features import phantom_runtime_dependencies

    added = sorted(_manifest_name_sets(new_files) - _manifest_name_sets(old_files))
    phantom = phantom_runtime_dependencies(old_files, new_files)
    lines = ["[dependency_delta]"]
    lines.append("added: " + (", ".join(added) if added else "(none)"))
    if phantom:
        lines.append("phantom_unreferenced: " + ", ".join(phantom))
    else:
        lines.append("phantom_unreferenced: (none)")
    return "\n".join(lines)


def _window_body(item: FileDiff, cap: int, needles: list[str]) -> str:
    body = item.diff_text.strip() or item.added_text
    limit = min(cap, DOC_WINDOW_CAP) if _is_doc_path(item.path) else cap
    if len(body) <= limit:
        return body
    lines = body.splitlines()
    picked = list(lines[:24])
    lowered = [needle.lower() for needle in needles if needle]
    for line in lines[24:]:
        sample = line.lower()
        if any(needle in sample for needle in lowered):
            picked.append(line)
        if sum(len(part) + 1 for part in picked) >= limit:
            break
    text = "\n".join(picked)
    if len(text) > limit:
        text = text[:limit]
    return text + "\n[window]"


def render_ranked_excerpt(
    diffs: list[FileDiff],
    *,
    limit_chars: int | None = None,
    preface: str = "",
    needles: list[str] | None = None,
) -> str:
    """IOC order for the triage window. Jev packing still uses render_excerpt."""
    ordered = rank_diffs(diffs)
    interest = list(needles or [])
    chunks: list[str] = []
    if preface.strip():
        chunks.append(preface.strip())
    if not ordered and not chunks:
        text = "(no install scripts, entry points, workflows, or suspicious source in this release diff)"
        return text if limit_chars is None else text[:limit_chars]
    for item in ordered:
        remaining = None if limit_chars is None else limit_chars - sum(len(part) + 1 for part in chunks)
        if remaining is not None and remaining <= 80:
            break
        cap = remaining if remaining is not None else 10**9
        body = _window_body(item, cap, interest)
        chunks.append(f"--- {item.category}:{item.path}\n{body}")
    text = "\n".join(chunks)
    if limit_chars is not None and len(text) > limit_chars:
        return text[:limit_chars] + "\n[truncated]"
    return text


def ranked_triage_excerpt(
    old_files: dict[str, str],
    new_files: dict[str, str],
    *,
    limit_chars: int = 12_000,
    force_keep: Mapping[str, list] | None = None,
) -> str:
    """Triage evidence window. The dependency preface is reserved at the front."""
    added = sorted(_manifest_name_sets(new_files) - _manifest_name_sets(old_files))
    preface = dependency_delta_block(old_files, new_files)
    diffs = diff_trees(old_files, new_files, force_keep=force_keep)
    return render_ranked_excerpt(
        diffs,
        limit_chars=limit_chars,
        preface=preface,
        needles=added + ["dependencies", "postinstall", "preinstall", "install"],
    )


# The inline excerpt stays short. The workspace file can be larger, then stops with [TRUNCATION].
FULL_DIFF_CHAR_CAP = 1_000_000


def _is_lockfile(path: str) -> bool:
    name = _base_name(path)
    return name in LOCKFILES or name.endswith(".lock")


# New text files at or under this size are sent in full. A longer file is cut.
NEW_TEXT_FILE_BYTES = 16 * 1024
NEW_FILE_CUT_MARKER = "\n[hunter:new-file-cut]"


def _utf8_prefix(text: str, limit: int) -> str:
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text
    clipped = encoded[:limit]
    while clipped:
        try:
            return clipped.decode("utf-8")
        except UnicodeDecodeError:
            clipped = clipped[:-1]
    return ""


def _new_text_skipped(path: str, text: str) -> bool:
    if not text or not text.strip():
        return True
    if text.startswith(BINARY_MARKER) or is_binary_media(path, text):
        return True
    if _is_lockfile(path) or _is_generated_noise(path) or is_noise(path):
        return True
    from hunter.features import is_executable_binary

    if is_executable_binary(path, text):
        return True
    return False


def prepare_new_text(path: str, text: str) -> tuple[str, str] | None:
    """Body to send for one new text file, and the manifest detail.

    A file over about 16 KiB is cut. The cut body ends with NEW_FILE_CUT_MARKER.
    None means Scout does not read this path as a new text file.
    """
    if _new_text_skipped(path, text):
        return None
    if len(text.encode("utf-8")) <= NEW_TEXT_FILE_BYTES:
        return text, "new_file"
    return _utf8_prefix(text, NEW_TEXT_FILE_BYTES) + NEW_FILE_CUT_MARKER, "new_file partial"


def new_text_file_diffs(
    old_files: dict[str, str],
    new_files: dict[str, str],
    kept: list[FileDiff],
) -> tuple[list[FileDiff], bool]:
    """New text files the pattern filter dropped, up to about 16 KiB each.

    The second value is true when at least one file was cut.
    """
    kept_paths = {item.path for item in kept}
    extra: list[FileDiff] = []
    truncated = False
    for path in sorted(set(new_files) - set(old_files)):
        if path in kept_paths:
            continue
        prepared = prepare_new_text(path, new_files.get(path, ""))
        if prepared is None:
            continue
        body, detail = prepared
        if detail != "new_file":
            truncated = True
        diff_text = unified_diff(path, "", body)
        extra.append(
            FileDiff(
                path=path,
                category="new_file",
                diff_text=diff_text,
                added_text=added_lines(diff_text),
                old_text="",
                new_text=body,
            )
        )
    return extra, truncated


def _change_kind(path: str, old_files: dict[str, str], new_files: dict[str, str]) -> str:
    if path not in old_files:
        return "added"
    if path not in new_files:
        return "deleted"
    return "modified"


def _disposition(path: str, old: str, new: str, *, is_new: bool) -> tuple[str, str]:
    """Whether the noise filter kept this path, and the category or drop reason."""
    added = added_lines(unified_diff(path, old, new))
    category = categorize(path, added, new, is_new)
    if category is not None and category != "binary_media":
        return "included", category
    if _is_lockfile(path):
        return "dropped", "lockfile"
    if category == "binary_media" or is_binary_media(path, new) or is_binary_media(path, old):
        return "dropped", "binary"
    if is_source_map(path):
        return "dropped", "source map"
    if is_type_declaration(path):
        return "dropped", "type declaration"
    if is_snapshot(path):
        return "dropped", "snapshot"
    if is_test_fixture(path):
        return "dropped", "test fixture"
    if is_noise(path):
        return "dropped", "docs"
    if is_new:
        prepared = prepare_new_text(path, new)
        if prepared is not None:
            return "included", prepared[1]
    return "dropped", "no suspicious pattern"


def _changed_rows(
    old_files: dict[str, str],
    new_files: dict[str, str],
    force_keep: Mapping[str, list] | None = None,
) -> list[tuple[str, str, str, str]]:
    forced = force_keep or {}
    kind_order = {"added": 0, "deleted": 1, "modified": 2}
    paths = sorted(
        set(old_files) | set(new_files),
        key=lambda item: (kind_order[_change_kind(item, old_files, new_files)], item),
    )
    rows: list[tuple[str, str, str, str]] = []
    for path in paths:
        old = old_files.get(path, "")
        new = new_files.get(path, "")
        if old == new:
            continue
        kind = _change_kind(path, old_files, new_files)
        disposition, detail = _disposition(path, old, new, is_new=path not in old_files)
        if path in forced:
            rule_detail = _rule_hit_detail(forced[path])
            if disposition == "dropped":
                disposition, detail = "included", rule_detail
            elif forced[path]:
                detail = f"{detail}; {rule_detail}"
        rows.append((kind, disposition, path, detail))
    return _mark_bundle_duplicate_rows(rows, old_files, new_files, forced=set(forced))


def changed_file_manifest(
    old_files: dict[str, str],
    new_files: dict[str, str],
    *,
    force_keep: Mapping[str, list] | None = None,
) -> str:
    """Every added, deleted, and modified path, including ones the noise filter dropped."""
    rows = _changed_rows(old_files, new_files, force_keep)
    counts = {"added": 0, "deleted": 0, "modified": 0, "included": 0, "dropped": 0}
    lines = []
    for kind, disposition, path, detail in rows:
        counts[kind] += 1
        counts[disposition] += 1
        lines.append(f"{kind} {disposition} {path} ({detail})")
    header = (
        "counts: "
        f"added={counts['added']} deleted={counts['deleted']} modified={counts['modified']} "
        f"included={counts['included']} dropped={counts['dropped']}"
    )
    return "\n".join(["[changed_files]", header, *lines])


def _cap_text(parts: list[str], cap: int) -> str:
    chunks: list[str] = []
    used = 0
    truncated = False
    for part in parts:
        if not part:
            continue
        piece = part if not chunks else "\n" + part
        room = cap - used
        if len(piece) <= room:
            chunks.append(piece)
            used += len(piece)
            continue
        if room > 0:
            chunks.append(piece[:room])
        truncated = True
        break
    text = "".join(chunks)
    if not truncated:
        return text
    note = (
        "\n[TRUNCATION]\n"
        f"The filtered diff was cut at {cap} characters. Later content was omitted.\n"
    )
    return text + note


_CUT_NOTE = re.compile(
    r"\n\[TRUNCATION\]\nThe filtered diff was cut at \d+ characters\. Later content was omitted\.\n\Z"
)


def diff_was_cut(text: str) -> bool:
    """True when full_filtered_diff stopped at its character cap."""
    return bool(_CUT_NOTE.search(text or ""))


# An added or changed file over this size that looks minified or bundled is
# summarized in the Triage and Analyst workspace diff instead of copied in full.
BUNDLE_SUMMARY_BYTES = 64 * 1024
BUNDLE_SUMMARY_HITS = 40
BUNDLE_SUMMARY_CHARS = 24_000
BUNDLE_CONTEXT_CHARS = 300
_BUNDLE_NAME = re.compile(r"\.(?:min|bundle|umd)\.(?:js|mjs|cjs)$", re.IGNORECASE)
_MINIFIED_LINE = 5_000
_ENV_NAME = re.compile(
    r"process\.env(?:\.[A-Za-z_]\w*|\[[^\]\n]{1,80}\])"
    r"|os\.environ(?:\[[^\]\n]{1,80}\]|\.get\([^)\n]{1,80}\))?"
    r"|\bAWS_[A-Z0-9_]+"
)
_PROCESS = re.compile(
    r"\b(?:exec|execSync|execFile|spawn|spawnSync|fork|eval|system|popen)\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\("
)


def looks_bundled(path: str, text: str) -> bool:
    """Minified or bundled text: dense long lines, a very long line, or a min/bundle name."""
    if _dense_bytes_per_token(text) is not None:
        return True
    if _BUNDLE_NAME.search(path):
        return True
    return any(len(line) >= _MINIFIED_LINE for line in text.splitlines())


def _should_summarize(path: str, text: str) -> bool:
    if len(text.encode("utf-8")) <= BUNDLE_SUMMARY_BYTES:
        return False
    return looks_bundled(path, text)


def _short_sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]


def _indicator_hits(text: str) -> list[tuple[str, str, int, int]]:
    """Hosts, IPv4 literals, credential and env names, and process calls.

    Each kind is deduplicated by matched text. Kinds are interleaved so one
    kind does not fill the limit.
    """
    kinds: list[list[tuple[str, str, int, int]]] = []
    hosts: list[tuple[str, str, int, int]] = []
    seen: set[str] = set()
    for match in HOST.finditer(text):
        if not unexpected_hosts(match.group(0)):
            continue
        name = match.group(1).lower().rstrip(".")
        if name in seen:
            continue
        seen.add(name)
        hosts.append(("host", name, match.start(), match.end()))
    kinds.append(hosts)
    for kind, patterns in (
        ("ipv4", (RAW_IP,)),
        ("credential", (_ENV_NAME, ENV_TOKEN, CREDENTIAL)),
        ("process", (_PROCESS, SHELL)),
    ):
        found: list[tuple[str, str, int, int]] = []
        seen = {*LOOPBACK} if kind == "ipv4" else set()
        for pattern in patterns:
            for match in pattern.finditer(text):
                value = match.group(0)
                key = value.lower()
                if key in seen:
                    continue
                if any(match.start() < end and start < match.end() for _k, _v, start, end in found):
                    # process.env.NPM_TOKEN matches more than one pattern; show it once.
                    continue
                seen.add(key)
                found.append((kind, value, match.start(), match.end()))
        found.sort(key=lambda item: item[2])
        kinds.append(found)
    merged: list[tuple[str, str, int, int]] = []
    index = 0
    while len(merged) < BUNDLE_SUMMARY_HITS and any(index < len(group) for group in kinds):
        for group in kinds:
            if index < len(group) and len(merged) < BUNDLE_SUMMARY_HITS:
                merged.append(group[index])
        index += 1
    return merged


def bundle_summary(path: str, old: str | None, new: str) -> str:
    """Summary block that stands in for a large minified or bundled file."""
    size = len(new.encode("utf-8"))
    header = [
        f"[summarized_bundle:{path}]",
        f"The full file was summarized because of size ({size} bytes, minified or bundled). "
        "Its raw text is not included.",
        f"path: {path}",
        f"size_bytes: {size}",
        f"old_sha256: {_short_sha(old) if old is not None else 'none'}",
        f"new_sha256: {_short_sha(new)}",
        f"old_version_had_file: {'yes' if old is not None else 'no'}",
    ]
    hits = _indicator_hits(new)
    body: list[str] = []
    used = sum(len(line) + 1 for line in header) + 64
    shown = 0
    for kind, value, start, end in hits:
        left = max(0, start - BUNDLE_CONTEXT_CHARS)
        right = min(len(new), end + BUNDLE_CONTEXT_CHARS)
        context = new[left:right].replace("\x00", "")
        entry = f"- {kind} {value} at offset {start}:\n  {context}"
        if used + len(entry) + 1 > BUNDLE_SUMMARY_CHARS:
            break
        body.append(entry)
        used += len(entry) + 1
        shown += 1
    header.append(f"indicators: {shown} shown of {len(hits)} found (limit {BUNDLE_SUMMARY_HITS})")
    return "\n".join(header + body)


def full_filtered_diff(
    old_files: dict[str, str],
    new_files: dict[str, str],
    *,
    limit_chars: int = FULL_DIFF_CHAR_CAP,
    force_keep: Mapping[str, list] | None = None,
) -> str:
    """Dependency preface, changed-file manifest, then the kept diffs and new-file contents.

    Binary files stay in the manifest as dropped. Their bytes are not written out.
    Paths in `force_keep` (rule hits) are kept even when the noise filter would drop them.
    """
    rows = _changed_rows(old_files, new_files, force_keep)
    kept = {
        path
        for _kind, disposition, path, _detail in rows
        if disposition == "included"
    }
    diffs = rank_diffs(
        [item for item in diff_trees(old_files, new_files, force_keep=force_keep) if item.path in kept]
    )
    parts = [
        dependency_delta_block(old_files, new_files).strip(),
        changed_file_manifest(old_files, new_files, force_keep=force_keep).strip(),
    ]
    summarized: set[str] = set()
    for item in diffs:
        new_text = new_files.get(item.path, "")
        if item.path in new_files and _should_summarize(item.path, new_text):
            summarized.add(item.path)
            parts.append(bundle_summary(item.path, old_files.get(item.path), new_text))
            continue
        body = item.diff_text.strip() or item.added_text
        parts.append(f"--- {item.category}:{item.path}\n{body}")
    for kind, disposition, path, detail in rows:
        if kind != "added" or disposition != "included" or path in summarized:
            continue
        body = new_files.get(path, "")
        if _should_summarize(path, body):
            parts.append(bundle_summary(path, None, body))
            continue
        if detail in {"new_file", "new_file partial"}:
            prepared = prepare_new_text(path, body)
            if prepared is not None:
                body = prepared[0]
        parts.append(f"[added_file:{path}]\n{body}")
    return _cap_text(parts, limit_chars)


_DENSE_SAMPLE = 12_000
_DENSE_MIN_CHARS = 180
_LONG_LINE = 240
_ENCODED_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_CODE_PUNCTUATION = frozenset("{}[]();,")


def estimate_tokens(text: str) -> int:
    """Coarse character estimate, used only when a call reports no token count.

    Packing uses the vendored Jev counter in hunter.jev_tokens, not this function.
    Prose stays at about four characters per token. A long line with few spaces
    is counted as one token per two bytes. A long, nearly spaceless, high-entropy
    run is counted as one token per byte.
    """
    if not text:
        return 1
    ordinary = max(1, (len(text) + 3) // 4)
    per_byte = _dense_bytes_per_token(text)
    if per_byte is None:
        return ordinary
    nbytes = len(text.encode("utf-8"))
    dense = max(1, (nbytes + per_byte - 1) // per_byte)
    return max(ordinary, dense)


def _dense_bytes_per_token(text: str) -> int | None:
    sample = text[:_DENSE_SAMPLE]
    if len(sample) < _DENSE_MIN_CHARS:
        return None
    spaces = sample.count(" ") + sample.count("\t") + sample.count("\n") + sample.count("\r")
    space_ratio = spaces / len(sample)
    longest = max((len(line) for line in sample.splitlines()), default=0)
    long_line = longest >= _LONG_LINE
    if long_line and space_ratio < 0.05 and shannon_entropy(sample) >= 4.5:
        return 1
    if long_line and space_ratio < 0.12:
        return 2
    return None


def _is_encoded_alphabet(compact: str) -> bool:
    if not compact or any(char not in _ENCODED_ALPHABET for char in compact):
        return False
    return any(char.isdigit() or char in "+/" for char in compact)


def _has_code_punctuation(compact: str) -> bool:
    return any(char in _CODE_PUNCTUATION for char in compact)


def _is_bundle_path(path: str) -> bool:
    return any(part in _BUNDLE_DIRS for part in _parts(path)[:-1])


def _loose_stem(path: str) -> str:
    name = PurePosixPath(path).name.lower()
    for suffix in (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".py"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    for suffix in (".min", ".esm", ".cjs", ".umd", ".bundle", ".development", ".production"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
    return name


def _compact_text(text: str) -> str:
    return "".join(text.split())


def _mechanical_copy(bundle: str, source: str) -> bool:
    """True when the bundle is the source with whitespace removed, not a rewritten build."""
    left = _compact_text(bundle)
    right = _compact_text(source)
    if len(left) < 40 or len(right) < 40:
        return False
    if left == right:
        return True
    shorter, longer = (left, right) if len(left) <= len(right) else (right, left)
    return shorter in longer and len(shorter) / len(longer) >= 0.8


def _adds_hostile_literal(bundle: str, sources: list[str]) -> bool:
    """True when the bundle carries a hostile literal the kept source does not."""
    if not actionable_literal(bundle):
        return False
    joined = "\n".join(sources)
    if not actionable_literal(joined):
        return True
    if DECODE_EXEC.search(bundle) and not DECODE_EXEC.search(joined):
        return True
    if ENCODED_IMPORT.search(bundle) and not ENCODED_IMPORT.search(joined):
        return True
    return False


def _without_bundle_duplicates(diffs: list[FileDiff], *, forced: set[str] | None = None) -> list[FileDiff]:
    """Drop a dist or build file that is a whitespace copy of a source file already kept.

    A package that only ships the bundle keeps it. A bundle that adds a hostile
    literal the source does not have stays, so a payload that exists only in the
    bundle is still sent. A file a rule hit is never dropped.
    """
    forced = forced or set()
    sources = [item for item in diffs if not _is_bundle_path(item.path) and item.category != "binary_media"]
    if not sources:
        return diffs
    by_stem: dict[str, list[FileDiff]] = {}
    for item in sources:
        by_stem.setdefault(_loose_stem(item.path), []).append(item)
    kept: list[FileDiff] = []
    for item in diffs:
        if (
            item.path in forced
            or not _is_bundle_path(item.path)
            or is_install_script(item.path)
            or is_workflow(item.path)
            or is_entry_point(item.path)
        ):
            kept.append(item)
            continue
        twins = by_stem.get(_loose_stem(item.path), [])
        source_text = [twin.new_text for twin in twins]
        if (
            twins
            and any(_mechanical_copy(item.new_text, twin.new_text) for twin in twins)
            and not _adds_hostile_literal(item.new_text, source_text)
        ):
            continue
        kept.append(item)
    return kept


def _mark_bundle_duplicate_rows(
    rows: list[tuple[str, str, str, str]],
    old_files: dict[str, str],
    new_files: dict[str, str],
    *,
    forced: set[str] | None = None,
) -> list[tuple[str, str, str, str]]:
    forced = forced or set()
    sources: dict[str, list[str]] = {}
    for _kind, disposition, path, _detail in rows:
        if disposition != "included" or _is_bundle_path(path):
            continue
        sources.setdefault(_loose_stem(path), []).append(new_files.get(path, old_files.get(path, "")))
    if not sources:
        return rows
    updated: list[tuple[str, str, str, str]] = []
    for kind, disposition, path, detail in rows:
        text = new_files.get(path, old_files.get(path, ""))
        twins = sources.get(_loose_stem(path), [])
        if (
            disposition == "included"
            and path not in forced
            and _is_bundle_path(path)
            and not is_install_script(path)
            and not is_workflow(path)
            and not is_entry_point(path)
            and twins
            and any(_mechanical_copy(text, twin) for twin in twins)
            and not _adds_hostile_literal(text, twins)
        ):
            updated.append((kind, "dropped", path, "bundle duplicate"))
            continue
        updated.append((kind, disposition, path, detail))
    return updated
