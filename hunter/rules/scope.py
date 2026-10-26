"""Which kind of file a path is, so each rule reads only the files it is meant for."""

from __future__ import annotations

import contextvars
from contextlib import contextmanager
from pathlib import PurePosixPath

JS_EXT = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"}
PY_EXT = {".py", ".pyw"}
SHELL_EXT = {".sh", ".bash", ".ps1", ".bat", ".cmd"}
DOC_EXT = {".md", ".rst", ".txt", ".adoc"}
DOC_STEMS = {"readme", "changelog", "changes", "history", "license", "licence", "notice", "authors"}
TEST_DATA_EXT = {".json", ".txt", ".yml", ".yaml", ".csv", ".xml", ".html"}
TEST_DIRS = {"tests", "test", "__tests__", "fixtures", "__fixtures__", "testdata", "__testdata__"}
BUNDLE_DIRS = {"dist", "build", "out", "umd", "min"}
LOCKFILES = {
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "pipfile.lock",
    "uv.lock",
    "cargo.lock",
}
AGENT_CONFIG = (
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".claude.json",
    ".mcp.json",
    ".cursor/mcp.json",
    ".kiro/settings/mcp.json",
    ".vscode/tasks.json",
    ".vscode/settings.json",
)

# Words a rule may use in its scope that stand for several classes.
ALIASES = {
    "code": {"js", "py", "shell"},
    "manifest": {"npm_manifest", "py_manifest"},
}
CLASSES = {
    "js",
    "py",
    "shell",
    "pth",
    "rb",
    "gem_hook",
    "npm_manifest",
    "py_manifest",
    "gyp",
    "workflow",
    "action",
    "agent_config",
    "bundle",
    "docs",
    "test_data",
    "map",
    "lockfile",
    "other_text",
    "rust",
    "rust_build",
    "rust_manifest",
}
_RB_EXT = {".rb", ".rake", ".gemspec"}
_RB_NAMES = {"rakefile", "gemfile"}

# Paths a Cargo.toml `[package] build` key names. Set for the duration of one scan.
_RUST_BUILD: contextvars.ContextVar[frozenset[str]] = contextvars.ContextVar(
    "hunter_rust_build_paths",
    default=frozenset(),
)


@contextmanager
def rust_build_paths(paths):
    """Treat these paths as ``rust_build`` for the scan on this thread."""
    normalized = frozenset(str(path).lower().replace("\\", "/") for path in paths)
    token = _RUST_BUILD.set(normalized)
    try:
        yield
    finally:
        _RUST_BUILD.reset(token)


def expand(scope: str) -> frozenset[str]:
    """Rule scope text such as "code,manifest" as a set of file classes."""
    found: set[str] = set()
    for word in (part.strip() for part in scope.split(",")):
        if not word:
            continue
        if word in ALIASES:
            found |= ALIASES[word]
        elif word in CLASSES:
            found.add(word)
        else:
            raise ValueError(f"unknown rule scope {word!r}")
    return frozenset(found)


def _is_workflow(lowered: str, name: str) -> bool:
    wrapped = f"/{lowered}"
    if "/.github/workflows/" in wrapped or "/.circleci/" in wrapped:
        return True
    return name in {".gitlab-ci.yml", "azure-pipelines.yml", "jenkinsfile"}


def _code_class(name: str, suffix: str, text: str) -> str | None:
    if name.endswith((".d.ts", ".d.mts", ".d.cts")):
        return None
    if suffix in JS_EXT:
        return "js"
    if suffix in PY_EXT:
        return "py"
    if suffix in SHELL_EXT:
        return "shell"
    if not suffix and text.lstrip("﻿").startswith("#!"):
        return "shell"
    return None


def _is_ruby(name: str, suffix: str) -> bool:
    return suffix in _RB_EXT or name in _RB_NAMES


def _is_gem_hook(lowered: str, name: str, hook_paths) -> bool:
    """``extconf.rb``, or a path listed in the gemspec ``extensions``."""
    if name == "extconf.rb":
        return True
    if not hook_paths:
        return False
    text = lowered[2:] if lowered.startswith("./") else lowered
    for raw in hook_paths:
        hook = str(raw or "").strip().replace("\\", "/").lower()
        while hook.startswith("./"):
            hook = hook[2:]
        if hook and hook == text:
            return True
    return False


def file_classes(path: str, text: str = "", *, hook_paths=None) -> frozenset[str]:
    """Scope classes for one file. Empty means no rule reads it."""
    found = _file_classes(path, text, hook_paths=hook_paths)
    lowered = path.lower().replace("\\", "/")
    if lowered in _RUST_BUILD.get():
        return found | {"rust_build"}
    return found


def _file_classes(path: str, text: str = "", *, hook_paths=None) -> frozenset[str]:
    lowered = path.lower().replace("\\", "/")
    pure = PurePosixPath(lowered)
    classes = set(_base_classes(path, text))
    if _is_ruby(pure.name, pure.suffix):
        classes.discard("other_text")
        classes.add("rb")
    if _is_gem_hook(lowered, pure.name, hook_paths):
        classes.discard("other_text")
        classes.add("gem_hook")
    return frozenset(classes)


def _base_classes(path: str, text: str = "") -> frozenset[str]:
    """Scope classes before Ruby and install-hook tags are added."""
    lowered = path.lower().replace("\\", "/")
    pure = PurePosixPath(lowered)
    name = pure.name
    suffix = pure.suffix
    dirs = pure.parts[:-1]
    if suffix == ".map":
        return frozenset({"map"})
    if name in LOCKFILES:
        return frozenset({"lockfile"})
    if suffix == ".pth":
        return frozenset({"pth"})
    if name == "package.json":
        return frozenset({"npm_manifest"})
    if name == "setup.py":
        return frozenset({"py", "py_manifest"})
    if name in {"setup.cfg", "pyproject.toml"}:
        return frozenset({"py_manifest"})
    if name == "cargo.toml":
        return frozenset({"rust_manifest"})
    if suffix == ".rs":
        if name == "build.rs":
            return frozenset({"rust", "rust_build"})
        return frozenset({"rust"})
    if name == "binding.gyp" or suffix == ".gypi":
        return frozenset({"gyp"})
    if lowered.endswith(AGENT_CONFIG):
        return frozenset({"agent_config"})
    if _is_workflow(lowered, name):
        return frozenset({"workflow"})
    if name in {"action.yml", "action.yaml"}:
        return frozenset({"action", "workflow"})
    code = _code_class(name, suffix, text)
    if code is not None:
        if code == "js" and (any(part in BUNDLE_DIRS for part in dirs) or name.endswith((".min.js", ".bundle.js"))):
            return frozenset({"bundle"})
        return frozenset({code})
    if any(part in TEST_DIRS for part in dirs) and suffix in TEST_DATA_EXT:
        return frozenset({"test_data"})
    if suffix in DOC_EXT or pure.stem in DOC_STEMS or "docs" in dirs or "doc" in dirs:
        return frozenset({"docs"})
    return frozenset({"other_text"})
