"""Rules and confirmers that are easier to write in Python than in YARA."""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..patterns import HOST
from ..patterns import _host_allowed as host_allowed
from ..triage import STARTUP_HOOK_NAMES, new_pth_import_lines

if TYPE_CHECKING:
    from .engine import Buffer

RAW_IP = re.compile(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?![\w.])")
IP_URL = re.compile(r"https?://((?:\d{1,3}\.){3}\d{1,3})")
WHITESPACE_RUN = re.compile(r"[ \t]{400,}(\S[^\n]{0,60})")
SPACE_RUN = " " * 400
TAB_RUN = "\t" * 400
JS_EVAL = re.compile(r"\beval\s*\(|\bFunction\s*\(")
PY_EXEC = re.compile(r"\b(exec|eval)\s*\(")
DEPENDENCY_KEYS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
GIT_SHORTHAND = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+#[0-9a-f]{7,40}$")
REMOTE_ARCHIVE = re.compile(r"^https?://\S+\.(tgz|tar\.gz|tar|zip)(?:[?#]\S*)?$", re.IGNORECASE)


@dataclass
class FileContext:
    path: str
    classes: frozenset[str]
    old: str | None
    new: str
    buffer: Buffer
    old_texts: list[str]
    old_files: Mapping[str, str]
    new_files: Mapping[str, str]


def public_ip(text: str) -> str | None:
    """The address when `text` holds a public IPv4 address, else None."""
    for candidate in RAW_IP.findall(text) or IP_URL.findall(text):
        try:
            address = ipaddress.IPv4Address(candidate)
        except ValueError:
            continue
        if address.is_global:
            return candidate
    return None


def confirm(name: str, fragment: str) -> bool:
    if name == "public_ip_url":
        return public_ip(fragment) is not None
    raise ValueError(f"unknown confirmer {name!r}")


def _matches_outside_comments(context: FileContext, pattern: re.Pattern[str]) -> Iterator[tuple[int, str]]:
    """Each match of `pattern` in the added text, with its line number, skipping comment lines."""
    from .engine import is_comment_line

    text = context.buffer.text
    line_index = 0
    line_start = 0
    for found in pattern.finditer(text):
        while True:
            line_end = text.find("\n", line_start)
            if line_end < 0 or line_end >= found.start():
                break
            line_start = line_end + 1
            line_index += 1
        line_no, line = context.buffer.line_at(line_index)
        if not is_comment_line(line):
            yield line_no, found.group(1) if pattern.groups else found.group(0)


def _raw_ip(context: FileContext) -> Iterator[tuple[int, str]]:
    for line_no, candidate in _matches_outside_comments(context, RAW_IP):
        address = public_ip(candidate)
        if address and all(text.count(address) < context.new.count(address) for text in context.old_texts):
            yield line_no, address
            return


def _hidden_whitespace(context: FileContext, runner: re.Pattern[str]) -> Iterator[tuple[int, str]]:
    added = context.buffer.text
    if SPACE_RUN not in added and TAB_RUN not in added:
        return
    if not runner.search(context.new):
        return
    new_runs = len(WHITESPACE_RUN.findall(context.new))
    if any(len(WHITESPACE_RUN.findall(text)) >= new_runs for text in context.old_texts):
        return
    for index, line in enumerate(context.buffer.lines):
        found = WHITESPACE_RUN.search(line)
        if found:
            yield context.buffer.line_numbers[index], f"[{len(line) - len(line.lstrip())} spaces] {found.group(1)}"
            return


def _dependencies(text: str | None) -> dict[str, str]:
    if not text:
        return {}
    try:
        data = json.loads(text)
    except ValueError:
        return {}
    found: dict[str, str] = {}
    if not isinstance(data, dict):
        return found
    for key in DEPENDENCY_KEYS:
        block = data.get(key)
        if isinstance(block, dict):
            for name, spec in block.items():
                if isinstance(spec, str):
                    found[name] = spec
    return found


def _risky_dependency_spec(spec: str) -> bool:
    value = spec.strip()
    lowered = value.lower()
    if lowered.startswith("http://") or lowered.startswith("git+http://"):
        return True
    if IP_URL.match(value):
        return True
    if bool(REMOTE_ARCHIVE.match(value)):
        return True
    # Code pulled from a git host instead of the registry, so the registry tarball never shows it.
    if lowered.startswith(("github:", "gitlab:", "bitbucket:", "git+", "git://", "git@")):
        return True
    return bool(GIT_SHORTHAND.match(value))


def _line_of(text: str, needle: str) -> int:
    position = text.find(needle)
    if position < 0:
        return 1
    return text.count("\n", 0, position) + 1


def _url_dependency(context: FileContext) -> Iterator[tuple[int, str]]:
    old = _dependencies(context.old)
    for name, spec in _dependencies(context.new).items():
        if old.get(name) == spec or not _risky_dependency_spec(spec):
            continue
        yield _line_of(context.new, f'"{name}"'), f'"{name}": "{spec}"'
        return


NOT_CODE = (".md", ".map", ".d.ts", ".txt", ".lock", "license", "changelog.md")


def _phantom_dependency(context: FileContext) -> Iterator[tuple[int, str]]:
    """A runtime dependency added in this release that no shipped file ever loads.

    Only `dependencies` and `optionalDependencies` count: those are installed for
    every user, so an unused one exists only for its own install scripts.
    """
    if not context.path.endswith("package.json") or context.path.count("/") > 1:
        return
    try:
        old_data = json.loads(context.old) if context.old else {}
        new_data = json.loads(context.new)
    except ValueError:
        return
    if not isinstance(new_data, dict) or not isinstance(old_data, dict) or not old_data:
        return
    old_names = set()
    for key in DEPENDENCY_KEYS:
        if isinstance(old_data.get(key), dict):
            old_names |= set(old_data[key])
    added = []
    for key in ("dependencies", "optionalDependencies"):
        block = new_data.get(key)
        if isinstance(block, dict):
            added += [name for name in block if name not in old_names and not name.startswith("@types/")]
    if not added or len(added) > 3:
        return
    files = context.new_files or {}
    texts = [text for path, text in files.items()
             if path != context.path and not path.lower().endswith(NOT_CODE)
             and not path.lower().endswith(("package-lock.json", "yarn.lock", "pnpm-lock.yaml"))]
    for name in added:
        if not any(name in text for text in texts):
            yield _line_of(context.new, f'"{name}"'), f'"{name}" added but never loaded'
            return


def _utf16(context: FileContext) -> Iterator[tuple[int, str]]:
    new_paths = getattr(context.new_files, "utf16_paths", None) or set()
    old_paths = getattr(context.old_files, "utf16_paths", None) or set()
    if context.path in new_paths and context.path not in old_paths:
        yield 1, "file is UTF-16 encoded"


def _base_name(path: str) -> str:
    return path.replace("\\", "/").rsplit("/", 1)[-1].lower()


def _new_pth_lines(context: FileContext) -> list[tuple[int, str]]:
    """Import lines this .pth gained. A hook the old release shipped unchanged has none."""
    return new_pth_import_lines(context.path, context.new, context.old_texts)


def _new_hook_lines(context: FileContext) -> list[tuple[int, str]]:
    """Code lines a sitecustomize.py or usercustomize.py gained, new file or edit."""
    from .engine import is_comment_line

    if _base_name(context.path) not in STARTUP_HOOK_NAMES:
        return []
    old_lines = {line.strip() for text in context.old_texts for line in text.splitlines()}
    found = []
    for index, line in enumerate(context.buffer.lines):
        if line.strip() and not is_comment_line(line) and line.strip() not in old_lines:
            found.append((context.buffer.line_numbers[index], line.strip()))
    return found


def _pth_import_line(context: FileContext) -> Iterator[tuple[int, str]]:
    for line_no, line in _new_pth_lines(context):
        yield line_no, line
        return


def _startup_hook_file(context: FileContext) -> Iterator[tuple[int, str]]:
    for line_no, line in _new_hook_lines(context):
        yield line_no, f"{_base_name(context.path)}: {line}"
        return


def _startup_hook_payload(context: FileContext) -> Iterator[tuple[int, str]]:
    """A new startup hook that loads a module this release adds at the top of site-packages,
    where that module decodes and runs code or reaches the network.

    A new hook that loads the package's own code, or a new module with none of those, stays weak.
    """
    from ..features import (
        install_target,
        is_new_install,
        new_top_level_module,
        payload_indicators,
        pth_imported_modules,
    )

    is_pth = context.path.lower().endswith(".pth")
    hook_lines = _new_pth_lines(context) if is_pth else _new_hook_lines(context)
    if not hook_lines:
        return
    old_files = dict(context.old_files)
    new_files = dict(context.new_files)
    target = install_target(new_files, context.path)
    if target is None or "/" in target:
        return
    if is_pth:
        for line_no, line in hook_lines:
            for module in pth_imported_modules(line):
                for path in new_top_level_module(old_files, new_files, module):
                    found = payload_indicators(new_files[path])
                    if found:
                        yield line_no, f"{line.strip()} -> {path}: {','.join(found)}"
                        return
        return
    if not is_new_install(old_files, target):
        return
    found = payload_indicators(context.new)
    if found:
        yield hook_lines[0][0], f"{target}: {','.join(found)}"


def _new_host(context: FileContext) -> Iterator[tuple[int, str]]:
    for line_no, raw in _matches_outside_comments(context, HOST):
        host = raw.lower().rstrip(".")
        if not host or host_allowed(host) or any(host in text.lower() for text in context.old_texts):
            continue
        yield line_no, host
        return


RULES = {
    "h_raw_ip": _raw_ip,
    "js_hidden_whitespace": lambda context: _hidden_whitespace(context, JS_EVAL),
    "py_hidden_whitespace": lambda context: _hidden_whitespace(context, PY_EXEC),
    "npm_url_dependency": _url_dependency,
    "utf16_code_file": _utf16,
    "npm_phantom_dependency": _phantom_dependency,
    "h_new_host": _new_host,
    "pth_import_line": _pth_import_line,
    "py_startup_hook_file": _startup_hook_file,
    "startup_hook_payload": _startup_hook_payload,
}


def run(context: FileContext, wanted: set[str]) -> Iterator[tuple[str, int, str]]:
    for rule_id, rule in RULES.items():
        if rule_id not in wanted:
            continue
        for line_no, matched in rule(context):
            yield rule_id, line_no, matched
