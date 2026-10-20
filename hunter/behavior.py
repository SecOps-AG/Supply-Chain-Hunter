"""Ordered install, import, and run behavior chains from added lines.

Hits stay in source order inside a phase. One direct local call is inlined so a
payload split across ``start()`` and ``send()`` still counts. Runtime chains are
recorded and do not floor the score.
"""

from __future__ import annotations

import difflib
import json
import re

from hunter.models import FileDiff
from hunter.patterns import CREDENTIAL, raw_ips, unexpected_hosts

_HIT_CAP = 24
_CALL_CAP = 8
_CHAIN_CAP = 4
_SKIP_PARTS = {"sdist", "wheel", "package"}
_NOISE_DIRS = {"test", "tests", "docs", "examples", "example", "node_modules"}
_IMPORT_NAMES = {
    "__init__.py",
    "index.js",
    "index.mjs",
    "index.cjs",
    "main.js",
    "main.mjs",
    "main.cjs",
    "main",
}
_PY_SUFFIX = {".py"}
_JS_SUFFIX = {".js", ".mjs", ".cjs", ".ts", ".tsx"}
_SOURCE_SUFFIX = _PY_SUFFIX | _JS_SUFFIX | {".sh"}

_PY_DEF = re.compile(r"^([ \t]*)(?:async[ \t]+)?def[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]*\(")
_JS_FUNC = re.compile(
    r"""(?:^|[^\w$])(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\("""
    r"""|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)"""
)
_CALL = re.compile(r"(?<![\w$])([A-Za-z_$][\w$]*)\s*\(")
_CALL_SKIP = {
    "if",
    "for",
    "while",
    "switch",
    "catch",
    "function",
    "return",
    "import",
    "await",
    "new",
    "typeof",
    "void",
    "case",
    "elif",
    "else",
    "except",
    "with",
    "assert",
    "lambda",
    "raise",
    "del",
    "yield",
    "from",
    "print",
    "super",
    "class",
    "def",
    "async",
}
_MACHINE = re.compile(
    r"socket\.gethostname\s*\(|os\.uname\s*\(|platform\.(?:node|system|machine|platform)\s*\(|"
    r"gethostname\s*\(|\bwhoami\b|getcwd\s*\(|getlogin\s*\(|os\.getlogin\s*\(|"
    r"userInfo\s*\(|homedir\s*\(|process\.cwd\s*\(|os\.getcwd\s*\(|hostname\s*\(",
    re.IGNORECASE,
)
_NETWORK = re.compile(
    r"requests\.(?:get|post|put|patch|delete|request)\s*\(|"
    r"urlopen\s*\(|urllib\.request|fetch\s*\(|"
    r"axios\.(?:get|post|put|patch|delete|request)\s*\(|"
    r"https?\.(?:get|request)\s*\(|http\.request\s*\(|"
    r"net\.connect\s*\(|socket\.connect\s*\(|"
    r"XMLHttpRequest|WebSocket\s*\(",
    re.IGNORECASE,
)
_DECODE = re.compile(
    r"\bbase64\b|atob\s*\(|Buffer\.from\s*\(|codecs\.decode\s*\(|"
    r"b64decode\s*\(|decodeURIComponent\s*\(|\bunescape\s*\(",
    re.IGNORECASE,
)
_EXEC = re.compile(
    r"\beval\s*\(|(?<![.\w])exec\s*\(|execSync\s*\(|spawn(?:Sync)?\s*\(|"
    r"\bFunction\s*\(|os\.system\s*\(|subprocess\.(?:run|call|Popen|check_output|check_call|getoutput)\s*\(|"
    r"\bPopen\s*\(|check_call\s*\(|check_output\s*\(|"
    r"curl\s+[^\n]*\|\s*(?:sh|bash)",
    re.IGNORECASE,
)


class _Marker:
    __slots__ = ("start", "kind", "label")

    def __init__(self, start: int, kind: str, label: str):
        self.start = start
        self.kind = kind
        self.label = label


def find_behavior_chains(
    old_files: dict[str, str],
    new_files: dict[str, str],
    kept: list[FileDiff],
) -> tuple[list[str], list[str]]:
    """Return ``(install/import chains, runtime chains)`` as short prose."""
    from hunter.features import _SCRIPT_FILE, added_install_commands

    kept_paths = {item.path: item for item in kept}
    install_paths = _install_paths(old_files, new_files, _SCRIPT_FILE, added_install_commands)
    import_paths = _import_paths(new_files) - install_paths
    entries = install_paths | import_paths
    triggering: list[str] = []
    runtime: list[str] = []
    inlined: set[tuple[str, str]] = set()

    for _key, command in added_install_commands(old_files, new_files):
        triggering.extend(_details("install", "package.json", _markers(command)))

    for path, item in kept_paths.items():
        if path not in entries or _binary(item.new_text) or not _source_path(path):
            continue
        phase = "install" if path in install_paths else "import"
        prose, used = _entry_chains(phase, path, item)
        triggering.extend(prose)
        inlined.update(used)

    for path, item in kept_paths.items():
        if _binary(item.new_text) or not _source_path(path):
            continue
        runtime.extend(_runtime_chains(path, item, inlined, entries))

    return triggering[:_CHAIN_CAP], runtime[:_CHAIN_CAP]


def _install_paths(old_files, new_files, script_file, added_commands) -> set[str]:
    found: set[str] = set()
    for path in set(old_files) | set(new_files):
        if path.rsplit("/", 1)[-1].lower() == "setup.py":
            found.add(path)
    for _name, command in added_commands(old_files, new_files):
        for match in script_file.finditer(command):
            target = _lookup_path(new_files, match.group(1))
            if target:
                found.add(target)
    return found


def _lookup_path(files: dict[str, str], relative: str) -> str:
    rel = relative.replace("\\", "/").strip()
    while rel.startswith("./"):
        rel = rel[2:]
    if not rel:
        return ""
    if rel in files:
        return rel
    suffix = "/" + rel
    for path in files:
        if path.endswith(suffix) or path.rsplit("/", 1)[-1] == rel:
            return path
    return ""


def _import_paths(new_files: dict[str, str]) -> set[str]:
    found: set[str] = set()
    for path in new_files:
        parts = _display_parts(path)
        if not parts or _noisy(parts):
            continue
        if parts[-1].lower() in _IMPORT_NAMES:
            found.add(path)
    for path, text in new_files.items():
        if path.rsplit("/", 1)[-1].lower() != "package.json":
            continue
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        main = data.get("main")
        if not isinstance(main, str) or not main.strip():
            continue
        target = _resolve_main(new_files, path, main)
        if target:
            found.add(target)
    return found


def _resolve_main(files: dict[str, str], manifest: str, spec: str) -> str:
    rel = spec.strip().replace("\\", "/")
    while rel.startswith("./"):
        rel = rel[2:]
    if not rel or "://" in rel:
        return ""
    folder = manifest.rsplit("/", 1)[0] if "/" in manifest else ""
    candidate = f"{folder}/{rel}" if folder else rel
    if candidate in files:
        return candidate
    suffix = "/" + rel
    for path in files:
        if path.endswith(suffix) or path.rsplit("/", 1)[-1] == rel:
            return path
    return ""


def _entry_chains(phase: str, path: str, item: FileDiff) -> tuple[list[str], set[tuple[str, str]]]:
    lines = item.new_text.splitlines()
    added = _added_indexes(item.old_text, item.new_text)
    top, functions = _layout(path, lines, item.new_text)
    seen: set[str] = set()
    markers = _markers_for(lines, top, added, functions, depth=0, seen=seen)
    if phase == "install" and "cmdclass" in item.added_text.lower() and "run" in functions and "run" not in seen:
        seen.add("run")
        markers.extend(_markers_for(lines, functions["run"], added, functions, depth=1, seen=seen))
    used = {(path, name) for name in seen}
    return _details(phase, path, markers), used


def _runtime_chains(
    path: str,
    item: FileDiff,
    inlined: set[tuple[str, str]],
    entries: set[str],
) -> list[str]:
    lines = item.new_text.splitlines()
    added = _added_indexes(item.old_text, item.new_text)
    top, functions = _layout(path, lines, item.new_text)
    found: list[str] = []
    if path not in entries:
        seen: set[str] = set()
        markers = _markers_for(lines, top, added, functions, depth=0, seen=seen)
        found.extend(_details("run", path, markers))
        for name in seen:
            inlined.add((path, name))
    for name, body in functions.items():
        if (path, name) in inlined:
            continue
        markers = _markers_for(lines, body, added, functions, depth=1, seen=set())
        found.extend(_details("run", path, markers))
    return found


def _details(phase: str, path: str, markers: list[_Marker]) -> list[str]:
    read_label = ""
    decode_seen = False
    exfil = ""
    loader = ""
    for marker in markers[:_HIT_CAP]:
        if marker.kind == "read" and not read_label:
            read_label = marker.label
        elif marker.kind == "decode" and not decode_seen:
            decode_seen = True
        elif marker.kind == "send" and read_label and not exfil:
            exfil = f"{read_label}, then {marker.label}"
        elif marker.kind == "exec" and decode_seen and not loader:
            loader = "fetch or decode payload, then execute"
    prose: list[str] = []
    if exfil:
        prose.append(f"{phase} {path}: {exfil}")
    if loader:
        prose.append(f"{phase} {path}: {loader}")
    return prose


def _markers_for(lines, indexes, added, functions, depth: int, seen: set[str]) -> list[_Marker]:
    found: list[_Marker] = []
    followed = 0
    for index in indexes:
        if index not in added or index < 0 or index >= len(lines):
            continue
        line = _code_only(lines[index])
        found.extend(_markers(line))
        if depth < 1 and followed < _CALL_CAP:
            for name in _calls(line):
                if name in seen or name not in functions:
                    continue
                seen.add(name)
                followed += 1
                found.extend(_markers_for(lines, functions[name], added, functions, depth + 1, seen))
                if len(found) >= _HIT_CAP:
                    return found[:_HIT_CAP]
        if len(found) >= _HIT_CAP:
            return found[:_HIT_CAP]
    return found


def _markers(line: str) -> list[_Marker]:
    text = _code_only(line)
    if not text.strip():
        return []
    send_label = "send to new host" if unexpected_hosts(text) or raw_ips(text) else "send over the network"
    found: list[_Marker] = []
    credential = CREDENTIAL.search(text)
    if credential:
        found.append(_Marker(credential.start(), "read", "read credential"))
    for match in _MACHINE.finditer(text):
        found.append(_Marker(match.start(), "read", "read host or user"))
    for match in _NETWORK.finditer(text):
        found.append(_Marker(match.start(), "send", send_label))
        found.append(_Marker(match.start(), "decode", "fetch or decode payload"))
    for host in unexpected_hosts(text):
        pos = text.lower().find(host.lower())
        if pos >= 0:
            found.append(_Marker(pos, "send", "send to new host"))
            found.append(_Marker(pos, "decode", "fetch or decode payload"))
    for ip in raw_ips(text):
        pos = text.find(ip)
        if pos >= 0:
            found.append(_Marker(pos, "send", "send to new host"))
            found.append(_Marker(pos, "decode", "fetch or decode payload"))
    for match in _DECODE.finditer(text):
        found.append(_Marker(match.start(), "decode", "fetch or decode payload"))
    for match in _EXEC.finditer(text):
        found.append(_Marker(match.start(), "exec", "execute"))
    return _order_markers(text, found)


def _order_markers(line: str, markers: list[_Marker]) -> list[_Marker]:
    ordered = sorted(markers, key=lambda item: (item.start, item.kind))
    for _ in range(6):
        moved = False
        for marker in ordered:
            if marker.kind not in {"send", "exec"}:
                continue
            close = _call_end(line, marker.start)
            if close is None:
                continue
            inner = [
                item
                for item in ordered
                if item.start > marker.start and item.start < close and item.kind in {"read", "decode"}
            ]
            if not inner:
                continue
            before = [item for item in ordered if item.start < marker.start and item not in inner]
            after = [
                item
                for item in ordered
                if item is not marker and item not in inner and item.start >= marker.start
            ]
            reordered = before + inner + [marker] + after
            if [id(item) for item in reordered] != [id(item) for item in ordered]:
                ordered = reordered
                moved = True
                break
        if not moved:
            break
    return ordered


def _call_end(line: str, start: int) -> int | None:
    paren = line.find("(", start)
    if paren < 0 or paren - start > 48:
        return None
    depth = 0
    quote = ""
    index = paren
    while index < len(line):
        char = line[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = ""
            index += 1
            continue
        if char in {"'", '"', "`"}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def _calls(line: str) -> list[str]:
    names: list[str] = []
    for match in _CALL.finditer(line):
        name = match.group(1)
        if name in _CALL_SKIP or name in names:
            continue
        names.append(name)
    return names


def _layout(path: str, lines: list[str], text: str) -> tuple[list[int], dict[str, list[int]]]:
    suffix = _suffix(path)
    if suffix in _PY_SUFFIX:
        return _python_layout(lines)
    if suffix in _JS_SUFFIX:
        return _js_layout(lines, text)
    return list(range(len(lines))), {}


def _python_layout(lines: list[str]) -> tuple[list[int], dict[str, list[int]]]:
    top: list[int] = []
    functions: dict[str, list[int]] = {}
    stack: list[tuple[str, int]] = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" \t")) if stripped else None
        if stripped and indent is not None:
            while stack and indent <= stack[-1][1]:
                stack.pop()
        match = _PY_DEF.match(line) if stripped else None
        if match and indent is not None:
            name = match.group(2)
            functions[name] = [index]
            stack.append((name, indent))
            continue
        if stack:
            functions[stack[-1][0]].append(index)
        else:
            top.append(index)
    return top, functions


def _js_layout(lines: list[str], text: str) -> tuple[list[int], dict[str, list[int]]]:
    depths = _line_start_depths(text)
    top: list[int] = []
    functions: dict[str, list[int]] = {}
    active: tuple[str, int] | None = None
    for index, line in enumerate(lines):
        depth = depths[index] if index < len(depths) else 0
        if active is not None and depth <= active[1]:
            active = None
        name = _js_function_name(line) if active is None else None
        if name:
            functions[name] = [index]
            if "{" in _code_only(line):
                active = (name, depth)
            continue
        if active is not None:
            functions[active[0]].append(index)
        else:
            top.append(index)
    return top, functions


def _js_function_name(line: str) -> str:
    match = _JS_FUNC.search(_code_only(line))
    if not match:
        return ""
    return match.group(1) or match.group(2) or ""


def _line_start_depths(text: str) -> list[int]:
    starts = [0]
    depth = 0
    in_sq = in_dq = in_bt = in_line = in_block = False
    index = 0
    while index < len(text):
        char = text[index]
        nxt = text[index + 1] if index + 1 < len(text) else ""
        if in_line:
            if char == "\n":
                in_line = False
                starts.append(depth)
            index += 1
            continue
        if in_block:
            if char == "*" and nxt == "/":
                in_block = False
                index += 2
                continue
            if char == "\n":
                starts.append(depth)
            index += 1
            continue
        if in_sq or in_dq or in_bt:
            if char == "\\":
                index += 2
                continue
            if (in_sq and char == "'") or (in_dq and char == '"') or (in_bt and char == "`"):
                in_sq = in_dq = in_bt = False
            if char == "\n":
                starts.append(depth)
            index += 1
            continue
        if char == "/" and nxt == "/":
            in_line = True
            index += 2
            continue
        if char == "/" and nxt == "*":
            in_block = True
            index += 2
            continue
        if char == "'":
            in_sq = True
        elif char == '"':
            in_dq = True
        elif char == "`":
            in_bt = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth = max(0, depth - 1)
        elif char == "\n":
            starts.append(depth)
        index += 1
    return starts


def _code_only(line: str) -> str:
    """Drop a trailing line comment that is outside a string."""
    out: list[str] = []
    quote = ""
    index = 0
    while index < len(line):
        char = line[index]
        nxt = line[index + 1] if index + 1 < len(line) else ""
        if quote:
            out.append(char)
            if char == "\\":
                if nxt:
                    out.append(nxt)
                index += 2
                continue
            if char == quote:
                quote = ""
            index += 1
            continue
        if char in {"'", '"', "`"}:
            quote = char
            out.append(char)
        elif char == "#" or (char == "/" and nxt == "/"):
            break
        else:
            out.append(char)
        index += 1
    return "".join(out)


def _added_indexes(old: str, new: str) -> set[int]:
    if not old:
        return set(range(len(new.splitlines())))
    added: set[int] = set()
    matcher = difflib.SequenceMatcher(a=old.splitlines(), b=new.splitlines())
    for tag, _i1, _i2, j1, j2 in matcher.get_opcodes():
        if tag in {"insert", "replace"}:
            added.update(range(j1, j2))
    return added


def _display_parts(path: str) -> list[str]:
    return [part for part in path.split("/") if part and part not in _SKIP_PARTS]


def _noisy(parts: list[str]) -> bool:
    return any(part.lower() in _NOISE_DIRS for part in parts[:-1])


def _suffix(path: str) -> str:
    name = path.rsplit("/", 1)[-1]
    if "." not in name:
        return ""
    return "." + name.rsplit(".", 1)[-1].lower()


def _source_path(path: str) -> bool:
    return _suffix(path) in _SOURCE_SUFFIX


def _binary(text: str) -> bool:
    return text.startswith("[binary-or-media-file]")
