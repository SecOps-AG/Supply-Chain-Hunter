"""Read an extracted package as text and diff MCP tool definitions.

Nothing in the tree is imported or executed. Tool descriptions stay out of
model prompts: callers store a signal id, the tool name, and a short escaped
excerpt.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

SOURCE_SUFFIXES = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}
MAX_SOURCE_BYTES = 1024 * 1024
_SKIP_DIRS = {"node_modules", "test", "tests", "__tests__", "harness"}
_HIDDEN = ("\u200b", "\u200c", "\ufeff", "\u2060", "\u180e")
_ZWJ = "\u200d"
_ZERO_WIDTH = {ord(ch): None for ch in (*_HIDDEN, _ZWJ)}

_SHELL_RE = re.compile(r"\b(?:shell|bash|subprocess|exec)\b", re.IGNORECASE)
_NET_RE = re.compile(r"\b(?:url|uri|endpoint|webhook)\b", re.IGNORECASE)
_FILE_RE = re.compile(r"\bread\s+file\b|\bwrite\s+file\b|\bfilesystem\b", re.IGNORECASE)
_SHELL_PROPS = frozenset({"command", "cmd", "shell"})
_NET_PROPS = frozenset({"url", "uri", "endpoint", "webhook"})
_FILE_PROPS = frozenset({"path", "file", "filename", "directory"})

_INSTRUCTION = (
    re.compile(
        r"ignore(?:\s+all)?\s+(?:previous|prior|above)\s+(?:instructions|prompts|rules)",
        re.IGNORECASE,
    ),
    re.compile(r"disregard\s+(?:instructions|rules|system\s+prompt)", re.IGNORECASE),
    re.compile(r"before\s+using\s+this\s+tool", re.IGNORECASE),
    re.compile(r"do\s+not\s+tell\s+the\s+user", re.IGNORECASE),
    re.compile(r"you\s+must\s+(?:read|send|exfiltrate|ignore)\b", re.IGNORECASE),
    re.compile(r"~/\.ssh\b|~/\.aws\b|~/\.npmrc\b|\bid_rsa\b", re.IGNORECASE),
)

_TOOL_ORDER = (
    "tool_instruction_added",
    "tool_hidden_unicode",
    "tool_bidi",
    "capability_shell",
    "capability_network",
    "capability_file",
)


@dataclass
class Tool:
    name: str
    description: str = ""
    properties: set[str] = field(default_factory=set)


def extract_tools(files: Mapping[str, str] | None) -> dict[str, Tool]:
    """Tool name to definition. Files are read as text. Nothing is imported or run."""
    found: dict[str, Tool] = {}
    if not files:
        return found
    for path, text in _sources(files):
        suffix = Path(path).suffix.lower()
        tools = _python_tools(text) if suffix == ".py" else _js_tools(text)
        for tool in tools:
            current = found.get(tool.name)
            if current is None:
                found[tool.name] = tool
                continue
            current.properties |= tool.properties
            if len(tool.description) > len(current.description):
                current.description = tool.description
    return found


def diff_tools(
    old: Mapping[str, str] | None,
    new: Mapping[str, str] | None,
) -> tuple[list[str], dict]:
    """Signals for tools in `new` compared with `old`.

    No previous tree means the new description is all new. Instruction, hidden
    character, and bidi checks still run. Capability signals need the same
    tool name in the previous tree, so a first release stays quiet on those.
    """
    old_tools = extract_tools(old)
    new_tools = extract_tools(new)
    hits: dict[str, list[dict]] = {}
    for name in sorted(new_tools):
        tool = new_tools[name]
        previous = old_tools.get(name)
        old_text = previous.description if previous is not None else ""
        added = tool.description if previous is None else _added_text(old_text, tool.description)
        phrase = _instruction_match(added)
        if phrase:
            _hit(hits, "tool_instruction_added", name, phrase)
        if _hidden_added(old_text, tool.description):
            _hit(hits, "tool_hidden_unicode", name, _hidden_window(tool.description))
        if _bidi_added(old_text, tool.description):
            _hit(hits, "tool_bidi", name, _bidi_window(tool.description))
        if previous is None:
            continue
        _capability(hits, previous, tool)
    signals = [name for name in _TOOL_ORDER if name in hits]
    return signals, {name: hits[name] for name in signals}


def _hit(hits: dict[str, list[dict]], signal: str, tool: str, excerpt: str) -> None:
    hits.setdefault(signal, []).append({"tool": tool, "excerpt": _escape_excerpt(excerpt)})


def _capability(hits: dict[str, list[dict]], old: Tool, new: Tool) -> None:
    if not _shell(old) and _shell(new):
        _hit(hits, "capability_shell", new.name, _shell_excerpt(old, new))
    if not _network(old) and _network(new):
        _hit(hits, "capability_network", new.name, _net_excerpt(old, new))
    if not _file_class(old) and _file_class(new):
        _hit(hits, "capability_file", new.name, _file_excerpt(old, new))


def _shell(tool: Tool) -> bool:
    return bool(_SHELL_RE.search(tool.description) or (tool.properties & _SHELL_PROPS))


def _network(tool: Tool) -> bool:
    return bool(_NET_RE.search(tool.description) or (tool.properties & _NET_PROPS))


def _file_class(tool: Tool) -> bool:
    return bool(_FILE_RE.search(tool.description) or (tool.properties & _FILE_PROPS))


def _shell_excerpt(old: Tool, new: Tool) -> str:
    added = (new.properties & _SHELL_PROPS) - (old.properties & _SHELL_PROPS)
    if added:
        return "property " + ", ".join(sorted(added))
    found = _SHELL_RE.search(new.description)
    return found.group(0) if found else ""


def _net_excerpt(old: Tool, new: Tool) -> str:
    added = (new.properties & _NET_PROPS) - (old.properties & _NET_PROPS)
    if added:
        return "property " + ", ".join(sorted(added))
    found = _NET_RE.search(new.description)
    return found.group(0) if found else ""


def _file_excerpt(old: Tool, new: Tool) -> str:
    added = (new.properties & _FILE_PROPS) - (old.properties & _FILE_PROPS)
    if added:
        return "property " + ", ".join(sorted(added))
    found = _FILE_RE.search(new.description)
    return found.group(0) if found else ""


def _collapse(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _added_text(old: str, new: str) -> str:
    """New description with phrases already present in the old one removed."""
    old_c = _collapse(old)
    new_c = _collapse(new)
    if not old_c:
        return new_c
    if old_c == new_c:
        return ""
    result = new_c
    if old_c in result:
        result = result.replace(old_c, " ")
    else:
        for piece in re.split(r"(?<=[.!?])\s+", old_c):
            piece = piece.strip()
            if len(piece) >= 8 and piece in result:
                result = result.replace(piece, " ")
    return _collapse(result)


def _instruction_match(text: str) -> str | None:
    cleaned = _collapse(text.translate(_ZERO_WIDTH))
    for pattern in _INSTRUCTION:
        found = pattern.search(cleaned)
        if found:
            return found.group(0)
    return None


def _hidden_added(old: str, new: str) -> bool:
    for ch in _HIDDEN:
        if new.count(ch) > old.count(ch):
            return True
    return _zwj_ascii(new) > _zwj_ascii(old)


def _zwj_ascii(text: str) -> int:
    count = 0
    for index, ch in enumerate(text):
        if ch != _ZWJ:
            continue
        prev = text[index - 1] if index else ""
        nxt = text[index + 1] if index + 1 < len(text) else ""
        if _ascii_letter(prev) or _ascii_letter(nxt):
            count += 1
    return count


def _ascii_letter(ch: str) -> bool:
    return len(ch) == 1 and ch.isascii() and ch.isalpha()


def _bidi_added(old: str, new: str) -> bool:
    return _bidi_count(new) > _bidi_count(old)


def _bidi_count(text: str) -> int:
    return sum(1 for ch in text if _is_bidi(ch))


def _is_bidi(ch: str) -> bool:
    code = ord(ch)
    return 0x202A <= code <= 0x202E or 0x2066 <= code <= 0x2069


def _hidden_window(text: str) -> str:
    for ch in (*_HIDDEN, _ZWJ):
        index = text.find(ch)
        if index >= 0:
            return text[max(0, index - 24) : index + 25]
    return text[:80]


def _bidi_window(text: str) -> str:
    for index, ch in enumerate(text):
        if _is_bidi(ch):
            return text[max(0, index - 24) : index + 25]
    return text[:80]


def _escape_excerpt(text: str, limit: int = 120) -> str:
    collapsed = _collapse(text)[:limit]
    out: list[str] = []
    for ch in collapsed:
        code = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif code < 32 or code == 127 or ch in _HIDDEN or ch == _ZWJ or _is_bidi(ch):
            out.append("\\u%04x" % code)
        else:
            out.append(ch)
    return "".join(out)


def _sources(files: Mapping[str, str]):
    index = None
    getter = getattr(files, "_index", None)
    if callable(getter):
        try:
            index = getter()
        except Exception:
            index = None
    for path in sorted(files):
        if not isinstance(path, str) or _skip_path(path):
            continue
        if Path(path).suffix.lower() not in SOURCE_SUFFIXES:
            continue
        if isinstance(index, dict) and path in index:
            try:
                if index[path].stat().st_size > MAX_SOURCE_BYTES:
                    continue
            except OSError:
                continue
        text = files[path]
        if not isinstance(text, str):
            continue
        if index is None and len(text.encode("utf-8", errors="replace")) > MAX_SOURCE_BYTES:
            continue
        if text.startswith("[binary-or-media-file]"):
            continue
        yield path, text


def _skip_path(path: str) -> bool:
    parts = [part for part in path.replace("\\", "/").split("/") if part not in {"", "."}]
    if not parts:
        return True
    dirs = {part.lower() for part in parts[:-1]}
    if dirs & _SKIP_DIRS:
        return True
    name = parts[-1].lower()
    if "harness" in name:
        return True
    for suffix in SOURCE_SUFFIXES:
        if name.endswith(".test" + suffix) or name.endswith(".spec" + suffix):
            return True
    if name.startswith("test_") and name.endswith(".py"):
        return True
    if name.endswith("_test.py"):
        return True
    return False


def _js_tools(text: str) -> list[Tool]:
    if "registerTool" not in text and not re.search(r"(?<![\w$])tools\s*:", text):
        return []
    schemas = _zod_schemas(text)
    found = _register_tools(text, schemas)
    found.extend(_tools_arrays(text, schemas))
    return found


def _zod_schemas(text: str) -> dict[str, set[str]]:
    schemas: dict[str, set[str]] = {}
    for match in re.finditer(r"\b([A-Za-z_$][\w$]*)\s*=\s*z\s*\.\s*object\s*\(", text):
        args = _split_args(text, match.end() - 1)
        if not args:
            continue
        props = _object_keys(text, args[0][0], args[0][1])
        if props:
            schemas[match.group(1)] = props
    return schemas


def _register_tools(text: str, schemas: dict[str, set[str]]) -> list[Tool]:
    found: list[Tool] = []
    for match in re.finditer(r"(?<![\w$])registerTool\s*\(", text):
        args = _split_args(text, match.end() - 1)
        if len(args) < 2:
            continue
        name = _js_string(text, args[0][0], args[0][1])
        if not name:
            continue
        fields = _fields(text, args[1][0], args[1][1])
        description = ""
        props: set[str] = set()
        if "description" in fields:
            start, end = fields["description"]
            description = _js_string(text, start, end) or ""
        if "inputSchema" in fields:
            start, end = fields["inputSchema"]
            props = _schema_props(text, start, end, schemas)
        found.append(Tool(name, description, props))
    return found


def _tools_arrays(text: str, schemas: dict[str, set[str]]) -> list[Tool]:
    found: list[Tool] = []
    for match in re.finditer(r"(?<![\w$])tools\s*:", text):
        index = _skip_gap(text, match.end())
        if index >= len(text) or text[index] != "[":
            continue
        end = _skip_bracket(text, index)
        cursor = index + 1
        while cursor < end:
            cursor = _skip_gap(text, cursor)
            if cursor >= end or text[cursor] == "]":
                break
            if text[cursor] == "{":
                obj_end = _skip_bracket(text, cursor)
                fields = _fields(text, cursor, obj_end)
                name = _js_string(text, *fields["name"]) if "name" in fields else None
                description = _js_string(text, *fields["description"]) if "description" in fields else ""
                props: set[str] = set()
                if "inputSchema" in fields:
                    props = _schema_props(text, *fields["inputSchema"], schemas)
                if name:
                    found.append(Tool(name, description or "", props))
                cursor = obj_end
                continue
            nxt = _skip_value(text, cursor)
            if nxt <= cursor:
                break
            cursor = nxt
    return found


def _schema_props(text: str, start: int, end: int, schemas: dict[str, set[str]]) -> set[str]:
    props: set[str] = set()
    fields = _fields(text, start, end)
    if "properties" in fields:
        prop_start, prop_end = fields["properties"]
        props |= _object_keys(text, prop_start, prop_end)
    region = text[start:end]
    for match in re.finditer(r"\bz\s*\.\s*object\s*\(", region):
        args = _split_args(text, start + match.end() - 1)
        if args:
            props |= _object_keys(text, args[0][0], args[0][1])
    if schemas:
        bare = _without_strings(region)
        for name, keys in schemas.items():
            if re.search(r"\b" + re.escape(name) + r"\b", bare):
                props |= keys
    return {key.lower() for key in props}


def _object_keys(text: str, start: int, end: int) -> set[str]:
    return set(_fields(text, start, end))


def _fields(text: str, start: int, end: int) -> dict[str, tuple[int, int]]:
    index = _skip_gap(text, start)
    if index >= end or index >= len(text) or text[index] != "{":
        return {}
    fields: dict[str, tuple[int, int]] = {}
    cursor = index + 1
    while cursor < end:
        cursor = _skip_gap(text, cursor)
        if cursor >= end or cursor >= len(text) or text[cursor] == "}":
            break
        key, cursor = _read_key(text, cursor)
        cursor = _skip_gap(text, cursor)
        if cursor < len(text) and text[cursor] == ":":
            cursor += 1
        value_at = _skip_gap(text, cursor)
        value_end = _skip_value(text, value_at)
        if value_end <= value_at:
            cursor = value_at + 1
            continue
        if key and key not in fields:
            fields[key] = (value_at, value_end)
        cursor = _skip_gap(text, value_end)
        if cursor < len(text) and text[cursor] == ",":
            cursor += 1
    return fields


def _read_key(text: str, index: int) -> tuple[str | None, int]:
    index = _skip_gap(text, index)
    if index >= len(text):
        return None, index
    if text[index] in "'\"`":
        value, end = _read_string(text, index)
        return value, end
    if text[index].isalpha() or text[index] in "_$":
        end = index + 1
        while end < len(text) and (text[end].isalnum() or text[end] in "_$"):
            end += 1
        return text[index:end], end
    return None, index + 1


def _js_string(text: str, start: int, end: int) -> str | None:
    index = _skip_gap(text, start)
    while index < end and text[index] == "(":
        index = _skip_gap(text, index + 1)
    if index >= end or text[index] not in "'\"`":
        return None
    parts: list[str] = []
    while index < end and text[index] in "'\"`":
        value, index = _read_string(text, index)
        parts.append(value)
        nxt = _skip_gap(text, index)
        if nxt < end and text[nxt] == "+":
            nxt = _skip_gap(text, nxt + 1)
            if nxt < end and text[nxt] in "'\"`":
                index = nxt
                continue
        break
    return "".join(parts)


def _read_string(text: str, index: int) -> tuple[str, int]:
    quote = text[index]
    index += 1
    out: list[str] = []
    simple = {"n": "\n", "r": "\r", "t": "\t", "\\": "\\", "'": "'", '"': '"', "`": "`", "/": "/"}
    while index < len(text):
        ch = text[index]
        if ch == "\\":
            if index + 1 >= len(text):
                break
            esc = text[index + 1]
            if esc in simple:
                out.append(simple[esc])
                index += 2
                continue
            if esc == "u" and index + 6 <= len(text) and all(c in "0123456789abcdefABCDEF" for c in text[index + 2 : index + 6]):
                out.append(chr(int(text[index + 2 : index + 6], 16)))
                index += 6
                continue
            out.append(esc)
            index += 2
            continue
        if quote == "`" and ch == "$" and index + 1 < len(text) and text[index + 1] == "{":
            index = _skip_bracket(text, index + 1)
            out.append(" ")
            continue
        if ch == quote:
            return "".join(out), index + 1
        if ch == "\n" and quote != "`":
            return "".join(out), index
        out.append(ch)
        index += 1
    return "".join(out), index


def _without_strings(text: str) -> str:
    out: list[str] = []
    index = 0
    while index < len(text):
        if text.startswith("//", index):
            newline = text.find("\n", index)
            index = len(text) if newline < 0 else newline + 1
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            index = len(text) if end < 0 else end + 2
            continue
        if text[index] in "'\"`":
            _, index = _read_string(text, index)
            out.append(" ")
            continue
        out.append(text[index])
        index += 1
    return "".join(out)


def _split_args(text: str, paren: int) -> list[tuple[int, int]]:
    if paren >= len(text) or text[paren] != "(":
        return []
    args: list[tuple[int, int]] = []
    index = paren + 1
    start = index
    stack = [")"]
    closers = {"}": "{", "]": "[", ")": "("}
    openers = {"{": "}", "[": "]", "(": ")"}
    while index < len(text):
        if text.startswith("//", index) or text.startswith("/*", index):
            index = _skip_gap(text, index)
            if index < len(text) and text[index] not in " \t\r\n":
                continue
            continue
        ch = text[index]
        if ch in "'\"`":
            _, index = _read_string(text, index)
            continue
        if ch in openers:
            stack.append(openers[ch])
            index += 1
            continue
        if stack and ch == stack[-1]:
            stack.pop()
            if not stack:
                args.append((start, index))
                return args
            index += 1
            continue
        if ch == "," and len(stack) == 1:
            args.append((start, index))
            start = index + 1
        if ch in closers and not stack:
            break
        index += 1
    return args


def _skip_value(text: str, index: int) -> int:
    index = _skip_gap(text, index)
    if index >= len(text):
        return index
    if text[index] in "'\"`":
        end = index
        while end < len(text) and text[end] in "'\"`":
            _, end = _read_string(text, end)
            nxt = _skip_gap(text, end)
            if nxt < len(text) and text[nxt] == "+":
                nxt = _skip_gap(text, nxt + 1)
                if nxt < len(text) and text[nxt] in "'\"`":
                    end = nxt
                    continue
            return nxt
        return end
    if text[index] in "{[(":
        return _skip_bracket(text, index)
    return _skip_expr(text, index)


def _skip_expr(text: str, index: int) -> int:
    stack: list[str] = []
    openers = {"{": "}", "[": "]", "(": ")"}
    while index < len(text):
        if text.startswith("//", index) or text.startswith("/*", index):
            index = _skip_comment(text, index)
            continue
        ch = text[index]
        if ch in "'\"`":
            _, index = _read_string(text, index)
            continue
        if ch in openers:
            stack.append(openers[ch])
        elif stack and ch == stack[-1]:
            stack.pop()
        elif not stack and ch in ",}])":
            break
        index += 1
    return index


def _skip_bracket(text: str, index: int) -> int:
    openers = {"{": "}", "[": "]", "(": ")"}
    if index >= len(text) or text[index] not in openers:
        return index
    stack = [openers[text[index]]]
    index += 1
    while index < len(text) and stack:
        if text.startswith("//", index) or text.startswith("/*", index):
            index = _skip_comment(text, index)
            continue
        ch = text[index]
        if ch in "'\"`":
            _, index = _read_string(text, index)
            continue
        if ch in openers:
            stack.append(openers[ch])
        elif ch == stack[-1]:
            stack.pop()
        index += 1
    return index


def _skip_gap(text: str, index: int) -> int:
    while index < len(text):
        if text[index] in " \t\r\n":
            index += 1
            continue
        if text.startswith("//", index) or text.startswith("/*", index):
            index = _skip_comment(text, index)
            continue
        break
    return index


def _skip_comment(text: str, index: int) -> int:
    if text.startswith("//", index):
        newline = text.find("\n", index)
        return len(text) if newline < 0 else newline + 1
    if text.startswith("/*", index):
        end = text.find("*/", index + 2)
        return len(text) if end < 0 else end + 2
    return index


def _python_tools(text: str) -> list[Tool]:
    """Decorator tools only. `ast` parses the source; it does not run it."""
    if ".tool" not in text:
        return []
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    enums = _enums(tree)
    found: list[Tool] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for deco in node.decorator_list:
            tool = _decorator_tool(deco, enums)
            if tool is not None:
                found.append(tool)
    return found


def _enums(tree: ast.AST) -> dict[str, str]:
    found: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef) or not _enum_class(node):
            continue
        for item in node.body:
            target, value = _assign(item)
            if target is None or value is None:
                continue
            literal = _literal(value)
            if literal is not None:
                found[f"{node.name}.{target}"] = literal
    return found


def _enum_class(node: ast.ClassDef) -> bool:
    for base in node.bases:
        name = _dotted(base)
        if name == "Enum" or name.endswith(".Enum") or (name.endswith("Enum") and name != "str"):
            return True
    return False


def _assign(node: ast.AST) -> tuple[str | None, ast.AST | None]:
    if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
        return node.targets[0].id, node.value
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
        return node.target.id, node.value
    return None, None


def _decorator_tool(node: ast.AST, enums: dict[str, str]) -> Tool | None:
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
        return None
    if node.func.attr != "tool":
        return None
    name = None
    description = ""
    for keyword in node.keywords:
        if keyword.arg == "name":
            name = _resolve(keyword.value, enums)
        elif keyword.arg == "description":
            description = _literal(keyword.value) or ""
    if not name:
        return None
    return Tool(name, description, set())


def _resolve(node: ast.AST, enums: dict[str, str]) -> str | None:
    literal = _literal(node)
    if literal is not None:
        return literal
    if isinstance(node, ast.Attribute) and node.attr == "value":
        return enums.get(_dotted(node.value))
    return None


def _literal(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _literal(node.left), _literal(node.right)
        if left is None or right is None:
            return None
        return left + right
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                parts.append(part.value)
            else:
                parts.append(" ")
        return "".join(parts)
    return None


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""
