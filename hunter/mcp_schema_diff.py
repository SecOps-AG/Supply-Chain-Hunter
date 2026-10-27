"""Diff two MCP `tools/list` manifests: descriptions and input schemas.

A manifest is JSON data (`{"tools": [...]}` or the bare list), each tool with a
`name`, a `description`, and an `inputSchema`. Nothing is imported or executed.
Signals reuse the same text checks as `hunter.mcp_tools`, but also read the
descriptions inside the input schema, and add schema-shape changes. Callers
store the signal id, the tool name, and a short escaped excerpt.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

from hunter.mcp_tools import (
    _added_text,
    _bidi_added,
    _bidi_window,
    _escape_excerpt,
    _hidden_added,
    _hidden_window,
    _instruction_match,
)

MAX_TOOLS = 500
MAX_PARAMS = 200
MAX_DEPTH = 6

_ORDER = (
    "manifest_instruction_added",
    "manifest_hidden_unicode",
    "manifest_bidi",
    "manifest_exfil_param",
    "manifest_schema_broadened",
)
# Argument names a model can fill with conversation or file content that the
# server then sends somewhere: a destination, or a free-text side channel.
_EXFIL_NAMES = frozenset(
    {
        "url", "uri", "endpoint", "webhook", "callback", "callbackurl", "email", "recipient",
        "destination", "host", "sidenote", "note", "notes", "context", "memory", "metadata",
        "conversation", "history", "systemprompt",
    }
)
_NAME_STRIP = re.compile(r"[^a-z0-9]")


def diff_manifests(old: object, new: object) -> tuple[list[str], dict]:
    """Signals for tools in `new` compared with `old`.

    No previous manifest means every description is new text: instruction,
    hidden character, and bidi checks still run. Parameter and schema checks
    need the same tool name in the previous manifest, so a new tool stays quiet
    on those.
    """
    old_tools = _tools(old)
    new_tools = _tools(new)
    hits: dict[str, list[dict]] = {}
    for name in sorted(new_tools):
        tool = new_tools[name]
        previous = old_tools.get(name)
        new_params = _params(tool.get("inputSchema"))
        old_params = _params(previous.get("inputSchema")) if previous is not None else {}
        for where, new_text, old_text in _texts(tool, new_params, previous, old_params):
            added = new_text if previous is None else _added_text(old_text, new_text)
            phrase = _instruction_match(added)
            if phrase:
                _hit(hits, "manifest_instruction_added", name, where, phrase)
            if _hidden_added(old_text, new_text):
                _hit(hits, "manifest_hidden_unicode", name, where, _hidden_window(new_text))
            if _bidi_added(old_text, new_text):
                _hit(hits, "manifest_bidi", name, where, _bidi_window(new_text))
        if previous is None:
            continue
        for path in new_params:
            if path and path not in old_params and _exfil_name(path):
                _hit(hits, "manifest_exfil_param", name, path, "new parameter " + path)
        for path, node in new_params.items():
            before = old_params.get(path)
            if before is None:
                continue
            for reason in _broadened(before, node):
                _hit(hits, "manifest_schema_broadened", name, path or "schema", reason)
    signals = [item for item in _ORDER if item in hits]
    return signals, {item: hits[item] for item in signals}


def _hit(hits: dict[str, list[dict]], signal: str, tool: str, where: str, excerpt: str) -> None:
    label = f"{where}: {excerpt}" if where else excerpt
    hits.setdefault(signal, []).append({"tool": tool, "excerpt": _escape_excerpt(label)})


def _tools(manifest: object) -> dict[str, dict]:
    items = manifest.get("tools") if isinstance(manifest, Mapping) else manifest
    found: dict[str, dict] = {}
    if not isinstance(items, list):
        return found
    for item in items[:MAX_TOOLS]:
        if isinstance(item, Mapping) and isinstance(item.get("name"), str) and item["name"]:
            found[item["name"]] = dict(item)
    return found


def _texts(tool: dict, new_params: dict, previous: dict | None, old_params: dict):
    """`(where, new text, old text)` for the tool description and each parameter description."""
    yield "", _text(tool.get("description")), _text(previous.get("description")) if previous else ""
    for path, node in new_params.items():
        if path:
            yield path, _text(node.get("description")), _text(old_params.get(path, {}).get("description"))


def _text(value: object) -> str:
    return value if isinstance(value, str) else ""


def _params(schema: object) -> dict[str, dict]:
    """Schema path to node. The root is `""`; nested objects use `a.b`, array items `a[]`."""
    found: dict[str, dict] = {}
    if isinstance(schema, Mapping):
        _walk(schema, "", found, 0)
    return found


def _walk(node: Mapping, path: str, found: dict[str, dict], depth: int) -> None:
    if len(found) >= MAX_PARAMS:
        return
    found[path] = dict(node)
    if depth >= MAX_DEPTH:
        return
    props = node.get("properties")
    if isinstance(props, Mapping):
        for key, child in props.items():
            if isinstance(key, str) and isinstance(child, Mapping):
                _walk(child, f"{path}.{key}" if path else key, found, depth + 1)
    items = node.get("items")
    if isinstance(items, Mapping):
        _walk(items, path + "[]", found, depth + 1)


def _exfil_name(path: str) -> bool:
    leaf = _NAME_STRIP.sub("", path.rsplit(".", 1)[-1].lower())
    return leaf in _EXFIL_NAMES or leaf.endswith(("url", "uri", "webhook"))


def _broadened(old: dict, new: dict) -> list[str]:
    """Ways one schema node accepts more than it did."""
    reasons: list[str] = []
    old_enum = old.get("enum")
    new_enum = new.get("enum")
    if isinstance(old_enum, list):
        if not isinstance(new_enum, list):
            reasons.append("enum removed")
        else:
            added = {repr(v) for v in new_enum} - {repr(v) for v in old_enum}
            if added:
                reasons.append("enum gained " + ", ".join(sorted(added)[:5]))
    if old.get("pattern") and not new.get("pattern"):
        reasons.append("pattern removed")
    if old.get("additionalProperties") is False and new.get("additionalProperties") is not False:
        reasons.append("additionalProperties opened")
    if _bounded(old) and not _bounded(new):
        reasons.append("length limit removed")
    return reasons


def _bounded(node: dict) -> bool:
    return node.get("type") == "string" and isinstance(node.get("maxLength"), int)
