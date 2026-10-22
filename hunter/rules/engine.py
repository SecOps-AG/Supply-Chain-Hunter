"""Run the rule pack over the text one release added. Static text only, nothing is run."""

from __future__ import annotations

import bisect
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from functools import cached_property
from pathlib import PurePosixPath

from ..archives import BINARY_MARKER, FILE_CUT_MARKER, MEDIA_SUFFIXES
from ..models import RuleHit, RuleReport
from ..triage import unified_diff
from . import structural
from .registry import RulePack, RuleSpec, load_pack
from .scope import file_classes

MATCHED_CHARS = 200
INSTANCES_PER_RULE = 8
YARA_TIMEOUT_SECONDS = 5
DECODE_ERROR_SHARE = 0.01
FONT_SUFFIXES = {".woff", ".woff2", ".ttf", ".otf", ".eot"}
NOTE_SUFFIXES = MEDIA_SUFFIXES | FONT_SUFFIXES | {".pdf", ".svg", ".tiff"}
EXECUTABLE_SUFFIXES = {".node", ".so", ".dll", ".dylib", ".exe"}
ARCHIVE_SUFFIXES = {".tgz", ".tar", ".zip", ".whl", ".jar", ".egg", ".7z", ".gz", ".bz2", ".xz"}
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


@dataclass
class Buffer:
    """The text a rule reads for one file, with the new-file line number of each line."""

    lines: list[str]
    line_numbers: list[int]

    @cached_property
    def text(self) -> str:
        return "\n".join(self.lines)

    def line_at(self, index: int) -> tuple[int, str]:
        return self.line_numbers[index], self.lines[index]


_VERSION_IN_NAME = re.compile(r"\d+(?:\.\d+)+")


def _versionless(name: str) -> str:
    """File name with version numbers blanked, so protobuf-3.20.2-nspkg.pth matches protobuf-3.20.3-nspkg.pth."""
    return _VERSION_IN_NAME.sub("#", name)


def _whole_file(text: str) -> Buffer:
    lines = text.splitlines()
    return Buffer(lines, list(range(1, len(lines) + 1)))


def added_buffer(path: str, old: str | None, new: str, diff_text: str | None = None) -> Buffer:
    """Added lines of a changed file, or the whole file when it is new."""
    if old is None:
        return _whole_file(new)
    if diff_text is None:
        diff_text = unified_diff(path, old, new)
    lines: list[str] = []
    numbers: list[int] = []
    current = 0
    for raw in diff_text.splitlines():
        if raw.startswith("+++") or raw.startswith("---"):
            continue
        head = _HUNK.match(raw)
        if head:
            current = int(head.group(1))
            continue
        if raw.startswith("+"):
            lines.append(raw[1:])
            numbers.append(current)
            current += 1
        elif raw.startswith(" "):
            current += 1
    return Buffer(lines, numbers)


def is_comment_line(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith(("//", "#", "*", "/*", '"""', "'''"))


def printable(text: str, limit: int = MATCHED_CHARS) -> str:
    """Matched text safe to show: hidden and control characters are written as escapes."""
    out = []
    for char in text:
        if char.isprintable() or char == " ":
            out.append(char)
        else:
            out.append(f"\\u{ord(char):04x}")
    joined = "".join(out)
    return joined if len(joined) <= limit else joined[: limit - 3] + "..."


def _binary_field(text: str, name: str) -> str:
    for line in text.splitlines():
        if line.startswith(f"{name}: "):
            return line[len(name) + 2 :].strip()
    return ""


def unscannable_reason(path: str, text: str) -> str | None:
    """Why a changed file cannot be read by the rules. "note:" reasons do not change the verdict."""
    suffix = PurePosixPath(path.lower()).suffix
    name = path.lower()
    if suffix in ARCHIVE_SUFFIXES or name.endswith(".tar.gz"):
        return "unscanned:nested_archive"
    if text.startswith(BINARY_MARKER):
        header = _binary_field(text, "header")
        if header not in ("", "none") or suffix in EXECUTABLE_SUFFIXES:
            return "unscanned:executable"
        if suffix in {".pyc", ".pyo"}:
            return "unscanned:compiled_py"
        if suffix == ".wasm":
            return "unscanned:wasm"
        if suffix in NOTE_SUFFIXES:
            return "note:media"
        return "unscanned:unknown_binary"
    if suffix in EXECUTABLE_SUFFIXES:
        return "unscanned:executable"
    if suffix == ".wasm":
        return "unscanned:wasm"
    if text.endswith(FILE_CUT_MARKER):
        return "unscanned:cut"
    return None


def _decode_errors(text: str) -> float:
    if not text:
        return 0.0
    return text.count("�") / len(text)


class _ReleaseScan:
    def __init__(
        self,
        pack: RulePack,
        old_files: Mapping[str, str],
        new_files: Mapping[str, str],
        ecosystem: str | None,
        diffs: Mapping[str, str] | None,
    ):
        self.pack = pack
        self.old_files = old_files
        self.new_files = new_files
        self.ecosystem = ecosystem
        self.diffs = diffs or {}
        self.report = RuleReport(pack_version=pack.version)
        self._old_by_name: dict[str, list[str]] | None = None

    def _moved_from(self, path: str) -> list[str]:
        """Old files with the same file name, so a moved file is not read as all new."""
        if self._old_by_name is None:
            grouped: dict[str, list[str]] = {}
            for old_path in self.old_files:
                grouped.setdefault(_versionless(PurePosixPath(old_path).name), []).append(old_path)
            self._old_by_name = grouped
        texts = []
        for old_path in self._old_by_name.get(_versionless(PurePosixPath(path).name), []):
            text = self.old_files[old_path]
            if not text.startswith(BINARY_MARKER):
                texts.append(text)
        return texts

    def _old_texts(self, path: str, old: str | None) -> list[str]:
        return [old] if old is not None else self._moved_from(path)

    def _is_new(self, fragment: str, new: str, old_texts: list[str]) -> bool:
        if not fragment:
            return False
        count = new.count(fragment)
        return all(count > text.count(fragment) for text in old_texts)

    def _add(self, spec: RuleSpec, path: str, line: int, matched: str) -> None:
        strong = spec.id in self.pack.strong
        hit = RuleHit(
            rule=spec.id,
            tier="strong" if strong else spec.tier,
            path=path,
            line=line,
            matched=printable(matched),
            summary=spec.summary,
        )
        if strong:
            self.report.strong_floors[spec.id] = self.pack.strong[spec.id]
        if hit.tier == "info":
            self.report.info.append(hit)
        else:
            self.report.hits.append(hit)

    def scan(self) -> RuleReport:
        started = time.perf_counter()
        for path in sorted(self.new_files):
            new = self.new_files[path]
            old = self.old_files[path] if path in self.old_files else None
            if old is not None and old == new:
                continue
            self._scan_file(path, old, new)
        report = self.report
        if report.strong_hits:
            report.verdict = "malicious"
        elif report.hits or report.unscanned:
            report.verdict = "unsure"
        else:
            report.verdict = "nothing"
        report.elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        return report

    def _scan_file(self, path: str, old: str | None, new: str) -> None:
        reason = unscannable_reason(path, new)
        if reason is not None:
            if reason.startswith("note:"):
                self.report.notes.append((path, reason[5:]))
            else:
                self.report.unscanned.append((path, reason))
            return
        classes = file_classes(path, new)
        specs = [spec for spec in self.pack.specs.values() if spec.reads(classes, self.ecosystem)]
        if not specs:
            return
        if _decode_errors(new) > DECODE_ERROR_SHARE and _decode_errors(new) > _decode_errors(old or ""):
            self.report.unscanned.append((path, "unscanned:decode"))
            return
        buffer = added_buffer(path, old, new, self.diffs.get(path))
        context = structural.FileContext(
            path=path,
            classes=classes,
            old=old,
            new=new,
            buffer=buffer,
            old_texts=self._old_texts(path, old),
            old_files=self.old_files,
            new_files=self.new_files,
        )
        wanted = {spec.id for spec in specs}
        if buffer.lines and any(line.strip() for line in buffer.lines):
            self._run_yara(context, wanted)
        for rule_id, line, matched in structural.run(context, wanted):
            self._add(self.pack.specs[rule_id], path, line, matched)

    def _run_yara(self, context: structural.FileContext, wanted: set[str]) -> None:
        import yara

        encoded_lines = [line.encode("utf-8", "surrogatepass") for line in context.buffer.lines]
        starts: list[int] = []
        offset = 0
        for raw in encoded_lines:
            starts.append(offset)
            offset += len(raw) + 1
        data = b"\n".join(encoded_lines)
        try:
            matches = self.pack.compiled.match(data=data, timeout=YARA_TIMEOUT_SECONDS)
        except yara.TimeoutError:
            self.report.unscanned.append((context.path, "unscanned:timeout"))
            return
        old_rule_ids: set[str] | None = None
        for match in matches:
            if match.rule not in wanted:
                continue
            spec = self.pack.specs[match.rule]
            if spec.newness == "rule" and context.old is not None:
                if old_rule_ids is None:
                    old_rule_ids = self._rules_in(context.old)
                if spec.id in old_rule_ids:
                    continue
            found = self._first_new_instance(spec, match, context, starts)
            if found is not None:
                self._add(spec, context.path, *found)

    def _rules_in(self, text: str) -> set[str]:
        import yara

        try:
            return {m.rule for m in self.pack.compiled.match(data=text.encode("utf-8", "surrogatepass"),
                                                             timeout=YARA_TIMEOUT_SECONDS)}
        except yara.TimeoutError:
            return set()

    def _first_new_instance(self, spec: RuleSpec, match, context: structural.FileContext, starts: list[int]):
        seen = 0
        for string in match.strings:
            for instance in string.instances:
                seen += 1
                if seen > INSTANCES_PER_RULE:
                    return None
                index = bisect.bisect_right(starts, instance.offset) - 1
                line_no, line_text = context.buffer.line_at(index)
                if spec.comments == "skip" and is_comment_line(line_text):
                    continue
                fragment = instance.matched_data.decode("utf-8", "replace")
                if spec.confirm and not structural.confirm(spec.confirm, fragment):
                    continue
                if spec.newness == "bytes" and not self._is_new(fragment, context.new, context.old_texts):
                    continue
                return line_no, fragment
        return None


def scan_release(
    old_files: Mapping[str, str],
    new_files: Mapping[str, str],
    *,
    ecosystem: str | None = None,
    diffs: Mapping[str, str] | None = None,
) -> RuleReport:
    """Scan the text this release added. `diffs` reuses unified diffs already made by triage."""
    return _ReleaseScan(load_pack(), old_files, new_files, ecosystem, diffs).scan()
