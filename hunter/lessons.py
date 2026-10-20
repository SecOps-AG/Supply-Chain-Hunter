"""Triage SOP loader and the Analyst teach-loop file."""

from __future__ import annotations

import fcntl
import re
from pathlib import Path

from hunter.db import iso, utcnow

LESSON_CHAR_CAP = 8_000
_LESSON_RE = re.compile(
    r"<!-- lesson (?P<id>L\d+) (?P<key>\S+) pattern:(?P<pattern>[a-z0-9-]+) -->\n"
    r"## (?P=id) (?P<stamp>\S+)\n"
    r"(?P<body>(?:- .+\n)+)",
    re.MULTILINE,
)
_PATTERN_RE = re.compile(
    r"(?im)^[\s>*_`-]*pattern\**\s*:\s*\**\s*([a-z0-9]+(?:-[a-z0-9]+)*)\b"
)
_RULE_RE = re.compile(r"(?im)^[\s>*_`-]*rule\**\s*:\s*\**\s*(.+?)\s*$")
_PATTERN_OK = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_BANNED = ("verdict:", "ignore previous", "ignore the sop", "system prompt")
_SHORT_SOP = (
    "Verdict: malicious only for a real supply-chain compromise: "
    "an install-time payload, an obfuscated loader, or credential collection with a send path. "
    "A version-line restore, a historical prepare script, or a documented sandbox API is not enough. "
    "An unexpected new runtime dependency on a review or alert in dependency abuse is a compromised library, "
    "even when the excerpt is a changelog."
)


def _packaged(name: str) -> str:
    path = Path(__file__).resolve().parent / "triage_skill" / name
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8")


def sop_text() -> str:
    text = _packaged("SKILL.md").strip()
    return text or _SHORT_SOP


def lessons_path(config) -> Path:
    raw = str(getattr(config, "triage_lessons", "") or "").strip()
    if raw:
        return Path(raw)
    db_path = getattr(config, "db_path", None)
    if db_path:
        return Path(db_path).parent / "triage-lessons.md"
    return Path("triage-lessons.md")


def pending_lessons_path(config) -> Path:
    """Analyst overturns wait here until a person copies one into the production file."""
    path = lessons_path(config)
    return path.with_name(f"{path.stem}-pending{path.suffix}")


def parse_lessons(text: str) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    for match in _LESSON_RE.finditer(text or ""):
        rule = ""
        for line in match.group("body").splitlines():
            if line.startswith("- rule:"):
                rule = line.split(":", 1)[1].strip()
        if not rule:
            continue
        found.append(
            {
                "id": match.group("id"),
                "key": match.group("key"),
                "pattern": match.group("pattern"),
                "stamp": match.group("stamp"),
                "rule": rule,
            }
        )
    return found


def render_lessons(*texts: str, limit: int = LESSON_CHAR_CAP) -> str:
    items: list[dict[str, str]] = []
    for text in texts:
        items.extend(parse_lessons(text))
    items.sort(key=lambda item: item["stamp"])
    by_pattern: dict[str, dict[str, str]] = {}
    for item in items:
        by_pattern[item["pattern"]] = item
    ordered = sorted(by_pattern.values(), key=lambda item: item["stamp"], reverse=True)
    lines: list[str] = []
    total = 0
    for item in ordered:
        line = f"- [{item['pattern']}] {item['rule']}"
        extra = len(line) + (1 if lines else 0)
        if total + extra > limit:
            break
        lines.append(line)
        total += extra
    return "\n".join(lines)


def lesson_section(config=None) -> str:
    runtime = ""
    if config is not None:
        path = lessons_path(config)
        if path.is_file():
            runtime = path.read_text(encoding="utf-8")
    rendered = render_lessons(_packaged("LESSONS.md"), runtime)
    return rendered or "(none yet)"


def sanitize_rule(rule: str) -> str | None:
    text = " ".join((rule or "").split())
    if not text:
        return None
    text = text[:400]
    lowered = text.lower()
    if any(token in lowered for token in _BANNED):
        return None
    if "`" in text or "$(" in text:
        return None
    return text


def parse_lesson_fields(text: str) -> tuple[str | None, str | None]:
    patterns = _PATTERN_RE.findall(text or "")
    rules = _RULE_RE.findall(text or "")
    pattern = patterns[-1] if patterns else None
    rule = rules[-1].strip() if rules else None
    if pattern and (len(pattern) > 60 or not _PATTERN_OK.fullmatch(pattern)):
        pattern = None
    return pattern, rule


def fallback_rule(signals: object) -> str:
    shown = "none"
    if isinstance(signals, list):
        parts = [str(item) for item in signals[:8] if str(item).strip()]
        if parts:
            shown = ", ".join(parts)
    text = (
        f"Do not treat signals {shown} as malicious by themselves; this release was overturned."
    )
    return text[:400]


def _next_id(*texts: str) -> str:
    highest = 0
    for text in texts:
        for number in re.findall(r"<!-- lesson L(\d+)", text or ""):
            highest = max(highest, int(number))
    return f"L{highest + 1:04d}"


def append_triage_lesson(
    path: Path,
    *,
    package_key: str,
    package_label: str,
    signals: list[str],
    pattern: str,
    rule: str,
    source: str,
    when=None,
) -> str | None:
    """Append one overturn. The same release key is written once."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(path.name + ".lock")
    stamp = iso(when or utcnow())
    signal_text = ", ".join(signals[:12])
    with lock_path.open("a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            existing = path.read_text(encoding="utf-8") if path.is_file() else ""
            if re.search(rf"<!-- lesson L\d+ {re.escape(package_key)} ", existing):
                return None
            lesson_id = _next_id(_packaged("LESSONS.md"), existing)
            block = (
                f"<!-- lesson {lesson_id} {package_key} pattern:{pattern} -->\n"
                f"## {lesson_id} {stamp}\n"
                f"- package: {package_label}\n"
                f"- signals: {signal_text}\n"
                "- triage_verdict: malicious\n"
                "- analyst_verdict: benign\n"
                f"- pattern: {pattern}\n"
                f"- rule: {rule}\n"
                f"- source: {source}\n\n"
            )
            if not existing:
                block = "# Triage lessons\n\n" + block
            with path.open("a", encoding="utf-8") as handle:
                handle.write(block)
            return lesson_id
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def record_overturn(config, evidence: dict, report: str, *, when=None) -> str | None:
    """Write an Analyst benign overturn into the pending lessons file.

    The production lessons file is what Triage reads. A pending lesson stays
    out of that prompt until a person promotes it.
    """
    pattern, rule = parse_lesson_fields(report)
    clean = sanitize_rule(rule or "")
    source = "analyst"
    if not pattern or not clean:
        pattern = pattern or "overturned-release"
        if not _PATTERN_OK.fullmatch(pattern) or len(pattern) > 60:
            pattern = "overturned-release"
        clean = fallback_rule(evidence.get("signals"))
        source = "fallback"
    ecosystem = str(evidence.get("ecosystem") or "")
    package = str(evidence.get("package") or "")
    version = str(evidence.get("new_version") or "")
    key = str(evidence.get("idempotency_key") or "").strip() or f"{ecosystem}:{package}:{version}"
    signals = [str(item) for item in (evidence.get("signals") or [])]
    label = f"{ecosystem}/{package}@{version}".strip("/")
    return append_triage_lesson(
        pending_lessons_path(config),
        package_key=key,
        package_label=label,
        signals=signals,
        pattern=pattern,
        rule=clean,
        source=source,
        when=when,
    )
