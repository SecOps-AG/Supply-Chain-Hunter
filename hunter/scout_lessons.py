"""Scout suppression lessons. They skip Triage; they are not Triage SOP text."""

from __future__ import annotations

import fcntl
import re
from pathlib import Path

from hunter.db import iso, utcnow
from hunter.lessons import parse_lesson_fields, sanitize_rule
from hunter.models import Classification

SCOUT_LESSON_CHAR_CAP = 8_000
TEACH_CLUSTER_MIN = 3
TEACH_CLUSTER_MAX = 5
ALERT_PROBABILITY = 0.70
_TOKEN_OK = re.compile(r"^[a-z][a-z0-9_]*$")
_SUPPRESS_RE = re.compile(r"(?im)^[\s>*_`-]*suppress\**\s*:\s*\**\s*(.+?)\s*$")
_SCOUT_RE = re.compile(
    r"<!-- scout-lesson (?P<id>S\d+) (?P<key>\S+) pattern:(?P<pattern>[a-z0-9-]+) -->\n"
    r"## (?P=id) (?P<stamp>\S+)\n"
    r"(?P<body>(?:- .+\n)+)",
    re.MULTILINE,
)
_REVIEWER_LINE = re.compile(
    r"(?i)ignore\s+(?:all\s+|previous\s+|the\s+)?(?:findings|instructions|sop)"
    r"|you are a reviewer|system prompt"
)

# Presence of any of these keeps the release on the Triage path.
HARD_NEVER = frozenset(
    {
        "compound_install_payload",
        "literal_decode_exec",
        "literal_encoded_import",
        "child_alert",
        "child_unavailable",
        "rule_malicious",
    }
)


def scout_lessons_path(config) -> Path:
    raw = str(getattr(config, "scout_lessons", "") or "").strip()
    if raw:
        return Path(raw)
    db_path = getattr(config, "db_path", None)
    if db_path:
        return Path(db_path).parent / "scout-lessons.md"
    return Path("scout-lessons.md")


def normalize_signal(signal: str) -> str:
    text = str(signal or "").strip()
    if ":" in text:
        text = text.split(":", 1)[0].strip()
    return text


def signature_tokens(signals: object) -> tuple[str, ...]:
    """Sorted signal stems. Package-specific suffixes and pass-D bookkeeping are dropped."""
    if not isinstance(signals, list):
        return ()
    stems: list[str] = []
    for item in signals:
        stem = normalize_signal(str(item))
        if not stem or stem.startswith("pass_d_"):
            continue
        stems.append(stem)
    return tuple(sorted(set(stems)))


def signature_key(signals: object) -> str:
    return "+".join(signature_tokens(signals))


def parse_suppress_tokens(text: str) -> tuple[str, ...] | None:
    found = _SUPPRESS_RE.findall(text or "")
    if not found:
        return None
    parts = [piece.strip() for piece in found[-1].split(",") if piece.strip()]
    if not parts or any(_TOKEN_OK.fullmatch(part) is None for part in parts):
        return None
    return tuple(sorted(set(parts)))


def _field(body: str, name: str) -> str:
    prefix = f"- {name}:"
    for line in body.splitlines():
        if line.startswith(prefix):
            return line.split(":", 1)[1].strip()
    return ""


def parse_scout_lessons(text: str) -> list[dict[str, object]]:
    found: list[dict[str, object]] = []
    for match in _SCOUT_RE.finditer(text or ""):
        body = match.group("body")
        raw_suppress = _field(body, "suppress_if_only")
        tokens = tuple(
            sorted(
                {
                    part.strip()
                    for part in raw_suppress.split(",")
                    if part.strip() and _TOKEN_OK.fullmatch(part.strip())
                }
            )
        )
        if not tokens:
            continue
        found.append(
            {
                "id": match.group("id"),
                "key": match.group("key"),
                "pattern": match.group("pattern"),
                "stamp": match.group("stamp"),
                "signature": _field(body, "signature"),
                "rule": _field(body, "rule"),
                "suppress": tokens,
                "source": _field(body, "source"),
            }
        )
    return found


def load_scout_lessons(config) -> list[dict[str, object]]:
    path = scout_lessons_path(config)
    if not path.is_file():
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    return parse_scout_lessons(text)


def _next_id(existing: str) -> str:
    highest = 0
    for number in re.findall(r"<!-- scout-lesson S(\d+)", existing or ""):
        highest = max(highest, int(number))
    return f"S{highest + 1:04d}"


def append_scout_lesson(
    path: Path,
    *,
    signature: str,
    pattern: str,
    rule: str,
    suppress: tuple[str, ...] | list[str],
    when=None,
) -> str | None:
    """Append one signature. The same signature is written once. Source is always analyst."""
    tokens = tuple(sorted({str(item).strip() for item in suppress if str(item).strip()}))
    if not signature or not tokens or not pattern or not rule:
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(path.name + ".lock")
    stamp = iso(when or utcnow())
    rendered = ",".join(tokens)
    with lock_path.open("a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            existing = path.read_text(encoding="utf-8") if path.is_file() else ""
            known = parse_scout_lessons(existing)
            if any(str(item.get("signature") or "") == signature for item in known):
                return None
            if any(item.get("key") == signature for item in known):
                return None
            lesson_id = _next_id(existing)
            block = (
                f"<!-- scout-lesson {lesson_id} {signature} pattern:{pattern} -->\n"
                f"## {lesson_id} {stamp}\n"
                f"- signature: {signature}\n"
                f"- pattern: {pattern}\n"
                f"- rule: {rule}\n"
                f"- suppress_if_only: {rendered}\n"
                "- source: analyst\n\n"
            )
            if not existing:
                block = "# Scout lessons\n\n" + block
            if len(existing) + len(block) > SCOUT_LESSON_CHAR_CAP:
                return None
            with path.open("a", encoding="utf-8") as handle:
                handle.write(block)
            return lesson_id
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def lesson_from_teacher_text(text: str, tokens: tuple[str, ...]) -> dict[str, object] | None:
    """Accept a teacher reply only when it is benign and Suppress equals the cluster."""
    from hunter.webhook import parse_verdict

    if parse_verdict(text) != "benign":
        return None
    pattern, rule = parse_lesson_fields(text)
    clean = sanitize_rule(rule or "")
    if not pattern or not clean:
        return None
    suppress = parse_suppress_tokens(text)
    if suppress is None or set(suppress) != set(tokens) or not tokens:
        return None
    return {"pattern": pattern, "rule": clean, "suppress": suppress}


def redact_excerpt(text: str, limit: int = 1_500) -> str:
    kept: list[str] = []
    for line in (text or "").splitlines():
        if _REVIEWER_LINE.search(line):
            continue
        kept.append(line)
    return "\n".join(kept)[:limit]


def _band_probability_signals(evidence_or_result) -> tuple[str, float, list[str]]:
    if isinstance(evidence_or_result, Classification):
        return (
            str(evidence_or_result.band or ""),
            float(evidence_or_result.malice_probability or 0.0),
            list(evidence_or_result.signals or []),
        )
    if isinstance(evidence_or_result, dict):
        band = evidence_or_result.get("primary_band", evidence_or_result.get("band", ""))
        try:
            probability = float(evidence_or_result.get("malice_probability") or 0.0)
        except (TypeError, ValueError):
            probability = 0.0
        signals = evidence_or_result.get("signals") or []
        if not isinstance(signals, list):
            signals = []
        return str(band or ""), probability, [str(item) for item in signals]
    return "", 0.0, []


def suppression_blocked(band: str, probability: float, signals: list[str]) -> bool:
    """True when this release must stay on the Triage path."""
    if band not in {"review", "benign"}:
        return True
    if probability >= ALERT_PROBABILITY:
        return True
    raw = [str(item) for item in signals]
    if any(item.startswith("child_alert") or item.startswith("child_unavailable") for item in raw):
        return True
    tokens = set(signature_tokens(raw))
    if tokens & HARD_NEVER:
        return True
    if "encoded_dynamic_import" in tokens and (band != "benign" or len(tokens) > 1):
        return True
    return False


def _matching_lesson(tokens: tuple[str, ...], lessons: list[dict[str, object]]) -> dict[str, object] | None:
    token_set = set(tokens)
    if not token_set:
        return None
    candidates = []
    for lesson in lessons:
        allow = set(lesson.get("suppress") or ())
        if token_set <= allow:
            candidates.append(lesson)
    if not candidates:
        return None
    candidates.sort(key=lambda item: (len(item.get("suppress") or ()), str(item.get("id") or "")))
    return candidates[0]


def scout_lesson_suppresses(config, evidence_or_result) -> str | None:
    """Lesson id when Triage should be skipped. Default off unless the apply flag is set."""
    if not bool(getattr(config, "scout_lessons_apply", False)):
        return None
    band, probability, signals = _band_probability_signals(evidence_or_result)
    if suppression_blocked(band, probability, signals):
        return None
    tokens = signature_tokens(signals)
    lesson = _matching_lesson(tokens, load_scout_lessons(config))
    if lesson is None:
        return None
    return str(lesson["id"])
