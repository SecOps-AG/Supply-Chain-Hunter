"""Offline teach-until-catch. Sandbox lessons only. Never posts an alert."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from pathlib import Path

from hunter.config import DEFAULT_SMART_MODEL, Config, analyst_slug_allowed
from hunter.db import iso, utcnow
from hunter.fixtures_io import load_fixture
from hunter.investigate import (
    analyst_endpoint,
    build_analyst_prompt,
    build_evidence,
    build_triage_prompt,
    excerpt_for,
    run_model,
    triage_endpoint,
)
from hunter.llm import CURSOR_BACKEND, OPENROUTER_BACKEND, ModelEndpoint, normalize_backend
from hunter.triage import changed_file_manifest, full_filtered_diff
from hunter.lessons import _packaged, render_lessons, sanitize_rule, sop_text
from hunter.models import ReleaseMeta
from hunter.scout_lessons import parse_scout_lessons, scout_lessons_path
from hunter.webhook import parse_verdict, should_deliver_analysis

DEFAULT_LABEL = "compromised_lib"
FIXTURE_NOTE = "teach-fixture.md"
EXCERPT_LIMIT = 12_000
_CONTROL_NEEDLES = (
    "compromised library",
    "unexpected new runtime dependency",
    "unexpected-new-dependency",
)
_UNSAFE = ("ignore previous", "ignore the sop", "ignore all findings", "system prompt")
_NOTE_RE = re.compile(r"(?im)^\s*(?:fixture|path|trees)\s*:\s*(\S+)\s*$")
_ADDED_RE = re.compile(r"(?m)^added:\s*(.+)$")


class TeachRefused(RuntimeError):
    """The teach run refused to call a model or to touch a protected file."""


def assert_non_fast(slug: str, role: str, *, backend: str | None = None) -> str:
    """Refuse a fast Cursor slug. An explicit OpenRouter model id is kept as given."""
    text = (slug or "").strip()
    if backend is not None and normalize_backend(backend) == OPENROUTER_BACKEND:
        if not text:
            raise TeachRefused(f"{role} model id is empty")
        return text
    if not text or "fast" in text.lower() or not analyst_slug_allowed(text, allow_fast=False):
        raise TeachRefused(f"{role} model slug missing or contains fast: {text or '(empty)'}")
    return text


def resolve_triage_model(explicit: str | None = None) -> str:
    """Mid-tier, balanced model (Triage): the argument, then HUNTER_SMART_MODEL, then the CLI default."""
    env = os.environ.get("HUNTER_SMART_MODEL", "").strip()
    backend = normalize_backend(os.environ.get("HUNTER_SMART_BACKEND", CURSOR_BACKEND))
    fallback = DEFAULT_SMART_MODEL if backend == CURSOR_BACKEND else ""
    return assert_non_fast((explicit or env or fallback).strip(), "mid-tier, balanced model (Triage)", backend=backend)


def resolve_teacher_model(explicit: str | None = None) -> str:
    """Frontier model (Analyst) and teacher: the argument, then HUNTER_ANALYST_MODEL. There is no default."""
    env = os.environ.get("HUNTER_ANALYST_MODEL", "").strip()
    raw_backend = os.environ.get("HUNTER_ANALYST_BACKEND", "").strip()
    backend = (
        normalize_backend(raw_backend)
        if raw_backend
        else normalize_backend(os.environ.get("HUNTER_SMART_BACKEND", CURSOR_BACKEND))
    )
    return assert_non_fast((explicit or env).strip(), "Frontier model (Analyst)", backend=backend)


def production_should_escalate(evidence: dict, verdict: str | None, *, enabled: bool) -> bool:
    """Uncertain to Analyst, only for an alert or a dependency signal.

    This predicate is not wired into serve. Turning the flag on must still leave
    alerts off until Analyst confirms malicious under the existing gate.
    """
    if not enabled:
        return False
    if (verdict or "").strip().lower() != "uncertain":
        return False
    band = str(evidence.get("primary_band") or "")
    family = str(evidence.get("attack_family") or "")
    if band == "alert" or family == "dependency_abuse":
        return True
    return any(str(item).startswith("phantom_runtime_dependency") for item in evidence.get("signals") or [])


def strong_scout(evidence: dict) -> bool:
    band = str(evidence.get("primary_band") or "")
    if band not in {"review", "alert"}:
        return False
    if band == "alert" or str(evidence.get("attack_family") or "") == "dependency_abuse":
        return True
    for item in evidence.get("signals") or []:
        text = str(item)
        if text.startswith("phantom_runtime_dependency") or text.startswith("new_dependency"):
            return True
    return False


def teach_should_escalate(evidence: dict, verdict: str | None) -> bool:
    """Teach-loop only. Benign or uncertain on a strong Scout hit goes to Analyst."""
    text = (verdict or "").strip().lower()
    if text == "malicious":
        return False
    if text not in {"uncertain", "benign", ""}:
        return False
    return strong_scout(evidence)


def controls_mark_compromised_lib(sop: str, lessons: str) -> bool:
    blob = f"{sop}\n{lessons}".lower()
    return any(needle in blob for needle in _CONTROL_NEEDLES)


def dependency_names(evidence: dict) -> list[str]:
    found: list[str] = []
    for item in evidence.get("signals") or []:
        text = str(item)
        for prefix in ("phantom_runtime_dependency:", "new_dependency:"):
            if text.startswith(prefix):
                found.extend(part.strip() for part in text.split(":", 1)[1].split(",") if part.strip())
    excerpt = str(evidence.get("diff_excerpt") or "")
    match = _ADDED_RE.search(excerpt)
    if match:
        raw = match.group(1).strip()
        if raw and raw != "(none)":
            found.extend(part.strip() for part in raw.split(",") if part.strip() and part.strip() != "(none)")
    ordered: list[str] = []
    seen: set[str] = set()
    for name in found:
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        ordered.append(name)
    return ordered


def dependency_visible(evidence: dict) -> bool:
    names = dependency_names(evidence)
    if not names:
        return False
    excerpt = str(evidence.get("diff_excerpt") or "").lower()
    return any(name.lower() in excerpt for name in names)


def mock_triage_report(evidence: dict, sop: str, lessons: str) -> str:
    """Dry-run Composer. It follows the sandbox SOP and lessons, not a hidden verdict."""
    names = dependency_names(evidence)
    visible = dependency_visible(evidence)
    if not visible:
        return (
            "The visible excerpt is changelog and docs. No new dependency name is in the window, "
            "so this reads as release notes.\n"
            "Verdict: benign\n"
        )
    if strong_scout(evidence) and controls_mark_compromised_lib(sop, lessons):
        shown = ", ".join(names) or "the new dependency"
        return (
            f"Scout placed this in {evidence.get('primary_band')} "
            f"({evidence.get('attack_family')}). The manifest adds {shown}, "
            "and the package source does not import it. That is a compromised library. "
            "Changelog text does not explain the add.\n"
            "Verdict: malicious\n"
        )
    if strong_scout(evidence):
        return (
            "A new dependency is visible, and Scout asked for review, but the current instructions "
            "do not mark this compromised-library case as malicious.\n"
            "Verdict: uncertain\n"
        )
    return "The change does not meet the bar.\nVerdict: benign\n"


def mock_analyst_report(evidence: dict, triage_report: str) -> str:
    """Dry-run Analyst. Confirms a visible unexpected dependency. Does not post."""
    del triage_report
    if (
        dependency_visible(evidence)
        and str(evidence.get("primary_band") or "") in {"review", "alert"}
        and (
            str(evidence.get("attack_family") or "") == "dependency_abuse"
            or any(str(item).startswith("phantom_runtime_dependency") for item in evidence.get("signals") or [])
        )
    ):
        shown = ", ".join(dependency_names(evidence))
        return (
            f"The manifest adds {shown}, and the package does not import it. "
            "I confirm the compromised library.\n"
            "Verdict: malicious\n"
        )
    return "The evidence does not show a dependency add I can confirm.\nVerdict: uncertain\n"


def mock_teacher_text(context: dict) -> str:
    """Dry-run teacher. The patch stays in the sandbox until a human applies it."""
    package = str(context.get("package") or "package")
    payload = {
        "triage_lessons": [
            {
                "pattern": "unexpected-new-dependency",
                "rule": (
                    "An unexpected new runtime dependency that the package does not import, "
                    "on a Scout review or alert in the dependency abuse family, is a compromised library. "
                    "Changelog and docs do not make that add benign."
                ),
                "package": package,
            }
        ],
        "sop_tweaks": [
            {
                "heading": "Compromised library",
                "text": (
                    "An unexpected new runtime dependency is actionable for a compromised library. "
                    "When Scout's band is review or alert, or the attack family is dependency_abuse, "
                    "and the manifest adds a dependency the package source does not import, "
                    "treat it as malicious. Do not dismiss it because the excerpt is changelog or docs."
                ),
            }
        ],
        "scout_lessons": [],
        "deterministic_floors": [
            {
                "name": "manifest_before_changelog",
                "proposal": (
                    "Keep package manifest dependency adds inside the triage excerpt ahead of changelog text."
                ),
                "enable": False,
            }
        ],
        "notes": "Sandbox only. Do not post an alert. Do not suppress Scout for this label.",
    }
    return json.dumps(payload)


def strip_markdown_section(text: str, title: str) -> str:
    """Drop one second-level section. Used to ablate a control inside the sandbox."""
    target = title.strip().lower()
    skipping = False
    kept: list[str] = []
    for line in text.splitlines(keepends=True):
        if line.startswith("## "):
            heading = line[3:].strip().lower()
            if heading == target:
                skipping = True
                continue
            if skipping:
                skipping = False
        if not skipping:
            kept.append(line)
    return "".join(kept)


def parse_teacher_patch(text: str) -> dict:
    start = (text or "").find("{")
    end = (text or "").rfind("}")
    empty = {
        "triage_lessons": [],
        "sop_tweaks": [],
        "scout_lessons": [],
        "deterministic_floors": [],
        "notes": "",
        "error": "",
    }
    if start < 0 or end <= start:
        empty["error"] = "no json"
        return empty
    try:
        data = json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        empty["error"] = "bad json"
        return empty
    if not isinstance(data, dict):
        empty["error"] = "not an object"
        return empty
    empty["error"] = ""
    for key in ("triage_lessons", "sop_tweaks", "scout_lessons", "deterministic_floors"):
        value = data.get(key) or []
        empty[key] = value if isinstance(value, list) else []
    empty["notes"] = str(data.get("notes") or "")
    return empty


def _unsafe(text: str) -> bool:
    lowered = text.lower()
    return any(token in lowered for token in _UNSAFE)


def _next_lesson_id(*texts: str) -> str:
    highest = 0
    for text in texts:
        for number in re.findall(r"<!-- lesson L(\d+)", text or ""):
            highest = max(highest, int(number))
    return f"L{highest + 1:04d}"


def append_sandbox_lesson(
    path: Path,
    *,
    package_key: str,
    package_label: str,
    signals: list[str],
    pattern: str,
    rule: str,
) -> str | None:
    """Parser-compatible lesson. This is a catch lesson, not an Analyst overturn."""
    clean = sanitize_rule(rule)
    if not clean or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", pattern or "") or len(pattern) > 60:
        return None
    if _unsafe(clean):
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = path.read_text(encoding="utf-8") if path.is_file() else ""
    if re.search(rf"<!-- lesson L\d+ {re.escape(package_key)} ", existing):
        return None
    lesson_id = _next_lesson_id(_packaged("LESSONS.md"), existing)
    stamp = iso(utcnow())
    signal_text = ", ".join(signals[:12])
    block = (
        f"<!-- lesson {lesson_id} {package_key} pattern:{pattern} -->\n"
        f"## {lesson_id} {stamp}\n"
        f"- package: {package_label}\n"
        f"- signals: {signal_text}\n"
        "- triage_verdict: needs_update\n"
        "- analyst_target: confirm_malicious\n"
        f"- pattern: {pattern}\n"
        f"- rule: {clean}\n"
        "- source: teach-sandbox\n\n"
    )
    if not existing:
        block = "# Triage lessons\n\n" + block
    with path.open("a", encoding="utf-8") as handle:
        handle.write(block)
    return lesson_id


def apply_teacher_patch(sandbox: Path, patch: dict, *, package_label: str, signals: list[str]) -> dict:
    """Write teacher output under the sandbox. Scout suppression for this label is rejected."""
    applied = {
        "triage_lessons": [],
        "sop_tweaks": [],
        "floors": [],
        "rejected_scout": [],
    }
    lessons_path = sandbox / "triage-lessons.md"
    for item in patch.get("triage_lessons") or []:
        if not isinstance(item, dict):
            continue
        pattern = str(item.get("pattern") or "").strip()
        rule = str(item.get("rule") or "").strip()
        key = "teach/" + package_label.replace(" ", "") + "/" + pattern
        lesson_id = append_sandbox_lesson(
            lessons_path,
            package_key=key,
            package_label=package_label,
            signals=signals,
            pattern=pattern,
            rule=rule,
        )
        if lesson_id:
            applied["triage_lessons"].append({"id": lesson_id, "pattern": pattern, "rule": sanitize_rule(rule)})
    skill_path = sandbox / "SKILL.md"
    for tweak in patch.get("sop_tweaks") or []:
        if not isinstance(tweak, dict):
            continue
        heading = re.sub(r"\s+", " ", str(tweak.get("heading") or "Teacher tweak")).strip()[:80]
        text = str(tweak.get("text") or "").strip()
        if not heading or not text or _unsafe(heading) or _unsafe(text):
            continue
        if heading.startswith("#"):
            continue
        with skill_path.open("a", encoding="utf-8") as handle:
            handle.write(f"\n## {heading}\n\n{text}\n")
        applied["sop_tweaks"].append({"heading": heading, "text": text})
    for item in patch.get("scout_lessons") or []:
        applied["rejected_scout"].append(item if isinstance(item, dict) else {"raw": str(item)})
    floor_path = sandbox / "floor-proposals.md"
    for item in patch.get("deterministic_floors") or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "floor").strip()
        proposal = str(item.get("proposal") or "").strip()
        if not proposal or _unsafe(proposal):
            continue
        if not floor_path.exists():
            floor_path.write_text("# Floor proposals\n\nNot enabled. A human has to apply these.\n\n", encoding="utf-8")
        with floor_path.open("a", encoding="utf-8") as handle:
            handle.write(f"- {name}: {proposal} (enable={bool(item.get('enable'))}; left off)\n")
        applied["floors"].append({"name": name, "proposal": proposal, "enable": False})
    return applied


class FileGuard:
    """Remember bytes so a teach run can prove it did not touch production files."""

    def __init__(self, paths: list[Path]):
        self.paths = paths
        self.before: dict[str, bytes | None] = {}
        for path in paths:
            self.before[str(path)] = path.read_bytes() if path.is_file() else None

    def check(self) -> None:
        for path in self.paths:
            key = str(path)
            current = path.read_bytes() if path.is_file() else None
            if current != self.before[key]:
                raise TeachRefused(f"refusing to leave {path} modified")


def _read_tree(root: Path) -> dict[str, str]:
    files: dict[str, str] = {}
    if not root.is_dir():
        return files
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.stat().st_size > 1_500_000:
            continue
        data = path.read_bytes()
        if b"\x00" in data[:1024]:
            continue
        files[path.relative_to(root).as_posix()] = data.decode("utf-8", errors="replace")
    return files


def load_release(path: Path) -> tuple[ReleaseMeta, dict[str, str], dict[str, str], str]:
    """JSON fixture or an old/new text tree. Package code is read, never executed."""
    if path.is_file() and path.suffix.lower() == ".json":
        meta, old_files, new_files, _band = load_fixture(path)
        data = json.loads(path.read_text(encoding="utf-8"))
        label = str(data.get("label") or data.get("msp_label") or DEFAULT_LABEL)
        return meta, old_files, new_files, label
    if not path.is_dir():
        raise TeachRefused(f"fixture not found: {path}")
    meta_path = path / "meta.json"
    raw = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.is_file() else {}
    old_dir = path / str(raw.get("old_dir") or "old")
    new_dir = path / str(raw.get("new_dir") or "new")
    if not old_dir.is_dir() or not new_dir.is_dir():
        raise TeachRefused(f"fixture {path} needs old/ and new/ trees or a JSON file")
    meta = ReleaseMeta(
        ecosystem=str(raw.get("ecosystem") or "npm"),
        name=str(raw.get("name") or path.name),
        new_version=str(raw.get("new_version") or "new"),
        old_version=str(raw.get("old_version") or "old"),
        rank=raw.get("rank"),
        registry_url=str(raw.get("registry_url") or ""),
    )
    label = str(raw.get("label") or raw.get("msp_label") or DEFAULT_LABEL)
    return meta, _read_tree(old_dir), _read_tree(new_dir), label


def fixture_from_note(path: Path) -> str | None:
    if not path.is_file():
        return None
    match = _NOTE_RE.search(path.read_text(encoding="utf-8", errors="replace"))
    if not match:
        return None
    return match.group(1).strip()


def discover_fixture(explicit: str | None = None) -> Path | None:
    if explicit:
        return Path(explicit)
    env = os.environ.get("HUNTER_TEACH_FIXTURE", "").strip()
    if env:
        return Path(env)
    found = fixture_from_note(Path(FIXTURE_NOTE))
    if found:
        return Path(found)
    return None


def write_axios_distillation(dest: Path, *, changelog_chars: int = 20_000) -> Path:
    """Inert axios-shaped trees. A long changelog used to fill the 12k triage window.

    This is a synthetic stand-in for the attached trees. It does not contain a payload.
    """
    if dest.exists():
        shutil.rmtree(dest)
    old = dest / "old"
    new = dest / "new"
    old.mkdir(parents=True)
    new.mkdir(parents=True)
    old_manifest = {
        "name": "axios",
        "version": "1.14.0",
        "main": "index.js",
        "dependencies": {"follow-redirects": "^1.15.0"},
    }
    new_manifest = {
        "name": "axios",
        "version": "1.14.1",
        "main": "index.js",
        "dependencies": {"follow-redirects": "^1.15.0", "plain-crypto-js": "^4.2.1"},
    }
    source = 'const hops = require("follow-redirects");\nfunction get(url) { return hops.request(url); }\nmodule.exports = { get };\n'
    note = "Release notes. See https://notes.example.test/axios-notes\n"
    changelog = note * max(1, changelog_chars // len(note))
    (old / "package.json").write_text(json.dumps(old_manifest, indent=2) + "\n", encoding="utf-8")
    (new / "package.json").write_text(json.dumps(new_manifest, indent=2) + "\n", encoding="utf-8")
    (old / "index.js").write_text(source, encoding="utf-8")
    (new / "index.js").write_text(source, encoding="utf-8")
    (old / "CHANGELOG.md").write_text("Earlier notes.\n", encoding="utf-8")
    (new / "CHANGELOG.md").write_text(changelog, encoding="utf-8")
    meta = {
        "ecosystem": "npm",
        "name": "axios",
        "old_version": "1.14.0",
        "new_version": "1.14.1",
        "rank": 1,
        "label": DEFAULT_LABEL,
        "registry_url": "https://www.npmjs.com/package/axios/v/1.14.1",
        "note": "Synthetic distillation. Not the full registry trees.",
    }
    (dest / "meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    return dest


def _sandbox_sop(sandbox: Path) -> str:
    path = sandbox / "SKILL.md"
    if path.is_file():
        return path.read_text(encoding="utf-8")
    return sop_text()


def _sandbox_lessons(sandbox: Path) -> str:
    parts = []
    seed = sandbox / "LESSONS.md"
    runtime = sandbox / "triage-lessons.md"
    if seed.is_file():
        parts.append(seed.read_text(encoding="utf-8"))
    if runtime.is_file():
        parts.append(runtime.read_text(encoding="utf-8"))
    rendered = render_lessons(*parts)
    return rendered or "(none yet)"


def _init_sandbox(sandbox: Path, *, strip_sections: list[str] | None, production_scout: Path | None) -> None:
    sandbox.mkdir(parents=True, exist_ok=True)
    skill = _packaged("SKILL.md") or sop_text()
    for title in strip_sections or []:
        skill = strip_markdown_section(skill, title)
    (sandbox / "SKILL.md").write_text(skill, encoding="utf-8")
    (sandbox / "LESSONS.md").write_text(_packaged("LESSONS.md"), encoding="utf-8")
    runtime = sandbox / "triage-lessons.md"
    if not runtime.exists():
        runtime.write_text("# Triage lessons\n\n", encoding="utf-8")
    scout = sandbox / "scout-lessons.md"
    if production_scout is not None and production_scout.is_file():
        scout.write_text(production_scout.read_text(encoding="utf-8"), encoding="utf-8")
    elif not scout.exists():
        scout.write_text("# Scout lessons\n\n", encoding="utf-8")
    proposals = sandbox / "floor-proposals.md"
    if not proposals.exists():
        proposals.write_text("# Floor proposals\n\nNot enabled. A human has to apply these.\n\n", encoding="utf-8")


def _live_ready(endpoints: list[ModelEndpoint]) -> tuple[bool, str]:
    """True when every role has a model and its backend can be reached from here."""
    for endpoint in endpoints:
        if not endpoint.model:
            return False, f"no model set for the {endpoint.backend} backend"
        if endpoint.backend == CURSOR_BACKEND:
            if not shutil.which("agent"):
                return False, "agent CLI is not installed"
            if not os.environ.get("CURSOR_API_KEY", "").strip():
                return False, "CURSOR_API_KEY is unset"
        if endpoint.backend == OPENROUTER_BACKEND and not endpoint.api_key:
            from hunter.openrouter import OPENROUTER_KEY_MISSING

            return False, OPENROUTER_KEY_MISSING
    return True, ""


def _scout(meta, old_files, new_files, jev):
    from hunter.classify import classify_files

    return classify_files(meta=meta, old_files=old_files, new_files=new_files, jev=jev)


def _default_jev():
    from hunter.fake_jev import KeywordJev

    return KeywordJev()


def _run_live(prompt: str, endpoint: ModelEndpoint, evidence: dict | None = None) -> str:
    assert_non_fast(endpoint.model, "live", backend=endpoint.backend)
    return run_model(prompt, endpoint, evidence=evidence)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def run_teach(
    fixture: Path,
    *,
    max_rounds: int = 5,
    out_dir: Path | None = None,
    sandbox: Path | None = None,
    mode: str = "auto",
    triage_model: str | None = None,
    teacher_model: str | None = None,
    strip_sections: list[str] | None = None,
    protect: list[Path] | None = None,
    jev=None,
    triage_runner=None,
    analyst_runner=None,
    teacher_runner=None,
    timeout: float = 300.0,
    analyst_timeout: float | None = None,
) -> dict:
    """Scout, Triage, and Analyst until the alert gate would open. Nothing is posted.

    Lessons land in the sandbox. Production scout lessons and the packaged SOP stay put.
    """
    if mode not in {"auto", "mock", "live"}:
        raise TeachRefused(f"unknown teach mode {mode}")
    env_config = Config.from_env()
    ready, reason = True, ""
    triage_slug = teacher_slug = ""
    try:
        triage_slug = resolve_triage_model(triage_model)
        teacher_slug = resolve_teacher_model(teacher_model)
    except TeachRefused as exc:
        if mode == "live" or (triage_model or teacher_model):
            raise
        ready, reason = False, str(exc)
    triage_point = triage_endpoint(env_config)
    triage_point.model = triage_slug
    teacher_point = analyst_endpoint(env_config, timeout=timeout)
    teacher_point.model = teacher_slug
    if ready:
        ready, reason = _live_ready([triage_point, teacher_point])
    if mode == "live" and not ready:
        raise TeachRefused(reason)
    analyst_slug = teacher_slug
    use_live = mode == "live" or (mode == "auto" and ready)
    if triage_runner or analyst_runner or teacher_runner:
        use_live = False
    label_mode = "live" if use_live else "mock"
    meta, old_files, new_files, label = load_release(Path(fixture))
    out = Path(out_dir) if out_dir else Path("teach-sandbox")
    box = Path(sandbox) if sandbox else out / "sandbox"
    production_scout = scout_lessons_path(env_config)
    if analyst_timeout is None:
        analyst_timeout = env_config.analyst_timeout
    triage_point.timeout = timeout
    analyst_point = analyst_endpoint(env_config, timeout=analyst_timeout)
    analyst_point.model = analyst_slug
    skill_file = Path(__file__).resolve().parent / "triage_skill" / "SKILL.md"
    lessons_file = Path(__file__).resolve().parent / "triage_skill" / "LESSONS.md"
    guarded = FileGuard([*(protect or []), production_scout, skill_file, lessons_file])
    _init_sandbox(box, strip_sections=strip_sections, production_scout=production_scout if production_scout.is_file() else None)
    webhook_set = bool(os.environ.get("ALERT_WEBHOOK_URL", "").strip())
    result = {
        "success": False,
        "refused": "",
        "mode": label_mode,
        "live_reason": "" if use_live else (reason or "mock runner"),
        "triage_model": triage_slug or "mock",
        "teacher_model": teacher_slug or "mock",
        "analyst_model": analyst_slug or "mock",
        "label": label,
        "package": meta.name,
        "ecosystem": meta.ecosystem,
        "old_version": meta.old_version,
        "new_version": meta.new_version,
        "fixture": str(fixture),
        "sandbox": str(box),
        "alert_sent": False,
        "would_alert": False,
        "webhook_ignored": True,
        "webhook_env_was_set": webhook_set,
        "production_files_untouched": True,
        "escalate_uncertain_default": False,
        "lessons_proposed": [],
        "floor_proposals": [],
        "scout_lesson_proposals_rejected": [],
        "rounds": [],
    }
    client = jev if jev is not None else _default_jev()
    package_label = f"{meta.ecosystem}/{meta.name}@{meta.new_version}"
    prior_benign = 0
    try:
        for number in range(1, max(1, max_rounds) + 1):
            scout = _scout(meta, old_files, new_files, client)
            excerpt = excerpt_for(old_files, new_files)
            evidence = build_evidence(
                scout,
                excerpt,
                manifest=changed_file_manifest(old_files, new_files),
                full_diff=full_filtered_diff(old_files, new_files),
            )
            evidence["diff_excerpt"] = excerpt[:EXCERPT_LIMIT]
            evidence["label"] = label
            sop = _sandbox_sop(box)
            lessons = _sandbox_lessons(box)
            if triage_runner is not None:
                triage_text = str(triage_runner(evidence, sop, lessons))
            elif use_live:
                prompt = build_triage_prompt(evidence, sop_override=sop, lessons_override=lessons)
                triage_text = _run_live(prompt, triage_point, evidence)
            else:
                triage_text = mock_triage_report(evidence, sop, lessons)
            triage_verdict = parse_verdict(triage_text)
            escalated = teach_should_escalate(evidence, triage_verdict)
            analyst_text = ""
            analyst_verdict = None
            call_analyst = triage_verdict == "malicious" or escalated
            if call_analyst:
                analyst_evidence = dict(evidence)
                analyst_evidence["triage_report"] = triage_text
                analyst_evidence["triage_verdict"] = triage_verdict or ""
                if analyst_runner is not None:
                    analyst_text = str(analyst_runner(analyst_evidence, sop, lessons))
                elif use_live:
                    prompt = build_analyst_prompt(
                        analyst_evidence, sop_override=sop, lessons_override=lessons
                    )
                    analyst_text = _run_live(prompt, analyst_point, analyst_evidence)
                else:
                    analyst_text = mock_analyst_report(analyst_evidence, triage_text)
                analyst_verdict = parse_verdict(analyst_text)
            would = bool(
                scout.band in {"review", "alert"}
                and triage_verdict == "malicious"
                and analyst_verdict == "malicious"
                and should_deliver_analysis(
                    evidence,
                    analyst_verdict,
                    confirmed_by="analyst",
                )
            )
            if triage_verdict == "benign":
                prior_benign += 1
            round_row = {
                "round": number,
                "scout_band": scout.band,
                "attack_family": scout.attack_family,
                "subtype": scout.subtype,
                "malice_probability": scout.malice_probability,
                "signals": list(scout.signals),
                "dep_visible": dependency_visible(evidence),
                "dependency_names": dependency_names(evidence),
                "excerpt_sha256": _sha(excerpt),
                "excerpt_chars": len(excerpt),
                "triage_verdict": triage_verdict,
                "triage_model": triage_slug,
                "analyst_verdict": analyst_verdict,
                "analyst_model": analyst_slug if call_analyst else "",
                "escalated": escalated,
                "would_alert": would,
                "alert_sent": False,
                "teacher_called": False,
            }
            if out_dir is not None:
                out.mkdir(parents=True, exist_ok=True)
                (out / f"round-{number}-excerpt.txt").write_text(excerpt, encoding="utf-8")
                (out / f"round-{number}-triage.txt").write_text(triage_text, encoding="utf-8")
                if analyst_text:
                    (out / f"round-{number}-analyst.txt").write_text(analyst_text, encoding="utf-8")
            if would:
                result["rounds"].append(round_row)
                result["success"] = True
                result["would_alert"] = True
                break
            if number == max(1, max_rounds):
                result["rounds"].append(round_row)
                break
            context = {
                "label": label,
                "package": package_label,
                "scout_band": scout.band,
                "attack_family": scout.attack_family,
                "signals": list(scout.signals),
                "triage_report": triage_text[:4000],
                "analyst_report": analyst_text[:4000],
                "diff_excerpt": excerpt[:EXCERPT_LIMIT],
                "sop": sop,
                "lessons": lessons,
                "scout_lessons": (box / "scout-lessons.md").read_text(encoding="utf-8")
                if (box / "scout-lessons.md").is_file()
                else "",
            }
            if teacher_runner is not None:
                teacher_text = str(teacher_runner(context))
            elif use_live:
                teacher_text = _run_live(_teacher_prompt(context), teacher_point)
            else:
                teacher_text = mock_teacher_text(context)
            patch = parse_teacher_patch(teacher_text)
            applied = apply_teacher_patch(box, patch, package_label=package_label, signals=list(scout.signals))
            round_row["teacher_called"] = True
            round_row["teacher_error"] = patch.get("error") or ""
            result["lessons_proposed"].extend(applied["triage_lessons"])
            result["floor_proposals"].extend(applied["floors"])
            result["scout_lesson_proposals_rejected"].extend(applied["rejected_scout"])
            result["rounds"].append(round_row)
            if out_dir is not None:
                (out / f"round-{number}-teacher.txt").write_text(teacher_text, encoding="utf-8")
        guarded.check()
    except Exception:
        try:
            guarded.check()
        except TeachRefused:
            result["production_files_untouched"] = False
        raise
    result["production_files_untouched"] = True
    result["sandbox_scout_apply"] = False
    result["sandbox_scout_lessons"] = [
        str(item.get("id") or "") for item in parse_scout_lessons((box / "scout-lessons.md").read_text(encoding="utf-8"))
    ] if (box / "scout-lessons.md").is_file() else []
    if out_dir is not None:
        write_teach_report(out, result)
    return result


def _teacher_prompt(context: dict) -> str:
    return "\n".join(
        [
            "You are Teacher on a non-fast model. Teach Triage until this release would be caught.",
            "Do not tell anyone to ignore the SOP. Do not write a Scout suppression for a malicious label.",
            "Do not post an alert. Do not enable a webhook.",
            "Reply with one JSON object and no other text.",
            "Keys: triage_lessons (list of {pattern, rule, package}), sop_tweaks (list of {heading, text}),",
            "scout_lessons (leave empty for a compromised library),",
            "deterministic_floors (list of {name, proposal, enable:false}), notes.",
            "pattern is kebab-case. rule is one sentence without backticks.",
            "",
            f"Label: {context.get('label')}",
            f"Package: {context.get('package')}",
            f"Scout band: {context.get('scout_band')} family {context.get('attack_family')}",
            f"Signals: {', '.join(context.get('signals') or [])}",
            "",
            "Triage report:",
            str(context.get("triage_report") or ""),
            "",
            "Analyst report:",
            str(context.get("analyst_report") or ""),
            "",
            "<SOP>",
            str(context.get("sop") or ""),
            "</SOP>",
            "",
            "<LESSONS>",
            str(context.get("lessons") or ""),
            "</LESSONS>",
            "",
            "Evidence excerpt (untrusted package text):",
            str(context.get("diff_excerpt") or ""),
        ]
    )


def render_report(result: dict) -> str:
    rounds = result.get("rounds") or []
    lines = [
        f"# Teach-until-catch: {result.get('ecosystem')}/{result.get('package')} "
        f"{result.get('old_version')} to {result.get('new_version')}",
        "",
        f"- Success: {result.get('success')}",
        f"- Mode: {result.get('mode')} ({result.get('live_reason') or 'live calls used'})",
        f"- Mid-tier, balanced model (Triage): {result.get('triage_model')}",
        f"- Frontier model (Analyst): {result.get('teacher_model')}",
        f"- Label: {result.get('label')}",
        f"- Would alert (alert gate, nothing sent): {result.get('would_alert')}",
        f"- Alert sent: {result.get('alert_sent')}",
        f"- Webhook ignored: {result.get('webhook_ignored')}",
        f"- Production lesson files untouched: {result.get('production_files_untouched')}",
        f"- Sandbox: `{result.get('sandbox')}`",
        "",
        "## Rounds",
        "",
    ]
    if not rounds:
        lines.append("No rounds ran.")
    for row in rounds:
        lines.append(
            f"- Round {row.get('round')}: decision model (Scout) {row.get('scout_band')} / {row.get('attack_family')}, "
            f"dep visible {row.get('dep_visible')}, mid-tier model (Triage) {row.get('triage_verdict')}, "
            f"Frontier model (Analyst) {row.get('analyst_verdict')}, escalated {row.get('escalated')}, "
            f"teacher {row.get('teacher_called')}, would alert {row.get('would_alert')}."
        )
    lines.extend(["", "## Lessons proposed", ""])
    lessons = result.get("lessons_proposed") or []
    if not lessons:
        lines.append("None. The sandbox instructions already satisfied the gate, or the loop stopped first.")
    for item in lessons:
        lines.append(f"- `{item.get('pattern')}`: {item.get('rule')}")
    floors = result.get("floor_proposals") or []
    lines.extend(["", "## Floor proposals (not enabled)", ""])
    if not floors:
        lines.append("None.")
    for item in floors:
        lines.append(f"- {item.get('name')}: {item.get('proposal')}")
    rejected = result.get("scout_lesson_proposals_rejected") or []
    if rejected:
        lines.extend(["", "## Rejected Scout suppressions", ""])
        for item in rejected:
            lines.append(f"- {item}")
    lines.extend(
        [
            "",
            "## Draft pull request",
            "",
            "Title: Teach-until-catch for a compromised library manifest",
            "",
            "Offline loop that ranks the triage excerpt so a changelog cannot hide a new dependency,",
            "then teaches Triage in a sandbox until Scout, Triage, and Analyst would have alerted.",
            "No webhook is set. Production scout lessons stay untouched until a human says so.",
            "",
        ]
    )
    return "\n".join(lines) + "\n"


def write_teach_report(out: Path, result: dict) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "rounds.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "REPORT.md").write_text(render_report(result), encoding="utf-8")
