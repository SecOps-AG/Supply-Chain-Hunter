"""Three passes of the decision model (Scout) and the logistic head. The head, not a single Noul, makes the call.

`jev` is whichever decision model HUNTER_SCOUT_MODEL selected (Jev or Clef). The name is kept so callers and
stored signals (`jev_retry`, `jev_unreadable`) do not change. OpenRouter does not replace this path.
"""

from __future__ import annotations

import logging
import os

from hunter import JEV_MODEL_ID
from hunter.bands import (
    GATE_LOW,
    REVIEW_FLOOR,
    REVIEW_THRESHOLD,
    decide_band,
)
from hunter.features import extract_features
from hunter.head import feature_vector, load_head
from hunter.jev import (
    STATE_TOKEN_BUDGET,
    JevResult,
    JevUnavailable,
    build_state,
    max_pool,
    pack_chunks,
    slice_state,
)
from hunter.jev_tokens import predict_input_tokens
from hunter.models import Classification, CodeFeatures, FileDiff, ReleaseMeta, RuleReport
from hunter.patterns import CREDENTIAL, DECODE_EXEC, ENCODED_IMPORT, PERSISTENCE, SHELL, XOR, raw_ips
from hunter.model_limits import input_limit, overflow_route, state_budget
from hunter.scout_model import ContextOverflow, head_name, state_token_budget
from hunter.questions import (
    BEHAVIORAL_NOULS,
    PASS_A_IDS,
    PASS_B_IDS,
    pass_a_questions,
    pass_b_questions,
    pass_c_questions,
    subtype_questions,
)
from hunter.taxonomy import SUBTYPES, winning_families
from hunter.archives import FILE_CUT_MARKER, aligned_release_trees
from hunter.rules import rules_enabled, scan_release
from hunter.triage import (
    NEW_FILE_CUT_MARKER,
    changed_diffs,
    changed_file_manifest,
    diff_trees,
    new_text_file_diffs,
    render_excerpt,
)

log = logging.getLogger(__name__)


class _SkipGate(Exception):
    """The rule verdict asks for a full read, so Pass A does not run."""

# Pass B input tokens one release may use. A bigger release is not read by Scout;
# it goes to Triage as unread. 0 turns the cap off.
SCOUT_RELEASE_TOKENS = 10_000_000


def scout_release_token_cap() -> int:
    raw = os.environ.get("HUNTER_SCOUT_RELEASE_TOKENS", "").strip()
    if not raw:
        return SCOUT_RELEASE_TOKENS
    try:
        return max(0, int(raw))
    except ValueError:
        log.warning("HUNTER_SCOUT_RELEASE_TOKENS=%r is not a whole number; using %s", raw, SCOUT_RELEASE_TOKENS)
        return SCOUT_RELEASE_TOKENS


# A release over the cap is not sent to Triage unread. Scout reads its riskiest files
# first, up to this many Pass B tokens, and the row is marked as a partial read.
# 0 turns the partial read off: an over-cap release goes to Triage unread again.
SCOUT_PARTIAL_TOKENS = 1_000_000
# Read order for a partial read. Lower reads first. Files in no tier are not read.
_RISK_TIERS = {
    "install_scripts": 0,
    "workflows": 0,
    "entry_points": 1,
    "suspicious_payload": 2,
    "suspicious_source": 2,
    "changed_code": 1,
    "new_file": 3,
}
# Rough upper bound on text characters per Pass B token, used to pick the files to pack.
_CHARS_PER_TOKEN = 4


def scout_partial_token_budget() -> int:
    raw = os.environ.get("HUNTER_SCOUT_PARTIAL_TOKENS", "").strip()
    if not raw:
        return SCOUT_PARTIAL_TOKENS
    try:
        return max(0, int(raw))
    except ValueError:
        log.warning("HUNTER_SCOUT_PARTIAL_TOKENS=%r is not a whole number; using %s", raw, SCOUT_PARTIAL_TOKENS)
        return SCOUT_PARTIAL_TOKENS


def riskiest_first(diffs: list[FileDiff]) -> list[FileDiff]:
    """Files in partial-read order: install and manifest files, entry points, files with
    suspicious text, then new files. Smaller files first within a tier, then by path."""
    ranked = [item for item in diffs if item.category in _RISK_TIERS]
    return sorted(
        ranked,
        key=lambda item: (_RISK_TIERS[item.category], len(item.diff_text or item.new_text or ""), item.path),
    )


def partial_read_chunks(
    diffs: list[FileDiff],
    meta: ReleaseMeta,
    *,
    budget: int,
    pack_budget: int,
    changed_files: str | None,
) -> tuple[list[dict], int]:
    """Chunks for the riskiest files that fit in ``budget`` Pass B tokens.

    Returns the chunks and the number of files they cover in full or in part. The
    changed-file list states always come first. Returns no chunks when not even the
    first file fits.
    """
    if budget <= 0:
        return [], 0
    ordered = riskiest_first(diffs)
    picked: list[FileDiff] = []
    chars = 0
    for item in ordered:
        size = len(item.diff_text or item.new_text or "") + len(item.path)
        if picked and chars + size > budget * _CHARS_PER_TOKEN:
            break
        picked.append(item)
        chars += size
    if not picked:
        return [], 0
    packed = pack_chunks(picked, meta, budget=pack_budget, changed_files=changed_files)
    questions = pass_b_questions()
    chunks: list[dict] = []
    total = 0
    for state in packed:
        total += predict_input_tokens(state, questions)
        if total > budget:
            break
        chunks.append(state)
    read_paths: set[str] = set()
    for state in chunks:
        read_paths.update(str(path) for path in state.get("file_paths") or [])
    files = sum(1 for item in picked if item.path in read_paths)
    if not files:
        return [], 0
    return chunks, files


def _over_release_tokens(chunks: list[dict], cap: int) -> bool:
    if cap <= 0:
        return False
    questions = pass_b_questions()
    total = 0
    for state in chunks:
        total += predict_input_tokens(state, questions)
        if total > cap:
            return True
    return False


def _note_local_signals(state: dict, code: CodeFeatures) -> None:
    notes = []
    if code.phantom_runtime_dependencies:
        notes.append("local_signal phantom_runtime_dependency: " + ",".join(code.phantom_runtime_dependencies))
    if code.outside_package_files:
        notes.append("local_signal outside_package_install: " + ",".join(code.outside_package_files[:12]))
    if code.wheel_only_files:
        notes.append("local_signal wheel_only_file: " + ",".join(code.wheel_only_files[:12]))
    if code.build_config_changes:
        notes.append("local_signal build_config_change: " + ",".join(code.build_config_changes[:4]))
    if not notes:
        return
    state["diff_excerpt"] = (state.get("diff_excerpt") or "") + "\n" + "\n".join(notes)
    state["local_signals"] = code.signal_list()


# Two or more of these at CONSENSUS_NOUL or higher, plus a hostile literal in the
# diff, floor the score at review even when the head scores the release low.
CONSENSUS_NOULS = (
    "decode_then_run",
    "network",
    "credential_read",
    "shell_child_process",
    "embedded_payload",
)
CONSENSUS_NOUL = 0.9
CONSENSUS_COUNT = 2


def jev_consensus(nouls: dict[str, float], code: CodeFeatures) -> bool:
    """Jev is sure about two core behaviors and the code has a matching literal."""
    sure = sum(1 for key in CONSENSUS_NOULS if float(nouls.get(key, 0.0)) >= CONSENSUS_NOUL)
    literal = code.literal_decode_exec or code.literal_shell or code.literal_raw_ip
    return sure >= CONSENSUS_COUNT and bool(literal)


def jev_unsure(nouls: dict[str, float]) -> bool:
    """True when a behavioral Noul is not a clear no."""
    return any(float(nouls.get(key, 0.0)) >= GATE_LOW for key in BEHAVIORAL_NOULS)


# Local facts. A Jev answer name such as install_time_execution is not in this set.
_WARNING_SIGNALS = frozenset(
    {
        "lifecycle_script_edits",
        "literal_decode_exec",
        "literal_shell",
        "literal_raw_ip",
        "literal_credential",
        "literal_xor",
        "literal_encoded_import",
        "literal_minified_payload",
        "literal_new_host",
        "literal_persistence",
        "compound_install_payload",
        "entrypoint_payload",
        "install_sidecar",
        "new_binary",
        "binary_media_change",
        "partial_read",
        "rule_malicious",
        "rule_unsure",
    }
)
_WARNING_PREFIXES = (
    "rule:",
    "unscanned:",
    "phantom_runtime_dependency:",
    "dependency_typosquat:",
    "typosquat_name:",
    "behavior_chain:",
    "runtime_behavior_chain:",
    "outside_package_install:",
    "wheel_only_file:",
    "build_config_change:",
)


# A benign row goes to Triage only when Jev is fairly sure about a behavior and the
# diff has a local sign that is new in this release. Common release noise (a new URL,
# a minified bundle, a native binary, a script edit) does not route by itself.
ROUTE_NOUL = 0.80
# Structural signs route by themselves.
_ROUTE_STRUCTURAL = frozenset(
    {
        "compound_install_payload",
        "entrypoint_payload",
        "install_sidecar",
        "new_binary",
        "partial_read",
        "rule_malicious",
    }
)
_ROUTE_STRUCTURAL_PREFIXES = (
    "phantom_runtime_dependency:",
    "dependency_typosquat:",
    "typosquat_name:",
    "behavior_chain:",
    "outside_package_install:",
    "build_config_change:",
)
# These literals route by themselves when the previous version did not have them.
_ROUTE_STRONG_LITERALS = frozenset({"literal_decode_exec", "literal_raw_ip", "literal_encoded_import"})
# A new behavior literal, or a runtime behavior chain, routes with one more sign.
_ROUTE_BEHAVIOR_LITERALS = frozenset({"literal_shell", "literal_credential", "literal_xor", "literal_persistence"})
_ROUTE_BEHAVIOR_PREFIX = "runtime_behavior_chain:"
# Signs that only count next to a behavior sign.
_ROUTE_CONTEXT = frozenset(
    {"lifecycle_script_edits", "literal_minified_payload", "literal_new_host", "binary_media_change"}
)
_LITERAL_MATCHERS = {
    "literal_decode_exec": DECODE_EXEC.search,
    "literal_shell": SHELL.search,
    "literal_raw_ip": raw_ips,
    "literal_credential": CREDENTIAL.search,
    "literal_xor": XOR.search,
    "literal_encoded_import": ENCODED_IMPORT.search,
    "literal_persistence": PERSISTENCE.search,
}


def literals_in_old(names: set[str], old_files: dict[str, str]) -> set[str]:
    """The literal signals in ``names`` that the previous version's text already had."""
    found: set[str] = set()
    wanted = [name for name in sorted(names) if name in _LITERAL_MATCHERS]
    if not wanted:
        return found
    for text in old_files.values():
        if not isinstance(text, str) or not text:
            continue
        for name in wanted:
            if name not in found and _LITERAL_MATCHERS[name](text):
                found.add(name)
        if len(found) == len(wanted):
            break
    return found


def unsure_route(nouls: dict[str, float], signals: list[str], old_files: dict[str, str]) -> bool:
    """True when a benign row should still go to Triage.

    Jev must give a behavioral Noul of at least ROUTE_NOUL, and the diff must have one of:
    a structural sign, a new decode/raw-IP/encoded-import literal, or a new behavior
    literal or runtime behavior chain together with one more sign.
    """
    if not any(float(nouls.get(key, 0.0)) >= ROUTE_NOUL for key in BEHAVIORAL_NOULS):
        return False
    present = set(signals)
    if present & _ROUTE_STRUCTURAL or any(sig.startswith(_ROUTE_STRUCTURAL_PREFIXES) for sig in present):
        return True
    literals = present & (_ROUTE_STRONG_LITERALS | _ROUTE_BEHAVIOR_LITERALS)
    if not literals and not any(sig.startswith(_ROUTE_BEHAVIOR_PREFIX) for sig in present):
        return False
    new_literals = literals - literals_in_old(literals, old_files)
    if new_literals & _ROUTE_STRONG_LITERALS:
        return True
    behavior = new_literals & _ROUTE_BEHAVIOR_LITERALS
    if any(sig.startswith(_ROUTE_BEHAVIOR_PREFIX) for sig in present):
        behavior.add(_ROUTE_BEHAVIOR_PREFIX)
    return bool(behavior) and len(behavior | (present & _ROUTE_CONTEXT)) >= 2


def has_warning_sign(signals: list[str]) -> bool:
    """True when the diff has a local fact, not only a mid-range Jev answer.

    Install-script edits, a new executable, a credential read, network or decode
    literals, and a partial read are warning signs. A Noul by itself is not.
    """
    for signal in signals:
        if signal in _WARNING_SIGNALS or signal.startswith(_WARNING_PREFIXES):
            return True
    return False


def _blank(
    meta: ReleaseMeta,
    *,
    band: str,
    probability: float,
    model_id: str,
    signals: list[str],
    family: str = "none",
    subtype: str | None = None,
) -> Classification:
    return Classification(
        ecosystem=meta.ecosystem,
        name=meta.name,
        old_version=meta.old_version,
        new_version=meta.new_version,
        rank=meta.rank,
        registry_url=meta.registry_url,
        band=band,
        malice_probability=probability,
        jev_model_id=model_id,
        attack_family=family,
        subtype=subtype,
        signals=signals,
    )


def _stage_reason(exc: BaseException, stage: str) -> str:
    """Stable retry reason. Local heuristics are not a verdict."""
    text = str(exc).lower()
    if "503" in text or "service unavailable" in text:
        return "gateway_503"
    if "max_tokens" in text or "max tokens" in text or "context length" in text:
        return "max_tokens"
    if "missing noul" in text or "missing answer" in text:
        return f"{stage}_missing_answers"
    return f"jev_{stage}_failed"


def _deferred(
    meta: ReleaseMeta,
    code: CodeFeatures,
    model_id: str,
    reason: str,
    *,
    probability: float = 0.0,
) -> Classification:
    """Incomplete Jev work. Not an alert, review, or benign verdict."""
    signals = code.signal_list() + ["ai_incomplete", "jev_retry", reason]
    row = _blank(
        meta,
        band="deferred",
        probability=round(probability, 4),
        model_id=model_id,
        signals=signals,
    )
    row.defer_reason = reason
    row.needs_llm_review = False
    return row


def _apply_score_floors(code: CodeFeatures, probability: float, head) -> float:
    """Local structural floors. They still apply when Jev cannot read the text.

    Levels come from the weight file when it has a floors object. Otherwise the
    built-in levels apply. A null level leaves that signal off.
    """
    checks = (
        ("compound_install_payload", bool(code.compound_install_payload)),
        (
            "phantom_or_typosquat",
            bool(code.phantom_runtime_dependencies or code.dependency_typosquats or code.package_typosquat),
        ),
        ("entrypoint_payload", bool(code.entrypoint_payload)),
        ("install_sidecar", bool(code.install_sidecar)),
        ("behavior_chains", bool(code.behavior_chains)),
        ("outside_package_install", bool(code.outside_package_files)),
    )
    for name, active in checks:
        if not active:
            continue
        level = head.floor_level(name)
        if level is None:
            continue
        probability = max(probability, level)
    rule_level = _rule_floor(code, head)
    if rule_level is not None:
        probability = max(probability, rule_level)
    return probability


def _review_unread(
    meta: ReleaseMeta,
    code: CodeFeatures,
    model_id: str,
    head,
    *,
    probability: float = 0.0,
) -> Classification:
    """Jev could not read this release. Floors still run, and Triage reviews it."""
    probability = max(_apply_score_floors(code, probability, head), REVIEW_THRESHOLD)
    family = "none"
    subtype = None
    cause = "unknown"
    if code.phantom_runtime_dependencies:
        family = "dependency_abuse"
        subtype = "new_unrelated"
    if code.dependency_typosquats and family in ("", "none"):
        family = "dependency_abuse"
        subtype = subtype or "new_unrelated"
    if code.package_typosquat and cause in ("", "unknown"):
        cause = "typosquat_name"
    band = "review"
    return Classification(
        ecosystem=meta.ecosystem,
        name=meta.name,
        old_version=meta.old_version,
        new_version=meta.new_version,
        rank=meta.rank,
        registry_url=meta.registry_url,
        band=band,
        malice_probability=round(probability, 4),
        jev_model_id=model_id,
        attack_family=family,
        subtype=subtype,
        cause=cause,
        signals=code.signal_list() + ["jev_unreadable"],
        needs_llm_review=True,
    )


def _on_jev_error(
    meta: ReleaseMeta,
    code: CodeFeatures,
    model_id: str,
    exc: BaseException,
    stage: str,
    head,
    *,
    probability: float = 0.0,
) -> Classification:
    if isinstance(exc, ContextOverflow):
        # Too large for this model's window. Not cut: the row says so, and the caller may route it.
        row = _review_unread(meta, code, model_id, head, probability=probability)
        row.signals.append(CONTEXT_OVERFLOW_SIGNAL)
        row.context_overflow_tokens = exc.needed_tokens
        return row
    if getattr(exc, "review_unread", False):
        row = _review_unread(meta, code, model_id, head, probability=probability)
        if "release_budget" not in row.signals:
            row.signals.append("release_budget")
        return row
    reason = SPEND_STOP_REASON if SPEND_STOP_REASON in str(exc) else _stage_reason(exc, stage)
    if reason == "max_tokens":
        return _review_unread(meta, code, model_id, head, probability=probability)
    return _deferred(meta, code, model_id, reason, probability=probability)


def _partial_read(result: object) -> bool:
    return bool(getattr(result, "partial", False))


def _unread_partial(
    meta: ReleaseMeta,
    code: CodeFeatures,
    model_id: str,
    head,
    *,
    probability: float = 0.0,
) -> Classification:
    """A chunk was only partly read. That is not a finished Scout verdict."""
    row = _review_unread(meta, code, model_id, head, probability=probability)
    if "partial_read" not in row.signals:
        row.signals.append("partial_read")
    return row


def _flag_new_binary(meta: ReleaseMeta, code: CodeFeatures, model_id: str) -> Classification:
    """A new executable, decided in code. No model call."""
    row = _blank(
        meta,
        band="review",
        probability=REVIEW_THRESHOLD,
        model_id=model_id,
        signals=code.signal_list(),
    )
    row.needs_llm_review = True
    return row


def _text_for_model(diffs: list[FileDiff]) -> bool:
    return any(item.category != "binary_media" for item in diffs)


def _text_was_cut(files) -> bool:
    """True when a file read stopped at the byte cap."""
    for text in files.values():
        if isinstance(text, str) and text.endswith(FILE_CUT_MARKER):
            return True
    return False


def _floor_keeps_review(head, name: str, active: bool, band: str, probability: float) -> tuple[str, float]:
    """A floor at or above the review line still holds a benign score in review."""
    if not active or band != "benign":
        return band, probability
    level = head.floor_level(name)
    if level is None or level < REVIEW_THRESHOLD:
        return band, probability
    return "review", max(probability, level)


def classification_incomplete(result: Classification) -> bool:
    if result.band == "deferred" or result.defer_reason:
        return True
    return "ai_incomplete" in result.signals


def _require_nouls(result: JevResult, ids: tuple[str, ...] | list[str]) -> dict[str, float]:
    missing = [key for key in ids if key not in result.nouls]
    if missing:
        raise JevUnavailable(f"missing nouls: {', '.join(missing)}")
    return {key: float(result.nouls[key].noul) for key in ids}


def _legend_label(score) -> str | None:
    if score is None or not score.probabilities:
        return None
    best = max(score.probabilities.items(), key=lambda item: item[1])[0]
    return score.legend.get(best)


def classify_files(
    *,
    meta: ReleaseMeta,
    old_files: dict[str, str],
    new_files: dict[str, str],
    jev,
    head=None,
    popular_names: set[str] | None = None,
) -> Classification:
    head = head or load_head(head_name(jev))
    begin = getattr(jev, "begin_release", None)
    if begin is not None:
        begin()
    old_files, new_files = aligned_release_trees(
        old_files,
        new_files,
        ecosystem=meta.ecosystem,
        name=meta.name,
        old_version=meta.old_version,
        new_version=meta.new_version,
    )
    report: RuleReport | None = None
    known_diffs: dict[str, str] | None = None
    if rules_enabled():
        known_diffs = changed_diffs(old_files, new_files)
        report = _scan_rules(meta, old_files, new_files, known_diffs)
    row = _classify_aligned(
        meta=meta,
        old_files=old_files,
        new_files=new_files,
        jev=jev,
        head=head,
        popular_names=popular_names,
        report=report,
        known_diffs=known_diffs,
    )
    backup = getattr(jev, "backup", None)
    if backup is not None and decision_model_failed(row):
        # Retry the whole release on the backup decision model, with its own scoring file,
        # so one row never mixes two models' answers.
        log.warning(
            "%s %s: decision model %s failed (%s); retrying on backup %s",
            meta.name,
            meta.new_version,
            row.jev_model_id,
            row.defer_reason,
            getattr(backup, "model", "backup"),
        )
        begin_backup = getattr(backup, "begin_release", None)
        if begin_backup is not None:
            begin_backup()
        backup_row = _classify_aligned(
            meta=meta,
            old_files=old_files,
            new_files=new_files,
            jev=backup,
            head=load_head(head_name(backup)),
            popular_names=popular_names,
            report=report,
            known_diffs=known_diffs,
        )
        backup_row.signals.append(BACKUP_SIGNAL)
        row = backup_row
    if CONTEXT_OVERFLOW_SIGNAL in row.signals:
        row = _route_overflow(
            row, meta, jev, old_files, new_files, popular_names, report, known_diffs
        )
    if decision_model_failed(row):
        row.signals.append(MODEL_DOWN_SIGNAL)
    if report is not None:
        row.rule_verdict = report.verdict
        row.rule_hits = report.hit_dicts()
        row.rule_pack = report.pack_version
        if report.verdict == "malicious" and decision_model_failed(row):
            _rule_fallback(row)
        if report.verdict == "malicious" and not classification_incomplete(row):
            row.needs_llm_review = True
    return row


def _rule_fallback(row: Classification) -> None:
    """Scout failed on a release a promoted rule marks malicious. Triage and Analyst read it now.

    The failed-pass signal stays on the row so the alert says Scout did not finish.
    """
    row.band = "review"
    row.malice_probability = round(max(row.malice_probability, REVIEW_FLOOR), 4)
    row.defer_reason = ""
    row.signals = [item for item in row.signals if item not in ("ai_incomplete", "jev_retry")]
    row.signals.append(RULE_FALLBACK_SIGNAL)
    row.needs_llm_review = True


# Signals for the decision-model failure path (rule plan section 6.3).
BACKUP_SIGNAL = "backup_decision_model"
# The release did not fit the model's context window and was not cut to fit.
CONTEXT_OVERFLOW_SIGNAL = "context_overflow"
ROUTED_SIGNAL_PREFIX = "routed_context_overflow:"
MODEL_DOWN_SIGNAL = "decision_model_down"
# Scout failed and a promoted rule hit, so the release went to Triage and Analyst instead of a retry.
RULE_FALLBACK_SIGNAL = "jev_failed_rule_fallback"
SPEND_STOP_REASON = "spend_cap_reached"


def _route_overflow(row, meta, jev, old_files, new_files, popular_names, report, known_diffs):
    """Read an oversize release on a model with a larger window.

    The routed model is named in the row's signals and in the log. With no route
    that fits, the row stays an unread review that carries context_overflow.
    """
    needed = int(getattr(row, "context_overflow_tokens", 0) or 0)
    routes = getattr(jev, "overflow_routes", None) or {}
    picked = overflow_route(needed, routes, exclude=getattr(jev, "model", None))
    if picked is None:
        log.warning(
            "%s %s: needs %d input tokens, more than %s takes, and no larger model is set up; sending to review unread",
            meta.name,
            meta.new_version,
            needed,
            getattr(jev, "model", "the model"),
        )
        return row
    name, client = picked
    log.warning(
        "%s %s: needs %d input tokens, more than %s takes; routing it to %s",
        meta.name,
        meta.new_version,
        needed,
        getattr(jev, "model", "the model"),
        name,
    )
    begin = getattr(client, "begin_release", None)
    if begin is not None:
        begin()
    routed = _classify_aligned(
        meta=meta,
        old_files=old_files,
        new_files=new_files,
        jev=client,
        head=load_head(head_name(client)),
        popular_names=popular_names,
        report=report,
        known_diffs=known_diffs,
    )
    if decision_model_failed(routed):
        row.signals.append(f"{ROUTED_SIGNAL_PREFIX}{name}:failed")
        return row
    routed.signals.append(f"{ROUTED_SIGNAL_PREFIX}{name}")
    return routed


def _fit_to_model(client, budget: int, questions: dict) -> int:
    """Lower a state budget so state plus questions fit this model's window."""
    if input_limit(getattr(client, "model", None)) is None:
        return budget
    counter = getattr(client, "question_tokens", None)
    spent = counter(questions) if callable(counter) else predict_input_tokens({}, questions)
    return state_budget(getattr(client, "model", None), spent, budget)


def decision_model_failed(row: Classification) -> bool:
    """True when no answer came back from the decision model. A spend-cap stop is not a failure."""
    return row.band == "deferred" and row.defer_reason not in ("", SPEND_STOP_REASON)


def _scan_rules(
    meta: ReleaseMeta,
    old_files: dict[str, str],
    new_files: dict[str, str],
    known_diffs: dict[str, str],
) -> RuleReport:
    """Rule verdict for one release. A scan error asks for a full read instead of failing the release."""
    try:
        return scan_release(old_files, new_files, ecosystem=meta.ecosystem, diffs=known_diffs)
    except Exception:
        log.exception("%s %s: rule scan failed; reading the release in full", meta.name, meta.new_version)
        return RuleReport(verdict="unsure", unscanned=[("", "unscanned:rule_error")])


def _rule_floor(code: CodeFeatures, head) -> float | None:
    """Highest score floor among promoted rules that hit. None when no promoted rule hit."""
    report = code.rule_report
    if report is None:
        return None
    levels = [head.rule_floor(rule_id, level) for rule_id, level in report.strong_floors.items()]
    levels = [level for level in levels if level is not None]
    return max(levels) if levels else None


def _classify_aligned(
    *,
    meta: ReleaseMeta,
    old_files: dict[str, str],
    new_files: dict[str, str],
    jev,
    head,
    popular_names: set[str] | None,
    report: RuleReport | None,
    known_diffs: dict[str, str] | None,
) -> Classification:
    kept: list[FileDiff] = diff_trees(
        old_files,
        new_files,
        force_keep=report.hits_by_path() if report is not None else None,
        known_diffs=known_diffs,
    )
    code = extract_features(old_files, new_files, kept, meta, popular_names)
    code.rule_report = report
    rule_verdict = report.verdict if report is not None else ""
    extra, text_cut = new_text_file_diffs(old_files, new_files, kept)
    scout = kept + extra
    # Scout's manifest lists rule-kept paths as kept without naming the rule.
    hidden = {path: [] for path in report.hits_by_path()} if report is not None else None
    manifest = changed_file_manifest(old_files, new_files, force_keep=hidden)
    model_id = getattr(jev, "fallback_model_id", None) or JEV_MODEL_ID
    if _text_was_cut(old_files) or _text_was_cut(new_files):
        return _unread_partial(meta, code, model_id, head)
    if (
        code.new_binary
        and rule_verdict != "malicious"
        and not _text_for_model(scout)
        and not code.static_hot()
        and not code.phantom_runtime_dependencies
        and not code.dependency_typosquats
        and not code.package_typosquat
    ):
        return _flag_new_binary(meta, code, model_id)
    # A rule hit or a file the rules could not read skips the quick check: Scout reads the release in full.
    skip_gate = rule_verdict in ("malicious", "unsure")
    try:
        if skip_gate:
            raise _SkipGate
        gate_state = slice_state(scout, meta, "gate", changed_files=manifest)
        if not scout:
            gate_state = build_state(
                meta,
                render_excerpt([]),
                slice_name="gate",
                changed_files=manifest,
            )
        _note_local_signals(gate_state, code)
        gate = jev.system_one(gate_state, pass_a_questions())
        if _partial_read(gate):
            return _unread_partial(meta, code, gate.model or model_id, head)
        model_id = gate.model or model_id
        gate_nouls = _require_nouls(gate, PASS_A_IDS)
    except _SkipGate:
        gate_nouls = None
    except JevUnavailable as exc:
        return _on_jev_error(meta, code, model_id, exc, "pass_a", head)

    quiet_gate = gate_nouls is not None and all(value < GATE_LOW for value in gate_nouls.values())
    if (
        quiet_gate
        and not code.static_hot()
        and not code.phantom_runtime_dependencies
        and not code.new_binary
        and not extra
        and not text_cut
    ):
        return _blank(
            meta,
            band="benign",
            probability=0.05,
            model_id=model_id,
            signals=code.signal_list() + ["pass_a_gate"],
        )

    try:
        pack_budget = state_token_budget(jev, STATE_TOKEN_BUDGET)
        pack_budget = _fit_to_model(jev, pack_budget, pass_b_questions())
        if getattr(jev, "splits_full_excerpt", False):
            # This model splits the excerpt itself and must see every byte.
            pack_budget = max(pack_budget, 1_000_000_000)
        chunks = pack_chunks(scout, meta, budget=pack_budget, changed_files=manifest)
        budget_partial = False
        for state in chunks:
            _note_local_signals(state, code)
        if not getattr(jev, "splits_full_excerpt", False) and _over_release_tokens(
            chunks, scout_release_token_cap()
        ):
            partial_chunks, files_read = partial_read_chunks(
                scout,
                meta,
                budget=min(scout_partial_token_budget(), scout_release_token_cap()),
                pack_budget=pack_budget,
                changed_files=manifest,
            )
            if not partial_chunks:
                log.info(
                    "%s %s: %d Scout chunks are over the release token cap; sending to Triage unread",
                    meta.name,
                    meta.new_version,
                    len(chunks),
                )
                row = _review_unread(meta, code, model_id, head)
                row.signals.append("release_budget")
                return row
            log.info(
                "%s %s: %d Scout chunks are over the release token cap; reading the riskiest %d of %d files as a partial read",
                meta.name,
                meta.new_version,
                len(chunks),
                files_read,
                len(scout),
            )
            chunks = partial_chunks
            budget_partial = True
        pooled_parts: list[JevResult] = []
        for state in chunks:
            part = jev.system_one(state, pass_b_questions())
            if _partial_read(part):
                return _unread_partial(meta, code, part.model or model_id, head)
            pooled_parts.append(part)
        model_id = pooled_parts[-1].model or model_id
        list_cut = any(NEW_FILE_CUT_MARKER in str(state.get("changed_files") or "") for state in chunks)
        if (text_cut or list_cut) and not budget_partial:
            return _unread_partial(meta, code, model_id, head)
        pooled = max_pool(pooled_parts, PASS_B_IDS)
        if any(key not in pooled_parts[-1].nouls for key in PASS_B_IDS):
            # max_pool skips missing keys; require a complete fan-out on the last chunk
            # and a value for every id across the pool.
            for key in PASS_B_IDS:
                if not any(key in part.nouls for part in pooled_parts):
                    raise JevUnavailable(f"missing noul {key}")
    except JevUnavailable as exc:
        return _on_jev_error(meta, code, model_id, exc, "pass_b", head)

    vector = feature_vector(pooled, code)
    probability = head.predict(vector)
    # Entrypoint swaps and install sidecars are review, not the compound alert floor.
    probability = _apply_score_floors(code, probability, head)
    rule_floor = _rule_floor(code, head)
    consensus = jev_consensus(pooled, code)
    if consensus:
        level = head.floor_level("jev_consensus")
        if level is not None:
            probability = max(probability, level)
    reviewer = pooled.get("reviewer_instructions", 0.0)
    signals = code.signal_list()
    if consensus:
        signals.append("jev_consensus")
    signals.extend(name for name, value in pooled.items() if value >= 0.5)
    if budget_partial:
        # Keep the partial read visible in the row, Triage, Analyst and the alert.
        signals.extend(["release_budget", "release_budget_partial"])

    family = "none"
    subtype = None
    family_probs: dict[str, float] = {}
    cause = "unknown"
    cause_probs: dict[str, float] = {}
    subtype_probs: dict[str, float] = {}
    blast_score = None
    blast_label = None
    data_score = None
    capability: dict[str, float] = {}

    if probability >= REVIEW_THRESHOLD:
        intel_state = slice_state(scout, meta, "combined", changed_files=manifest)
        winners = []
        try:
            intel = jev.system_one(intel_state, pass_c_questions())
            if _partial_read(intel):
                raise JevUnavailable("partial read")
            model_id = intel.model or model_id
            family_answer = intel.choices["attack_family"]
            family = family_answer.choice
            family_probs = dict(family_answer.probabilities)
            cause_answer = intel.choices["suspected_cause"]
            cause = cause_answer.choice
            cause_probs = dict(cause_answer.probabilities)
            blast = intel.scores.get("blast_radius")
            data = intel.scores.get("data_collection")
            if blast is not None:
                blast_score = blast.score
                blast_label = _legend_label(blast)
            if data is not None:
                data_score = data.score
            for key in ("cap_network", "cap_process", "cap_credential", "cap_persist", "cap_install_time"):
                if key in intel.nouls:
                    capability[key] = float(intel.nouls[key].noul)
            winners = winning_families(family_probs, family)
        except JevUnavailable as exc:
            if getattr(exc, "review_unread", False):
                return _on_jev_error(
                    meta,
                    code,
                    model_id,
                    exc,
                    "pass_c",
                    head,
                    probability=probability,
                )
            log.warning("Pass C failed; keeping the Pass B score")
            signals.append("pass_c_failed")
        if winners:
            try:
                sub_questions = subtype_questions(winners)
                sub = jev.system_one(intel_state, sub_questions)
                model_id = sub.model or model_id
                if family not in winners:
                    family = winners[0]
                answer = sub.choices.get(f"subtype_{family}")
                if answer is not None:
                    subtype = answer.choice
                    subtype_probs = dict(answer.probabilities)
            except JevUnavailable:
                log.warning("subtype questions were rejected; keeping the other Pass C answers")
        if family != "none" and SUBTYPES.get(family) and not subtype:
            subtype = next(iter(SUBTYPES[family]))
        if (family in ("", "none")) and probability >= 0.70 and not code.phantom_runtime_dependencies:
            family = "other"
            subtype = "unspecified"

    band = decide_band(probability, reviewer_noul=reviewer)
    band, probability = _floor_keeps_review(
        head,
        "phantom_or_typosquat",
        bool(code.phantom_runtime_dependencies or code.dependency_typosquats or code.package_typosquat),
        band,
        probability,
    )
    band, probability = _floor_keeps_review(
        head,
        "behavior_chains",
        bool(code.behavior_chains),
        band,
        probability,
    )
    band, probability = _floor_keeps_review(
        head,
        "outside_package_install",
        bool(code.outside_package_files),
        band,
        probability,
    )
    if rule_floor is not None and rule_floor >= REVIEW_THRESHOLD and band == "benign":
        # A promoted rule hit cannot drop below review, even after the reviewer-instructions check.
        band = "review"
        probability = max(probability, rule_floor)
    if code.phantom_runtime_dependencies and family in ("", "none"):
        family = "dependency_abuse"
        subtype = subtype or "new_unrelated"
    if code.dependency_typosquats and family in ("", "none"):
        family = "dependency_abuse"
        subtype = subtype or "new_unrelated"
    if code.package_typosquat and cause in ("", "unknown"):
        cause = "typosquat_name"
    if code.new_binary and band == "benign":
        band = "review"
        probability = max(probability, REVIEW_THRESHOLD)
    if band == "benign":
        family = "none"
        subtype = None
    return Classification(
        ecosystem=meta.ecosystem,
        name=meta.name,
        old_version=meta.old_version,
        new_version=meta.new_version,
        rank=meta.rank,
        registry_url=meta.registry_url,
        band=band,
        malice_probability=round(probability, 4),
        jev_model_id=model_id,
        attack_family=family,
        subtype=subtype,
        family_probabilities=family_probs,
        cause=cause,
        cause_probabilities=cause_probs,
        subtype_probabilities=subtype_probs,
        blast_radius_score=blast_score,
        blast_radius_label=blast_label,
        data_collection_score=data_score,
        capability_nouls=capability,
        noul_probabilities=pooled,
        signals=signals,
        reviewer_noul=reviewer,
        needs_llm_review=band in {"alert", "review"} or unsure_route(pooled, code.signal_list(), old_files),
    )
