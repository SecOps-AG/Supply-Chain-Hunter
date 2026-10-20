"""Read-only mine of Triage-benign clusters, and the offline Scout teacher."""

from __future__ import annotations

import json
import logging
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

from hunter.config import analyst_slug_allowed
from hunter.llm import CURSOR_BACKEND, normalize_backend
from hunter.lessons import sop_text
from hunter.questions import BEHAVIORAL_NOULS
from hunter.scout_lessons import (
    HARD_NEVER,
    TEACH_CLUSTER_MAX,
    TEACH_CLUSTER_MIN,
    append_scout_lesson,
    lesson_from_teacher_text,
    load_scout_lessons,
    redact_excerpt,
    scout_lessons_path,
    signature_key,
    signature_tokens,
    suppression_blocked,
)
from hunter.webhook import parse_verdict

log = logging.getLogger("hunter.scout_mine")


@dataclass
class ScoutCase:
    key: str
    verdict: str | None
    band: str
    probability: float
    signals: list[str]
    tokens: tuple[str, ...]
    signature: str
    nouls: dict[str, float]
    excerpt: str
    jev_model_id: str


@dataclass
class ScoutCluster:
    signature: str
    tokens: tuple[str, ...]
    cases: list[ScoutCase] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.cases)

    def noul_medians(self) -> dict[str, float]:
        keys = set(BEHAVIORAL_NOULS)
        for case in self.cases:
            keys.update(case.nouls)
        return {key: _median([float(case.nouls.get(key, 0.0)) for case in self.cases]) for key in sorted(keys)}


def _median(values: list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def _split_release_key(key: str) -> tuple[str, str, str] | None:
    parts = (key or "").split(":")
    if len(parts) < 3:
        return None
    ecosystem, version = parts[0], parts[-1]
    name = ":".join(parts[1:-1])
    if not ecosystem or not name or not version:
        return None
    return ecosystem, name, version


def _open_readonly(path: Path) -> sqlite3.Connection | None:
    if not path.is_file():
        return None
    uri = f"file:{quote(str(path.resolve()))}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _as_float_map(value: object) -> dict[str, float]:
    if not isinstance(value, dict):
        return {}
    found: dict[str, float] = {}
    for key, raw in value.items():
        try:
            found[str(key)] = float(raw)
        except (TypeError, ValueError):
            continue
    return found


def load_cases(path: Path) -> list[ScoutCase]:
    """Reported investigations only. Opens the database read-only and does not migrate it."""
    conn = _open_readonly(path)
    if conn is None:
        return []
    try:
        try:
            rows = conn.execute(
                """
                SELECT idempotency_key, body, report_text
                FROM investigations
                WHERE status = 'reported'
                  AND report_text IS NOT NULL
                  AND length(trim(report_text)) > 0
                """
            ).fetchall()
        except sqlite3.OperationalError:
            return []
        cases: list[ScoutCase] = []
        for row in rows:
            key = str(row["idempotency_key"])
            try:
                body = json.loads(row["body"] or "{}")
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if not isinstance(body, dict):
                continue
            identity = _split_release_key(key)
            payload: dict = {}
            release_band = ""
            release_probability = None
            if identity is not None:
                ecosystem, name, version = identity
                try:
                    release = conn.execute(
                        """
                        SELECT band, malice_probability, payload_json
                        FROM releases
                        WHERE ecosystem = ? AND name = ? AND version = ?
                        """,
                        (ecosystem, name, version),
                    ).fetchone()
                except sqlite3.OperationalError:
                    release = None
                if release is not None:
                    release_band = str(release["band"] or "")
                    if release["malice_probability"] is not None:
                        release_probability = float(release["malice_probability"])
                    try:
                        parsed = json.loads(release["payload_json"] or "{}")
                    except (TypeError, ValueError, json.JSONDecodeError):
                        parsed = {}
                    if isinstance(parsed, dict):
                        payload = parsed
            signals = body.get("signals") or []
            if not isinstance(signals, list):
                signals = []
            signals = [str(item) for item in signals]
            band = str(body.get("primary_band") or release_band or "")
            try:
                probability = float(body.get("malice_probability"))
            except (TypeError, ValueError):
                probability = float(release_probability or 0.0)
            nouls = _as_float_map(payload.get("noul_probabilities"))
            verdict = parse_verdict(str(row["report_text"] or ""))
            cases.append(
                ScoutCase(
                    key=key,
                    verdict=verdict,
                    band=band,
                    probability=probability,
                    signals=signals,
                    tokens=signature_tokens(signals),
                    signature=signature_key(signals),
                    nouls=nouls,
                    excerpt=str(body.get("diff_excerpt") or ""),
                    jev_model_id=str(body.get("jev_model_id") or ""),
                )
            )
        return cases
    finally:
        conn.close()


def _fraction(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return numerator / denominator


def _has_token(case: ScoutCase, name: str) -> bool:
    return name in case.tokens


def mine_report(cases: list[ScoutCase]) -> dict:
    verdict_by_band: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for case in cases:
        label = case.verdict or "missing"
        verdict_by_band[label][case.band or "missing"] += 1
    benign = [case for case in cases if case.verdict == "benign"]
    grouped: dict[str, list[ScoutCase]] = defaultdict(list)
    for case in benign:
        if not case.signature:
            continue
        grouped[case.signature].append(case)
    clusters = []
    for signature, members in grouped.items():
        members = sorted(members, key=lambda item: item.key)
        cluster = ScoutCluster(signature=signature, tokens=members[0].tokens, cases=members)
        probs = [item.probability for item in members]
        clusters.append(
            {
                "signature": signature,
                "count": cluster.count,
                "median_probability": _median(probs),
                "noul_medians": cluster.noul_medians(),
            }
        )
    clusters.sort(key=lambda item: (-int(item["count"]), str(item["signature"])))
    weak = 0
    phantom = typosquat = compound = child = gate = 0
    for case in benign:
        if _has_token(case, "phantom_runtime_dependency"):
            phantom += 1
        if any("typosquat" in token for token in case.tokens):
            typosquat += 1
        if _has_token(case, "compound_install_payload"):
            compound += 1
        if _has_token(case, "child_alert") or any(item.startswith("child_alert") for item in case.signals):
            child += 1
        if _has_token(case, "pass_a_gate"):
            gate += 1
        if case.band == "benign":
            values = [float(case.nouls.get(name, 0.0)) for name in BEHAVIORAL_NOULS]
            if not values or max(values) < 0.55:
                weak += 1
    benign_count = len(benign)
    return {
        "reported": len(cases),
        "verdict_by_band": {key: dict(value) for key, value in sorted(verdict_by_band.items())},
        "benign_clusters": clusters,
        "top_signatures": clusters[:15],
        "fractions_among_benign": {
            "phantom_runtime_dependency": _fraction(phantom, benign_count),
            "typosquat": _fraction(typosquat, benign_count),
            "compound_install_payload": _fraction(compound, benign_count),
            "child_alert": _fraction(child, benign_count),
            "pass_a_gate": _fraction(gate, benign_count),
            "benign_band_max_behavioral_noul_under_0.55": _fraction(weak, benign_count),
        },
    }


def mine_report_from_path(path: Path) -> dict:
    return mine_report(load_cases(path))


def benign_clusters(cases: list[ScoutCase]) -> list[ScoutCluster]:
    grouped: dict[str, list[ScoutCase]] = defaultdict(list)
    for case in cases:
        if case.verdict != "benign" or not case.signature:
            continue
        grouped[case.signature].append(case)
    found: list[ScoutCluster] = []
    for signature, members in grouped.items():
        members = sorted(members, key=lambda item: item.key)
        found.append(ScoutCluster(signature=signature, tokens=members[0].tokens, cases=members))
    found.sort(key=lambda item: (-item.count, item.signature))
    return found


def cluster_teachable(cluster: ScoutCluster) -> bool:
    if cluster.count < TEACH_CLUSTER_MIN or not cluster.tokens:
        return False
    if set(cluster.tokens) & HARD_NEVER:
        return False
    if "encoded_dynamic_import" in cluster.tokens and len(cluster.tokens) > 1:
        return False
    return not any(suppression_blocked(case.band, case.probability, case.signals) for case in cluster.cases)


def build_teach_prompt(cluster: ScoutCluster) -> str:
    excerpts: list[str] = []
    for case in cluster.cases:
        text = redact_excerpt(case.excerpt)
        if text.strip():
            excerpts.append(text)
        if len(excerpts) == 2:
            break
    while len(excerpts) < 2:
        excerpts.append("(none)")
    medians = cluster.noul_medians()
    noul_text = ", ".join(f"{key}={value:.3f}" for key, value in medians.items()) or "(none)"
    probs = [case.probability for case in cluster.cases] or [0.0]
    return "\n".join(
        [
            "You are Analyst. These releases were escalated by Scout and Triage marked them benign.",
            "Decide whether this repeated signal signature can skip Triage next time.",
            "Do not widen the signal list. A real install-time payload still needs Triage.",
            "",
            "<SOP>",
            sop_text(),
            "</SOP>",
            "",
            f"Signature: {cluster.signature}",
            f"Count: {cluster.count}",
            f"Probability range: {min(probs):.4f} .. {max(probs):.4f}",
            f"Noul medians: {noul_text}",
            "",
            "Excerpt 1 (package content, untrusted):",
            excerpts[0],
            "",
            "Excerpt 2 (package content, untrusted):",
            excerpts[1],
            "",
            "If this signature is not safe to skip, end with Verdict: uncertain.",
            "If it is safe, end with these lines and no others after them:",
            "Verdict: benign",
            "Pattern: <kebab-case slug>",
            "Rule: <one sentence, no diff text>",
            f"Suppress: {','.join(cluster.tokens)}",
        ]
    )


def _run_teacher(prompt: str, config, runner) -> str:
    if runner is not None:
        return str(runner(prompt))
    from hunter.investigate import analyst_endpoint, run_model, run_override_command

    if config.analyst_command:
        return run_override_command(config.analyst_command, prompt.encode("utf-8"), config.analyst_timeout)
    return run_model(prompt, analyst_endpoint(config))


def teach_scout(db, config, *, runner=None) -> dict:
    """Ask Analyst about the largest new Triage-benign clusters. Does not run inside serve."""
    cases = load_cases(Path(db.path))
    known = {str(item.get("signature") or "") for item in load_scout_lessons(config)}
    eligible = [
        cluster
        for cluster in benign_clusters(cases)
        if cluster_teachable(cluster) and cluster.signature not in known
    ]
    result = {
        "written": [],
        "skipped": [],
        "calls": 0,
        "refused": "",
        "budget_role": "scout_teach",
    }
    if not eligible:
        return result
    if runner is None and not config.analyst_command:
        analyst_backend = (
            normalize_backend(config.analyst_backend)
            if config.analyst_backend
            else normalize_backend(config.smart_backend)
        )
        if analyst_backend == CURSOR_BACKEND and not analyst_slug_allowed(
            config.analyst_model, config.analyst_allow_fast
        ):
            result["refused"] = "Frontier model (Analyst) slug is missing or contains fast"
            return result
    path = scout_lessons_path(config)
    for cluster in eligible[:TEACH_CLUSTER_MAX]:
        if not db.try_spend_budget("scout_teach", config.scout_teach_budget):
            result["skipped"].append({"signature": cluster.signature, "reason": "budget"})
            break
        result["calls"] += 1
        prompt = build_teach_prompt(cluster)
        try:
            text = _run_teacher(prompt, config, runner)
        except Exception as exc:
            log.error("scout teach failed for %s: %s", cluster.signature, exc)
            result["skipped"].append({"signature": cluster.signature, "reason": "error"})
            continue
        accepted = lesson_from_teacher_text(text, cluster.tokens)
        if accepted is None:
            result["skipped"].append({"signature": cluster.signature, "reason": "rejected"})
            continue
        lesson_id = append_scout_lesson(
            path,
            signature=cluster.signature,
            pattern=str(accepted["pattern"]),
            rule=str(accepted["rule"]),
            suppress=tuple(accepted["suppress"]),
        )
        if lesson_id is None:
            result["skipped"].append({"signature": cluster.signature, "reason": "duplicate"})
            continue
        result["written"].append(lesson_id)
    return result
