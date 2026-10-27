"""Explainable 0-100 risk score for one release, with a short why-list.

This is separate from malice_probability and the band: nothing routes on it. It is
derived from signals the classification already carries, so it adds no model calls.
"""

from __future__ import annotations

from dataclasses import dataclass

WHY_LIMIT = 3
MAX_SCORE = 100
TEXT_LIMIT = 120
RULE_ID_LIMIT = 80
STRONG_RULE_POINTS = 25
OTHER_RULE_POINTS = 6
RULE_POINTS_CAP = 45
EXPOSURE_POINTS_CAP = 10

# signal name (text before ":") -> (bucket, points, text)
SIGNAL_WEIGHTS: dict[str, tuple[str, int, str]] = {
    "compound_install_payload": ("compound_install_payload", 30, "Install hook and a payload in the same added script"),
    "entrypoint_payload": ("entrypoint_payload", 25, "Package entrypoint gained a payload"),
    "install_sidecar": ("install_sidecar", 20, "New script runs at install"),
    "literal_decode_exec": ("literal_decode_exec", 20, "Decodes data and runs it"),
    "literal_credential": ("literal_credential", 20, "References credentials or secrets"),
    "behavior_chain": ("behavior_chain", 20, "Install or import runs a suspicious chain of actions"),
    "runtime_behavior_chain": ("behavior_chain", 20, "Install or import runs a suspicious chain of actions"),
    "phantom_runtime_dependency": ("phantom_runtime_dependency", 15, "Adds a dependency the code never uses"),
    "typosquat_name": ("typosquat_name", 15, "Package name imitates a popular package"),
    "dependency_typosquat": ("dependency_typosquat", 15, "Adds a dependency that imitates a popular package"),
    "new_binary": ("new_binary", 15, "Adds a new executable binary"),
    "literal_xor": ("literal_xor", 12, "XOR-style obfuscation in added code"),
    "literal_encoded_import": ("literal_encoded_import", 12, "Imports a module by an encoded name"),
    "literal_minified_payload": ("literal_minified_payload", 12, "Added minified or packed payload"),
    "literal_raw_ip": ("literal_raw_ip", 12, "Contacts a raw IP address"),
    "literal_persistence": ("literal_persistence", 12, "Sets up persistence on the host"),
    "outside_package_install": ("outside_package_install", 12, "Installs files outside the package"),
    "literal_shell": ("literal_shell", 10, "Runs shell commands"),
    "literal_new_host": ("literal_new_host", 10, "Contacts a host not seen in the old version"),
    "high_entropy_additions": ("high_entropy_additions", 8, "Adds high-entropy blobs"),
    "lifecycle_script_edits": ("lifecycle_script_edits", 8, "Changed an install lifecycle script"),
    "publisher_changed": ("publisher_changed", 8, "Publisher changed"),
    "wheel_only_file": ("wheel_only_file", 8, "Wheel holds files the source does not"),
    "build_config_change": ("build_config_change", 6, "Build configuration changed"),
    "short_release_gap": ("short_release_gap", 3, "Released very soon after the previous version"),
    "binary_media_change": ("binary_media_change", 3, "Binary or media files changed"),
}


@dataclass(frozen=True)
class Reason:
    code: str
    points: int
    text: str

    def to_dict(self) -> dict:
        return {"code": self.code, "points": self.points, "text": self.text}


@dataclass(frozen=True)
class RiskScore:
    score: int | None
    why: tuple[Reason, ...] = ()

    def why_dicts(self) -> list[dict]:
        return [reason.to_dict() for reason in self.why]


def _clamp(value: object, limit: int) -> str:
    return " ".join(str(value).split())[:limit]


def _number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _incomplete(result) -> bool:
    if getattr(result, "defer_reason", ""):
        return True
    return any(str(item) == "download_failed" for item in getattr(result, "signals", None) or [])


def _signal_reasons(signals) -> dict[str, Reason]:
    found: dict[str, Reason] = {}
    for item in signals or []:
        name = str(item).split(":", 1)[0]
        if name.startswith("rule:"):
            continue
        weight = SIGNAL_WEIGHTS.get(name)
        if weight is None:
            continue
        bucket, points, text = weight
        if bucket not in found:
            found[bucket] = Reason(bucket, points, text)
    return found


def _rule_reasons(hits) -> list[Reason]:
    strong: dict[str, None] = {}
    other: dict[str, None] = {}
    for hit in hits or []:
        if not isinstance(hit, dict) or not hit.get("rule"):
            continue
        rule = _clamp(hit["rule"], RULE_ID_LIMIT)
        (strong if hit.get("tier") == "strong" else other).setdefault(rule, None)
    reasons: list[Reason] = []
    budget = RULE_POINTS_CAP
    for rule in strong:
        points = min(STRONG_RULE_POINTS, budget)
        if points <= 0:
            break
        budget -= points
        reasons.append(Reason(f"rule:{rule}", points, f"Strong rule matched: {rule}"))
    for rule in other:
        points = min(OTHER_RULE_POINTS, budget)
        if points <= 0:
            break
        budget -= points
        reasons.append(Reason(f"rule:{rule}", points, f"Rule matched: {rule}"))
    return reasons


def _exposure_reason(result) -> Reason | None:
    parts = [
        value
        for value in (_number(getattr(result, "data_collection_score", None)), _number(getattr(result, "blast_radius_score", None)))
        if value is not None
    ]
    if not parts:
        return None
    level = max(0.0, min(1.0, max(parts)))
    points = round(level * EXPOSURE_POINTS_CAP)
    if points <= 0:
        return None
    return Reason("exposure", points, "High data exposure or blast radius")


def risk_score(result) -> RiskScore:
    """Score a Classification. None means the read was incomplete, not that it is safe."""
    if _incomplete(result):
        return RiskScore(None)
    reasons = list(_signal_reasons(getattr(result, "signals", None)).values())
    reasons.extend(_rule_reasons(getattr(result, "rule_hits", None)))
    exposure = _exposure_reason(result)
    if exposure is not None:
        reasons.append(exposure)
    reasons.sort(key=lambda reason: (-reason.points, reason.code))
    total = min(MAX_SCORE, sum(reason.points for reason in reasons))
    top = tuple(Reason(r.code, r.points, r.text[:TEXT_LIMIT]) for r in reasons[:WHY_LIMIT])
    return RiskScore(total, top)
