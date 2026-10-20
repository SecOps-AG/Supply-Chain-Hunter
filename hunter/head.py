"""Regularized logistic head. Scoring uses shipped coefficients and does not need an API key."""

from __future__ import annotations

import json
import math
from importlib.resources import files

from hunter.bands import ALERT_THRESHOLD as ALERT_LINE
from hunter.bands import REVIEW_FLOOR
from hunter.bands import REVIEW_THRESHOLD as REVIEW_LINE
from hunter.models import CodeFeatures

# Same levels the classifier applies when a weight file has no floors object.
# A null level in a floors object turns that one floor off.
BUILTIN_FLOORS = {
    "compound_install_payload": 0.86,
    "phantom_or_typosquat": REVIEW_FLOOR,
    "entrypoint_payload": REVIEW_FLOOR,
    "install_sidecar": REVIEW_FLOOR,
    "behavior_chains": REVIEW_FLOOR,
    "jev_consensus": REVIEW_FLOOR,
    "rule_strong": REVIEW_FLOOR,
}

NOUL_FEATURES = (
    "noul_decode_then_run",
    "noul_shell_child_process",
    "noul_network",
    "noul_credential_read",
    "noul_persistence_path",
    "noul_install_time_execution",
    "noul_unrelated_new_dependency",
    "noul_embedded_payload",
    "noul_reviewer_instructions",
)

CODE_FEATURES = (
    "lifecycle_script_edits",
    "new_dependency_count",
    "publisher_changed",
    "short_release_gap",
    "high_entropy_additions",
    "literal_decode_exec",
    "literal_shell",
    "literal_raw_ip",
)

FEATURE_NAMES = NOUL_FEATURES + CODE_FEATURES


def sigmoid(value: float) -> float:
    if value >= 0:
        ez = math.exp(-value)
        return 1.0 / (1.0 + ez)
    ez = math.exp(value)
    return ez / (1.0 + ez)


def cutoff_map(raw: float, review_at: float, alert_at: float) -> float:
    """Move a model's own review and alert scores onto Scout's 0.40 and 0.70 lines. Order is kept."""
    raw = min(1.0, max(0.0, float(raw)))
    if raw <= review_at:
        return REVIEW_LINE * raw / review_at
    if raw <= alert_at:
        return REVIEW_LINE + (ALERT_LINE - REVIEW_LINE) * (raw - review_at) / (alert_at - review_at)
    return ALERT_LINE + (1.0 - ALERT_LINE) * (raw - alert_at) / (1.0 - alert_at)


def _floors(payload: dict) -> dict[str, float | None] | None:
    """None when the file has no floors object, so the built-in levels apply."""
    if "floors" not in payload:
        return None
    raw = payload["floors"]
    if not isinstance(raw, dict):
        raise ValueError("logistic head floors must be an object")
    parsed: dict[str, float | None] = {}
    for name, value in raw.items():
        if value is None:
            parsed[str(name)] = None
            continue
        parsed[str(name)] = float(value)
    return parsed


def _cutoffs(payload: dict) -> tuple[float, float] | None:
    raw = payload.get("cutoffs")
    if not raw:
        return None
    review_at = float(raw["review"])
    alert_at = float(raw["alert"])
    if not 0.0 < review_at < alert_at < 1.0:
        raise ValueError("logistic head cutoffs must satisfy 0 < review < alert < 1")
    return review_at, alert_at


class LogisticHead:
    def __init__(self, payload: dict):
        self.model_id = payload.get("model_id", "jev-1.13.0")
        self.feature_names = list(payload["features"])
        self.coefficients = [float(value) for value in payload["coefficients"]]
        self.intercept = float(payload["intercept"])
        self.holdout = payload.get("holdout") or {}
        self.source = payload.get("source", "prior")
        self.cutoffs = _cutoffs(payload)
        self.floors = _floors(payload)
        if len(self.coefficients) != len(self.feature_names):
            raise ValueError("logistic head coefficients do not match features")

    def floor_level(self, name: str) -> float | None:
        """Score floor for one local signal. None means that floor is off.

        A weight file with no floors object keeps today's built-in levels.
        """
        if self.floors is None:
            return BUILTIN_FLOORS.get(name)
        return self.floors.get(name)

    def rule_floor(self, rule_id: str, level: str = "review") -> float | None:
        """Score floor for one promoted rule.

        A "rule:<id>" key in the floors object wins, and null turns that rule's floor off.
        Otherwise the rule uses the rule_strong level, raised to the built-in alert
        floor when promoted.json gives the rule an alert level.
        """
        floors = BUILTIN_FLOORS if self.floors is None else self.floors
        key = f"rule:{rule_id}"
        if key in floors:
            return floors[key]
        base = self.floor_level("rule_strong")
        if base is None:
            return None
        if level == "alert":
            return max(base, BUILTIN_FLOORS["compound_install_payload"])
        return base

    def raw_predict(self, features: dict[str, float]) -> float:
        total = self.intercept
        for name, weight in zip(self.feature_names, self.coefficients):
            total += weight * float(features.get(name, 0.0))
        return sigmoid(total)

    def predict(self, features: dict[str, float]) -> float:
        """Probability on Scout's scale. A head without cutoffs is already on it."""
        raw = self.raw_predict(features)
        if self.cutoffs is None:
            return raw
        return cutoff_map(raw, *self.cutoffs)


def feature_vector(nouls: dict[str, float], code: CodeFeatures) -> dict[str, float]:
    def noul(name: str) -> float:
        return float(nouls.get(name, 0.0))

    return {
        "noul_decode_then_run": noul("decode_then_run"),
        "noul_shell_child_process": noul("shell_child_process"),
        "noul_network": noul("network"),
        "noul_credential_read": noul("credential_read"),
        "noul_persistence_path": noul("persistence_path"),
        "noul_install_time_execution": noul("install_time_execution"),
        "noul_unrelated_new_dependency": noul("unrelated_new_dependency"),
        "noul_embedded_payload": noul("embedded_payload"),
        "noul_reviewer_instructions": noul("reviewer_instructions"),
        "lifecycle_script_edits": min(code.lifecycle_script_edits, 3) / 3,
        "new_dependency_count": min(code.new_dependency_count, 8) / 8,
        "publisher_changed": 1.0 if code.publisher_changed else 0.0,
        "short_release_gap": 1.0 if code.short_release_gap else 0.0,
        "high_entropy_additions": min(code.high_entropy_additions, 5) / 5,
        "literal_decode_exec": 1.0 if code.literal_decode_exec else 0.0,
        "literal_shell": 1.0 if code.literal_shell else 0.0,
        "literal_raw_ip": 1.0 if code.literal_raw_ip else 0.0,
    }


def head_file(name: str = "jev") -> str:
    """Jev keeps the original file name. Other models use logistic_head_<name>.json."""
    return "logistic_head.json" if name == "jev" else f"logistic_head_{name}.json"


def head_available(name: str = "jev") -> bool:
    return files("hunter").joinpath(head_file(name)).is_file()


def load_head(name: str = "jev") -> LogisticHead:
    """Each Scout model has its own weights. A missing file raises FileNotFoundError."""
    path = files("hunter").joinpath(head_file(name))
    if not path.is_file():
        raise FileNotFoundError(f"no scoring-layer file for Scout model {name}: hunter/{head_file(name)}")
    return LogisticHead(json.loads(path.read_text(encoding="utf-8")))
