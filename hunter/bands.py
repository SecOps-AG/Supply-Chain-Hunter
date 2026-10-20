"""Alert, review, and benign thresholds."""

from __future__ import annotations

ALERT_THRESHOLD = 0.70
REVIEW_THRESHOLD = 0.40
HIGH_REVIEW = 0.55
# Local structural signals floor here: phantom dependencies, entrypoint payloads,
# install sidecars, and install/import behavior chains.
REVIEW_FLOOR = 0.62
PHANTOM_REVIEW_FLOOR = REVIEW_FLOOR
DEGRADED_REVIEW = 0.45
GATE_LOW = 0.30
REVIEWER_DROP = 0.60


def raw_band(probability: float) -> str:
    if probability >= ALERT_THRESHOLD:
        return "alert"
    if probability >= REVIEW_THRESHOLD:
        return "review"
    return "benign"


def decide_band(probability: float, *, reviewer_noul: float) -> str:
    """A high reviewer Noul drops an alert to review."""
    band = raw_band(probability)
    if band == "alert" and reviewer_noul >= REVIEWER_DROP:
        band = "review"
    return band
