import json
import math
from pathlib import Path

import pytest

from hunter.head import FEATURE_NAMES, BUILTIN_FLOORS, load_head

SHIPPED = Path(__file__).resolve().parent.parent / "hunter" / "logistic_head.json"

pytestmark = pytest.mark.shipped_head


def test_shipped_head_loads_with_matching_features():
    head = load_head("jev")
    assert head.feature_names == list(FEATURE_NAMES)
    assert len(head.coefficients) == len(FEATURE_NAMES)
    assert all(math.isfinite(value) for value in head.coefficients)


def test_shipped_head_cutoffs_and_floors_are_valid():
    head = load_head("jev")
    assert head.cutoffs is not None
    review, alert = head.cutoffs
    assert 0.0 < review < alert < 1.0
    assert head.floors is not None
    assert set(head.floors) <= set(BUILTIN_FLOORS)
    for level in head.floors.values():
        assert level is None or 0.0 < level < 1.0


def test_shipped_head_carries_no_case_data():
    payload = json.loads(SHIPPED.read_text(encoding="utf-8"))
    allowed = {
        "model_id", "estimator", "params", "features", "coefficients",
        "intercept", "cutoffs", "floors", "holdout", "source",
    }
    assert set(payload) <= allowed
    assert set(payload.get("holdout", {})) <= {"precision", "recall", "false_positive_rate", "n", "method"}
