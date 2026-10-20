"""Scoring-layer cutoffs for a new Scout model. Synthetic rows only; no network."""

import random

import pytest

from hunter.bands import ALERT_THRESHOLD, REVIEW_THRESHOLD
from hunter.head import FEATURE_NAMES, LogisticHead, cutoff_map, load_head
from hunter.train import choose_cutoffs, fit_calibrated_head


def test_cutoff_map_hits_the_two_lines_and_keeps_order():
    assert cutoff_map(0.0, 0.2, 0.5) == 0.0
    assert cutoff_map(0.2, 0.2, 0.5) == pytest.approx(REVIEW_THRESHOLD)
    assert cutoff_map(0.5, 0.2, 0.5) == pytest.approx(ALERT_THRESHOLD)
    assert cutoff_map(1.0, 0.2, 0.5) == pytest.approx(1.0)
    values = [index / 100 for index in range(101)]
    mapped = [cutoff_map(value, 0.2, 0.5) for value in values]
    assert mapped == sorted(mapped)


def test_bad_cutoffs_are_rejected():
    payload = {"features": ["a"], "coefficients": [1.0], "intercept": 0.0, "cutoffs": {"review": 0.6, "alert": 0.5}}
    with pytest.raises(ValueError, match="cutoffs"):
        LogisticHead(payload)


def test_jev_head_has_no_cutoffs_and_scores_as_before():
    head = load_head("jev")
    assert head.cutoffs is None
    row = {name: 0.5 for name in FEATURE_NAMES}
    assert head.predict(row) == head.raw_predict(row)


def test_head_with_cutoffs_predicts_on_scouts_scale():
    payload = {
        "features": ["a"],
        "coefficients": [0.0],
        "intercept": 0.0,
        "cutoffs": {"review": 0.3, "alert": 0.5},
    }
    head = LogisticHead(payload)
    assert head.raw_predict({"a": 1.0}) == pytest.approx(0.5)
    assert head.predict({"a": 1.0}) == pytest.approx(ALERT_THRESHOLD)


def test_review_cutoff_respects_the_clean_flag_limit():
    clean = [0.045 * index for index in range(1, 21)]
    bad = [0.6, 0.7, 0.8, 0.9, 0.3]
    picked = choose_cutoffs(bad, clean, max_clean_flag_rate=0.10)
    assert picked["tuning_clean_flagged"] <= 2
    assert picked["tuning_clean_alert"] == 0
    assert picked["review"] < picked["alert"]
    assert picked["tuning_bad_caught"] == sum(1 for score in bad if score >= picked["review"])


def _rows(seed: int = 7) -> list[dict]:
    rng = random.Random(seed)
    rows = []
    for label, count in ((1, 40), (0, 80)):
        for _ in range(count):
            row = {name: 0.0 for name in FEATURE_NAMES}
            for name in FEATURE_NAMES:
                if not name.startswith("noul_"):
                    continue
                if label == 1:
                    row[name] = min(1.0, max(0.0, rng.gauss(0.75, 0.2)))
                else:
                    row[name] = min(1.0, max(0.0, rng.gauss(0.35, 0.25)))
            row["literal_shell"] = 1.0 if rng.random() < (0.7 if label else 0.2) else 0.0
            row["label"] = label
            rows.append(row)
    return rows


def test_fit_on_tuning_rows_writes_weights_and_cutoffs():
    rows = _rows()
    payload = fit_calibrated_head(rows, model_id="clef", max_clean_flag_rate=0.15)
    assert payload["model_id"] == "clef"
    assert payload["source"] == "calibrated"
    assert payload["features"] == list(FEATURE_NAMES)
    info = payload["calibration"]
    assert info["tuning_bad"] == 40
    assert info["tuning_clean"] == 80
    assert info["tuning_clean_flagged"] <= 12
    assert info["tuning_clean_alert"] == 0
    assert info["C"] in (0.1, 0.3, 1.0, 3.0)
    head = LogisticHead(payload)
    scored = [head.predict(row) for row in rows if row["label"] == 0]
    assert sum(1 for score in scored if score >= ALERT_THRESHOLD) == 0
    assert sum(1 for score in scored if score >= REVIEW_THRESHOLD) == info["tuning_clean_flagged"]


def test_fit_is_repeatable():
    first = fit_calibrated_head(_rows(), model_id="clef", max_clean_flag_rate=0.15)
    second = fit_calibrated_head(_rows(), model_id="clef", max_clean_flag_rate=0.15)
    assert first["coefficients"] == second["coefficients"]
    assert first["cutoffs"] == second["cutoffs"]
