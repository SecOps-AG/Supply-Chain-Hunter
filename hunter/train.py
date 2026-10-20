"""Fit the logistic head on Pass B rows. Shipped priors need no API key."""

from __future__ import annotations

import json
from pathlib import Path

from hunter import JEV_MODEL_ID
from hunter.features import extract_features
from hunter.fixtures_io import iter_fixtures
from hunter.head import FEATURE_NAMES, feature_vector
from hunter.jev import JevUnavailable, max_pool, pack_chunks
from hunter.questions import PASS_B_IDS, pass_b_questions
from hunter.standin import noul_values
from hunter.triage import diff_trees, render_excerpt

HEAD_PATH = Path(__file__).resolve().parent / "logistic_head.json"


def _blank_row(label: int, **overrides: float) -> dict:
    row = {name: 0.0 for name in FEATURE_NAMES}
    for name in FEATURE_NAMES:
        if name.startswith("noul_"):
            row[name] = 0.04
    row.update(overrides)
    row["label"] = label
    return row


def synthetic_rows() -> list[dict]:
    """Separable rows for a regularized balanced logistic prior."""
    rows = [
        _blank_row(0),
        _blank_row(0, noul_reviewer_instructions=0.9),
        _blank_row(0, publisher_changed=1),
        _blank_row(0, short_release_gap=1),
        _blank_row(0, new_dependency_count=0.125),
        _blank_row(0, high_entropy_additions=0.4),
        _blank_row(0, lifecycle_script_edits=0.33),
        _blank_row(0, literal_shell=1),
        _blank_row(0, noul_network=0.3, noul_shell_child_process=0.22),
        _blank_row(0, publisher_changed=1, short_release_gap=1, lifecycle_script_edits=0.33),
        _blank_row(0, noul_install_time_execution=0.2, noul_decode_then_run=0.12),
        _blank_row(
            1,
            noul_install_time_execution=0.96,
            noul_decode_then_run=0.94,
            noul_shell_child_process=0.91,
            noul_credential_read=0.9,
            noul_network=0.86,
            noul_embedded_payload=0.84,
            lifecycle_script_edits=0.33,
            literal_decode_exec=1,
            literal_shell=1,
            literal_raw_ip=1,
            high_entropy_additions=0.4,
        ),
        _blank_row(
            1,
            noul_install_time_execution=0.9,
            noul_credential_read=0.88,
            lifecycle_script_edits=0.33,
            literal_shell=1,
        ),
        _blank_row(
            1,
            noul_decode_then_run=0.93,
            noul_shell_child_process=0.9,
            noul_network=0.85,
            noul_embedded_payload=0.8,
            literal_decode_exec=1,
            literal_raw_ip=1,
            high_entropy_additions=0.6,
        ),
        _blank_row(
            1,
            noul_install_time_execution=0.92,
            noul_unrelated_new_dependency=0.84,
            new_dependency_count=0.25,
            lifecycle_script_edits=0.33,
        ),
        _blank_row(
            1,
            noul_persistence_path=0.9,
            noul_shell_child_process=0.86,
            literal_shell=1,
            lifecycle_script_edits=0.33,
        ),
        _blank_row(
            1,
            noul_install_time_execution=0.7,
            noul_decode_then_run=0.75,
            literal_decode_exec=1,
            literal_shell=1,
            lifecycle_script_edits=1,
        ),
    ]
    quiet = [_blank_row(0, **{name: 0.08 for name in FEATURE_NAMES if name.startswith("noul_")}) for _ in range(6)]
    return rows + quiet


def fixture_rows(root: str | Path) -> list[dict]:
    rows = []
    for _path, (meta, old_files, new_files, label) in iter_fixtures(root):
        kept = diff_trees(old_files, new_files)
        code = extract_features(old_files, new_files, kept, meta)
        nouls = noul_values(render_excerpt(kept))
        if label not in {"malicious", "benign"}:
            continue
        vector = feature_vector(nouls, code)
        vector["label"] = 1 if label == "malicious" else 0
        rows.append(vector)
    return rows


def pass_b_row(meta, old_files, new_files, jev) -> dict[str, float]:
    kept = diff_trees(old_files, new_files)
    code = extract_features(old_files, new_files, kept, meta)
    chunks = pack_chunks(kept, meta)
    results = [jev.system_one(state, pass_b_questions()) for state in chunks]
    pooled = max_pool(results, PASS_B_IDS)
    return feature_vector(pooled, code)


def fit_head(rows: list[dict], *, model_id: str = JEV_MODEL_ID, c: float = 1.0) -> dict:
    import numpy as np
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import train_test_split

    matrix = np.array([[float(row[name]) for name in FEATURE_NAMES] for row in rows], dtype=float)
    labels = np.array([int(row["label"]) for row in rows], dtype=int)
    holdout = {"precision": None, "recall": None, "n": int(len(rows))}
    if len(set(labels.tolist())) > 1 and len(rows) >= 8:
        train_x, test_x, train_y, test_y = train_test_split(
            matrix,
            labels,
            test_size=0.25,
            random_state=13,
            stratify=labels,
        )
        probe = LogisticRegression(
            C=c,
            class_weight="balanced",
            solver="lbfgs",
            max_iter=1000,
        )
        probe.fit(train_x, train_y)
        predicted = probe.predict(test_x)
        true_pos = int(((predicted == 1) & (test_y == 1)).sum())
        false_pos = int(((predicted == 1) & (test_y == 0)).sum())
        false_neg = int(((predicted == 0) & (test_y == 1)).sum())
        holdout = {
            "precision": true_pos / (true_pos + false_pos) if (true_pos + false_pos) else 0.0,
            "recall": true_pos / (true_pos + false_neg) if (true_pos + false_neg) else 0.0,
            "n": int(len(test_y)),
        }
    full = LogisticRegression(
        C=c,
        class_weight="balanced",
        solver="lbfgs",
        max_iter=1000,
    )
    full.fit(matrix, labels)
    return {
        "model_id": model_id,
        "estimator": "sklearn.linear_model.LogisticRegression",
        "params": {"C": c, "class_weight": "balanced", "penalty": "l2", "solver": "lbfgs"},
        "features": list(FEATURE_NAMES),
        "coefficients": [float(value) for value in full.coef_.ravel()],
        "intercept": float(full.intercept_[0]),
        "holdout": holdout,
        "source": "prior",
    }


def write_prior(fixtures_root: str | Path = "fixtures", path: Path = HEAD_PATH) -> dict:
    rows = synthetic_rows() + fixture_rows(fixtures_root) * 4
    payload = fit_head(rows)
    payload["source"] = "prior"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return payload


def train_live(fixtures_root: str | Path, db, jev, path: Path = HEAD_PATH) -> dict:
    rows = []
    model_id = JEV_MODEL_ID
    for fixture_path, (meta, old_files, new_files, label) in iter_fixtures(fixtures_root):
        if label not in {"malicious", "benign"}:
            continue
        vector = pass_b_row(meta, old_files, new_files, jev)
        model_id = getattr(jev, "model", model_id)
        numeric_label = 1 if label == "malicious" else 0
        vector["label"] = numeric_label
        rows.append(vector)
        if db is not None:
            db.save_train_row(fixture_path.stem, json.dumps(vector), numeric_label, model_id)
    if not rows:
        raise JevUnavailable("no fixtures to train on")
    payload = fit_head(rows, model_id=model_id)
    payload["source"] = "train"
    payload["model_id"] = model_id
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return payload


C_GRID = (0.1, 0.3, 1.0, 3.0)
_EDGE = 1e-6


def choose_c(rows: list[dict], *, c_grid=C_GRID, folds: int = 5, repeats: int = 10, seed: int = 13) -> float:
    """Regularization with the best mean log loss over repeated stratified folds of the tuning rows."""
    import numpy as np
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import RepeatedStratifiedKFold, cross_val_score

    matrix = np.array([[float(row[name]) for name in FEATURE_NAMES] for row in rows], dtype=float)
    labels = np.array([int(row["label"]) for row in rows], dtype=int)
    minority = min(int((labels == 1).sum()), int((labels == 0).sum()))
    if minority < 2:
        return 1.0
    splitter = RepeatedStratifiedKFold(n_splits=min(folds, minority), n_repeats=repeats, random_state=seed)
    scores = {}
    for c in c_grid:
        model = LogisticRegression(C=c, class_weight="balanced", solver="lbfgs", max_iter=1000)
        scores[c] = float(cross_val_score(model, matrix, labels, cv=splitter, scoring="neg_log_loss").mean())
    return max(c_grid, key=lambda c: scores[c])


def choose_cutoffs(bad_scores: list[float], clean_scores: list[float], *, max_clean_flag_rate: float) -> dict:
    """Review: most catches with at most that share of tuning clean releases at or above it.
    Alert: just above every tuning clean release."""
    if not clean_scores or not bad_scores:
        raise ValueError("cutoffs need both bad and clean tuning rows")
    clean = sorted(clean_scores, reverse=True)
    allowed = int(max_clean_flag_rate * len(clean) + 1e-9)
    review = clean[allowed] + _EDGE if allowed < len(clean) else clean[-1]
    review = min(max(review, 0.01), 0.97)
    alert = min(max(clean[0] + _EDGE, review + 0.01), 0.99)
    return {
        "review": review,
        "alert": alert,
        "tuning_bad_caught": sum(1 for score in bad_scores if score >= review),
        "tuning_bad_alert": sum(1 for score in bad_scores if score >= alert),
        "tuning_clean_flagged": sum(1 for score in clean_scores if score >= review),
        "tuning_clean_alert": sum(1 for score in clean_scores if score >= alert),
    }


def fit_calibrated_head(
    rows: list[dict],
    *,
    model_id: str,
    max_clean_flag_rate: float,
    c_grid=C_GRID,
    seed: int = 13,
) -> dict:
    """Weights and cutoffs for a new Scout model, from tuning rows only. Held-out rows must not be passed in."""
    from hunter.head import LogisticHead

    c = choose_c(rows, c_grid=c_grid, seed=seed)
    payload = fit_head(rows, model_id=model_id, c=c)
    head = LogisticHead(payload)
    bad = [head.raw_predict(row) for row in rows if int(row["label"]) == 1]
    clean = [head.raw_predict(row) for row in rows if int(row["label"]) == 0]
    picked = choose_cutoffs(bad, clean, max_clean_flag_rate=max_clean_flag_rate)
    payload["cutoffs"] = {"review": picked["review"], "alert": picked["alert"]}
    payload["source"] = "calibrated"
    payload["calibration"] = {
        "C": c,
        "max_clean_flag_rate": max_clean_flag_rate,
        "tuning_bad": len(bad),
        "tuning_clean": len(clean),
        **{key: value for key, value in picked.items() if key.startswith("tuning_")},
    }
    return payload
