"""Refit the scoring head and its floors from local cases and saved Scout output.

Package files are read as text. Nothing in a case is executed, and this command
does not call Scout. It does not write the live weight file.

    python -m hunter.refit_head \
        --cases /path/to/cases \
        --scout /path/to/scout-output.jsonl \
        --out /path/to/logistic_head_refit.json

``--cases`` is a directory of fixture JSON files. ``--scout`` is Scout's saved
answers for those same cases: one JSON object per line, a JSON list, or a JSON
object keyed by case id. The id is the fixture file name without ``.json``.
Each object needs ``nouls`` (name to probability) or a ``vector`` of head
features. Optional fields: ``unreadable``, ``deferred``, ``gate_cleared``,
``band``, ``model_id``, and a group (``group``, ``set``, ``split``, ``bucket``,
or ``cohort``). A group whose name contains "held" or "hold" is scored once
and is not used to choose weights.

With no ``--max-clean-flag-rate``, the new weights may not flag a larger share
of the tuning clean cases than the current head and floors. The printed
recall and false-positive rate are from cross-validation. The written review
cutoff and floors are chosen from out-of-fold scores on the tuning cases.
"""

from __future__ import annotations

import argparse
import itertools
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

from hunter.archives import aligned_release_trees, close_trees
from hunter.bands import REVIEW_THRESHOLD
from hunter.features import extract_features
from hunter.fixtures_io import iter_fixtures
from hunter.head import BUILTIN_FLOORS, FEATURE_NAMES, LogisticHead, feature_vector, load_head
from hunter.train import C_GRID, HEAD_PATH, choose_c, fit_head
from hunter.triage import diff_trees

FLOOR_NAMES = tuple(BUILTIN_FLOORS)
# Same levels classify applies when a weight file has no floors object.
CURRENT_FLOORS = BUILTIN_FLOORS
_EDGE = 1e-6


@dataclass
class CaseRow:
    id: str
    label: int
    vector: dict[str, float] | None
    floor_flags: dict[str, bool]
    unreadable: bool = False
    deferred: bool = False
    gate_cleared: bool = False
    held_out: bool = False
    model_id: str | None = None

    @property
    def scored(self) -> bool:
        return self.vector is not None and not self.unreadable and not self.deferred and not self.gate_cleared


@dataclass
class Rates:
    bad: int = 0
    clean: int = 0
    flagged_bad: int = 0
    flagged_clean: int = 0

    @property
    def recall(self) -> float:
        return self.flagged_bad / self.bad if self.bad else 0.0

    @property
    def false_positive_rate(self) -> float:
        return self.flagged_clean / self.clean if self.clean else 0.0


@dataclass
class RefitResult:
    payload: dict
    before: Rates
    after: Rates
    after_current_floors: Rates
    held_out_before: Rates | None
    held_out_after: Rates | None
    cap: float
    folds: int
    review_at: float
    floors: dict[str, float | None]
    counts: dict[str, int] = field(default_factory=dict)


def _blank_flags() -> dict[str, bool]:
    return {name: False for name in FLOOR_NAMES}


def floor_flags_from_code(code) -> dict[str, bool]:
    return {
        "compound_install_payload": bool(code.compound_install_payload),
        "phantom_or_typosquat": bool(
            code.phantom_runtime_dependencies or code.dependency_typosquats or code.package_typosquat
        ),
        "entrypoint_payload": bool(code.entrypoint_payload),
        "install_sidecar": bool(code.install_sidecar),
        "behavior_chains": bool(code.behavior_chains),
    }


def _normalize_nouls(raw: dict) -> dict[str, float]:
    nouls = {}
    for key, value in raw.items():
        name = str(key)
        if name.startswith("noul_"):
            name = name[len("noul_") :]
        nouls[name] = float(value)
    return nouls


def _vector_from_scout(raw: dict, code) -> dict[str, float] | None:
    if isinstance(raw.get("nouls"), dict):
        return feature_vector(_normalize_nouls(raw["nouls"]), code)
    vector = raw.get("vector")
    if isinstance(vector, dict):
        return {name: float(vector.get(name, 0.0)) for name in FEATURE_NAMES}
    return None


def _kind(raw: dict) -> str:
    band = str(raw.get("band") or "").strip().lower()
    unreadable = bool(raw.get("unreadable"))
    deferred = bool(raw.get("deferred")) or band == "deferred"
    has_input = isinstance(raw.get("nouls"), dict) or isinstance(raw.get("vector"), dict)
    if deferred:
        return "deferred"
    if unreadable:
        return "unreadable"
    if bool(raw.get("gate_cleared")) or not has_input:
        return "gate"
    return "scored"


def _group(raw: dict) -> str:
    for key in ("group", "set", "split", "bucket", "cohort"):
        if raw.get(key) not in (None, ""):
            return str(raw[key])
    return ""


def is_held_out(group: str) -> bool:
    text = group.strip().lower().replace("-", "_").replace(" ", "_")
    return "held" in text or "hold" in text


def _label_value(value) -> int | None:
    if value in (1, "1", "malicious", True):
        return 1
    if value in (0, "0", "benign", False):
        return 0
    return None


def _scout_rows(path: Path, stripped: str, lines: list[str]) -> list:
    if len(lines) > 1 and lines[0].lstrip().startswith("{"):
        try:
            first = json.loads(lines[0])
        except json.JSONDecodeError:
            first = None
        if isinstance(first, dict):
            return [json.loads(line) for line in lines]
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"scout file is not JSON or one object per line: {path}") from exc
    if isinstance(data, list):
        return data
    if not isinstance(data, dict):
        raise SystemExit(f"scout file must be a list, an object, or one object per line: {path}")
    if any(key in data for key in ("id", "nouls", "vector", "band")):
        return [data]
    rows = []
    for key, value in data.items():
        if not isinstance(value, dict):
            raise SystemExit(f"scout entry {key} is not an object")
        row = dict(value)
        row.setdefault("id", key)
        rows.append(row)
    return rows


def load_scout(path: Path) -> dict[str, dict]:
    text = path.read_text(encoding="utf-8")
    stripped = text.strip()
    if not stripped:
        raise SystemExit(f"scout file is empty: {path}")
    lines = [line for line in text.splitlines() if line.strip()]
    rows = _scout_rows(path, stripped, lines)
    index = {}
    for row in rows:
        if not isinstance(row, dict):
            raise SystemExit("a scout row is not an object")
        ident = str(row.get("id") or "").strip()
        if ident.endswith(".json"):
            ident = ident[: -len(".json")]
        if not ident:
            raise SystemExit("a scout row has no id")
        if ident in index:
            raise SystemExit(f"duplicate scout id {ident}")
        index[ident] = row
    if not index:
        raise SystemExit(f"scout file has no rows: {path}")
    return index


def load_cases(cases_dir: Path, scout_path: Path) -> list[CaseRow]:
    scout = load_scout(scout_path)
    fixtures = list(iter_fixtures(cases_dir))
    if not fixtures:
        raise SystemExit(f"no case files in {cases_dir}")
    rows = []
    missing = []
    seen = set()
    for path, loaded in fixtures:
        meta, old_files, new_files, label_name = loaded
        ident = path.stem
        seen.add(ident)
        raw = scout.get(ident)
        if raw is None:
            missing.append(ident)
            continue
        label = _label_value(label_name)
        if label is None:
            raise SystemExit(f"case {ident} has an unknown label")
        scout_label = _label_value(raw["label"]) if "label" in raw else None
        if scout_label is not None and scout_label != label:
            raise SystemExit(f"case {ident} label does not match the scout file")
        old_aligned, new_aligned = aligned_release_trees(
            old_files,
            new_files,
            ecosystem=meta.ecosystem,
            name=meta.name,
            old_version=meta.old_version,
            new_version=meta.new_version,
        )
        try:
            kept = diff_trees(old_aligned, new_aligned)
            code = extract_features(old_aligned, new_aligned, kept, meta, None)
        finally:
            close_trees(old_aligned, new_aligned)
        kind = _kind(raw)
        vector = None if kind != "scored" else _vector_from_scout(raw, code)
        if kind == "scored" and vector is None:
            raise SystemExit(f"case {ident} has no nouls or vector in the scout file")
        model_id = raw.get("model_id")
        rows.append(
            CaseRow(
                id=ident,
                label=label,
                vector=vector,
                floor_flags=floor_flags_from_code(code),
                unreadable=kind == "unreadable",
                deferred=kind == "deferred",
                gate_cleared=kind == "gate",
                held_out=is_held_out(_group(raw)),
                model_id=str(model_id) if model_id else None,
            )
        )
    extra = sorted(set(scout) - seen)
    if missing or extra:
        detail = []
        if missing:
            detail.append(f"{len(missing)} cases have no scout row, first {missing[0]}")
        if extra:
            detail.append(f"{len(extra)} scout rows have no case, first {extra[0]}")
        raise SystemExit("; ".join(detail))
    return rows


def apply_flag(row: CaseRow, score: float | None, floors: dict[str, float | None], review_at: float) -> bool:
    """Final band at the review line: unread counts as flagged; a deferred or gate-cleared case does not."""
    if row.deferred:
        return False
    if row.unreadable:
        return True
    if row.gate_cleared or score is None:
        return False
    if score >= review_at:
        return True
    for name in FLOOR_NAMES:
        level = floors.get(name)
        if level is not None and level >= REVIEW_THRESHOLD and row.floor_flags.get(name):
            return True
    return False


def rates_for(
    scored: list[CaseRow],
    scores: list[float | None],
    others: list[CaseRow],
    floors: dict[str, float | None],
    review_at: float,
) -> Rates:
    rates = Rates()
    paired = list(zip(scored, scores, strict=True)) + [(row, None) for row in others]
    for row, score in paired:
        flagged = apply_flag(row, score, floors, review_at)
        if row.label == 1:
            rates.bad += 1
            rates.flagged_bad += int(flagged)
        else:
            rates.clean += 1
            rates.flagged_clean += int(flagged)
    return rates


def _floor_choices(fixed: dict[str, float | None] | None) -> list[dict[str, float | None]]:
    if fixed is not None:
        return [dict(fixed)]
    choices = []
    for mask in itertools.product((True, False), repeat=len(FLOOR_NAMES)):
        floors = {}
        for name, on in zip(FLOOR_NAMES, mask, strict=True):
            floors[name] = CURRENT_FLOORS[name] if on else None
        choices.append(floors)
    return choices


def select_policy(
    scored: list[CaseRow],
    scores: list[float],
    others: list[CaseRow],
    cap: float,
    *,
    fixed_floors: dict[str, float | None] | None = None,
) -> tuple[float, dict[str, float | None]]:
    """Review cutoff and floors with the most bad catches at or under the clean-flag cap.

    The cutoff is the highest one that still reaches that catch rate, and a floor
    stays on when turning it off does not help.
    """
    candidates = {REVIEW_THRESHOLD, 0.01, 0.97}
    for score in scores:
        if 0.01 <= score <= 0.97:
            candidates.add(float(score))
    feasible = []
    fallback = []
    for floors in _floor_choices(fixed_floors):
        for review_at in candidates:
            rates = rates_for(scored, scores, others, floors, review_at)
            item = (review_at, floors, rates)
            if rates.false_positive_rate <= cap + 1e-9:
                feasible.append(item)
            else:
                fallback.append(item)
    if feasible:
        _review_at, floors, _rates = max(
            feasible,
            key=lambda item: (item[2].recall, -item[2].false_positive_rate, item[0], _floors_on(item[1])),
        )
    else:
        _review_at, floors, _rates = max(
            fallback,
            key=lambda item: (-item[2].false_positive_rate, item[2].recall, item[0], _floors_on(item[1])),
        )
    return float(_review_at), floors


def _floors_on(floors: dict[str, float | None]) -> int:
    return sum(level is not None for level in floors.values())


def _matrix(rows: list[CaseRow]):
    import numpy as np

    matrix = np.array([[float(row.vector[name]) for name in FEATURE_NAMES] for row in rows], dtype=float)
    labels = np.array([row.label for row in rows], dtype=int)
    return matrix, labels


def _fit_predict(train: list[CaseRow], test: list[CaseRow], c: float) -> list[float]:
    from sklearn.linear_model import LogisticRegression

    train_x, train_y = _matrix(train)
    test_x, _test_y = _matrix(test)
    model = LogisticRegression(C=c, class_weight="balanced", solver="lbfgs", max_iter=1000)
    model.fit(train_x, train_y)
    return [float(value) for value in model.predict_proba(test_x)[:, 1]]


def oof_scores(rows: list[CaseRow], c: float, folds: int, seed: int) -> list[float]:
    from sklearn.model_selection import StratifiedKFold

    matrix, labels = _matrix(rows)
    minority = min(int((labels == 1).sum()), int((labels == 0).sum()))
    if minority < 2:
        raise SystemExit("need at least 2 bad and 2 clean tuning cases that reached the scoring layer")
    splits = min(folds, minority)
    oof = [0.0] * len(rows)
    splitter = StratifiedKFold(n_splits=splits, shuffle=True, random_state=seed)
    for train_idx, test_idx in splitter.split(matrix, labels):
        train = [rows[index] for index in train_idx]
        test = [rows[index] for index in test_idx]
        predicted = _fit_predict(train, test, c)
        for index, score in zip(test_idx, predicted, strict=True):
            oof[int(index)] = score
    return oof


def _selection_scores(rows: list[CaseRow], c: float, folds: int, seed: int) -> list[float]:
    labels = [row.label for row in rows]
    minority = min(labels.count(0), labels.count(1))
    if minority < 2:
        return _fit_predict(rows, rows, c)
    return oof_scores(rows, c, folds, seed)


def _split_counts(rows: list[CaseRow]) -> dict[str, int]:
    return {
        "bad": sum(row.label == 1 for row in rows),
        "clean": sum(row.label == 0 for row in rows),
        "unreadable": sum(row.unreadable for row in rows),
        "deferred": sum(row.deferred for row in rows),
        "gate_cleared": sum(row.gate_cleared for row in rows),
        "scored": sum(row.scored for row in rows),
    }


def _model_id(rows: list[CaseRow]) -> str:
    found = {row.model_id for row in rows if row.model_id}
    if len(found) == 1:
        return next(iter(found))
    return load_head("jev").model_id


def alert_cutoff(clean_scores: list[float], review_at: float) -> float:
    review_at = min(max(review_at, 0.01), 0.97)
    top = max(clean_scores) if clean_scores else review_at
    return min(max(top + _EDGE, review_at + 0.01), 0.99)


def cross_validated_rates(
    scored: list[CaseRow],
    others: list[CaseRow],
    c: float,
    folds: int,
    seed: int,
    cap: float,
) -> tuple[Rates, Rates, int]:
    """Outer-fold flags. Each fold chooses its cutoff and floors without the fold's cases."""
    from sklearn.model_selection import StratifiedKFold

    matrix, labels = _matrix(scored)
    minority = min(int((labels == 1).sum()), int((labels == 0).sum()))
    splits = min(folds, minority)
    new_flags = [False] * len(scored)
    current_flags = [False] * len(scored)
    splitter = StratifiedKFold(n_splits=splits, shuffle=True, random_state=seed)
    for train_idx, test_idx in splitter.split(matrix, labels):
        train = [scored[int(index)] for index in train_idx]
        test = [scored[int(index)] for index in test_idx]
        held = _selection_scores(train, c, folds, seed)
        review_new, floors_new = select_policy(train, held, others, cap)
        review_current, floors_current = select_policy(train, held, others, cap, fixed_floors=CURRENT_FLOORS)
        predicted = _fit_predict(train, test, c)
        for offset, index in enumerate(test_idx):
            row = scored[int(index)]
            score = predicted[offset]
            new_flags[int(index)] = apply_flag(row, score, floors_new, review_new)
            current_flags[int(index)] = apply_flag(row, score, floors_current, review_current)
    other_flags = [apply_flag(row, None, CURRENT_FLOORS, REVIEW_THRESHOLD) for row in others]
    after = _rates_from_flags(scored, new_flags, others, other_flags)
    current = _rates_from_flags(scored, current_flags, others, other_flags)
    return after, current, splits


def _rates_from_flags(
    scored: list[CaseRow],
    scored_flags: list[bool],
    others: list[CaseRow],
    other_flags: list[bool],
) -> Rates:
    rates = Rates()
    for row, flagged in list(zip(scored, scored_flags, strict=True)) + list(zip(others, other_flags, strict=True)):
        if row.label == 1:
            rates.bad += 1
            rates.flagged_bad += int(flagged)
        else:
            rates.clean += 1
            rates.flagged_clean += int(flagged)
    return rates


def _shipped_scores(rows: list[CaseRow]) -> list[float]:
    head = load_head("jev")
    return [head.predict(row.vector) for row in rows]


def _require_both_classes(scored: list[CaseRow]) -> None:
    bad = sum(row.label == 1 for row in scored)
    clean = sum(row.label == 0 for row in scored)
    if bad < 2 or clean < 2:
        raise SystemExit(
            f"only {bad} bad and {clean} clean tuning cases reached the scoring layer; "
            "at least 2 of each are required"
        )


def refit_rows(
    rows: list[CaseRow],
    *,
    max_clean_flag_rate: float | None = None,
    folds: int = 5,
    repeats: int = 10,
    seed: int = 13,
    c_grid=C_GRID,
) -> RefitResult:
    if folds < 2:
        raise SystemExit("folds must be at least 2")
    tuning = [row for row in rows if not row.held_out]
    held = [row for row in rows if row.held_out]
    scored = [row for row in tuning if row.scored]
    others = [row for row in tuning if not row.scored]
    _require_both_classes(scored)
    before = rates_for(scored, _shipped_scores(scored), others, CURRENT_FLOORS, REVIEW_THRESHOLD)
    cap = before.false_positive_rate if max_clean_flag_rate is None else float(max_clean_flag_rate)
    if not 0.0 <= cap <= 1.0:
        raise SystemExit("max clean flag rate must be between 0 and 1")
    fit_input = [{**row.vector, "label": row.label} for row in scored]
    c = choose_c(fit_input, c_grid=c_grid, folds=folds, repeats=repeats, seed=seed)
    after, after_current, splits = cross_validated_rates(scored, others, c, folds, seed, cap)
    oof = oof_scores(scored, c, folds, seed)
    review_at, floors = select_policy(scored, oof, others, cap)
    review_at = min(max(review_at, 0.01), 0.97)
    clean_oof = [score for row, score in zip(scored, oof, strict=True) if row.label == 0]
    alert_at = alert_cutoff(clean_oof, review_at)
    payload = fit_head(fit_input, model_id=_model_id(tuning), c=c)
    payload["source"] = "refit"
    payload["cutoffs"] = {"review": review_at, "alert": alert_at}
    payload["floors"] = floors
    payload["holdout"] = {
        "precision": None,
        "recall": after.recall,
        "false_positive_rate": after.false_positive_rate,
        "n": after.bad + after.clean,
        "method": "cross_validation",
    }
    payload["cv"] = {
        "folds": splits,
        "seed": seed,
        "max_clean_flag_rate": cap,
        "c_chosen_on": "all_tuning_rows",
        "cutoffs_and_floors_chosen_on": "out_of_fold_scores",
        "tuning_bad": before.bad,
        "tuning_clean": before.clean,
        "tuning_scored": len(scored),
        "tuning_unreadable": sum(row.unreadable for row in tuning),
        "tuning_deferred": sum(row.deferred for row in tuning),
        "tuning_gate_cleared": sum(row.gate_cleared for row in tuning),
        "flagged_bad_before": before.flagged_bad,
        "flagged_clean_before": before.flagged_clean,
        "flagged_bad_after": after.flagged_bad,
        "flagged_clean_after": after.flagged_clean,
        "recall_before": before.recall,
        "false_positive_rate_before": before.false_positive_rate,
        "recall_after": after.recall,
        "false_positive_rate_after": after.false_positive_rate,
        "recall_after_current_floors": after_current.recall,
        "false_positive_rate_after_current_floors": after_current.false_positive_rate,
    }
    held_before = held_after = None
    if held:
        held_scored = [row for row in held if row.scored]
        held_others = [row for row in held if not row.scored]
        held_before = rates_for(held_scored, _shipped_scores(held_scored), held_others, CURRENT_FLOORS, REVIEW_THRESHOLD)
        head = LogisticHead(payload)
        held_after = rates_for(
            held_scored,
            [head.raw_predict(row.vector) for row in held_scored],
            held_others,
            floors,
            review_at,
        )
    return RefitResult(
        payload=payload,
        before=before,
        after=after,
        after_current_floors=after_current,
        held_out_before=held_before,
        held_out_after=held_after,
        cap=cap,
        folds=splits,
        review_at=review_at,
        floors=floors,
        counts=_split_counts(tuning),
    )


def _rate_text(rates: Rates) -> str:
    parts = []
    if rates.bad:
        parts.append(f"recall {rates.flagged_bad}/{rates.bad} ({rates.recall:.3f})")
    if rates.clean:
        parts.append(
            f"false-positive rate {rates.flagged_clean}/{rates.clean} ({rates.false_positive_rate:.3f})"
        )
    return ", ".join(parts) if parts else "no cases"


def _floor_text(floors: dict[str, float | None]) -> str:
    parts = []
    for name in FLOOR_NAMES:
        level = floors[name]
        parts.append(f"{name} off" if level is None else f"{name} {level:.2f}")
    return ", ".join(parts)


def render_report(result: RefitResult, out: Path) -> str:
    counts = result.counts
    lines = [
        (
            f"Tuning cases: {counts['bad']} bad, {counts['clean']} clean. "
            f"Unread {counts['unreadable']} (counted as flagged). "
            f"Gate-cleared {counts['gate_cleared']} (counted as not flagged). "
            f"Deferred {counts['deferred']} (counted as not flagged)."
        ),
        f"Clean-flag cap: {result.cap:.3f}.",
        f"Before, current head and current floors: {_rate_text(result.before)}.",
        (
            f"After, new head and new floors, {result.folds}-fold cross-validation: "
            f"{_rate_text(result.after)}."
        ),
        (
            f"After, new head and current floors, {result.folds}-fold cross-validation: "
            f"{_rate_text(result.after_current_floors)}."
        ),
        f"Floors written: {_floor_text(result.floors)}.",
        (
            f"Review cutoff {result.payload['cutoffs']['review']:.3f}, "
            f"alert cutoff {result.payload['cutoffs']['alert']:.3f}."
        ),
    ]
    if result.held_out_before is not None and result.held_out_after is not None:
        lines.append(
            "Held-out, scored once and not used to fit. "
            f"Before: {_rate_text(result.held_out_before)}. "
            f"After: {_rate_text(result.held_out_after)}."
        )
    lines.append("Installing this file uses the new weights, cutoffs, and floor levels.")
    lines.append(f"Wrote {out}.")
    return "\n".join(lines) + "\n"


def refuse_live_head(path: Path) -> None:
    if path.resolve() == HEAD_PATH.resolve():
        raise SystemExit(f"refusing to write {path}; that file is the live scoring head")


def write_payload(path: Path, payload: dict) -> None:
    refuse_live_head(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def refit_paths(
    cases: Path,
    scout: Path,
    out: Path,
    *,
    max_clean_flag_rate: float | None = None,
    folds: int = 5,
    repeats: int = 10,
    seed: int = 13,
) -> RefitResult:
    refuse_live_head(out)
    rows = load_cases(cases, scout)
    result = refit_rows(
        rows,
        max_clean_flag_rate=max_clean_flag_rate,
        folds=folds,
        repeats=repeats,
        seed=seed,
    )
    write_payload(out, result.payload)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Refit the scoring head and floors from local cases.")
    parser.add_argument("--cases", type=Path, required=True, help="Directory of fixture JSON files")
    parser.add_argument("--scout", type=Path, required=True, help="Saved Scout output for those cases")
    parser.add_argument("--out", type=Path, required=True, help="Where to write the new weight file")
    parser.add_argument(
        "--max-clean-flag-rate",
        type=float,
        default=None,
        help="Largest share of tuning clean cases the new weights may flag. Default: the current rate.",
    )
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--seed", type=int, default=13)
    args = parser.parse_args(argv)
    result = refit_paths(
        args.cases,
        args.scout,
        args.out,
        max_clean_flag_rate=args.max_clean_flag_rate,
        folds=args.folds,
        repeats=args.repeats,
        seed=args.seed,
    )
    sys.stdout.write(render_report(result, args.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
