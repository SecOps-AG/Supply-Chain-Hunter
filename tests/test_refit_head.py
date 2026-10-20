"""Synthetic cases only. The refit tool never sees real packages and does not use the network."""

import json
from pathlib import Path

import pytest

from hunter.head import FEATURE_NAMES, LogisticHead
from hunter.refit_head import (
    CURRENT_FLOORS,
    FLOOR_NAMES,
    CaseRow,
    apply_flag,
    main,
    oof_scores,
    refit_paths,
    refit_rows,
    select_policy,
)
from hunter.train import HEAD_PATH


def _flags(**on: bool) -> dict[str, bool]:
    flags = {name: False for name in FLOOR_NAMES}
    flags.update(on)
    return flags


def _vector(noul: float) -> dict[str, float]:
    row = {name: 0.0 for name in FEATURE_NAMES}
    row["noul_install_time_execution"] = noul
    return row


def _row(label: int, noul: float, **flag_on: bool) -> CaseRow:
    return CaseRow(id=f"row-{label}-{noul}", label=label, vector=_vector(noul), floor_flags=_flags(**flag_on))


def test_unread_clean_does_not_excuse_flagging_more_clean_cases():
    scored = [_row(1, 0.9) for _ in range(4)] + [_row(0, 0.05) for _ in range(4)]
    unread = CaseRow(
        id="unread-clean",
        label=0,
        vector=None,
        floor_flags=_flags(),
        unreadable=True,
    )
    scores = [0.9 if row.label == 1 else 0.05 for row in scored]
    review_at, floors = select_policy(scored, scores, [unread], cap=0.0)
    assert review_at > 0.05
    assert all(not apply_flag(row, score, floors, review_at) for row, score in zip(scored, scores) if row.label == 0)
    assert all(apply_flag(row, score, floors, review_at) for row, score in zip(scored, scores) if row.label == 1)


def test_floor_search_turns_off_a_floor_that_only_flags_clean_cases():
    scored = [_row(1, 0.9) for _ in range(4)] + [_row(0, 0.1, entrypoint_payload=True) for _ in range(2)]
    scored += [_row(0, 0.1) for _ in range(2)]
    scores = [0.9 if row.label == 1 else 0.1 for row in scored]
    review_at, floors = select_policy(scored, scores, [], cap=0.0)
    assert floors["entrypoint_payload"] is None
    assert review_at >= 0.1
    assert all(not apply_flag(row, score, floors, review_at) for row, score in zip(scored, scores) if row.label == 0)
    assert all(apply_flag(row, score, floors, review_at) for row, score in zip(scored, scores) if row.label == 1)


def test_written_cutoff_uses_out_of_fold_scores(monkeypatch):
    def fake_oof(rows, c, folds, seed):
        return [0.9 if row.label == 1 else 0.1 for row in rows]

    monkeypatch.setattr("hunter.refit_head.oof_scores", fake_oof)
    rows = [_row(1, 0.99) for _ in range(6)] + [_row(0, 0.02) for _ in range(6)]
    result = refit_rows(rows, folds=3, repeats=1, c_grid=(1.0,))
    assert result.payload["cutoffs"]["review"] == pytest.approx(0.9)
    assert result.payload["source"] == "refit"
    assert result.payload["cv"]["cutoffs_and_floors_chosen_on"] == "out_of_fold_scores"
    assert 0.0 < result.payload["cutoffs"]["review"] < result.payload["cutoffs"]["alert"] < 1.0


def _fixture(label: str) -> dict:
    body = "function pad(value) {\n  return value;\n}\n"
    return {
        "label": label,
        "ecosystem": "npm",
        "name": "sample-widget",
        "old_version": "1.0.0",
        "new_version": "1.0.1",
        "old_files": {
            "package.json": '{"name":"sample-widget","version":"1.0.0"}\n',
            "index.js": body,
        },
        "new_files": {
            "package.json": '{"name":"sample-widget","version":"1.0.1"}\n',
            "index.js": body,
        },
    }


def _write_set(directory: Path, *, poison: bool) -> Path:
    scout = []
    for index in range(8):
        stem = f"sample-bad-{index}"
        (directory / f"{stem}.json").write_text(json.dumps(_fixture("malicious")), encoding="utf-8")
        scout.append({"id": stem, "nouls": {"install_time_execution": 0.99}, "group": "train_bad"})
    for index in range(8):
        stem = f"sample-clean-{index}"
        (directory / f"{stem}.json").write_text(json.dumps(_fixture("benign")), encoding="utf-8")
        scout.append({"id": stem, "nouls": {"install_time_execution": 0.02}, "group": "clean_tune"})
    if poison:
        stem = "sample-held-clean"
        (directory / f"{stem}.json").write_text(json.dumps(_fixture("benign")), encoding="utf-8")
        scout.append(
            {
                "id": stem,
                "nouls": {name.removeprefix("noul_"): 1.0 for name in FEATURE_NAMES if name.startswith("noul_")},
                "group": "clean_held_out",
                "label": 0,
            }
        )
    path = directory / "scout.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in scout), encoding="utf-8")
    return path


def test_command_prints_rates_and_leaves_the_live_head_alone(tmp_path, capsys):
    live_before = HEAD_PATH.read_bytes()
    cases = tmp_path / "cases"
    cases.mkdir()
    scout = _write_set(cases, poison=True)
    out = tmp_path / "logistic_head_refit.json"
    code = main(
        ["--cases", str(cases), "--scout", str(scout), "--out", str(out), "--folds", "3", "--repeats", "1"]
    )
    printed = capsys.readouterr().out
    assert code == 0
    assert "Before, current head and current floors: recall 0/8 (0.000), false-positive rate 0/8 (0.000)." in printed
    assert "After, new head and new floors, 3-fold cross-validation: recall 8/8 (1.000), false-positive rate 0/8 (0.000)." in printed
    assert "Installing this file uses the new weights, cutoffs, and floor levels." in printed
    assert "sample-bad-0" not in printed
    assert "sample-widget" not in printed
    assert HEAD_PATH.read_bytes() == live_before
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert "sample-bad-0" not in out.read_text(encoding="utf-8")
    assert "sample-widget" not in out.read_text(encoding="utf-8")
    head = LogisticHead(payload)
    assert head.feature_names == list(FEATURE_NAMES)
    assert payload["floors"]["entrypoint_payload"] == CURRENT_FLOORS["entrypoint_payload"]
    assert payload["cv"]["tuning_bad"] == 8
    assert payload["cv"]["tuning_clean"] == 8
    assert "Held-out, scored once and not used to fit." in printed
    bad = _vector(0.99)
    clean = _vector(0.02)
    assert head.raw_predict(bad) > head.raw_predict(clean)


def test_held_out_rows_do_not_change_the_weights(tmp_path):
    plain = tmp_path / "plain"
    poisoned = tmp_path / "poisoned"
    plain.mkdir()
    poisoned.mkdir()
    first = refit_paths(plain, _write_set(plain, poison=False), tmp_path / "a.json", folds=3, repeats=1)
    second = refit_paths(poisoned, _write_set(poisoned, poison=True), tmp_path / "b.json", folds=3, repeats=1)
    assert first.payload["coefficients"] == second.payload["coefficients"]
    assert first.payload["intercept"] == second.payload["intercept"]
    assert second.payload["cv"]["tuning_bad"] == 8
    assert second.held_out_before is not None
    assert second.held_out_before.clean == 1


def test_refuses_to_overwrite_the_live_head(tmp_path):
    cases = tmp_path / "cases"
    cases.mkdir()
    scout = _write_set(cases, poison=False)
    live_before = HEAD_PATH.read_bytes()
    with pytest.raises(SystemExit, match="live scoring head"):
        main(["--cases", str(cases), "--scout", str(scout), "--out", str(HEAD_PATH), "--repeats", "1"])
    assert HEAD_PATH.read_bytes() == live_before


def test_missing_scout_row_is_an_error(tmp_path):
    cases = tmp_path / "cases"
    cases.mkdir()
    (cases / "sample-bad-0.json").write_text(json.dumps(_fixture("malicious")), encoding="utf-8")
    (cases / "sample-clean-0.json").write_text(json.dumps(_fixture("benign")), encoding="utf-8")
    scout = tmp_path / "scout.json"
    scout.write_text(json.dumps({"sample-bad-0": {"nouls": {"install_time_execution": 0.5}}}), encoding="utf-8")
    with pytest.raises(SystemExit, match="no scout row"):
        refit_paths(cases, scout, tmp_path / "out.json", repeats=1)
    assert not (tmp_path / "out.json").exists()


def test_oof_scores_cover_every_row():
    rows = [_row(1, 0.99) for _ in range(4)] + [_row(0, 0.01) for _ in range(4)]
    scores = oof_scores(rows, c=1.0, folds=2, seed=13)
    assert len(scores) == len(rows)
    assert all(0.0 <= score <= 1.0 for score in scores)
    bad = [score for row, score in zip(rows, scores) if row.label == 1]
    clean = [score for row, score in zip(rows, scores) if row.label == 0]
    assert min(bad) > max(clean)
