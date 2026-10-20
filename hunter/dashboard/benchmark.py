"""Read decision-model benchmark results from a results directory for the dashboard.

The directory is set by HUNTER_BENCH_DIR. It holds one folder per run, each with a
`leaderboard.json` and optional per-case files in `data/<model>-cases.jsonl`, or it is
one such run folder itself. Files are only parsed as JSON. Values that are missing or
were skipped stay null; nothing is filled in.
"""

from __future__ import annotations

import json
import math
import re
from pathlib import Path

LEADERBOARD = "leaderboard.json"
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_RUNS = 200
MAX_CASES = 5000
_MODEL_FILE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

MODEL_FIELDS_INT = (
    "cases",
    "bad_n",
    "clean_n",
    "catch",
    "false_flags",
    "alert_bad",
    "alert_clean",
    "deferred",
    "input_tokens",
    "output_tokens",
    "calls",
)
MODEL_FIELDS_FLOAT = ("catch_rate", "false_flag_rate", "usd", "usd_per_case", "seconds_per_case")
MODEL_FIELDS_TEXT = ("model", "backend", "model_id", "rules", "corpus", "skip_reason")
CASE_FIELDS_TEXT = ("id", "group", "label", "band", "status", "defer_reason")
PIPELINE_CASE_TEXT = ("id", "label", "scout_band", "triage_status", "triage_verdict", "analyst_status", "analyst_verdict")


def _num(value, *, integer: bool = False):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not math.isfinite(value):
        return None
    return int(value) if integer else float(value)


def _text(value, limit: int = 300) -> str | None:
    if value is None:
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        value = str(value)
    if not isinstance(value, str):
        return None
    return value[:limit]


def _bool(value) -> bool | None:
    return value if isinstance(value, bool) else None


def _read_json(path: Path):
    try:
        if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None


def _read_jsonl(path: Path, limit: int = MAX_CASES) -> list[dict]:
    try:
        if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
            return []
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return []
    rows: list[dict] = []
    for line in lines[:limit]:
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _flat(source: object, depth: int = 0) -> object:
    """Numbers, booleans, short strings and nested dicts/lists of them. Anything else is dropped."""
    if isinstance(source, bool) or source is None:
        return source
    if isinstance(source, (int, float)):
        return _num(source)
    if isinstance(source, str):
        return source[:400]
    if depth >= 3:
        return None
    if isinstance(source, dict):
        return {str(key)[:80]: _flat(value, depth + 1) for key, value in list(source.items())[:60]}
    if isinstance(source, list):
        return [_flat(value, depth + 1) for value in source[:60]]
    return None


def model_status(row: dict) -> str:
    if row.get("skip_reason") or row.get("backend") == "skipped":
        return "skipped"
    if row.get("catch") is None and row.get("false_flags") is None:
        return "unavailable"
    return "ok"


def normalize_model(raw: dict) -> dict:
    row: dict = {}
    for name in MODEL_FIELDS_TEXT:
        row[name] = _text(raw.get(name))
    for name in MODEL_FIELDS_INT:
        row[name] = _num(raw.get(name), integer=True)
    for name in MODEL_FIELDS_FLOAT:
        row[name] = _num(raw.get(name))
    row["status"] = model_status(row)
    if row["status"] == "skipped":
        # A skipped model has no measured spend, even when the file writes $0.
        row["usd"] = None
    return row


def _case(raw: dict) -> dict:
    row = {name: _text(raw.get(name), 200) for name in CASE_FIELDS_TEXT}
    row["p"] = _num(raw.get("p"))
    row["usd"] = _num(raw.get("usd"))
    row["seconds"] = _num(raw.get("seconds"))
    row["to_triage"] = _bool(raw.get("to_triage"))
    return row


def _pipeline_case(raw: dict) -> dict:
    row = {name: _text(raw.get(name), 200) for name in PIPELINE_CASE_TEXT}
    row["would_alert"] = _bool(raw.get("discord"))
    row["triage_seconds"] = _num(raw.get("triage_secs"))
    row["analyst_seconds"] = _num(raw.get("analyst_secs"))
    return row


def load_run(folder: Path) -> dict | None:
    board = _read_json(folder / LEADERBOARD)
    if not isinstance(board, dict):
        return None
    raw_models = board.get("models") if isinstance(board.get("models"), list) else []
    models = [normalize_model(item) for item in raw_models if isinstance(item, dict)]
    commit = _text(board.get("product_commit"), 64)
    short = _text(board.get("product_commit_short"), 16) or (commit[:7] if commit else None)
    cases: dict[str, list[dict]] = {}
    data = folder / "data"
    for model in models:
        name = (model.get("model") or "").lower()
        if model["status"] != "ok" or not _MODEL_FILE.match(name):
            continue
        rows = _read_jsonl(data / f"{name}-cases.jsonl")
        if rows:
            cases[name] = [_case(row) for row in rows]
            if model["deferred"] is None:
                # Counted from the measured per-case rows, never guessed.
                model["deferred"] = sum(1 for row in cases[name] if row["band"] == "deferred")
    pipeline_cases = [_pipeline_case(row) for row in _read_jsonl(data / "pipeline-cases.jsonl")]
    skipped = []
    for item in board.get("skipped") or []:
        if isinstance(item, dict):
            skipped.append({"item": _text(item.get("item")), "reason": _text(item.get("reason"))})
    return {
        "id": folder.name[:120],
        "run_date": _text(board.get("run_date_pt") or board.get("run_date"), 40),
        "product_commit": commit,
        "product_commit_short": short,
        "product_release": _text(board.get("product_release") or board.get("release"), 60),
        "corpus": _text(board.get("corpus_id"), 120),
        "corpus_note": _text(board.get("corpus_note"), 400),
        "hard_cap_usd": _num(board.get("hard_cap_usd_scout_models")),
        "total_paid_usd": _num(board.get("total_scout_paid_usd")),
        "models": models,
        "cases": cases,
        "pipeline": _flat(board.get("pipeline")) if isinstance(board.get("pipeline"), dict) else None,
        "pipeline_cases": pipeline_cases,
        "rules_on_vs_off": _flat(board.get("rules_on_vs_off")) if isinstance(board.get("rules_on_vs_off"), dict) else None,
        "fallback": _flat(board.get("fallback")) if isinstance(board.get("fallback"), dict) else None,
        "skipped": skipped,
    }


def run_folders(root: Path) -> list[Path]:
    if (root / LEADERBOARD).is_file():
        return [root]
    try:
        children = sorted(path for path in root.iterdir() if path.is_dir() and not path.is_symlink())
    except OSError:
        return []
    return [path for path in children if (path / LEADERBOARD).is_file()][-MAX_RUNS:]


def load_benchmarks(bench_dir: str) -> dict:
    """Benchmark runs, oldest first. `configured` is False when no directory is set."""
    if not (bench_dir or "").strip():
        return {"configured": False, "runs": [], "error": None}
    root = Path(bench_dir).expanduser()
    if not root.is_dir():
        return {"configured": True, "runs": [], "error": "The benchmark directory does not exist."}
    runs = [run for run in (load_run(folder) for folder in run_folders(root)) if run is not None]
    runs.sort(key=lambda run: (run.get("run_date") or "", run["id"]))
    return {"configured": True, "runs": runs, "error": None}
