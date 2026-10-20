"""Offline labeled-corpus report. Metrics are omitted when the sample cannot support them."""

from __future__ import annotations

from hunter.classify import classify_files
from hunter.fixtures_io import iter_fixtures


def evaluate_fixtures(root: str, *, jev) -> dict:
    rows = []
    histogram = {"alert": 0, "review": 0, "benign": 0}
    tp = fp = fn = tn = 0
    labeled = 0
    for path, (meta, old_files, new_files, label) in iter_fixtures(root):
        result = classify_files(meta=meta, old_files=old_files, new_files=new_files, jev=jev)
        histogram[result.band] = histogram.get(result.band, 0) + 1
        row = {
            "id": path.stem,
            "label": label,
            "band": result.band,
            "malice_probability": result.malice_probability,
            "attack_family": result.attack_family,
            "signals": result.signals,
        }
        rows.append(row)
        if label not in {"malicious", "benign"}:
            continue
        labeled += 1
        predicted = result.band == "alert"
        actual = label == "malicious"
        if predicted and actual:
            tp += 1
        elif predicted and not actual:
            fp += 1
        elif not predicted and actual:
            fn += 1
        else:
            tn += 1
    precision = (tp / (tp + fp)) if (tp + fp) else None
    recall = (tp / (tp + fn)) if (tp + fn) else None
    return {
        "rows": rows,
        "histogram": histogram,
        "labeled_binary": labeled,
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "precision": precision,
        "recall": recall,
    }


def format_report(report: dict) -> str:
    lines = [
        "Offline fixture evaluation",
        f"rows={len(report['rows'])} binary_labels={report['labeled_binary']}",
        "histogram " + " ".join(f"{name}={count}" for name, count in report["histogram"].items()),
        "confusion tp={tp} fp={fp} fn={fn} tn={tn}".format(**report["confusion"]),
    ]
    if report["precision"] is None:
        lines.append("precision withheld (no predicted alerts in the binary set)")
    else:
        lines.append(f"precision={report['precision']:.3f}")
    if report["recall"] is None:
        lines.append("recall withheld (no malicious labels in the binary set)")
    else:
        lines.append(f"recall={report['recall']:.3f}")
    return "\n".join(lines) + "\n"
