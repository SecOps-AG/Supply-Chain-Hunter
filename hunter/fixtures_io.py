"""Load synthetic labeled release fixtures from JSON."""

from __future__ import annotations

import json
from pathlib import Path

from hunter.models import ReleaseMeta
from hunter.registry import parse_time


def load_fixture(path: str | Path) -> tuple[ReleaseMeta, dict[str, str], dict[str, str], str]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    meta = ReleaseMeta(
        ecosystem=data["ecosystem"],
        name=data["name"],
        new_version=data["new_version"],
        old_version=data.get("old_version"),
        rank=data.get("rank"),
        registry_url=data.get("registry_url") or "",
        old_publishers=frozenset(data.get("old_publishers") or []),
        new_publishers=frozenset(data.get("new_publishers") or []),
        old_time=parse_time(data.get("old_time")),
        new_time=parse_time(data.get("new_time")),
    )
    return meta, dict(data.get("old_files") or {}), dict(data.get("new_files") or {}), data["label"]


def iter_fixtures(root: str | Path):
    for path in sorted(Path(root).glob("*.json")):
        yield path, load_fixture(path)
