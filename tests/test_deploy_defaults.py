"""The shipped systemd unit turns the rule pack on."""

from __future__ import annotations

from pathlib import Path

from hunter.rules import rules_enabled

UNIT = Path(__file__).resolve().parents[1] / "deploy" / "hunter.service"


def _environment(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("Environment="):
            key, _, value = line[len("Environment="):].partition("=")
            found[key] = value
    return found


def test_unit_sets_hunter_rules_on():
    assert _environment(UNIT.read_text(encoding="utf-8")).get("HUNTER_RULES") == "on"


def test_unit_value_turns_the_rule_pack_on(monkeypatch):
    monkeypatch.setenv("HUNTER_RULES", _environment(UNIT.read_text(encoding="utf-8"))["HUNTER_RULES"])
    assert rules_enabled() is True
