"""Offline teach-until-catch. No webhook, no production lesson writes."""

import json
from pathlib import Path

import pytest

from hunter.config import Config
from hunter.teach import (
    TeachRefused,
    discover_fixture,
    fixture_from_note,
    mock_triage_report,
    production_should_escalate,
    resolve_teacher_model,
    resolve_triage_model,
    run_teach,
    write_axios_distillation,
)


def _quiet_env(monkeypatch):
    monkeypatch.delenv("HUNTER_SMART_MODEL", raising=False)
    monkeypatch.delenv("HUNTER_ANALYST_MODEL", raising=False)
    monkeypatch.delenv("ALERT_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("HUNTER_SCOUT_LESSONS", raising=False)
    monkeypatch.delenv("HUNTER_ESCALATE_UNCERTAIN", raising=False)
    monkeypatch.delenv("HUNTER_SMART_BACKEND", raising=False)
    monkeypatch.delenv("HUNTER_ANALYST_BACKEND", raising=False)


def test_fast_slugs_are_refused(monkeypatch):
    _quiet_env(monkeypatch)
    with pytest.raises(TeachRefused):
        resolve_triage_model("composer-2.5-fast")
    with pytest.raises(TeachRefused):
        resolve_teacher_model("grok-4.7-fast")
    monkeypatch.setenv("HUNTER_ANALYST_ALLOW_FAST", "1")
    with pytest.raises(TeachRefused):
        resolve_teacher_model("grok-4.7-fast")
    assert resolve_triage_model(None) == "composer-2.5"
    with pytest.raises(TeachRefused):
        resolve_teacher_model(None)
    assert resolve_teacher_model("grok-4.7") == "grok-4.7"
    monkeypatch.setenv("HUNTER_ANALYST_MODEL", "any-provider/big-model")
    assert resolve_teacher_model(None) == "any-provider/big-model"


def test_http_backend_triage_model_has_no_default(monkeypatch):
    _quiet_env(monkeypatch)
    monkeypatch.setenv("HUNTER_SMART_BACKEND", "openai")
    with pytest.raises(TeachRefused):
        resolve_triage_model(None)
    monkeypatch.setenv("HUNTER_SMART_MODEL", "my-triage-model")
    assert resolve_triage_model(None) == "my-triage-model"


def test_escalate_flag_defaults_off_and_predicate_stays_narrow(monkeypatch):
    _quiet_env(monkeypatch)
    config = Config.from_env()
    assert config.escalate_uncertain is False
    assert config.escalate_uncertain_budget == 5
    evidence = {
        "primary_band": "review",
        "attack_family": "dependency_abuse",
        "signals": ["phantom_runtime_dependency:plain-crypto-js"],
    }
    assert production_should_escalate(evidence, "uncertain", enabled=False) is False
    assert production_should_escalate(evidence, "benign", enabled=True) is False
    assert production_should_escalate(evidence, "uncertain", enabled=True) is True
    assert production_should_escalate({"primary_band": "benign", "signals": []}, "uncertain", enabled=True) is False


def test_note_points_at_a_fixture(tmp_path, monkeypatch):
    trees = tmp_path / "trees"
    trees.mkdir()
    note = tmp_path / "teach-fixture.md"
    note.write_text(f"fixture: {trees}\n", encoding="utf-8")
    assert fixture_from_note(note) == str(trees)
    monkeypatch.chdir(tmp_path)
    assert discover_fixture(None) == trees


def test_hidden_dependency_is_benign_until_the_excerpt_shows_it():
    evidence = {
        "primary_band": "review",
        "attack_family": "dependency_abuse",
        "signals": ["phantom_runtime_dependency:plain-crypto-js"],
        "diff_excerpt": "CHANGELOG only\n" * 50,
    }
    report = mock_triage_report(evidence, "An unexpected new runtime dependency is a compromised library.", "")
    assert "Verdict: benign" in report


def test_production_sop_catches_axios_distillation_without_posting(tmp_path, monkeypatch):
    _quiet_env(monkeypatch)
    monkeypatch.setenv("ALERT_WEBHOOK_URL", "https://discord.com/api/webhooks/9/token")
    calls = []

    def _post(*_args, **_kwargs):
        calls.append(1)

    monkeypatch.setattr("hunter.webhook.post_json", _post)
    production = tmp_path / "scout-lessons.md"
    production.write_text("# Scout lessons\n\nuntouched\n", encoding="utf-8")
    monkeypatch.setenv("HUNTER_SCOUT_LESSONS", str(production))
    packaged_skill = Path("hunter/triage_skill/SKILL.md").read_text(encoding="utf-8")
    packaged_lessons = Path("hunter/triage_skill/LESSONS.md").read_text(encoding="utf-8")
    root = write_axios_distillation(tmp_path / "trees")
    result = run_teach(root, max_rounds=5, out_dir=tmp_path / "out", mode="mock")
    assert result["success"] is True
    assert result["would_alert"] is True
    assert result["alert_sent"] is False
    assert result["mode"] == "mock"
    assert calls == []
    assert result["rounds"][0]["scout_band"] in {"review", "alert"}
    assert result["rounds"][0]["triage_verdict"] == "malicious"
    assert result["rounds"][0]["analyst_verdict"] == "malicious"
    assert result["rounds"][0]["dep_visible"] is True
    assert result["rounds"][0]["teacher_called"] is False
    assert result["lessons_proposed"] == []
    assert production.read_text(encoding="utf-8") == "# Scout lessons\n\nuntouched\n"
    assert Path("hunter/triage_skill/SKILL.md").read_text(encoding="utf-8") == packaged_skill
    assert Path("hunter/triage_skill/LESSONS.md").read_text(encoding="utf-8") == packaged_lessons
    assert "plain-crypto-js" in (tmp_path / "out" / "round-1-excerpt.txt").read_text(encoding="utf-8")
    sandbox_scout = (tmp_path / "out" / "sandbox" / "scout-lessons.md").read_text(encoding="utf-8")
    assert "untouched" in sandbox_scout


def test_ablation_teaches_a_sandbox_lesson_and_then_catches(tmp_path, monkeypatch):
    _quiet_env(monkeypatch)
    production = tmp_path / "production-scout-lessons.md"
    production.write_text("# Scout lessons\n", encoding="utf-8")
    monkeypatch.setenv("HUNTER_SCOUT_LESSONS", str(production))
    before = production.read_bytes()
    root = write_axios_distillation(tmp_path / "trees")
    result = run_teach(
        root,
        max_rounds=5,
        out_dir=tmp_path / "out",
        mode="mock",
        strip_sections=["Compromised library"],
    )
    assert result["success"] is True
    assert result["would_alert"] is True
    assert result["alert_sent"] is False
    assert len(result["rounds"]) >= 2
    assert result["rounds"][0]["triage_verdict"] == "uncertain"
    assert result["rounds"][0]["escalated"] is True
    assert result["rounds"][0]["analyst_verdict"] == "malicious"
    assert result["rounds"][0]["teacher_called"] is True
    assert result["rounds"][-1]["triage_verdict"] == "malicious"
    assert result["lessons_proposed"][0]["pattern"] == "unexpected-new-dependency"
    assert "changelog" in result["lessons_proposed"][0]["rule"].lower()
    lesson_file = (tmp_path / "out" / "sandbox" / "triage-lessons.md").read_text(encoding="utf-8")
    assert "unexpected-new-dependency" in lesson_file
    assert production.read_bytes() == before


def test_live_mode_refuses_without_a_key(tmp_path, monkeypatch):
    _quiet_env(monkeypatch)
    monkeypatch.delenv("CURSOR_API_KEY", raising=False)
    root = write_axios_distillation(tmp_path / "trees", changelog_chars=200)
    with pytest.raises(TeachRefused):
        run_teach(root, max_rounds=1, out_dir=tmp_path / "out", mode="live")
