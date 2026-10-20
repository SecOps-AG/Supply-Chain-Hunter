"""The default cursor backend says clearly what to do when the agent CLI is missing."""

import dataclasses
import logging

import pytest

from hunter import investigate
from hunter.config import CURSOR_CLI_MISSING, Config, cursor_cli_missing


def _config(**overrides) -> Config:
    return dataclasses.replace(Config.from_env(), **overrides)


def test_message_names_both_ways_out():
    assert "install the Cursor CLI" in CURSOR_CLI_MISSING
    assert "HUNTER_SMART_BACKEND=openai or anthropic" in CURSOR_CLI_MISSING
    assert "HUNTER_SMART_BASE_URL" in CURSOR_CLI_MISSING and "HUNTER_SMART_API_KEY" in CURSOR_CLI_MISSING
    assert "\n" not in CURSOR_CLI_MISSING


def test_cursor_cli_missing_only_for_cursor_backend(monkeypatch):
    monkeypatch.setattr("hunter.config.shutil.which", lambda _name: None)
    assert cursor_cli_missing(_config(smart_backend="cursor", smart_analysis=True,
                                      investigate_command="", investigate_url=""))
    assert not cursor_cli_missing(_config(smart_backend="openai", smart_analysis=True,
                                          investigate_command="", investigate_url=""))
    assert not cursor_cli_missing(_config(smart_backend="cursor", smart_analysis=False,
                                          investigate_command="", investigate_url=""))
    monkeypatch.setattr("hunter.config.shutil.which", lambda _name: "/usr/bin/agent")
    assert not cursor_cli_missing(_config(smart_backend="cursor", smart_analysis=True,
                                          investigate_command="", investigate_url=""))


def test_startup_logs_one_line(monkeypatch, caplog):
    monkeypatch.setattr("hunter.config.shutil.which", lambda _name: None)
    monkeypatch.setattr(investigate, "_WARNED", set())
    cfg = _config(smart_backend="cursor", smart_analysis=True, investigate_command="", investigate_url="")
    with caplog.at_level(logging.ERROR):
        investigate.warn_smart_config(cfg)
    lines = [r.getMessage() for r in caplog.records if "Cursor Agent CLI" in r.getMessage()]
    assert lines == [f"The mid-tier, balanced model (Triage) cannot run. {CURSOR_CLI_MISSING}"]


def test_triage_call_without_agent_binary_raises_clear_error(monkeypatch):
    def missing(*_args, **_kwargs):
        raise FileNotFoundError(2, "No such file or directory", "agent")

    monkeypatch.setattr(investigate.subprocess, "run", missing)
    with pytest.raises(RuntimeError) as err:
        investigate.run_agent_cli("prompt", model="composer-2.5", timeout=5)
    assert str(err.value) == CURSOR_CLI_MISSING
