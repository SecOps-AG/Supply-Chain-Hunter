"""OpenRouter for the mid-tier, balanced model and the Frontier model. No live calls."""

import argparse
import json

import pytest

from hunter.cli import _cmd_models
from hunter.config import Config, active_role_models, smart_analysis_enabled
from hunter.investigate import analyst_can_run, run_agent_cli, run_smart_analysis, triage_endpoint, warn_smart_config
from hunter.llm import ModelCallError, ModelEndpoint, call_http_model, normalize_backend
from hunter.openrouter import (
    list_openrouter_models,
    resolve_openrouter_api_key,
    resolve_openrouter_base_url,
)
from hunter.scout_model import scout_model_from_env
from hunter.service import health_payload
from hunter.db import Database
from hunter.teach import resolve_teacher_model, resolve_triage_model


@pytest.fixture(autouse=True)
def _clear_openrouter_env(monkeypatch):
    for name in (
        "OpenRouter",
        "OPENROUTER_API_KEY",
        "HUNTER_OPENROUTER_API_KEY",
        "HUNTER_SMART_API_KEY",
        "HUNTER_ANALYST_API_KEY",
        "HUNTER_SMART_BASE_URL",
        "HUNTER_ANALYST_BASE_URL",
        "HUNTER_SMART_BACKEND",
        "HUNTER_ANALYST_BACKEND",
        "HUNTER_SMART_MODEL",
        "HUNTER_ANALYST_MODEL",
        "HUNTER_SCOUT_MODEL",
    ):
        monkeypatch.delenv(name, raising=False)


def _same(actual: str, expected: str, label: str) -> None:
    if actual != expected:
        raise AssertionError(label)


class FakePost:
    def __init__(self, reply):
        self.reply = reply
        self.calls = []

    def __call__(self, url, body, headers, timeout):
        self.calls.append({"url": url, "body": body, "headers": headers, "timeout": timeout})
        return self.reply


def test_backend_name_and_default_stay_cursor(monkeypatch):
    assert normalize_backend("OpenRouter") == "openrouter"
    monkeypatch.setenv("OpenRouter", "present-but-unused")
    config = Config.from_env()
    assert config.smart_backend == "cursor"
    assert config.analyst_backend == ""
    assert config.smart_model == "composer-2.5"
    if config.smart_api_key or config.analyst_api_key:
        raise AssertionError("default cursor backend stored an API key")
    if "present-but-unused" in repr(config):
        raise AssertionError("config repr included an API key")


def test_key_order_and_role_override(monkeypatch):
    monkeypatch.setenv("HUNTER_OPENROUTER_API_KEY", "from-hunter")
    _same(resolve_openrouter_api_key(), "from-hunter", "third key name was not used")
    monkeypatch.setenv("OPENROUTER_API_KEY", "from-openai-name")
    _same(resolve_openrouter_api_key(), "from-openai-name", "second key name was not used")
    monkeypatch.setenv("OpenRouter", "from-runtime")
    _same(resolve_openrouter_api_key(), "from-runtime", "OpenRouter env var was not used first")
    monkeypatch.setenv("HUNTER_SMART_BACKEND", "openrouter")
    monkeypatch.setenv("HUNTER_SMART_MODEL", "google/gemini-2.5-flash")
    monkeypatch.setenv("HUNTER_SMART_API_KEY", "role-override")
    monkeypatch.setenv("HUNTER_ANALYST_BACKEND", "openrouter")
    monkeypatch.setenv("HUNTER_ANALYST_MODEL", "vendor/model-fast")
    monkeypatch.setenv("HUNTER_ANALYST_API_KEY", "frontier-override")
    config = Config.from_env()
    _same(config.smart_api_key, "role-override", "mid-tier role key did not override the shared key")
    _same(config.analyst_api_key, "frontier-override", "Frontier role key did not override the shared key")
    _same(config.smart_model, "google/gemini-2.5-flash", "mid-tier model id was changed")
    _same(config.analyst_model, "vendor/model-fast", "Frontier model id was changed")
    _same(config.smart_base_url, "https://openrouter.ai/api/v1", "OpenRouter base URL was not the public API")
    shown = repr(config)
    if "role-override" in shown or "frontier-override" in shown or "from-runtime" in shown:
        raise AssertionError("config repr included an API key")


def test_cursor_client_url_is_refused():
    with pytest.raises(ValueError, match="not used"):
        resolve_openrouter_base_url("https://openrouter.ai/api/v1/cursor")
    monkey_env = {}
    assert "cursor" not in resolve_openrouter_base_url("")
    assert monkey_env == {}


def test_missing_key_fails_and_does_not_call(monkeypatch):
    post = FakePost({"choices": [{"message": {"content": "Verdict: malicious"}}]})
    with pytest.raises(ModelCallError, match="will not fall back"):
        call_http_model(ModelEndpoint(backend="openrouter", model="any/id"), "hello", post=post)
    assert post.calls == []
    assert not smart_analysis_enabled(Config(smart_backend="openrouter", smart_model="any/id"))
    monkeypatch.setattr("hunter.investigate._WARNED", set())
    import logging

    class Capture(logging.Handler):
        def __init__(self):
            super().__init__()
            self.messages = []

        def emit(self, record):
            self.messages.append(record.getMessage())

    handler = Capture()
    logging.getLogger("hunter.investigate").addHandler(handler)
    try:
        warn_smart_config(Config(smart_backend="openrouter", smart_model="any/id", smart_analysis=True))
    finally:
        logging.getLogger("hunter.investigate").removeHandler(handler)
    assert any("will not fall back" in message for message in handler.messages)
    with pytest.raises(ModelCallError, match="will not fall back"):
        run_smart_analysis({}, config=Config(smart_backend="openrouter", smart_model="any/id"))


def test_any_model_id_is_sent_including_fast_and_flash():
    post = FakePost({"choices": [{"message": {"content": "Verdict: benign"}}]})
    endpoint = ModelEndpoint(
        backend="openrouter",
        model="google/gemini-2.5-flash",
        api_key="explicit-test-key",
        timeout=12,
        max_output_tokens=321,
    )
    assert call_http_model(endpoint, "hello", post=post) == "Verdict: benign"
    call = post.calls[0]
    _same(call["url"], "https://openrouter.ai/api/v1/chat/completions", "chat URL was not the OpenRouter API")
    if "/cursor" in call["url"]:
        raise AssertionError("cursor endpoint was used")
    _same(call["body"]["model"], "google/gemini-2.5-flash", "flash model id was not passed through")
    _same(call["headers"].get("Authorization"), "Bearer explicit-test-key", "Authorization was not the explicit test key")
    assert call["body"]["max_tokens"] == 321
    assert call["timeout"] == 12
    post.calls.clear()
    fast = ModelEndpoint(backend="openrouter", model="custom/whatever-fast", api_key="explicit-test-key")
    call_http_model(fast, "hello", post=post)
    _same(post.calls[0]["body"]["model"], "custom/whatever-fast", "fast model id was rewritten")


def test_frontier_fast_id_is_honored_and_cursor_fast_is_still_refused():
    assert analyst_can_run(
        Config(
            analyst_backend="openrouter",
            analyst_model="google/gemini-2.5-flash",
            analyst_api_key="frontier-test-key",
        )
    )
    assert analyst_can_run(
        Config(
            smart_backend="openrouter",
            smart_model="openai/gpt-4.1",
            smart_api_key="mid-test-key",
            analyst_model="vendor/model-fast",
        )
    )
    assert not analyst_can_run(Config(analyst_model="grok-4.7-fast"))
    point = triage_endpoint(Config(smart_backend="openrouter", smart_model="not-a-listed-id", smart_api_key="mid-test-key"))
    _same(point.backend, "openrouter", "triage left OpenRouter")
    _same(point.model, "not-a-listed-id", "triage model was filtered")
    _same(point.base_url, "https://openrouter.ai/api/v1", "triage base URL changed")


def test_models_list_returns_every_id():
    class Response:
        def read(self):
            return json.dumps(
                {
                    "data": [
                        {"id": "google/gemini-2.5-flash", "name": "Flash"},
                        {"id": "anthropic/claude-sonnet-4", "name": "Sonnet"},
                        {"id": "custom/whatever-fast", "name": "Fast"},
                    ]
                }
            ).encode()

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    def opener(request, timeout):
        _same(request.full_url, "https://openrouter.ai/api/v1/models", "models URL was not GET /models")
        if "/cursor" in request.full_url:
            raise AssertionError("cursor endpoint was used")
        _same(request.get_header("Authorization"), "Bearer list-test-key", "list request did not use the explicit test key")
        assert timeout == 30
        return Response()

    models = list_openrouter_models(api_key="list-test-key", opener=opener)
    assert [item["id"] for item in models] == [
        "google/gemini-2.5-flash",
        "anthropic/claude-sonnet-4",
        "custom/whatever-fast",
    ]


def test_models_command_and_health_hide_the_key(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("OpenRouter", "status-test-key")
    monkeypatch.setenv("HUNTER_SMART_BACKEND", "openrouter")
    monkeypatch.setenv("HUNTER_SMART_MODEL", "openai/gpt-4.1")
    monkeypatch.setenv("HUNTER_ANALYST_BACKEND", "openrouter")
    monkeypatch.setenv("HUNTER_ANALYST_MODEL", "anthropic/claude-sonnet-4")
    config = Config.from_env()
    assert _cmd_models(argparse.Namespace(list=False), config) == 0
    out = capsys.readouterr().out
    if "status-test-key" in out:
        raise AssertionError("models output included an API key")
    body = json.loads(out)
    assert body["decision_model"]["label"] == "decision model"
    assert body["decision_model"]["role"] == "Scout"
    assert body["decision_model"]["openrouter"] is False
    assert body["mid_tier_model"]["label"] == "mid-tier, balanced model"
    assert body["mid_tier_model"]["model"] == "openai/gpt-4.1"
    assert body["frontier_model"]["label"] == "Frontier model"
    assert body["frontier_model"]["model"] == "anthropic/claude-sonnet-4"
    assert body["mid_tier_model"]["openrouter_key_set"] is True
    db = Database(tmp_path / "hunter.sqlite3")
    health = json.dumps(health_payload(db, 0.0, config.scout_model_id(), config))
    if "status-test-key" in health:
        raise AssertionError("health payload included an API key")
    assert "Frontier model" in health
    assert "mid-tier, balanced model" in health


def test_models_list_command_errors_without_a_key(capsys):
    assert _cmd_models(argparse.Namespace(list=True), Config()) == 2
    err = capsys.readouterr().err
    assert "will not fall back" in err


def test_teach_honors_an_openrouter_fast_id(monkeypatch):
    monkeypatch.setenv("HUNTER_SMART_BACKEND", "openrouter")
    monkeypatch.setenv("HUNTER_ANALYST_BACKEND", "openrouter")
    assert resolve_triage_model("google/gemini-2.5-flash") == "google/gemini-2.5-flash"
    assert resolve_teacher_model("vendor/model-fast") == "vendor/model-fast"


def test_decision_model_stays_jev_or_clef():
    with pytest.raises(ValueError, match="decision model"):
        scout_model_from_env("google/gemini-2.5-pro")
    roles = active_role_models(Config())
    assert roles["decision_model"]["provider"] == "jev"
    assert roles["decision_model"]["openrouter"] is False


def test_cursor_agent_argv_never_sets_fast(monkeypatch):
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = list(argv)

        class Result:
            returncode = 0
            stdout = b"Verdict: benign"
            stderr = b""

        return Result()

    monkeypatch.setattr("hunter.investigate.subprocess.run", fake_run)
    run_agent_cli("prompt", model="grok-4.7-high", timeout=5)
    argv = captured["argv"]
    assert "fast=true" not in argv
    assert "--fast" not in argv
