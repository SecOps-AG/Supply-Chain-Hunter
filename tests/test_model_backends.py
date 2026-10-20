"""Triage and Analyst over OpenAI-compatible and Anthropic HTTP APIs. No network."""

import json

import pytest

from hunter.config import Config, smart_analysis_enabled, webhook_headers_from_env
from hunter.db import Database
from hunter.investigate import (
    analyst_endpoint,
    build_evidence,
    drain_analyst,
    run_analyst_analysis,
    run_smart_analysis,
    triage_endpoint,
)
from hunter.llm import (
    DIFF_TRUNCATION_NOTE,
    ModelCallError,
    ModelEndpoint,
    call_http_model,
    normalize_backend,
    prompt_with_diff,
)
from hunter.models import Classification
from hunter.webhook import drain_outbox


def _row(**overrides):
    values = dict(
        ecosystem="npm",
        name="leftpad",
        old_version="1",
        new_version="2",
        rank=1,
        registry_url="https://www.npmjs.com/package/leftpad/v/2",
        band="review",
        malice_probability=0.6,
        jev_model_id="jev-1.13.0",
    )
    values.update(overrides)
    return Classification(**values)


class FakePost:
    def __init__(self, reply):
        self.reply = reply
        self.calls = []

    def __call__(self, url, body, headers, timeout):
        self.calls.append({"url": url, "body": body, "headers": headers, "timeout": timeout})
        return self.reply


def test_backend_names_and_aliases():
    assert normalize_backend(None) == "cursor"
    assert normalize_backend("OpenAI") == "openai"
    assert normalize_backend("api_key") == "openai"
    assert normalize_backend("anthropic") == "anthropic"
    with pytest.raises(ValueError):
        normalize_backend("carrier-pigeon")


def test_openai_compatible_request_and_reply():
    post = FakePost({"choices": [{"message": {"content": "Looks bad.\nVerdict: malicious"}}]})
    endpoint = ModelEndpoint(
        backend="openai",
        model="my-model",
        base_url="http://localhost:11434/v1/",
        api_key="k",
        timeout=12,
    )
    text = call_http_model(endpoint, "hello", post=post)
    assert text.endswith("Verdict: malicious")
    call = post.calls[0]
    assert call["url"] == "http://localhost:11434/v1/chat/completions"
    assert call["headers"]["Authorization"] == "Bearer k"
    assert call["body"]["model"] == "my-model"
    assert call["body"]["messages"][-1] == {"role": "user", "content": "hello"}
    assert call["timeout"] == 12


def test_openai_without_key_sends_no_authorization():
    post = FakePost({"choices": [{"message": {"content": [{"type": "text", "text": "Verdict: benign"}]}}]})
    endpoint = ModelEndpoint(backend="openai", model="local")
    assert call_http_model(endpoint, "x", post=post) == "Verdict: benign"
    assert "Authorization" not in post.calls[0]["headers"]
    assert post.calls[0]["url"] == "https://api.openai.com/v1/chat/completions"


def test_anthropic_request_and_reply():
    post = FakePost({"content": [{"type": "text", "text": "Verdict: uncertain"}]})
    endpoint = ModelEndpoint(backend="anthropic", model="a-model", api_key="secret", max_output_tokens=1000)
    assert call_http_model(endpoint, "x", post=post) == "Verdict: uncertain"
    call = post.calls[0]
    assert call["url"] == "https://api.anthropic.com/v1/messages"
    assert call["headers"]["x-api-key"] == "secret"
    assert call["headers"]["anthropic-version"]
    assert call["body"]["max_tokens"] == 1000


def test_empty_reply_and_missing_model_fail():
    with pytest.raises(ModelCallError):
        call_http_model(ModelEndpoint(backend="openai", model=""), "x", post=FakePost({}))
    with pytest.raises(ModelCallError):
        call_http_model(
            ModelEndpoint(backend="openai", model="m"),
            "x",
            post=FakePost({"choices": [{"message": {"content": ""}}]}),
        )


def test_diff_is_appended_and_cut_to_the_prompt_limit():
    prompt, cut = prompt_with_diff("P", "line\n" * 10, file_name="filtered-diff.txt", max_chars=10_000)
    assert not cut
    assert "<filtered-diff.txt>" in prompt and prompt.startswith("P")
    prompt, cut = prompt_with_diff("P", "x" * 50_000, file_name="filtered-diff.txt", max_chars=10_000)
    assert cut
    assert DIFF_TRUNCATION_NOTE in prompt
    assert len(prompt) <= 10_000 + 200


def test_triage_and_analyst_use_http_backend(monkeypatch):
    seen = []

    def fake_call(endpoint, prompt):
        seen.append((endpoint.backend, endpoint.model, endpoint.base_url, endpoint.api_key, prompt))
        return "Verdict: malicious"

    monkeypatch.setattr("hunter.investigate.call_http_model", fake_call)
    evidence = build_evidence(_row(), "excerpt", full_diff="diff body " * 10)
    config = Config(
        smart_backend="openai",
        smart_model="triage-model",
        smart_base_url="http://triage.local/v1",
        smart_api_key="tk",
        analyst_model="analyst-model",
        analyst_backend="anthropic",
        analyst_api_key="ak",
    )
    assert run_smart_analysis(evidence, config=config) == ("Verdict: malicious", "triage-model")
    assert run_analyst_analysis(evidence, config=config) == ("Verdict: malicious", "analyst-model")
    assert seen[0][:4] == ("openai", "triage-model", "http://triage.local/v1", "tk")
    assert seen[1][:4] == ("anthropic", "analyst-model", "", "ak")
    assert "diff body" in seen[0][4]
    assert "You are Triage" in seen[0][4]
    assert "You are Analyst" in seen[1][4]


def test_analyst_follows_triage_backend_when_unset():
    config = Config(smart_backend="openai", smart_base_url="http://x/v1", smart_api_key="k", analyst_model="m")
    point = analyst_endpoint(config)
    assert (point.backend, point.base_url, point.api_key, point.model) == ("openai", "http://x/v1", "k", "m")
    assert triage_endpoint(config).backend == "openai"


def test_cut_diff_marks_the_evidence(monkeypatch):
    monkeypatch.setattr("hunter.investigate.call_http_model", lambda endpoint, prompt: "Verdict: benign")
    evidence = build_evidence(_row(), "excerpt", full_diff="y" * 30_000)
    evidence["signals"] = [s for s in evidence["signals"] if s != "triage_diff_cut"]
    config = Config(smart_backend="openai", smart_model="m", model_max_prompt_chars=10_000)
    run_smart_analysis(evidence, config=config)
    assert "triage_diff_cut" in evidence["signals"]


def test_http_backend_needs_only_a_model(monkeypatch):
    monkeypatch.delenv("CURSOR_API_KEY", raising=False)
    assert smart_analysis_enabled(Config(smart_backend="openai", smart_model="m"))
    assert not smart_analysis_enabled(Config(smart_backend="openai", smart_model=""))


def test_config_from_env_reads_backends(monkeypatch):
    monkeypatch.setenv("HUNTER_SMART_BACKEND", "openai")
    monkeypatch.delenv("HUNTER_SMART_MODEL", raising=False)
    monkeypatch.setenv("HUNTER_SMART_BASE_URL", "http://localhost:8000/v1")
    monkeypatch.setenv("HUNTER_ANALYST_BACKEND", "anthropic")
    config = Config.from_env()
    assert config.smart_backend == "openai"
    assert config.smart_model == ""
    assert config.smart_base_url == "http://localhost:8000/v1"
    assert config.analyst_backend == "anthropic"
    monkeypatch.setenv("HUNTER_SMART_BACKEND", "nope")
    with pytest.raises(ValueError):
        Config.from_env()


def test_cursor_backend_keeps_its_default_model(monkeypatch):
    monkeypatch.delenv("HUNTER_SMART_BACKEND", raising=False)
    monkeypatch.delenv("HUNTER_SMART_MODEL", raising=False)
    assert Config.from_env().smart_model == "composer-2.5"


def test_api_keys_are_not_in_config_repr():
    config = Config(smart_api_key="sk-secret", analyst_api_key="ak-secret")
    assert "sk-secret" not in repr(config)
    assert "ak-secret" not in repr(config)


def test_webhook_headers_parse_and_reject_bad_values():
    assert webhook_headers_from_env("") == {}
    assert webhook_headers_from_env('{"Authorization": "Bearer t"}') == {"Authorization": "Bearer t"}
    with pytest.raises(ValueError):
        webhook_headers_from_env("Authorization: Bearer t")
    with pytest.raises(ValueError):
        webhook_headers_from_env('{"X-Count": 3}')


def test_outbox_sends_extra_headers(tmp_path):
    db = Database(tmp_path / "h.sqlite3")
    assert db.enqueue("npm:a:1:analysis", json.dumps({"kind": "smart_analysis"}))
    sent = []
    assert (
        drain_outbox(
            db,
            url="https://alerts.example/hook",
            secret="s",
            poster=lambda url, body, headers: sent.append(headers),
            extra_headers={"Authorization": "Bearer t"},
        )
        == 1
    )
    assert sent[0]["Authorization"] == "Bearer t"
    assert sent[0]["X-Hunter-Signature"].startswith("sha256=")


def test_confirmed_verdict_without_webhook_is_logged_and_stored(tmp_path, caplog):
    db = Database(tmp_path / "h.sqlite3")
    evidence = build_evidence(_row())
    packet = dict(evidence, triage_report="Verdict: malicious", triage_verdict="malicious")
    assert db.enqueue_analyst(evidence["idempotency_key"], json.dumps(packet))
    config = Config(analyst_model="m", webhook_url="")
    with caplog.at_level("WARNING", logger="hunter.investigate"):
        assert drain_analyst(db, config=config, runner=lambda _p, _b: "Verdict: malicious") == 1
    assert "confirmed malicious: npm/leftpad 2" in caplog.text
    assert "no ALERT_WEBHOOK_URL" in caplog.text
    assert db.outbox_depth() == 0
