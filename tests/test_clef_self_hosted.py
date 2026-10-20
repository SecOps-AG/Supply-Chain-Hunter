"""Clef against a self-hosted System One server. Synthetic inputs only; no network."""

import json

import pytest

from hunter.clef import SELF_HOSTED_CONTEXT_TOKENS, SELF_HOSTED_STATE_TOKENS, ClefClient
from hunter.questions import pass_b_questions
from hunter.scout_model import ScoutModelUnavailable
from tests.test_clef import FakeClef, answers_for


def _bare(payload: dict, input_tokens: int = 500) -> tuple[int, bytes]:
    body = {
        "model": payload["model"],
        "answers": answers_for(payload["questions"], 0.2),
        "usage": {"input_tokens": input_tokens, "output_tokens": 0},
    }
    return 200, json.dumps(body).encode()


def _client(fake, **kwargs) -> ClefClient:
    options = {"base_url": "http://clef.internal:8000/", "retries": 1, "max_rpm": 100_000}
    options.update(kwargs)
    return ClefClient(transport=fake, sleep=lambda _delay: None, **options)


def test_requests_go_to_the_system_one_path(monkeypatch):
    monkeypatch.delenv("CLOUDFLARE_ACCOUNT_ID", raising=False)
    fake = FakeClef(lambda payload, _count: _bare(payload))
    result = _client(fake).system_one({"diff_excerpt": "x"}, pass_b_questions())
    assert fake.requests[0]["url"] == "http://clef.internal:8000/v1/systemone"
    assert fake.requests[0]["body"]["model"] == "clef"
    assert result.nouls["network"].noul == 0.2


def test_no_token_means_no_authorization_header(monkeypatch):
    monkeypatch.delenv("HUNTER_CLEF_API_TOKEN", raising=False)
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "cloudflare-secret")
    fake = FakeClef(lambda payload, _count: _bare(payload))
    client = ClefClient(base_url="http://clef.internal:8000", transport=fake, retries=1, max_rpm=100_000)
    client.system_one({"diff_excerpt": "x"}, pass_b_questions())
    assert "Authorization" not in fake.requests[0]["headers"]
    assert client.api_token == ""


def test_self_hosted_token_is_sent(monkeypatch):
    monkeypatch.setenv("HUNTER_CLEF_API_TOKEN", "server-token")
    fake = FakeClef(lambda payload, _count: _bare(payload))
    ClefClient(base_url="http://clef.internal:8000", transport=fake, retries=1, max_rpm=100_000).system_one(
        {"diff_excerpt": "x"}, pass_b_questions()
    )
    assert fake.requests[0]["headers"]["Authorization"] == "Bearer server-token"


def test_base_url_setting(monkeypatch):
    monkeypatch.setenv("HUNTER_CLEF_BASE_URL", "https://clef.example.test")
    monkeypatch.delenv("HUNTER_CLEF_CONTEXT_TOKENS", raising=False)
    monkeypatch.delenv("HUNTER_CLEF_STATE_TOKENS", raising=False)
    client = ClefClient()
    assert client.self_hosted
    assert client.url() == "https://clef.example.test/v1/systemone"
    assert client.context_tokens == SELF_HOSTED_CONTEXT_TOKENS
    assert client.state_token_budget == SELF_HOSTED_STATE_TOKENS


def test_sizes_can_be_set_to_match_the_server(monkeypatch):
    monkeypatch.setenv("HUNTER_CLEF_BASE_URL", "https://clef.example.test")
    monkeypatch.setenv("HUNTER_CLEF_CONTEXT_TOKENS", "32768")
    monkeypatch.setenv("HUNTER_CLEF_STATE_TOKENS", "24000")
    client = ClefClient()
    assert client.context_tokens == 32_768
    assert client.state_token_budget == 24_000


def test_truncation_guard_uses_the_self_hosted_context():
    fake = FakeClef(lambda payload, _count: _bare(payload, input_tokens=SELF_HOSTED_CONTEXT_TOKENS - 100))
    with pytest.raises(ScoutModelUnavailable, match="max_tokens"):
        _client(fake).system_one({"diff_excerpt": "x" * 100}, {"network": pass_b_questions()["network"]})


def test_self_hosted_does_not_split_on_the_hosted_token_budget():
    fake = FakeClef(lambda payload, _count: _bare(payload, input_tokens=4_000))
    excerpt = "function step(n) { return n + 1; }\n" * 400
    assert len(excerpt) > 6_000
    client = _client(fake)
    assert client.splits_full_excerpt is False
    assert client.state_token_budget == SELF_HOSTED_STATE_TOKENS
    client.system_one({"diff_excerpt": excerpt}, {"network": pass_b_questions()["network"]})
    assert len(fake.requests) == 1
    assert fake.requests[0]["body"]["state"]["diff_excerpt"] == excerpt


def test_server_error_is_unavailable():
    fake = FakeClef(lambda _payload, _count: (500, b"internal error"))
    with pytest.raises(ScoutModelUnavailable, match="500"):
        _client(fake).system_one({"diff_excerpt": "x"}, pass_b_questions())
