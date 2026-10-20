"""Per-model context limits, chunk sizing, oversize routing, and Cloudflare pinning. No network."""

from __future__ import annotations

import json
import logging

import pytest

from hunter.classify import CONTEXT_OVERFLOW_SIGNAL, ROUTED_SIGNAL_PREFIX, classify_files
from hunter.clef import CLEF_MODELS, TRUNCATION_MARGIN, ClefClient, resolve_clef_model
from hunter.fake_jev import KeywordJev
from hunter.head import load_head
from hunter.jev import JevUnavailable
from hunter.llm import ModelCallError, ModelEndpoint, call_http_model
from hunter.model_limits import (
    MODEL_CONTEXT_TOKENS,
    canonical_model,
    context_limit,
    input_limit,
    openrouter_provider,
    overflow_route,
    state_budget,
)
from hunter.models import ReleaseMeta
from hunter.questions import pass_b_questions
from hunter.scout_model import ContextOverflow
from hunter.spend import DEFAULT_USD_PER_M_INPUT, price_key, prices_from_env
from tests.test_clef import FakeClef, _client

OLD = {"index.js": "module.exports = 1;\n"}
NEW = {"index.js": "module.exports = 2;\nrequire('child_process').exec('echo hi');\n"}


def _meta() -> ReleaseMeta:
    return ReleaseMeta(ecosystem="npm", name="widget", old_version="1.0.0", new_version="1.0.1", rank=4)


def test_limits_are_the_published_windows():
    assert MODEL_CONTEXT_TOKENS == {
        "clef-flash": 24_576,
        "microsoft-decision-1": 32_768,
        "clef": 65_536,
        "clef-omni": 65_536,
        "jev": 64_000,
        "luna": 1_050_000,
    }


@pytest.mark.parametrize(
    "model,key",
    [
        ("@cf/cloudflare/clef-flash", "clef-flash"),
        ("cloudflare/clef-omni", "clef-omni"),
        ("cloudflare/clef", "clef"),
        ("microsoft/microsoft-decision-1", "microsoft-decision-1"),
        ("jev-1.13.0", "jev"),
        ("typesafe/jev-latest", "jev"),
        ("openai/gpt-6-luna-decisions", "luna"),
        ("something-else", None),
        (None, None),
    ],
)
def test_model_ids_map_to_a_limit(model, key):
    assert canonical_model(model) == key
    assert context_limit(model) == (MODEL_CONTEXT_TOKENS[key] if key else None)


def test_input_limit_keeps_room_for_the_answer():
    assert input_limit("clef-flash") == 24_576 - TRUNCATION_MARGIN
    assert input_limit("unknown") is None


def test_state_budget_counts_the_questions_and_never_grows():
    assert state_budget("clef-flash", 3_000, 12_000) == 12_000
    assert state_budget("clef-flash", 12_000, 12_000) == 24_576 - TRUNCATION_MARGIN - 12_000
    assert state_budget("clef", 3_000, 12_000) == 12_000
    assert state_budget("unknown", 3_000, 12_000) == 12_000
    assert state_budget("clef-flash", 999_999, 12_000) == 1


def test_clients_take_their_own_context_window():
    assert ClefClient(model="clef-flash", api_token="t", account_id="a", base_url="").context_tokens == 24_576
    assert ClefClient(model="clef-omni", api_token="t", account_id="a", base_url="").context_tokens == 65_536
    assert ClefClient(model="clef", api_token="t", account_id="a", base_url="").context_tokens == 65_536
    assert "clef-omni" in CLEF_MODELS
    assert resolve_clef_model("Clef-Omni") == "clef-omni"


def test_flash_refuses_a_call_over_its_window_instead_of_sending_it():
    fake = FakeClef()
    client = _client(fake, model="clef-flash")
    questions = pass_b_questions()
    # Fixed state fields alone are larger than the window, so splitting the excerpt cannot help.
    state = {"diff_excerpt": "x", "file_paths": ["dir/file%d.js" % i for i in range(9_000)]}
    with pytest.raises(ContextOverflow) as caught:
        client.system_one(state, questions)
    assert fake.requests == []
    assert caught.value.limit_tokens == 24_576 - TRUNCATION_MARGIN
    assert caught.value.needed_tokens > caught.value.limit_tokens
    assert "context_overflow" in str(caught.value)


def test_the_same_state_is_sent_to_a_larger_window():
    fake = FakeClef()
    client = _client(fake, model="clef-omni", state_tokens=60_000)
    state = {"diff_excerpt": "x", "file_paths": ["dir/file%d.js" % i for i in range(4_000)]}
    flash = _client(FakeClef(), model="clef-flash")
    with pytest.raises(ContextOverflow):
        flash.system_one(state, pass_b_questions())
    # Omni's window holds it; the call is made, not refused for size.
    client.system_one(state, pass_b_questions())
    assert len(fake.requests) == 1


def test_flash_chunks_leave_room_for_the_questions():
    fake = FakeClef()
    client = _client(fake, model="clef-flash", state_tokens=100_000)
    state = {"diff_excerpt": "\n".join(f"+line {i} of the change" for i in range(6_000))}
    client.system_one(state, pass_b_questions())
    assert len(fake.requests) > 1
    for request in fake.requests:
        assert request["body"]["state"]
    from hunter.clef_tokens import state_tokens

    room = client.input_limit - client.question_tokens(pass_b_questions())
    assert all(state_tokens(r["body"]["state"]) <= room for r in fake.requests)


class _OverflowClef:
    """Stands in for a Flash client whose call never fits."""

    model = "clef-flash"
    head_name = "jev"
    fallback_model_id = "clef-flash"
    state_token_budget = 1_900

    def __init__(self, routes=None):
        self.overflow_routes = routes or {}
        self.calls = 0

    def system_one(self, state, questions):
        self.calls += 1
        raise ContextOverflow("clef-flash", 40_000, 22_528)


class _RouteJev(KeywordJev):
    model = "jev-1.13.0"


def _classify(client):
    return classify_files(meta=_meta(), old_files=OLD, new_files=NEW, jev=client, head=load_head())


def test_overflow_routes_to_a_larger_model_and_says_so(caplog):
    target = _RouteJev()
    flash = _OverflowClef({"jev": target})
    with caplog.at_level(logging.WARNING, logger="hunter.classify"):
        row = _classify(flash)
    assert target.calls
    assert f"{ROUTED_SIGNAL_PREFIX}jev" in row.signals
    assert row.band != "deferred"
    assert any("routing it to jev" in record.getMessage() for record in caplog.records)


def test_overflow_with_no_route_is_an_explicit_unread_review():
    row = _classify(_OverflowClef())
    assert row.band == "review"
    assert row.needs_llm_review is True
    assert CONTEXT_OVERFLOW_SIGNAL in row.signals
    assert "jev_unreadable" in row.signals


def test_a_failed_route_keeps_the_overflow_review():
    class Down:
        model = "jev-1.13.0"
        head_name = "jev"
        backup = None

        def system_one(self, state, questions):
            raise JevUnavailable("503 down")

    row = _classify(_OverflowClef({"jev": Down()}))
    assert CONTEXT_OVERFLOW_SIGNAL in row.signals
    assert f"{ROUTED_SIGNAL_PREFIX}jev:failed" in row.signals
    assert row.band == "review"


def test_route_order_prefers_omni_and_skips_what_does_not_fit():
    routes = {"clef-omni": "omni", "jev": "jev"}
    assert overflow_route(30_000, routes, exclude="clef-flash") == ("clef-omni", "omni")
    assert overflow_route(30_000, {"jev": "jev"}, exclude="clef-flash") == ("jev", "jev")
    assert overflow_route(70_000, routes, exclude="clef-flash") is None
    assert overflow_route(30_000, routes, exclude="clef-omni") == ("jev", "jev")


def test_clef_models_through_openrouter_are_pinned_to_cloudflare():
    for model in ("cloudflare/clef-flash", "cloudflare/clef", "cloudflare/clef-omni"):
        preferences = openrouter_provider(model)
        assert preferences["order"] == ["cloudflare"]
        assert preferences["allow_fallbacks"] is False
    assert openrouter_provider("microsoft/microsoft-decision-1") is None


def _post_reply(provider=None):
    sent = []

    def post(url, body, headers, timeout):
        sent.append(body)
        reply = {"choices": [{"message": {"content": "ok"}}]}
        if provider:
            reply["provider"] = provider
        return reply

    post.sent = sent
    return post


def test_openrouter_chat_call_carries_the_pin_and_replaces_a_loose_one():
    post = _post_reply("Cloudflare")
    endpoint = ModelEndpoint(backend="openrouter", model="cloudflare/clef-flash", api_key="test-key")
    assert call_http_model(endpoint, "hi", post=post) == "ok"
    provider = post.sent[0]["provider"]
    assert provider["order"] == ["cloudflare"]
    assert provider["allow_fallbacks"] is False
    from hunter.openrouter import pin_provider

    body = {"model": "cloudflare/clef", "provider": {"allow_fallbacks": True, "order": ["primeintellect"]}}
    pin_provider(body)
    assert body["provider"]["order"] == ["cloudflare"] and body["provider"]["allow_fallbacks"] is False


def test_other_openrouter_models_get_no_provider_setting():
    post = _post_reply()
    endpoint = ModelEndpoint(backend="openrouter", model="microsoft/microsoft-decision-1", api_key="test-key")
    call_http_model(endpoint, "hi", post=post)
    assert "provider" not in post.sent[0]


def test_an_answer_from_another_provider_is_refused():
    post = _post_reply("PrimeIntellect")
    endpoint = ModelEndpoint(backend="openrouter", model="cloudflare/clef-flash", api_key="test-key")
    with pytest.raises(ModelCallError, match="pinned provider"):
        call_http_model(endpoint, "hi", post=post)


def test_price_table_has_the_new_rates(monkeypatch):
    assert DEFAULT_USD_PER_M_INPUT["clef-flash"] == 0.038
    assert DEFAULT_USD_PER_M_INPUT["clef-omni"] == 0.15
    assert DEFAULT_USD_PER_M_INPUT["microsoft-decision-1"] == 0.042
    assert price_key("clef", "@cf/cloudflare/clef-omni") == "clef-omni"
    assert price_key("clef", "clef-flash") == "clef-flash"
    assert price_key("openrouter", "microsoft/microsoft-decision-1") == "microsoft-decision-1"
    assert price_key("clef", "clef") == "clef"
    monkeypatch.setenv("HUNTER_CLEF_OMNI_USD_PER_M_INPUT", "0.2")
    assert prices_from_env()["clef-omni"] == 0.2
