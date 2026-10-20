"""Luna decision model (GPT-6 Luna Decisions on OpenRouter). Synthetic inputs only; no network."""

import json

import pytest

from hunter.classify import classify_files
from hunter.config import Config, active_role_models
from hunter.head import load_head
from hunter.jev import STATE_TOKEN_BUDGET
from hunter.luna import DEFAULT_LUNA_MODEL, LunaClient, reported_cost, resolve_luna_model
from hunter.models import ReleaseMeta
from hunter.questions import pass_b_questions, pass_c_questions
from hunter.scout_model import (
    ScoutModelUnavailable,
    head_name,
    head_name_for,
    make_scout_model,
    require_scoring_layer,
    scout_backup_from_env,
    scout_model_from_env,
    state_token_budget,
)
from hunter.spend import DEFAULT_USD_PER_M_INPUT


def _answer(questions: dict, value: float = 0.1, tokens: int = 200) -> bytes:
    answers = {}
    for key, question in questions.items():
        kind = question.get("type")
        if kind == "noul":
            answers[key] = {"type": "noul", "noul": value}
        elif kind == "choice":
            options = list(question.get("criteria") or {"none": ""})
            answers[key] = {
                "type": "choice",
                "choice": options[0],
                "probabilities": {name: (1.0 if name == options[0] else 0.0) for name in options},
                "confidence": 0.9,
            }
        elif kind == "score":
            answers[key] = {"type": "score", "score": 0.0, "probabilities": {"0": 1.0}, "confidence": 0.9, "legend": {}}
    return json.dumps(
        {
            "model": "openai/gpt-6-luna-decisions-20261006",
            "answers": answers,
            "usage": {"input_tokens": tokens, "output_tokens": 0, "cost": tokens / 1e7},
            "provider": "OpenAI",
        }
    ).encode()


class FakeTransport:
    def __init__(self, replies=None, value: float = 0.1):
        self.replies = list(replies or [])
        self.value = value
        self.calls = []

    def __call__(self, url, headers, body, timeout):
        payload = json.loads(body)
        self.calls.append({"url": url, "headers": headers, "payload": payload})
        if self.replies:
            reply = self.replies.pop(0)
            if reply is not None:
                return reply
        return 200, _answer(payload["questions"], self.value), {}


def _client(transport, **kwargs) -> LunaClient:
    return LunaClient(api_key="test-key", transport=transport, sleep=lambda _s: None, **kwargs)


def _meta() -> ReleaseMeta:
    return ReleaseMeta(
        ecosystem="npm",
        name="widget",
        new_version="1.0.1",
        old_version="1.0.0",
        rank=3,
        registry_url="https://example.test/widget",
    )


def test_luna_is_an_allowed_decision_model(monkeypatch):
    monkeypatch.setenv("HUNTER_SCOUT_MODEL", "luna")
    assert Config.from_env().scout_model == "luna"
    assert scout_model_from_env("openrouter-decisions") == "luna"
    assert scout_model_from_env(" LUNA ") == "luna"


def test_other_openrouter_ids_are_still_rejected():
    with pytest.raises(ValueError, match="HUNTER_SCOUT_MODEL"):
        scout_model_from_env("openai/gpt-6-luna")
    with pytest.raises(ValueError, match="HUNTER_SCOUT_MODEL"):
        scout_model_from_env("anthropic/some-chat-model")


def test_luna_can_be_the_backup():
    assert scout_backup_from_env("jev", "luna") == "luna"
    assert scout_backup_from_env("luna", "openrouter-decisions") == ""


def test_model_id_default_and_fast_refused(monkeypatch):
    monkeypatch.delenv("HUNTER_LUNA_MODEL", raising=False)
    assert resolve_luna_model() == DEFAULT_LUNA_MODEL
    with pytest.raises(ValueError, match="fast"):
        resolve_luna_model("openai/gpt-6-luna-decisions-fast")
    with pytest.raises(ValueError, match="decisions"):
        resolve_luna_model("openai/gpt-6-luna")


def test_factory_builds_luna_with_jevs_scoring_file(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    config = Config(scout_model="luna")
    client = make_scout_model(config)
    assert isinstance(client, LunaClient)
    assert head_name(client) == "jev"
    assert head_name_for(config) == "jev"
    require_scoring_layer(config)
    assert state_token_budget(client, 1) == STATE_TOKEN_BUDGET
    assert config.scout_model_id() == DEFAULT_LUNA_MODEL


def test_role_summary_marks_luna_as_openrouter():
    roles = active_role_models(Config(scout_model="luna"))
    assert roles["decision_model"]["openrouter"] is True
    assert roles["decision_model"]["model"] == DEFAULT_LUNA_MODEL
    assert active_role_models(Config())["decision_model"]["openrouter"] is False


def test_price_is_listed():
    assert DEFAULT_USD_PER_M_INPUT["luna"] == pytest.approx(0.10)


def test_request_shape_and_noul_parsing():
    transport = FakeTransport(value=0.97)
    client = _client(transport)
    questions = pass_b_questions()
    result = client.system_one({"package_name": "widget", "diff_excerpt": "x"}, questions)
    call = transport.calls[0]
    assert call["url"] == "https://openrouter.ai/api/alpha/decisions"
    assert call["headers"]["Authorization"] == "Bearer test-key"
    assert call["payload"]["model"] == DEFAULT_LUNA_MODEL
    assert call["payload"]["questions"] == questions
    assert set(result.nouls) == set(questions)
    assert result.nouls["network"].noul == pytest.approx(0.97)
    assert result.usage.input_tokens == 200
    assert client.last_cost_usd == pytest.approx(200 / 1e7)


def test_choice_and_score_answers_are_parsed():
    client = _client(FakeTransport())
    questions = pass_c_questions()
    result = client.system_one({"diff_excerpt": "x"}, questions)
    for key, question in questions.items():
        bucket = {"noul": result.nouls, "choice": result.choices, "score": result.scores}[question["type"]]
        assert key in bucket


def test_answers_are_cached():
    transport = FakeTransport()
    client = _client(transport)
    questions = pass_b_questions()
    client.system_one({"diff_excerpt": "same"}, questions)
    client.system_one({"diff_excerpt": "same"}, questions)
    assert len(transport.calls) == 1


def test_rate_limit_and_refusal_are_retried():
    replies = [
        (429, b'{"error":{"message":"slow down","code":429}}', {"Retry-After": "1"}),
        (502, b'{"error":{"message":"OpenAI refused to answer question \\"q\\"","code":502}}', {}),
    ]
    transport = FakeTransport(replies)
    waits = []
    client = LunaClient(api_key="k", transport=transport, sleep=waits.append)
    result = client.system_one({"diff_excerpt": "x"}, pass_b_questions())
    assert len(transport.calls) == 3
    assert result.nouls
    assert 1.0 in waits


def test_token_limit_splits_the_piece():
    over = (400, b'{"error":{"message":"Decision input exceeds the token limit.","code":400}}', {})
    transport = FakeTransport([over])
    client = _client(transport)
    excerpt = "\n".join(f"--- file{i}.js\n+ line {i} " + "y" * 300 for i in range(6))
    result = client.system_one({"diff_excerpt": excerpt}, pass_b_questions())
    assert len(transport.calls) == 3
    sent = [call["payload"]["state"]["diff_excerpt"] for call in transport.calls[1:]]
    assert all(len(piece) < len(excerpt) for piece in sent)
    assert result.nouls


def test_auth_failure_stops_the_client():
    transport = FakeTransport([(401, b'{"error":{"message":"bad key","code":401}}', {})])
    client = _client(transport)
    with pytest.raises(ScoutModelUnavailable, match="401"):
        client.system_one({"diff_excerpt": "x"}, pass_b_questions())
    with pytest.raises(ScoutModelUnavailable):
        client.system_one({"diff_excerpt": "other"}, pass_b_questions())
    assert len(transport.calls) == 1


def test_missing_key_is_not_retried():
    transport = FakeTransport()
    client = LunaClient(api_key="", transport=transport, sleep=lambda _s: None)
    with pytest.raises(ScoutModelUnavailable, match="OPENROUTER_API_KEY"):
        client.system_one({"diff_excerpt": "x"}, pass_b_questions())
    assert transport.calls == []


def test_missing_answer_is_an_error():
    def transport(url, headers, body, timeout):
        return 200, json.dumps({"answers": {}, "usage": {"input_tokens": 5}}).encode(), {}

    client = LunaClient(api_key="k", transport=transport, sleep=lambda _s: None, retries=1)
    with pytest.raises(ScoutModelUnavailable, match="missing answers"):
        client.system_one({"diff_excerpt": "x"}, pass_b_questions())


def test_meter_sees_luna_usage():
    seen = []

    class Meter:
        def before_call(self):
            pass

        def record(self, provider, model, usage, **_kw):
            seen.append((provider, usage.input_tokens))

    client = _client(FakeTransport())
    client.meter = Meter()
    client.system_one({"diff_excerpt": "x"}, pass_b_questions())
    assert seen == [("luna", 200)]


def test_reported_cost_tolerates_bad_bodies():
    assert reported_cost(b"not json") == 0.0
    assert reported_cost(b'{"usage":{"cost":0.002}}') == pytest.approx(0.002)


def test_classify_runs_end_to_end_on_luna():
    client = _client(FakeTransport(value=0.02))
    old = {"package.json": '{"name":"widget","version":"1.0.0"}', "index.js": "module.exports = 1;\n"}
    new = {"package.json": '{"name":"widget","version":"1.0.1"}', "index.js": "module.exports = 2;\n"}
    result = classify_files(meta=_meta(), old_files=old, new_files=new, jev=client, head=load_head("jev"))
    assert result.band == "benign"


def _refusal(key: str):
    body = json.dumps({"error": {"message": f'OpenAI refused to answer question "{key}"', "code": 502}}).encode()
    return 502, body, {}


def test_refused_question_is_asked_alone_then_counted_as_yes():
    transport = FakeTransport([_refusal("network"), None, _refusal("network")], value=0.05)
    client = _client(transport)
    questions = pass_b_questions()
    result = client.system_one({"diff_excerpt": "x"}, questions)
    assert set(result.nouls) == set(questions)
    assert result.nouls["network"].noul == pytest.approx(1.0)
    assert result.nouls["shell_child_process"].noul == pytest.approx(0.05)
    assert client.refusals == ["network"]
    sent = [set(call["payload"]["questions"]) for call in transport.calls]
    assert sent[1] == set(questions) - {"network"}
    assert sent[2] == {"network"}


def test_refusal_that_clears_on_the_second_ask_keeps_the_answer():
    transport = FakeTransport([_refusal("network")], value=0.2)
    client = _client(transport)
    result = client.system_one({"diff_excerpt": "x"}, pass_b_questions())
    assert result.nouls["network"].noul == pytest.approx(0.2)
    assert client.refusals == []


def test_refusal_value_is_configurable(monkeypatch):
    monkeypatch.setenv("HUNTER_LUNA_REFUSAL_NOUL", "0.5")
    transport = FakeTransport([_refusal("network"), None, _refusal("network")])
    result = _client(transport).system_one({"diff_excerpt": "x"}, pass_b_questions())
    assert result.nouls["network"].noul == pytest.approx(0.5)
    monkeypatch.setenv("HUNTER_LUNA_REFUSAL_NOUL", "2")
    with pytest.raises(ValueError):
        _client(FakeTransport())


def test_refused_choice_question_is_an_error():
    questions = pass_c_questions()
    transport = FakeTransport([_refusal("attack_family"), None, _refusal("attack_family")])
    with pytest.raises(ScoutModelUnavailable, match="refused"):
        _client(transport).system_one({"diff_excerpt": "x"}, questions)
