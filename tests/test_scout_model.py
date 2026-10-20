"""The Scout model setting and the shared answer shape. Synthetic inputs only; no network."""

import json
from types import SimpleNamespace

import pytest

from hunter.classify import classify_files
from hunter.config import Config
from hunter.head import head_available, head_file, load_head
from hunter.jev import STATE_TOKEN_BUDGET, JevClient, JevResult, JevUnavailable, NoulView, merge_answers, pack_chunks
from hunter.models import ReleaseMeta
from hunter.scout_model import (
    ScoutAnswer,
    ScoutModelUnavailable,
    Usage,
    head_name,
    make_scout_model,
    scout_model_from_env,
    state_token_budget,
    usage_from,
)
from hunter.service import health_payload
from hunter.triage import diff_trees
from hunter.fake_jev import KeywordJev


def _meta() -> ReleaseMeta:
    return ReleaseMeta(
        ecosystem="npm",
        name="widget",
        new_version="1.0.1",
        old_version="1.0.0",
        rank=3,
        registry_url="https://example.test/widget",
    )


def test_jev_is_the_default(monkeypatch):
    monkeypatch.delenv("HUNTER_SCOUT_MODEL", raising=False)
    assert scout_model_from_env() == "jev"
    assert Config.from_env().scout_model == "jev"


def test_setting_is_case_and_space_tolerant(monkeypatch):
    monkeypatch.setenv("HUNTER_SCOUT_MODEL", "  JEV ")
    assert Config.from_env().scout_model == "jev"


def test_unknown_model_stops_startup(monkeypatch):
    monkeypatch.setenv("HUNTER_SCOUT_MODEL", "something-else")
    with pytest.raises(ValueError, match="HUNTER_SCOUT_MODEL"):
        Config.from_env()


def test_factory_builds_jev(monkeypatch):
    monkeypatch.delenv("HUNTER_SCOUT_MODEL", raising=False)
    client = make_scout_model(Config())
    assert isinstance(client, JevClient)
    assert head_name(client) == "jev"
    assert state_token_budget(client, 1) == STATE_TOKEN_BUDGET


def test_jev_names_are_the_shared_types():
    assert JevResult is ScoutAnswer
    assert JevUnavailable is ScoutModelUnavailable


def test_usage_reads_sdk_objects_and_dicts():
    assert usage_from(SimpleNamespace(input_tokens=12, output_tokens=3)) == Usage(12, 3)
    assert usage_from({"input_tokens": "7"}) == Usage(7, 0)
    assert usage_from(None) == Usage()
    assert usage_from({"input_tokens": "lots"}) == Usage()


def test_jev_answer_carries_reported_usage():
    from hunter.jev import _normalize

    raw = SimpleNamespace(
        model="jev-1.13.0",
        nouls={"network": SimpleNamespace(noul=0.4)},
        choices={},
        scores={},
        usage=SimpleNamespace(input_tokens=900, output_tokens=5),
    )
    result = _normalize(raw, "jev-1.13.0")
    assert result.usage == Usage(900, 5)
    assert result.nouls["network"].noul == 0.4


def test_split_pieces_add_their_usage_and_keep_the_highest_noul():
    left = JevResult(model="m", nouls={"network": NoulView(0.2)}, usage=Usage(100, 1))
    right = JevResult(model="m", nouls={"network": NoulView(0.7)}, usage=Usage(50, 2))
    merged = merge_answers([left, right])
    assert merged.usage == Usage(150, 3)
    assert merged.nouls["network"].noul == 0.7


def test_jev_head_file_is_unchanged():
    assert head_file("jev") == "logistic_head.json"
    assert head_available("jev")
    assert load_head("jev").coefficients == load_head().coefficients


def test_missing_head_file_is_an_error():
    assert not head_available("no-such-model")
    with pytest.raises(FileNotFoundError, match="no-such-model"):
        load_head("no-such-model")


def test_chunk_budget_comes_from_the_model():
    body = "\n".join(f"const value{index} = fetch('https://example.test/{index}');" for index in range(60))
    diffs = diff_trees({}, {f"lib/part{number}.js": body for number in range(6)})
    default_chunks = pack_chunks(diffs, _meta())
    small_chunks = pack_chunks(diffs, _meta(), budget=3_000)
    assert len(small_chunks) > len(default_chunks)


class SmallBudget(KeywordJev):
    state_token_budget = 3_000


def test_classify_packs_with_the_model_budget():
    body = "\n".join(f"require('child_process').execSync('echo {index}');" for index in range(60))
    old = {"package.json": json.dumps({"name": "widget", "version": "1.0.0"})}
    new = {"package.json": json.dumps({"name": "widget", "version": "1.0.1"})}
    new.update({f"lib/part{number}.js": body for number in range(6)})
    default_model = KeywordJev()
    small_model = SmallBudget()
    classify_files(meta=_meta(), old_files=old, new_files=new, jev=default_model)
    classify_files(meta=_meta(), old_files=old, new_files=new, jev=small_model)
    assert len(small_model.calls) > len(default_model.calls)


def test_health_reports_the_scout_model(tmp_path):
    from hunter.db import Database

    db = Database(tmp_path / "h.sqlite3")
    try:
        body = health_payload(db, 0.0, "jev-1.13.0", Config())
    finally:
        db.close()
    assert body["scout_model"] == "jev"
    assert body["jev_model_id"] == "jev-1.13.0"
