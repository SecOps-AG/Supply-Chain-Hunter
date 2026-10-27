import json
from pathlib import Path

import pytest

from hunter.classify import classify_files
from hunter.dashboard import _release_summary
from hunter.fake_jev import KeywordJev
from hunter.fixtures_io import iter_fixtures
from hunter.head import load_head
from hunter.models import Classification
from hunter.risk_score import MAX_SCORE, SIGNAL_WEIGHTS, WHY_LIMIT, risk_score
from hunter.webhook import build_payload

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _result(**extra) -> Classification:
    base = dict(
        ecosystem="npm",
        name="widget",
        old_version="1.0.0",
        new_version="1.0.1",
        rank=4,
        registry_url="https://example.test/widget",
        band="review",
        malice_probability=0.5,
        jev_model_id="jev-1.13.0",
    )
    base.update(extra)
    return Classification(**base)


def _hit(rule, tier="strong"):
    return {"rule": rule, "tier": tier, "path": "a.js", "line": 1, "matched_text": "x", "summary": ""}


@pytest.mark.parametrize(
    "signals, expected, first",
    [
        ([], 0, None),
        (["unknown_signal", "rule:foo"], 0, None),
        (["publisher_changed"], 8, "publisher_changed"),
        (["compound_install_payload"], 30, "compound_install_payload"),
        (["literal_shell", "literal_shell"], 10, "literal_shell"),
        (["new_dependency:left-pad"], 0, None),
        (["behavior_chain:a", "runtime_behavior_chain:b"], 20, "behavior_chain"),
        (["entrypoint_payload", "install_sidecar", "literal_decode_exec"], 65, "entrypoint_payload"),
        (["phantom_runtime_dependency:x,y"], 15, "phantom_runtime_dependency"),
    ],
)
def test_signal_table(signals, expected, first):
    score = risk_score(_result(signals=signals))
    assert score.score == expected
    assert (score.why[0].code if score.why else None) == first


def test_score_caps_at_100_and_why_is_top_three_in_order():
    signals = list(SIGNAL_WEIGHTS)
    score = risk_score(_result(signals=signals, rule_hits=[_hit("r1"), _hit("r2")]))
    assert score.score == MAX_SCORE
    assert len(score.why) == WHY_LIMIT
    points = [reason.points for reason in score.why]
    assert points == sorted(points, reverse=True)
    assert score.why[0].code == "compound_install_payload"


def test_ties_are_ordered_by_code():
    score = risk_score(_result(signals=["literal_xor", "literal_raw_ip", "literal_encoded_import"]))
    assert [r.code for r in score.why] == ["literal_encoded_import", "literal_raw_ip", "literal_xor"]


@pytest.mark.parametrize(
    "hits, expected",
    [
        ([], 0),
        ([_hit("a")], 25),
        ([_hit("a"), _hit("a")], 25),
        ([_hit("a", "weak")], 6),
        ([_hit("a"), _hit("b")], 45),
        ([_hit("a"), _hit("b"), _hit("c")], 45),
        ([_hit(f"w{i}", "weak") for i in range(30)], 45),
        (["bad", None, {"tier": "strong"}, {"rule": ""}], 0),
    ],
)
def test_rule_hits(hits, expected):
    assert risk_score(_result(rule_hits=hits)).score == expected


def test_rule_text_is_clamped_and_single_line():
    score = risk_score(_result(rule_hits=[_hit("x\n" + "y" * 500)]))
    reason = score.why[0]
    assert "\n" not in reason.text and len(reason.text) <= 120
    assert len(reason.code) <= 85


@pytest.mark.parametrize(
    "extra",
    [{"defer_reason": "download_failed"}, {"signals": ["download_failed", "literal_shell"]}, {"defer_reason": "spend"}],
)
def test_incomplete_reads_have_no_score(extra):
    score = risk_score(_result(**extra))
    assert score.score is None and score.why == ()


@pytest.mark.parametrize(
    "data, blast, expected",
    [(None, None, 0), (1.0, None, 10), (0.5, 0.2, 5), (None, 0.3, 3), (9.0, None, 10), (-1.0, None, 0)],
)
def test_exposure_term(data, blast, expected):
    assert risk_score(_result(data_collection_score=data, blast_radius_score=blast)).score == expected


def test_payload_carries_score_and_leaves_existing_keys():
    row = _result(signals=["literal_shell"], rule_hits=[_hit("r1")], rule_verdict="malicious")
    payload = build_payload(row)
    assert payload["risk_score"] == 35
    assert payload["risk_why"][0] == {"code": "rule:r1", "points": 25, "text": "Strong rule matched: r1"}
    assert payload["band"] == "review" and payload["malice_probability"] == 0.5
    assert payload["signals"] == ["literal_shell"]
    assert json.loads(json.dumps(payload))["risk_score"] == 35
    assert build_payload(_result(defer_reason="x"))["risk_score"] is None


@pytest.mark.parametrize(
    "payload, score, why_len",
    [
        ({}, None, 0),
        ({"risk_score": 40, "risk_why": [{"code": "a", "points": 25, "text": "t"}]}, 40, 1),
        ({"risk_score": "40", "risk_why": "nope"}, None, 0),
        ({"risk_score": True, "risk_why": [1, None, {"code": "a"}]}, None, 1),
        ({"risk_score": None, "risk_why": [{"code": "a"}] * 9}, None, 5),
    ],
)
def test_dashboard_summary_is_defensive(payload, score, why_len):
    row = {"ecosystem": "npm", "name": "w", "version": "1", "payload_json": json.dumps(payload)}
    summary = _release_summary(row)
    assert summary["risk_score"] == score
    assert len(summary["risk_why"]) == why_len


def test_known_bad_fixtures_score_above_clean():
    head = load_head()
    scores = {"malicious": [], "benign": []}
    for path, (meta, old_files, new_files, label) in iter_fixtures(FIXTURES):
        result = classify_files(meta=meta, old_files=old_files, new_files=new_files, jev=KeywordJev(), head=head)
        before = (result.band, result.malice_probability)
        scored = risk_score(result)
        assert (result.band, result.malice_probability) == before
        if label in scores:
            assert scored.score is not None, path.stem
            scores[label].append((scored.score, path.stem))
    assert scores["malicious"] and scores["benign"]
    assert min(scores["malicious"])[0] > max(scores["benign"])[0], scores
