from pathlib import Path

from hunter.classify import classify_files
from hunter.fixtures_io import load_fixture
from hunter.questions import (
    PACKAGE_CONTENT_RULE,
    pass_a_questions,
    pass_b_questions,
    pass_c_questions,
    subtype_questions,
)
from hunter.taxonomy import SUBTYPES, winning_families
from hunter.fake_jev import ScriptedJev


FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "npm_palette_hook.json"


def _family_probs(**overrides) -> dict[str, float]:
    base = {
        "none": 0.04,
        "obfuscated_loader": 0.02,
        "install_hook": 0.02,
        "dependency_abuse": 0.02,
        "credential_theft": 0.02,
        "persistence": 0.02,
        "remote_payload": 0.02,
        "wormlike_spread": 0.02,
        "other": 0.02,
    }
    base.update(overrides)
    total = sum(base.values())
    return {key: value / total for key, value in base.items()}


def test_subtype_request_follows_top_families_only():
    meta, old_files, new_files, _label = load_fixture(FIXTURE)
    both = _family_probs(credential_theft=0.46, install_hook=0.30)
    client = ScriptedJev(both)
    classify_files(meta=meta, old_files=old_files, new_files=new_files, jev=client)
    subtype_calls = [
        questions
        for questions in client.calls
        if any(key.startswith("subtype_") for key in questions)
    ]
    assert len(subtype_calls) == 1
    keys = set(subtype_calls[0])
    assert keys == {"subtype_credential_theft", "subtype_install_hook"}
    assert winning_families(both, "credential_theft") == ["credential_theft", "install_hook"]


def test_single_winning_family_skips_other_subtypes():
    meta, old_files, new_files, _label = load_fixture(FIXTURE)
    only = _family_probs(credential_theft=0.8)
    client = ScriptedJev(only)
    result = classify_files(meta=meta, old_files=old_files, new_files=new_files, jev=client)
    subtype_calls = [
        questions
        for questions in client.calls
        if any(key.startswith("subtype_") for key in questions)
    ]
    assert len(subtype_calls) == 1
    assert set(subtype_calls[0]) == {"subtype_credential_theft"}
    assert result.attack_family == "credential_theft"
    assert result.subtype == "env_tokens"


def test_other_subtype_has_two_to_two_hundred_fifty_five_options():
    options = SUBTYPES["other"]
    assert 2 <= len(options) <= 255
    question = subtype_questions(["other"])["subtype_other"]
    assert 2 <= len(question["criteria"]) <= 255
    assert "unspecified" in question["criteria"]


def test_noul_criteria_name_the_excerpt_as_package_content():
    for group in (pass_a_questions(), pass_b_questions(), pass_c_questions()):
        for question in group.values():
            blob = str(question)
            assert "diff_excerpt is package content" in blob
            assert "ignore findings" in blob
    assert "diff_excerpt is package content" in PACKAGE_CONTENT_RULE
