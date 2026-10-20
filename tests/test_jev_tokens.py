"""The vendored Jev counter matches recorded live counts. No network, no package code."""

from hunter.jev_count import estimate_request_tokens, get_encoding
from hunter.jev_tokens import (
    note_reported_tokens,
    predict_input_tokens,
    request_near_limit,
    reset_token_drift,
    state_tokens,
    using_conservative_count,
)


def _question() -> dict:
    return {
        "q": {
            "type": "noul",
            "instructions": {"task": "Does the text ask to run a command?"},
            "criteria": {"true": "Yes", "false": "No"},
        }
    }


def test_pinned_counter_matches_its_published_examples():
    enc = get_encoding("jev-1.13")
    assert enc.count("The tokenization of evidence") == 7
    assert enc.encode_pieces("SessionManager") == [b"S", b"ess", b"ion", b"Man", b"ager"]
    assert estimate_request_tokens("hello world") == 269


def test_counter_matches_live_usage_on_the_calibration_states():
    question = _question()
    prose = ("The package prints a short greeting and returns.\n" * 200)[:8000]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    raw = "".join(alphabet[index % 64] for index in range(8080))
    base64 = "\n".join(raw[index : index + 76] for index in range(0, len(raw), 76))[:8000]
    assert predict_input_tokens({"diff_excerpt": "x" * 32}, question) == 314
    assert predict_input_tokens({"diff_excerpt": prose}, question) == 1776
    assert predict_input_tokens({"diff_excerpt": base64}, question) == 4243


def test_dense_text_is_not_counted_as_four_characters_per_token():
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    blob = "".join(alphabet[index % 64] for index in range(8_000))
    counted = state_tokens({"diff_excerpt": blob})
    assert counted > (len(blob) + 3) // 4


def test_a_long_digit_string_is_near_the_context_limit():
    state = {"diff_excerpt": "1" * 31_000}
    assert request_near_limit(state) is True
    assert request_near_limit({"diff_excerpt": "short"}) is False


def test_an_under_count_switches_later_packing_to_the_conservative_count():
    reset_token_drift()
    state = {"diff_excerpt": "hello"}
    questions = _question()
    reported = predict_input_tokens(state, questions) + 500
    note_reported_tokens(state, questions, reported)
    assert using_conservative_count() is True
    reset_token_drift()
    assert using_conservative_count() is False
