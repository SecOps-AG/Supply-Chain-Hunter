"""Large-file packing must match the exact counter and must not recount the file.

Synthetic text only. These tests do not call Jev or a registry.
"""

import time
import unicodedata

from hunter.jev import STATE_TOKEN_BUDGET, _take_piece, build_state, pack_chunks
from hunter.jev_count import get_encoding
from hunter.jev_tokens import (
    BodyTokenIndex,
    note_reported_tokens,
    reset_token_drift,
    state_tokens,
    using_conservative_count,
)
from hunter.models import FileDiff, ReleaseMeta
from hunter.triage import render_excerpt


def _meta() -> ReleaseMeta:
    return ReleaseMeta(
        ecosystem="npm",
        name="widget",
        new_version="1.0.1",
        old_version="1.0.0",
        rank=3,
        registry_url="https://example.test/widget",
    )


def _source(chars: int, *, long_run: int = 0) -> str:
    lines = []
    size = 0
    index = 0
    while size < chars:
        if long_run and index % 40 == 0:
            piece = "A" * long_run + "\n"
        else:
            piece = f"const value{index} = add({index}, {index}+1);\n"
            if index % 3 == 0:
                piece += "    function add(a, b) { return a + b; }\n"
            if index % 17 == 0:
                piece += "\n"
            if index % 29 == 0:
                piece += "x = './path';\n"
            if index % 41 == 0:
                piece += "    \n"
            if index % 53 == 0:
                piece += "/* comment */\n"
        lines.append(piece)
        size += len(piece)
        index += 1
    return "".join(lines)[:chars]


def _item(text: str) -> FileDiff:
    return FileDiff(
        path="lib/payload.js",
        category="suspicious_source",
        diff_text=text,
        added_text=text,
        old_text="",
        new_text=text,
    )


def _reference_states(meta, excerpt, paths, budget, changed_files):
    header, sep, body = excerpt.partition("\n")
    if not sep or not body:
        return [
            build_state(
                meta,
                excerpt,
                slice_name="combined",
                file_paths=paths,
                changed_files=changed_files,
            )
        ]
    states = []
    rest = body
    while rest:
        piece, rest = _take_piece(
            meta, paths, header, rest, budget, changed_files=changed_files
        )
        if not piece:
            piece, rest = rest[:1], rest[1:]
        states.append(
            build_state(
                meta,
                header + "\n" + piece,
                slice_name="combined",
                file_paths=paths,
                changed_files=changed_files,
            )
        )
    return states


def test_indexed_counts_match_the_exact_counter():
    get_encoding()
    body = _source(12_000, long_run=300)
    body += "\r\nline\n\n  \nfunction add(a, b) { return a+b; }\n"
    body += "café\n\u00a0nbsp\n\u3000ideographic\n"
    index = BodyTokenIndex(body)
    header = "--- suspicious_source:lib/payload.js\n"
    enc = get_encoding()
    starts = [0, 1, 5, 24, 100, len(body) // 2, len(body) - 3]
    for offset, char in enumerate(body):
        if char == "\n" and len(starts) < 40:
            starts.append(offset + 1)
    lengths = (0, 1, 2, 3, 8, 40, 200, 1500)
    for start in starts:
        for length in lengths:
            end = min(len(body), start + length)
            assert index.count_with_header(header, start, end) == enc.count(header + body[start:end])


def test_large_chunks_match_the_recounting_packer():
    meta = _meta()
    text = _source(180_000)
    item = _item(text)
    fast = pack_chunks([item], meta)
    excerpt = render_excerpt([item])
    slow = _reference_states(meta, excerpt, [item.path], STATE_TOKEN_BUDGET, None)
    assert len(fast) > 1
    assert fast == slow
    covered = []
    header = excerpt.split("\n", 1)[0]
    for state in fast:
        assert state_tokens(state) <= STATE_TOKEN_BUDGET
        body = state["diff_excerpt"][len(header) + 1 :]
        covered.append(body)
    assert "".join(covered) == excerpt.split("\n", 1)[1]


def test_mid_token_cuts_match_the_recounting_packer():
    meta = _meta()
    # The run is longer than the body budget left after the state overhead
    # (about 120 tokens), so the cut falls inside the run.
    text = _source(5_000, long_run=2_000)
    item = _item(text)
    budget = 400
    changed = "lib/payload.js\nlib/other.js"
    fast = pack_chunks([item], meta, budget=budget, changed_files=changed)
    excerpt = render_excerpt([item])
    slow = _reference_states(meta, excerpt, [item.path], budget, changed)
    assert fast == slow
    assert len(fast) > 1
    bodies = [state["diff_excerpt"].split("\n", 1)[1] for state in fast]
    assert not any("A" * 2_000 in body for body in bodies)
    assert any(body.startswith("A") for body in bodies[1:])


def test_non_nfc_text_is_packed_as_nfc_and_matches_the_recounting_packer():
    # Jev NFC-normalizes before tokenizing, so packing indexes the NFC text.
    meta = _meta()
    text = ("const e\u0301 = 1;\n" * 400)
    item = _item(text)
    fast = pack_chunks([item], meta, budget=300)
    excerpt = unicodedata.normalize("NFC", render_excerpt([item]))
    slow = _reference_states(meta, excerpt, [item.path], 300, None)
    assert fast == slow
    assert len(fast) > 1
    for state in fast:
        assert state_tokens(state) <= 300


def test_large_non_nfc_file_uses_the_index():
    get_encoding()
    meta = _meta()
    text = ("const e\u0301 = 1;\n" + _source(400)) * 5_000
    item = _item(text)
    started = time.perf_counter()
    chunks = pack_chunks([item], meta)
    elapsed = time.perf_counter() - started
    # About 2 MB. Recounting each probe took minutes at this size.
    assert elapsed < 20, f"packing took {elapsed:.1f}s"
    assert len(chunks) > 10
    excerpt = unicodedata.normalize("NFC", render_excerpt([item]))
    header, body = excerpt.split("\n", 1)
    covered = []
    for state in chunks:
        assert state_tokens(state) <= STATE_TOKEN_BUDGET
        assert state["diff_excerpt"].startswith(header + "\n")
        covered.append(state["diff_excerpt"][len(header) + 1 :])
    assert "".join(covered) == body


def test_conservative_count_still_matches_the_recounting_packer():
    meta = _meta()
    reset_token_drift()
    try:
        note_reported_tokens({"diff_excerpt": "hi"}, {"q": {"type": "noul", "instructions": "x"}}, 8_000)
        assert using_conservative_count()
        text = _source(8_000)
        item = _item(text)
        fast = pack_chunks([item], meta, budget=400)
        excerpt = render_excerpt([item])
        slow = _reference_states(meta, excerpt, [item.path], 400, None)
        assert fast == slow
        assert len(fast) > 1
    finally:
        reset_token_drift()


def test_two_megabytes_packs_without_the_quadratic_scan():
    get_encoding()
    meta = _meta()
    text = _source(2_000_000)
    item = _item(text)
    started = time.perf_counter()
    chunks = pack_chunks([item], meta)
    elapsed = time.perf_counter() - started
    # Recounting this size takes over a minute. One pretokenization stays
    # under this line even on a slow runner.
    assert elapsed < 20, f"packing took {elapsed:.1f}s"
    assert len(chunks) > 10
    excerpt = render_excerpt([item])
    header, body = excerpt.split("\n", 1)
    covered = []
    for state in chunks:
        assert state_tokens(state) <= STATE_TOKEN_BUDGET
        assert state["diff_excerpt"].startswith(header + "\n")
        covered.append(state["diff_excerpt"][len(header) + 1 :])
    assert "".join(covered) == body



def _fallback_body_check(chunks, item):
    excerpt = unicodedata.normalize("NFC", render_excerpt([item]))
    header, body = excerpt.split("\n", 1)
    covered = []
    for state in chunks:
        assert state_tokens(state) <= STATE_TOKEN_BUDGET
        assert state["diff_excerpt"].startswith(header + "\n")
        covered.append(state["diff_excerpt"][len(header) + 1 :])
    assert "".join(covered) == body


def _pack_counting(monkeypatch, item, meta):
    """Pack and return the chunks plus how many excerpt characters were counted."""
    import hunter.jev as jev

    counted = [0]
    real = jev._state_fits

    def spy(state, budget):
        counted[0] += len(state.get("diff_excerpt", ""))
        return real(state, budget)

    monkeypatch.setattr(jev, "_state_fits", spy)
    chunks = pack_chunks([item], meta)
    return chunks, counted[0]


def test_large_non_nfc_file_counts_each_piece_not_the_remainder(monkeypatch):
    # Non-NFC text used to take the recounting path, which counted the whole
    # remaining file for every piece and hung serve on a large release. It is
    # now normalized and indexed.
    meta = _meta()
    text = ("const e\u0301 = 1;\n" + _source(400)) * 2_400
    item = _item(text)
    chunks, counted = _pack_counting(monkeypatch, item, meta)
    assert len(chunks) > 10
    # Near-linear: about 20 passes over the text (a binary search per piece).
    # The old packer recounted the remainder and needed about 50 here.
    assert counted < 30 * len(text), counted / len(text)
    _fallback_body_check(chunks, item)


def test_large_file_under_the_conservative_count_counts_each_piece(monkeypatch):
    meta = _meta()
    reset_token_drift()
    try:
        note_reported_tokens({"diff_excerpt": "hi"}, {"q": {"type": "noul", "instructions": "x"}}, 8_000)
        assert using_conservative_count()
        text = _source(500_000)
        item = _item(text)
        chunks, counted = _pack_counting(monkeypatch, item, meta)
        assert len(chunks) > 10
        assert counted < 30 * len(text), counted / len(text)
        _fallback_body_check(chunks, item)
    finally:
        reset_token_drift()
