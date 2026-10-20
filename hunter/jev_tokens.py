"""Jev token counts for packing and for the drift log.

The counter is the vendored copy of jevtok at commit 698c53b. On the calibration
calls from 2026-10-04 it matched usage.input_tokens exactly, including a question
whose instructions are an object. A mismatch is logged and does not stop the
client. If the reported count is meaningfully higher, later chunks use a
conservative o200k count times 2.2 so a dense file is not under-counted.
"""

from __future__ import annotations

import json
import logging
import math
from typing import Any

from hunter.jev_count import get_encoding, state_cost
from hunter.jev_count.request import BASE_OVERHEAD, QUESTION_OVERHEAD
from hunter.jev_count.tokenizer import PRETOK

log = logging.getLogger(__name__)

# state + the largest question. The API rejects above 32,736. 30,000 is the
# ceiling used to decide that a bare HTTP 400 is a too-long input.
NEAR_LIMIT_TOKENS = 30_000
# Packing stays far under that line. 28,000 leaves room for the longest question.
HARD_STATE_TOKENS = 28_000

_under_count = False
_mismatch_count = 0


def reset_token_drift() -> None:
    """Test helper. Production does not call this."""
    global _under_count, _mismatch_count
    _under_count = False
    _mismatch_count = 0


def mismatch_count() -> int:
    return _mismatch_count


def using_conservative_count() -> bool:
    return _under_count


def question_body(question: dict[str, Any], encoding=None) -> int:
    """Tokens in one question body, excluding the per-question overhead of 7.

    String instructions use the vendored rules. An instructions object is counted
    as a state value, which matched the live calls where instructions were a dict.
    """
    enc = encoding or get_encoding()
    instructions = question.get("instructions", "")
    if isinstance(instructions, str):
        body = enc.count(instructions)
    else:
        body = state_cost(instructions, enc, outermost=True)
    kind = question.get("type")
    criteria = question.get("criteria")
    if kind == "choice":
        criteria = criteria or {}
        body += 4 + sum(5 + enc.count(str(key)) for key in criteria)
        descriptions = [value for value in criteria.values() if value is not None] if any(criteria.values()) else []
    elif kind == "score":
        descriptions = list(criteria or [])
    elif kind == "noul":
        descriptions = [criteria["true"], criteria["false"]] if criteria is not None else []
    else:
        descriptions = []
    if descriptions:
        body += 6 + sum(5 + enc.count(str(description)) for description in descriptions)
    return body


def predict_input_tokens(state: Any, questions: dict | None) -> int:
    """Predicted usage.input_tokens for one request. Does not raise on the context cap."""
    enc = get_encoding()
    if not questions:
        questions = {"q": {"type": "noul", "instructions": "x"}}
    bodies = [question_body(question, enc) for question in questions.values()]
    shared = state_cost(state, enc)
    return BASE_OVERHEAD + shared + sum(QUESTION_OVERHEAD + body for body in bodies)


def state_tokens(state: Any) -> int:
    """Tokens in a Scout state. This is what packing compares to the chunk target."""
    enc = get_encoding()
    exact = state_cost(state, enc)
    if not _under_count:
        return exact
    rendered = json.dumps(state, sort_keys=True, default=str)
    rough = len(enc._base.encode(rendered, disallowed_special=()))
    return max(exact, math.ceil(rough * 2.2))


def request_near_limit(state: Any, questions: dict | None = None) -> bool:
    """True when state plus the largest question is at the 30,000-token ceiling."""
    enc = get_encoding()
    shared = state_tokens(state) if _under_count else state_cost(state, enc)
    if not questions:
        return shared >= NEAR_LIMIT_TOKENS
    largest = max(question_body(question, enc) for question in questions.values())
    return shared + largest >= NEAR_LIMIT_TOKENS


def note_reported_tokens(state: Any, questions: dict | None, reported: int) -> None:
    """Log a mismatch with usage.input_tokens. Do not stop the client.

    An under-count of at least 100 tokens and 10 percent switches later packing
    to the conservative fallback.
    """
    global _under_count, _mismatch_count
    reported = int(reported or 0)
    if reported <= 0:
        return
    predicted = predict_input_tokens(state, questions)
    if predicted == reported:
        return
    _mismatch_count += 1
    log.warning("jev token drift: predicted %s input tokens, Jev reported %s", predicted, reported)
    if reported > predicted and reported - predicted >= 100 and reported > predicted * 1.1:
        if not _under_count:
            log.warning(
                "jev token counter is below the reported count; later chunks use a conservative count"
            )
        _under_count = True


def _merge_len(fragment: str) -> int:
    """How far a leading whitespace run that contains a newline extends.

    A header that already ends in a newline merges with that run into one
    pretoken. The merge stops after the last newline in the run.
    """
    last_newline = -1
    for index, char in enumerate(fragment):
        if not char.isspace():
            break
        if char in "\r\n":
            last_newline = index
    if last_newline < 0:
        return 0
    return last_newline + 1


class BodyTokenIndex:
    """Token counts for slices of one file body, from a single pretokenization.

    Packing used to recount the whole remaining file on every binary-search
    probe. The cuts depend only on prefix counts of ``header + body[start:end]``,
    and those counts are fixed by the pretokens of the body plus a short join
    at the header. ``count_with_header`` matches ``Encoding.count`` for NFC text.
    """

    def __init__(self, text: str):
        self.text = text
        self._enc = get_encoding()
        self._spans: list[tuple[int, int, int, bool]] = []
        self._prefix = [0]
        self._cache: dict[int, tuple[str, int, int]] = {}
        for match in PRETOK.finditer(text):
            piece = match.group()
            tokens = len(self._enc._encode_pretoken(piece.encode("utf-8")))
            self._spans.append((match.start(), match.end(), tokens, piece.strip() != ""))
            self._prefix.append(self._prefix[-1] + tokens)

    def count_with_header(self, header_nl: str, start: int, end: int) -> int:
        """Tokens in ``header_nl + text[start:end]``. ``header_nl`` ends with a newline."""
        text = self.text
        if end < start:
            end = start
        if start >= len(text) or end == start:
            return self._enc.count(header_nl)
        split, head_tokens = self._junction(header_nl, start)
        if end <= split:
            return self._enc.count(header_nl + text[start:end])
        return head_tokens + self._count_from(split, end)

    def _junction(self, header_nl: str, start: int) -> tuple[int, int]:
        cached = self._cache.get(start)
        if cached is not None and cached[0] == header_nl:
            return cached[1], cached[2]
        text = self.text
        split = max(self._boundary_at_or_after(start), start + _merge_len(text[start:]))
        if split <= start:
            head_tokens = self._enc.count(header_nl)
        else:
            head_tokens = self._enc.count(header_nl + text[start:split])
        self._cache[start] = (header_nl, split, head_tokens)
        return split, head_tokens

    def _boundary_at_or_after(self, start: int) -> int:
        spans = self._spans
        lo, hi = 0, len(spans)
        while lo < hi:
            mid = (lo + hi) // 2
            if spans[mid][1] <= start:
                lo = mid + 1
            else:
                hi = mid
        if lo >= len(spans) or spans[lo][0] >= start:
            return start
        return spans[lo][1]

    def _count_from(self, origin: int, end: int) -> int:
        """Tokens in ``text[origin:end]`` when ``origin`` is a pretoken boundary."""
        if end <= origin:
            return 0
        spans = self._spans
        prefix = self._prefix
        lo, hi = 0, len(spans)
        while lo < hi:
            mid = (lo + hi) // 2
            if spans[mid][1] <= origin:
                lo = mid + 1
            else:
                hi = mid
        first = lo
        lo, hi = first, len(spans)
        while lo < hi:
            mid = (lo + hi) // 2
            if spans[mid][1] <= end:
                lo = mid + 1
            else:
                hi = mid
        if lo == len(spans) or spans[lo][0] >= end:
            return prefix[lo] - prefix[first]
        span_start, _span_end, _tokens, content = spans[lo]
        partial = self.text[span_start:end]
        if content and partial[:1].isspace() and partial.strip() == "":
            if lo > first and not spans[lo - 1][3]:
                prev_start = spans[lo - 1][0]
                return (prefix[lo - 1] - prefix[first]) + self._enc.count(self.text[prev_start:end])
            return (prefix[lo] - prefix[first]) + self._enc.count(partial)
        return (prefix[lo] - prefix[first]) + self._enc.count(partial)
