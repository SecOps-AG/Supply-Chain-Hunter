"""Predict ``usage.input_tokens`` for a full Jev decision request.

Measured formula (exact on every accepted request observed):

    input_tokens = 259 + state_cost(state) + sum(7 + body(q) for q in questions)

where ``body(q)`` is the token count of the instructions plus type-specific
extras, and the request is rejected with ``max_tokens_exceeded`` when
``state_cost + max(body) > 32736``.

Structured states (dict/list) are *not* tokenized as JSON text: each string
leaf is tokenized on its own, and the structure is charged in fixed tokens
(outer container free, nested container 2, separator 1, key colon 3 incl.
quotes, string quotes 2). Numbers are normalized the way a JavaScript
``JSON.stringify`` followed by Python ``repr`` would render them.
"""
from __future__ import annotations

import json
import math
from decimal import Decimal
from typing import Any

from .tokenizer import Encoding, get_encoding

CONTEXT_LIMIT = 32736
BASE_OVERHEAD = 259
QUESTION_OVERHEAD = 7


class ContextLimitExceeded(ValueError):
    """Raised when the API would reject the request with ``max_tokens_exceeded``."""


def _number_text(value: float | int) -> str:
    value = float(value)
    if not math.isfinite(value):
        raise ValueError("JSON numbers must be finite")
    if value == 0:
        return "0"
    text = repr(value)
    if 1e-6 <= abs(value) < 1e21:
        text = format(Decimal(text), "f")
        if "." in text:
            text = text.rstrip("0").rstrip(".")
    return str(json.loads(text))


def state_cost(state: Any, enc: Encoding, *, outermost: bool = True) -> int:
    count = enc.count
    if isinstance(state, dict):
        return ((0 if outermost else 2) + max(0, len(state) - 1)
                + sum(count(k) + 3 + state_cost(v, enc, outermost=False) for k, v in state.items()))
    if isinstance(state, list):
        return ((0 if outermost else 2) + max(0, len(state) - 1)
                + sum(state_cost(v, enc, outermost=False) for v in state))
    if isinstance(state, str):
        return count(state) + (0 if outermost else 2)
    if state is None or isinstance(state, bool):
        return 1
    if isinstance(state, (int, float)):
        return count(_number_text(state))
    raise TypeError(f"unsupported state value: {type(state).__name__}")


def question_cost(question: dict[str, Any], enc: Encoding) -> int:
    """Body cost of one question (excluding the per-question overhead)."""
    count = enc.count
    body = count(question["instructions"])
    kind = question["type"]
    criteria = question.get("criteria")
    if kind == "choice":
        body += 4 + sum(5 + count(key) for key in criteria)
        descriptions = ([v for v in criteria.values() if v is not None]
                        if any(criteria.values()) else [])
    elif kind == "score":
        descriptions = list(criteria)
    elif kind == "noul":
        descriptions = [criteria["true"], criteria["false"]] if criteria is not None else []
    else:
        raise ValueError(f"unknown question type {kind!r}")
    if descriptions:
        body += 6 + sum(5 + count(d) for d in descriptions)
    return body


def estimate_request_tokens(state: Any, questions: dict[str, dict[str, Any]] | None = None,
                            *, encoding: Encoding | None = None) -> int:
    """Predict ``usage.input_tokens`` for ``{state, questions}``.

    Raises :class:`ContextLimitExceeded` if the API would reject the request.
    Schema validity (e.g. noul criteria needing both ``true`` and ``false``)
    is the caller's responsibility.
    """
    enc = encoding or get_encoding()
    if questions is None:
        questions = {"q": {"type": "noul", "instructions": "x"}}
    if not questions:
        raise ValueError("at least one question is required")
    bodies = [question_cost(q, enc) for q in questions.values()]
    shared = state_cost(state, enc)
    if shared + max(bodies) > CONTEXT_LIMIT:
        raise ContextLimitExceeded(
            f"state ({shared}) + largest question ({max(bodies)}) exceeds {CONTEXT_LIMIT}")
    return BASE_OVERHEAD + shared + sum(QUESTION_OVERHEAD + b for b in bodies)
