"""Count tokens with the published Clef tokenizer.

Hosted Clef keeps the first 2,048 tokens of a state and drops the rest without
saying so. Question text is not cut. State is rendered as compact JSON with the
keys sorted, which is the order those tokens are taken in. Counts here use that
same rendering and the tokenizer Cloudflare published with Clef, so a local
count matches the state portion of a hosted call.
"""

from __future__ import annotations

import json
import math
from functools import lru_cache
from pathlib import Path
from typing import Any

HOSTED_STATE_LIMIT = 2_048
HOSTED_STATE_BUDGET = 1_900

_TOKENIZER_PATH = Path(__file__).resolve().parent / "clef_tokenizer" / "tokenizer.json"

# Prompt text around the state in the published encoder. The question block
# sits outside the 2,048-token state cut.
_SYSTEM_PROMPT = (
    "Read the complete state and schema. Decide every field jointly. Each answer "
    "must be exactly one of that field's allowed options."
)
_PREFIX = f"<|im_start|>system\n{_SYSTEM_PROMPT}<|im_end|>\n<|im_start|>user\nSTATE:\n"
_SUFFIX = "\n<|im_end|>\n<|im_start|>assistant\n<think>\n\n</think>\n\nJOINT SCHEMA DECISIONS:"
_NOUL_DEFAULTS = {
    "true": "The proposition is true or the answer is yes.",
    "false": "The proposition is false or the answer is no.",
}


def render(value: Any) -> str:
    """Compact JSON with sorted keys, matching the published encoder."""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


@lru_cache(maxsize=1)
def _tokenizer():
    from tokenizers import Tokenizer

    return Tokenizer.from_file(str(_TOKENIZER_PATH))


def count_tokens(text: str) -> int:
    if not text:
        return 0
    return len(_tokenizer().encode(text, add_special_tokens=False).ids)


def state_tokens(state: dict) -> int:
    return count_tokens(render(state))


def _schema_text(questions: dict) -> str:
    parts = ["\n\nSCHEMA FIELDS:\n"]
    for index, (question_id, question) in enumerate(questions.items()):
        parts.append(f"\nFIELD {index + 1}\nID: {question_id}\nTYPE: {question['type']}\nINSTRUCTION: ")
        instructions = question.get("instructions")
        if instructions is None or instructions == "":
            instructions = str(question_id)
        parts.append(render(instructions))
        parts.append("\nALLOWED OPTIONS:\n")
        kind = str(question.get("type"))
        if kind == "noul":
            criteria = dict(_NOUL_DEFAULTS)
            criteria.update(question.get("criteria") or {})
            options = [(key, criteria[key]) for key in ("true", "false")]
        elif kind == "choice":
            options = sorted((str(key), value) for key, value in question["criteria"].items())
        else:
            options = [(str(item_index), value) for item_index, value in enumerate(question["criteria"])]
        for option_index, (option_id, description) in enumerate(options):
            parts.append(f"OPTION {option_index + 1}: ")
            semantics: dict[str, Any] = {"option_id": option_id}
            if description is not None:
                semantics["description"] = description
            parts.append(render(semantics))
            parts.append("\n")
        parts.append("END FIELD\n")
    return "".join(parts)


def question_schema_tokens(questions: dict) -> int:
    """Tokens in the question block, not counting the state."""
    return count_tokens(_schema_text(questions))


def wrapper_tokens(questions: dict) -> int:
    """Tokens that sit outside the state: prompt, questions, and the closing mark."""
    return count_tokens(_PREFIX) + question_schema_tokens(questions) + count_tokens(_SUFFIX)


# Workers AI may report a few tokens off the prediction. The allowance is the
# larger of a fixed floor and a small share of the prediction. A real cut, or a
# count that matches neither known method, is larger than this.
HOSTED_COUNT_TOLERANCE = 8
HOSTED_COUNT_SHARE = 0.005


def hosted_count_tolerance(expected: int) -> int:
    """Tokens a hosted total may sit from its prediction and still count as that read."""
    return max(HOSTED_COUNT_TOLERANCE, math.ceil(HOSTED_COUNT_SHARE * max(0, int(expected))))


def option_count(question: dict) -> int:
    """Allowed options in one question, the same way the schema text lists them."""
    kind = str(question.get("type"))
    if kind == "noul":
        return 2
    criteria = question.get("criteria") or ()
    return len(criteria)


def hosted_schema_overhead(questions: dict) -> int:
    """Extra tokens Workers AI reports for the question block.

    Measured on live hosted Clef calls on 2026-10-03: the reported total is the
    published encoder count plus 2 tokens for every field and 1 for every
    allowed option, for noul, choice, and score fields alike. The prefix and
    suffix add nothing. Examples: one noul field +4; 7 noul fields +28 (the
    `@adyen/adyen-web` 3.15.0 first pass, 2,797 predicted, 2,825 reported);
    11 noul fields +44 (its first Pass B piece, 2,883 predicted, 2,927
    reported); a 9-option choice +11; a 4-option score +6; the 9-field Pass C
    block +50.
    """
    return sum(2 + option_count(question) for question in questions.values())


def hosted_state_was_cut(state_token_count: int, input_tokens: int, wrapper: int = 0, overhead: int = 0) -> bool:
    """True when the reported total cannot be a full read of this state.

    A full read counts the state plus the questions. Fewer tokens than the state
    alone means part of the state was dropped. Hosted Clef also stops the state
    at exactly 2,048 tokens, so a total that is only the questions plus 2,048
    is a cut when the local state is longer than that. ``overhead`` is the
    hosted question-block overhead from ``hosted_schema_overhead``.
    """
    if input_tokens <= 0 or state_token_count <= 0:
        return False
    if input_tokens < state_token_count:
        return True
    if wrapper <= 0 or state_token_count <= HOSTED_STATE_LIMIT + 32:
        return False
    for extra in {0, max(0, int(overhead))}:
        implied_state = input_tokens - wrapper - extra
        if implied_state <= HOSTED_STATE_LIMIT and implied_state + 32 < state_token_count:
            return True
    return False


def _piece_state(state: dict, excerpt: str) -> dict:
    copied = dict(state)
    copied["diff_excerpt"] = excerpt
    for key in ("package_name", "old_version", "new_version", "file_paths"):
        if key in state:
            copied[key] = state[key]
    return copied


def _char_end(excerpt: str, offsets: list[tuple[int, int]], index: int) -> int:
    if index >= len(offsets):
        return len(excerpt)
    return offsets[index][0]


def split_excerpt(excerpt: str, state: dict, budget: int) -> list[str]:
    """Cover `excerpt` with pieces whose full state stays within `budget` tokens.

    The whole state is counted, including the package name, versions, and file
    paths, because those fields sort after diff_excerpt and are the ones a cut
    drops. Pieces meet at token boundaries, and a newline is preferred when one
    falls inside the piece. Nothing in `excerpt` is left out.
    """
    if budget <= 0 or state_tokens(_piece_state(state, excerpt)) <= budget:
        return [excerpt]
    if not excerpt:
        return [excerpt]
    encoding = _tokenizer().encode(excerpt, add_special_tokens=False)
    offsets = [(int(start), int(end)) for start, end in encoding.offsets]
    if not offsets:
        return [excerpt]
    overhead = state_tokens(_piece_state(state, ""))
    room = max(1, budget - overhead - 4)
    pieces: list[str] = []
    position = 0
    token_index = 0
    total = len(offsets)
    while position < len(excerpt):
        while token_index < total and offsets[token_index][0] < position:
            token_index += 1
        end_index = min(total, token_index + room)
        while end_index > token_index:
            char_end = _char_end(excerpt, offsets, end_index)
            if char_end <= position:
                break
            if state_tokens(_piece_state(state, excerpt[position:char_end])) <= budget:
                break
            end_index -= max(1, (end_index - token_index) // 5)
        char_end = _char_end(excerpt, offsets, end_index)
        if char_end <= position:
            char_end = min(len(excerpt), position + 1)
        if char_end < len(excerpt):
            newline = excerpt.rfind("\n", position + 1, char_end)
            if newline > position:
                cut = newline + 1
                if state_tokens(_piece_state(state, excerpt[position:cut])) <= budget:
                    char_end = cut
        piece = excerpt[position:char_end]
        if not piece:
            char_end = min(len(excerpt), position + 1)
            piece = excerpt[position:char_end]
        pieces.append(piece)
        position = char_end
    return pieces or [excerpt]
