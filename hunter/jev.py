"""Jev client pinned to jev-1.13.0, plus chunking under the state token budget."""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
import unicodedata
from collections import OrderedDict

from hunter import JEV_MODEL_ID
from hunter.jev_count import get_encoding
from hunter.jev_tokens import (
    HARD_STATE_TOKENS,
    BodyTokenIndex,
    note_reported_tokens,
    predict_input_tokens,
    request_near_limit,
    state_tokens,
    using_conservative_count,
)
from hunter.models import FileDiff, ReleaseMeta
from hunter.questions import PACKAGE_CONTENT_RULE
from hunter.scout_model import (
    ChoiceView,
    NoulView,
    ScoreView,
    ScoutAnswer,
    ScoutModelUnavailable,
    usage_from,
)
from hunter.triage import NEW_FILE_CUT_MARKER, render_excerpt

# Target size for one Scout state, in real Jev tokens. Today's chunks land
# around 8,000 to 12,000. The target stays there: a larger state is a separate
# accuracy question, not something to push up to the 32,736 rejection line.
# HARD_STATE_TOKENS is the ceiling a single piece is allowed to reach.
STATE_TOKEN_BUDGET = 12_000
GATE_EXCERPT_CHARS = 4_000
# A changed-file list up to this many tokens rides on every Scout state. A longer
# list is sent once and every chunk carries only its counts.
INLINE_CHANGED_FILES_TOKENS = 1_500
CHANGED_FILES_SENT_NOTE = "(full changed-file list was sent in separate pieces of this release)"
SLICE_EXCERPT_CHARS = 12_000
GATEWAY_BASE_URL = "https://ai-gateway.vercel.sh/typesafe"
# Pinned like JEV_MODEL_ID: the bare "typesafe-ai/jev" alias can move to a newer
# Jev release, and the shipped scoring head was calibrated on jev-1.13.0.
GATEWAY_MODEL_ID = f"typesafe-ai/{JEV_MODEL_ID}"


JevUnavailable = ScoutModelUnavailable
JevResult = ScoutAnswer


def build_state(
    meta: ReleaseMeta,
    excerpt: str,
    *,
    slice_name: str,
    file_paths: list[str] | None = None,
    changed_files: str | None = None,
) -> dict:
    state = {
        "package_name": meta.name,
        "ecosystem": meta.ecosystem,
        "old_version": meta.old_version or "",
        "new_version": meta.new_version,
        "diff_excerpt": excerpt,
        "slice": slice_name,
        "file_paths": file_paths or [],
        "content_note": PACKAGE_CONTENT_RULE,
    }
    if changed_files is not None:
        state["changed_files"] = changed_files
    return state


def pack_chunks(
    diffs: list[FileDiff],
    meta: ReleaseMeta,
    *,
    budget: int = STATE_TOKEN_BUDGET,
    changed_files: str | None = None,
) -> list[dict]:
    """Pack triaged diffs into states that stay under the token budget.

    When changed_files is set, every release carries that list. The list is
    counted with the same token counter as the excerpt. A list that does not
    fit is split across its own states. A line that still does not fit is cut
    and marked with the new-file cut marker.
    """
    leading, listed = _changed_file_plan(meta, changed_files, budget)
    if not diffs:
        empty = build_state(
            meta,
            render_excerpt([]),
            slice_name="combined",
            file_paths=[],
            changed_files=listed,
        )
        return leading + [empty]
    chunks: list[dict] = []
    batch: list[FileDiff] = []

    def flush() -> None:
        if not batch:
            return
        excerpt = render_excerpt(batch)
        chunks.append(
            build_state(
                meta,
                excerpt,
                slice_name="combined",
                file_paths=[item.path for item in batch],
                changed_files=listed,
            )
        )
        batch.clear()

    for item in diffs:
        trial = batch + [item]
        excerpt = render_excerpt(trial)
        state = build_state(
            meta,
            excerpt,
            slice_name="combined",
            file_paths=[item.path],
            changed_files=listed,
        )
        if _state_fits(state, budget):
            batch.append(item)
            continue
        flush()
        chunks.extend(_fit_file(meta, item, budget, changed_files=listed))
    flush()
    if not chunks:
        chunks = [
            build_state(
                meta,
                render_excerpt([]),
                slice_name="combined",
                changed_files=listed,
            )
        ]
    return leading + chunks


def slice_state(
    diffs: list[FileDiff],
    meta: ReleaseMeta,
    slice_name: str,
    *,
    changed_files: str | None = None,
) -> dict:
    if slice_name == "manifests":
        chosen = [item for item in diffs if item.category in {"install_scripts", "entry_points", "workflows"}]
    elif slice_name == "code_hunks":
        chosen = [item for item in diffs if item.category == "suspicious_source"]
    else:
        chosen = list(diffs)
    limit = GATE_EXCERPT_CHARS if slice_name == "gate" else SLICE_EXCERPT_CHARS
    state = build_state(
        meta,
        render_excerpt(chosen, limit_chars=limit),
        slice_name=slice_name,
        file_paths=[item.path for item in chosen],
    )
    if changed_files is None:
        return state
    stamped = dict(state)
    if slice_name != "gate" and _long_changed_files(meta, changed_files):
        # Pass C makes one call. The full list was already read in Pass B.
        changed_files = changed_files_summary(changed_files)
    stamped["changed_files"] = changed_files
    if _state_fits(stamped, STATE_TOKEN_BUDGET):
        return stamped
    stamped["changed_files"] = _prefix_changed_files(meta, state, changed_files, STATE_TOKEN_BUDGET)
    return stamped


def _fit_file(
    meta: ReleaseMeta,
    item: FileDiff,
    budget: int = STATE_TOKEN_BUDGET,
    *,
    changed_files: str | None = None,
) -> list[dict]:
    """One state when the file fits. Otherwise several states that cover the whole file."""
    excerpt = render_excerpt([item])
    paths = [item.path]
    if _excerpt_fits(meta, excerpt, paths, budget, changed_files=changed_files):
        return [
            build_state(
                meta,
                excerpt,
                slice_name="combined",
                file_paths=paths,
                changed_files=changed_files,
            )
        ]
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
    states: list[dict] = []
    header_nl = header + "\n"
    # Recounting the remaining file on every probe is quadratic. The exact
    # counter's prefix counts come from one pretokenization, except when the
    # conservative fallback is on.
    if not using_conservative_count() and not (_nfc(header_nl) and _nfc(body)):
        # Jev NFC-normalizes text before tokenizing, so the normalized text reads
        # the same to it. Normalizing here lets non-NFC files use the index
        # instead of recounting each probe, which took many minutes on big releases.
        header_nl = unicodedata.normalize("NFC", header_nl)
        body = unicodedata.normalize("NFC", body)
    if using_conservative_count():
        rest = body
        while rest:
            piece, rest = _take_piece(meta, paths, header, rest, budget, changed_files=changed_files)
            if not piece:
                piece, rest = rest[:1], rest[1:]
            states.append(
                build_state(
                    meta,
                    header_nl + piece,
                    slice_name="combined",
                    file_paths=paths,
                    changed_files=changed_files,
                )
            )
        return states or [
            build_state(
                meta,
                excerpt,
                slice_name="combined",
                file_paths=paths,
                changed_files=changed_files,
            )
        ]
    index = BodyTokenIndex(body)
    overhead = _excerpt_overhead(meta, paths, header_nl, changed_files)
    pos = 0
    while pos < len(body):
        end = _indexed_cut(index, header_nl, body, pos, overhead, budget)
        if end <= pos:
            end = pos + 1
        states.append(
            build_state(
                meta,
                header_nl + body[pos:end],
                slice_name="combined",
                file_paths=paths,
                changed_files=changed_files,
            )
        )
        pos = end
    return states or [
        build_state(
            meta,
            excerpt,
            slice_name="combined",
            file_paths=paths,
            changed_files=changed_files,
        )
    ]


def _excerpt_fits(
    meta: ReleaseMeta,
    excerpt: str,
    paths: list[str],
    budget: int,
    *,
    changed_files: str | None = None,
) -> bool:
    state = build_state(
        meta,
        excerpt,
        slice_name="combined",
        file_paths=paths,
        changed_files=changed_files,
    )
    return _state_fits(state, budget)


def _take_piece(
    meta: ReleaseMeta,
    paths: list[str],
    header: str,
    body: str,
    budget: int,
    *,
    changed_files: str | None = None,
) -> tuple[str, str]:
    """The longest prefix of body that still fits, then the unread remainder."""

    def fits(fragment: str) -> bool:
        return _excerpt_fits(meta, header + "\n" + fragment, paths, budget, changed_files=changed_files)

    # Probe growing prefixes instead of the whole remainder. Counting the full
    # remaining body on every piece made a multi-MB file quadratic.
    best = 0
    hi = min(len(body), max(1, budget) * 4)
    while hi < len(body) and fits(body[:hi]):
        best = hi
        hi = min(len(body), hi * 2)
    if hi == len(body) and fits(body):
        return body, ""
    lo, hi = best + 1, hi - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        if fits(body[:mid]):
            best = mid
            lo = mid + 1
        else:
            hi = mid - 1
    if best <= 0:
        best = 1
    else:
        newline = body.rfind("\n", 0, best)
        if newline > 0:
            best = newline + 1
    return body[:best], body[best:]


def _nfc(text: str) -> bool:
    return unicodedata.is_normalized("NFC", text)


def _excerpt_overhead(
    meta: ReleaseMeta,
    paths: list[str],
    header_nl: str,
    changed_files: str | None,
) -> int:
    """State tokens that do not change as the excerpt body grows."""
    state = build_state(
        meta,
        header_nl,
        slice_name="combined",
        file_paths=paths,
        changed_files=changed_files,
    )
    return state_tokens(state) - get_encoding().count(header_nl)


def _indexed_cut(
    index: BodyTokenIndex,
    header_nl: str,
    body: str,
    pos: int,
    overhead: int,
    budget: int,
) -> int:
    """End index of the next piece. Same cuts as ``_take_piece`` on ``body[pos:]``."""

    def fits(end: int) -> bool:
        tokens = overhead + index.count_with_header(header_nl, pos, end)
        return tokens <= budget and tokens <= HARD_STATE_TOKENS

    limit = len(body)
    if fits(limit):
        return limit
    lo, hi = pos + 1, limit
    best = pos
    while lo <= hi:
        mid = (lo + hi) // 2
        if fits(mid):
            best = mid
            lo = mid + 1
        else:
            hi = mid - 1
    if best <= pos:
        return pos + 1
    newline = body.rfind("\n", pos, best)
    if newline > pos:
        return newline + 1
    return best


def _state_fits(state: dict, budget: int) -> bool:
    tokens = state_tokens(state)
    return tokens <= budget and tokens <= HARD_STATE_TOKENS


def _changed_file_plan(
    meta: ReleaseMeta,
    changed_files: str | None,
    budget: int,
) -> tuple[list[dict], str | None]:
    """Put a short changed-file list on each state. A long list is sent once, in leading states.

    Repeating a long list on every chunk left little room for the diff, so one
    large release could need thousands of chunks.
    """
    if changed_files is None:
        return [], None
    probe = build_state(meta, "", slice_name="combined", changed_files=changed_files)
    if _state_fits(probe, budget) and not _long_changed_files(meta, changed_files):
        return [], changed_files
    pieces = _split_changed_files(meta, changed_files, budget)
    leading = [
        build_state(
            meta,
            "(changed file list)",
            slice_name="changed_files",
            file_paths=[],
            changed_files=piece,
        )
        for piece in pieces
    ]
    return leading, changed_files_summary(changed_files)


def _long_changed_files(meta: ReleaseMeta, changed_files: str) -> bool:
    probe = build_state(meta, "", slice_name="combined", changed_files=changed_files)
    return state_tokens(probe) - _empty_state_tokens(meta) > INLINE_CHANGED_FILES_TOKENS


def _empty_state_tokens(meta: ReleaseMeta) -> int:
    return state_tokens(build_state(meta, "", slice_name="combined", changed_files=""))


def changed_files_summary(changed_files: str) -> str:
    """The list header and counts, with a note that the full list was sent in its own pieces."""
    kept = [line for line in changed_files.split("\n")[:2] if line.startswith(("[changed_files]", "counts:"))]
    kept.append(CHANGED_FILES_SENT_NOTE)
    return "\n".join(kept)


def _split_changed_files(meta: ReleaseMeta, text: str, budget: int) -> list[str]:
    lines = text.split("\n")
    pieces: list[str] = []
    current: list[str] = []

    def fits(block: str) -> bool:
        state = build_state(
            meta,
            "(changed file list)",
            slice_name="changed_files",
            changed_files=block,
        )
        return _state_fits(state, budget)

    for line in lines:
        trial = "\n".join([*current, line])
        if current and fits(trial):
            current.append(line)
            continue
        if not current and fits(line):
            current = [line]
            continue
        if current:
            pieces.append("\n".join(current))
            current = []
            if fits(line):
                current = [line]
                continue
        pieces.append(_clip_to_budget(meta, line, budget) + NEW_FILE_CUT_MARKER)
    if current:
        pieces.append("\n".join(current))
    return pieces or [""]


def _clip_to_budget(meta: ReleaseMeta, line: str, budget: int) -> str:
    lo, hi = 0, len(line)
    best = 0
    while lo <= hi:
        mid = (lo + hi) // 2
        block = line[:mid] + NEW_FILE_CUT_MARKER
        state = build_state(
            meta,
            "(changed file list)",
            slice_name="changed_files",
            changed_files=block,
        )
        if _state_fits(state, budget):
            best = mid
            lo = mid + 1
        else:
            hi = mid - 1
    return line[:best]


def _prefix_changed_files(meta: ReleaseMeta, state: dict, changed_files: str, budget: int) -> str:
    """The longest prefix of the list that still fits beside this excerpt."""
    lo, hi = 0, len(changed_files)
    best = 0
    while lo <= hi:
        mid = (lo + hi) // 2
        trial = dict(state)
        trial["changed_files"] = changed_files[:mid]
        if _state_fits(trial, budget):
            best = mid
            lo = mid + 1
        else:
            hi = mid - 1
    return changed_files[:best]


def max_pool(results: list[JevResult], ids: tuple[str, ...] | list[str]) -> dict[str, float]:
    pooled = {key: 0.0 for key in ids}
    for result in results:
        for key in ids:
            view = result.nouls.get(key)
            if view is not None:
                pooled[key] = max(pooled[key], float(view.noul))
    return pooled


def _normalize(raw, fallback_model: str) -> JevResult:
    model = getattr(raw, "model", None) or fallback_model
    nouls = {
        key: NoulView(noul=float(answer.noul))
        for key, answer in dict(raw.nouls).items()
    }
    choices = {
        key: ChoiceView(
            choice=str(answer.choice),
            probabilities={str(name): float(prob) for name, prob in dict(answer.probabilities).items()},
            confidence=float(answer.confidence),
        )
        for key, answer in dict(raw.choices).items()
    }
    scores = {}
    for key, answer in dict(raw.scores).items():
        legend = {}
        for level, text in dict(answer.legend).items():
            legend[str(level)] = text if isinstance(text, str) else str(text)
        probabilities = {str(level): float(prob) for level, prob in dict(answer.probabilities).items()}
        scores[key] = ScoreView(
            score=float(answer.score),
            probabilities=probabilities,
            confidence=float(answer.confidence),
            legend=legend,
        )
    return JevResult(
        model=str(model),
        nouls=nouls,
        choices=choices,
        scores=scores,
        usage=usage_from(getattr(raw, "usage", None)),
    )


def _max_tokens_error(exc: BaseException) -> bool:
    text = str(exc).lower()
    return "max_tokens" in text or "max tokens" in text or "context length" in text


def _bare_status_400(exc: BaseException) -> bool:
    """Gateway 400 that names no error type. It is not a transient failure."""
    if _max_tokens_error(exc):
        return False
    return "returned status 400" in str(exc).lower()


def _too_long_input(exc: BaseException, state: dict, questions: dict | None) -> bool:
    """Split this input. A bare 400 counts only when the request is near the cap."""
    if _max_tokens_error(exc):
        return True
    return _bare_status_400(exc) and request_near_limit(state, questions)


def _transient_jev_error(exc: BaseException) -> bool:
    if _max_tokens_error(exc):
        return False
    text = str(exc).lower()
    markers = ("503", "429", "timeout", "unavailable", "overloaded")
    return any(marker in text for marker in markers)


def invoke_with_retry(fn, *, retries: int = 5, sleep=time.sleep):
    """Call fn until it returns or the retry budget is spent. Failures are not cached.

    Gateway 503 and other transient errors wait, then send the same request again.
    A max_tokens error is not retried here: the same input would be rejected again.
    Callers that can shrink the chunk use invoke_states.
    """
    attempts = max(1, int(retries))
    last: Exception | None = None
    for attempt in range(attempts):
        try:
            return fn()
        except JevUnavailable as exc:
            last = exc
            if getattr(exc, "retryable", None) is False or _max_tokens_error(exc) or _bare_status_400(exc):
                raise
            if attempt + 1 >= attempts:
                break
            sleep(_retry_delay(exc, attempt + 1))
    assert last is not None
    raise last


_SECTION_MARK = re.compile(r"(?m)^--- ")
_MIN_SPLIT_CHARS = 400


def split_chunk_state(state: dict) -> list[dict] | None:
    """Split one packed state into smaller states. None when it cannot shrink."""
    excerpt = str(state.get("diff_excerpt") or "")
    if len(excerpt) <= _MIN_SPLIT_CHARS:
        return None
    pieces = _split_excerpt(excerpt)
    if not pieces:
        return None
    if all(len(piece) >= len(excerpt) for piece in pieces):
        return None
    return [_replace_excerpt(state, piece) for piece in pieces]


def _split_excerpt(excerpt: str) -> list[str] | None:
    sections = _excerpt_sections(excerpt)
    if len(sections) >= 2:
        mid = len(sections) // 2
        groups = (sections[:mid], sections[mid:])
        parts = ["\n".join(group).strip() for group in groups]
        parts = [part for part in parts if part]
        if len(parts) >= 2 and all(len(part) < len(excerpt) for part in parts):
            return parts
    cut = max(_MIN_SPLIT_CHARS // 2, len(excerpt) // 2)
    newline = excerpt.rfind("\n", 0, cut)
    if newline >= _MIN_SPLIT_CHARS // 2:
        cut = newline
    left = excerpt[:cut].rstrip()
    right = excerpt[cut:].lstrip()
    if len(left) < 80:
        return None
    left_text = left if left.endswith("[truncated]") else left + "\n[truncated]"
    if len(right) < 80:
        if len(left_text) >= len(excerpt):
            return None
        return [left_text]
    right_text = right if right.endswith("[truncated]") else right + "\n[truncated]"
    if len(left_text) >= len(excerpt) or len(right_text) >= len(excerpt):
        return None
    return [left_text, right_text]


def _excerpt_sections(excerpt: str) -> list[str]:
    matches = list(_SECTION_MARK.finditer(excerpt))
    if len(matches) < 2:
        return [excerpt] if excerpt else []
    sections: list[str] = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(excerpt)
        sections.append(excerpt[match.start() : end].strip())
    if matches[0].start() > 0 and sections:
        sections[0] = excerpt[: matches[0].start()].rstrip() + "\n" + sections[0]
    return [part for part in sections if part]


def _replace_excerpt(state: dict, excerpt: str) -> dict:
    copied = dict(state)
    copied["diff_excerpt"] = excerpt
    paths = list(state.get("file_paths") or [])
    if paths:
        kept = [path for path in paths if path and path in excerpt]
        copied["file_paths"] = kept or paths
    return copied


def invoke_states(call, state, *, retries: int = 5, sleep=time.sleep, merge=None, questions=None):
    """Send one chunk. On max_tokens, split it and retry the smaller pieces.

    The same excerpt is not sent again after max_tokens. A bare
    ``400 typesafe returned status 400`` is split only when the request is near
    the context cap; otherwise it is not sent again. Transient errors still
    wait and retry that piece. Each send counts toward ``retries``. When sends
    run out with text still unread, the returned answer is marked partial.
    """
    remaining = max(1, int(retries))
    pending: list[dict] = [state]
    results = []
    last: Exception | None = None
    transient_waits = 0
    incomplete = False
    while pending and remaining > 0:
        current = pending.pop(0)
        try:
            remaining -= 1
            results.append(call(current))
        except JevUnavailable as exc:
            last = exc
            if getattr(exc, "retryable", None) is False:
                raise
            if _too_long_input(exc, current, questions):
                pieces = split_chunk_state(current)
                if not pieces:
                    incomplete = True
                    if results:
                        continue
                    raise
                pending = pieces + pending
                continue
            if _bare_status_400(exc):
                raise
            if remaining <= 0:
                raise
            transient_waits += 1
            sleep(_retry_delay(exc, transient_waits))
            pending.insert(0, current)
    if pending:
        incomplete = True
    if not results:
        assert last is not None
        raise last
    if len(results) == 1:
        result = results[0]
    elif merge is None:
        result = results
    else:
        result = merge(results)
    if incomplete and getattr(result, "partial", None) is not None:
        result.partial = True
    return result


def _retry_delay(exc: BaseException, transient_waits: int) -> float:
    """Seconds to wait before sending again. A Retry-After value wins over the backoff."""
    delay = getattr(exc, "retry_after", None)
    if delay is not None:
        try:
            return min(120.0, max(0.0, float(delay)))
        except (TypeError, ValueError):
            pass
    power = 2 ** max(0, transient_waits - 1)
    if _transient_jev_error(exc):
        return min(30.0, 0.5 * power)
    return min(8.0, 0.25 * power)


def merge_answers(results: list[JevResult]) -> JevResult:
    """Combine the answers for the pieces of one split chunk. Each value keeps its highest reading."""
    merged = JevResult(model=results[-1].model)
    for result in results:
        if result.model:
            merged.model = result.model
        merged.usage = merged.usage + result.usage
        for key, view in result.nouls.items():
            current = merged.nouls.get(key)
            if current is None or view.noul > current.noul:
                merged.nouls[key] = view
        for key, view in result.choices.items():
            current = merged.choices.get(key)
            if current is None or view.confidence > current.confidence:
                merged.choices[key] = view
        for key, view in result.scores.items():
            current = merged.scores.get(key)
            if current is None or view.score > current.score:
                merged.scores[key] = view
        if result.partial:
            merged.partial = True
    return merged


def gateway_configured() -> bool:
    """True when Jev should use the Vercel AI Gateway route."""
    url = os.environ.get("TYPESAFE_BASE_URL", "").strip()
    if "ai-gateway.vercel.sh" in url:
        return True
    return bool(os.environ.get("AI_GATEWAY_API_KEY", "").strip())


def resolve_jev_api_key(explicit: str | None = None) -> str:
    if explicit is not None:
        return explicit
    gateway_key = os.environ.get("AI_GATEWAY_API_KEY", "").strip()
    typesafe_key = os.environ.get("TYPESAFE_API_KEY", "").strip()
    if gateway_configured() and gateway_key:
        return gateway_key
    return typesafe_key or gateway_key


def resolve_jev_base_url(explicit: str | None = None) -> str:
    if explicit is not None:
        return explicit.strip()
    configured = os.environ.get("TYPESAFE_BASE_URL", "").strip()
    if configured:
        return configured
    if os.environ.get("AI_GATEWAY_API_KEY", "").strip():
        return GATEWAY_BASE_URL
    return ""


def resolve_jev_model(explicit: str | None = None) -> str:
    if explicit is not None and explicit.strip():
        return explicit.strip()
    override = os.environ.get("HUNTER_JEV_MODEL", "").strip()
    if override:
        return override
    if gateway_configured():
        return GATEWAY_MODEL_ID
    return JEV_MODEL_ID


class JevClient:
    """Talks to TypeSafe Jev. Question dicts match the system_one wire format."""

    provider = "jev"
    head_name = "jev"
    state_token_budget = STATE_TOKEN_BUDGET
    fallback_model_id = JEV_MODEL_ID

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        retries: int = 5,
        base_url: str | None = None,
    ):
        self.api_key = resolve_jev_api_key(api_key)
        self.base_url = resolve_jev_base_url(base_url)
        self.model = resolve_jev_model(model)
        self.retries = max(1, int(os.environ.get("HUNTER_JEV_RETRIES", str(retries))))
        self._client = None
        self._cache: OrderedDict[str, JevResult] = OrderedDict()
        self._sleep = time.sleep
        self.meter = None

    def question_tokens(self, questions: dict) -> int:
        """Tokens one call spends outside the state: the request frame and the questions."""
        return predict_input_tokens({}, questions)

    def client_kwargs(self) -> dict:
        kwargs = {"api_key": self.api_key, "model": self.model, "timeout": 45.0}
        if self.base_url:
            kwargs["base_url"] = self.base_url
        return kwargs

    def system_one(self, state: dict, questions: dict) -> JevResult:
        key = _cache_key(self.model, state, questions)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        result = invoke_states(
            lambda piece: self._system_one_once(piece, questions),
            state,
            retries=self.retries,
            sleep=self._sleep,
            merge=merge_answers,
            questions=questions,
        )
        if getattr(result, "partial", False):
            return result
        self._cache[key] = result
        while len(self._cache) > 128:
            self._cache.popitem(last=False)
        return result

    def _system_one_once(self, state: dict, questions: dict) -> JevResult:
        if not self.api_key:
            if self.base_url:
                raise JevUnavailable("AI_GATEWAY_API_KEY or TYPESAFE_API_KEY is not set")
            raise JevUnavailable("TYPESAFE_API_KEY is not set")
        try:
            from typesafe_sdk import TypeSafeClient
            from typesafe_sdk import TypeSafeError
        except ImportError as exc:
            raise JevUnavailable("typesafe-sdk is not installed") from exc
        if self.meter is not None:
            self.meter.before_call()
        if self._client is None:
            self._client = TypeSafeClient(**self.client_kwargs())
        try:
            raw = self._client.system_one(state=state, questions=questions, model=self.model)
        except TypeSafeError as exc:
            raise JevUnavailable(str(exc)) from exc
        except OSError as exc:
            raise JevUnavailable(str(exc)) from exc
        result = _normalize(raw, self.model)
        note_reported_tokens(state, questions, result.usage.input_tokens)
        if self.meter is not None:
            self.meter.record(self.provider, result.model or self.model, result.usage, state=state, questions=questions)
        missing = [key for key in questions if answer_missing(result, questions[key], key)]
        if missing:
            raise JevUnavailable(f"Jev response missing answers: {', '.join(missing)}")
        return result

    def list_model_ids(self) -> list[str]:
        if not self.api_key:
            return []
        import json
        import urllib.error
        import urllib.request

        request = urllib.request.Request(
            "https://api.typesafe.ai/v1/models",
            headers={"Authorization": f"Bearer {self.api_key}"},
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                body = json.loads(response.read().decode())
        except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, OSError):
            return []
        return list_model_ids_from(body)


def _cache_key(model: str, state: dict, questions: dict) -> str:
    blob = json.dumps({"model": model, "state": state, "questions": questions}, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def list_model_ids_from(body: object) -> list[str]:
    if isinstance(body, list):
        rows = body
    elif isinstance(body, dict):
        rows = body.get("data") or body.get("models") or []
    else:
        return []
    found: list[str] = []
    for row in rows:
        if isinstance(row, str):
            found.append(row)
        elif isinstance(row, dict):
            for key in ("id", "name", "model"):
                if row.get(key):
                    found.append(str(row[key]))
                    break
    return found


def newer_than_pin(model_ids: list[str], pin: str) -> list[str]:
    pin_key = _version_key(pin)
    if pin_key is None:
        return []
    newer: list[str] = []
    for model_id in model_ids:
        key = _version_key(model_id)
        if key is not None and key > pin_key:
            newer.append(model_id)
    return newer


def _version_key(model_id: str) -> tuple[int, ...] | None:
    if not model_id.startswith("jev-"):
        return None
    rest = model_id.removeprefix("jev-")
    if rest in {"latest", "preview"}:
        return None
    numbers: list[int] = []
    for part in rest.split("."):
        if not part.isdigit():
            return None
        numbers.append(int(part))
    return tuple(numbers)


def answer_missing(result: JevResult, question: dict, key: str) -> bool:
    kind = question.get("type")
    if kind == "noul":
        return key not in result.nouls
    if kind == "choice":
        return key not in result.choices
    if kind == "score":
        return key not in result.scores
    return True
