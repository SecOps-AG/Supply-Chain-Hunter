"""OpenRouter decisions client for GPT-6 Luna Decisions (experimental decision model).

Luna answers the same typed questions as Jev through OpenRouter's decisions
endpoint (POST {base}/decisions). The request body is the System One shape:
model, state, and questions. Noul answers come back as probabilities, so
Hunter scores them with Jev's scoring file unless a Luna scoring file exists.

Luna gets the same state packing and per-release token cap as Jev, so the two
models read the same text.

OpenRouter answers HTTP 502 "refused to answer question X" when the model will
not answer one question, which happens on some hostile releases. Luna then asks
the other questions without X and asks X once more on its own. If X is refused
again, a yes/no question counts as yes (HUNTER_LUNA_REFUSAL_NOUL, default 1.0)
and the refusal is counted on the client. A refused choice or score question is
an error, as before.

HTTP 400 "exceeds the token limit" is treated like Jev's max_tokens: the piece
is split and asked again. HTTP 401, 402 and 403 stop the client and are not
retried. HTTP 429 waits for Retry-After when the server sends one. HTTP 5xx,
including a 502 "refused to answer", is retried with backoff.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
import time
from collections import OrderedDict

from hunter.clef import _error_text, _read_transport, parse_answer, retry_after_seconds, urllib_post
from hunter.jev import STATE_TOKEN_BUDGET, answer_missing, invoke_states, merge_answers
from hunter.scout_model import NoulView, ScoutAnswer, ScoutModelUnavailable

log = logging.getLogger(__name__)

DEFAULT_LUNA_MODEL = "openai/gpt-6-luna-decisions"
DEFAULT_LUNA_BASE_URL = "https://openrouter.ai/api/alpha"
DEFAULT_MAX_RPM = 240
DEFAULT_REFUSAL_NOUL = 1.0
_REFUSED = re.compile(r'refused to answer question \\?"([^"\\]+)\\?"')
REQUEST_TIMEOUT = 90.0


def resolve_luna_model(explicit: str | None = None) -> str:
    """Model id for Luna. Fast variants are refused."""
    raw = os.environ.get("HUNTER_LUNA_MODEL", "") if explicit is None else explicit
    name = raw.strip() or DEFAULT_LUNA_MODEL
    lowered = name.lower()
    if "fast" in lowered.replace("/", "-").split("-"):
        raise ValueError(f"HUNTER_LUNA_MODEL={name!r} is a fast variant; fast variants are not allowed")
    if "decisions" not in lowered:
        raise ValueError(
            f"HUNTER_LUNA_MODEL={name!r} is not a decisions model; the decision model (Scout) needs "
            "a model served by OpenRouter's decisions endpoint"
        )
    return name


def resolve_luna_api_key(explicit: str | None = None) -> str:
    if explicit is not None:
        return explicit.strip()
    from hunter.openrouter import resolve_openrouter_api_key

    return os.environ.get("HUNTER_LUNA_API_KEY", "").strip() or resolve_openrouter_api_key()


def resolve_luna_base_url(explicit: str | None = None) -> str:
    raw = os.environ.get("HUNTER_LUNA_BASE_URL", "") if explicit is None else explicit
    return (raw.strip() or DEFAULT_LUNA_BASE_URL).rstrip("/")


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    value = int(raw)
    if value <= 0:
        raise ValueError(f"{name} must be greater than zero")
    return value


def luna_head_name() -> str:
    """Luna's own scoring file when one has been fitted, else Jev's."""
    from hunter.head import head_available

    return "luna" if head_available("luna") else "jev"


class LunaClient:
    """Talks to OpenRouter's decisions endpoint. Question dicts are Jev's."""

    provider = "luna"
    state_token_budget = STATE_TOKEN_BUDGET

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        base_url: str | None = None,
        retries: int | None = None,
        max_rpm: int | None = None,
        transport=None,
        sleep=time.sleep,
        clock=time.monotonic,
    ):
        self.api_key = resolve_luna_api_key(api_key)
        self.model = resolve_luna_model(model)
        self.fallback_model_id = self.model
        self.head_name = luna_head_name()
        self.base_url = resolve_luna_base_url(base_url)
        self.retries = retries if retries is not None else _env_int("HUNTER_LUNA_RETRIES", 5)
        self.max_rpm = max_rpm if max_rpm is not None else _env_int("HUNTER_LUNA_MAX_RPM", DEFAULT_MAX_RPM)
        self.transport = transport or urllib_post
        self.meter = None
        self.backup = None
        self._sleep = sleep
        self._clock = clock
        self._pace_lock = threading.Lock()
        self._next_send = 0.0
        self._cache: OrderedDict[str, ScoutAnswer] = OrderedDict()
        self._cache_lock = threading.Lock()
        self._halt_error: ScoutModelUnavailable | None = None
        self.last_cost_usd = 0.0
        self.refusal_noul = _refusal_noul()
        # Question ids the model refused twice, in order. Read by tools; not reset per release.
        self.refusals: list[str] = []

    def url(self) -> str:
        return self.base_url + "/decisions"

    def system_one(self, state: dict, questions: dict) -> ScoutAnswer:
        self._refuse_if_halted()
        key = _cache_key(self.model, state, questions)
        with self._cache_lock:
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
        with self._cache_lock:
            self._cache[key] = result
            while len(self._cache) > 128:
                self._cache.popitem(last=False)
        return result

    def _system_one_once(self, state: dict, questions: dict) -> ScoutAnswer:
        self._refuse_if_halted()
        if not self.api_key:
            raise ScoutModelUnavailable("OPENROUTER_API_KEY is not set", retryable=False)
        if self.meter is not None:
            self.meter.before_call()
        self._pace()
        body = json.dumps({"model": self.model, "state": state, "questions": questions}).encode("utf-8")
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"}
        try:
            status, raw, response_headers = _read_transport(self.transport(self.url(), headers, body, REQUEST_TIMEOUT))
        except ScoutModelUnavailable:
            raise
        except (OSError, TimeoutError) as exc:
            raise ScoutModelUnavailable(f"luna unavailable: {exc}") from exc
        if status != 200:
            refused = refused_question(status, raw)
            if refused and refused in questions:
                return self._without_refused(state, questions, refused)
            raise self._http_error(status, raw, response_headers)
        result = parse_answer(raw, self.model, questions)
        self.last_cost_usd = reported_cost(raw)
        if self.meter is not None:
            self.meter.record(self.provider, result.model or self.model, result.usage, state=state, questions=questions)
        missing = [key for key in questions if answer_missing(result, questions[key], key)]
        if missing:
            raise ScoutModelUnavailable(f"Luna response missing answers: {', '.join(missing)}")
        return result

    def _without_refused(self, state: dict, questions: dict, refused: str) -> ScoutAnswer:
        """Answer the other questions, then ask the refused one alone once more."""
        question = questions[refused]
        if len(questions) > 1:
            rest = {key: value for key, value in questions.items() if key != refused}
            result = self._system_one_once(state, rest)
            alone = self._ask_alone(state, refused, question)
            result.nouls.update(alone.nouls)
            result.choices.update(alone.choices)
            result.scores.update(alone.scores)
            result.usage = result.usage + alone.usage
            return result
        if question.get("type") != "noul":
            raise ScoutModelUnavailable(f"luna refused to answer {refused}", retryable=False)
        self.refusals.append(refused)
        log.info("Luna refused %s twice; counting it as %.2f", refused, self.refusal_noul)
        return ScoutAnswer(model=self.model, nouls={refused: NoulView(noul=self.refusal_noul)})

    def _ask_alone(self, state: dict, key: str, question: dict) -> ScoutAnswer:
        return self._system_one_once(state, {key: question})

    def _refuse_if_halted(self) -> None:
        if self._halt_error is not None:
            raise self._halt_error

    def _pace(self) -> None:
        interval = 60.0 / max(1, self.max_rpm)
        with self._pace_lock:
            now = self._clock()
            wait = self._next_send - now
            self._next_send = max(now, self._next_send) + interval
        if wait > 0:
            self._sleep(wait)

    def _http_error(self, status: int, raw: bytes, headers: dict | None = None) -> ScoutModelUnavailable:
        detail = _error_text(raw)
        lowered = detail.lower()
        if status in (401, 402, 403):
            log.error("OpenRouter rejected the Luna request (HTTP %s): %s", status, detail)
            exc = ScoutModelUnavailable(f"luna auth or credit failure {status}: {detail}", retryable=False)
            self._halt_error = exc
            return exc
        if "token limit" in lowered or "context" in lowered or "too long" in lowered:
            return ScoutModelUnavailable(f"max_tokens: luna HTTP {status}: {detail}")
        if status == 429:
            exc = ScoutModelUnavailable(f"429 luna rate limited: {detail}")
            delay = retry_after_seconds(headers)
            if delay is not None:
                exc.retry_after = delay
            return exc
        if status >= 500 or status == 408:
            return ScoutModelUnavailable(f"{status} luna unavailable: {detail}")
        return ScoutModelUnavailable(f"luna HTTP {status}: {detail}", retryable=False)


def _refusal_noul() -> float:
    raw = os.environ.get("HUNTER_LUNA_REFUSAL_NOUL", "").strip()
    if not raw:
        return DEFAULT_REFUSAL_NOUL
    value = float(raw)
    if not 0.0 <= value <= 1.0:
        raise ValueError("HUNTER_LUNA_REFUSAL_NOUL must be between 0 and 1")
    return value


def refused_question(status: int, raw: bytes) -> str:
    """Question id from a 502 refusal, or an empty string."""
    if status != 502:
        return ""
    match = _REFUSED.search(_error_text(raw))
    return match.group(1) if match else ""


def reported_cost(raw: bytes) -> float:
    """USD cost OpenRouter reports for one call, or 0.0 when it is missing."""
    try:
        body = json.loads(raw.decode("utf-8"))
        return max(0.0, float((body.get("usage") or {}).get("cost") or 0.0))
    except (UnicodeDecodeError, ValueError, TypeError, AttributeError):
        return 0.0


def _cache_key(model: str, state: dict, questions: dict) -> str:
    blob = json.dumps({"model": model, "state": state, "questions": questions}, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()
