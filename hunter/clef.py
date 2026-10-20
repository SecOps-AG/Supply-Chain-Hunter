"""Cloudflare Clef client. Clef answers the same typed questions as Jev.

HUNTER_CLEF_BASE_URL points it at a self-hosted server instead of Workers AI. That
server must accept a System One body at POST {base}/v1/systemone and return
model, answers, and usage.

Hosted Clef keeps the first 2,048 tokens of the state and drops the rest without
an error. Question text is not cut. Hunter counts the state with the published
Clef tokenizer and sends pieces that stay under about 1,900 tokens, including
the package name, versions, and file paths. A reported token count that cannot
be a full read of that state takes the same path as Jev's max_tokens: split and
ask again, then send the release to review with the local floors applied. A
self-hosted server keeps its own context limit and is not split this way.
HTTP 422 is not retried. HTTP 401 and 403 stop the client and are not retried.
HTTP 429 waits for Retry-After when the server sends one, then retries. HTTP 5xx retries.
A reported token count that is neither a full read of the state nor the 2,048-token
cut stops the client. The full-read prediction includes the 2 tokens per question
and 1 per allowed option that Workers AI adds to the published count, plus a
small allowance (8 tokens or 0.5% of the prediction, whichever is larger). HUNTER_CLEF_RELEASE_TOKENS
and HUNTER_CLEF_RELEASE_USD cap
one release. Crossing either cap sends that release to review.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
import urllib.error
import urllib.request
from collections import OrderedDict

from hunter.clef_tokens import (
    HOSTED_STATE_BUDGET,
    HOSTED_STATE_LIMIT,
    hosted_count_tolerance,
    hosted_schema_overhead,
    hosted_state_was_cut,
    split_excerpt,
    state_tokens,
    wrapper_tokens,
)
from hunter.model_limits import OUTPUT_MARGIN_TOKENS, context_limit
from hunter.spend import DEFAULT_USD_PER_M_INPUT, price_key
from hunter.jev import answer_missing, invoke_states, merge_answers
from hunter.questions import questions_for_clef
from hunter.scout_model import (
    ChoiceView,
    ContextOverflow,
    NoulView,
    ScoreView,
    ScoutAnswer,
    ScoutModelUnavailable,
    usage_from,
)

log = logging.getLogger(__name__)

CLOUDFLARE_API = "https://api.cloudflare.com/client/v4"
CLEF_MODELS = ("clef", "clef-flash", "clef-omni")
DEFAULT_CLEF_MODEL = "clef"
# Each hosted model has its own context window; see hunter.model_limits.
TRUNCATION_MARGIN = OUTPUT_MARGIN_TOKENS
# Hosted state budget. The API keeps 2,048 state tokens; 1,900 leaves room so
# the name, versions, and file paths are still inside that window.
STATE_TOKENS = HOSTED_STATE_BUDGET
# Cloudflare's reference encoder for a self-hosted server stops at 16,384 tokens.
SELF_HOSTED_CONTEXT_TOKENS = 16_384
SELF_HOSTED_STATE_TOKENS = 12_000
DEFAULT_MAX_RPM = 240
REQUEST_TIMEOUT = 45.0


def resolve_clef_model(explicit: str | None = None) -> str:
    raw = os.environ.get("HUNTER_CLEF_MODEL", "") if explicit is None else explicit
    name = raw.strip().lower() or DEFAULT_CLEF_MODEL
    if name not in CLEF_MODELS:
        raise ValueError(f"HUNTER_CLEF_MODEL={raw.strip()!r} is not supported; use one of: {', '.join(CLEF_MODELS)}")
    return name


def clef_head_name(model: str) -> str:
    return model.replace("-", "_")


def chunk_excerpt_states(state: dict, budget: int) -> list[dict]:
    """Split one state so each piece's full state stays within `budget` tokens.

    A budget of 0 leaves the state alone. Self-hosted servers use that.
    """
    if budget <= 0:
        return [state]
    excerpt = str(state.get("diff_excerpt") or "")
    return [_piece_state(state, piece) for piece in split_excerpt(excerpt, state, budget)]


def _piece_state(state: dict, excerpt: str) -> dict:
    copied = dict(state)
    copied["diff_excerpt"] = excerpt
    for key in ("package_name", "old_version", "new_version", "file_paths"):
        if key in state:
            copied[key] = state[key]
    return copied


def _harmless_choice(key: str, choice: str) -> bool:
    if key == "attack_family":
        return choice in {"", "none"}
    if key == "suspected_cause":
        return choice in {"", "unknown"}
    if key.startswith("subtype_"):
        return choice in {"", "unspecified"}
    return False


def merge_dangerous_answers(results: list[ScoutAnswer]) -> ScoutAnswer:
    """Keep the most dangerous reading when one release was split into pieces.

    A confident "none" or "unknown" from a harmless piece does not outvote a
    less confident hostile answer from another piece. Nouls and scores already
    keep their highest reading. Jev still uses merge_answers.
    """
    merged = merge_answers(results)
    for key in list(merged.choices):
        best = None
        for result in results:
            view = result.choices.get(key)
            if view is None:
                continue
            if best is None or _more_dangerous(key, view, best):
                best = view
        if best is not None:
            merged.choices[key] = best
    return merged


def _more_dangerous(key: str, view: ChoiceView, current: ChoiceView) -> bool:
    view_harmless = _harmless_choice(key, view.choice)
    current_harmless = _harmless_choice(key, current.choice)
    if view_harmless != current_harmless:
        return not view_harmless
    return view.confidence > current.confidence


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    value = int(raw)
    if value <= 0:
        raise ValueError(f"{name} must be greater than zero")
    return value


def urllib_post(url: str, headers: dict[str, str], body: bytes, timeout: float) -> tuple[int, bytes, dict[str, str]]:
    """POST and return status, body, and response headers. HTTP errors are returned, not raised."""
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read(), _header_map(response.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read() or b"", _header_map(exc.headers)


def _header_map(headers) -> dict[str, str]:
    if headers is None:
        return {}
    return {str(key): str(value) for key, value in headers.items()}


def _read_transport(outcome) -> tuple[int, bytes, dict]:
    if isinstance(outcome, tuple) and len(outcome) >= 3:
        status, raw, headers = outcome[0], outcome[1], outcome[2]
        return int(status), raw, headers or {}
    if isinstance(outcome, tuple) and len(outcome) == 2:
        status, raw = outcome
        return int(status), raw, {}
    raise ScoutModelUnavailable("clef transport returned an unexpected result")


def retry_after_seconds(headers: dict | None) -> float | None:
    """Seconds from a Retry-After header. None when the header is missing or not a delay."""
    if not headers:
        return None
    raw = ""
    for key, value in headers.items():
        if str(key).lower() == "retry-after":
            raw = str(value).strip()
            break
    if not raw:
        return None
    try:
        return max(0.0, float(raw))
    except ValueError:
        pass
    try:
        from datetime import timezone
        from email.utils import parsedate_to_datetime

        when = parsedate_to_datetime(raw)
        if when is None:
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return max(0.0, when.timestamp() - time.time())
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _near(reported: int, expected: int) -> bool:
    return abs(reported - expected) <= hosted_count_tolerance(expected)


def counts_drifted(local_state: int, input_tokens: int, wrapper: int, overhead: int = 0) -> bool:
    """True when the reported total matches neither a full read nor the known state cut.

    A full read is the local state plus the question tokens. Workers AI also
    adds ``overhead`` tokens for the question block (2 per field and 1 per
    allowed option, see ``hosted_schema_overhead``). A total within a small
    allowance of that prediction still counts as that read. A cut of a longer
    state is the question tokens plus 2,048, with the same overhead. Any other
    positive total means the server is no longer counting the way this client
    expects, so Clef should stop. A total smaller than the state itself is the
    existing cut signal, not drift.
    """
    if input_tokens <= 0 or local_state <= 0 or wrapper <= 0:
        return False
    if input_tokens < local_state:
        return False
    extras = {0, max(0, int(overhead))}
    if any(_near(input_tokens, local_state + wrapper + extra) for extra in extras):
        return False
    if local_state > HOSTED_STATE_LIMIT:
        if any(_near(input_tokens, wrapper + extra + HOSTED_STATE_LIMIT) for extra in extras):
            return False
    return True


def _env_optional_int(name: str) -> int | None:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return None
    value = int(raw)
    if value <= 0:
        return None
    return value


def _env_optional_float(name: str) -> float | None:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return None
    value = float(raw)
    if value <= 0:
        return None
    return value


class ClefClient:
    """Talks to Clef on Workers AI. Question dicts match the System One wire format."""

    provider = "clef"

    def __init__(
        self,
        *,
        model: str | None = None,
        api_token: str | None = None,
        account_id: str | None = None,
        retries: int | None = None,
        max_rpm: int | None = None,
        state_tokens: int | None = None,
        context_tokens: int | None = None,
        base_url: str | None = None,
        transport=None,
        sleep=time.sleep,
        clock=time.monotonic,
        release_tokens: int | None = None,
        release_usd: float | None = None,
    ):
        self.model = resolve_clef_model(model)
        self.head_name = clef_head_name(self.model)
        self.fallback_model_id = self.model
        self.base_url = (base_url if base_url is not None else os.environ.get("HUNTER_CLEF_BASE_URL", "")).strip()
        if api_token is None:
            api_token = os.environ.get("HUNTER_CLEF_API_TOKEN", "").strip()
            if not self.base_url:
                # The Cloudflare token is never sent to a self-hosted server.
                api_token = api_token or os.environ.get("CLOUDFLARE_API_TOKEN", "").strip()
        self.api_token = api_token
        self.account_id = account_id if account_id is not None else os.environ.get("CLOUDFLARE_ACCOUNT_ID", "").strip()
        self.retries = retries if retries is not None else _env_int("HUNTER_CLEF_RETRIES", 5)
        self.max_rpm = max_rpm if max_rpm is not None else _env_int("HUNTER_CLEF_MAX_RPM", DEFAULT_MAX_RPM)
        default_state = SELF_HOSTED_STATE_TOKENS if self.base_url else STATE_TOKENS
        default_context = SELF_HOSTED_CONTEXT_TOKENS if self.base_url else context_limit(self.model)
        self.state_token_budget = state_tokens or _env_int("HUNTER_CLEF_STATE_TOKENS", default_state)
        self.context_tokens = context_tokens or _env_int("HUNTER_CLEF_CONTEXT_TOKENS", default_context)
        self.transport = transport or urllib_post
        self.meter = None
        self._sleep = sleep
        self._clock = clock
        self._pace_lock = threading.Lock()
        self._next_send = 0.0
        self._cache: OrderedDict[str, ScoutAnswer] = OrderedDict()
        self._cache_lock = threading.Lock()
        self._seen_model: str | None = None
        self._auth_logged = False
        self._halt_error: ScoutModelUnavailable | None = None
        token_budget = _env_optional_int("HUNTER_CLEF_RELEASE_TOKENS") if release_tokens is None else release_tokens
        usd_budget = _env_optional_float("HUNTER_CLEF_RELEASE_USD") if release_usd is None else release_usd
        self.release_token_budget = token_budget if token_budget and token_budget > 0 else None
        self.release_usd_budget = usd_budget if usd_budget and usd_budget > 0 else None
        self._release_tokens = 0
        self._release_usd = 0.0

    @property
    def self_hosted(self) -> bool:
        return bool(self.base_url)

    @property
    def input_limit(self) -> int:
        """Most input tokens one call may carry: the context window less room for the answer."""
        return max(1, self.context_tokens - TRUNCATION_MARGIN)

    def question_tokens(self, questions: dict) -> int:
        """Tokens one call spends outside the state: prompt, questions, and their overhead."""
        return self._call_overhead(questions_for_clef(questions))

    @staticmethod
    def _call_overhead(questions: dict) -> int:
        return wrapper_tokens(questions) + hosted_schema_overhead(questions)

    @property
    def splits_full_excerpt(self) -> bool:
        """Hosted Clef splits by real tokens and must be given the whole excerpt."""
        return not self.self_hosted

    def url(self) -> str:
        if self.self_hosted:
            return self.base_url.rstrip("/") + "/v1/systemone"
        return f"{CLOUDFLARE_API}/accounts/{self.account_id}/ai/run/@cf/cloudflare/{self.model}"

    def begin_release(self) -> None:
        """Start the token and dollar counters for one release. A client stop stays in force."""
        self._release_tokens = 0
        self._release_usd = 0.0

    def system_one(self, state: dict, questions: dict) -> ScoutAnswer:
        self._refuse_if_halted()
        questions = questions_for_clef(questions)
        key = _cache_key(self.model, state, questions)
        with self._cache_lock:
            cached = self._cache.get(key)
        if cached is not None:
            return cached
        budget = 0 if self.self_hosted else self.state_token_budget
        if not self.self_hosted:
            # Chunks are sized for this model: the questions count against its window too.
            room = self.input_limit - self.question_tokens(questions)
            fixed = state_tokens({**state, "diff_excerpt": ""})
            if fixed > room:
                # Splitting the excerpt cannot make the fixed part of the state smaller.
                raise ContextOverflow(self.model, fixed + self.question_tokens(questions), self.input_limit)
            budget = max(1, min(budget, room))
        pieces = chunk_excerpt_states(state, budget)
        results = [
            invoke_states(
                lambda piece: self._system_one_once(piece, questions),
                piece_state,
                retries=self.retries,
                sleep=self._sleep,
                merge=merge_dangerous_answers,
            )
            for piece_state in pieces
        ]
        result = results[0] if len(results) == 1 else merge_dangerous_answers(results)
        if any(getattr(item, "partial", False) for item in results):
            result.partial = True
            return result
        with self._cache_lock:
            self._cache[key] = result
            while len(self._cache) > 128:
                self._cache.popitem(last=False)
        return result

    def _system_one_once(self, state: dict, questions: dict) -> ScoutAnswer:
        self._refuse_if_halted()
        if self._over_release_budget():
            raise self._budget_stop()
        if not self.self_hosted:
            if not self.api_token:
                raise ScoutModelUnavailable("CLOUDFLARE_API_TOKEN is not set")
            if not self.account_id:
                raise ScoutModelUnavailable("CLOUDFLARE_ACCOUNT_ID is not set")
        self._refuse_overflow(state, questions)
        if self.meter is not None:
            self.meter.before_call()
        self._pace()
        body = json.dumps({"model": self.model, "state": state, "questions": questions}).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"
        try:
            status, raw, response_headers = _read_transport(self.transport(self.url(), headers, body, REQUEST_TIMEOUT))
        except ScoutModelUnavailable:
            raise
        except (OSError, TimeoutError) as exc:
            raise ScoutModelUnavailable(f"clef unavailable: {exc}") from exc
        if status != 200:
            raise self._http_error(status, raw, response_headers)
        result = parse_answer(raw, self.model, questions)
        if self.meter is not None:
            self.meter.record(self.provider, result.model or self.model, result.usage, state=state, questions=questions)
        self._note_model(result.model)
        self._add_release_usage(result.usage.input_tokens)
        local_state = state_tokens(state)
        question_tokens = wrapper_tokens(questions)
        overhead = hosted_schema_overhead(questions)
        if not self.self_hosted and counts_drifted(local_state, result.usage.input_tokens, question_tokens, overhead):
            raise self._halt(
                ScoutModelUnavailable(
                    f"clef drift: reported {result.usage.input_tokens} input tokens for a state of "
                    f"{local_state} tokens and {question_tokens} question tokens",
                    retryable=False,
                )
            )
        if self._over_release_budget():
            raise self._budget_stop()
        if result.usage.input_tokens >= self.input_limit:
            raise ScoutModelUnavailable(
                f"max_tokens: clef read {result.usage.input_tokens} input tokens of a "
                f"{self.context_tokens}-token context, so the input was likely cut off"
            )
        if not self.self_hosted and hosted_state_was_cut(local_state, result.usage.input_tokens, question_tokens, overhead):
            raise ScoutModelUnavailable(
                f"max_tokens: clef reported {result.usage.input_tokens} input tokens for a state of "
                f"{local_state} tokens, so the state was cut"
            )
        missing = [key for key in questions if answer_missing(result, questions[key], key)]
        if missing:
            raise ScoutModelUnavailable(f"Clef response missing answers: {', '.join(missing)}")
        return result

    def _refuse_overflow(self, state: dict, questions: dict) -> None:
        """Do not send a call that is larger than this model's window; it would be cut."""
        needed = state_tokens(state) + self._call_overhead(questions)
        if needed > self.input_limit:
            raise ContextOverflow(self.model, needed, self.input_limit)

    def _refuse_if_halted(self) -> None:
        if self._halt_error is not None:
            raise self._halt_error

    def _halt(self, exc: ScoutModelUnavailable) -> ScoutModelUnavailable:
        self._halt_error = exc
        return exc

    def _price_per_million(self) -> float:
        return float(DEFAULT_USD_PER_M_INPUT[price_key(self.provider, self.model)])

    def _add_release_usage(self, input_tokens: int) -> None:
        tokens = max(0, int(input_tokens))
        self._release_tokens += tokens
        self._release_usd += tokens / 1_000_000 * self._price_per_million()

    def _over_release_budget(self) -> bool:
        if self.release_token_budget is not None and self._release_tokens > self.release_token_budget:
            return True
        if self.release_usd_budget is not None and self._release_usd > self.release_usd_budget:
            return True
        return False

    def _budget_stop(self) -> ScoutModelUnavailable:
        exc = ScoutModelUnavailable("clef release budget exceeded", retryable=False)
        exc.review_unread = True
        return exc

    def _pace(self) -> None:
        interval = 60.0 / max(1, self.max_rpm)
        with self._pace_lock:
            now = self._clock()
            wait = self._next_send - now
            self._next_send = max(now, self._next_send) + interval
        if wait > 0:
            self._sleep(wait)

    def _note_model(self, model: str) -> None:
        if not model:
            return
        if self._seen_model is None:
            self._seen_model = model
        elif model != self._seen_model:
            log.warning(
                "Clef answered as %s after %s; its scoring layer was set for the earlier model",
                model,
                self._seen_model,
            )
            self._seen_model = model

    def _http_error(self, status: int, raw: bytes, headers: dict | None = None) -> ScoutModelUnavailable:
        detail = _error_text(raw)
        if status in (401, 403):
            if not self._auth_logged:
                self._auth_logged = True
                where = "the self-hosted server" if self.self_hosted else "Cloudflare"
                log.error("Clef at %s rejected the token or account (HTTP %s): %s", where, status, detail)
            return self._halt(ScoutModelUnavailable(f"clef auth failed {status}: {detail}", retryable=False))
        if status == 422:
            return ScoutModelUnavailable(f"clef HTTP 422: {detail}", retryable=False)
        if status == 429:
            exc = ScoutModelUnavailable(f"429 clef rate limited: {detail}")
            delay = retry_after_seconds(headers)
            if delay is not None:
                exc.retry_after = delay
            return exc
        if status >= 500:
            return ScoutModelUnavailable(f"{status} clef unavailable: {detail}")
        lowered = detail.lower()
        if "context" in lowered or "too long" in lowered or "too many tokens" in lowered:
            return ScoutModelUnavailable(f"max_tokens: clef HTTP {status}: {detail}")
        return ScoutModelUnavailable(f"clef HTTP {status}: {detail}", retryable=False)


def _cache_key(model: str, state: dict, questions: dict) -> str:
    blob = json.dumps({"model": model, "state": state, "questions": questions}, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _error_text(raw: bytes) -> str:
    try:
        body = json.loads(raw.decode("utf-8") or "{}")
    except (UnicodeDecodeError, json.JSONDecodeError):
        return raw[:300].decode("utf-8", errors="replace")
    if isinstance(body, dict):
        errors = body.get("errors")
        if isinstance(errors, list) and errors:
            parts = []
            for item in errors:
                if isinstance(item, dict):
                    parts.append(f"{item.get('code', '')} {item.get('message', '')}".strip())
                else:
                    parts.append(str(item))
            return "; ".join(parts)[:300]
        for key in ("error", "message", "detail"):
            if body.get(key):
                return str(body[key])[:300]
    return str(body)[:300]


def _probabilities(answer: dict) -> dict[str, float]:
    return {str(name): float(prob) for name, prob in dict(answer.get("probabilities") or {}).items()}


def parse_answer(raw: bytes, fallback_model: str, questions: dict) -> ScoutAnswer:
    """Read a Workers AI envelope ({"result": ..., "success": ...}) or a bare System One body."""
    try:
        body = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ScoutModelUnavailable(f"clef returned a body that is not JSON: {exc}") from exc
    if not isinstance(body, dict):
        raise ScoutModelUnavailable("clef returned a body that is not an object")
    if "result" in body and ("success" in body or "errors" in body):
        if body.get("success") is False:
            raise ScoutModelUnavailable(f"clef request failed: {_error_text(raw)}")
        body = body.get("result") or {}
        if not isinstance(body, dict):
            raise ScoutModelUnavailable("clef result is not an object")
    answers = body.get("answers")
    if not isinstance(answers, dict):
        raise ScoutModelUnavailable("Clef response missing answers")
    result = ScoutAnswer(model=str(body.get("model") or fallback_model), usage=usage_from(body.get("usage")))
    for key, answer in answers.items():
        if not isinstance(answer, dict):
            continue
        kind = (questions.get(key) or {}).get("type") or answer.get("type")
        try:
            if kind == "noul" and "noul" in answer:
                result.nouls[key] = NoulView(noul=float(answer["noul"]))
            elif kind == "choice" and "choice" in answer:
                result.choices[key] = ChoiceView(
                    choice=str(answer["choice"]),
                    probabilities=_probabilities(answer),
                    confidence=float(answer.get("confidence") or 0.0),
                )
            elif kind == "score" and "score" in answer:
                legend = dict(answer.get("legend") or {})
                result.scores[key] = ScoreView(
                    score=float(answer["score"]),
                    probabilities=_probabilities(answer),
                    confidence=float(answer.get("confidence") or 0.0),
                    legend={str(level): text if isinstance(text, str) else str(text) for level, text in legend.items()},
                )
        except (TypeError, ValueError) as exc:
            raise ScoutModelUnavailable(f"clef answer {key} is malformed: {exc}") from exc
    return result
