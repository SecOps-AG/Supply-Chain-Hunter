"""Decision model (Scout) setting and the answer shape every Scout model returns.

Scout runs on Jev, Clef, or Luna (GPT-6 Luna Decisions through OpenRouter's
decisions endpoint, experimental). Those models return per-question
probabilities for a fitted scoring file. An OpenRouter chat model is not a
Scout backend.
"""

from __future__ import annotations

import copy
import os
from dataclasses import dataclass, field

SCOUT_MODELS = ("jev", "clef", "luna")
# Accepted spellings for the Luna decision model.
SCOUT_MODEL_ALIASES = {"openrouter-decisions": "luna"}
DEFAULT_SCOUT_MODEL = "jev"


class ScoutModelUnavailable(Exception):
    """The model could not answer. Callers defer the release and retry.

    `retryable` False means the same request must not be sent again. Jev leaves
    it unset, so Jev's retries stay as they are.
    """

    def __init__(self, message: str = "", *args, retryable: bool | None = None):
        super().__init__(message, *args)
        self.retryable = retryable


class ContextOverflow(ScoutModelUnavailable):
    """One call would not fit the model's context window, even after chunking.

    The call is not sent. Callers read the release on a model with a larger
    window, or send it to review unread. It is never cut to fit.
    """

    review_unread = True

    def __init__(self, model: str, needed_tokens: int, limit_tokens: int):
        super().__init__(
            f"context_overflow: {model} needs {needed_tokens} input tokens but takes {limit_tokens}",
            retryable=False,
        )
        self.model = model
        self.needed_tokens = needed_tokens
        self.limit_tokens = limit_tokens


@dataclass
class NoulView:
    noul: float


@dataclass
class ChoiceView:
    choice: str
    probabilities: dict[str, float]
    confidence: float


@dataclass
class ScoreView:
    score: float
    probabilities: dict[str, float]
    confidence: float
    legend: dict[str, str]


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0

    def __add__(self, other: Usage) -> Usage:
        return Usage(
            input_tokens=self.input_tokens + other.input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
        )


@dataclass
class ScoutAnswer:
    model: str
    nouls: dict[str, NoulView] = field(default_factory=dict)
    choices: dict[str, ChoiceView] = field(default_factory=dict)
    scores: dict[str, ScoreView] = field(default_factory=dict)
    usage: Usage = field(default_factory=Usage)
    # True when some of the text was not read. Callers must not treat that as a full answer.
    partial: bool = False


def usage_from(raw: object) -> Usage:
    """Token counts from an SDK object or a JSON dict. Missing counts are zero."""
    if raw is None:
        return Usage()

    def read(name: str) -> int:
        value = raw.get(name) if isinstance(raw, dict) else getattr(raw, name, None)
        try:
            return max(0, int(value or 0))
        except (TypeError, ValueError):
            return 0

    return Usage(input_tokens=read("input_tokens"), output_tokens=read("output_tokens"))


def scout_model_from_env(raw: str | None = None) -> str:
    """The decision model (Scout). An unknown name stops startup.

    The providers are jev, clef and luna (alias openrouter-decisions). Luna is
    GPT-6 Luna Decisions on OpenRouter's decisions endpoint; its model id is set
    with HUNTER_LUNA_MODEL. Any other OpenRouter model id goes on
    HUNTER_SMART_MODEL (mid-tier, balanced model) and HUNTER_ANALYST_MODEL
    (Frontier model).
    """
    value = os.environ.get("HUNTER_SCOUT_MODEL", "") if raw is None else raw
    name = value.strip().lower() or DEFAULT_SCOUT_MODEL
    name = SCOUT_MODEL_ALIASES.get(name, name)
    if name not in SCOUT_MODELS:
        raise ValueError(
            f"HUNTER_SCOUT_MODEL={value.strip()!r} is not supported; use one of: "
            f"{', '.join(SCOUT_MODELS)} (or openrouter-decisions for luna). "
            "The decision model (Scout) runs on Jev, Clef, or Luna (OpenRouter decisions). "
            "Any other OpenRouter model id belongs in HUNTER_SMART_MODEL "
            "(mid-tier, balanced model) or HUNTER_ANALYST_MODEL (Frontier model)."
        )
    return name


def scout_backup_from_env(primary: str, raw: str | None = None) -> str:
    """Backup decision model from HUNTER_SCOUT_FALLBACK, or empty when unset or the same as the primary."""
    value = os.environ.get("HUNTER_SCOUT_FALLBACK", "") if raw is None else raw
    name = value.strip().lower()
    if not name or name in ("off", "none"):
        return ""
    name = SCOUT_MODEL_ALIASES.get(name, name)
    if name not in SCOUT_MODELS:
        raise ValueError(f"HUNTER_SCOUT_FALLBACK={value.strip()!r} is not supported; use one of: {', '.join(SCOUT_MODELS)}")
    return "" if name == primary else name


def make_scout_model(config, *, meter=None, with_backup: bool = True):
    """Build the client for config.scout_model. A meter records spend and enforces the cap.

    With HUNTER_SCOUT_FALLBACK set, the client carries a `backup` client. When the primary
    cannot answer for a release, Scout reads that release again on the backup.
    """
    name = scout_model_from_env(getattr(config, "scout_model", DEFAULT_SCOUT_MODEL))
    if name == "jev":
        from hunter.jev import JevClient

        client = JevClient(model=config.jev_model, retries=config.jev_retries, base_url=config.jev_base_url)
    elif name == "clef":
        from hunter.clef import ClefClient

        client = ClefClient(model=getattr(config, "clef_model", None))
    elif name == "luna":
        from hunter.luna import LunaClient

        client = LunaClient(model=getattr(config, "luna_model", None))
    else:
        raise ValueError(f"no client for Scout model {name}")
    client.meter = meter
    client.backup = None
    client.overflow_routes = overflow_routes_for(name, config, meter) if with_backup else {}
    backup_name = scout_backup_from_env(name) if with_backup else ""
    if backup_name:
        backup_config = copy.copy(config)
        backup_config.scout_model = backup_name
        require_scoring_layer(backup_config)
        client.backup = make_scout_model(backup_config, meter=meter, with_backup=False)
    return client


def overflow_routes_for(name: str, config, meter) -> dict:
    """Models that can read a release too large for a Clef model: Omni, then Jev.

    A route is set up only when it can answer: Omni needs a scoring-layer file,
    and Jev needs an API key. Jev has a window of its own, so it has no routes.
    """
    if name != "clef":
        return {}
    from hunter.head import head_available

    routes = {}
    if head_available("clef_omni"):
        from hunter.clef import ClefClient

        routes["clef-omni"] = ClefClient(model="clef-omni")
    from hunter.jev import JevClient, resolve_jev_api_key

    if resolve_jev_api_key():
        routes["jev"] = JevClient(model=config.jev_model, retries=config.jev_retries, base_url=config.jev_base_url)
    for client in routes.values():
        client.meter = meter
        client.backup = None
        client.overflow_routes = {}
    return routes


def head_name_for(config) -> str:
    """Scoring-layer name for the configured model, without building a client."""
    name = scout_model_from_env(getattr(config, "scout_model", DEFAULT_SCOUT_MODEL))
    if name == "clef":
        from hunter.clef import clef_head_name, resolve_clef_model

        return clef_head_name(resolve_clef_model(getattr(config, "clef_model", None)))
    if name == "luna":
        from hunter.luna import luna_head_name

        return luna_head_name()
    return name


def require_scoring_layer(config) -> None:
    """Stop before any work when the configured model has no scoring-layer file yet."""
    from hunter.head import head_available, head_file

    name = head_name_for(config)
    if not head_available(name):
        raise ValueError(
            f"HUNTER_SCOUT_MODEL={config.scout_model} has no scoring-layer file (hunter/{head_file(name)}); "
            "it cannot run until that model has been calibrated"
        )


def head_name(model) -> str:
    """Which scoring-layer file this model uses. Test stand-ins default to Jev's."""
    return str(getattr(model, "head_name", "jev") or "jev")


def state_token_budget(model, default: int) -> int:
    value = getattr(model, "state_token_budget", None)
    if isinstance(value, int) and value > 0:
        return value
    return default
