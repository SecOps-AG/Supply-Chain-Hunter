"""Context limits per decision model, and the rules that follow from them.

Limits are in tokens. A call's input is kept under the limit minus a margin that
leaves room for the answer. A release that cannot fit one model after chunking
is read by a model with a larger window instead of being cut.
"""

from __future__ import annotations

MODEL_CONTEXT_TOKENS = {
    "clef-flash": 24_576,
    "microsoft-decision-1": 32_768,
    "clef": 65_536,
    "clef-omni": 65_536,
    "jev": 64_000,
    "luna": 1_050_000,
}

# Tokens kept free for the answer.
OUTPUT_MARGIN_TOKENS = 2_048

# Where a release goes when it is too large for the model that was reading it.
# The first model in this order whose window holds the release is used.
OVERFLOW_ROUTE_ORDER = ("clef-omni", "jev")

CLOUDFLARE_PROVIDER = "cloudflare"


def canonical_model(model: str | None) -> str | None:
    """Table key for a model id, or None when the id is not in the table.

    Handles provider prefixes (``@cf/cloudflare/clef-flash``, ``cloudflare/clef``,
    ``microsoft/microsoft-decision-1``) and Jev and Luna version suffixes.
    """
    name = (model or "").strip().lower().rsplit("/", 1)[-1]
    if not name:
        return None
    if name in MODEL_CONTEXT_TOKENS:
        return name
    if name.startswith("jev"):
        return "jev"
    if "luna" in name:
        return "luna"
    return None


def context_limit(model: str | None) -> int | None:
    """Context window in tokens, or None for a model that is not in the table."""
    key = canonical_model(model)
    return MODEL_CONTEXT_TOKENS[key] if key else None


def input_limit(model: str | None, margin: int = OUTPUT_MARGIN_TOKENS) -> int | None:
    """Most input tokens one call may carry, or None for an unknown model."""
    limit = context_limit(model)
    return None if limit is None else max(1, limit - margin)


def state_budget(model: str | None, question_tokens: int, default: int) -> int:
    """State tokens one call may carry for this model, after the questions.

    Never above `default`. An unknown model keeps `default`.
    """
    room = input_limit(model)
    if room is None:
        return default
    return max(1, min(default, room - max(0, int(question_tokens))))


def overflow_route(needed_tokens: int, available: dict | None, exclude: str | None = None):
    """Pick (name, client) from `available` for a release of `needed_tokens`.

    Follows OVERFLOW_ROUTE_ORDER. A model is skipped when its window cannot hold
    the release. Returns None when nothing fits.
    """
    skip = canonical_model(exclude)
    for name in OVERFLOW_ROUTE_ORDER:
        client = (available or {}).get(name)
        if client is None or name == skip:
            continue
        room = input_limit(name)
        if room is not None and needed_tokens <= room:
            return name, client
    return None


def is_cloudflare_clef(model: str | None) -> bool:
    name = (model or "").strip().lower()
    return name.startswith("cloudflare/clef") or name.startswith("@cf/cloudflare/clef")


def openrouter_provider(model: str | None) -> dict | None:
    """OpenRouter ``provider`` preferences for a model, or None when it needs none.

    Clef models are pinned to Cloudflare with no fallback. Some providers behind
    the same id serve the full window, but at least one serves only 16,384 tokens
    and would cut the input, and OpenRouter can route to any of them.
    """
    if not is_cloudflare_clef(model):
        return None
    return {"order": [CLOUDFLARE_PROVIDER], "only": [CLOUDFLARE_PROVIDER], "allow_fallbacks": False}
