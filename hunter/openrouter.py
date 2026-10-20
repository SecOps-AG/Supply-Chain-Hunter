"""Optional OpenRouter chat completions for the mid-tier model and the Frontier model.

The default backend is the Cursor agent CLI. This module runs only when an
operator sets ``HUNTER_SMART_BACKEND=openrouter`` or ``HUNTER_ANALYST_BACKEND=openrouter``.
A key in the environment does not switch the backend. The decision model (Scout)
is not called here: Jev uses its own API, and Clef uses the Cloudflare API.

The API key is read from the environment and is never logged. Order:

1. ``OpenRouter``
2. ``OPENROUTER_API_KEY``
3. ``HUNTER_OPENROUTER_API_KEY``

A role can override that shared key with ``HUNTER_SMART_API_KEY`` (Triage, the
mid-tier, balanced model) or ``HUNTER_ANALYST_API_KEY`` (Analyst, the Frontier
model). Chat calls go to ``https://openrouter.ai/api/v1``. The ``/cursor``
endpoint is refused.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import replace

from hunter.llm import (
    OPENROUTER_API_BASE,
    OPENROUTER_BACKEND,
    USER_AGENT,
    ModelCallError,
    ModelEndpoint,
)

from hunter.model_limits import openrouter_provider

OPENROUTER_KEY_NAMES = ("OpenRouter", "OPENROUTER_API_KEY", "HUNTER_OPENROUTER_API_KEY")
OPENROUTER_KEY_MISSING = (
    "OpenRouter API key is not set. Set OpenRouter, OPENROUTER_API_KEY, or "
    "HUNTER_OPENROUTER_API_KEY. Hunter will not fall back to another provider."
)
OPENROUTER_CURSOR_URL = (
    "OpenRouter calls use https://openrouter.ai/api/v1. "
    "The /cursor endpoint is not used."
)


def resolve_openrouter_api_key() -> str:
    """First non-empty shared OpenRouter key. The value is not logged."""
    for name in OPENROUTER_KEY_NAMES:
        raw = os.environ.get(name)
        if raw is not None and raw.strip():
            return raw.strip()
    return ""


def openrouter_key_is_set() -> bool:
    """True when a shared OpenRouter key is present. The value is not returned."""
    return bool(resolve_openrouter_api_key())


def resolve_openrouter_base_url(explicit: str = "") -> str:
    """OpenRouter API root. An empty value is the public chat API, never /cursor."""
    url = (explicit or OPENROUTER_API_BASE).strip().rstrip("/")
    path = url.split("?", 1)[0].rstrip("/")
    if path.endswith("/cursor") or "/v1/cursor" in path:
        raise ValueError(OPENROUTER_CURSOR_URL)
    return url


def apply_openrouter_settings(endpoint: ModelEndpoint) -> ModelEndpoint:
    """Fill the key and base URL. Does not raise when the key is still empty."""
    if endpoint.backend != OPENROUTER_BACKEND:
        return endpoint
    key = (endpoint.api_key or "").strip() or resolve_openrouter_api_key()
    base = resolve_openrouter_base_url(endpoint.base_url)
    return replace(endpoint, api_key=key, base_url=base)


def prepare_openrouter_endpoint(endpoint: ModelEndpoint) -> ModelEndpoint:
    """Same as apply, then refuse a missing key or an empty model id."""
    ready = apply_openrouter_settings(endpoint)
    if not ready.api_key:
        raise ModelCallError(OPENROUTER_KEY_MISSING)
    if not (ready.model or "").strip():
        raise ModelCallError(
            "OpenRouter model id is empty. Set HUNTER_SMART_MODEL for the mid-tier, "
            "balanced model (Triage) or HUNTER_ANALYST_MODEL for the Frontier model "
            "(Analyst). Any model id OpenRouter accepts is allowed."
        )
    return ready


def pin_provider(body: dict) -> dict | None:
    """Pin a Clef request to Cloudflare. Returns the preferences set, or None.

    Without a pin, OpenRouter may send the call to a provider that serves only a
    16,384-token window, which cuts the input. Any provider setting already on the body is
    replaced for these models.
    """
    preferences = openrouter_provider(body.get("model"))
    if preferences is not None:
        body["provider"] = dict(preferences)
    return preferences


def check_pinned_provider(data: dict, preferences: dict) -> None:
    """Refuse an answer that a provider outside the pin served."""
    served = data.get("provider")
    if not isinstance(served, str) or not served.strip():
        return
    allowed = {str(name).lower() for name in preferences.get("order", [])}
    if served.strip().lower() not in allowed:
        raise ModelCallError(f"OpenRouter served the call from {served.strip()}, not the pinned provider")


def _read_response(response) -> dict:
    raw = response.read()
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ModelCallError("OpenRouter models list did not return JSON") from exc
    if not isinstance(parsed, dict):
        raise ModelCallError("OpenRouter models list returned an unexpected body")
    return parsed


def list_openrouter_models(
    *,
    api_key: str | None = None,
    base_url: str | None = None,
    opener=None,
) -> list[dict[str, str]]:
    """Every model id from GET /models. Nothing is filtered out.

    ``opener`` is a callable ``(request, timeout) -> response`` for tests.
    The API key is sent as a bearer token and is not included in errors.
    """
    key = resolve_openrouter_api_key() if api_key is None else api_key.strip()
    if not key:
        raise ModelCallError(OPENROUTER_KEY_MISSING)
    base = resolve_openrouter_base_url(base_url or "")
    url = f"{base}/models"
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {key}",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        },
        method="GET",
    )
    fetch = opener or (lambda req, timeout: urllib.request.urlopen(req, timeout=timeout))
    try:
        with fetch(request, 30) as response:
            parsed = _read_response(response)
    except ModelCallError:
        raise
    except urllib.error.HTTPError as exc:
        raise ModelCallError(f"HTTP {exc.code} from {url}") from exc
    except urllib.error.URLError as exc:
        raise ModelCallError(f"cannot reach {url}: {exc.reason}") from exc
    except TimeoutError as exc:
        raise ModelCallError(f"timed out after 30s calling {url}") from exc
    data = parsed.get("data")
    if not isinstance(data, list):
        raise ModelCallError("OpenRouter models list has no data array")
    models: list[dict[str, str]] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        model_id = item.get("id")
        if not isinstance(model_id, str) or not model_id.strip():
            continue
        name = item.get("name")
        models.append({"id": model_id.strip(), "name": name.strip() if isinstance(name, str) else ""})
    return models
