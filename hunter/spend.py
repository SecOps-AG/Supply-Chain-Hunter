"""Scout model spend: a ledger per model and Pacific day, and a test spend cap.

When the day's spend reaches HUNTER_SCOUT_DAILY_USD_CAP, Scout stops making model
calls. Releases stay queued. Scout does not start again at midnight: the stop is
kept in the database until the cap is set to a different value.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime
from zoneinfo import ZoneInfo

from hunter.db import utcnow
from hunter.scout_model import ScoutModelUnavailable, Usage
from hunter.jev_tokens import predict_input_tokens
from hunter.triage import estimate_tokens

log = logging.getLogger(__name__)

PACIFIC = ZoneInfo("America/Los_Angeles")
DEFAULT_USD_PER_M_INPUT = {
    "jev": 0.042,
    "clef": 0.24,
    "clef-flash": 0.038,
    "clef-omni": 0.15,
    "microsoft-decision-1": 0.042,
    "luna": 0.10,
}
PRICE_ENV = {
    "jev": "HUNTER_JEV_USD_PER_M_INPUT",
    "clef": "HUNTER_CLEF_USD_PER_M_INPUT",
    "clef-flash": "HUNTER_CLEF_FLASH_USD_PER_M_INPUT",
    "clef-omni": "HUNTER_CLEF_OMNI_USD_PER_M_INPUT",
    "microsoft-decision-1": "HUNTER_MICROSOFT_DECISION_USD_PER_M_INPUT",
    "luna": "HUNTER_LUNA_USD_PER_M_INPUT",
}
STOP_REASON = "spend_cap_reached"


def pacific_day(moment: datetime | None = None) -> str:
    return (moment or utcnow()).astimezone(PACIFIC).date().isoformat()


def price_key(provider: str, model: str) -> str:
    name = (model or "").lower()
    if provider == "clef" and "flash" in name:
        return "clef-flash"
    if provider == "clef" and "omni" in name:
        return "clef-omni"
    if "microsoft-decision" in name:
        return "microsoft-decision-1"
    return provider


def prices_from_env() -> dict[str, float]:
    prices = dict(DEFAULT_USD_PER_M_INPUT)
    for key, name in PRICE_ENV.items():
        raw = os.environ.get(name, "").strip()
        if not raw:
            continue
        value = float(raw)
        if value < 0:
            raise ValueError(f"{name} must be zero or greater")
        prices[key] = value
    return prices


def cap_from_env() -> float | None:
    """Unset or 0 means no cap. A value that is not a number stops startup."""
    raw = os.environ.get("HUNTER_SCOUT_DAILY_USD_CAP", "").strip()
    if not raw:
        return None
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"HUNTER_SCOUT_DAILY_USD_CAP={raw!r} is not a number") from exc
    if value < 0:
        raise ValueError("HUNTER_SCOUT_DAILY_USD_CAP must be zero or greater")
    return value or None


def _cap_text(cap: float) -> str:
    return f"{cap:.6f}"


class SpendMeter:
    """Shared by every worker. Overshoot is limited to calls already in flight."""

    def __init__(
        self,
        db,
        *,
        cap_usd: float | None = None,
        prices: dict[str, float] | None = None,
        stop: threading.Event | None = None,
        clock=utcnow,
        wait_seconds: float = 60.0,
    ):
        self.db = db
        self.cap_usd = cap_usd
        self.prices = dict(prices or DEFAULT_USD_PER_M_INPUT)
        self.stop = stop or threading.Event()
        self.clock = clock
        self.wait_seconds = wait_seconds
        self._announced = False

    def spent_today(self) -> float:
        return self.db.scout_spend(pacific_day(self.clock()))

    def stopped(self) -> bool:
        if self.cap_usd is None:
            return False
        cap = _cap_text(self.cap_usd)
        held = self.db.scout_spend_stop()
        if held is not None:
            if held["cap_usd"] == cap:
                return True
            self.db.clear_scout_spend_stop()
            self._announced = False
            log.info("Scout spend cap changed to $%s; Scout model calls resume", cap)
        day = pacific_day(self.clock())
        if self.db.scout_spend(day) >= self.cap_usd:
            self.db.set_scout_spend_stop(cap, day, self.clock())
            return True
        return False

    def before_call(self) -> None:
        """Wait while the cap holds. On shutdown the call fails so the release is retried later."""
        while self.stopped():
            if not self._announced:
                self._announced = True
                log.warning(
                    "Scout spend cap reached: $%.4f spent today of $%.2f. Scout model calls are stopped "
                    "and releases stay queued until HUNTER_SCOUT_DAILY_USD_CAP is set to a new value.",
                    self.spent_today(),
                    self.cap_usd,
                )
            if self.stop.wait(self.wait_seconds):
                raise ScoutModelUnavailable(STOP_REASON)

    def record(self, provider: str, model: str, usage: Usage, *, state=None, questions=None) -> float:
        """Add one successful call. When the API reports no input tokens, the local estimate is used."""
        input_tokens = int(usage.input_tokens)
        estimated = False
        if input_tokens <= 0 and state is not None:
            try:
                input_tokens = predict_input_tokens(state, questions)
            except (TypeError, ValueError):
                blob = json.dumps({"state": state, "questions": questions}, sort_keys=True, default=str)
                input_tokens = estimate_tokens(blob)
            estimated = True
        price = self.prices.get(price_key(provider, model), 0.0)
        usd = input_tokens / 1_000_000 * price
        self.db.add_scout_usage(
            day=pacific_day(self.clock()),
            provider=provider,
            model=model,
            input_tokens=input_tokens,
            output_tokens=int(usage.output_tokens),
            usd=usd,
            estimated=estimated,
            when=self.clock(),
        )
        return usd

    def health(self) -> dict:
        return {
            "scout_spend_today_usd": round(self.spent_today(), 6),
            "scout_spend_cap_usd": self.cap_usd,
            "scout_spend_stopped": self.stopped(),
        }
