"""Process environment for the long-running watcher."""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from hunter import JEV_MODEL_ID
from hunter.clef import DEFAULT_CLEF_MODEL, resolve_clef_model
from hunter.luna import DEFAULT_LUNA_MODEL, resolve_luna_model
from hunter.jev import resolve_jev_base_url, resolve_jev_model
from hunter.llm import (
    CURSOR_BACKEND,
    DEFAULT_MAX_OUTPUT_TOKENS,
    DEFAULT_MAX_PROMPT_CHARS,
    OPENROUTER_BACKEND,
    normalize_backend,
)
from hunter.scout_model import DEFAULT_SCOUT_MODEL, scout_model_from_env
from hunter.spend import DEFAULT_USD_PER_M_INPUT, cap_from_env, prices_from_env

# Mid-tier, balanced model (Triage) for the Cursor CLI backend when HUNTER_SMART_MODEL is unset.
# The HTTP backends, including OpenRouter, have no default; set HUNTER_SMART_MODEL for them.
DEFAULT_SMART_MODEL = "composer-2.5"
# Immediate classification webhook requires an alert at least this malicious.
# Lower alerts are handled like reviews. Override with ALERT_WEBHOOK_MIN_PROBABILITY.
ALERT_WEBHOOK_MIN_PROBABILITY = 0.80
DEFAULT_FEED_TITLE = "Supply Chain Hunter alerts"
DEFAULT_FEED_LIMIT = 200
DEFAULT_FEED_CACHE_MAX_AGE = 60
MAX_FEED_LIMIT = 1000
MAX_FEED_CACHE_MAX_AGE = 86400


def escalate_uncertain_budget_from_env() -> int | None:
    """Cap for a future uncertain-to-Analyst path. Unset means 5. Zero means unlimited.

    The flag that would spend this cap defaults off. Teach runs do not post anywhere.
    """
    raw = os.environ.get("HUNTER_ESCALATE_UNCERTAIN_BUDGET")
    if raw is None or not raw.strip():
        return 5
    return _budget("HUNTER_ESCALATE_UNCERTAIN_BUDGET")


def scout_teach_budget_from_env() -> int | None:
    """Lifetime cap for the offline Scout teacher. Unset means 5. Zero means unlimited."""
    raw = os.environ.get("HUNTER_SCOUT_TEACH_BUDGET")
    if raw is None or not raw.strip():
        return 5
    return _budget("HUNTER_SCOUT_TEACH_BUDGET")


def _budget(*names: str) -> int | None:
    """Positive cap, or None when unset or 0 (unlimited). The first set name wins."""
    raw = None
    for name in names:
        candidate = os.environ.get(name)
        if candidate is not None and candidate.strip():
            raw = candidate
            break
    if raw is None:
        return None
    try:
        value = int(raw.strip())
    except ValueError:
        return None
    if value <= 0:
        return None
    return value


def analyst_slug_allowed(model: str, allow_fast: bool = False) -> bool:
    """True when a Cursor agent CLI slug is non-empty and not a fast variant.

    OpenRouter model ids are not checked here. A selected OpenRouter id is used
    as given, even when it contains ``fast`` or ``flash``.
    """
    slug = (model or "").strip()
    if not slug:
        return False
    if "fast" in slug.lower() and not allow_fast:
        return False
    return True


def webhook_headers_from_env(raw: str | None = None) -> dict[str, str]:
    """Extra alert webhook headers from ALERT_WEBHOOK_HEADERS, a JSON object.

    A value that is not a JSON object of strings stops startup, so a typo does
    not silently drop an Authorization header.
    """
    value = os.environ.get("ALERT_WEBHOOK_HEADERS", "") if raw is None else raw
    if not value.strip():
        return {}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError(f"ALERT_WEBHOOK_HEADERS is not valid JSON: {exc.msg}") from exc
    if not isinstance(parsed, dict) or not all(
        isinstance(key, str) and isinstance(item, str) for key, item in parsed.items()
    ):
        raise ValueError('ALERT_WEBHOOK_HEADERS must be a JSON object of strings, like {"Authorization": "Bearer ..."}')
    return dict(parsed)


def normalize_feed_base_url(raw: str | None) -> str:
    """HTTPS origin with no path and no userinfo, or empty when it cannot be public.

    The R2 S3 API host is not a reader URL. An unusable value turns publishing off.
    """
    value = (raw or "").strip().rstrip("/")
    if not value:
        return ""
    parsed = urlparse(value)
    if parsed.scheme != "https" or parsed.username or parsed.password:
        return ""
    if parsed.query or parsed.fragment or parsed.path:
        return ""
    host = (parsed.hostname or "").lower()
    if not host or host.endswith(".r2.cloudflarestorage.com"):
        return ""
    return value


def _feed_token(name: str, allowed: str) -> str:
    """One R2 label made only of the allowed characters. Empty when it is unsafe."""
    value = os.environ.get(name, "").strip()
    if not value or any(char not in allowed for char in value):
        return ""
    return value


def _feed_secret(name: str) -> str:
    """Secret with no whitespace. Slashes are kept; R2 secrets may contain them."""
    value = os.environ.get(name, "").strip()
    if not value or any(char.isspace() for char in value):
        return ""
    return value


def _feed_limit_from_env() -> int:
    raw = os.environ.get("HUNTER_FEED_LIMIT")
    if raw is None or not raw.strip():
        return DEFAULT_FEED_LIMIT
    try:
        value = int(raw.strip())
    except ValueError:
        return DEFAULT_FEED_LIMIT
    if value < 1:
        return DEFAULT_FEED_LIMIT
    return min(value, MAX_FEED_LIMIT)


def _feed_cache_max_age_from_env() -> int:
    raw = os.environ.get("HUNTER_FEED_CACHE_MAX_AGE")
    if raw is None or not raw.strip():
        return DEFAULT_FEED_CACHE_MAX_AGE
    try:
        value = int(raw.strip())
    except ValueError:
        return DEFAULT_FEED_CACHE_MAX_AGE
    if value < 0:
        return DEFAULT_FEED_CACHE_MAX_AGE
    return min(value, MAX_FEED_CACHE_MAX_AGE)


def _feed_title_from_env() -> str:
    raw = os.environ.get("HUNTER_FEED_TITLE", "")
    cleaned = "".join(" " if ord(char) < 32 or ord(char) == 127 else char for char in raw)
    return " ".join(cleaned.split()) or DEFAULT_FEED_TITLE


# Most-used GitHub Actions, by dependent repositories (ecosyste.ms).
ACTIONS_TOP_URL = "https://packages.ecosyste.ms/api/v1/registries/github%20actions/packages"
OSV_API = "https://api.osv.dev"
GROUND_TRUTH_REPO = "https://github.com/ossf/malicious-packages.git"


def _ground_truth_source_from_env() -> str:
    value = os.environ.get("HUNTER_GROUND_TRUTH_SOURCE", "").strip().lower()
    return value if value in {"api", "git"} else "api"


# Official MCP server registry. It asks aggregators to poll about once an hour.
MCP_REGISTRY_URL = "https://registry.modelcontextprotocol.io"
OPENVSX_URL = "https://open-vsx.org"


def _flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _name_list(name: str) -> tuple[str, ...]:
    """Comma or space separated ``owner/repo`` names, lower case, in order, without repeats."""
    found: list[str] = []
    for part in os.environ.get(name, "").replace(",", " ").split():
        text = part.strip().lower()
        if text.count("/") == 1 and text not in found:
            found.append(text)
    return tuple(found)


def _unit_interval(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    if value < 0.0 or value > 1.0:
        return default
    return value


@dataclass
class Config:
    db_path: Path = Path("hunter.sqlite3")
    top_n: int = 15000
    poll_interval: float = 300.0
    watchlist_refresh: float = 6 * 3600
    # Each worker can have an old and a new sdist and wheel open at once.
    # Four is the overlap a production host handled well. Eight held too many
    # archives at the same time. Set HUNTER_WORKERS to change it.
    workers: int = 4
    webhook_url: str = ""
    webhook_secret: str = ""
    webhook_headers: dict[str, str] = field(default_factory=dict)
    webhook_on_review: bool = False
    bind: str = "127.0.0.1"
    port: int = 8080
    scout_model: str = DEFAULT_SCOUT_MODEL
    clef_model: str = DEFAULT_CLEF_MODEL
    luna_model: str = DEFAULT_LUNA_MODEL
    scout_daily_usd_cap: float | None = None
    scout_prices: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_USD_PER_M_INPUT))
    jev_model: str = JEV_MODEL_ID
    jev_base_url: str = ""
    jev_retries: int = 5
    classify_batch: int = 25
    investigate_batch: int = 20
    outbox_batch: int = 50
    classify_cycle_cap: int = 100
    ai_max_attempts: int = 5
    skip_pypi: bool = False
    skip_npm: bool = False
    npm_top_n: int = 0
    max_pending: int = 2000
    webhook_format: str = "json"
    webhook_min_probability: float = ALERT_WEBHOOK_MIN_PROBABILITY
    webhook_on_phantom: bool = False
    inspect_dependencies: bool = True
    dep_inspect_limit: int = 3
    smart_analysis: bool = True
    # Backend and model for the mid-tier, balanced model (Triage). Env: HUNTER_SMART_*.
    smart_backend: str = "cursor"
    smart_model: str = DEFAULT_SMART_MODEL
    smart_base_url: str = ""
    smart_api_key: str = field(default="", repr=False)
    # Frontier model (Analyst) backend, base URL, and key. Empty means the same as Triage.
    # Env names stay HUNTER_ANALYST_*.
    analyst_backend: str = ""
    analyst_base_url: str = ""
    analyst_api_key: str = field(default="", repr=False)
    model_max_prompt_chars: int = DEFAULT_MAX_PROMPT_CHARS
    model_max_output_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS
    investigate_url: str = ""
    investigate_secret: str = ""
    investigate_command: str = ""
    investigate_timeout: float = 300.0
    # Analyst reads the same workspace diff as Triage but takes longer on big releases.
    analyst_timeout: float = 900.0
    # Frontier model (Analyst). Env: HUNTER_ANALYST, HUNTER_ANALYST_MODEL.
    analyst: bool = True
    analyst_model: str = ""
    analyst_command: str = ""
    analyst_allow_fast: bool = False
    triage_budget: int | None = None
    analyst_budget: int | None = None
    triage_lessons: str = ""
    scout_lessons: str = ""
    scout_lessons_apply: bool = False
    scout_teach_budget: int | None = 5
    # Offline design only. serve does not escalate, and this never posts an alert.
    escalate_uncertain: bool = False
    escalate_uncertain_budget: int | None = 5
    feed_public_base_url: str = ""
    feed_r2_account_id: str = ""
    feed_r2_bucket: str = ""
    feed_r2_access_key_id: str = field(default="", repr=False)
    feed_r2_secret_access_key: str = field(default="", repr=False)
    feed_limit: int = DEFAULT_FEED_LIMIT
    feed_cache_max_age: int = DEFAULT_FEED_CACHE_MAX_AGE
    feed_title: str = DEFAULT_FEED_TITLE
    # Public dashboard JSON on the feed R2 bucket (HUNTER_DASH_PUBLISH, HUNTER_DASH_PUBLIC_BASE_URL).
    dash_publish: bool = False
    dash_public_base_url: str = ""
    # Dashboard: benchmark results folder (HUNTER_BENCH_DIR, unset means no Benchmark data)
    # and an optional bearer token for /api/* (HUNTER_DASHBOARD_TOKEN).
    bench_dir: str = ""
    dashboard_token: str = field(default="", repr=False)
    # GitHub Actions monitoring (HUNTER_ACTIONS). Off by default. A token is optional:
    # without one, tags are read over git smart HTTP and the package-repo source is skipped.
    actions: bool = False
    github_token: str = field(default="", repr=False)
    actions_top_n: int = 3000
    actions_max: int = 5000
    actions_top_url: str = ACTIONS_TOP_URL
    actions_extra: tuple[str, ...] = ()
    actions_from_packages: bool = True
    actions_poll_interval: float = 300.0
    actions_poll_workers: int = 8
    actions_sweep_interval: float = 24 * 3600
    actions_watchlist_refresh: float = 7 * 24 * 3600
    # Scout on new action tags (phase 2). Off until the Actions eval says it is ready.
    actions_scout: bool = False
    actions_scout_per_day: int = 100
    # Ground-truth job (HUNTER_GROUND_TRUTH). Off by default. Compares scored releases with
    # OSV MAL- records and npm takedowns; reads JSON only.
    ground_truth: bool = False
    ground_truth_dir: str = ""
    ground_truth_source: str = "api"
    ground_truth_interval: float = 24 * 3600
    ground_truth_days: int = 30
    ground_truth_npm_checks: int = 200
    ground_truth_repo: str = GROUND_TRUTH_REPO
    osv_api: str = OSV_API
    # MCP registry as a watchlist source (HUNTER_MCP_REGISTRY). Off by default. Each
    # server's npm and PyPI packages join the npm and PyPI watch, whatever their rank.
    mcp_registry: bool = False
    mcp_registry_url: str = MCP_REGISTRY_URL
    mcp_poll_interval: float = 3600.0
    # Open VSX extensions through the registry changes feed (HUNTER_OPENVSX). Off by default.
    # Rules read every release; Scout reads a release only when a rule hit and HUNTER_OPENVSX_SCOUT is on.
    openvsx: bool = False
    openvsx_url: str = OPENVSX_URL
    openvsx_poll_interval: float = 300.0
    openvsx_page_size: int = 200
    openvsx_scout: bool = False
    # Account-takeover signals from registry metadata before Scout (HUNTER_TAKEOVER_SIGNALS).
    # Off by default. No model calls; on, the classify queue takes higher scores first.
    takeover_signals: bool = False
    takeover_batch: int = 50
    takeover_dormant_days: int = 365
    takeover_major_jump: int = 2
    takeover_burst_count: int = 5
    takeover_burst_hours: int = 24
    pypi_top_url: str = (
        "https://raw.githubusercontent.com/hugovk/top-pypi-packages/main/"
        "top-pypi-packages-30-days.min.json"
    )
    pypi_base: str = "https://pypi.org/pypi"
    npm_registry: str = "https://registry.npmjs.org"
    npm_changes: str = "https://replicate.npmjs.com"
    npm_page_size: int = 1000

    def feed_configured(self) -> bool:
        """True when every required public-feed setting is present and the base URL is usable."""
        return bool(
            self.feed_public_base_url
            and self.feed_r2_account_id
            and self.feed_r2_bucket
            and self.feed_r2_access_key_id
            and self.feed_r2_secret_access_key
        )

    def dash_configured(self) -> bool:
        """True when dashboard publishing to the feed bucket is enabled and configured."""
        return bool(self.dash_publish and self.feed_configured() and self.dash_public_base_url)

    def scout_model_id(self) -> str:
        if self.scout_model == "clef":
            return self.clef_model
        if self.scout_model == "luna":
            return self.luna_model
        return self.jev_model

    @classmethod
    def from_env(cls) -> Config:
        from hunter.openrouter import resolve_openrouter_api_key, resolve_openrouter_base_url

        smart_backend = normalize_backend(os.environ.get("HUNTER_SMART_BACKEND", CURSOR_BACKEND))
        raw_analyst_backend = os.environ.get("HUNTER_ANALYST_BACKEND", "").strip()
        analyst_backend = normalize_backend(raw_analyst_backend) if raw_analyst_backend else ""
        smart_api_key = os.environ.get("HUNTER_SMART_API_KEY", "").strip()
        smart_base_url = os.environ.get("HUNTER_SMART_BASE_URL", "").strip()
        if smart_backend == OPENROUTER_BACKEND:
            smart_api_key = smart_api_key or resolve_openrouter_api_key()
            smart_base_url = resolve_openrouter_base_url(smart_base_url)
        analyst_api_key = os.environ.get("HUNTER_ANALYST_API_KEY", "").strip()
        analyst_base_url = os.environ.get("HUNTER_ANALYST_BASE_URL", "").strip()
        analyst_effective = analyst_backend or smart_backend
        if analyst_effective == OPENROUTER_BACKEND:
            if not analyst_api_key:
                analyst_api_key = resolve_openrouter_api_key() or (
                    smart_api_key if analyst_effective == smart_backend else ""
                )
            if analyst_base_url:
                analyst_base_url = resolve_openrouter_base_url(analyst_base_url)
            elif analyst_effective == smart_backend and smart_base_url:
                analyst_base_url = smart_base_url
            else:
                analyst_base_url = resolve_openrouter_base_url("")
        return cls(
            db_path=Path(os.environ.get("HUNTER_DB", "hunter.sqlite3")),
            top_n=int(os.environ.get("HUNTER_TOP_N", "15000")),
            poll_interval=float(os.environ.get("HUNTER_POLL_INTERVAL", "300")),
            watchlist_refresh=float(os.environ.get("HUNTER_WATCHLIST_REFRESH", str(6 * 3600))),
            workers=int(os.environ.get("HUNTER_WORKERS", "4")),
            webhook_url=os.environ.get("ALERT_WEBHOOK_URL", ""),
            webhook_secret=os.environ.get("ALERT_WEBHOOK_SECRET", ""),
            webhook_headers=webhook_headers_from_env(),
            webhook_on_review=_flag("ALERT_WEBHOOK_ON_REVIEW"),
            bind=os.environ.get("HUNTER_BIND", "127.0.0.1"),
            port=int(os.environ.get("HUNTER_PORT", "8080")),
            scout_model=scout_model_from_env(),
            clef_model=resolve_clef_model(),
            luna_model=resolve_luna_model(),
            scout_daily_usd_cap=cap_from_env(),
            scout_prices=prices_from_env(),
            jev_model=resolve_jev_model(),
            jev_base_url=resolve_jev_base_url(),
            jev_retries=int(os.environ.get("HUNTER_JEV_RETRIES", "5")),
            classify_batch=max(1, int(os.environ.get("HUNTER_CLASSIFY_BATCH", "25"))),
            investigate_batch=max(1, int(os.environ.get("HUNTER_INVESTIGATE_BATCH", "20"))),
            outbox_batch=max(1, int(os.environ.get("HUNTER_OUTBOX_BATCH", "50"))),
            classify_cycle_cap=max(1, int(os.environ.get("HUNTER_CLASSIFY_CYCLE_CAP", "100"))),
            ai_max_attempts=max(1, int(os.environ.get("HUNTER_AI_MAX_ATTEMPTS", "5"))),
            skip_pypi=_flag("HUNTER_SKIP_PYPI"),
            skip_npm=_flag("HUNTER_SKIP_NPM"),
            npm_top_n=int(os.environ.get("HUNTER_NPM_TOP_N", "0")),
            max_pending=int(os.environ.get("HUNTER_MAX_PENDING", "2000")),
            webhook_format=os.environ.get("ALERT_WEBHOOK_FORMAT", "json").strip().lower() or "json",
            webhook_min_probability=_unit_interval(
                "ALERT_WEBHOOK_MIN_PROBABILITY", ALERT_WEBHOOK_MIN_PROBABILITY
            ),
            webhook_on_phantom=_flag("ALERT_WEBHOOK_ON_PHANTOM"),
            inspect_dependencies=not _flag("HUNTER_SKIP_DEP_INSPECT"),
            dep_inspect_limit=int(os.environ.get("HUNTER_DEP_INSPECT_LIMIT", "3")),
            smart_analysis=_flag("HUNTER_SMART_ANALYSIS", default=True),
            smart_backend=smart_backend,
            smart_model=os.environ.get("HUNTER_SMART_MODEL", "").strip()
            or (DEFAULT_SMART_MODEL if smart_backend == CURSOR_BACKEND else ""),
            smart_base_url=smart_base_url,
            smart_api_key=smart_api_key,
            analyst_backend=analyst_backend,
            analyst_base_url=analyst_base_url,
            analyst_api_key=analyst_api_key,
            model_max_prompt_chars=max(
                10_000, int(os.environ.get("HUNTER_MODEL_MAX_PROMPT_CHARS", str(DEFAULT_MAX_PROMPT_CHARS)))
            ),
            model_max_output_tokens=max(
                256, int(os.environ.get("HUNTER_MODEL_MAX_OUTPUT_TOKENS", str(DEFAULT_MAX_OUTPUT_TOKENS)))
            ),
            investigate_url=os.environ.get("HUNTER_INVESTIGATE_URL", ""),
            investigate_secret=os.environ.get("HUNTER_INVESTIGATE_SECRET", ""),
            investigate_command=os.environ.get("HUNTER_INVESTIGATE_COMMAND", ""),
            investigate_timeout=float(os.environ.get("HUNTER_INVESTIGATE_TIMEOUT", "300")),
            analyst_timeout=float(os.environ.get("HUNTER_ANALYST_TIMEOUT", "900")),
            analyst=_flag("HUNTER_ANALYST", default=True),
            analyst_model=os.environ.get("HUNTER_ANALYST_MODEL", "").strip(),
            analyst_command=os.environ.get("HUNTER_ANALYST_COMMAND", ""),
            analyst_allow_fast=_flag("HUNTER_ANALYST_ALLOW_FAST"),
            triage_budget=_budget("HUNTER_TRIAGE_BUDGET", "HUNTER_SMART_BUDGET"),
            analyst_budget=_budget("HUNTER_ANALYST_BUDGET"),
            triage_lessons=os.environ.get("HUNTER_TRIAGE_LESSONS", "").strip(),
            scout_lessons=os.environ.get("HUNTER_SCOUT_LESSONS", "").strip(),
            scout_lessons_apply=_flag("HUNTER_SCOUT_LESSONS_APPLY"),
            scout_teach_budget=scout_teach_budget_from_env(),
            escalate_uncertain=_flag("HUNTER_ESCALATE_UNCERTAIN"),
            escalate_uncertain_budget=escalate_uncertain_budget_from_env(),
            feed_public_base_url=normalize_feed_base_url(os.environ.get("HUNTER_FEED_PUBLIC_BASE_URL")),
            feed_r2_account_id=_feed_token("HUNTER_FEED_R2_ACCOUNT_ID", "0123456789abcdefABCDEF"),
            feed_r2_bucket=_feed_token("HUNTER_FEED_R2_BUCKET", "abcdefghijklmnopqrstuvwxyz0123456789.-"),
            feed_r2_access_key_id=_feed_secret("HUNTER_FEED_R2_ACCESS_KEY_ID"),
            feed_r2_secret_access_key=_feed_secret("HUNTER_FEED_R2_SECRET_ACCESS_KEY"),
            feed_limit=_feed_limit_from_env(),
            feed_cache_max_age=_feed_cache_max_age_from_env(),
            feed_title=_feed_title_from_env(),
            dash_publish=_flag("HUNTER_DASH_PUBLISH"),
            dash_public_base_url=normalize_feed_base_url(os.environ.get("HUNTER_DASH_PUBLIC_BASE_URL")),
            bench_dir=os.environ.get("HUNTER_BENCH_DIR", "").strip(),
            dashboard_token=os.environ.get("HUNTER_DASHBOARD_TOKEN", "").strip(),
            actions=_flag("HUNTER_ACTIONS"),
            github_token=os.environ.get("HUNTER_GITHUB_TOKEN", "").strip(),
            actions_top_n=max(0, int(os.environ.get("HUNTER_ACTIONS_TOP_N", "3000"))),
            actions_max=max(1, int(os.environ.get("HUNTER_ACTIONS_MAX", "5000"))),
            actions_top_url=os.environ.get("HUNTER_ACTIONS_TOP_URL", "").strip() or ACTIONS_TOP_URL,
            actions_extra=_name_list("HUNTER_ACTIONS_EXTRA"),
            actions_from_packages=_flag("HUNTER_ACTIONS_FROM_PACKAGES", default=True),
            actions_poll_interval=max(30.0, float(os.environ.get("HUNTER_ACTIONS_POLL_INTERVAL", "300"))),
            actions_poll_workers=max(1, int(os.environ.get("HUNTER_ACTIONS_POLL_WORKERS", "8"))),
            actions_sweep_interval=max(3600.0, float(os.environ.get("HUNTER_ACTIONS_SWEEP_INTERVAL", str(24 * 3600)))),
            actions_watchlist_refresh=max(
                3600.0, float(os.environ.get("HUNTER_ACTIONS_WATCHLIST_REFRESH", str(7 * 24 * 3600)))
            ),
            actions_scout=_flag("HUNTER_ACTIONS_SCOUT"),
            actions_scout_per_day=max(0, int(os.environ.get("HUNTER_ACTIONS_SCOUT_PER_DAY", "100"))),
            ground_truth=_flag("HUNTER_GROUND_TRUTH"),
            ground_truth_dir=os.environ.get("HUNTER_GROUND_TRUTH_DIR", "").strip(),
            ground_truth_source=_ground_truth_source_from_env(),
            ground_truth_interval=max(
                3600.0, float(os.environ.get("HUNTER_GROUND_TRUTH_INTERVAL", str(24 * 3600)))
            ),
            ground_truth_days=max(0, int(os.environ.get("HUNTER_GROUND_TRUTH_DAYS", "30"))),
            ground_truth_npm_checks=max(0, int(os.environ.get("HUNTER_GROUND_TRUTH_NPM_CHECKS", "200"))),
            ground_truth_repo=os.environ.get("HUNTER_GROUND_TRUTH_REPO", "").strip() or GROUND_TRUTH_REPO,
            osv_api=os.environ.get("HUNTER_OSV_API", "").strip() or OSV_API,
            mcp_registry=_flag("HUNTER_MCP_REGISTRY"),
            mcp_registry_url=os.environ.get("HUNTER_MCP_REGISTRY_URL", "").strip().rstrip("/") or MCP_REGISTRY_URL,
            mcp_poll_interval=max(300.0, float(os.environ.get("HUNTER_MCP_POLL_INTERVAL", "3600"))),
            openvsx=_flag("HUNTER_OPENVSX"),
            openvsx_url=os.environ.get("HUNTER_OPENVSX_URL", "").strip().rstrip("/") or OPENVSX_URL,
            openvsx_poll_interval=max(60.0, float(os.environ.get("HUNTER_OPENVSX_POLL_INTERVAL", "300"))),
            openvsx_page_size=min(1000, max(1, int(os.environ.get("HUNTER_OPENVSX_PAGE_SIZE", "200")))),
            openvsx_scout=_flag("HUNTER_OPENVSX_SCOUT"),
            takeover_signals=_flag("HUNTER_TAKEOVER_SIGNALS"),
            takeover_batch=max(1, int(os.environ.get("HUNTER_TAKEOVER_BATCH", "50"))),
            takeover_dormant_days=max(0, int(os.environ.get("HUNTER_TAKEOVER_DORMANT_DAYS", "365"))),
            takeover_major_jump=max(0, int(os.environ.get("HUNTER_TAKEOVER_MAJOR_JUMP", "2"))),
            takeover_burst_count=max(0, int(os.environ.get("HUNTER_TAKEOVER_BURST_COUNT", "5"))),
            takeover_burst_hours=max(0, int(os.environ.get("HUNTER_TAKEOVER_BURST_HOURS", "24"))),
        )


CURSOR_CLI_MISSING = (
    "Cursor Agent CLI (agent) not found on PATH: install the Cursor CLI, or set "
    "HUNTER_SMART_BACKEND=openai or anthropic with HUNTER_SMART_BASE_URL, "
    "HUNTER_SMART_API_KEY, and HUNTER_SMART_MODEL. "
    "HUNTER_SMART_BACKEND=openrouter is optional and is not the default."
)


def cursor_cli_missing(config: Config) -> bool:
    """True when the mid-tier, balanced model (Triage) would use cursor but agent is not on PATH."""
    if not config.smart_analysis or config.investigate_command or config.investigate_url:
        return False
    if normalize_backend(config.smart_backend) != CURSOR_BACKEND:
        return False
    return shutil.which("agent") is None


def smart_analysis_enabled(config: Config) -> bool:
    """True when the mid-tier, balanced model (Triage) should run."""
    if not config.smart_analysis:
        return False
    if config.investigate_command or config.investigate_url:
        return True
    backend = normalize_backend(config.smart_backend)
    if backend == CURSOR_BACKEND:
        return bool(shutil.which("agent")) or bool(os.environ.get("CURSOR_API_KEY"))
    if backend == OPENROUTER_BACKEND:
        from hunter.openrouter import resolve_openrouter_api_key

        key = (config.smart_api_key or "").strip() or resolve_openrouter_api_key()
        return bool(config.smart_model.strip()) and bool(key)
    # Other HTTP backends need a model name. A key is optional: local servers often have none.
    return bool(config.smart_model.strip())


def active_role_models(config: Config) -> dict:
    """Selected models for the three roles. No secrets.

    The decision model (Scout) is Jev, Clef, or Luna. Luna is the one OpenRouter
    model allowed there: GPT-6 Luna Decisions on OpenRouter's decisions
    endpoint. Other OpenRouter ids are accepted for the mid-tier, balanced model
    (Triage) and the Frontier model (Analyst).
    """
    from hunter.openrouter import openrouter_key_is_set

    triage_backend = normalize_backend(config.smart_backend)
    analyst_backend = normalize_backend(config.analyst_backend) if config.analyst_backend else triage_backend
    triage_key = bool((config.smart_api_key or "").strip()) or (
        openrouter_key_is_set() if triage_backend == OPENROUTER_BACKEND else False
    )
    analyst_key = bool((config.analyst_api_key or "").strip()) or (
        openrouter_key_is_set() if analyst_backend == OPENROUTER_BACKEND else False
    )
    return {
        "decision_model": {
            "label": "decision model",
            "role": "Scout",
            "provider": config.scout_model,
            "model": config.scout_model_id(),
            "openrouter": config.scout_model == "luna",
        },
        "mid_tier_model": {
            "label": "mid-tier, balanced model",
            "role": "Triage",
            "backend": triage_backend,
            "model": config.smart_model,
            "openrouter_key_set": triage_key if triage_backend == OPENROUTER_BACKEND else False,
        },
        "frontier_model": {
            "label": "Frontier model",
            "role": "Analyst",
            "backend": analyst_backend,
            "model": config.analyst_model,
            "openrouter_key_set": analyst_key if analyst_backend == OPENROUTER_BACKEND else False,
        },
    }
