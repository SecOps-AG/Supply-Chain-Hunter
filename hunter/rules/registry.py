"""Load the rule pack once per process and check every rule's meta."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from .scope import expand

RULE_DIR = Path(__file__).resolve().parent
YAR_DIR = RULE_DIR / "yar"
PROMOTED_PATH = RULE_DIR / "promoted.json"

TIERS = {"weak", "info"}
# "both" means npm and PyPI. "actions" rules read only GitHub Actions releases,
# and an Actions release reads every rule, since an action's code is JS, Python or shell.
ECOS = {"npm", "pypi", "both", "actions"}
ACTIONS_ECOSYSTEM = "github-actions"
# An Open VSX extension is JavaScript with a package.json, so it reads the npm rules.
OPENVSX_ECOSYSTEM = "openvsx"
COMMENTS = {"count", "skip"}
NEWNESS = {"bytes", "rule"}
CONFIRMERS = {"public_ip_url"}
META_KEYS = {"tier", "scope", "eco", "comments", "newness", "confirm", "summary"}
FLOOR_LEVELS = {"review", "alert"}


@dataclass(frozen=True)
class RuleSpec:
    id: str
    tier: str
    scope: frozenset[str]
    eco: str
    summary: str
    comments: str = "count"
    newness: str = "bytes"
    confirm: str = ""
    source: str = "yara"

    def reads(self, classes: frozenset[str], ecosystem: str | None) -> bool:
        if not (self.scope & classes):
            return False
        if ecosystem is None or ecosystem == ACTIONS_ECOSYSTEM:
            return True
        if ecosystem == OPENVSX_ECOSYSTEM:
            return self.eco in {"both", "npm"}
        return self.eco == "both" or self.eco == ecosystem


# Rules written in Python (structural.py). Same meta as the YARA rules.
PYTHON_RULES = (
    RuleSpec("h_raw_ip", "weak", expand("code,manifest"), "both",
             "dotted public IPv4 address in code", comments="skip", source="python"),
    RuleSpec("js_hidden_whitespace", "weak", expand("js,bundle"), "npm",
             "code pushed off screen by 400 or more spaces, in a file that calls eval or Function",
             source="python"),
    RuleSpec("py_hidden_whitespace", "weak", expand("py,pth"), "pypi",
             "Python code pushed off screen by 400 or more spaces, in a file that calls exec or eval",
             source="python"),
    RuleSpec("npm_url_dependency", "weak", expand("npm_manifest"), "npm",
             "new dependency fetched from a raw IP, a remote archive, plain http, or a git host", source="python"),
    RuleSpec("npm_phantom_dependency", "weak", expand("npm_manifest"), "npm",
             "new runtime dependency that no file in the package loads", newness="rule", source="python"),
    RuleSpec("utf16_code_file", "weak", expand("code,pth,bundle"), "both",
             "code file that became UTF-16 in this release", source="python"),
    RuleSpec("h_new_host", "info", expand("code,manifest"), "both",
             "URL host not on the allowlist and not in the old file", comments="skip", source="python"),
)


@dataclass(frozen=True)
class RulePack:
    compiled: object
    specs: dict[str, RuleSpec]
    strong: dict[str, str]
    version: str


def _sources() -> list[Path]:
    return sorted(YAR_DIR.glob("*.yar"))


def _spec_from_meta(rule_id: str, meta: dict) -> RuleSpec:
    unknown = set(meta) - META_KEYS
    if unknown:
        raise ValueError(f"rule {rule_id}: unknown meta {sorted(unknown)}")
    for key in ("tier", "scope", "eco", "summary"):
        if not meta.get(key):
            raise ValueError(f"rule {rule_id}: missing meta {key}")
    tier = meta["tier"]
    if tier not in TIERS:
        raise ValueError(f"rule {rule_id}: tier {tier!r} must be weak or info; strong comes from promoted.json")
    if meta["eco"] not in ECOS:
        raise ValueError(f"rule {rule_id}: eco {meta['eco']!r}")
    comments = meta.get("comments", "count")
    if comments not in COMMENTS:
        raise ValueError(f"rule {rule_id}: comments {comments!r}")
    newness = meta.get("newness", "bytes")
    if newness not in NEWNESS:
        raise ValueError(f"rule {rule_id}: newness {newness!r}")
    confirm = meta.get("confirm", "")
    if confirm and confirm not in CONFIRMERS:
        raise ValueError(f"rule {rule_id}: confirm {confirm!r}")
    return RuleSpec(
        id=rule_id,
        tier=tier,
        scope=expand(meta["scope"]),
        eco=meta["eco"],
        summary=meta["summary"],
        comments=comments,
        newness=newness,
        confirm=confirm,
    )


def _load_strong(specs: dict[str, RuleSpec]) -> dict[str, str]:
    """Promoted rules and their floor. A null floor switches a promoted rule back to weak."""
    data = json.loads(PROMOTED_PATH.read_text(encoding="utf-8"))
    strong: dict[str, str] = {}
    for rule_id, entry in (data.get("strong") or {}).items():
        if rule_id not in specs:
            raise ValueError(f"promoted.json names unknown rule {rule_id!r}")
        if not isinstance(entry, dict) or not entry.get("test") or not entry.get("evidence"):
            raise ValueError(f"promoted rule {rule_id!r} needs a test and an evidence link")
        floor = entry.get("floor")
        if floor is None:
            continue
        if floor not in FLOOR_LEVELS:
            raise ValueError(f"promoted rule {rule_id!r}: floor {floor!r}")
        strong[rule_id] = floor
    return strong


def compile_sources(*, error_on_warning: bool = True):
    import yara

    return yara.compile(
        filepaths={path.stem: str(path) for path in _sources()},
        error_on_warning=error_on_warning,
    )


def pack_version() -> str:
    digest = hashlib.sha256()
    for path in _sources() + [PROMOTED_PATH]:
        digest.update(path.name.encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()[:12]


@lru_cache(maxsize=1)
def load_pack() -> RulePack:
    compiled = compile_sources()
    specs: dict[str, RuleSpec] = {}
    for rule in compiled:
        if rule.identifier in specs:
            raise ValueError(f"duplicate rule id {rule.identifier}")
        specs[rule.identifier] = _spec_from_meta(rule.identifier, dict(rule.meta))
    for spec in PYTHON_RULES:
        if spec.id in specs:
            raise ValueError(f"duplicate rule id {spec.id}")
        specs[spec.id] = spec
    return RulePack(compiled=compiled, specs=specs, strong=_load_strong(specs), version=pack_version())
