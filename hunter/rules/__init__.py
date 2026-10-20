"""Deterministic rule pack that reads each release diff before Jev.

Rules read package files as static text. Nothing in a package is imported, installed or run.
HUNTER_RULES=on turns the pack on in the classifier; it is off by default.
"""

from __future__ import annotations

import logging
import os

from .engine import scan_release
from .registry import load_pack, pack_version

RULE_PACK_VERSION = pack_version()
log = logging.getLogger(__name__)


def rules_enabled() -> bool:
    raw = os.environ.get("HUNTER_RULES", "off").strip().lower()
    if raw in ("", "off", "0", "false", "no"):
        return False
    if raw in ("on", "1", "true", "yes"):
        return True
    log.error("HUNTER_RULES=%r is not on or off; the rule pack stays off", raw)
    return False


__all__ = ["RULE_PACK_VERSION", "load_pack", "rules_enabled", "scan_release"]
