"""RubyGems monitoring: poll timeframe versions and review each ruby-platform release.

A release is a ``.gem`` file. Hunter diffs its library code and install-hook
fields against the previous ruby-platform version. Scout reads a release only
when a rule hit and ``HUNTER_RUBYGEMS_SCOUT`` is on. Nothing in the gem is
installed or run.

Release identity in the shared tables: ecosystem ``rubygems``, the published
name, and the version number (no platform suffix).
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

ECOSYSTEM = "rubygems"
REGISTRY = "https://rubygems.org"
_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]{0,127}$")


def valid_name(name: str) -> bool:
    """True when ``name`` is safe to put in a RubyGems URL."""
    return bool(_NAME.match(name or "")) and ".." not in (name or "")


def valid_version(version: str) -> bool:
    """True when ``version`` is a version number with no platform suffix tricks."""
    return bool(_VERSION.match(version or "")) and ".." not in (version or "")


def registry_url(name: str, version: str) -> str:
    """Public RubyGems page for one version."""
    return f"{REGISTRY}/gems/{name}/versions/{version}"


def allowed_gem_url(url: str) -> bool:
    """True for an https gem download on rubygems.org and nowhere else."""
    if not url or any(ord(char) <= 32 or ord(char) == 127 for char in url):
        return False
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.netloc != "rubygems.org":
        return False
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        return False
    path = parsed.path
    if ".." in path or not path.endswith(".gem"):
        return False
    return path.startswith("/gems/") or path.startswith("/downloads/")
