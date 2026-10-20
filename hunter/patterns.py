"""Literal signals counted in code. Jev 1.13 is a poor counter, so these stay here."""

from __future__ import annotations

import math
import re
from collections import Counter

DECODE_EXEC = re.compile(
    r"(base64|atob|codecs\.decode|Buffer\.from\([^)\n]{0,80}base64)"
    r".{0,240}(exec|eval|execSync|spawn|Function\()|"
    r"(exec|eval|execSync|Function\().{0,160}(base64|atob|codecs\.decode)",
    re.IGNORECASE | re.DOTALL,
)
SHELL = re.compile(
    r"\b(child_process|execSync|spawnSync|os\.system|subprocess|Popen|check_call|"
    r"Runtime\.getRuntime|curl\s+[^\n]*\|\s*(sh|bash))\b",
    re.IGNORECASE,
)
RAW_IP = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
LOOPBACK = {"127.0.0.1", "0.0.0.0"}
CREDENTIAL = re.compile(
    r"(NPM_TOKEN|NODE_AUTH_TOKEN|AWS_SECRET|AWS_ACCESS_KEY|id_rsa|\.ssh/|"
    r"authorized_keys|credentials\.json|GH_TOKEN|GITHUB_TOKEN|BROWSER_COOKIE)",
    re.IGNORECASE,
)
SSH = re.compile(r"(id_rsa|\.ssh/|authorized_keys)", re.IGNORECASE)
CLOUD = re.compile(r"(AWS_SECRET|AWS_ACCESS_KEY|credentials\.json)", re.IGNORECASE)
ENV_TOKEN = re.compile(r"(NPM_TOKEN|NODE_AUTH_TOKEN|GH_TOKEN|GITHUB_TOKEN|process\.env|os\.environ)", re.IGNORECASE)
XOR = re.compile(
    r"(\bxor\b|charCodeAt\s*\([^)]{0,40}\)\s*\^|fromCharCode\s*\([^)\n]{0,80}\^)",
    re.IGNORECASE,
)
ENCODED_IMPORT = re.compile(
    r"(?:require|import)\s*\(\s*(?:atob|unescape|decodeURIComponent|Buffer\.from)\b"
    r"|(?:require|import)\s*\([^)\n]{0,160}(?:base64|atob)\b",
    re.IGNORECASE,
)
PERSISTENCE = re.compile(
    r"(crontab|cron\.d|/etc/rc\.|/etc/init\.|\.bashrc|\.zshrc|\.bash_profile|\.profile|"
    r"authorized_keys|LaunchAgents|LaunchDaemons|systemd|schtasks|"
    r"CurrentVersion\\Run)",
    re.IGNORECASE,
)
HOST = re.compile(r"https?://([A-Za-z0-9.-]+)", re.IGNORECASE)
ALLOW_HOST_SUFFIXES = (
    "localhost",
    "example.com",
    "example.org",
    "example.net",
    "schema.org",
    "pypi.org",
    "pythonhosted.org",
    "npmjs.com",
    "npmjs.org",
    "github.com",
    "githubusercontent.com",
    "gitlab.com",
    "python.org",
    "nodejs.org",
    "w3.org",
)


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def high_entropy_line(line: str) -> bool:
    stripped = line.strip()
    if len(stripped) < 40:
        return False
    return shannon_entropy(stripped) >= 4.4


def raw_ips(text: str) -> list[str]:
    found = []
    for match in RAW_IP.findall(text):
        if match not in LOOPBACK:
            found.append(match)
    return found


def _host_allowed(host: str) -> bool:
    name = host.lower().rstrip(".")
    if name in LOOPBACK or name.endswith(".local"):
        return True
    return any(name == suffix or name.endswith("." + suffix) for suffix in ALLOW_HOST_SUFFIXES)


def unexpected_hosts(text: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for host in HOST.findall(text or ""):
        name = host.lower().rstrip(".")
        if not name or name in seen or _host_allowed(name):
            continue
        seen.add(name)
        found.append(name)
    return found


def actionable_literal(text: str) -> bool:
    """Hostile literals. High-entropy text alone is not enough inside docs or lockfiles."""
    if not text or not text.strip():
        return False
    if DECODE_EXEC.search(text) or SHELL.search(text) or CREDENTIAL.search(text):
        return True
    if XOR.search(text) or ENCODED_IMPORT.search(text) or PERSISTENCE.search(text):
        return True
    return bool(raw_ips(text) or unexpected_hosts(text))


def looks_suspicious(text: str) -> bool:
    if actionable_literal(text):
        return True
    if not text or not text.strip():
        return False
    return any(high_entropy_line(line) for line in text.splitlines())
