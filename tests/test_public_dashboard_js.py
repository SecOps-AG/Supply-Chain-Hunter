"""Public dashboard page checks: node tests for the replay, and the strict CSP."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DASH = ROOT / "public_dashboard"
JS_TESTS = sorted((ROOT / "tests" / "js").glob("*.test.js"))


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_public_dashboard_node_tests():
    assert JS_TESTS
    result = subprocess.run(
        ["node", "--test", *[str(path) for path in JS_TESTS]],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_page_keeps_strict_csp():
    headers = (DASH / "_headers").read_text(encoding="utf-8")
    csp = re.search(r"Content-Security-Policy: (.+)", headers).group(1)
    assert "script-src 'self';" in csp
    assert "style-src 'self';" in csp
    assert "connect-src 'self' https:" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    html = (DASH / "index.html").read_text(encoding="utf-8")
    scripts = re.findall(r"<script\b([^>]*)>(.*?)</script>", html, re.S)
    assert scripts
    for attrs, body in scripts:
        assert re.search(r'\bsrc="[\w.-]+\.js"', attrs) and not body.strip()
    assert "<style" not in html
    assert not re.search(r"\sstyle=", html)
    assert not re.search(r"\son\w+=", html)
    order = [re.search(r'src="([^"]+)"', attrs).group(1) for attrs, _ in scripts]
    assert order.index("replay.js") < order.index("app.js")
