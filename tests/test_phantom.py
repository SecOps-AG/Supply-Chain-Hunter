import json
from datetime import datetime, timezone

from hunter.bands import PHANTOM_REVIEW_FLOOR
from hunter.classify import classify_files
from hunter.features import phantom_runtime_dependencies
from hunter.fixtures_io import load_fixture
from hunter.head import load_head
from hunter.jev import JevUnavailable
from hunter.models import ReleaseMeta
from pathlib import Path

from hunter.fake_jev import KeywordJev


ROOT = Path(__file__).resolve().parents[1] / "fixtures"


def _score(name: str, jev=None):
    meta, old_files, new_files, _label = load_fixture(ROOT / name)
    return classify_files(
        meta=meta,
        old_files=old_files,
        new_files=new_files,
        jev=jev or KeywordJev(),
        head=load_head(),
    )


def test_manifest_only_phantom_is_high_review_when_prepare_script_is_removed():
    result = _score("npm_phantom_manifest.json")
    assert any(item.startswith("phantom_runtime_dependency:codec-pad") for item in result.signals)
    assert result.band == "review"
    assert result.malice_probability >= PHANTOM_REVIEW_FLOOR
    assert result.attack_family == "dependency_abuse"
    assert result.subtype == "new_unrelated"


def test_manifest_only_phantom_without_script_edits_is_still_high_review():
    meta, old_files, new_files, _label = load_fixture(ROOT / "npm_phantom_manifest.json")
    old = dict(old_files)
    new = dict(new_files)
    old["package/package.json"] = json.dumps(
        {
            "name": "widget-http",
            "version": "0.30.3",
            "main": "index.js",
            "dependencies": {"follow-hops": "^1.0.0"},
        }
    )
    new["package/package.json"] = json.dumps(
        {
            "name": "widget-http",
            "version": "0.30.4",
            "main": "index.js",
            "dependencies": {"follow-hops": "^1.0.0", "codec-pad": "^4.2.1"},
        }
    )
    meta = ReleaseMeta(
        ecosystem="npm",
        name="widget-http",
        old_version="0.30.3",
        new_version="0.30.4",
        new_time=datetime(2026, 3, 31, tzinfo=timezone.utc),
    )
    result = classify_files(meta=meta, old_files=old, new_files=new, jev=KeywordJev(), head=load_head())
    assert phantom_runtime_dependencies(old, new) == ["codec-pad"]
    assert result.band == "review"
    assert result.malice_probability >= PHANTOM_REVIEW_FLOOR


def test_imported_new_dependency_stays_benign():
    result = _score("npm_benign_import.json")
    assert result.band == "benign"
    assert not any(item.startswith("phantom_runtime_dependency") for item in result.signals)


def test_dropper_dependency_alerts_from_install_hook_and_obfuscation():
    result = _score("npm_child_dropper.json")
    assert result.band == "alert"
    assert result.malice_probability >= 0.70


class Down:
    def system_one(self, state, questions):
        raise JevUnavailable("timeout")


def test_jev_timeout_does_not_alert_on_scattered_literals():
    meta = ReleaseMeta(ecosystem="npm", name="widget", new_version="1.0.1", old_version="1.0.0")
    old = {"package/index.js": "function add(a, b) { return a + b; }\n"}
    new = {
        "package/index.js": "function add(a, b) { return a + b; }\nconst token = process.env.NPM_TOKEN;\n",
        "package/package.json": '{"name":"widget","version":"1.0.1","scripts":{"postinstall":"echo hi"}}\n',
    }
    result = classify_files(meta=meta, old_files=old, new_files=new, jev=Down(), head=load_head())
    assert result.band == "deferred"
    assert "static_rule" not in result.signals
    assert "jev_retry" in result.signals
    assert result.defer_reason.startswith("jev_pass_")


def test_jev_timeout_on_a_quiet_release_is_deferred():
    result = _score("npm_version_bump.json", jev=Down())
    assert result.band == "deferred"
    assert "static_rule" not in result.signals
    assert "jev_retry" in result.signals
