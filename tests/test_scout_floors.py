"""Review floors for entrypoint payloads and install sidecars, plus archive prefix alignment."""

import json
from pathlib import Path

from hunter.bands import ALERT_THRESHOLD, REVIEW_FLOOR, REVIEW_THRESHOLD
from hunter.classify import classify_files
from hunter.features import compound_install_payload, entrypoint_payload_change, install_sidecar_change
from hunter.fixtures_io import load_fixture
from hunter.head import BUILTIN_FLOORS, LogisticHead, load_head
from hunter.models import ReleaseMeta
from hunter.patterns import high_entropy_line
from hunter.triage import align_release_trees, diff_trees
from hunter.fake_jev import KeywordJev


ROOT = Path(__file__).resolve().parent / "fixtures"
# A weight file with no floors object (the original Jev head).
PRIOR_HEAD = Path(__file__).resolve().parent / "heads" / "logistic_head_prior.json"


def _entropy(count: int = 220) -> str:
    return "".join(chr(33 + ((index * 17) % 90)) for index in range(count))


def _meta(
    *,
    ecosystem: str = "npm",
    name: str = "widget",
    old_version: str = "1.0.0",
    new_version: str = "1.0.1",
) -> ReleaseMeta:
    return ReleaseMeta(
        ecosystem=ecosystem,
        name=name,
        old_version=old_version,
        new_version=new_version,
        rank=4,
        registry_url="https://example.test/widget",
    )


def _score(old, new, meta=None):
    return classify_files(
        meta=meta or _meta(),
        old_files=old,
        new_files=new,
        jev=KeywordJev(),
        head=load_head(),
    )


def _ordinary() -> str:
    return "function add(a, b) {\n  return a + b;\n}\nmodule.exports = add;\n"


def _head_with_floors(floors: dict) -> LogisticHead:
    payload = json.loads(PRIOR_HEAD.read_text(encoding="utf-8"))
    payload["floors"] = floors
    return LogisticHead(payload)


def test_weight_file_floors_replace_the_built_in_levels():
    meta, old, new, label = load_fixture(ROOT / "npm_entrypoint_swap.json")
    assert label == "review"
    builtin = _score(old, new, meta)
    assert builtin.malice_probability >= REVIEW_FLOOR
    off = dict(BUILTIN_FLOORS)
    off["entrypoint_payload"] = None
    without = classify_files(
        meta=meta,
        old_files=old,
        new_files=new,
        jev=KeywordJev(),
        head=_head_with_floors(off),
    )
    assert "entrypoint_payload" in without.signals
    assert without.malice_probability < REVIEW_FLOOR
    raised = dict(BUILTIN_FLOORS)
    raised["entrypoint_payload"] = 0.91
    high = classify_files(
        meta=meta,
        old_files=old,
        new_files=new,
        jev=KeywordJev(),
        head=_head_with_floors(raised),
    )
    assert high.malice_probability >= 0.91
    same = LogisticHead(json.loads(PRIOR_HEAD.read_text(encoding="utf-8")))
    assert same.floor_level("entrypoint_payload") == REVIEW_FLOOR
    assert same.floor_level("compound_install_payload") == 0.86


def test_entrypoint_swap_floors_to_review_without_a_lifecycle_edit():
    meta, old, new, label = load_fixture(ROOT / "npm_entrypoint_swap.json")
    assert label == "review"
    result = _score(old, new, meta)
    assert "lifecycle_script_edits" not in result.signals
    assert "high_entropy_additions" in result.signals
    assert "entrypoint_payload" in result.signals
    assert "compound_install_payload" not in result.signals
    assert result.band == "review"
    assert REVIEW_FLOOR <= result.malice_probability < ALERT_THRESHOLD


def test_new_main_file_with_entropy_is_an_entrypoint_payload():
    old = {
        "package.json": '{"name":"widget","version":"1.0.0","main":"index.js"}\n',
        "index.js": _ordinary(),
    }
    new = {
        "package.json": '{"name":"widget","version":"1.0.1","main":"bundle.js"}\n',
        "index.js": _ordinary(),
        "bundle.js": _entropy() + "\n",
    }
    result = _score(old, new)
    assert "entrypoint_payload" in result.signals
    assert "lifecycle_script_edits" not in result.signals
    assert result.band == "review"
    assert result.malice_probability >= REVIEW_FLOOR


def test_pypi_module_file_replacement_floors():
    old = {"spellnum.py": "def to_cardinal(value):\n    return str(value)\n"}
    new = {"spellnum.py": _entropy() + "\n"}
    meta = _meta(ecosystem="pypi", name="spellnum", old_version="0.5.12", new_version="0.5.13")
    result = _score(old, new, meta)
    assert "entrypoint_payload" in result.signals
    assert result.band == "review"


def test_declared_export_replacement_is_an_entrypoint_payload():
    body = _ordinary()
    payload = _entropy() + "\n"
    old = {
        "package.json": '{"name":"widget","version":"1.0.0","exports":{".":{"import":"./lib/entry.mjs","require":"./lib/entry.cjs"}}}\n',
        "lib/entry.cjs": body,
        "readme.md": "widget\n",
    }
    new = {
        "package.json": '{"name":"widget","version":"1.0.1","exports":{".":{"import":"./lib/entry.mjs","require":"./lib/entry.cjs"}}}\n',
        "lib/entry.cjs": payload,
        "readme.md": "widget\n",
    }
    result = _score(old, new)
    assert "entrypoint_payload" in result.signals
    assert "literal_minified_payload" not in result.signals
    assert "lifecycle_script_edits" not in result.signals
    assert result.band == "review"
    assert result.malice_probability >= REVIEW_FLOOR


def test_pypi_init_replacement_floors_even_under_versioned_prefixes():
    old_body = "def to_cardinal(value):\n    return str(value)\n"
    new_body = _entropy() + "\n"
    old = {"sdist/spellnum-0.5.12/spellnum/__init__.py": old_body}
    new = {"sdist/spellnum-0.5.13/spellnum/__init__.py": new_body}
    meta = _meta(ecosystem="pypi", name="spellnum", old_version="0.5.12", new_version="0.5.13")
    result = _score(old, new, meta)
    assert "entrypoint_payload" in result.signals
    assert "lifecycle_script_edits" not in result.signals
    assert result.band == "review"
    assert result.malice_probability >= REVIEW_FLOOR


def test_short_entropy_token_on_a_grown_entrypoint_does_not_floor():
    token = _entropy(50)
    assert high_entropy_line(token)
    assert len(token) < 180
    padding = "// ordinary comment line for a normal release\n" * 8
    old = {
        "index.js": _ordinary(),
        "package.json": '{"name":"widget","version":"1.0.0","main":"index.js"}\n',
    }
    new = {
        "index.js": _ordinary() + padding + token + "\n",
        "package.json": '{"name":"widget","version":"1.0.1","main":"index.js"}\n',
    }
    assert len(new["index.js"]) >= len(old["index.js"]) + 180
    result = _score(old, new)
    assert "high_entropy_additions" in result.signals
    assert "entrypoint_payload" not in result.signals
    assert result.band == "benign"


def test_editing_an_already_minified_entrypoint_does_not_floor():
    blob = _entropy() + "\n"
    assert len(blob.strip()) >= 180
    old = {
        "index.js": blob,
        "package.json": '{"name":"widget","version":"1.0.0","main":"index.js"}\n',
    }
    new = {
        "index.js": blob + _entropy() + "\n",
        "package.json": '{"name":"widget","version":"1.0.1","main":"index.js"}\n',
    }
    result = _score(old, new)
    assert "entrypoint_payload" not in result.signals
    assert result.band == "benign"


def test_small_entropy_token_on_a_stable_entrypoint_does_not_floor():
    token = _entropy(50)
    assert high_entropy_line(token)
    assert len(token) < 180
    old = {"index.js": _ordinary(), "package.json": '{"name":"widget","version":"1.0.0","main":"index.js"}\n'}
    new = {
        "index.js": _ordinary() + token + "\n",
        "package.json": '{"name":"widget","version":"1.0.1","main":"index.js"}\n',
    }
    result = _score(old, new)
    assert "high_entropy_additions" in result.signals
    assert "entrypoint_payload" not in result.signals
    assert result.band == "benign"
    assert result.malice_probability < REVIEW_THRESHOLD


def test_minified_side_file_is_not_an_entrypoint_floor():
    old = {"index.js": _ordinary()}
    new = {"index.js": _ordinary(), "payload.js": _entropy() + "\n"}
    result = _score(old, new)
    assert "literal_minified_payload" in result.signals
    assert "entrypoint_payload" not in result.signals
    assert result.band == "benign"


def test_install_sidecar_floors_when_compound_payload_is_false():
    meta, old, new, _label = load_fixture(ROOT / "npm_install_sidecar.json")
    assert compound_install_payload(old, new) is False
    result = _score(old, new, meta)
    assert "lifecycle_script_edits" in result.signals
    assert "install_sidecar" in result.signals
    assert "binary_media_change" in result.signals
    assert "compound_install_payload" not in result.signals
    assert result.band == "review"
    assert REVIEW_FLOOR <= result.malice_probability < ALERT_THRESHOLD


def test_new_install_file_floors_without_a_binary():
    old = {
        "package.json": '{"name":"widget","version":"1.0.0","main":"index.js"}\n',
        "index.js": _ordinary(),
    }
    new = {
        "package.json": '{"name":"widget","version":"1.0.1","main":"index.js","scripts":{"install":"node install.js"}}\n',
        "index.js": _ordinary(),
        "install.js": "function ready() {\n  return true;\n}\n",
    }
    result = _score(old, new)
    assert compound_install_payload(old, new) is False
    assert "binary_media_change" not in result.signals
    assert "install_sidecar" in result.signals
    assert result.band == "review"


def test_native_rebuild_with_new_binaries_does_not_floor():
    old = {
        "package.json": '{"name":"widget","version":"1.0.0"}\n',
        "index.js": _ordinary(),
    }
    new = {
        "package.json": '{"name":"widget","version":"1.0.1","scripts":{"install":"node-gyp-build"}}\n',
        "index.js": _ordinary(),
        "prebuilds/linux-x64/addon.bin": "marker-bytes\n",
    }
    result = _score(old, new)
    assert "binary_media_change" in result.signals
    assert "install_sidecar" not in result.signals
    assert result.band == "benign"


def test_native_rebuild_that_also_names_a_new_script_still_floors():
    old = {
        "package.json": '{"name":"widget","version":"1.0.0"}\n',
        "index.js": _ordinary(),
    }
    new = {
        "package.json": '{"name":"widget","version":"1.0.1","scripts":{"install":"node-gyp-build && node install.js"}}\n',
        "index.js": _ordinary(),
        "install.js": "function ready() {\n  return true;\n}\n",
        "prebuilds/linux-x64/addon.bin": "marker-bytes\n",
    }
    result = _score(old, new)
    assert "install_sidecar" in result.signals
    assert result.band == "review"


def test_binary_change_with_a_lifecycle_edit_floors_without_a_new_script():
    old = {
        "package.json": '{"name":"widget","version":"1.0.0"}\n',
        "index.js": _ordinary(),
    }
    new = {
        "package.json": '{"name":"widget","version":"1.0.1","scripts":{"install":"node -e \\"process.exit(0)\\""}}\n',
        "index.js": _ordinary(),
        "addon.bin": "marker-bytes\n",
    }
    result = _score(old, new)
    assert "install_sidecar" in result.signals
    assert "compound_install_payload" not in result.signals
    assert result.band == "review"


def test_existing_install_script_without_a_binary_does_not_floor():
    shared = "function ready() {\n  return true;\n}\n"
    old = {
        "package.json": '{"name":"widget","version":"1.0.0","main":"index.js"}\n',
        "index.js": _ordinary(),
        "install.js": shared,
    }
    new = {
        "package.json": '{"name":"widget","version":"1.0.1","main":"index.js","scripts":{"install":"node install.js"}}\n',
        "index.js": _ordinary(),
        "install.js": shared,
    }
    result = _score(old, new)
    assert "lifecycle_script_edits" in result.signals
    assert "install_sidecar" not in result.signals
    assert result.band == "benign"
    assert result.malice_probability < REVIEW_THRESHOLD


def test_sdist_version_prefix_does_not_make_unchanged_files_added():
    meta, old, new, label = load_fixture(ROOT / "pypi_sdist_prefix.json")
    assert label == "benign"
    raw = diff_trees(old, new)
    assert any(item.path.endswith("data.py") for item in raw)
    assert any("0.5.12" in item.path or "0.5.13" in item.path for item in raw)
    aligned_old, aligned_new = align_release_trees(
        old,
        new,
        ecosystem=meta.ecosystem,
        name=meta.name,
        old_version=meta.old_version,
        new_version=meta.new_version,
    )
    aligned = diff_trees(aligned_old, aligned_new)
    assert aligned
    assert {item.path for item in aligned} == {"sdist/setup.py"}
    assert all("STABLE" not in item.added_text and "STABLE" not in item.new_text for item in aligned)
    assert entrypoint_payload_change(aligned_old, aligned_new, meta) is False
    result = _score(old, new, meta)
    assert "high_entropy_additions" not in result.signals
    assert "entrypoint_payload" not in result.signals
    assert "literal_minified_payload" not in result.signals
    assert result.band == "benign"
    assert "pass_a_gate" in result.signals


def test_npm_package_wrapper_is_stripped_when_only_one_side_has_it():
    payload = _entropy() + "\n"
    old = {
        "package/package.json": '{"name":"widget","version":"1.0.0","main":"index.js"}\n',
        "package/index.js": payload,
    }
    new = {
        "package.json": '{"name":"widget","version":"1.0.1","main":"index.js"}\n',
        "index.js": payload,
    }
    meta = _meta()
    aligned_old, aligned_new = align_release_trees(
        old,
        new,
        ecosystem="npm",
        name="widget",
        old_version="1.0.0",
        new_version="1.0.1",
    )
    diffs = diff_trees(aligned_old, aligned_new)
    assert all(not item.path.endswith("index.js") for item in diffs)
    result = _score(old, new, meta)
    assert "entrypoint_payload" not in result.signals
    assert "high_entropy_additions" not in result.signals
    assert result.band == "benign"


def test_real_edit_under_mismatched_sdist_prefixes_is_still_visible():
    marker = "STABLE_BLOB"
    old = {
        "spellnum-0.5.12/spellnum/__init__.py": "def to_cardinal(value):\n    return str(value)\n",
        "spellnum-0.5.12/spellnum/data.py": marker + "\n" + _entropy() + "\n",
        "spellnum-0.5.12/setup.py": "from setuptools import setup\nsetup(name='spellnum')\n",
    }
    new = {
        "spellnum-0.5.13/spellnum/__init__.py": (
            "def to_cardinal(value):\n    return str(value)\n"
            "eval(__import__('base64').b64decode('bm9uZQ=='))\n"
        ),
        "spellnum-0.5.13/spellnum/data.py": marker + "\n" + _entropy() + "\n",
        "spellnum-0.5.13/setup.py": "from setuptools import setup\nsetup(name='spellnum')\n",
    }
    meta = _meta(ecosystem="pypi", name="spellnum", old_version="0.5.12", new_version="0.5.13")
    aligned_old, aligned_new = align_release_trees(
        old,
        new,
        ecosystem="pypi",
        name="spellnum",
        old_version="0.5.12",
        new_version="0.5.13",
    )
    diffs = diff_trees(aligned_old, aligned_new)
    assert any("b64decode" in item.added_text for item in diffs)
    assert all(marker not in item.path and marker not in item.added_text for item in diffs)
    assert all("0.5.12" not in item.path and "0.5.13" not in item.path for item in diffs)
    result = _score(old, new, meta)
    assert "literal_decode_exec" in result.signals
    assert "pass_a_gate" not in result.signals
    assert result.needs_llm_review


def test_unrelated_single_directory_is_not_stripped():
    old = {"src/index.js": _ordinary(), "backup-1.0.1/notes.py": "x = 1\n"}
    new = {"src/index.js": _ordinary() + "// note\n", "backup-1.0.1/notes.py": "x = 1\n"}
    # backup-1.0.1 is not the only top-level directory, and src is not a version wrapper.
    aligned_old, aligned_new = align_release_trees(
        {"src/index.js": _ordinary()},
        {"src/index.js": _ordinary() + "// note\n"},
        ecosystem="npm",
        name="widget",
        old_version="1.0.0",
        new_version="1.0.1",
    )
    assert "src/index.js" in aligned_old
    assert "src/index.js" in aligned_new
    kept_old, kept_new = align_release_trees(
        old,
        new,
        ecosystem="pypi",
        name="spellnum",
        old_version="0.5.12",
        new_version="0.5.13",
    )
    assert "backup-1.0.1/notes.py" in kept_old
    assert "src/index.js" in kept_new


def test_pypi_does_not_strip_a_directory_named_package():
    files = {"package/__init__.py": "x = 1\n"}
    aligned, _same = align_release_trees(
        files,
        files,
        ecosystem="pypi",
        name="package",
        old_version="1.0.0",
        new_version="1.0.1",
    )
    assert "package/__init__.py" in aligned


def test_sidecar_helper_ignores_a_lifecycle_edit_below_one():
    old = {"index.js": _ordinary()}
    new = {"index.js": _ordinary(), "addon.bin": "marker-bytes\n"}
    assert (
        install_sidecar_change(old, new, lifecycle_edits=0, binary_media_changes=1) is False
    )
