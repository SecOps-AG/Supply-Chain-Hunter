"""Changed files that wire up code a release added stay in the model context."""

from hunter.triage import (
    FULL_DIFF_CHAR_CAP,
    LINKED_KEEP_LIMIT,
    NEW_TEXT_FILE_BYTES,
    changed_file_manifest,
    diff_trees,
    full_filtered_diff,
    linked_paths,
    ranked_triage_excerpt,
)

INIT_OLD = "VERSION = '1.0'\n__all__ = ['VERSION']\n"


def _kept(old, new):
    return {item.path: item.category for item in diff_trees(old, new)}


def test_new_pth_line_keeps_the_module_it_loads():
    old = {"demo/__init__.py": INIT_OLD, "other/__init__.py": INIT_OLD}
    new = {
        "demo.pth": "import demo\n",
        "demo/__init__.py": INIT_OLD + "LABEL = 'x'\n",
        "other/__init__.py": INIT_OLD + "LABEL = 'y'\n",
    }
    kept = _kept(old, new)
    assert kept["demo/__init__.py"] == "changed_code"
    assert "other/__init__.py" not in kept
    assert "demo.pth" in linked_paths(old, new)["demo/__init__.py"]


def test_pth_submodule_import_keeps_package_init_and_module():
    old = {"demo/__init__.py": INIT_OLD, "demo/sub.py": "A = 1\n"}
    new = {
        "demo.pth": "import os; import demo.sub\n",
        "demo/__init__.py": INIT_OLD + "B = 2\n",
        "demo/sub.py": "A = 1\nB = 2\n",
    }
    assert set(linked_paths(old, new)) == {"demo/__init__.py", "demo/sub.py"}


def test_unchanged_pth_line_links_nothing():
    old = {"demo.pth": "import demo\n", "demo/__init__.py": INIT_OLD}
    new = {"demo.pth": "import demo\n# note\n", "demo/__init__.py": INIT_OLD + "B = 2\n"}
    assert linked_paths(old, new) == {}
    assert "demo/__init__.py" not in _kept(old, new)


def test_modified_file_that_imports_a_new_module_is_kept():
    old = {"lib/core.py": "def main():\n    return 1\n", "lib/misc.py": "X = 1\n"}
    new = {
        "lib/core.py": "from . import helper_mod\n\ndef main():\n    return helper_mod.value()\n",
        "lib/misc.py": "X = 2\n",
        "lib/helper_mod.py": "def value():\n    return 1\n",
    }
    kept = _kept(old, new)
    assert kept["lib/core.py"] == "changed_code"
    assert "lib/misc.py" not in kept
    assert linked_paths(old, new) == {"lib/core.py": "linked_code: uses new module helper_mod"}


def test_modified_file_that_calls_a_new_module_is_kept():
    old = {"app/run.py": "import tools\n"}
    new = {
        "app/run.py": "import tools\nimport importlib\nimportlib.import_module('app.extra_bits').go()\n",
        "app/extra_bits.py": "def go():\n    return None\n",
    }
    assert "app/run.py" in linked_paths(old, new)


def test_js_require_of_a_new_module_is_kept():
    old = {"lib/index.js": "module.exports = {};\n"}
    new = {
        "lib/index.js": "const side = require('./side_part');\nmodule.exports = {};\n",
        "lib/side_part.js": "module.exports = 1;\n",
    }
    assert "lib/index.js" in linked_paths(old, new)


def test_plain_mention_of_a_new_module_name_is_not_a_link():
    old = {"lib/core.py": "X = 1\n"}
    new = {"lib/core.py": "X = 1\n# helper_mod lives next door\n", "lib/helper_mod.py": "Y = 1\n"}
    assert linked_paths(old, new) == {}


def test_release_layout_new_pth_into_existing_package_that_starts_a_new_module():
    # A new .pth imports an existing package; its modified __init__ now starts a module
    # added in the same release. Inert synthetic text only.
    old = {
        "wheel/demo_pkg/__init__.py": INIT_OLD,
        "wheel/demo_pkg-1.0.dist-info/METADATA": "Name: demo-pkg\nVersion: 1.0\n",
    }
    new = {
        "wheel/demo_pkg.pth": "import demo_pkg\n",
        "wheel/demo_pkg/__init__.py": INIT_OLD
        + "\ntry:\n    from . import _probe\n    _probe._start()\nexcept Exception:\n    pass\n",
        "wheel/demo_pkg/_probe.py": "def _start():\n    return None\n",
        "wheel/demo_pkg-1.1.dist-info/METADATA": "Name: demo-pkg\nVersion: 1.1\n",
    }
    kept = _kept(old, new)
    assert kept["wheel/demo_pkg/__init__.py"] == "changed_code"
    assert kept["wheel/demo_pkg.pth"] == "install_scripts"

    manifest = changed_file_manifest(old, new)
    assert "modified included wheel/demo_pkg/__init__.py (linked_code: loaded by new .pth line" in manifest

    full = full_filtered_diff(old, new)
    assert "--- changed_code:wheel/demo_pkg/__init__.py" in full
    assert "_probe._start()" in full

    excerpt = ranked_triage_excerpt(old, new)
    assert "changed_code:wheel/demo_pkg/__init__.py" in excerpt
    assert "_probe._start()" in excerpt


def test_linked_keeps_are_capped_with_pth_targets_first():
    old = {f"pkg/m{n:02}.py": "A = 1\n" for n in range(30)}
    old["zz/__init__.py"] = INIT_OLD
    new = {path: "from pkg import fresh_mod\nA = fresh_mod.get()\n" for path in old if path.startswith("pkg/")}
    new.update({"pkg/fresh_mod.py": "def get():\n    return 1\n", "zz.pth": "import zz\n", "zz/__init__.py": INIT_OLD + "B = 1\n"})
    linked = linked_paths(old, new)
    assert len(linked) == LINKED_KEEP_LIMIT
    assert next(iter(linked)) == "zz/__init__.py"
    kept = _kept(old, new)
    assert sum(1 for category in kept.values() if category == "changed_code") == LINKED_KEEP_LIMIT


def test_linked_files_lead_the_window_and_size_limits_hold():
    # Existing caps are unchanged.
    assert FULL_DIFF_CHAR_CAP == 1_000_000
    assert NEW_TEXT_FILE_BYTES == 16 * 1024
    big_old = "".join(f"console.log({n});\n" for n in range(1500))
    old = {"bin/cli.js": big_old, "demo/__init__.py": INIT_OLD}
    new = {
        "bin/cli.js": big_old.replace("log(", "info("),
        "demo.pth": "import demo\n",
        "demo/__init__.py": INIT_OLD + "from . import part_two\npart_two.go()\n",
        "demo/part_two.py": "def go():\n    return None\n",
    }
    limit = 3_000
    excerpt = ranked_triage_excerpt(old, new, limit_chars=limit)
    assert len(excerpt) <= limit + len("\n[truncated]")
    assert excerpt.index("changed_code:demo/__init__.py") < excerpt.index("entry_points:bin/cli.js")
    full = full_filtered_diff(old, new, limit_chars=limit)
    assert "[TRUNCATION]" in full
    assert len(full.split("\n[TRUNCATION]\n")[0]) <= limit
