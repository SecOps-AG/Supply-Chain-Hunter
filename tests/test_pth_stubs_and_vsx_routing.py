"""Startup-hook stubs and Open VSX routing. Synthetic inert text only."""

from __future__ import annotations

from hunter.models import ReleaseMeta
from hunter.triage import pth_import_lines


def test_a_stub_prefix_with_more_statements_still_counts():
    cases = {
        "evil-nspkg.pth": "import sys, types, os; import evilmod\n",
        "__editable__.widget-1.0.pth": "import __editable___widget_1_0_finder; import evilmod\n",
        "distutils-precedence.pth": (
            "import os; import evilmod; __import__('_distutils_hack').add_shim(); \n"
        ),
        "_virtualenv.pth": "import _virtualenv ; import evilmod\n",
    }
    for name, text in cases.items():
        assert pth_import_lines(name, text), name


from hunter.openvsx.review import review_trees as vsx_review_trees


def test_openvsx_weak_hit_and_one_medium_signal_routes_without_scout():
    meta = ReleaseMeta(ecosystem="openvsx", name="pub.ext", new_version="1.1.0", old_version="1.0.0", registry_url="")
    new = {"extension/out/new.js": "const m = require(atob(name));\n"}
    row = vsx_review_trees(meta, {}, new, ["vsx_main_changed"], jev=None)
    assert row.rule_verdict != "malicious"
    assert row.rule_hits
    assert row.band == "review"
    assert row.needs_llm_review is True
