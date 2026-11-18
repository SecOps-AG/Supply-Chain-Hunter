"""A PyPI release that ships only a wheel after earlier releases shipped an sdist."""

from __future__ import annotations

from types import SimpleNamespace

from hunter.classify import has_warning_sign
from hunter.features import extract_features, sdist_dropped
from hunter.models import ReleaseMeta
from hunter.risk_score import risk_score

OLD = {
    "sdist/demo-1.0/PKG-INFO": "Name: demo\n",
    "sdist/demo-1.0/demo/__init__.py": "VERSION = '1.0'\n",
    "wheel/demo/__init__.py": "VERSION = '1.0'\n",
    "wheel/demo-1.0.dist-info/METADATA": "Name: demo\n",
}
NEW_WHEEL_ONLY = {
    "wheel/demo/__init__.py": "VERSION = '1.1'\n",
    "wheel/demo-1.1.dist-info/METADATA": "Name: demo\n",
}


def test_fires_when_the_sdist_goes_away():
    assert sdist_dropped(OLD, NEW_WHEEL_ONLY) is True


def test_quiet_when_both_releases_have_an_sdist():
    new = dict(NEW_WHEEL_ONLY)
    new["sdist/demo-1.1/PKG-INFO"] = "Name: demo\n"
    assert sdist_dropped(OLD, new) is False


def test_quiet_when_the_old_release_was_wheel_only_too():
    old = {path: text for path, text in OLD.items() if not path.startswith("sdist/")}
    assert sdist_dropped(old, NEW_WHEEL_ONLY) is False


def test_quiet_on_first_release_and_on_npm_trees():
    assert sdist_dropped({}, NEW_WHEEL_ONLY) is False
    assert sdist_dropped({"package/index.js": "1"}, {"package/index.js": "2"}) is False
    assert sdist_dropped(OLD, {}) is False


def test_signal_reaches_the_row_and_the_risk_score():
    meta = ReleaseMeta("pypi", "demo", "1.1", "1.0")
    code = extract_features(OLD, NEW_WHEEL_ONLY, [], meta)
    assert code.sdist_dropped is True
    assert "sdist_dropped" in code.signal_list()
    assert code.static_hot()
    assert has_warning_sign(["sdist_dropped"])
    score = risk_score(SimpleNamespace(signals=["sdist_dropped"], rule_hits=[], defer_reason=""))
    assert [reason.code for reason in score.why] == ["sdist_dropped"]


def test_no_signal_when_nothing_dropped():
    meta = ReleaseMeta("pypi", "demo", "1.1", "1.0")
    new = dict(NEW_WHEEL_ONLY)
    new["sdist/demo-1.1/PKG-INFO"] = "Name: demo\n"
    assert "sdist_dropped" not in extract_features(OLD, new, [], meta).signal_list()
