"""Shared test setup.

Behavior tests pin the original Jev scoring head (tests/heads/logistic_head_prior.json:
no cutoffs, built-in floor levels), so band, floor, and alert mechanics are tested
apart from whatever refit weights ship in hunter/logistic_head.json. A test marked
``shipped_head`` reads the real shipped file instead.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import hunter.head as head_module

PRIOR_HEAD = Path(__file__).resolve().parent / "heads" / "logistic_head_prior.json"


def pytest_configure(config):
    config.addinivalue_line("markers", "shipped_head: read the shipped hunter/logistic_head.json")


class _PinnedPackage:
    def __init__(self, real):
        self._real = real

    def joinpath(self, name: str):
        if name == head_module.head_file("jev"):
            return PRIOR_HEAD
        return self._real.joinpath(name)


@pytest.fixture(autouse=True)
def _pin_prior_jev_head(request, monkeypatch):
    if request.node.get_closest_marker("shipped_head"):
        return
    real_files = head_module.files

    def files(package):
        found = real_files(package)
        return _PinnedPackage(found) if package == "hunter" else found

    monkeypatch.setattr(head_module, "files", files)
