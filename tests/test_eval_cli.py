"""`hunter eval` works from any directory and does not import the tests package."""

import os
import subprocess
import sys
from pathlib import Path

from hunter.cli import default_fixtures_dir, main

REPO = Path(__file__).resolve().parent.parent


def test_default_fixtures_dir_is_repo_fixtures():
    assert default_fixtures_dir() == REPO / "fixtures"
    assert default_fixtures_dir().is_dir()


def test_eval_runs_from_temp_cwd_without_tests_package(tmp_path):
    code = (
        "import sys; sys.modules['tests'] = None\n"
        "from hunter.cli import main\n"
        "sys.exit(main(['eval']))\n"
    )
    env = {k: v for k, v in os.environ.items() if not k.startswith(("HUNTER_", "ALERT_"))}
    env["PYTHONPATH"] = str(REPO)
    env["HUNTER_DB"] = str(tmp_path / "hunter.sqlite3")
    done = subprocess.run(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert done.returncode == 0, done.stderr[-2000:]
    assert "precision=" in done.stdout and "recall=" in done.stdout


def test_eval_missing_fixtures_dir_is_a_clear_error(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HUNTER_DB", str(tmp_path / "hunter.sqlite3"))
    assert main(["eval", "--fixtures", "nope"]) == 2
    assert "fixtures directory not found" in capsys.readouterr().err
