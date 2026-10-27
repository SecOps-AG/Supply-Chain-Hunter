"""Importing a user watchlist from disk and the ``hunter watchlist`` commands.

Every file is written to tmp_path from an inline string. No fixture corpus is read,
and nothing imported is run: the no-exec test makes any subprocess call fail.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
from datetime import timedelta

import pytest

from hunter.cli import main
from hunter.config import Config
from hunter.db import Database, iso, utcnow
from hunter.inventory.load import (
    CONFIG_SOURCES_CHECKPOINT,
    discover,
    import_paths,
    prime_new_names,
    read_capped,
    refresh_from_config,
)

LOCK = json.dumps(
    {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"left-pad": "1.3.0"}},
            "node_modules/left-pad": {"version": "1.3.0"},
            "node_modules/is-odd": {"version": "3.0.1"},
        },
    }
)
REQUIREMENTS = "requests==2.31.0\nurllib3>=2\n"


def _write(path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _tree(root):
    _write(root / "api" / "package-lock.json", LOCK)
    _write(root / "api" / "node_modules" / "left-pad" / "package.json", '{"name": "left-pad"}')
    _write(root / "worker" / "requirements.txt", REQUIREMENTS)
    _write(root / ".github" / "workflows" / "ci.yml", "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n")
    _write(root / "notes.md", "# not a watchlist file\n")
    return root


def test_discover_skips_dependency_folders_and_symlinks(tmp_path):
    root = _tree(tmp_path / "repo")
    outside = _write(tmp_path / "outside" / "package.json", '{"dependencies": {"x": "1.0.0"}}')
    os.symlink(outside, root / "package.json")
    os.symlink(outside.parent, root / "linked-dir")
    files, partial = discover(root)
    assert not partial
    assert [path.relative_to(root).as_posix() for path in files] == [
        ".github/workflows/ci.yml",
        "api/package-lock.json",
        "worker/requirements.txt",
    ]


def test_discover_stops_at_the_file_cap(tmp_path):
    root = _tree(tmp_path / "repo")
    files, partial = discover(root, max_files=2)
    assert len(files) == 2 and partial


def test_read_capped_skips_large_files_and_symlinks(tmp_path):
    small = _write(tmp_path / "small.txt", "a" * 10)
    big = _write(tmp_path / "big.txt", "a" * 2048)
    os.symlink(small, tmp_path / "link.txt")
    assert read_capped(small, 1024) == "a" * 10
    assert read_capped(big, 1024) is None
    assert read_capped(tmp_path / "link.txt", 1024) is None


def test_import_labels_rows_by_source_and_reimport_replaces_only_that_source(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    root = _tree(tmp_path / "repo")
    report = import_paths(db, [str(root)], source="acme")
    assert {item.source: item.format for item in report.files} == {
        "acme/.github/workflows/ci.yml": "workflow",
        "acme/api/package-lock.json": "npm-lock",
        "acme/worker/requirements.txt": "requirements",
    }
    assert db.user_watch_names("npm") == {"left-pad", "is-odd"}
    assert db.user_watch_names("pypi") == {"requests", "urllib3"}
    assert db.user_watch_names("github-actions") == {"actions/checkout"}
    assert ("npm", "left-pad") in report.new_names

    _write(root / "worker" / "requirements.txt", "requests==2.32.0\n")
    import_paths(db, [str(root / "worker" / "requirements.txt")], source="acme/worker")
    assert db.user_watch_names("pypi") == {"requests"}
    assert db.user_watch_names("npm") == {"left-pad", "is-odd"}
    pins = {row["version"] for row in db.user_watch_entries("pypi", "requests")}
    assert pins == {"2.32.0"}
    db.close()


def test_two_roots_without_a_source_get_distinct_labels(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    one = _write(tmp_path / "one" / "requirements.txt", "a==1\n").parent
    two = _write(tmp_path / "two" / "requirements.txt", "b==1\n").parent
    import_paths(db, [str(one), str(two)])
    labels = {row["source"] for row in db.user_watch_sources()}
    assert labels == {f"{one.as_posix()}/requirements.txt", f"{two.as_posix()}/requirements.txt"}
    db.close()


def test_dry_run_writes_nothing(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    report = import_paths(db, [str(_tree(tmp_path / "repo"))], dry_run=True)
    assert report.dry_run and report.components == 5
    assert not db.has_user_watch()
    assert db.user_watch_sources() == []
    db.close()


def test_stdin_needs_a_format(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    report = import_paths(db, ["-"], stdin=io.StringIO("npm lodash\n"))
    assert report.files[0].error
    report = import_paths(db, ["-"], fmt="plain", source="typed", stdin=io.StringIO("npm lodash\npypi Flask\n"))
    assert report.files[0].format == "plain"
    assert db.user_watch_names("pypi") == {"flask"}
    assert {row["source"] for row in db.user_watch_sources()} == {"typed"}
    db.close()


def test_import_never_runs_package_code(tmp_path, monkeypatch):
    def refuse(*_args, **_kwargs):
        raise AssertionError("import tried to run a process")

    monkeypatch.setattr(subprocess, "run", refuse)
    monkeypatch.setattr(subprocess, "Popen", refuse)
    monkeypatch.setattr(os, "system", refuse)
    root = tmp_path / "repo"
    marker = tmp_path / "ran.txt"
    _write(
        root / "package.json",
        json.dumps({"name": "app", "scripts": {"postinstall": f"touch {marker}"}, "dependencies": {"left-pad": "1.3.0"}}),
    )
    _write(root / "setup.py", f"open({str(marker)!r}, 'w').write('ran')\n")
    _write(
        root / ".github" / "workflows" / "build.yml",
        f"jobs:\n  a:\n    steps:\n      - uses: actions/setup-node@v4\n      - run: touch {marker}\n",
    )
    db = Database(tmp_path / "hunter.sqlite3")
    report = import_paths(db, [str(root)])
    assert sorted(item.source for item in report.files) == [".github/workflows/build.yml", "package.json"]
    assert db.user_watch_names("npm") == {"left-pad"}
    assert db.user_watch_names("github-actions") == {"actions/setup-node"}
    assert not marker.exists()
    db.close()


def test_readding_an_npm_name_moves_its_old_cursor_forward(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    db.set_package_cursor("npm", "left-pad", "1.0.0", "2026-01-01T00:00:00.000Z")
    db.set_package_cursor("npm", "fresh", "2.0.0", "2999-01-01T00:00:00.000Z")
    poll = utcnow()
    db.mark_poll_success("npm", when=poll)
    assert prime_new_names(db, [("npm", "left-pad"), ("npm", "fresh"), ("npm", "never-seen"), ("pypi", "x")]) == 1
    assert db.get_package_cursor("npm", "left-pad") == ("1.0.0", iso(poll)[:-1] + ".000Z")
    assert db.get_package_cursor("npm", "fresh")[1] == "2999-01-01T00:00:00.000Z"
    assert db.get_package_cursor("npm", "never-seen") == (None, None)
    db.close()


def test_config_refresh_drops_sources_whose_file_is_gone(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    root = _tree(tmp_path / "repo")
    config = Config(db_path=db.path, watchlist_paths=(str(root),))
    refresh_from_config(db, config)
    labels = {row["source"] for row in db.user_watch_sources()}
    assert f"{root.as_posix()}/worker/requirements.txt" in labels
    (root / "worker" / "requirements.txt").unlink()
    refresh_from_config(db, config)
    assert f"{root.as_posix()}/worker/requirements.txt" not in {row["source"] for row in db.user_watch_sources()}
    assert db.user_watch_names("pypi") == set()
    assert db.user_watch_names("npm") == {"left-pad", "is-odd"}
    assert json.loads(db.get_checkpoint(CONFIG_SOURCES_CHECKPOINT))
    db.close()


# --- CLI ----------------------------------------------------------------------


@pytest.fixture()
def cli_env(tmp_path, monkeypatch):
    for name in ("HUNTER_WATCH_MODE", "HUNTER_ALERT_SCOPE", "HUNTER_WATCHLIST_PATHS", "HUNTER_ACTIONS", "HUNTER_OPENVSX"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HUNTER_DB", str(tmp_path / "hunter.sqlite3"))
    monkeypatch.setenv("HUNTER_LOG_DIR", str(tmp_path / "logs"))
    return tmp_path


def test_cli_import_add_remove_and_list(cli_env, capsys):
    root = _tree(cli_env / "repo")
    assert main(["watchlist", "import", str(root), "--source", "acme", "--dry-run", "--json"]) == 0
    dry = json.loads(capsys.readouterr().out)
    assert dry["dry_run"] and len(dry["files"]) == 3
    assert main(["watchlist", "list", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == []

    assert main(["watchlist", "import", str(root), "--source", "acme"]) == 0
    out = capsys.readouterr().out
    assert "acme/api/package-lock.json\tnpm-lock\t2 components" in out
    assert main(["watchlist", "add", "pip", "Flask", "3.0.0"]) == 0
    capsys.readouterr()
    assert main(["watchlist", "add", "npm", "not a name"]) == 2
    capsys.readouterr()
    assert main(["watchlist", "list", "--ecosystem", "pypi", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert {(row["name"], row["version"], row["source"]) for row in rows} == {
        ("flask", "3.0.0", "manual"),
        ("requests", "2.31.0", "acme/worker/requirements.txt"),
        ("urllib3", "", "acme/worker/requirements.txt"),
    }

    assert main(["watchlist", "remove", "pypi", "requests"]) == 0
    assert "removed 1 rows" in capsys.readouterr().out
    assert main(["watchlist", "remove", "--source", "acme/api/package-lock.json"]) == 0
    assert "removed 2 rows" in capsys.readouterr().out
    assert main(["watchlist", "remove"]) == 2
    capsys.readouterr()
    assert main(["watchlist", "list", "--json"]) == 0
    names = {(row["ecosystem"], row["name"]) for row in json.loads(capsys.readouterr().out)}
    assert names == {("pypi", "flask"), ("pypi", "urllib3"), ("github-actions", "actions/checkout")}


def test_cli_stdin_needs_format(cli_env, capsys, monkeypatch):
    assert main(["watchlist", "import", "-"]) == 2
    monkeypatch.setattr("sys.stdin", io.StringIO("npm lodash 4.17.21\n"))
    assert main(["watchlist", "import", "-", "--format", "plain", "--source", "pasted"]) == 0
    assert "pasted\tplain\t1 components" in capsys.readouterr().out


def test_cli_status_warnings(cli_env, capsys, monkeypatch):
    monkeypatch.setenv("HUNTER_WATCH_MODE", "watched")
    assert main(["watchlist", "status"]) == 0
    out = capsys.readouterr().out
    assert "mode watched, alert scope watched" in out
    assert "watchlist is empty" in out

    monkeypatch.setenv("HUNTER_WATCH_MODE", "all")
    assert main(["watchlist", "add", "actions", "actions/checkout", "v4"]) == 0
    db = Database(cli_env / "hunter.sqlite3")
    old = utcnow() - timedelta(days=10)
    db.replace_user_watch_source("old/requirements.txt", "requirements", [("pypi", "requests", "", None)], when=old)
    db.close()
    capsys.readouterr()
    assert main(["watchlist", "status"]) == 0
    out = capsys.readouterr().out
    assert "mode all, alert scope all" in out
    assert "HUNTER_WATCH_MODE=all" in out
    assert "HUNTER_ACTIONS is off" in out
    assert "old/requirements.txt was imported more than 7 days ago" in out
    assert "(stale)" in out


def test_cli_formats_lists_every_format(cli_env, capsys):
    assert main(["watchlist", "formats"]) == 0
    out = capsys.readouterr().out
    for fmt in ("npm-lock", "yarn-lock", "pnpm-lock", "requirements", "cyclonedx", "spdx", "plain", "workflow"):
        assert fmt in out
