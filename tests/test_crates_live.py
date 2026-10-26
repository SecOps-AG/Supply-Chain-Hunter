"""Live crates.io smoke. Skipped unless HUNTER_CRATES_LIVE=1. CI does not set that variable.

Scout and Triage stay off. Nothing in a downloaded crate is executed.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("HUNTER_CRATES_LIVE") != "1",
    reason="set HUNTER_CRATES_LIVE=1 to read crates.io",
)

BLOCKED = {"rustdecimal", "faster_log", "async_println", "evm-units", "uniswap-utils"}


def _refuse(*_args, **_kwargs):
    raise AssertionError("cargo or rustc must not run")


def test_live_crates_smoke(tmp_path, monkeypatch):
    monkeypatch.setattr(subprocess, "run", _refuse)
    monkeypatch.setattr(subprocess, "Popen", _refuse)

    from hunter.archives import aligned_release_trees
    from hunter.config import Config
    from hunter.crates.feed import parse_rss, poll_crates
    from hunter.crates.review import dl_template, fetch_index, predecessor
    from hunter.crates import download_url
    from hunter.db import Database
    from hunter.registry import http_get
    from hunter.rules.engine import scan_release
    from hunter.service import classify_job

    started = time.monotonic()
    updates = http_get("https://static.crates.io/rss/updates.xml", 60)
    items = parse_rss(updates)
    assert items, "updates.xml had no parseable item"
    assert all(item.published for item in items)
    blocked = sorted({item.name for item in items if item.name in BLOCKED})
    if blocked:
        pytest.fail("blocked crate in the live feed; not downloading: " + ", ".join(blocked))

    config = Config(
        db_path=tmp_path / "hunter.sqlite3",
        crates=True,
        crates_scout=False,
        crates_top_n=100,
        smart_analysis=False,
        max_pending=5,
    )
    chosen = []
    for item in items:
        if any(saved.name == item.name for saved in chosen):
            continue
        lines = fetch_index(config, item.name, http_get)
        current = next((line for line in lines if str(line.get("vers") or "") == item.version), None)
        if current is None or current.get("yanked"):
            continue
        earlier = predecessor(lines, item.version)
        chosen.append(item)
        if earlier is not None or len(chosen) >= 3:
            if len(chosen) >= 3:
                break
    chosen = chosen[:3]
    assert chosen, "no live crate version was readable"

    template = dl_template(config, http_get)
    notes = []
    for item in chosen:
        lines = fetch_index(config, item.name, http_get)
        current = next(line for line in lines if str(line.get("vers") or "") == item.version)
        earlier = predecessor(lines, item.version)
        new_url = download_url(template, item.name, item.version, str(current.get("cksum") or ""), config.crates_static)
        new_blob = http_get(new_url, 120)
        assert hashlib.sha256(new_blob).hexdigest().lower() == str(current.get("cksum") or "").lower()
        from hunter.archives import extract_archive

        new_tree = extract_archive(new_blob)
        old_tree = {}
        old_version = None
        if earlier is not None:
            old_version = str(earlier.get("vers") or "")
            old_url = download_url(
                template, item.name, old_version, str(earlier.get("cksum") or ""), config.crates_static
            )
            old_blob = http_get(old_url, 120)
            assert hashlib.sha256(old_blob).hexdigest().lower() == str(earlier.get("cksum") or "").lower()
            old_tree = extract_archive(old_blob)
        old_files, new_files = aligned_release_trees(
            old_tree,
            new_tree,
            ecosystem="crates",
            name=item.name,
            old_version=old_version,
            new_version=item.version,
        )
        assert any(path.endswith("Cargo.toml") or path == "Cargo.toml" for path in new_files)
        assert "Cargo.toml" in new_files
        report = scan_release(old_files, new_files, ecosystem="crates")
        assert report.pack_version
        notes.append(
            {
                "name": item.name,
                "version": item.version,
                "old_version": old_version,
                "files": len(list(new_files)),
                "rules": sorted({hit.rule for hit in report.hits + report.info}),
            }
        )
        if hasattr(new_tree, "close"):
            new_tree.close()
        if hasattr(old_tree, "close"):
            old_tree.close()

    db = Database(tmp_path / "hunter.sqlite3")
    poll_crates(db, config, http_get)
    sample = chosen[0]
    db.enqueue_job("crates", sample.name, sample.version, None, max_pending=config.max_pending)
    classify_job(
        db,
        config,
        {"ecosystem": "crates", "name": sample.name, "version": sample.version, "rank": None},
        jev=None,
        loader=None,
        transport=http_get,
    )
    saved = db.get_release("crates", sample.name, sample.version)
    assert saved is not None
    assert saved["band"] in {"benign", "review"}
    payload = json.loads(saved["payload_json"])
    assert payload.get("rule_pack")
    if notes[0]["old_version"]:
        assert payload.get("old_version") == notes[0]["old_version"]
    db.close()
    print(
        json.dumps(
            {"elapsed_seconds": round(time.monotonic() - started, 1), "releases": notes, "classified": sample.name},
            indent=2,
        )
    )
