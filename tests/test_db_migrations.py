"""Opening an existing database upgrades its schema in place."""

from __future__ import annotations

import sqlite3

from hunter.db import MIGRATIONS, Database

# Schema as shipped before the MCP, Open VSX and takeover tables and before user_version.
PRE_TONIGHT_SCHEMA = """
    CREATE TABLE IF NOT EXISTS checkpoints (
        ecosystem TEXT PRIMARY KEY,
        cursor TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS watchlist (
        ecosystem TEXT NOT NULL,
        name TEXT NOT NULL,
        rank INTEGER NOT NULL,
        downloads INTEGER,
        refreshed_at TEXT NOT NULL,
        PRIMARY KEY (ecosystem, name)
    );
    CREATE TABLE IF NOT EXISTS package_cursor (
        ecosystem TEXT NOT NULL,
        name TEXT NOT NULL,
        last_version TEXT,
        last_time TEXT,
        PRIMARY KEY (ecosystem, name)
    );
    CREATE TABLE IF NOT EXISTS releases (
        ecosystem TEXT NOT NULL,
        name TEXT NOT NULL,
        version TEXT NOT NULL,
        band TEXT,
        malice_probability REAL,
        family TEXT,
        subtype TEXT,
        payload_json TEXT,
        created_at TEXT NOT NULL,
        PRIMARY KEY (ecosystem, name, version)
    );
    CREATE TABLE IF NOT EXISTS outbox (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        idempotency_key TEXT NOT NULL UNIQUE,
        body TEXT NOT NULL,
        status TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        next_attempt_at TEXT NOT NULL,
        last_error TEXT,
        created_at TEXT NOT NULL,
        sent_at TEXT
    );
    CREATE TABLE IF NOT EXISTS poll_status (
        ecosystem TEXT PRIMARY KEY,
        last_success_at TEXT,
        last_error TEXT
    );
    CREATE TABLE IF NOT EXISTS release_jobs (
        ecosystem TEXT NOT NULL,
        name TEXT NOT NULL,
        version TEXT NOT NULL,
        rank INTEGER,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (ecosystem, name, version)
    );
    CREATE TABLE IF NOT EXISTS train_cache (
        fixture_id TEXT PRIMARY KEY,
        features_json TEXT NOT NULL,
        label INTEGER NOT NULL,
        model_id TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS classify_retries (
        ecosystem TEXT NOT NULL,
        name TEXT NOT NULL,
        version TEXT NOT NULL,
        rank INTEGER,
        attempts INTEGER NOT NULL DEFAULT 0,
        next_attempt_at TEXT NOT NULL,
        last_error TEXT,
        status TEXT NOT NULL,
        PRIMARY KEY (ecosystem, name, version)
    );
    CREATE TABLE IF NOT EXISTS investigations (
        idempotency_key TEXT PRIMARY KEY,
        body TEXT NOT NULL,
        status TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        next_attempt_at TEXT NOT NULL,
        report_text TEXT,
        last_error TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS human_review_queue (
        kind TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        ecosystem TEXT,
        name TEXT,
        version TEXT,
        attempts INTEGER NOT NULL,
        last_error TEXT,
        reason TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (kind, idempotency_key)
    );
    CREATE TABLE IF NOT EXISTS analyst_reviews (
        idempotency_key TEXT PRIMARY KEY,
        body TEXT NOT NULL,
        status TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        next_attempt_at TEXT NOT NULL,
        report_text TEXT,
        verdict TEXT,
        lesson_id TEXT,
        last_error TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS model_budget (
        role TEXT PRIMARY KEY,
        used INTEGER NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS scout_usage (
        day TEXT NOT NULL,
        provider TEXT NOT NULL,
        model TEXT NOT NULL,
        calls INTEGER NOT NULL,
        estimated_calls INTEGER NOT NULL,
        input_tokens INTEGER NOT NULL,
        output_tokens INTEGER NOT NULL,
        usd REAL NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (day, provider, model)
    );
    CREATE TABLE IF NOT EXISTS scout_spend_stop (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        cap_usd TEXT NOT NULL,
        day TEXT NOT NULL,
        reached_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS public_feed_items (
        ecosystem TEXT NOT NULL,
        name TEXT NOT NULL,
        version TEXT NOT NULL,
        previous_version TEXT NOT NULL,
        registry_url TEXT NOT NULL,
        behavior TEXT NOT NULL,
        cause TEXT NOT NULL,
        limited_review INTEGER NOT NULL,
        first_seen_at TEXT NOT NULL,
        PRIMARY KEY (ecosystem, name, version)
    );
    CREATE TABLE IF NOT EXISTS public_feed_state (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        content_hash TEXT,
        published_at TEXT,
        last_error TEXT
    );
    CREATE TABLE IF NOT EXISTS public_dash_state (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        live_hash TEXT,
        benchmark_hash TEXT,
        published_at TEXT,
        last_error TEXT
    );
    CREATE TABLE IF NOT EXISTS public_dash_releases (
        release_key TEXT PRIMARY KEY,
        content_hash TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS decision_model_outage (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        started_at TEXT NOT NULL,
        failures INTEGER NOT NULL,
        notified_at TEXT
    );
    CREATE TABLE IF NOT EXISTS action_tags (
        name TEXT NOT NULL,
        tag TEXT NOT NULL,
        sha TEXT NOT NULL,
        first_seen_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        PRIMARY KEY (name, tag)
    );
    CREATE TABLE IF NOT EXISTS action_tag_moves (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        tag TEXT NOT NULL,
        kind TEXT NOT NULL,
        old_sha TEXT,
        new_sha TEXT,
        seen_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS action_tag_moves_name ON action_tag_moves (name, seen_at);
    CREATE TABLE IF NOT EXISTS action_state (
        name TEXT PRIMARY KEY,
        seeded_at TEXT,
        last_polled_at TEXT,
        last_swept_at TEXT,
        default_branch TEXT,
        last_error TEXT
    );
    CREATE TABLE IF NOT EXISTS action_events (
        name TEXT NOT NULL,
        version TEXT NOT NULL,
        tag TEXT NOT NULL,
        kind TEXT NOT NULL,
        old_sha TEXT,
        new_sha TEXT NOT NULL,
        moves_in_poll INTEGER NOT NULL DEFAULT 0,
        tag_first_seen_at TEXT,
        seen_at TEXT NOT NULL,
        PRIMARY KEY (name, version)
    );
    CREATE TABLE IF NOT EXISTS action_watch_meta (
        name TEXT PRIMARY KEY,
        sources TEXT NOT NULL,
        dependents INTEGER,
        used_by_packages INTEGER NOT NULL DEFAULT 0,
        refreshed_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS action_scout_days (
        day TEXT PRIMARY KEY,
        used INTEGER NOT NULL
    );
"""

NEW_INDEXES = {
    "releases_created",
    "release_jobs_status_created",
    "investigations_created",
    "analyst_reviews_created",
    "outbox_status_next",
    "outbox_created",
    "takeover_signals_package_created",
}


def _indexes(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type = 'index' AND sql IS NOT NULL").fetchall()
    return {row[0] for row in rows}


def _tables(conn: sqlite3.Connection) -> set[str]:
    return {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def _user_version(conn: sqlite3.Connection) -> int:
    return int(conn.execute("PRAGMA user_version").fetchone()[0])


def test_fresh_database_gets_indexes_and_version(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    assert NEW_INDEXES <= _indexes(db._conn)
    assert _user_version(db._conn) == len(MIGRATIONS)
    assert int(db._conn.execute("PRAGMA busy_timeout").fetchone()[0]) == 5000
    db.close()


def test_pre_tonight_database_upgrades_and_keeps_rows(tmp_path):
    path = tmp_path / "old.sqlite3"
    old = sqlite3.connect(path)
    old.executescript(PRE_TONIGHT_SCHEMA)
    old.execute(
        "INSERT INTO releases (ecosystem, name, version, band, created_at) VALUES ('npm', 'left-pad', '1.0.0', 'review', '2026-10-01T00:00:00Z')"
    )
    old.execute(
        "INSERT INTO release_jobs (ecosystem, name, version, rank, status, created_at) VALUES ('npm', 'left-pad', '1.0.1', 3, 'pending', '2026-10-01T00:00:00Z')"
    )
    old.commit()
    assert _user_version(old) == 0
    assert not NEW_INDEXES & _indexes(old)
    assert "takeover_signals" not in _tables(old)
    old.close()

    db = Database(path)
    conn = db._conn
    assert {"mcp_packages", "openvsx_changes", "takeover_signals"} <= _tables(conn)
    assert NEW_INDEXES <= _indexes(conn)
    assert _user_version(conn) == len(MIGRATIONS)
    assert [dict(row) for row in conn.execute("SELECT name, version, band FROM releases")] == [
        {"name": "left-pad", "version": "1.0.0", "band": "review"}
    ]
    assert db.pending_count() == 1
    plan = " ".join(
        str(row[-1])
        for row in conn.execute("EXPLAIN QUERY PLAN SELECT * FROM releases WHERE created_at >= '2026-01-01'")
    )
    assert "releases_created" in plan
    db.close()

    reopened = Database(path)
    assert _user_version(reopened._conn) == len(MIGRATIONS)
    assert NEW_INDEXES <= _indexes(reopened._conn)
    reopened.close()


def test_old_database_gains_the_user_watchlist_tables(tmp_path):
    # A database written by the release before the user watchlist: the first step only.
    path = tmp_path / "old.sqlite3"
    Database(path).close()
    old = sqlite3.connect(path)
    old.executescript("DROP TABLE user_watch; DROP TABLE user_watch_sources; PRAGMA user_version = 1;")
    assert {"user_watch", "user_watch_sources"}.isdisjoint(_tables(old))
    assert _user_version(old) == 1
    old.close()

    db = Database(path)
    assert _user_version(db._conn) == len(MIGRATIONS) >= 2
    assert {"user_watch", "user_watch_sources"} <= _tables(db._conn)
    assert "user_watch_name" in _indexes(db._conn)
    assert not db.has_user_watch()
    db.replace_user_watch_source("manual", "plain", [("npm", "left-pad", "", 1)])
    assert db.user_watch_names("npm") == {"left-pad"}
    db.close()


def test_migrations_skip_steps_already_applied(tmp_path):
    path = tmp_path / "hunter.sqlite3"
    Database(path).close()
    conn = sqlite3.connect(path)
    conn.execute("DROP INDEX releases_created")
    conn.commit()
    conn.close()

    db = Database(path)
    assert "releases_created" not in _indexes(db._conn)
    db.close()
