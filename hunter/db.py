"""SQLite checkpoints, classifications, the webhook outbox, and the public feed."""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# Releases of the top ranked packages are never parked: they keep retrying until Scout answers.
NEVER_PARK_RANK = 300
# Longest classify retry wait, in seconds.
RETRY_DELAY_CAP = 3600


def never_park(rank: int | None) -> bool:
    return rank is not None and 0 < int(rank) <= NEVER_PARK_RANK


def _retry_delay(exponent: int) -> int:
    return min(RETRY_DELAY_CAP, 2 ** min(max(exponent, 0), 12))


def iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# Schema steps applied after the base tables, in order. PRAGMA user_version records how
# many have run, so add new steps (ALTER TABLE, new indexes) at the end and never edit old ones.
MIGRATIONS: tuple[str, ...] = (
    """
    CREATE INDEX IF NOT EXISTS releases_created ON releases (created_at);
    CREATE INDEX IF NOT EXISTS release_jobs_status_created ON release_jobs (status, created_at);
    CREATE INDEX IF NOT EXISTS investigations_created ON investigations (created_at);
    CREATE INDEX IF NOT EXISTS analyst_reviews_created ON analyst_reviews (created_at);
    CREATE INDEX IF NOT EXISTS outbox_status_next ON outbox (status, next_attempt_at);
    CREATE INDEX IF NOT EXISTS outbox_created ON outbox (created_at);
    CREATE INDEX IF NOT EXISTS takeover_signals_package_created ON takeover_signals (ecosystem, name, created_at);
    """,
    # User watchlist (hunter/inventory). Kept apart from `watchlist`, which every ranked refresh replaces.
    """
    CREATE TABLE IF NOT EXISTS user_watch_sources (
        source TEXT PRIMARY KEY,
        format TEXT NOT NULL,
        imported_at TEXT NOT NULL,
        components INTEGER NOT NULL,
        skipped INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS user_watch (
        ecosystem TEXT NOT NULL,
        name TEXT NOT NULL,
        version TEXT NOT NULL DEFAULT '',
        direct INTEGER,
        source TEXT NOT NULL,
        PRIMARY KEY (ecosystem, name, version, source)
    );
    CREATE INDEX IF NOT EXISTS user_watch_name ON user_watch (ecosystem, name);
    """,
)

# Ecosystems a user watchlist row may hold.
USER_WATCH_ECOSYSTEMS = ("npm", "pypi", "github-actions", "openvsx", "rubygems", "crates")
# Keeps only `releases` rows whose name is on the user watchlist.
_USER_WATCH_FILTER = (
    "AND EXISTS (SELECT 1 FROM user_watch w WHERE w.ecosystem = releases.ecosystem AND w.name = "
    "CASE WHEN releases.ecosystem IN ('rubygems', 'crates') THEN lower(releases.name) ELSE releases.name END)"
)


class Database:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        if self.path.parent and not self.path.parent.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._migrate()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _migrate(self) -> None:
        self._conn.executescript(
            """
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
                scored_at TEXT,
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
            CREATE TABLE IF NOT EXISTS mcp_packages (
                ecosystem TEXT NOT NULL,
                name TEXT NOT NULL,
                server TEXT NOT NULL,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                PRIMARY KEY (ecosystem, name)
            );
            CREATE TABLE IF NOT EXISTS openvsx_changes (
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                platform TEXT NOT NULL,
                state TEXT NOT NULL,
                published_at TEXT,
                changed_at TEXT,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                PRIMARY KEY (name, version, platform)
            );
            CREATE INDEX IF NOT EXISTS openvsx_changes_state ON openvsx_changes (state, last_seen_at);
            CREATE TABLE IF NOT EXISTS openvsx_labels (
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                platform TEXT NOT NULL,
                state TEXT NOT NULL,
                changed_at TEXT,
                first_seen_at TEXT NOT NULL,
                PRIMARY KEY (name, version, platform)
            );
            CREATE TABLE IF NOT EXISTS takeover_signals (
                ecosystem TEXT NOT NULL,
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                old_version TEXT,
                score INTEGER NOT NULL,
                signals_json TEXT NOT NULL,
                detail_json TEXT NOT NULL,
                error TEXT,
                created_at TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 1,
                retry_at TEXT,
                PRIMARY KEY (ecosystem, name, version)
            );
            CREATE TABLE IF NOT EXISTS mcp_risk (
                ecosystem TEXT NOT NULL,
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                old_version TEXT,
                server TEXT,
                score INTEGER NOT NULL,
                signals_json TEXT NOT NULL,
                detail_json TEXT NOT NULL,
                error TEXT,
                created_at TEXT NOT NULL,
                PRIMARY KEY (ecosystem, name, version)
            );
            """
        )
        columns = {row[1] for row in self._conn.execute("PRAGMA table_info(releases)")}
        if "scored_at" not in columns:
            # When the band last changed; created_at stays the first save.
            self._conn.execute("ALTER TABLE releases ADD COLUMN scored_at TEXT")
        columns = {row["name"] for row in self._conn.execute("PRAGMA table_info(takeover_signals)")}
        if "attempts" not in columns:
            self._conn.execute("ALTER TABLE takeover_signals ADD COLUMN attempts INTEGER NOT NULL DEFAULT 1")
        if "retry_at" not in columns:
            self._conn.execute("ALTER TABLE takeover_signals ADD COLUMN retry_at TEXT")
        self._migrate_public_dash_dirty()
        self._conn.commit()
        version = int(self._conn.execute("PRAGMA user_version").fetchone()[0])
        for step, script in enumerate(MIGRATIONS[version:], start=version + 1):
            self._conn.executescript(f"BEGIN;\n{script}\nPRAGMA user_version = {step};\nCOMMIT;")

    def _migrate_public_dash_dirty(self) -> None:
        """Triggers that note which published release objects need a rebuild.

        A write to any row ``release_detail`` reads adds the release key here, but only
        for keys already in ``public_dash_releases``. The publisher then rebuilds just
        those objects instead of every release on the public page each cycle.
        """
        fresh = (
            self._conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'public_dash_dirty'"
            ).fetchone()
            is None
        )
        statements = [
            """
            CREATE TABLE IF NOT EXISTS public_dash_dirty (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                release_key TEXT NOT NULL
            )
            """,
            "CREATE INDEX IF NOT EXISTS public_dash_dirty_key ON public_dash_dirty (release_key, id)",
        ]
        keys = {
            "releases": ("NEW.ecosystem || ':' || NEW.name || ':' || NEW.version",
                         "OLD.ecosystem || ':' || OLD.name || ':' || OLD.version"),
            "investigations": ("NEW.idempotency_key", "OLD.idempotency_key"),
            "analyst_reviews": ("NEW.idempotency_key", "OLD.idempotency_key"),
            "outbox": ("NEW.idempotency_key", "OLD.idempotency_key"),
        }
        for table, (new_key, old_key) in keys.items():
            for event, key in (("INSERT", new_key), ("UPDATE", new_key), ("DELETE", old_key)):
                candidates = key
                if table == "outbox":
                    # Analysis alerts are stored as "<release key>:analysis".
                    candidates = (
                        f"{key}, CASE WHEN {key} LIKE '%:analysis' "
                        f"THEN substr({key}, 1, length({key}) - 9) END"
                    )
                statements.append(
                    f"""
                    CREATE TRIGGER IF NOT EXISTS public_dash_dirty_{table}_{event.lower()}
                    AFTER {event} ON {table}
                    BEGIN
                        INSERT INTO public_dash_dirty (release_key)
                        SELECT release_key FROM public_dash_releases
                        WHERE release_key IN ({candidates});
                    END
                    """
                )
        for statement in statements:
            self._conn.execute(statement)
        if fresh:
            # Changes made before the triggers existed are unknown; recheck everything once.
            self._conn.execute(
                "INSERT INTO public_dash_dirty (release_key) SELECT release_key FROM public_dash_releases"
            )

    def get_checkpoint(self, ecosystem: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT cursor FROM checkpoints WHERE ecosystem = ?",
                (ecosystem,),
            ).fetchone()
        return None if row is None else str(row["cursor"])

    def set_checkpoint(self, ecosystem: str, cursor: str, when: datetime | None = None) -> None:
        moment = iso(when or utcnow())
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO checkpoints (ecosystem, cursor, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(ecosystem) DO UPDATE SET cursor = excluded.cursor, updated_at = excluded.updated_at
                """,
                (ecosystem, cursor, moment),
            )
            self._conn.commit()

    def replace_watchlist(self, ecosystem: str, rows: list[tuple[str, int, int]], when: datetime | None = None) -> None:
        moment = iso(when or utcnow())
        with self._lock:
            self._conn.execute("DELETE FROM watchlist WHERE ecosystem = ?", (ecosystem,))
            self._conn.executemany(
                """
                INSERT INTO watchlist (ecosystem, name, rank, downloads, refreshed_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                [(ecosystem, name, rank, downloads, moment) for name, rank, downloads in rows],
            )
            self._conn.commit()

    def watch_names(self, ecosystem: str) -> dict[str, int]:
        with self._lock:
            found = self._conn.execute(
                "SELECT name, rank FROM watchlist WHERE ecosystem = ?",
                (ecosystem,),
            ).fetchall()
        return {str(row["name"]): int(row["rank"]) for row in found}

    def watch_refreshed_at(self, ecosystem: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT MAX(refreshed_at) AS refreshed_at FROM watchlist WHERE ecosystem = ?",
                (ecosystem,),
            ).fetchone()
        if row is None or row["refreshed_at"] is None:
            return None
        return str(row["refreshed_at"])

    def get_package_cursor(self, ecosystem: str, name: str) -> tuple[str | None, str | None]:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT last_version, last_time FROM package_cursor
                WHERE ecosystem = ? AND name = ?
                """,
                (ecosystem, name),
            ).fetchone()
        if row is None:
            return None, None
        return row["last_version"], row["last_time"]

    def set_package_cursor(
        self,
        ecosystem: str,
        name: str,
        version: str | None,
        last_time: str | None,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO package_cursor (ecosystem, name, last_version, last_time)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(ecosystem, name) DO UPDATE SET
                    last_version = excluded.last_version,
                    last_time = excluded.last_time
                """,
                (ecosystem, name, version, last_time),
            )
            self._conn.commit()

    def has_release(self, ecosystem: str, name: str, version: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM releases WHERE ecosystem = ? AND name = ? AND version = ?",
                (ecosystem, name, version),
            ).fetchone()
        return row is not None

    def delete_release(self, ecosystem: str, name: str, version: str) -> None:
        """Drop a stored classification so a republished Open VSX version is reviewed again."""
        with self._lock:
            self._conn.execute(
                "DELETE FROM releases WHERE ecosystem = ? AND name = ? AND version = ?",
                (ecosystem, name, version),
            )
            self._conn.commit()

    def get_release(self, ecosystem: str, name: str, version: str) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                """
                SELECT ecosystem, name, version, band, payload_json
                FROM releases
                WHERE ecosystem = ? AND name = ? AND version = ?
                """,
                (ecosystem, name, version),
            ).fetchone()

    def save_release(
        self,
        ecosystem: str,
        name: str,
        version: str,
        band: str,
        probability: float,
        family: str,
        subtype: str | None,
        payload_json: str,
        when: datetime | None = None,
        replace: bool = False,
    ) -> None:
        moment = iso(when or utcnow())
        conflict = (
            """
            ON CONFLICT(ecosystem, name, version) DO UPDATE SET
                band = excluded.band,
                malice_probability = excluded.malice_probability,
                family = excluded.family,
                subtype = excluded.subtype,
                payload_json = excluded.payload_json,
                scored_at = CASE
                    WHEN releases.band IS excluded.band THEN releases.scored_at
                    WHEN releases.band IN ('review', 'alert') AND excluded.band IN ('review', 'alert')
                        THEN releases.scored_at
                    ELSE excluded.scored_at END
            """
            if replace
            else "ON CONFLICT(ecosystem, name, version) DO NOTHING"
        )
        with self._lock:
            self._conn.execute(
                f"""
                INSERT INTO releases (
                    ecosystem, name, version, band, malice_probability, family, subtype, payload_json, created_at,
                    scored_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                {conflict}
                """,
                (ecosystem, name, version, band, probability, family, subtype, payload_json, moment, moment),
            )
            self._conn.commit()

    def enqueue(self, idempotency_key: str, body: str, when: datetime | None = None) -> bool:
        moment = when or utcnow()
        with self._lock:
            try:
                self._conn.execute(
                    """
                    INSERT INTO outbox (idempotency_key, body, status, attempts, next_attempt_at, created_at)
                    VALUES (?, ?, 'pending', 0, ?, ?)
                    """,
                    (idempotency_key, body, iso(moment), iso(moment)),
                )
                self._conn.commit()
            except sqlite3.IntegrityError:
                return False
        return True

    def due_outbox(self, when: datetime | None = None, limit: int = 50) -> list[sqlite3.Row]:
        moment = iso(when or utcnow())
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT id, idempotency_key, body, attempts
                FROM outbox
                WHERE status = 'pending' AND next_attempt_at <= ?
                ORDER BY id
                LIMIT ?
                """,
                (moment, limit),
            ).fetchall()
        return list(rows)

    def mark_sent(self, row_id: int, when: datetime | None = None) -> None:
        moment = iso(when or utcnow())
        with self._lock:
            self._conn.execute(
                """
                UPDATE outbox
                SET status = 'sent', sent_at = ?, last_error = NULL
                WHERE id = ?
                """,
                (moment, row_id),
            )
            self._conn.commit()

    def mark_retry(self, row_id: int, attempts: int, error: str, when: datetime | None = None) -> None:
        moment = when or utcnow()
        delay = min(3600, 2 ** max(attempts - 1, 0))
        nxt = moment + timedelta(seconds=delay)
        with self._lock:
            self._conn.execute(
                """
                UPDATE outbox
                SET attempts = ?, next_attempt_at = ?, last_error = ?, status = 'pending'
                WHERE id = ?
                """,
                (attempts, iso(nxt), error[:500], row_id),
            )
            self._conn.commit()

    def outbox_depth(self) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM outbox WHERE status = 'pending'"
            ).fetchone()
        return int(row["n"])

    def mark_poll_success(self, ecosystem: str, when: datetime | None = None) -> None:
        moment = iso(when or utcnow())
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO poll_status (ecosystem, last_success_at, last_error)
                VALUES (?, ?, NULL)
                ON CONFLICT(ecosystem) DO UPDATE SET
                    last_success_at = excluded.last_success_at,
                    last_error = NULL
                """,
                (ecosystem, moment),
            )
            self._conn.commit()

    def mark_poll_error(self, ecosystem: str, error: str) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO poll_status (ecosystem, last_success_at, last_error)
                VALUES (?, NULL, ?)
                ON CONFLICT(ecosystem) DO UPDATE SET last_error = excluded.last_error
                """,
                (ecosystem, error[:500]),
            )
            self._conn.commit()

    def last_poll(self) -> dict[str, str | None]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT ecosystem, last_success_at FROM poll_status"
            ).fetchall()
        found = {str(row["ecosystem"]): row["last_success_at"] for row in rows}
        polls = {"pypi": found.get("pypi"), "npm": found.get("npm")}
        for extra in ("github-actions", "mcp", "openvsx", "rubygems", "crates"):
            if extra in found:
                polls[extra] = found[extra]
        return polls

    def pending_count(self) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM release_jobs WHERE status = 'pending'"
            ).fetchone()
        return int(row["n"])

    def has_release_job(self, ecosystem: str, name: str, version: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT 1 FROM release_jobs
                WHERE ecosystem = ? AND name = ? AND version = ?
                """,
                (ecosystem, name, version),
            ).fetchone()
        return row is not None

    def enqueue_job(
        self,
        ecosystem: str,
        name: str,
        version: str,
        rank: int | None,
        when: datetime | None = None,
        max_pending: int | None = None,
    ) -> bool:
        moment = iso(when or utcnow())
        with self._lock:
            if max_pending is not None:
                row = self._conn.execute(
                    "SELECT COUNT(*) AS n FROM release_jobs WHERE status = 'pending'"
                ).fetchone()
                if int(row["n"]) >= max_pending:
                    return False
            try:
                self._conn.execute(
                    """
                    INSERT INTO release_jobs (ecosystem, name, version, rank, status, created_at)
                    VALUES (?, ?, ?, ?, 'pending', ?)
                    """,
                    (ecosystem, name, version, rank, moment),
                )
                self._conn.commit()
            except sqlite3.IntegrityError:
                return False
        return True

    def pending_jobs(
        self,
        limit: int = 100,
        *,
        prioritize: bool = False,
        prioritize_mcp: bool = False,
        hold_ecosystems: tuple[str, ...] = (),
        hold_since: datetime | None = None,
    ) -> list[sqlite3.Row]:
        """Oldest first.

        `prioritize` puts a higher account-takeover score first.
        `prioritize_mcp` orders by the takeover score plus the MCP risk score.
        When `prioritize_mcp` is false, the SQL is unchanged.
        With `hold_since`, a prioritized query skips jobs in `hold_ecosystems`
        that have no takeover-signal row yet and were queued after `hold_since`,
        so a new release is not taken at score 0 before its signals exist.
        """
        hold_sql = ""
        hold_args: tuple = ()
        if hold_since is not None and hold_ecosystems:
            marks = ",".join("?" for _ in hold_ecosystems)
            hold_sql = f" AND NOT (t.name IS NULL AND j.ecosystem IN ({marks}) AND j.created_at > ?)"
            hold_args = (*hold_ecosystems, iso(hold_since))
        if prioritize_mcp:
            with self._lock:
                rows = self._conn.execute(
                    f"""
                    SELECT j.ecosystem, j.name, j.version, j.rank FROM release_jobs AS j
                    LEFT JOIN takeover_signals AS t
                        ON t.ecosystem = j.ecosystem AND t.name = j.name AND t.version = j.version
                    LEFT JOIN mcp_risk AS m
                        ON m.ecosystem = j.ecosystem AND m.name = j.name AND m.version = j.version
                    WHERE j.status = 'pending'{hold_sql}
                    ORDER BY (COALESCE(t.score, 0) + COALESCE(m.score, 0)) DESC,
                        j.created_at, j.ecosystem, j.name, j.version
                    LIMIT ?
                    """,
                    (*hold_args, limit),
                ).fetchall()
            return list(rows)
        if not prioritize:
            with self._lock:
                rows = self._conn.execute(
                    """
                    SELECT ecosystem, name, version, rank FROM release_jobs
                    WHERE status = 'pending'
                    ORDER BY created_at, ecosystem, name, version
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
            return list(rows)
        with self._lock:
            rows = self._conn.execute(
                f"""
                SELECT j.ecosystem, j.name, j.version, j.rank FROM release_jobs AS j
                LEFT JOIN takeover_signals AS t
                    ON t.ecosystem = j.ecosystem AND t.name = j.name AND t.version = j.version
                WHERE j.status = 'pending'{hold_sql}
                ORDER BY COALESCE(t.score, 0) DESC, j.created_at, j.ecosystem, j.name, j.version
                LIMIT ?
                """,
                (*hold_args, limit),
            ).fetchall()
        return list(rows)

    def unscored_pending_jobs(
        self, ecosystems: tuple[str, ...], limit: int = 50, now: datetime | None = None
    ) -> list[sqlite3.Row]:
        """Pending jobs with no takeover-signal row yet or a retry that is due, newest first.

        Under a backlog the newest releases, the likely live attacks, are scored first.
        """
        if not ecosystems or limit <= 0:
            return []
        marks = ",".join("?" for _ in ecosystems)
        with self._lock:
            rows = self._conn.execute(
                f"""
                SELECT j.ecosystem, j.name, j.version, j.rank, COALESCE(t.attempts, 0) AS attempts
                FROM release_jobs AS j
                LEFT JOIN takeover_signals AS t
                    ON t.ecosystem = j.ecosystem AND t.name = j.name AND t.version = j.version
                WHERE j.status = 'pending' AND j.ecosystem IN ({marks})
                    AND (t.name IS NULL OR (t.retry_at IS NOT NULL AND t.retry_at <= ?))
                ORDER BY j.created_at DESC, j.ecosystem, j.name, j.version
                LIMIT ?
                """,
                (*ecosystems, iso(now or utcnow()), limit),
            ).fetchall()
        return list(rows)

    def save_takeover_signals(
        self,
        ecosystem: str,
        name: str,
        version: str,
        score: int,
        signals: list[str],
        detail: dict,
        *,
        old_version: str | None = None,
        error: str = "",
        when: datetime | None = None,
        retry_at: datetime | None = None,
    ) -> None:
        """`retry_at` marks a transient read failure to score again; each save counts an attempt."""
        moment = iso(when or utcnow())
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO takeover_signals (
                    ecosystem, name, version, old_version, score, signals_json, detail_json, error, created_at,
                    attempts, retry_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                ON CONFLICT(ecosystem, name, version) DO UPDATE SET
                    old_version = excluded.old_version,
                    score = excluded.score,
                    signals_json = excluded.signals_json,
                    detail_json = excluded.detail_json,
                    error = excluded.error,
                    created_at = excluded.created_at,
                    attempts = takeover_signals.attempts + 1,
                    retry_at = excluded.retry_at
                """,
                (
                    ecosystem,
                    name,
                    version,
                    old_version,
                    int(score),
                    json.dumps(list(signals)),
                    json.dumps(detail, sort_keys=True, default=str),
                    error or None,
                    moment,
                    iso(retry_at) if retry_at is not None else None,
                ),
            )
            self._conn.commit()

    def takeover_signals(self, ecosystem: str, name: str, version: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM takeover_signals WHERE ecosystem = ? AND name = ? AND version = ?",
                (ecosystem, name, version),
            ).fetchone()
        if row is None:
            return None
        found = dict(row)
        found["signals"] = json.loads(found.pop("signals_json") or "[]")
        found["detail"] = json.loads(found.pop("detail_json") or "{}")
        return found

    def last_takeover_owners(self, ecosystem: str, name: str, *, exclude_version: str | None = None) -> set[str] | None:
        """Owner names recorded with the newest scored release of this package, or None."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT version, detail_json FROM takeover_signals
                WHERE ecosystem = ? AND name = ?
                ORDER BY created_at DESC
                """,
                (ecosystem, name),
            ).fetchall()
        for row in rows:
            if exclude_version is not None and str(row["version"]) == exclude_version:
                continue
            try:
                owners = (json.loads(row["detail_json"] or "{}") or {}).get("owners")
            except ValueError:
                continue
            if owners:
                return {str(item) for item in owners}
        return None

    def takeover_counts(self) -> dict:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT COUNT(*) AS scored, SUM(CASE WHEN score > 0 THEN 1 ELSE 0 END) AS flagged
                FROM takeover_signals
                """
            ).fetchone()
        return {"scored": int(row["scored"] or 0), "flagged": int(row["flagged"] or 0)}

    def reopen_job(
        self,
        ecosystem: str,
        name: str,
        version: str,
        rank: int | None = None,
        max_pending: int | None = None,
    ) -> str:
        """Pending stays pending. Done returns to pending. A missing row is inserted.

        Returns ``pending``, ``reopened``, ``inserted``, or ``refused``.
        ``max_pending`` refuses a new pending row when the queue is already full.
        An already-pending job is not refused.
        """
        moment = iso(utcnow())
        with self._lock:
            row = self._conn.execute(
                """
                SELECT status FROM release_jobs
                WHERE ecosystem = ? AND name = ? AND version = ?
                """,
                (ecosystem, name, version),
            ).fetchone()
            if row is not None and str(row["status"]) == "pending":
                return "pending"
            if max_pending is not None:
                count = self._conn.execute(
                    "SELECT COUNT(*) AS n FROM release_jobs WHERE status = 'pending'"
                ).fetchone()
                if int(count["n"]) >= max_pending:
                    return "refused"
            if row is None:
                self._conn.execute(
                    """
                    INSERT INTO release_jobs (ecosystem, name, version, rank, status, created_at)
                    VALUES (?, ?, ?, ?, 'pending', ?)
                    """,
                    (ecosystem, name, version, rank, moment),
                )
                self._conn.commit()
                return "inserted"
            self._conn.execute(
                """
                UPDATE release_jobs SET status = 'pending'
                WHERE ecosystem = ? AND name = ? AND version = ?
                """,
                (ecosystem, name, version),
            )
            self._conn.commit()
        return "reopened"

    def finish_job(self, ecosystem: str, name: str, version: str) -> None:
        with self._lock:
            self._conn.execute(
                """
                UPDATE release_jobs SET status = 'done'
                WHERE ecosystem = ? AND name = ? AND version = ?
                """,
                (ecosystem, name, version),
            )
            self._conn.commit()

    def save_train_row(self, fixture_id: str, features_json: str, label: int, model_id: str) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO train_cache (fixture_id, features_json, label, model_id)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(fixture_id) DO UPDATE SET
                    features_json = excluded.features_json,
                    label = excluded.label,
                    model_id = excluded.model_id
                """,
                (fixture_id, features_json, label, model_id),
            )
            self._conn.commit()

    def train_rows(self) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute("SELECT * FROM train_cache").fetchall())

    def enqueue_classify_retry(
        self,
        ecosystem: str,
        name: str,
        version: str,
        rank: int | None,
        error: str,
        when: datetime | None = None,
    ) -> None:
        moment = when or utcnow()
        with self._lock:
            row = self._conn.execute(
                """
                SELECT attempts FROM classify_retries
                WHERE ecosystem = ? AND name = ? AND version = ?
                """,
                (ecosystem, name, version),
            ).fetchone()
            attempts = int(row["attempts"]) if row else 0
            if attempts >= 5 and not never_park(rank):
                return
            delay = _retry_delay(attempts)
            nxt = moment + timedelta(seconds=delay)
            self._conn.execute(
                """
                INSERT INTO classify_retries (
                    ecosystem, name, version, rank, attempts, next_attempt_at, last_error, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
                ON CONFLICT(ecosystem, name, version) DO UPDATE SET
                    next_attempt_at = excluded.next_attempt_at,
                    last_error = excluded.last_error,
                    status = 'pending'
                """,
                (ecosystem, name, version, rank, attempts, iso(nxt), error[:500]),
            )
            self._conn.commit()

    def due_classify_retries(self, when: datetime | None = None, limit: int = 50) -> list[sqlite3.Row]:
        moment = iso(when or utcnow())
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT ecosystem, name, version, rank, attempts
                FROM classify_retries
                WHERE status IN ('pending', 'retrying') AND next_attempt_at <= ?
                ORDER BY next_attempt_at
                LIMIT ?
                """,
                (moment, limit),
            ).fetchall()
        return list(rows)

    def bump_classify_retry(self, ecosystem: str, name: str, version: str, when: datetime | None = None) -> None:
        moment = when or utcnow()
        with self._lock:
            row = self._conn.execute(
                """
                SELECT attempts, rank FROM classify_retries
                WHERE ecosystem = ? AND name = ? AND version = ?
                """,
                (ecosystem, name, version),
            ).fetchone()
            if row is None:
                return
            attempts = int(row["attempts"]) + 1
            delay = _retry_delay(attempts)
            status = "pending" if attempts < 5 or never_park(row["rank"]) else "exhausted"
            nxt = moment + timedelta(seconds=delay)
            self._conn.execute(
                """
                UPDATE classify_retries
                SET attempts = ?, next_attempt_at = ?, status = ?
                WHERE ecosystem = ? AND name = ? AND version = ?
                """,
                (attempts, iso(nxt), status, ecosystem, name, version),
            )
            self._conn.commit()

    def clear_classify_retry(self, ecosystem: str, name: str, version: str) -> None:
        with self._lock:
            self._conn.execute(
                """
                UPDATE classify_retries SET status = 'done'
                WHERE ecosystem = ? AND name = ? AND version = ?
                """,
                (ecosystem, name, version),
            )
            self._conn.commit()

    def retry_depth(self) -> int:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT COUNT(*) AS n FROM classify_retries
                WHERE status IN ('pending', 'retrying')
                """
            ).fetchone()
        return int(row["n"])

    def note_classify_failure(
        self,
        ecosystem: str,
        name: str,
        version: str,
        rank: int | None,
        error: str,
        *,
        reason: str = "",
        max_attempts: int = 5,
        when: datetime | None = None,
    ) -> str:
        """Record one failed classify attempt. Returns `retrying` or `exhausted`.

        A top ranked release (see NEVER_PARK_RANK) is never exhausted: it keeps retrying.
        """
        moment = when or utcnow()
        limit = max(1, int(max_attempts))
        with self._lock:
            row = self._conn.execute(
                """
                SELECT attempts, status FROM classify_retries
                WHERE ecosystem = ? AND name = ? AND version = ?
                """,
                (ecosystem, name, version),
            ).fetchone()
            keep = never_park(rank)
            if row is not None and str(row["status"]) == "exhausted" and not keep:
                return "exhausted"
            attempts = (int(row["attempts"]) if row else 0) + 1
            status = "exhausted" if attempts >= limit and not keep else "retrying"
            delay = _retry_delay(attempts - 1)
            nxt = moment + timedelta(seconds=delay)
            self._conn.execute(
                """
                INSERT INTO classify_retries (
                    ecosystem, name, version, rank, attempts, next_attempt_at, last_error, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ecosystem, name, version) DO UPDATE SET
                    rank = excluded.rank,
                    attempts = excluded.attempts,
                    next_attempt_at = excluded.next_attempt_at,
                    last_error = excluded.last_error,
                    status = excluded.status
                """,
                (ecosystem, name, version, rank, attempts, iso(nxt), error[:500], status),
            )
            if status == "exhausted":
                self._upsert_human_review(
                    kind="classify",
                    idempotency_key=f"{ecosystem}:{name}:{version}",
                    ecosystem=ecosystem,
                    name=name,
                    version=version,
                    attempts=attempts,
                    last_error=error,
                    reason=reason or error,
                    moment=iso(moment),
                )
            self._conn.commit()
        return status

    def enqueue_investigation(self, idempotency_key: str, body: str, when: datetime | None = None) -> bool:
        moment = iso(when or utcnow())
        with self._lock:
            try:
                self._conn.execute(
                    """
                    INSERT INTO investigations (
                        idempotency_key, body, status, attempts, next_attempt_at, created_at, updated_at
                    ) VALUES (?, ?, 'pending', 0, ?, ?, ?)
                    """,
                    (idempotency_key, body, moment, moment, moment),
                )
                self._conn.commit()
            except sqlite3.IntegrityError:
                return False
        return True

    def due_investigations(self, when: datetime | None = None, limit: int = 20) -> list[sqlite3.Row]:
        moment = iso(when or utcnow())
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT idempotency_key, body, attempts
                FROM investigations
                WHERE status IN ('pending', 'retrying') AND next_attempt_at <= ?
                ORDER BY created_at
                LIMIT ?
                """,
                (moment, limit),
            ).fetchall()
        return list(rows)

    def mark_investigation_reported(self, idempotency_key: str, report: str, when: datetime | None = None) -> None:
        moment = iso(when or utcnow())
        with self._lock:
            self._conn.execute(
                """
                UPDATE investigations
                SET status = 'reported', report_text = ?, last_error = NULL, updated_at = ?
                WHERE idempotency_key = ?
                """,
                (report[:20_000], moment, idempotency_key),
            )
            self._conn.commit()

    def mark_investigation_retry(self, idempotency_key: str, attempts: int, error: str, when: datetime | None = None) -> None:
        moment = when or utcnow()
        delay = min(3600, 2 ** max(attempts - 1, 0))
        nxt = moment + timedelta(seconds=delay)
        with self._lock:
            self._conn.execute(
                """
                UPDATE investigations
                SET attempts = ?, next_attempt_at = ?, last_error = ?, status = 'retrying', updated_at = ?
                WHERE idempotency_key = ?
                """,
                (attempts, iso(nxt), error[:500], iso(moment), idempotency_key),
            )
            self._conn.commit()

    def mark_investigation_exhausted(
        self,
        idempotency_key: str,
        attempts: int,
        error: str,
        *,
        ecosystem: str = "",
        name: str = "",
        version: str = "",
        reason: str = "composer_failed",
        when: datetime | None = None,
    ) -> None:
        moment = when or utcnow()
        with self._lock:
            self._conn.execute(
                """
                UPDATE investigations
                SET attempts = ?, last_error = ?, status = 'exhausted', updated_at = ?
                WHERE idempotency_key = ?
                """,
                (attempts, error[:500], iso(moment), idempotency_key),
            )
            self._upsert_human_review(
                kind="investigation",
                idempotency_key=idempotency_key,
                ecosystem=ecosystem,
                name=name,
                version=version,
                attempts=attempts,
                last_error=error,
                reason=reason,
                moment=iso(moment),
            )
            self._conn.commit()

    def investigation_depth(self) -> int:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT COUNT(*) AS n FROM investigations
                WHERE status IN ('pending', 'retrying')
                """
            ).fetchone()
        return int(row["n"])

    def _upsert_human_review(
        self,
        *,
        kind: str,
        idempotency_key: str,
        ecosystem: str,
        name: str,
        version: str,
        attempts: int,
        last_error: str,
        reason: str,
        moment: str,
    ) -> None:
        """Caller holds `_lock`. Does not commit."""
        self._conn.execute(
            """
            INSERT INTO human_review_queue (
                kind, idempotency_key, ecosystem, name, version, attempts,
                last_error, reason, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(kind, idempotency_key) DO UPDATE SET
                attempts = excluded.attempts,
                last_error = excluded.last_error,
                reason = excluded.reason,
                updated_at = excluded.updated_at
            """,
            (
                kind,
                idempotency_key,
                ecosystem,
                name,
                version,
                attempts,
                (last_error or "")[:500],
                (reason or "")[:200],
                moment,
                moment,
            ),
        )

    def human_review_queue(self, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT kind, idempotency_key, ecosystem, name, version, attempts,
                       last_error, reason, created_at, updated_at
                FROM human_review_queue
                ORDER BY updated_at, kind, idempotency_key
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def human_review_depth(self) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM human_review_queue"
            ).fetchone()
        return int(row["n"])

    def investigation_report(self, idempotency_key: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT report_text, status FROM investigations WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
        if row is None:
            return None
        return row["report_text"]

    def investigation_status(self, idempotency_key: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT status FROM investigations WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
        if row is None:
            return None
        return str(row["status"])

    def mark_investigation_suppressed(
        self,
        idempotency_key: str,
        report: str,
        when: datetime | None = None,
    ) -> None:
        """Skip Triage. The row leaves the pending queue and does not post an alert."""
        moment = iso(when or utcnow())
        with self._lock:
            self._conn.execute(
                """
                UPDATE investigations
                SET status = 'suppressed', report_text = ?, last_error = NULL, updated_at = ?
                WHERE idempotency_key = ?
                """,
                (report[:20_000], moment, idempotency_key),
            )
            self._conn.commit()

    def enqueue_analyst(self, idempotency_key: str, body: str, when: datetime | None = None) -> bool:
        moment = iso(when or utcnow())
        with self._lock:
            try:
                self._conn.execute(
                    """
                    INSERT INTO analyst_reviews (
                        idempotency_key, body, status, attempts, next_attempt_at, created_at, updated_at
                    ) VALUES (?, ?, 'pending', 0, ?, ?, ?)
                    """,
                    (idempotency_key, body, moment, moment, moment),
                )
                self._conn.commit()
            except sqlite3.IntegrityError:
                return False
        return True

    def due_analyst(self, when: datetime | None = None, limit: int = 20) -> list[sqlite3.Row]:
        moment = iso(when or utcnow())
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT idempotency_key, body, attempts
                FROM analyst_reviews
                WHERE status IN ('pending', 'retrying') AND next_attempt_at <= ?
                ORDER BY created_at
                LIMIT ?
                """,
                (moment, limit),
            ).fetchall()
        return list(rows)

    def mark_analyst_reported(
        self,
        idempotency_key: str,
        report: str,
        verdict: str | None,
        lesson_id: str | None,
        when: datetime | None = None,
    ) -> None:
        moment = iso(when or utcnow())
        with self._lock:
            self._conn.execute(
                """
                UPDATE analyst_reviews
                SET status = 'reported', report_text = ?, verdict = ?, lesson_id = ?,
                    last_error = NULL, updated_at = ?
                WHERE idempotency_key = ?
                """,
                (report[:20_000], verdict, lesson_id, moment, idempotency_key),
            )
            self._conn.commit()

    def mark_analyst_retry(
        self, idempotency_key: str, attempts: int, error: str, when: datetime | None = None
    ) -> None:
        moment = when or utcnow()
        delay = min(3600, 2 ** max(attempts - 1, 0))
        nxt = moment + timedelta(seconds=delay)
        with self._lock:
            self._conn.execute(
                """
                UPDATE analyst_reviews
                SET attempts = ?, next_attempt_at = ?, last_error = ?, status = 'retrying', updated_at = ?
                WHERE idempotency_key = ?
                """,
                (attempts, iso(nxt), error[:500], iso(moment), idempotency_key),
            )
            self._conn.commit()

    def mark_analyst_exhausted(
        self,
        idempotency_key: str,
        attempts: int,
        error: str,
        *,
        ecosystem: str = "",
        name: str = "",
        version: str = "",
        reason: str = "analyst_failed",
        when: datetime | None = None,
    ) -> None:
        moment = when or utcnow()
        with self._lock:
            self._conn.execute(
                """
                UPDATE analyst_reviews
                SET attempts = ?, last_error = ?, status = 'exhausted', updated_at = ?
                WHERE idempotency_key = ?
                """,
                (attempts, error[:500], iso(moment), idempotency_key),
            )
            self._upsert_human_review(
                kind="analyst",
                idempotency_key=idempotency_key,
                ecosystem=ecosystem,
                name=name,
                version=version,
                attempts=attempts,
                last_error=error,
                reason=reason,
                moment=iso(moment),
            )
            self._conn.commit()

    def analyst_depth(self) -> int:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT COUNT(*) AS n FROM analyst_reviews
                WHERE status IN ('pending', 'retrying')
                """
            ).fetchone()
        return int(row["n"])

    def try_spend_budget(self, role: str, limit: int | None, when: datetime | None = None) -> bool:
        """Increment a model spend. False when a finite cap is already met."""
        moment = iso(when or utcnow())
        with self._lock:
            row = self._conn.execute(
                "SELECT used FROM model_budget WHERE role = ?",
                (role,),
            ).fetchone()
            used = 0 if row is None else int(row["used"])
            if limit is not None and used >= limit:
                return False
            self._conn.execute(
                """
                INSERT INTO model_budget (role, used, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(role) DO UPDATE SET
                    used = excluded.used,
                    updated_at = excluded.updated_at
                """,
                (role, used + 1, moment),
            )
            self._conn.commit()
        return True

    def budget_used(self, role: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT used FROM model_budget WHERE role = ?",
                (role,),
            ).fetchone()
        if row is None:
            return 0
        return int(row["used"])

    def add_scout_usage(
        self,
        *,
        day: str,
        provider: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        usd: float,
        estimated: bool = False,
        when: datetime | None = None,
    ) -> None:
        moment = iso(when or utcnow())
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO scout_usage (
                    day, provider, model, calls, estimated_calls,
                    input_tokens, output_tokens, usd, updated_at
                )
                VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?)
                ON CONFLICT(day, provider, model) DO UPDATE SET
                    calls = calls + 1,
                    estimated_calls = estimated_calls + excluded.estimated_calls,
                    input_tokens = input_tokens + excluded.input_tokens,
                    output_tokens = output_tokens + excluded.output_tokens,
                    usd = usd + excluded.usd,
                    updated_at = excluded.updated_at
                """,
                (day, provider, model, 1 if estimated else 0, input_tokens, output_tokens, usd, moment),
            )
            self._conn.commit()

    def scout_spend(self, day: str) -> float:
        with self._lock:
            row = self._conn.execute(
                "SELECT COALESCE(SUM(usd), 0) AS usd FROM scout_usage WHERE day = ?",
                (day,),
            ).fetchone()
        return float(row["usd"])

    def scout_usage_rows(self, day: str | None = None) -> list[dict]:
        query = "SELECT * FROM scout_usage"
        params: tuple = ()
        if day is not None:
            query += " WHERE day = ?"
            params = (day,)
        with self._lock:
            rows = self._conn.execute(query + " ORDER BY day, provider, model", params).fetchall()
        return [dict(row) for row in rows]

    def scout_spend_stop(self) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT cap_usd, day, reached_at FROM scout_spend_stop WHERE id = 1").fetchone()
        return None if row is None else dict(row)

    def set_scout_spend_stop(self, cap_usd: str, day: str, when: datetime | None = None) -> None:
        moment = iso(when or utcnow())
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO scout_spend_stop (id, cap_usd, day, reached_at) VALUES (1, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    cap_usd = excluded.cap_usd, day = excluded.day, reached_at = excluded.reached_at
                """,
                (cap_usd, day, moment),
            )
            self._conn.commit()

    def clear_scout_spend_stop(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM scout_spend_stop")
            self._conn.commit()

    def insert_public_feed_item(
        self,
        *,
        ecosystem: str,
        name: str,
        version: str,
        previous_version: str,
        registry_url: str,
        behavior: str,
        cause: str,
        limited_review: bool,
        first_seen_at: str,
    ) -> bool:
        """Store one public alert. A repeat of the same version keeps the first time."""
        with self._lock:
            cursor = self._conn.execute(
                """
                INSERT INTO public_feed_items (
                    ecosystem, name, version, previous_version, registry_url,
                    behavior, cause, limited_review, first_seen_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ecosystem, name, version) DO NOTHING
                """,
                (
                    ecosystem,
                    name,
                    version,
                    previous_version,
                    registry_url,
                    behavior,
                    cause,
                    1 if limited_review else 0,
                    first_seen_at,
                ),
            )
            self._conn.commit()
        return cursor.rowcount > 0

    def public_feed_items(self, limit: int) -> list[sqlite3.Row]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT ecosystem, name, version, previous_version, registry_url,
                       behavior, cause, limited_review, first_seen_at
                FROM public_feed_items
                ORDER BY first_seen_at DESC, ecosystem, name, version
                LIMIT ?
                """,
                (max(0, int(limit)),),
            ).fetchall()
        return list(rows)

    def public_feed_state(self) -> sqlite3.Row | None:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT content_hash, published_at, last_error
                FROM public_feed_state
                WHERE id = 1
                """
            ).fetchone()
        return row

    def mark_public_feed_published(self, content_hash: str, when: datetime | None = None) -> None:
        moment = iso(when or utcnow())
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO public_feed_state (id, content_hash, published_at, last_error)
                VALUES (1, ?, ?, NULL)
                ON CONFLICT(id) DO UPDATE SET
                    content_hash = excluded.content_hash,
                    published_at = excluded.published_at,
                    last_error = NULL
                """,
                (content_hash, moment),
            )
            self._conn.commit()

    def mark_public_feed_error(self, error: str) -> None:
        """Record a failed upload without changing the last successful hash."""
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO public_feed_state (id, content_hash, published_at, last_error)
                VALUES (1, NULL, NULL, ?)
                ON CONFLICT(id) DO UPDATE SET last_error = excluded.last_error
                """,
                (error[:300],),
            )
            self._conn.commit()

    def public_dash_state(self) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                """
                SELECT live_hash, benchmark_hash, published_at, last_error
                FROM public_dash_state
                WHERE id = 1
                """
            ).fetchone()

    def mark_public_dash_live_published(self, live_hash: str, when: datetime | None = None) -> None:
        moment = iso(when or utcnow())
        with self._lock:
            self._conn.execute("INSERT OR IGNORE INTO public_dash_state (id) VALUES (1)")
            self._conn.execute(
                """
                UPDATE public_dash_state
                SET live_hash = ?, published_at = ?, last_error = NULL
                WHERE id = 1
                """,
                (live_hash, moment),
            )
            self._conn.commit()

    def mark_public_dash_benchmark_published(self, benchmark_hash: str, when: datetime | None = None) -> None:
        with self._lock:
            self._conn.execute("INSERT OR IGNORE INTO public_dash_state (id) VALUES (1)")
            self._conn.execute(
                """
                UPDATE public_dash_state
                SET benchmark_hash = ?, last_error = NULL
                WHERE id = 1
                """,
                (benchmark_hash,),
            )
            self._conn.commit()

    def mark_public_dash_published_at(self, moment: str) -> None:
        with self._lock:
            self._conn.execute("INSERT OR IGNORE INTO public_dash_state (id) VALUES (1)")
            self._conn.execute(
                "UPDATE public_dash_state SET published_at = ? WHERE id = 1",
                (moment,),
            )
            self._conn.commit()

    def mark_public_dash_error(self, error: str) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO public_dash_state (id, live_hash, benchmark_hash, published_at, last_error)
                VALUES (1, NULL, NULL, NULL, ?)
                ON CONFLICT(id) DO UPDATE SET last_error = excluded.last_error
                """,
                (error[:300],),
            )
            self._conn.commit()

    def public_dash_release_hash(self, release_key: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT content_hash FROM public_dash_releases WHERE release_key = ?",
                (release_key,),
            ).fetchone()
        return None if row is None else str(row["content_hash"])

    def mark_public_dash_release(self, release_key: str, content_hash: str) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO public_dash_releases (release_key, content_hash)
                VALUES (?, ?)
                ON CONFLICT(release_key) DO UPDATE SET content_hash = excluded.content_hash
                """,
                (release_key, content_hash),
            )
            self._conn.commit()

    def public_dash_releases_to_check(self, release_keys: list[str]) -> dict[str, int]:
        """Of `release_keys`, those whose public object may be missing or stale.

        Returns key -> newest dirty id (0 when the key was never published). Keys that
        were never published get a placeholder row first, so a write that lands while the
        publisher is building their object marks them dirty for the next cycle.
        """
        if not release_keys:
            return {}
        payload = json.dumps(list(release_keys))
        with self._lock:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO public_dash_releases (release_key, content_hash)
                SELECT value, '' FROM json_each(?)
                """,
                (payload,),
            )
            rows = self._conn.execute(
                """
                SELECT k.value AS release_key, p.content_hash,
                       (SELECT MAX(d.id) FROM public_dash_dirty d WHERE d.release_key = k.value) AS dirty_id
                FROM json_each(?) k
                JOIN public_dash_releases p ON p.release_key = k.value
                """,
                (payload,),
            ).fetchall()
            self._conn.commit()
        return {
            str(row["release_key"]): int(row["dirty_id"] or 0)
            for row in rows
            if row["content_hash"] == "" or row["dirty_id"] is not None
        }

    def clear_public_dash_dirty(self, checked: dict[str, int]) -> None:
        """Forget dirty marks up to the ids seen when `checked` was read. Later marks stay."""
        pairs = [(key, dirty_id) for key, dirty_id in checked.items() if dirty_id]
        if not pairs:
            return
        with self._lock:
            self._conn.executemany(
                "DELETE FROM public_dash_dirty WHERE release_key = ? AND id <= ?",
                pairs,
            )
            self._conn.commit()

    def note_decision_model_failure(self, when: datetime | None = None) -> dict:
        """Count one release no decision model could answer. Opens an outage on the first one."""
        moment = iso(when or utcnow())
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO decision_model_outage (id, started_at, failures, notified_at) VALUES (1, ?, 1, NULL)
                ON CONFLICT(id) DO UPDATE SET failures = failures + 1
                """,
                (moment,),
            )
            self._conn.commit()
            row = self._conn.execute(
                "SELECT started_at, failures, notified_at FROM decision_model_outage WHERE id = 1"
            ).fetchone()
        return dict(row)

    def mark_decision_model_outage_notified(self, when: datetime | None = None) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE decision_model_outage SET notified_at = ? WHERE id = 1",
                (iso(when or utcnow()),),
            )
            self._conn.commit()

    def clear_decision_model_outage(self) -> dict | None:
        """End the outage after a decision model answered. Returns the outage that ended, if any."""
        with self._lock:
            row = self._conn.execute(
                "SELECT started_at, failures, notified_at FROM decision_model_outage WHERE id = 1"
            ).fetchone()
            if row is None:
                return None
            self._conn.execute("DELETE FROM decision_model_outage")
            self._conn.commit()
        return dict(row)

    def deferred_release_counts(self) -> tuple[int, int]:
        """Releases waiting on a decision model, and how many of them have a promoted rule hit."""
        with self._lock:
            row = self._conn.execute(
                """
                SELECT COUNT(*) AS waiting,
                       SUM(CASE WHEN payload_json LIKE '%"rule_malicious"%' THEN 1 ELSE 0 END) AS strong
                FROM releases WHERE band = 'deferred'
                """
            ).fetchone()
        return int(row["waiting"] or 0), int(row["strong"] or 0)

    # Read-only queries for the dashboard. None of these change state.

    def release_bucket_counts(self, since: str, width: int, watched_only: bool = False) -> list[dict]:
        """Classified releases per time bucket, ecosystem and band. `width` is the ISO prefix length."""
        with self._lock:
            rows = self._conn.execute(
                f"""
                SELECT substr(created_at, 1, ?) AS bucket, ecosystem, band, COUNT(*) AS n
                FROM releases WHERE created_at >= ? {_USER_WATCH_FILTER if watched_only else ""}
                GROUP BY bucket, ecosystem, band
                """,
                (width, since),
            ).fetchall()
        return [dict(row) for row in rows]

    def flagged_releases_since(self, since: str, limit: int = 5000, watched_only: bool = False) -> list[dict]:
        """Releases Scout did not clear (review, alert or deferred), newest first."""
        with self._lock:
            rows = self._conn.execute(
                f"""
                SELECT ecosystem, name, version, band, malice_probability, family, subtype,
                       payload_json, created_at
                FROM releases
                WHERE created_at >= ? AND band IN ('review', 'alert', 'deferred')
                  {_USER_WATCH_FILTER if watched_only else ""}
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (since, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def ground_truth_releases(self, since: str) -> list[dict]:
        """npm, PyPI, and Open VSX releases first saved at or after `since`, with the confirmed public-alert time if any.

        `scored_at` is when the release was first caught (review or alert), or when the band last
        changed outside the caught bands (a deferred release re-scored later),
        or the first save for rows written before that column existed.
        """
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT r.ecosystem, r.name, r.version, r.band, r.payload_json, r.created_at,
                       COALESCE(r.scored_at, r.created_at) AS scored_at,
                       p.first_seen_at AS confirmed_at
                FROM releases r
                LEFT JOIN public_feed_items p
                  ON p.ecosystem = r.ecosystem AND p.name = r.name AND p.version = r.version
                WHERE r.ecosystem IN ('npm', 'pypi', 'openvsx', 'crates') AND r.created_at >= ?
                """,
                (since,),
            ).fetchall()
        return [dict(row) for row in rows]

    def investigations_since(self, since: str, limit: int = 5000) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT idempotency_key, status, attempts, report_text, created_at, updated_at
                FROM investigations WHERE created_at >= ?
                ORDER BY created_at DESC LIMIT ?
                """,
                (since, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def analyst_reviews_since(self, since: str, limit: int = 5000) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT idempotency_key, status, attempts, verdict, created_at, updated_at
                FROM analyst_reviews WHERE created_at >= ?
                ORDER BY created_at DESC LIMIT ?
                """,
                (since, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def outbox_since(self, since: str, limit: int = 5000) -> list[dict]:
        """Webhook rows without their bodies or error text, which can hold delivery details."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT idempotency_key, status, attempts, created_at, sent_at,
                       last_error IS NOT NULL AS has_error
                FROM outbox WHERE created_at >= ?
                ORDER BY created_at DESC LIMIT ?
                """,
                (since, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def releases_scored_since(self, since: str, limit: int = 250) -> list[dict]:
        """Every release Scout scored at or after `since`, any band, newest first."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT ecosystem, name, version, band, created_at
                FROM releases WHERE created_at >= ?
                ORDER BY created_at DESC LIMIT ?
                """,
                (since, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def investigations_touched_since(self, since: str, limit: int = 250) -> list[dict]:
        """Triage rows queued or updated at or after `since`, newest first."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT idempotency_key, status, report_text, created_at, updated_at
                FROM investigations WHERE created_at >= ? OR updated_at >= ?
                ORDER BY updated_at DESC LIMIT ?
                """,
                (since, since, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def analyst_reviews_touched_since(self, since: str, limit: int = 250) -> list[dict]:
        """Analyst rows queued or updated at or after `since`, newest first."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT idempotency_key, status, verdict, created_at, updated_at
                FROM analyst_reviews WHERE created_at >= ? OR updated_at >= ?
                ORDER BY updated_at DESC LIMIT ?
                """,
                (since, since, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def alerts_sent_since(self, since: str, limit: int = 250) -> list[dict]:
        """Outbox keys and send times for rows sent at or after `since`, newest first."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT idempotency_key, sent_at
                FROM outbox WHERE status = 'sent' AND sent_at >= ?
                ORDER BY sent_at DESC LIMIT ?
                """,
                (since, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def scout_usage_since(self, day: str) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM scout_usage WHERE day >= ? ORDER BY day, provider, model",
                (day,),
            ).fetchall()
        return [dict(row) for row in rows]

    def poll_errors(self) -> dict[str, str | None]:
        with self._lock:
            rows = self._conn.execute("SELECT ecosystem, last_error FROM poll_status").fetchall()
        return {row["ecosystem"]: row["last_error"] for row in rows}

    def release_detail(self, ecosystem: str, name: str, version: str) -> dict | None:
        """One release with its Triage, Analyst and webhook rows. Webhook bodies and errors are left out."""
        key = f"{ecosystem}:{name}:{version}"
        with self._lock:
            release = self._conn.execute(
                """
                SELECT ecosystem, name, version, band, malice_probability, family, subtype,
                       payload_json, created_at
                FROM releases WHERE ecosystem = ? AND name = ? AND version = ?
                """,
                (ecosystem, name, version),
            ).fetchone()
            if release is None:
                return None
            triage = self._conn.execute(
                """
                SELECT status, attempts, report_text, created_at, updated_at
                FROM investigations WHERE idempotency_key = ?
                """,
                (key,),
            ).fetchone()
            analyst = self._conn.execute(
                """
                SELECT status, attempts, report_text, verdict, created_at, updated_at
                FROM analyst_reviews WHERE idempotency_key = ?
                """,
                (key,),
            ).fetchone()
            outbox = self._conn.execute(
                """
                SELECT idempotency_key, status, attempts, created_at, sent_at,
                       last_error IS NOT NULL AS has_error
                FROM outbox WHERE idempotency_key IN (?, ?)
                ORDER BY created_at
                """,
                (key, f"{key}:analysis"),
            ).fetchall()
        return {
            "release": dict(release),
            "triage": None if triage is None else dict(triage),
            "analyst": None if analyst is None else dict(analyst),
            "outbox": [dict(row) for row in outbox],
        }

    # --- GitHub Actions ----------------------------------------------------

    def action_tags(self, name: str) -> dict[str, tuple[str, str]]:
        """Recorded tags of one action: tag -> (commit sha, first seen)."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT tag, sha, first_seen_at FROM action_tags WHERE name = ?",
                (name,),
            ).fetchall()
        return {str(row["tag"]): (str(row["sha"]), str(row["first_seen_at"])) for row in rows}

    def action_state(self, name: str) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                """
                SELECT name, seeded_at, last_polled_at, last_swept_at, default_branch, last_error
                FROM action_state WHERE name = ?
                """,
                (name,),
            ).fetchone()

    def action_states(self) -> dict[str, sqlite3.Row]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT name, seeded_at, last_polled_at, last_swept_at, default_branch, last_error FROM action_state"
            ).fetchall()
        return {str(row["name"]): row for row in rows}

    def mark_action_error(self, name: str, error: str, when: datetime | None = None) -> None:
        moment = iso(when or utcnow())
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO action_state (name, last_polled_at, last_error) VALUES (?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET last_polled_at = excluded.last_polled_at,
                    last_error = excluded.last_error
                """,
                (name, moment, error[:300]),
            )
            self._conn.commit()

    def record_action_poll(
        self,
        name: str,
        *,
        seen: dict[str, str],
        moved: dict[str, tuple[str, str]],
        added: dict[str, str],
        deleted: dict[str, str],
        events: list[dict],
        rank: int | None,
        default_branch: str | None,
        seed: bool,
        sweep: bool,
        when: datetime | None = None,
        max_pending: int | None = None,
    ) -> int:
        """Apply one poll of one action in a single transaction. Returns the number of jobs queued.

        ``seen`` is every tag read this poll. ``moved`` maps tag -> (old sha, new sha).
        ``events`` become rows in ``action_events`` and ``release_jobs``.
        """
        moment = iso(when or utcnow())
        queued = 0
        with self._lock:
            try:
                for tag, sha in added.items():
                    self._conn.execute(
                        """
                        INSERT INTO action_tags (name, tag, sha, first_seen_at, last_seen_at)
                        VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT(name, tag) DO UPDATE SET sha = excluded.sha, last_seen_at = excluded.last_seen_at
                        """,
                        (name, tag, sha, moment, moment),
                    )
                    if not seed:
                        self._conn.execute(
                            """
                            INSERT INTO action_tag_moves (name, tag, kind, old_sha, new_sha, seen_at)
                            VALUES (?, ?, 'new', NULL, ?, ?)
                            """,
                            (name, tag, sha, moment),
                        )
                for tag, (old_sha, new_sha) in moved.items():
                    self._conn.execute(
                        "UPDATE action_tags SET sha = ?, last_seen_at = ? WHERE name = ? AND tag = ?",
                        (new_sha, moment, name, tag),
                    )
                    self._conn.execute(
                        """
                        INSERT INTO action_tag_moves (name, tag, kind, old_sha, new_sha, seen_at)
                        VALUES (?, ?, 'moved', ?, ?, ?)
                        """,
                        (name, tag, old_sha, new_sha, moment),
                    )
                for tag, old_sha in deleted.items():
                    self._conn.execute("DELETE FROM action_tags WHERE name = ? AND tag = ?", (name, tag))
                    self._conn.execute(
                        """
                        INSERT INTO action_tag_moves (name, tag, kind, old_sha, new_sha, seen_at)
                        VALUES (?, ?, 'deleted', ?, NULL, ?)
                        """,
                        (name, tag, old_sha, moment),
                    )
                unchanged = [tag for tag in seen if tag not in added and tag not in moved]
                for start in range(0, len(unchanged), 500):
                    chunk = unchanged[start : start + 500]
                    marks = ",".join("?" for _ in chunk)
                    self._conn.execute(
                        f"UPDATE action_tags SET last_seen_at = ? WHERE name = ? AND tag IN ({marks})",
                        (moment, name, *chunk),
                    )
                pending = None
                if max_pending is not None:
                    row = self._conn.execute(
                        "SELECT COUNT(*) AS n FROM release_jobs WHERE status = 'pending'"
                    ).fetchone()
                    pending = int(row["n"])
                for event in events:
                    inserted = self._conn.execute(
                        """
                        INSERT OR IGNORE INTO action_events (
                            name, version, tag, kind, old_sha, new_sha, moves_in_poll, tag_first_seen_at, seen_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            name,
                            event["version"],
                            event["tag"],
                            event["kind"],
                            event.get("old_sha"),
                            event["new_sha"],
                            int(event.get("moves_in_poll") or 0),
                            event.get("tag_first_seen_at"),
                            moment,
                        ),
                    ).rowcount
                    if not inserted:
                        continue
                    if pending is not None and pending >= max_pending:
                        continue
                    added_job = self._conn.execute(
                        """
                        INSERT OR IGNORE INTO release_jobs (ecosystem, name, version, rank, status, created_at)
                        VALUES ('github-actions', ?, ?, ?, 'pending', ?)
                        """,
                        (name, event["version"], rank, moment),
                    ).rowcount
                    if added_job:
                        queued += 1
                        if pending is not None:
                            pending += 1
                self._conn.execute(
                    """
                    INSERT INTO action_state (name, seeded_at, last_polled_at, last_swept_at, default_branch, last_error)
                    VALUES (?, ?, ?, ?, ?, NULL)
                    ON CONFLICT(name) DO UPDATE SET
                        seeded_at = COALESCE(action_state.seeded_at, excluded.seeded_at),
                        last_polled_at = excluded.last_polled_at,
                        last_swept_at = COALESCE(excluded.last_swept_at, action_state.last_swept_at),
                        default_branch = COALESCE(excluded.default_branch, action_state.default_branch),
                        last_error = NULL
                    """,
                    (name, moment, moment, moment if sweep else None, default_branch),
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
        return queued

    def reseed_action(self, name: str) -> None:
        """Forget an action's baseline so the next poll records it again without events."""
        with self._lock:
            self._conn.execute("DELETE FROM action_tags WHERE name = ?", (name,))
            self._conn.execute("UPDATE action_state SET seeded_at = NULL WHERE name = ?", (name,))
            self._conn.commit()

    def action_event(self, name: str, version: str) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                """
                SELECT name, version, tag, kind, old_sha, new_sha, moves_in_poll, tag_first_seen_at, seen_at
                FROM action_events WHERE name = ? AND version = ?
                """,
                (name, version),
            ).fetchone()

    def action_moves(self, name: str, since: str | None = None, limit: int = 200) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT tag, kind, old_sha, new_sha, seen_at FROM action_tag_moves
                WHERE name = ? AND (? IS NULL OR seen_at >= ?)
                ORDER BY id DESC LIMIT ?
                """,
                (name, since, since, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def replace_action_watch_meta(self, rows: list[tuple[str, str, int | None, int]], when: datetime | None = None) -> None:
        """(name, sources, dependents, used_by_packages) for every watched action."""
        moment = iso(when or utcnow())
        with self._lock:
            self._conn.execute("DELETE FROM action_watch_meta")
            self._conn.executemany(
                """
                INSERT INTO action_watch_meta (name, sources, dependents, used_by_packages, refreshed_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                [(name, sources, dependents, used, moment) for name, sources, dependents, used in rows],
            )
            self._conn.commit()

    def action_watch_meta(self, name: str) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT name, sources, dependents, used_by_packages, refreshed_at FROM action_watch_meta WHERE name = ?",
                (name,),
            ).fetchone()

    def action_counts(self) -> dict[str, int]:
        """Watched actions, recorded tags, and tag events in the last day, for health and the dashboard."""
        since = iso(utcnow() - timedelta(days=1))
        with self._lock:
            watched = self._conn.execute(
                "SELECT COUNT(*) AS n FROM watchlist WHERE ecosystem = 'github-actions'"
            ).fetchone()
            tags = self._conn.execute("SELECT COUNT(*) AS n FROM action_tags").fetchone()
            moves = self._conn.execute(
                "SELECT kind, COUNT(*) AS n FROM action_tag_moves WHERE seen_at >= ? GROUP BY kind",
                (since,),
            ).fetchall()
        found = {"watched": int(watched["n"]), "tags": int(tags["n"])}
        for row in moves:
            found[f"{row['kind']}_24h"] = int(row["n"])
        return found

    def take_action_scout(self, day: str, limit: int) -> bool:
        """Count one Scout read of an action tag against today's limit. False when the limit is reached."""
        with self._lock:
            row = self._conn.execute("SELECT used FROM action_scout_days WHERE day = ?", (day,)).fetchone()
            used = int(row["used"]) if row else 0
            if used >= limit:
                return False
            self._conn.execute(
                """
                INSERT INTO action_scout_days (day, used) VALUES (?, 1)
                ON CONFLICT(day) DO UPDATE SET used = used + 1
                """,
                (day,),
            )
            self._conn.commit()
        return True

    def add_mcp_packages(self, rows: list[tuple[str, str, str]], when: datetime | None = None) -> int:
        """Record (ecosystem, name, server) rows from the MCP registry. Returns how many names were new.

        Rows are never removed: the registry is a preview and may reset its data,
        and a package that was once an MCP server stays worth watching.
        """
        moment = iso(when or utcnow())
        added = 0
        with self._lock:
            for ecosystem, name, server in rows:
                cursor = self._conn.execute(
                    """
                    INSERT INTO mcp_packages (ecosystem, name, server, first_seen_at, last_seen_at)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(ecosystem, name) DO NOTHING
                    """,
                    (ecosystem, name, server, moment, moment),
                )
                if cursor.rowcount:
                    added += 1
                else:
                    self._conn.execute(
                        "UPDATE mcp_packages SET server = ?, last_seen_at = ? WHERE ecosystem = ? AND name = ?",
                        (server, moment, ecosystem, name),
                    )
            self._conn.commit()
        return added

    def mcp_package_names(self, ecosystem: str) -> set[str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT name FROM mcp_packages WHERE ecosystem = ?",
                (ecosystem,),
            ).fetchall()
        return {str(row["name"]) for row in rows}

    def mcp_counts(self) -> dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT ecosystem, COUNT(*) AS n FROM mcp_packages GROUP BY ecosystem"
            ).fetchall()
        found = {str(row["ecosystem"]): int(row["n"]) for row in rows}
        return {"npm": found.get("npm", 0), "pypi": found.get("pypi", 0)}

    def save_mcp_risk(
        self,
        ecosystem: str,
        name: str,
        version: str,
        score: int,
        signals: list[str],
        detail: dict,
        *,
        server: str = "",
        old_version: str | None = None,
        error: str = "",
        when: datetime | None = None,
    ) -> None:
        moment = iso(when or utcnow())
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO mcp_risk (
                    ecosystem, name, version, old_version, server, score,
                    signals_json, detail_json, error, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ecosystem, name, version) DO UPDATE SET
                    old_version = excluded.old_version,
                    server = excluded.server,
                    score = excluded.score,
                    signals_json = excluded.signals_json,
                    detail_json = excluded.detail_json,
                    error = excluded.error,
                    created_at = excluded.created_at
                """,
                (
                    ecosystem,
                    name,
                    version,
                    old_version,
                    server or None,
                    int(score),
                    json.dumps(list(signals)),
                    json.dumps(detail, sort_keys=True, default=str),
                    error or None,
                    moment,
                ),
            )
            self._conn.commit()

    def mcp_risk(self, ecosystem: str, name: str, version: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM mcp_risk WHERE ecosystem = ? AND name = ? AND version = ?",
                (ecosystem, name, version),
            ).fetchone()
        if row is None:
            return None
        found = dict(row)
        found["signals"] = json.loads(found.pop("signals_json") or "[]")
        found["detail"] = json.loads(found.pop("detail_json") or "{}")
        return found

    def mcp_risk_counts(self) -> dict:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT COUNT(*) AS scored, SUM(CASE WHEN score > 0 THEN 1 ELSE 0 END) AS flagged
                FROM mcp_risk
                """
            ).fetchone()
        return {"scored": int(row["scored"] or 0), "flagged": int(row["flagged"] or 0)}

    def unscored_mcp_jobs(self, limit: int = 8) -> list[sqlite3.Row]:
        """Pending npm and PyPI jobs on the MCP watchlist with no mcp_risk row yet."""
        if limit <= 0:
            return []
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT j.ecosystem, j.name, j.version, j.rank, m.server
                FROM release_jobs AS j
                JOIN mcp_packages AS m
                    ON m.ecosystem = j.ecosystem AND m.name = j.name
                LEFT JOIN mcp_risk AS r
                    ON r.ecosystem = j.ecosystem AND r.name = j.name AND r.version = j.version
                WHERE j.status = 'pending'
                  AND r.name IS NULL
                  AND j.ecosystem IN ('npm', 'pypi')
                ORDER BY j.created_at, j.ecosystem, j.name, j.version
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return list(rows)

    def poll_last_error(self, ecosystem: str) -> str | None:
        """Stored ``poll_status.last_error`` for one feed, or None when there is no error."""
        with self._lock:
            row = self._conn.execute(
                "SELECT last_error FROM poll_status WHERE ecosystem = ?",
                (ecosystem,),
            ).fetchone()
        if row is None or row["last_error"] is None:
            return None
        text = str(row["last_error"]).strip()
        return text or None

    def mcp_packages_needing_catchup(self, since: str) -> list[tuple[str, str]]:
        """(ecosystem, name) first seen at or after ``since`` with no package cursor yet.

        A failed catch-up leaves the cursor empty. The next poll passes a ``since``
        that still covers that insert, so the read is tried again. Names that
        already have a cursor are left to the npm and PyPI feeds.
        """
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT m.ecosystem, m.name
                FROM mcp_packages AS m
                LEFT JOIN package_cursor AS c
                    ON c.ecosystem = m.ecosystem AND c.name = m.name
                WHERE m.first_seen_at >= ?
                  AND (c.ecosystem IS NULL OR c.last_time IS NULL)
                ORDER BY m.ecosystem, m.name
                """,
                (since,),
            ).fetchall()
        return [(str(row["ecosystem"]), str(row["name"])) for row in rows]

    def poll_watch(self, ecosystem: str) -> dict[str, int | None]:
        """Names the npm or PyPI poll queues releases for: the ranked watchlist plus MCP packages.

        An MCP package that is not on the ranked list has rank None. Typosquat
        checks keep using ``watch_names`` so MCP names never count as popular.
        """
        return self.poll_targets(ecosystem, include_ranked=True, include_mcp=True, include_user=False)

    def poll_targets(
        self,
        ecosystem: str,
        *,
        include_ranked: bool = True,
        include_mcp: bool = False,
        include_user: bool = False,
    ) -> dict[str, int | None]:
        """Names a poll queues releases for. Names not on the ranked list have rank None."""
        watch: dict[str, int | None] = dict(self.watch_names(ecosystem)) if include_ranked else {}
        if include_mcp:
            for name in self.mcp_package_names(ecosystem):
                watch.setdefault(name, None)
        if include_user:
            for name in self.user_watch_names(ecosystem):
                watch.setdefault(name, None)
        return watch

    # --- User watchlist ------------------------------------------------------

    def _user_watch_pairs(self) -> set[tuple[str, str]]:
        rows = self._conn.execute("SELECT DISTINCT ecosystem, name FROM user_watch").fetchall()
        return {(str(row["ecosystem"]), str(row["name"])) for row in rows}

    def _recount_user_watch_sources(self) -> None:
        self._conn.execute(
            """
            UPDATE user_watch_sources SET components = (
                SELECT COUNT(*) FROM user_watch w WHERE w.source = user_watch_sources.source
            )
            """
        )

    def replace_user_watch_source(
        self,
        source: str,
        fmt: str,
        rows: list[tuple[str, str, str, int | None]],
        skipped: int = 0,
        when: datetime | None = None,
    ) -> list[tuple[str, str]]:
        """Replace one source's rows in one transaction. Returns (ecosystem, name) pairs new to the poll set.

        ``rows`` are (ecosystem, name, version, direct) with names already normalized.
        """
        moment = iso(when or utcnow())
        cleaned: dict[tuple[str, str, str], int | None] = {}
        for ecosystem, name, version, direct in rows:
            if ecosystem not in USER_WATCH_ECOSYSTEMS or not name:
                continue
            key = (ecosystem, name, version or "")
            known = cleaned.get(key)
            flags = [flag for flag in (known, direct) if flag is not None]
            cleaned[key] = max(flags) if flags else None
        with self._lock:
            try:
                before = self._user_watch_pairs()
                self._conn.execute("DELETE FROM user_watch WHERE source = ?", (source,))
                self._conn.executemany(
                    "INSERT INTO user_watch (ecosystem, name, version, direct, source) VALUES (?, ?, ?, ?, ?)",
                    [(eco, name, version, direct, source) for (eco, name, version), direct in cleaned.items()],
                )
                self._conn.execute(
                    """
                    INSERT INTO user_watch_sources (source, format, imported_at, components, skipped)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(source) DO UPDATE SET
                        format = excluded.format,
                        imported_at = excluded.imported_at,
                        components = excluded.components,
                        skipped = excluded.skipped
                    """,
                    (source, fmt, moment, len(cleaned), int(skipped)),
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
        return sorted({(eco, name) for eco, name, _version in cleaned} - before)

    def add_user_watch(
        self,
        ecosystem: str,
        name: str,
        version: str = "",
        *,
        source: str = "manual",
        direct: int | None = 1,
        when: datetime | None = None,
    ) -> bool:
        """Add one row to a source without touching its other rows. True when the name is new to the poll set."""
        if ecosystem not in USER_WATCH_ECOSYSTEMS or not name:
            raise ValueError(f"unknown ecosystem {ecosystem!r}")
        moment = iso(when or utcnow())
        with self._lock:
            new = (ecosystem, name) not in self._user_watch_pairs()
            self._conn.execute(
                """
                INSERT INTO user_watch (ecosystem, name, version, direct, source) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(ecosystem, name, version, source) DO UPDATE SET direct = excluded.direct
                """,
                (ecosystem, name, version or "", direct, source),
            )
            self._conn.execute(
                """
                INSERT INTO user_watch_sources (source, format, imported_at, components, skipped)
                VALUES (?, 'plain', ?, 0, 0)
                ON CONFLICT(source) DO UPDATE SET imported_at = excluded.imported_at
                """,
                (source, moment),
            )
            self._recount_user_watch_sources()
            self._conn.commit()
        return new

    def remove_user_watch_source(self, source: str) -> int:
        """Drop one source and its rows. Returns rows removed."""
        with self._lock:
            removed = self._conn.execute("DELETE FROM user_watch WHERE source = ?", (source,)).rowcount
            self._conn.execute("DELETE FROM user_watch_sources WHERE source = ?", (source,))
            self._conn.commit()
        return int(removed)

    def remove_user_watch_name(self, ecosystem: str, name: str) -> int:
        """Drop a name from every source. Returns rows removed. A later import of a source adds it back."""
        with self._lock:
            removed = self._conn.execute(
                "DELETE FROM user_watch WHERE ecosystem = ? AND name = ?",
                (ecosystem, name),
            ).rowcount
            self._recount_user_watch_sources()
            self._conn.commit()
        return int(removed)

    def user_watch_names(self, ecosystem: str) -> set[str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT DISTINCT name FROM user_watch WHERE ecosystem = ?",
                (ecosystem,),
            ).fetchall()
        return {str(row["name"]) for row in rows}

    def user_watch_entries(self, ecosystem: str, name: str) -> list[dict]:
        """Every listed row for one name, with when its source was imported."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT w.version, w.direct, w.source, s.format, s.imported_at
                FROM user_watch w
                LEFT JOIN user_watch_sources s ON s.source = w.source
                WHERE w.ecosystem = ? AND w.name = ?
                ORDER BY w.source, w.version
                """,
                (ecosystem, name),
            ).fetchall()
        return [dict(row) for row in rows]

    def user_watch_rows(self, ecosystem: str | None = None) -> list[dict]:
        with self._lock:
            if ecosystem:
                rows = self._conn.execute(
                    """
                    SELECT ecosystem, name, version, direct, source FROM user_watch
                    WHERE ecosystem = ? ORDER BY ecosystem, name, version, source
                    """,
                    (ecosystem,),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT ecosystem, name, version, direct, source FROM user_watch ORDER BY ecosystem, name, version, source"
                ).fetchall()
        return [dict(row) for row in rows]

    def user_watch_sources(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT source, format, imported_at, components, skipped FROM user_watch_sources ORDER BY source"
            ).fetchall()
        return [dict(row) for row in rows]

    def user_watch_counts(self) -> dict:
        """Distinct listed names per ecosystem, the total, and the number of sources."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT ecosystem, COUNT(DISTINCT name) AS n FROM user_watch GROUP BY ecosystem"
            ).fetchall()
            sources = self._conn.execute("SELECT COUNT(*) AS n FROM user_watch_sources").fetchone()
        found = {str(row["ecosystem"]): int(row["n"]) for row in rows}
        counts = {eco: found.get(eco, 0) for eco in USER_WATCH_ECOSYSTEMS}
        counts["total"] = sum(counts.values())
        counts["sources"] = int(sources["n"] or 0)
        return counts

    def user_watch_oldest_import(self) -> str | None:
        with self._lock:
            row = self._conn.execute("SELECT MIN(imported_at) AS oldest FROM user_watch_sources").fetchone()
        return None if row is None or row["oldest"] is None else str(row["oldest"])

    def has_user_watch(self) -> bool:
        with self._lock:
            row = self._conn.execute("SELECT 1 FROM user_watch LIMIT 1").fetchone()
        return row is not None

    def record_openvsx_change(
        self,
        name: str,
        version: str,
        platform: str,
        state: str,
        published_at: str | None,
        changed_at: str | None,
        when: datetime | None = None,
    ) -> str | None:
        """Store one changes-feed row. Returns the state it had before, or None when it is new."""
        moment = iso(when or utcnow())
        with self._lock:
            row = self._conn.execute(
                "SELECT state FROM openvsx_changes WHERE name = ? AND version = ? AND platform = ?",
                (name, version, platform),
            ).fetchone()
            self._conn.execute(
                """
                INSERT INTO openvsx_changes
                    (name, version, platform, state, published_at, changed_at, first_seen_at, last_seen_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(name, version, platform) DO UPDATE SET
                    state = excluded.state,
                    published_at = COALESCE(excluded.published_at, openvsx_changes.published_at),
                    changed_at = excluded.changed_at,
                    last_seen_at = excluded.last_seen_at
                """,
                (name, version, platform, state, published_at, changed_at, moment, moment),
            )
            self._conn.commit()
        return None if row is None else str(row["state"])

    def openvsx_platforms(self, name: str, version: str) -> dict[str, str]:
        """Target platform -> state for one extension version."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT platform, state FROM openvsx_changes WHERE name = ? AND version = ?",
                (name, version),
            ).fetchall()
        return {str(row["platform"]): str(row["state"]) for row in rows}

    def openvsx_removed(self, limit: int = 500) -> list[dict]:
        """Removed extension versions, newest first. Ground truth for benchmarks."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT name, version, platform, published_at, changed_at, last_seen_at
                FROM openvsx_changes WHERE state = 'REMOVED'
                ORDER BY last_seen_at DESC, name, version LIMIT ?
                """,
                (int(limit),),
            ).fetchall()
        return [dict(row) for row in rows]

    def openvsx_counts(self) -> dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT state, COUNT(*) AS n FROM openvsx_changes GROUP BY state"
            ).fetchall()
        found = {str(row["state"]).lower(): int(row["n"]) for row in rows}
        other = sum(count for state, count in found.items() if state not in {"active", "removed"})
        return {"active": found.get("active", 0), "removed": found.get("removed", 0), "other": other}

    def record_openvsx_label(
        self,
        name: str,
        version: str,
        platform: str,
        state: str,
        changed_at: str | None,
        when: datetime | None = None,
    ) -> None:
        """Insert one removal or unpublish label. A second write for the same platform does nothing."""
        moment = iso(when or utcnow())
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO openvsx_labels (name, version, platform, state, changed_at, first_seen_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(name, version, platform) DO NOTHING
                """,
                (name, version, platform, state, changed_at, moment),
            )
            self._conn.commit()

    def openvsx_labels(self) -> list[dict]:
        """Append-only removal and unpublish labels. A later ACTIVE does not delete them."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT name, version, platform, state, changed_at, first_seen_at
                FROM openvsx_labels
                ORDER BY name, version, platform
                """
            ).fetchall()
        return [dict(row) for row in rows]
