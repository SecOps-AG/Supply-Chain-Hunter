"""Account-takeover signals from registry metadata. Synthetic documents, mocked HTTP."""

import base64
import json
import sqlite3
import threading
import urllib.error
from datetime import datetime, timedelta, timezone

from hunter import takeover
from hunter.config import Config
from hunter.db import Database
from hunter.registry import DownloadTooLarge, FeedError
from hunter.service import _takeover_loop, drain_jobs, drain_until_idle, health_payload
from hunter.takeover import (
    PROVENANCE_FILES,
    Thresholds,
    WEIGHTS,
    npm_provenance_identity,
    npm_signals,
    pypi_signals,
    score_pending_jobs,
)

NPM = "https://registry.example"
PYPI = "https://pypi.example/pypi"
INTEGRITY = "https://pypi.example/integrity"


class FakeHttp:
    """Answers from a dict of URL -> object. Unknown URLs are 404, like the registry."""

    def __init__(self, routes: dict, fail: set[str] | None = None):
        self.routes = routes
        self.fail = fail or set()
        self.calls: list[str] = []

    def __call__(self, url: str, timeout: float = 60.0) -> bytes:
        self.calls.append(url)
        if url in self.fail:
            raise FeedError("connection reset")
        if url not in self.routes:
            error = urllib.error.HTTPError(url, 404, "Not Found", {}, None)
            raise FeedError("Not Found") from error
        return json.dumps(self.routes[url]).encode()


def _attestation(repository: str, path: str = ".github/workflows/release.yml") -> dict:
    statement = {
        "predicate": {
            "buildDefinition": {
                "externalParameters": {"workflow": {"repository": repository, "path": path}}
            }
        }
    }
    payload = base64.b64encode(json.dumps(statement).encode()).decode()
    return {
        "attestations": [
            {"predicateType": "https://slsa.dev/provenance/v1", "bundle": {"dsseEnvelope": {"payload": payload}}}
        ]
    }


def _npm_doc(
    *,
    new_user=("ada", "ada@example.org"),
    new_maintainers=("ada",),
    old_time="2026-09-01T00:00:00.000Z",
    new_time="2026-10-01T00:00:00.000Z",
    new_version="1.0.1",
) -> dict:
    return {
        "time": {
            "created": "2025-01-01T00:00:00.000Z",
            "0.9.0": "2025-01-01T00:00:00.000Z",
            "1.0.0": old_time,
            new_version: new_time,
        },
        "versions": {
            "0.9.0": {"_npmUser": {"name": "ada", "email": "ada@example.org"}, "maintainers": [{"name": "ada"}]},
            "1.0.0": {"_npmUser": {"name": "ada", "email": "ada@example.org"}, "maintainers": [{"name": "ada"}]},
            new_version: {
                "_npmUser": {"name": new_user[0], "email": new_user[1]},
                "maintainers": [{"name": name} for name in new_maintainers],
            },
        },
    }


def _att_url(name: str, version: str) -> str:
    return f"{NPM}/-/npm/v1/attestations/{name}@{version}"


def test_clean_npm_release_has_no_signals():
    http = FakeHttp({_att_url("widget", "1.0.0"): _attestation("org/widget"), _att_url("widget", "1.0.1"): _attestation("org/widget")})
    found = npm_signals(_npm_doc(), "widget", "1.0.1", transport=http, registry=NPM)
    assert found.signals == []
    assert found.score == 0
    assert found.old_version == "1.0.0"


def test_npm_provenance_lost_after_a_release_that_had_it():
    http = FakeHttp({_att_url("widget", "1.0.0"): _attestation("org/widget")})
    found = npm_signals(_npm_doc(), "widget", "1.0.1", transport=http, registry=NPM)
    assert found.signals == ["provenance_lost"]
    assert found.score == WEIGHTS["provenance_lost"]


def test_npm_provenance_identity_change():
    http = FakeHttp(
        {_att_url("widget", "1.0.0"): _attestation("org/widget"), _att_url("widget", "1.0.1"): _attestation("evil/fork")}
    )
    found = npm_signals(_npm_doc(), "widget", "1.0.1", transport=http, registry=NPM)
    assert found.signals == ["provenance_identity_changed"]


def test_npm_no_provenance_either_side_is_not_a_signal_and_skips_the_second_call():
    http = FakeHttp({})
    found = npm_signals(_npm_doc(), "widget", "1.0.1", transport=http, registry=NPM)
    assert found.signals == []
    assert http.calls == [_att_url("widget", "1.0.0")]


def test_npm_provenance_read_failure_is_unknown_not_lost():
    http = FakeHttp({}, fail={_att_url("widget", "1.0.0")})
    found = npm_signals(_npm_doc(), "widget", "1.0.1", transport=http, registry=NPM)
    assert "provenance_lost" not in found.signals
    assert found.error.startswith("provenance")


def test_npm_new_publisher_and_added_maintainer():
    document = _npm_doc(new_user=("mallory", "m@evil.test"), new_maintainers=("ada", "mallory"))
    found = npm_signals(document, "widget", "1.0.1", transport=FakeHttp({}), registry=NPM)
    assert set(found.signals) == {"publisher_new", "maintainer_added"}
    assert found.detail["maintainer_added"]["added"] == ["mallory"]


def test_npm_same_publisher_new_email():
    document = _npm_doc(new_user=("ada", "ada@evil.test"))
    found = npm_signals(document, "widget", "1.0.1", transport=FakeHttp({}), registry=NPM)
    assert found.signals == ["publisher_email_changed"]


def test_npm_dormant_and_semver_jump():
    document = _npm_doc(old_time="2024-01-01T00:00:00.000Z", new_version="4.0.0")
    found = npm_signals(document, "widget", "4.0.0", transport=FakeHttp({}), registry=NPM)
    assert set(found.signals) == {"dormant_publish", "semver_jump"}
    assert found.detail["dormant_publish"]["idle_days"] >= 365


def test_npm_burst_publish():
    times = {f"1.0.{n}": f"2026-10-01T0{n}:00:00.000Z" for n in range(6)}
    versions = {version: {"_npmUser": {"name": "ada"}, "maintainers": [{"name": "ada"}]} for version in times}
    document = {"time": times, "versions": versions}
    found = npm_signals(document, "widget", "1.0.5", transport=FakeHttp({}), registry=NPM)
    assert found.signals == ["burst_publish"]
    quiet = npm_signals(document, "widget", "1.0.5", transport=FakeHttp({}), registry=NPM, thresholds=Thresholds(burst_count=10))
    assert quiet.signals == []


def test_npm_identity_without_workflow_is_blank():
    assert npm_provenance_identity({"attestations": [{"predicateType": "https://slsa.dev/provenance/v1"}]}) == ""
    assert npm_provenance_identity({"attestations": [{"predicateType": "https://github.com/npm/attestation"}]}) is None


def _pypi_doc(*, owners=("ada",), old_upload="2026-09-01T00:00:00Z", new_version="1.0.1") -> dict:
    return {
        "info": {"ownership": {"roles": [{"role": "Owner", "user": user} for user in owners]}},
        "releases": {
            "1.0.0": [{"filename": "pkg-1.0.0.tar.gz", "upload_time_iso_8601": old_upload}],
            new_version: [{"filename": f"pkg-{new_version}.tar.gz", "upload_time_iso_8601": "2026-10-01T00:00:00Z"}],
        },
    }


def _prov(version: str, repository: str = "org/pkg") -> tuple[str, dict]:
    url = f"{INTEGRITY}/pkg/{version}/pkg-{version}.tar.gz/provenance"
    body = {
        "version": 1,
        "attestation_bundles": [{"publisher": {"kind": "GitHub", "repository": repository, "workflow": "release.yml"}}],
    }
    return url, body


def _info(version: str, email: str) -> tuple[str, dict]:
    return f"{PYPI}/pkg/{version}/json", {"info": {"author_email": f"Ada <{email}>"}}


def _pypi_http(*extra: tuple[str, dict], old_email="ada@example.org", new_email="ada@example.org") -> FakeHttp:
    routes = dict([_info("1.0.0", old_email), _info("1.0.1", new_email), *extra])
    return FakeHttp(routes)


def test_clean_pypi_release_has_no_signals():
    http = _pypi_http(_prov("1.0.0"), _prov("1.0.1"))
    found = pypi_signals(_pypi_doc(), "pkg", "1.0.1", transport=http, pypi_base=PYPI, previous_owners={"ada"})
    assert found.signals == []
    assert found.error == ""


def test_pypi_provenance_lost_and_identity_change():
    lost = pypi_signals(_pypi_doc(), "pkg", "1.0.1", transport=_pypi_http(_prov("1.0.0")), pypi_base=PYPI)
    assert lost.signals == ["provenance_lost"]
    moved = pypi_signals(
        _pypi_doc(), "pkg", "1.0.1", transport=_pypi_http(_prov("1.0.0"), _prov("1.0.1", "evil/pkg")), pypi_base=PYPI
    )
    assert moved.signals == ["provenance_identity_changed"]


def test_pypi_email_change_and_new_owner():
    http = _pypi_http(new_email="x@evil.test")
    found = pypi_signals(
        _pypi_doc(owners=("ada", "mallory")), "pkg", "1.0.1", transport=http, pypi_base=PYPI, previous_owners={"ada"}
    )
    assert set(found.signals) == {"publisher_email_changed", "maintainer_added"}


def test_pypi_owners_without_a_recorded_baseline_are_not_a_change():
    found = pypi_signals(_pypi_doc(owners=("mallory",)), "pkg", "1.0.1", transport=_pypi_http(), pypi_base=PYPI)
    assert "maintainer_added" not in found.signals
    assert found.detail["owners"] == ["mallory"]


def test_pypi_dormant_and_semver_jump():
    found = pypi_signals(
        _pypi_doc(old_upload="2023-01-01T00:00:00Z", new_version="9.0.0"),
        "pkg",
        "9.0.0",
        transport=FakeHttp(dict([_info("1.0.0", "a@b.c"), _info("9.0.0", "a@b.c")])),
        pypi_base=PYPI,
    )
    assert set(found.signals) == {"dormant_publish", "semver_jump"}


def _config(tmp_path, **kwargs) -> Config:
    values = dict(db_path=tmp_path / "h.sqlite3", npm_registry=NPM, pypi_base=PYPI, takeover_signals=True)
    values.update(kwargs)
    return Config(**values)


def test_config_is_off_by_default(monkeypatch):
    monkeypatch.delenv("HUNTER_TAKEOVER_SIGNALS", raising=False)
    assert Config().takeover_signals is False
    assert Config.from_env().takeover_signals is False
    monkeypatch.setenv("HUNTER_TAKEOVER_SIGNALS", "on")
    monkeypatch.setenv("HUNTER_TAKEOVER_DORMANT_DAYS", "90")
    config = Config.from_env()
    assert config.takeover_signals is True
    assert config.takeover_dormant_days == 90


def test_score_pending_jobs_records_signals_and_reorders_the_queue(tmp_path):
    config = _config(tmp_path)
    db = Database(config.db_path)
    db.enqueue_job("npm", "calm", "1.0.1", 1, when=datetime(2026, 10, 1, 0, 0, 1, tzinfo=timezone.utc))
    db.enqueue_job("npm", "widget", "1.0.1", 2, when=datetime(2026, 10, 1, 0, 0, 2, tzinfo=timezone.utc))
    db.enqueue_job("github-actions", "org/act", "v1", 3, when=datetime(2026, 10, 1, 0, 0, 3, tzinfo=timezone.utc))
    risky = _npm_doc(new_user=("mallory", "m@evil.test"))
    http = FakeHttp(
        {
            f"{NPM}/calm": _npm_doc(),
            f"{NPM}/widget": risky,
            _att_url("widget", "1.0.0"): _attestation("org/widget"),
        }
    )
    assert [row["name"] for row in db.pending_jobs()] == ["calm", "widget", "org/act"]

    assert score_pending_jobs(db, config, http) == 2
    assert score_pending_jobs(db, config, http) == 0

    stored = db.takeover_signals("npm", "widget", "1.0.1")
    assert set(stored["signals"]) == {"publisher_new", "provenance_lost"}
    assert stored["score"] == WEIGHTS["publisher_new"] + WEIGHTS["provenance_lost"]
    assert db.takeover_signals("npm", "calm", "1.0.1")["score"] == 0
    assert db.takeover_signals("github-actions", "org/act", "v1") is None

    assert [row["name"] for row in db.pending_jobs(prioritize=True)] == ["widget", "calm", "org/act"]
    assert [row["name"] for row in db.pending_jobs()] == ["calm", "widget", "org/act"]
    assert db.takeover_counts() == {"scored": 2, "flagged": 1}
    assert health_payload(db, 0.0, config=config)["takeover_signals"] == {"scored": 2, "flagged": 1}
    assert "takeover_signals" not in health_payload(db, 0.0, config=_config(tmp_path, takeover_signals=False))


def test_a_missing_packument_is_recorded_and_not_retried(tmp_path):
    config = _config(tmp_path)
    db = Database(config.db_path)
    db.enqueue_job("npm", "gone", "1.0.0", 1)
    http = FakeHttp({})
    assert score_pending_jobs(db, config, http) == 1
    stored = db.takeover_signals("npm", "gone", "1.0.0")
    assert stored["score"] == 0 and stored["error"].startswith("metadata")
    assert score_pending_jobs(db, config, http) == 0


def test_pypi_owner_baseline_comes_from_the_previous_scored_release(tmp_path):
    config = _config(tmp_path)
    db = Database(config.db_path)
    db.save_takeover_signals("pypi", "pkg", "1.0.0", 0, [], {"owners": ["ada"]})
    db.enqueue_job("pypi", "pkg", "1.0.1", 1)
    http = _pypi_http((f"{PYPI}/pkg/json", _pypi_doc(owners=("ada", "mallory"))))
    score_pending_jobs(db, config, http)
    assert db.takeover_signals("pypi", "pkg", "1.0.1")["signals"] == ["maintainer_added"]


def test_drain_jobs_takes_the_highest_score_first_only_when_enabled(tmp_path, monkeypatch):
    db = Database(tmp_path / "h.sqlite3")
    db.enqueue_job("npm", "calm", "1.0.1", 1)
    db.enqueue_job("npm", "widget", "1.0.1", 2)
    db.save_takeover_signals("npm", "widget", "1.0.1", 40, ["provenance_lost"], {})
    db.save_takeover_signals("npm", "calm", "1.0.1", 0, [], {})
    seen: list[str] = []

    def fake_classify(_db, _config, job, **_kwargs):
        seen.append(str(job["name"]))
        _db.finish_job(job["ecosystem"], job["name"], job["version"])

    monkeypatch.setattr("hunter.service.classify_job", fake_classify)
    drain_jobs(db, _config(tmp_path, classify_batch=1), jev=None, loader=object(), workers=1)
    assert seen == ["widget"]
    drain_jobs(db, _config(tmp_path, classify_batch=1), jev=None, loader=object(), workers=1)
    assert seen == ["widget", "calm"]

    db.enqueue_job("npm", "a", "1", 1)
    db.enqueue_job("npm", "b", "1", 1)
    db.save_takeover_signals("npm", "b", "1", 40, ["provenance_lost"], {})
    assert [row["name"] for row in db.pending_jobs(limit=1)] == ["a"]


def _due_now(monkeypatch) -> None:
    monkeypatch.setattr(takeover, "RETRY_DELAY", timedelta(seconds=-1))


def test_a_transient_packument_failure_is_retried_until_the_attempt_limit(tmp_path, monkeypatch):
    _due_now(monkeypatch)
    config = _config(tmp_path)
    db = Database(config.db_path)
    db.enqueue_job("npm", "flaky", "1.0.1", 1)
    http = FakeHttp({}, fail={f"{NPM}/flaky"})
    for attempt in range(1, takeover.MAX_ATTEMPTS + 1):
        assert score_pending_jobs(db, config, http) == 1
        stored = db.takeover_signals("npm", "flaky", "1.0.1")
        assert stored["attempts"] == attempt and stored["error"].startswith("metadata")
    assert stored["retry_at"] is None
    assert score_pending_jobs(db, config, http) == 0


def test_a_transient_failure_waits_for_its_retry_time_then_recovers(tmp_path, monkeypatch):
    config = _config(tmp_path)
    db = Database(config.db_path)
    db.enqueue_job("npm", "flaky", "1.0.1", 1)
    http = FakeHttp({f"{NPM}/flaky": _npm_doc(new_user=("mallory", "m@evil.test"))}, fail={f"{NPM}/flaky"})
    assert score_pending_jobs(db, config, http) == 1
    assert db.takeover_signals("npm", "flaky", "1.0.1")["retry_at"] is not None
    assert score_pending_jobs(db, config, http) == 0
    later = datetime.now(timezone.utc) + takeover.RETRY_DELAY + timedelta(minutes=1)
    assert [row["name"] for row in db.unscored_pending_jobs(("npm",), now=later)] == ["flaky"]

    _due_now(monkeypatch)
    db.save_takeover_signals("npm", "flaky", "1.0.1", 0, [], {}, error="metadata: reset", retry_at=datetime(2020, 1, 1))
    http.fail.clear()
    assert score_pending_jobs(db, config, http) == 1
    stored = db.takeover_signals("npm", "flaky", "1.0.1")
    assert stored["signals"] == ["publisher_new"] and stored["error"] is None and stored["retry_at"] is None
    assert score_pending_jobs(db, config, http) == 0


def test_a_provenance_timeout_keeps_the_partial_score_and_is_retried(tmp_path, monkeypatch):
    _due_now(monkeypatch)
    config = _config(tmp_path)
    db = Database(config.db_path)
    db.enqueue_job("npm", "widget", "1.0.1", 1)
    http = FakeHttp(
        {f"{NPM}/widget": _npm_doc(new_user=("mallory", "m@evil.test"))}, fail={_att_url("widget", "1.0.0")}
    )
    score_pending_jobs(db, config, http)
    stored = db.takeover_signals("npm", "widget", "1.0.1")
    assert stored["signals"] == ["publisher_new"] and stored["retry_at"] is not None
    assert score_pending_jobs(db, config, http) == 1


class SizedHttp(FakeHttp):
    """Honours max_bytes like http_get does."""

    def __call__(self, url: str, timeout: float = 60.0, *, max_bytes: int | None = None) -> bytes:
        body = super().__call__(url, timeout)
        if max_bytes is not None and len(body) > max_bytes:
            raise DownloadTooLarge(f"package exceeds {max_bytes} bytes")
        self.caps = getattr(self, "caps", []) + [max_bytes]
        return body


def test_an_oversized_document_is_final_for_capped_and_plain_transports(tmp_path, monkeypatch):
    _due_now(monkeypatch)
    monkeypatch.setattr(takeover, "DOCUMENT_MAX_BYTES", 64)
    config = _config(tmp_path)
    for http in (FakeHttp({f"{NPM}/big": _npm_doc()}), SizedHttp({f"{NPM}/big": _npm_doc()})):
        db = Database(tmp_path / f"{type(http).__name__}.sqlite3")
        db.enqueue_job("npm", "big", "1.0.1", 1)
        assert score_pending_jobs(db, config, http) == 1
        stored = db.takeover_signals("npm", "big", "1.0.1")
        assert "64 bytes" in stored["error"] and stored["retry_at"] is None
        assert score_pending_jobs(db, config, http) == 0


def test_every_read_passes_a_size_cap(tmp_path):
    config = _config(tmp_path)
    db = Database(config.db_path)
    db.enqueue_job("npm", "widget", "1.0.1", 1)
    http = SizedHttp({f"{NPM}/widget": _npm_doc(), _att_url("widget", "1.0.0"): _attestation("org/widget")})
    score_pending_jobs(db, config, http)
    assert http.caps == [takeover.DOCUMENT_MAX_BYTES, takeover.SMALL_MAX_BYTES]


def test_pypi_provenance_checks_a_bounded_number_of_files_sdist_first():
    wheels = [
        {
            "filename": f"pkg-1.0.0-cp3{n}-none-any.whl",
            "packagetype": "bdist_wheel",
            "upload_time_iso_8601": "2026-09-01T00:00:00Z",
        }
        for n in range(39)
    ]
    sdist = {"filename": "pkg-1.0.0.tar.gz", "packagetype": "sdist", "upload_time_iso_8601": "2026-09-01T00:00:00Z"}
    document = _pypi_doc()
    document["releases"]["1.0.0"] = [*wheels, sdist]
    http = _pypi_http()
    found = pypi_signals(document, "pkg", "1.0.1", transport=http, pypi_base=PYPI)
    checked = [url for url in http.calls if url.startswith(INTEGRITY)]
    assert len(checked) == PROVENANCE_FILES
    assert checked[0] == f"{INTEGRITY}/pkg/1.0.0/pkg-1.0.0.tar.gz/provenance"
    assert found.signals == [] and found.error == ""


def test_backlog_is_scored_newest_first(tmp_path):
    config = _config(tmp_path, takeover_batch=1)
    db = Database(config.db_path)
    for second, name in enumerate(("old", "mid", "new"), start=1):
        db.enqueue_job("npm", name, "1.0.1", 1, when=datetime(2026, 10, 1, 0, 0, second, tzinfo=timezone.utc))
    http = FakeHttp({f"{NPM}/{name}": _npm_doc() for name in ("old", "mid", "new")})
    score_pending_jobs(db, config, http)
    assert http.calls[0] == f"{NPM}/new"
    assert db.takeover_signals("npm", "old", "1.0.1") is None and db.takeover_signals("npm", "mid", "1.0.1") is None


def test_a_database_from_before_the_retry_columns_is_upgraded(tmp_path):
    path = tmp_path / "h.sqlite3"
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE takeover_signals (
            ecosystem TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL, old_version TEXT,
            score INTEGER NOT NULL, signals_json TEXT NOT NULL, detail_json TEXT NOT NULL, error TEXT,
            created_at TEXT NOT NULL, PRIMARY KEY (ecosystem, name, version)
        )
        """
    )
    conn.execute(
        "INSERT INTO takeover_signals VALUES ('npm', 'a', '1', NULL, 0, '[]', '{}', NULL, '2026-10-01T00:00:00Z')"
    )
    conn.commit()
    conn.close()
    db = Database(path)
    assert db.takeover_signals("npm", "a", "1")["attempts"] == 1
    db.save_takeover_signals("npm", "a", "1", 0, [], {}, error="x", retry_at=datetime(2026, 10, 1, tzinfo=timezone.utc))
    stored = db.takeover_signals("npm", "a", "1")
    assert stored["attempts"] == 2 and stored["retry_at"] == "2026-10-01T00:00:00Z"


class _StopOnWait(threading.Event):
    def wait(self, timeout=None) -> bool:
        self.set()
        return True


def test_serve_scores_on_its_own_thread_not_in_the_classify_round(tmp_path, monkeypatch):
    config = _config(tmp_path)
    db = Database(config.db_path)
    db.enqueue_job("npm", "calm", "1.0.1", 1)
    _takeover_loop(db, config, FakeHttp({f"{NPM}/calm": _npm_doc()}), _StopOnWait())
    assert db.takeover_signals("npm", "calm", "1.0.1")["score"] == 0

    called = []
    monkeypatch.setattr("hunter.service._score_takeover_safely", lambda *args: called.append(args))
    monkeypatch.setattr("hunter.service.drain_jobs", lambda *args, **kwargs: 0)
    drain_until_idle(db, config, jev=None, loader=None, score_takeover=False)
    assert called == []
    drain_until_idle(db, config, jev=None, loader=None)
    assert len(called) == 1


def test_classify_waits_briefly_for_takeover_signals_on_new_releases(tmp_path, monkeypatch):
    db = Database(tmp_path / "h.sqlite3")
    now = datetime.now(timezone.utc)
    db.enqueue_job("npm", "old", "1.0.0", 1, when=now - timedelta(hours=1))
    db.save_takeover_signals("npm", "old", "1.0.0", 0, [], {})
    db.enqueue_job("npm", "fresh", "1.0.0", 2, when=now)
    db.enqueue_job("crates", "other", "1.0.0", 3, when=now)  # takeover never scores crates
    seen: list[str] = []

    def fake_classify(_db, _config, job, **_kwargs):
        seen.append(str(job["name"]))
        _db.finish_job(job["ecosystem"], job["name"], job["version"])

    monkeypatch.setattr("hunter.service.classify_job", fake_classify)
    drain_jobs(db, _config(tmp_path, classify_batch=10), jev=None, loader=object(), workers=1)
    # The fresh npm release is not classified at score 0 before its signals exist.
    assert seen == ["old", "other"]
    db.save_takeover_signals("npm", "fresh", "1.0.0", 40, ["provenance_lost"], {})
    drain_jobs(db, _config(tmp_path, classify_batch=10), jev=None, loader=object(), workers=1)
    assert seen == ["old", "other", "fresh"]


def test_classify_stops_waiting_for_takeover_signals_after_the_grace(tmp_path, monkeypatch):
    db = Database(tmp_path / "h.sqlite3")
    db.enqueue_job("npm", "stale", "1.0.0", 1, when=datetime.now(timezone.utc) - timedelta(minutes=10))
    seen: list[str] = []

    def fake_classify(_db, _config, job, **_kwargs):
        seen.append(str(job["name"]))
        _db.finish_job(job["ecosystem"], job["name"], job["version"])

    monkeypatch.setattr("hunter.service.classify_job", fake_classify)
    drain_jobs(db, _config(tmp_path), jev=None, loader=object(), workers=1)
    assert seen == ["stale"]
