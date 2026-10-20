"""One bad package download must not stop the serve worker pool."""

import http.client
import json
from pathlib import Path

import pytest

from hunter.archives import ArchiveError
from hunter.config import Config
from hunter.db import Database
from hunter.models import ReleaseMeta
from hunter.registry import DownloadTooLarge, fetch_capped, http_get, read_limited
from hunter.service import PACKAGE_DOWNLOAD_MAX_BYTES, ReleaseLoader, drain_jobs
from tests.archives_factory import BENIGN_NEW, BENIGN_OLD, tar_bytes
from hunter.fake_jev import KeywordJev


class _Body:
    def __init__(self, payload: bytes, headers: dict):
        self.payload = payload
        self.headers = headers
        self.offset = 0

    def read(self, amt=None):
        if amt is None:
            amt = len(self.payload) - self.offset
        chunk = self.payload[self.offset : self.offset + amt]
        self.offset += len(chunk)
        return chunk


def _retry(db: Database, name: str):
    with db._lock:
        return db._conn.execute(
            """
            SELECT status, last_error FROM classify_retries
            WHERE name = ?
            """,
            (name,),
        ).fetchone()


def _config(db: Database) -> Config:
    return Config(
        db_path=db.path,
        smart_analysis=False,
        analyst=False,
        inspect_dependencies=False,
        webhook_url="",
    )


class _Loader:
    def __init__(self, broken: dict[str, BaseException]):
        self.broken = broken
        self.seen: list[str] = []

    def load(self, ecosystem, name, version, rank):
        self.seen.append(name)
        if name in self.broken:
            raise self.broken[name]
        meta = ReleaseMeta(
            ecosystem=ecosystem,
            name=name,
            new_version=version,
            old_version="1.0.0",
            rank=rank,
            registry_url=f"https://example.test/{name}",
        )
        return BENIGN_OLD, BENIGN_NEW, meta


def test_truncated_download_records_retry_and_other_releases_continue(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = _config(db)
    db.enqueue_job("pypi", "cut-off", "1.2.3", 4)
    db.enqueue_job("pypi", "widget", "1.0.1", 5)
    loader = _Loader(
        {"cut-off": http.client.IncompleteRead(b"x" * 32, 11_988_021)}
    )
    processed = drain_jobs(db, config, jev=KeywordJev(), loader=loader, workers=2)
    assert processed == 2
    assert sorted(loader.seen) == ["cut-off", "widget"]
    assert db.pending_count() == 0

    stored = db.get_release("pypi", "cut-off", "1.2.3")
    payload = json.loads(stored["payload_json"])
    assert stored["band"] == "deferred"
    assert payload["defer_reason"] == "download_failed"
    assert "download_failed" in payload["signals"]
    retry = _retry(db, "cut-off")
    assert retry["status"] == "retrying"
    assert retry["last_error"] == "download_failed"
    assert db.retry_depth() == 1

    other = db.get_release("pypi", "widget", "1.0.1")
    assert other is not None
    assert other["band"] != "deferred"
    assert _retry(db, "widget") is None


def test_unexpected_release_error_does_not_stop_the_batch(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = _config(db)
    db.enqueue_job("npm", "boom", "9.9.9", 1)
    db.enqueue_job("npm", "widget", "1.0.1", 2)
    loader = _Loader({"boom": RuntimeError("classifier blew up")})
    assert drain_jobs(db, config, jev=KeywordJev(), loader=loader, workers=2) == 2
    assert db.pending_count() == 0
    retry = _retry(db, "boom")
    assert retry["status"] == "retrying"
    assert retry["last_error"] == "classify_failed"
    other = db.get_release("npm", "widget", "1.0.1")
    assert other is not None
    assert other["band"] != "deferred"


def test_missing_archive_stays_load_failed(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = _config(db)
    db.enqueue_job("pypi", "empty", "0.0.1", 1)
    drain_jobs(
        db,
        config,
        jev=KeywordJev(),
        loader=_Loader({"empty": ArchiveError("no archive for empty 0.0.1")}),
        workers=1,
    )
    payload = json.loads(db.get_release("pypi", "empty", "0.0.1")["payload_json"])
    assert payload["defer_reason"] == "load_failed"
    assert _retry(db, "empty")["last_error"] == "load_failed"


def test_http_get_does_not_read_a_body_past_the_cap(monkeypatch):
    class Response:
        headers = {"Content-Length": "999999999"}

        def read(self, amt=None):
            raise AssertionError("body was read")

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    monkeypatch.setattr("hunter.registry.urllib.request.urlopen", lambda request, timeout: Response())
    with pytest.raises(DownloadTooLarge):
        http_get("https://files.example/huge.whl", 5, max_bytes=1024)


def test_read_limited_stops_a_stream_and_reports_a_short_body():
    huge = _Body(b"y" * 50, {})
    with pytest.raises(DownloadTooLarge):
        read_limited(huge, 16)
    assert huge.offset == 17

    short = _Body(b"partial-body", {"Content-Length": "100"})
    with pytest.raises(http.client.HTTPException) as caught:
        read_limited(short, 1000)
    assert short.offset == len(b"partial-body")
    assert "IncompleteRead(12 bytes read, 88 more expected)" in str(caught.value)


def test_stream_limited_writes_the_body_and_drops_an_oversized_one(tmp_path):
    from hunter.registry import stream_limited

    dest = tmp_path / "pkg.tgz"
    body = _Body(b"hello-archive", {})
    assert stream_limited(body, dest, 1024) == len(b"hello-archive")
    assert dest.read_bytes() == b"hello-archive"
    assert body.offset == len(b"hello-archive")

    huge = _Body(b"y" * 50, {})
    oversized = tmp_path / "huge.tgz"
    with pytest.raises(DownloadTooLarge):
        stream_limited(huge, oversized, 16)
    assert not oversized.exists()
    assert huge.offset == 17


def test_fetch_capped_streams_http_to_a_file(monkeypatch, tmp_path):
    payload = b"not-a-real-package"
    reads: list[int | None] = []

    class Response:
        headers: dict[str, str] = {}

        def __init__(self):
            self.payload = payload
            self.offset = 0

        def read(self, amt=None):
            reads.append(amt)
            if amt is None:
                amt = len(self.payload) - self.offset
            chunk = self.payload[self.offset : self.offset + amt]
            self.offset += len(chunk)
            return chunk

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    monkeypatch.setattr("hunter.registry.urllib.request.urlopen", lambda request, timeout: Response())
    path = fetch_capped(http_get, "https://files.example/widget.tgz", 5, 1024)
    try:
        assert path.is_file()
        assert path.read_bytes() == payload
        assert reads
        assert all(amt is not None and amt <= 64 * 1024 for amt in reads)
    finally:
        path.unlink(missing_ok=True)


def test_loader_drops_archive_files_after_extract(monkeypatch):
    import tempfile

    created: list[Path] = []
    real_mkstemp = tempfile.mkstemp

    def spy(*args, **kwargs):
        fd, name = real_mkstemp(*args, **kwargs)
        created.append(Path(name))
        return fd, name

    monkeypatch.setattr("hunter.registry.tempfile.mkstemp", spy)
    old_blob = tar_bytes(BENIGN_OLD)
    new_blob = tar_bytes(BENIGN_NEW)
    document = {
        "time": {
            "1.0.0": "2026-01-01T00:00:00.000Z",
            "1.0.1": "2026-02-01T00:00:00.000Z",
        },
        "versions": {
            "1.0.0": {"dist": {"tarball": "https://registry.example/old.tgz"}},
            "1.0.1": {"dist": {"tarball": "https://registry.example/new.tgz"}},
        },
    }

    def transport(url, _timeout):
        if str(url).endswith("old.tgz"):
            return old_blob
        if str(url).endswith("new.tgz"):
            return new_blob
        return json.dumps(document).encode()

    loader = ReleaseLoader(Config(npm_registry="https://registry.example"), transport)
    old_files, new_files, _meta = loader.load_versions("npm", "widget", "1.0.0", "1.0.1")
    try:
        assert created
        assert all(not path.exists() for path in created)
        assert any(path.endswith("package.json") and '"1.0.1"' in text for path, text in new_files.items())
        assert any(path.endswith("package.json") and '"1.0.0"' in text for path, text in old_files.items())
        assert not any(isinstance(value, str) for value in new_files._index().values())
    finally:
        old_files.close()
        new_files.close()
    assert not new_files.root.exists()


def test_loader_rejects_an_oversized_archive(monkeypatch):
    monkeypatch.setattr("hunter.service.PACKAGE_DOWNLOAD_MAX_BYTES", 8)
    assert PACKAGE_DOWNLOAD_MAX_BYTES == 64 * 1024 * 1024
    document = {
        "time": {"1.0.1": "2026-02-01T00:00:00.000Z"},
        "versions": {"1.0.1": {"dist": {"tarball": "https://registry.example/new.tgz"}}},
    }
    caps = []

    def transport(url, _timeout, max_bytes=None):
        caps.append(max_bytes)
        if str(url).endswith(".tgz"):
            return b"0123456789abcdef"
        return json.dumps(document).encode()

    loader = ReleaseLoader(Config(npm_registry="https://registry.example"), transport)
    with pytest.raises(DownloadTooLarge):
        loader.load("npm", "widget", "1.0.1", 1)
    assert 8 in caps
