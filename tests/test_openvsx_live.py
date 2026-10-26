"""Opt-in Open VSX smoke. The default pytest run does not call the network.

Set HUNTER_OPENVSX_LIVE=1 to run it. At most six GETs, each with a 60 second
timeout. No model calls. Extracted trees are closed before the test exits.
Nothing in a downloaded extension is executed.
"""

from __future__ import annotations

import json
import os
from datetime import timedelta
from pathlib import Path
from urllib.parse import quote

import pytest

from hunter.archives import DiskTree, close_trees, extract_archive
from hunter.config import Config
from hunter.db import Database, utcnow
from hunter.models import ReleaseMeta
from hunter.openvsx import ECOSYSTEM, extension_url, release_name
from hunter.openvsx.feed import CHECKPOINT, SINCE_PREFIX, changes_url, poll_openvsx
from hunter.openvsx.review import predecessor, review_trees, version_api_url
from hunter.registry import PACKAGE_DOWNLOAD_MAX_BYTES, DownloadTooLarge, FeedError, fetch_capped, http_get
from hunter.webhook import build_payload, dump_body

pytestmark = pytest.mark.skipif(
    os.environ.get("HUNTER_OPENVSX_LIVE") != "1",
    reason="set HUNTER_OPENVSX_LIVE=1 to run the Open VSX smoke",
)

BASE = "https://open-vsx.org"
MAX_GETS = 6
_FIELDS = ("namespace", "name", "version", "targetPlatform", "state", "timestamp", "lastUpdated", "url")
_STATES = {"ACTIVE", "INACTIVE", "REMOVED"}


def _stamp(moment) -> str:
    return moment.astimezone(utcnow().tzinfo).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _denied() -> set[str]:
    raw = os.environ.get("HUNTER_OPENVSX_DENY", "").strip()
    if not raw:
        return set()
    found: set[str] = set()
    for line in Path(raw).read_text(encoding="utf-8").splitlines():
        text = line.split("#", 1)[0].strip().lower()
        if not text:
            continue
        if "/" in text:
            namespace, _, extension = text.partition("/")
        else:
            namespace, sep, extension = text.partition(".")
            if not sep:
                found.add(text)
                continue
        accepted = release_name(namespace, extension)
        found.add(accepted or text)
    return found


def _assert_page(page: object) -> list[dict]:
    assert isinstance(page, dict), "Open VSX changes feed did not return a JSON object"
    if page.get("error"):
        pytest.fail(f"Open VSX changes feed: {page['error']}")
    changes = page.get("changes")
    assert isinstance(changes, list)
    for change in changes:
        assert isinstance(change, dict)
        for field in _FIELDS:
            assert field in change, field
            if field != "targetPlatform":
                assert isinstance(change[field], str) and change[field].strip(), field
            else:
                assert isinstance(change[field], str)
        assert change["state"] in _STATES
    cursor = page.get("nextCursor")
    if cursor is not None:
        assert isinstance(cursor, str) and cursor.strip()
        assert isinstance(page.get("hasMore"), bool)
    return changes


def _identity(change: dict) -> tuple:
    return (
        change.get("namespace"),
        change.get("name"),
        change.get("version"),
        change.get("targetPlatform"),
        change.get("state"),
        change.get("lastUpdated"),
    )


def _platform(change: dict) -> str:
    return str(change.get("targetPlatform") or "universal").strip().lower() or "universal"


def _universal_active(changes: list[dict]) -> list[tuple[str, str]]:
    found = []
    for change in changes:
        if str(change.get("state")) != "ACTIVE" or _platform(change) != "universal":
            continue
        name = release_name(str(change.get("namespace") or ""), str(change.get("name") or ""))
        version = str(change.get("version") or "").strip()
        if name and version:
            found.append((name, version))
    return found


def _record(db: Database, changes: list[dict]) -> None:
    active: set[tuple[str, str]] = set()
    for change in changes:
        name = release_name(str(change.get("namespace") or ""), str(change.get("name") or ""))
        assert name, change
        if str(change["state"]) == "ACTIVE":
            active.add((name, str(change["version"])))
    labels = {(row["name"], row["version"], row["platform"], row["state"]) for row in db.openvsx_labels()}
    for name, version in active:
        assert db.has_release_job(ECOSYSTEM, name, version)
    for change in changes:
        state = str(change["state"])
        if state not in {"REMOVED", "INACTIVE"}:
            continue
        name = release_name(str(change["namespace"]), str(change["name"]))
        version = str(change["version"])
        label = "removed" if state == "REMOVED" else "inactive"
        assert (name, version, _platform(change), label) in labels
        if (name, version) not in active:
            assert not db.has_release_job(ECOSYSTEM, name, version)


def _poll_saved(db: Database, config: Config, body: bytes, checkpoint: str, size: int) -> None:
    config.openvsx_page_size = size
    db.set_checkpoint(CHECKPOINT, checkpoint)
    url = changes_url(config.openvsx_url, checkpoint, size)

    def transport(asked: str, timeout: float) -> bytes:
        if asked == url:
            return body
        # Do not walk history. A further page is an empty terminal page, not another GET.
        return b'{"changes":[],"hasMore":false}'

    poll_openvsx(db, config, transport)


def _object(blob: bytes) -> dict:
    data = json.loads(blob.decode("utf-8"))
    if not isinstance(data, dict):
        raise FeedError("Open VSX did not return a JSON object")
    if data.get("error"):
        raise FeedError(f"Open VSX: {data['error']}")
    return data


def _download(document: dict) -> str:
    url = str((document.get("files") or {}).get("download") or "").strip()
    if not url.startswith("https://"):
        raise FeedError("Open VSX version has no https download")
    return url


def _tree(transport, url: str) -> DiskTree:
    archive = fetch_capped(transport, url, 60, PACKAGE_DOWNLOAD_MAX_BYTES)
    try:
        return extract_archive(archive)
    finally:
        archive.unlink(missing_ok=True)


def _pack_ids(files) -> set[str]:
    if not files or "extension/package.json" not in files:
        return set()
    try:
        data = json.loads(files["extension/package.json"])
    except (TypeError, ValueError):
        return set()
    if not isinstance(data, dict):
        return set()
    found: set[str] = set()
    for key in ("extensionPack", "extensionDependencies"):
        value = data.get(key)
        if not isinstance(value, list):
            continue
        for item in value:
            text = str(item).strip().lower()
            if text:
                found.add(text)
    return found


def _login(document: dict) -> frozenset[str]:
    person = document.get("publishedBy") or {}
    login = person.get("loginName") if isinstance(person, dict) else None
    if login and str(login).strip():
        return frozenset({str(login).strip().lower()})
    return frozenset()


def _review_candidate(db: Database, get, name: str, version: str) -> None:
    document = _object(get(version_api_url(BASE, name, "universal", version), 60))
    assert _download(document).startswith("https://")
    assert version in (document.get("allVersions") or {})
    previous = predecessor(document, version)
    old_document = {}
    if previous:
        old_document = _object(get(version_api_url(BASE, name, "universal", previous), 60))
    new_files: DiskTree | None = None
    old_files: DiskTree | None = None
    try:
        new_files = _tree(get, _download(document))
        if previous:
            old_files = _tree(get, _download(old_document))
        readable = "extension/package.json" in new_files
        extra = []
        if not previous:
            extra.append("vsx_first_version")
        old_publishers = _login(old_document)
        new_publishers = _login(document)
        if old_publishers and new_publishers and old_publishers != new_publishers:
            extra.append("vsx_publisher_changed")
        meta = ReleaseMeta(
            ecosystem=ECOSYSTEM,
            name=name,
            new_version=version,
            old_version=previous,
            registry_url=extension_url(BASE, name, version),
            old_publishers=old_publishers,
            new_publishers=new_publishers,
        )
        result = review_trees(
            meta,
            old_files if old_files is not None else DiskTree.empty(),
            new_files,
            extra,
            jev=None,
        )
        if _pack_ids(new_files) - _pack_ids(old_files):
            assert "vsx_extension_pack_added" in result.signals
            assert result.band == "review"
        assert result.band in {"benign", "review"}
        assert result.old_version == previous
        assert readable or "vsx_first_version" in result.signals
        db.save_release(
            ECOSYSTEM,
            name,
            version,
            result.band,
            result.malice_probability,
            result.attack_family,
            result.subtype,
            dump_body(build_payload(result)).decode(),
        )
        stored = db.get_release(ECOSYSTEM, name, version)
        payload = json.loads(stored["payload_json"])
        assert stored["band"] in {"benign", "review"}
        assert payload["old_version"] == previous
        assert payload["band"] == result.band
    finally:
        close_trees(old_files, new_files)


def test_openvsx_live_feed_smoke(tmp_path):
    """Steps 1-4 against the public changes feed. Step 5 runs when a sampled page has a withdrawal.

    Six GETs cover one changes page, one follow-up page, one version document,
    its predecessor, and the two archives. When the first page has no universal
    ACTIVE row, the follow-up is the wider window instead of the cursor page,
    so the review still fits in the cap.
    """
    calls: list[str] = []

    def get(url: str, timeout: float = 60) -> bytes:
        if len(calls) >= MAX_GETS:
            pytest.fail(f"Open VSX smoke exceeded {MAX_GETS} GETs at {url}")
        calls.append(url)
        return http_get(url, timeout)

    db = Database(tmp_path / "hunter.sqlite3")
    config = Config(
        db_path=db.path,
        openvsx=True,
        openvsx_url=BASE,
        openvsx_page_size=5,
        smart_analysis=False,
    )
    start = _stamp(utcnow() - timedelta(minutes=15))
    checkpoint = f"{SINCE_PREFIX}{start}"
    first_body = get(changes_url(BASE, checkpoint, 5), 60)
    first_page = _object(first_body)
    first_changes = _assert_page(first_page)
    _poll_saved(db, config, first_body, checkpoint, 5)
    _record(db, first_changes)

    sampled = list(first_changes)
    any_active = any(str(change.get("state")) == "ACTIVE" for change in first_changes)
    candidates = _universal_active(first_changes)
    cursor = str(first_page.get("nextCursor") or "").strip()
    has_more = first_page.get("hasMore") is True
    window = start
    # The cursor page and the wider window cannot both fit with a version pair.
    if cursor and has_more and any_active:
        follow_body = get(f"{BASE}/api/-/version-changes?after={quote(cursor, safe='')}&size=1", 60)
        follow_changes = _assert_page(_object(follow_body))
        seen = {_identity(change) for change in first_changes}
        for change in follow_changes:
            assert _identity(change) not in seen
    elif not any_active:
        window = _stamp(utcnow() - timedelta(hours=6))
        wide_checkpoint = f"{SINCE_PREFIX}{window}"
        wide_body = get(changes_url(BASE, wide_checkpoint, 20), 60)
        wide_changes = _assert_page(_object(wide_body))
        _poll_saved(db, config, wide_body, wide_checkpoint, 20)
        _record(db, wide_changes)
        sampled.extend(wide_changes)
        if not any(str(change.get("state")) == "ACTIVE" for change in wide_changes):
            pytest.fail(f"Open VSX feed window {start} to {window} has no ACTIVE row")
        candidates = _universal_active(wide_changes)

    denied = _denied()
    oversized: list[str] = []
    reviewed = False
    for name, version in candidates:
        if name in denied:
            continue
        try:
            _review_candidate(db, get, name, version)
        except DownloadTooLarge as exc:
            oversized.append(f"{name}@{version}: {exc}")
            if len(oversized) >= 3:
                break
            continue
        reviewed = True
        break
    if not reviewed:
        if oversized:
            pytest.fail("Open VSX smoke: archives over the cap: " + "; ".join(oversized))
        pytest.fail(f"Open VSX feed window {start} to {window} has no universal ACTIVE row")

    withdrawn = [change for change in sampled if str(change.get("state")) in {"REMOVED", "INACTIVE"}]
    for change in withdrawn:
        assert str(change.get("url") or "") not in calls
    assert len(calls) <= MAX_GETS
