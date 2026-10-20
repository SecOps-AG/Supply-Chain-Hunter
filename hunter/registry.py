"""Watchlists and registry feeds. HTTP only; nothing is installed."""

from __future__ import annotations

import http.client
import inspect
import json
import logging
import os
import tempfile
import urllib.error
import urllib.request
import xmlrpc.client
from pathlib import Path
from urllib.parse import quote
from collections.abc import Callable
from datetime import datetime

from hunter.archives import ArchiveError, read_archive_member
from hunter.db import Database

log = logging.getLogger("hunter.registry")

USER_AGENT = "supply-chain-hunter/0.1"
HttpGet = Callable[[str, float], bytes]
# A single archive is streamed to a temp file and refused past this size.
# The body is not kept as one bytes object.
PACKAGE_DOWNLOAD_MAX_BYTES = 64 * 1024 * 1024
_READ_CHUNK = 64 * 1024


class FeedError(Exception):
    pass


class DownloadTooLarge(FeedError):
    """The package body is larger than the download cap."""


class TruncatedDownload(http.client.HTTPException):
    """The response ended before the declared package body arrived."""

    def __init__(self, read: int, remaining: int):
        self.read = int(read)
        self.remaining = int(remaining)
        super().__init__(
            f"IncompleteRead({self.read} bytes read, {self.remaining} more expected)"
        )


def http_get(
    url: str,
    timeout: float = 60.0,
    *,
    max_bytes: int | None = None,
    dest: Path | None = None,
) -> bytes | Path:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if dest is not None:
                stream_limited(response, dest, max_bytes)
                return dest
            return read_limited(response, max_bytes)
    except urllib.error.URLError as exc:
        raise FeedError(str(exc.reason)) from exc


def _content_length(response) -> int | None:
    raw = response.headers.get("Content-Length")
    if raw is None or str(raw).strip() == "":
        return None
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None
    if value < 0:
        return None
    return value


def _discard_download(dest: Path, handle) -> None:
    if handle is not None and not handle.closed:
        handle.close()
    dest.unlink(missing_ok=True)


def stream_limited(response, dest: Path, max_bytes: int | None) -> int:
    """Write a response body to `dest`. A cap stops the read before the rest is stored."""
    if max_bytes is not None and max_bytes < 0:
        raise ValueError("max_bytes must be non-negative")
    declared = _content_length(response)
    if max_bytes is not None and declared is not None and declared > max_bytes:
        raise DownloadTooLarge(f"package declares {declared} bytes; cap is {max_bytes}")
    total = 0
    handle = dest.open("wb")
    try:
        try:
            while True:
                if max_bytes is None:
                    block = response.read(_READ_CHUNK)
                else:
                    if total >= max_bytes:
                        break
                    block = response.read(min(_READ_CHUNK, max_bytes - total))
                if not block:
                    break
                handle.write(block)
                total += len(block)
        except http.client.IncompleteRead as exc:
            partial = getattr(exc, "partial", b"") or b""
            read = total + len(partial)
            remaining = exc.expected if isinstance(getattr(exc, "expected", None), int) else 0
            _discard_download(dest, handle)
            raise TruncatedDownload(read, remaining) from None
        if declared is not None and total < declared:
            _discard_download(dest, handle)
            raise TruncatedDownload(total, declared - total)
        if max_bytes is not None and total >= max_bytes:
            extra = response.read(1)
            if extra:
                _discard_download(dest, handle)
                raise DownloadTooLarge(f"package exceeds {max_bytes} bytes")
    finally:
        if not handle.closed:
            handle.close()
    return total


def read_limited(response, max_bytes: int | None) -> bytes:
    """Read a response body. A cap stops the read before the rest is buffered."""
    if max_bytes is None:
        return response.read()
    if max_bytes < 0:
        raise ValueError("max_bytes must be non-negative")
    declared = _content_length(response)
    if declared is not None and declared > max_bytes:
        raise DownloadTooLarge(f"package declares {declared} bytes; cap is {max_bytes}")
    chunks: list[bytes] = []
    total = 0
    try:
        while total < max_bytes:
            block = response.read(min(_READ_CHUNK, max_bytes - total))
            if not block:
                break
            chunks.append(block)
            total += len(block)
    except http.client.IncompleteRead as exc:
        partial = getattr(exc, "partial", b"") or b""
        read = total + len(partial)
        remaining = exc.expected if isinstance(getattr(exc, "expected", None), int) else 0
        raise TruncatedDownload(read, remaining) from None
    if declared is not None and total < declared:
        raise TruncatedDownload(total, declared - total)
    if total >= max_bytes:
        extra = response.read(1)
        if extra:
            raise DownloadTooLarge(f"package exceeds {max_bytes} bytes")
    return b"".join(chunks)


def _accepts_keyword(transport: HttpGet, name: str) -> bool:
    try:
        signature = inspect.signature(transport)
    except (TypeError, ValueError):
        return False
    for param_name, param in signature.parameters.items():
        if param_name == name:
            return True
        if param.kind is inspect.Parameter.VAR_KEYWORD:
            return True
    return False


def fetch_capped(transport: HttpGet, url: str, timeout: float, max_bytes: int) -> Path:
    """Stream `url` to a temp file, refusing a body larger than `max_bytes`.

    The archive is not kept as one bytes object. The caller deletes the file.
    Transports that accept `dest` write the body themselves. Others are written
    out after they return, then the returned bytes are dropped.
    """
    fd, name = tempfile.mkstemp(prefix="hunter-archive-")
    os.close(fd)
    path = Path(name)
    try:
        if _accepts_keyword(transport, "dest"):
            transport(url, timeout, max_bytes=max_bytes, dest=path)
            return path
        if _accepts_keyword(transport, "max_bytes"):
            blob = transport(url, timeout, max_bytes=max_bytes)
        else:
            blob = transport(url, timeout)
        if isinstance(blob, Path):
            if blob != path:
                path.write_bytes(blob.read_bytes())
            return path
        if not isinstance(blob, (bytes, bytearray)):
            raise FeedError("archive download did not return bytes")
        if len(blob) > max_bytes:
            raise DownloadTooLarge(f"package is {len(blob)} bytes; cap is {max_bytes}")
        view = memoryview(bytes(blob))
        with path.open("wb") as handle:
            offset = 0
            while offset < len(view):
                handle.write(view[offset : offset + _READ_CHUNK])
                offset += _READ_CHUNK
        return path
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _json(blob: bytes) -> dict:
    data = json.loads(blob.decode("utf-8"))
    if not isinstance(data, dict):
        raise FeedError("expected a JSON object")
    return data


def normalize_pypi_name(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def load_pypi_watchlist(top_n: int, url: str, transport: HttpGet = http_get) -> list[tuple[str, int, int]]:
    payload = _json(transport(url, 60))
    rows = payload.get("rows") or []
    ranked = []
    for row in rows:
        project = row.get("project")
        if not project:
            continue
        downloads = int(row.get("download_count") or 0)
        ranked.append((normalize_pypi_name(str(project)), downloads))
    ranked.sort(key=lambda item: item[1], reverse=True)
    return [(name, rank, downloads) for rank, (name, downloads) in enumerate(ranked[:top_n], start=1)]


def load_npm_watchlist(top_n: int, registry: str, transport: HttpGet = http_get) -> list[tuple[str, int, int]]:
    """Prefer the download-counts dataset. Fall back to the npm search API."""
    try:
        return _load_npm_watchlist_counts(top_n, registry, transport)
    except (FeedError, OSError, ValueError, json.JSONDecodeError) as exc:
        log.warning("download-counts unavailable (%s); using npm search", exc)
        return load_npm_watchlist_search(top_n, registry, transport)


def _load_npm_watchlist_counts(top_n: int, registry: str, transport: HttpGet) -> list[tuple[str, int, int]]:
    """The download-counts dataset ships counts.json inside its own npm tarball."""
    meta = _json(transport(f"{registry.rstrip('/')}/download-counts/latest", 60))
    tarball = (meta.get("dist") or {}).get("tarball")
    if not tarball:
        raise FeedError("download-counts metadata has no tarball")
    try:
        raw = read_archive_member(transport(str(tarball), 120), "counts.json")
    except ArchiveError as exc:
        raise FeedError(str(exc)) from exc
    if raw is None:
        raise FeedError("counts.json missing from download-counts")
    counts = json.loads(raw)
    if not isinstance(counts, dict):
        raise FeedError("counts.json must be an object")
    ranked = sorted(
        ((str(name), int(count)) for name, count in counts.items()),
        key=lambda item: item[1],
        reverse=True,
    )
    return [(name, rank, downloads) for rank, (name, downloads) in enumerate(ranked[:top_n], start=1)]


def load_npm_watchlist_search(
    top_n: int,
    registry: str,
    transport: HttpGet = http_get,
) -> list[tuple[str, int, int]]:
    """Monthly-download ranking from the npm search API when counts.json is unavailable."""
    ranked: list[tuple[str, int]] = []
    page_size = 250
    for offset in range(0, max(top_n, 1), page_size):
        size = min(page_size, top_n - offset)
        url = (
            f"{registry.rstrip('/')}/-/v1/search?"
            f"text=boost-exact:false&popularity=1.0&quality=0.0&maintenance=0.0"
            f"&size={size}&from={offset}"
        )
        payload = _json(transport(url, 60))
        objects = payload.get("objects") or []
        if not isinstance(objects, list):
            break
        for obj in objects:
            if not isinstance(obj, dict):
                continue
            package = obj.get("package") or {}
            name = package.get("name") if isinstance(package, dict) else None
            if not name:
                continue
            downloads = 0
            raw_downloads = obj.get("downloads")
            if isinstance(raw_downloads, dict):
                downloads = int(raw_downloads.get("monthly") or 0)
            ranked.append((str(name), downloads))
        if len(objects) < size:
            break
    if not ranked:
        raise FeedError("npm search returned no packages")
    return [(name, rank, downloads) for rank, (name, downloads) in enumerate(ranked[:top_n], start=1)]


class TimeoutTransport(xmlrpc.client.SafeTransport):
    def __init__(self, timeout: float):
        super().__init__()
        self._timeout = timeout

    def make_connection(self, host):
        connection = super().make_connection(host)
        connection.timeout = self._timeout
        return connection


class PypiSerialFeed:
    """PyPI changelog serial API (changelog_since_serial over HTTP)."""

    def __init__(self, base: str = "https://pypi.org/pypi", timeout: float = 60.0):
        self._proxy = xmlrpc.client.ServerProxy(
            base,
            transport=TimeoutTransport(timeout),
            allow_none=True,
        )

    def last_serial(self) -> int:
        return int(self._proxy.changelog_last_serial())

    def since(self, serial: int) -> list[tuple]:
        rows = self._proxy.changelog_since_serial(int(serial))
        return list(rows)


def pypi_events_to_versions(events: list[tuple], watch: dict[str, int]) -> list[tuple[str, str, int]]:
    """Collapse changelog rows to new (name, version, rank) pairs. Removals are ignored."""
    found: dict[tuple[str, str], int] = {}
    order: list[tuple[str, str]] = []
    max_serial = None
    for event in events:
        if len(event) < 5:
            continue
        name, version, _timestamp, action, serial = event[:5]
        max_serial = int(serial)
        action_text = str(action or "").lower()
        if action_text.startswith("remove") or "yank" in action_text:
            continue
        if not version:
            continue
        key_name = normalize_pypi_name(str(name))
        if key_name not in watch:
            continue
        pair = (key_name, str(version))
        if pair not in found:
            order.append(pair)
            found[pair] = watch[key_name]
    _ = max_serial
    return [(name, version, found[(name, version)]) for name, version in order]


def max_serial(events: list[tuple]) -> int | None:
    serials = [int(event[4]) for event in events if len(event) >= 5]
    return max(serials) if serials else None


def fetch_npm_changes(base: str, since: str, limit: int, transport: HttpGet = http_get) -> dict:
    url = f"{base.rstrip('/')}/_changes?since={quote(str(since), safe='')}&limit={int(limit)}"
    return _json(transport(url, 60))


def fetch_npm_changes_head(base: str, transport: HttpGet = http_get, limit: int = 1) -> dict:
    """Current feed head. replicate.npmjs.com rejects since=now."""
    url = f"{base.rstrip('/')}/_changes?descending=true&limit={int(limit)}"
    return _json(transport(url, 60))


def page_npm_changes(
    base: str,
    since: str,
    *,
    page_size: int = 1000,
    transport: HttpGet = http_get,
    stop=None,
):
    """Yield (results, checkpoint_seq, done) without jumping a gap."""
    cursor = str(since)
    while True:
        if stop is not None and stop.is_set():
            yield [], cursor, True
            return
        page = fetch_npm_changes(base, cursor, page_size, transport)
        results = list(page.get("results") or [])
        last = str(page.get("last_seq", cursor))
        if not results:
            yield [], last, True
            return
        finished = len(results) < page_size or last == cursor
        yield results, last, finished
        if finished:
            return
        cursor = last


def versions_after(meta: dict, last_time: str | None) -> list[tuple[str, str]]:
    times = meta.get("time") or {}
    ordered = []
    for version, stamp in times.items():
        if version in {"created", "modified"}:
            continue
        if last_time is None or str(stamp) > last_time:
            ordered.append((str(stamp), str(version)))
    ordered.sort()
    return [(version, stamp) for stamp, version in ordered]


def newest_version(meta: dict) -> tuple[str | None, str | None]:
    ordered = versions_after(meta, None)
    if not ordered:
        latest = (meta.get("dist-tags") or {}).get("latest")
        return (str(latest) if latest else None), None
    version, stamp = ordered[-1]
    return version, stamp


def predecessor_version(meta: dict, version: str) -> str | None:
    times = []
    for name, stamp in (meta.get("time") or {}).items():
        if name in {"created", "modified"}:
            continue
        times.append((str(stamp), str(name)))
    times.sort()
    names = [name for _, name in times]
    if version not in names:
        return names[-2] if len(names) >= 2 else None
    index = names.index(version)
    if index == 0:
        return None
    return names[index - 1]


def pypi_predecessor(project: dict, version: str) -> str | None:
    releases = project.get("releases") or {}
    def earliest(files: list) -> str:
        stamps = [str(item.get("upload_time_iso_8601") or "") for item in files or []]
        stamps = [stamp for stamp in stamps if stamp]
        return min(stamps) if stamps else ""

    new_stamp = earliest(releases.get(version) or [])
    candidates = []
    for other, files in releases.items():
        if other == version or not files:
            continue
        stamp = earliest(files)
        if new_stamp and stamp and stamp >= new_stamp:
            continue
        candidates.append((stamp, str(other)))
    if not candidates:
        return None
    candidates.sort()
    return candidates[-1][1]


def _best_wheel(wheels: list[dict]) -> dict:
    for item in wheels:
        name = str(item.get("filename") or item.get("url") or "").lower()
        if "py3-none-any" in name or "py2.py3-none-any" in name:
            return item
    return wheels[0]


def choose_pypi_artifacts(files: list[dict]) -> list[tuple[str, dict]]:
    """Sdist and wheel when both exist, so a payload in only one of them is still diffed."""
    sdists = [item for item in files if item.get("packagetype") == "sdist" and item.get("url")]
    wheels = [item for item in files if item.get("packagetype") == "bdist_wheel" and item.get("url")]
    chosen: list[tuple[str, dict]] = []
    if sdists:
        chosen.append(("sdist", sdists[0]))
    if wheels:
        chosen.append(("wheel", _best_wheel(wheels)))
    if chosen:
        return chosen
    rest = [item for item in files if item.get("url")]
    if rest:
        return [("archive", rest[0])]
    return []


def choose_pypi_file(files: list[dict]) -> dict | None:
    artifacts = choose_pypi_artifacts(files)
    return artifacts[0][1] if artifacts else None


def pypi_version_events(events: list[tuple]) -> list[tuple[str, str]]:
    """Every non-removal (name, version) in a changelog page, including names off the watchlist."""
    found: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for event in events:
        if len(event) < 5:
            continue
        name, version, _timestamp, action, _serial = event[:5]
        action_text = str(action or "").lower()
        if action_text.startswith("remove") or "yank" in action_text or not version:
            continue
        pair = (normalize_pypi_name(str(name)), str(version))
        if pair in seen:
            continue
        seen.add(pair)
        found.append(pair)
    return found


def publishers_pypi(info: dict) -> frozenset[str]:
    names = []
    for key in ("author", "maintainer"):
        value = (info or {}).get(key)
        if value and str(value).strip():
            names.append(str(value).strip().lower())
    return frozenset(names)


def _person_name(value) -> str:
    if isinstance(value, dict):
        value = value.get("name") or value.get("username")
    if value and str(value).strip():
        return str(value).strip().lower()
    return ""


def publishers_pypi_files(files: list | None) -> frozenset[str]:
    """Publisher names stored on this version's files.

    The project author is not a per-version publisher. File records often
    omit the uploader, and an empty result means that side is unknown.
    """
    names = []
    for item in files or []:
        if not isinstance(item, dict):
            continue
        for key in ("uploader", "author", "maintainer"):
            name = _person_name(item.get(key))
            if name:
                names.append(name)
    return frozenset(names)


def publishers_npm(version_doc: dict) -> frozenset[str]:
    names = []
    for person in version_doc.get("maintainers") or []:
        if isinstance(person, dict) and person.get("name"):
            names.append(str(person["name"]).strip().lower())
    user = version_doc.get("_npmUser") or {}
    if isinstance(user, dict) and user.get("name"):
        names.append(str(user["name"]).strip().lower())
    return frozenset(names)


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def refresh_watchlists(db: Database, config, transport: HttpGet = http_get) -> None:
    pypi_rows = load_pypi_watchlist(config.top_n, config.pypi_top_url, transport)
    db.replace_watchlist("pypi", pypi_rows)
    npm_limit = config.npm_top_n or config.top_n
    npm_rows = load_npm_watchlist(npm_limit, config.npm_registry, transport)
    db.replace_watchlist("npm", npm_rows)
    log.info("watchlists refreshed pypi=%s npm=%s", len(pypi_rows), len(npm_rows))


def bootstrap_pypi(db: Database, feed: PypiSerialFeed) -> None:
    if db.get_checkpoint("pypi") is None:
        db.set_checkpoint("pypi", str(feed.last_serial()))


def bootstrap_npm(db: Database, base: str, transport: HttpGet = http_get) -> None:
    if db.get_checkpoint("npm") is not None:
        return
    page = fetch_npm_changes_head(base, transport)
    last = page.get("last_seq")
    if last is None or str(last) == "":
        raise FeedError("npm changes feed did not return last_seq")
    db.set_checkpoint("npm", str(last))
