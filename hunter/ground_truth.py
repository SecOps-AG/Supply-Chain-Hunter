"""Ground truth: compare Hunter's scored releases with OSV MAL- records and npm takedowns.

Read-only. Only JSON is fetched and parsed: OSV records (from the OSV.dev API or a
shallow, sparse git checkout of the OpenSSF malicious-packages repo) and npm
packument documents. No package archive is downloaded and nothing is run.

The report gives recall (caught / malicious releases Hunter scored) and
time-to-detect (Hunter's flag time minus the first public malicious signal).
A negative time-to-detect means Hunter flagged the release first.
Open VSX registry labels are listed apart from that recall. A removal is not a
malware verdict, and no extension archive is fetched for one.
"""

from __future__ import annotations

import json
import logging
import os
import re
import statistics
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

from hunter.db import Database, iso, utcnow
from hunter.registry import USER_AGENT, FeedError, HttpGet, http_get, normalize_pypi_name, parse_time

log = logging.getLogger("hunter.ground_truth")

ECOSYSTEMS = {"npm": "npm", "pypi": "PyPI", "crates": "crates.io"}
OSV_ECOSYSTEMS = {value.lower(): key for key, value in ECOSYSTEMS.items()}
NPM_HOLDER_VERSION = "0.0.1-security"
OSV_BATCH = 1000
OSV_MAX_PAGES = 10
# An OSV record or npm holder packument larger than this is skipped, not parsed.
MAX_RECORD_BYTES = 2 * 1024 * 1024
REPORT_NAME = "ground-truth-report.json"
TAKEDOWN_CACHE = "npm-takedowns.json"
GIT_SPARSE_PATHS = ("osv/malicious/npm", "osv/malicious/pypi", "osv/malicious/crates.io")
GIT_TIMEOUT = 1800.0
CAUGHT_BANDS = {"review", "alert"}
_OPENVSX_NOT_REVIEWED = {"vsx_removed_before_review", "vsx_inactive_before_review"}

HttpPost = Callable[[str, bytes, float], bytes]
GitRunner = Callable[[list[str], Path | None], None]


def http_post_json(url: str, body: bytes, timeout: float = 60.0) -> bytes:
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"User-Agent": USER_AGENT, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read(64 * 1024 * 1024)
    except urllib.error.URLError as exc:
        raise FeedError(str(exc.reason)) from exc


def run_git(args: list[str], cwd: Path | None) -> None:
    """Run git without prompts or hooks. Symlinks in the checkout are written as plain files."""
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    subprocess.run(
        ["git", "-c", "core.symlinks=false", "-c", "core.hooksPath=/dev/null", *args],
        cwd=cwd,
        env=env,
        check=True,
        capture_output=True,
        timeout=GIT_TIMEOUT,
    )


# ---- versions ---------------------------------------------------------------


def _generic_version_key(text: str) -> tuple:
    """Semver-like order: numeric release parts, then a prerelease sorts before the release."""
    core, _, _build = text.strip().lstrip("v").partition("+")
    release, dash, pre = core.partition("-")
    numbers = []
    for part in release.split("."):
        match = re.match(r"\d+", part)
        numbers.append(int(match.group()) if match else 0)
    while len(numbers) < 3:
        numbers.append(0)
    pre_parts = tuple((0, int(part), "") if part.isdigit() else (1, 0, part) for part in pre.split(".") if part)
    return (tuple(numbers), 0 if dash else 1, pre_parts)


def version_key(ecosystem: str, text: str):
    if ecosystem == "pypi":
        try:
            from packaging.version import InvalidVersion, Version
        except ImportError:  # pragma: no cover - packaging ships with most installs
            return _generic_version_key(text)
        try:
            return (0, Version(text))
        except InvalidVersion:
            return None
    return _generic_version_key(text)


def _range_affects(ecosystem: str, events: list, version: str) -> bool:
    """OSV range events: each introduced opens an interval, the next fixed or last_affected closes it."""
    key = version_key(ecosystem, version)
    if key is None:
        return False
    opened = None
    for event in events:
        if not isinstance(event, dict):
            continue
        if "introduced" in event:
            text = str(event["introduced"])
            opened = "zero" if text in {"0", ""} else version_key(ecosystem, text)
            continue
        if opened is None:
            continue
        lower_ok = opened == "zero" or (opened is not None and _compare(opened, key) <= 0)
        if "fixed" in event:
            limit = version_key(ecosystem, str(event["fixed"]))
            if lower_ok and limit is not None and _compare(key, limit) < 0:
                return True
            opened = None
        elif "last_affected" in event:
            limit = version_key(ecosystem, str(event["last_affected"]))
            if lower_ok and limit is not None and _compare(key, limit) <= 0:
                return True
            opened = None
        elif "limit" in event:
            limit = version_key(ecosystem, str(event["limit"]))
            if lower_ok and limit is not None and _compare(key, limit) < 0:
                return True
            opened = None
    if opened is None:
        return False
    return opened == "zero" or _compare(opened, key) <= 0


def _compare(left, right) -> int:
    try:
        return (left > right) - (left < right)
    except TypeError:
        return 0


# ---- OSV records ------------------------------------------------------------


@dataclass
class MalRecord:
    id: str
    published: datetime | None
    modified: str
    # (ecosystem, normalized name) -> list of (explicit versions, ranges)
    affected: dict[tuple[str, str], list[tuple[set[str], list[list]]]] = field(default_factory=dict)

    def affects(self, ecosystem: str, name: str, version: str) -> bool:
        for versions, ranges in self.affected.get((ecosystem, name), []):
            if version in versions:
                return True
            if not versions and not ranges:
                return True
            if any(_range_affects(ecosystem, events, version) for events in ranges):
                return True
        return False


def normalize_name(ecosystem: str, name: str) -> str:
    return normalize_pypi_name(name) if ecosystem == "pypi" else name.strip()


def parse_mal_record(document: object) -> MalRecord | None:
    """One OSV JSON object, or None when it is not a live npm, PyPI, or crates.io MAL- record."""
    if not isinstance(document, dict):
        return None
    record_id = str(document.get("id") or "")
    if not record_id.startswith("MAL-") or document.get("withdrawn"):
        return None
    published = parse_time(str(document.get("published") or "")) or parse_time(str(document.get("modified") or ""))
    if published is not None and published.tzinfo is None:
        published = published.replace(tzinfo=timezone.utc)
    record = MalRecord(id=record_id, published=published, modified=str(document.get("modified") or ""))
    for entry in document.get("affected") or []:
        if not isinstance(entry, dict):
            continue
        package = entry.get("package") or {}
        if not isinstance(package, dict):
            continue
        ecosystem = OSV_ECOSYSTEMS.get(str(package.get("ecosystem") or "").lower())
        name = str(package.get("name") or "")
        if not ecosystem or not name:
            continue
        versions = {str(item) for item in entry.get("versions") or [] if isinstance(item, (str, int, float))}
        ranges = []
        for item in entry.get("ranges") or []:
            if isinstance(item, dict) and str(item.get("type") or "").upper() in {"SEMVER", "ECOSYSTEM"}:
                events = item.get("events")
                if isinstance(events, list):
                    ranges.append(events)
        record.affected.setdefault((ecosystem, normalize_name(ecosystem, name)), []).append((versions, ranges))
    return record if record.affected else None


def _load_json_file(path: Path) -> object:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_RECORD_BYTES:
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def _safe_id(record_id: str) -> bool:
    return bool(re.fullmatch(r"MAL-[A-Za-z0-9._-]+", record_id))


class OsvApiSource:
    """OSV.dev querybatch for the packages Hunter saw, then one GET per new or changed MAL- id.

    Full records are cached under ``data_dir/osv`` so a daily run only fetches what changed.
    """

    name = "api"

    def __init__(
        self,
        data_dir: Path,
        base: str = "https://api.osv.dev",
        transport: HttpGet = http_get,
        post: HttpPost = http_post_json,
    ):
        self.cache = Path(data_dir) / "osv"
        self.base = base.rstrip("/")
        self.transport = transport
        self.post = post

    def records(self, packages: Iterable[tuple[str, str]], *, fetch: bool = True) -> list[MalRecord]:
        if not fetch:
            return self._cached_records()
        listed = self._query(sorted(set(packages)))
        self.cache.mkdir(parents=True, exist_ok=True)
        found = []
        for record_id, modified in sorted(listed.items()):
            path = self.cache / f"{record_id}.json"
            document = _load_json_file(path)
            if not isinstance(document, dict) or (modified and document.get("modified") != modified):
                blob = self.transport(f"{self.base}/v1/vulns/{quote(record_id)}", 60)
                if len(blob) > MAX_RECORD_BYTES:
                    continue
                document = json.loads(blob.decode("utf-8"))
                _write_json(path, document)
            record = parse_mal_record(document)
            if record is not None:
                found.append(record)
        return found

    def _cached_records(self) -> list[MalRecord]:
        if not self.cache.is_dir():
            return []
        found = []
        for path in sorted(self.cache.glob("MAL-*.json")):
            record = parse_mal_record(_load_json_file(path))
            if record is not None:
                found.append(record)
        return found

    def _query(self, packages: list[tuple[str, str]]) -> dict[str, str]:
        listed: dict[str, str] = {}
        for start in range(0, len(packages), OSV_BATCH):
            chunk = packages[start : start + OSV_BATCH]
            queries = [{"package": {"ecosystem": ECOSYSTEMS[eco], "name": name}} for eco, name in chunk]
            pages = 0
            while queries and pages < OSV_MAX_PAGES:
                pages += 1
                body = json.dumps({"queries": queries}).encode()
                payload = json.loads(self.post(f"{self.base}/v1/querybatch", body, 120).decode("utf-8"))
                results = payload.get("results") or [] if isinstance(payload, dict) else []
                follow = []
                for query, result in zip(queries, results):
                    if not isinstance(result, dict):
                        continue
                    for vuln in result.get("vulns") or []:
                        record_id = str((vuln or {}).get("id") or "")
                        if record_id.startswith("MAL-") and _safe_id(record_id):
                            listed[record_id] = str(vuln.get("modified") or "")
                    token = result.get("next_page_token")
                    if token:
                        follow.append({**query, "page_token": token})
                queries = follow
        return listed


class OsvGitSource:
    """Shallow, sparse checkout of the malicious-packages repo: npm, PyPI, and crates.io folders.

    Records are read for the packages Hunter saw, by folder name. Files are parsed as
    JSON only; symlinks and oversized files are skipped.
    """

    name = "git"

    def __init__(self, data_dir: Path, repo_url: str, git: GitRunner = run_git):
        self.checkout = Path(data_dir) / "malicious-packages"
        self.repo_url = repo_url
        self.git = git

    def update(self) -> None:
        if (self.checkout / ".git").is_dir():
            self.git(["fetch", "--depth", "1", "origin", "HEAD"], self.checkout)
            self.git(["reset", "--hard", "FETCH_HEAD"], self.checkout)
            return
        self.checkout.parent.mkdir(parents=True, exist_ok=True)
        self.git(
            ["clone", "--depth", "1", "--filter=blob:none", "--sparse", self.repo_url, str(self.checkout)],
            None,
        )
        self.git(["sparse-checkout", "set", *GIT_SPARSE_PATHS], self.checkout)

    def records(self, packages: Iterable[tuple[str, str]], *, fetch: bool = True) -> list[MalRecord]:
        if fetch:
            self.update()
        root = self.checkout / "osv" / "malicious"
        pypi_dirs = self._pypi_index(root / "pypi")
        found: dict[str, MalRecord] = {}
        for ecosystem, name in packages:
            if ecosystem == "pypi":
                folder = pypi_dirs.get(normalize_pypi_name(name))
            else:
                folder_name = "crates.io" if ecosystem == "crates" else "npm"
                base = root / folder_name
                folder = base / name
                if ".." in Path(name).parts or not _inside(folder, base):
                    folder = None
            if folder is None or not folder.is_dir() or folder.is_symlink():
                continue
            for path in sorted(folder.glob("MAL-*.json")):
                record = parse_mal_record(_load_json_file(path))
                if record is not None:
                    found[record.id] = record
        return list(found.values())

    @staticmethod
    def _pypi_index(folder: Path) -> dict[str, Path]:
        if not folder.is_dir():
            return {}
        return {normalize_pypi_name(entry.name): entry for entry in folder.iterdir() if entry.is_dir()}


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return False
    return True


# ---- npm takedowns ----------------------------------------------------------


def _not_found(exc: Exception) -> bool:
    return "not found" in str(exc).lower()


def npm_takedown_time(name: str, registry: str, transport: HttpGet = http_get) -> datetime | None:
    """When npm replaced the package with its 0.0.1-security holder, or None when it has not.

    Reads the small version document first; the packument is only read for a holder,
    which has no other versions left.
    """
    base = f"{registry.rstrip('/')}/{quote(name)}"
    try:
        version_doc = json.loads(transport(f"{base}/{NPM_HOLDER_VERSION}", 30).decode("utf-8"))
    except FeedError as exc:
        if _not_found(exc):
            return None
        raise
    if not isinstance(version_doc, dict) or version_doc.get("version") != NPM_HOLDER_VERSION:
        return None
    blob = transport(base, 30)
    stamp = None
    if len(blob) <= MAX_RECORD_BYTES:
        packument = json.loads(blob.decode("utf-8"))
        times = packument.get("time") if isinstance(packument, dict) else None
        if isinstance(times, dict):
            stamp = parse_time(str(times.get(NPM_HOLDER_VERSION) or ""))
    if stamp is not None and stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp or utcnow()


def check_npm_takedowns(
    names: Iterable[str],
    *,
    flagged: set[str],
    cache_path: Path,
    registry: str,
    limit: int,
    transport: HttpGet = http_get,
    fetch: bool = True,
    now: datetime | None = None,
    stop: threading.Event | None = None,
) -> tuple[dict[str, datetime], int, list[str]]:
    """Takedown times by name, checks made, and errors.

    A known takedown is not checked again. Up to `limit` other names are checked
    per run: flagged and never-checked names first, then the longest unchecked.
    """
    moment = now or utcnow()
    cache = _read_json(cache_path)
    if not isinstance(cache, dict):
        cache = {}
    names = sorted(set(names))
    checked = 0
    errors: list[str] = []
    if fetch and limit > 0:
        due = [name for name in names if not (cache.get(name) or {}).get("takedown_at")]
        due.sort(key=lambda name: (name not in flagged, (cache.get(name) or {}).get("checked_at") or "", name))
        for name in due[:limit]:
            if stop is not None and stop.is_set():
                break
            try:
                when = npm_takedown_time(name, registry, transport)
            except (FeedError, OSError, ValueError) as exc:
                errors.append(f"npm {name}: {exc}")
                continue
            checked += 1
            cache[name] = {"checked_at": iso(moment), "takedown_at": iso(when) if when else None}
        _write_json(cache_path, cache)
    found = {}
    for name in names:
        stamp = parse_time((cache.get(name) or {}).get("takedown_at"))
        if stamp is not None:
            found[name] = stamp
    return found, checked, errors


# ---- report -----------------------------------------------------------------


def _hours(later: datetime | None, earlier: datetime | None) -> float | None:
    if later is None or earlier is None:
        return None
    return round((later - earlier).total_seconds() / 3600.0, 2)


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(fraction * (len(ordered) - 1))))
    return ordered[index]


def ttd_stats(values: list[float]) -> dict:
    if not values:
        return {"count": 0, "median": None, "p90": None, "mean": None, "min": None, "max": None, "hunter_first": 0}
    return {
        "count": len(values),
        "median": round(statistics.median(values), 2),
        "p90": round(_percentile(values, 0.9), 2),
        "mean": round(statistics.fmean(values), 2),
        "min": round(min(values), 2),
        "max": round(max(values), 2),
        "hunter_first": sum(1 for value in values if value < 0),
    }


def _ratio(part: int, whole: int) -> float | None:
    return round(part / whole, 4) if whole else None


def _aware(text: str | None) -> datetime | None:
    stamp = parse_time(text)
    if stamp is not None and stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp


def _payload_signals(row: dict) -> list[str]:
    raw = row.get("payload_json")
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    signals = data.get("signals")
    if not isinstance(signals, list):
        return []
    return [str(item) for item in signals]


def _label_views(rows: list[dict]) -> list[dict]:
    views = [
        {"platform": row.get("platform"), "state": row.get("state"), "changed_at": row.get("changed_at")}
        for row in rows
    ]
    views.sort(key=lambda item: (str(item["platform"]), str(item["state"]), str(item["changed_at"])))
    return views


def _openvsx_registry(rows: list[dict], labels: list[dict]) -> tuple[list[dict], dict]:
    """Scored Open VSX releases joined with registry labels. Labels alone are not misses."""
    grouped: dict[tuple[str, str], list[dict]] = {}
    for label in labels:
        grouped.setdefault((str(label.get("name")), str(label.get("version"))), []).append(label)
    seen: set[tuple[str, str]] = set()
    items: list[dict] = []
    scored = caught = not_reviewed = 0
    for row in rows:
        key = (str(row.get("name")), str(row.get("version")))
        seen.add(key)
        unread = bool(set(_payload_signals(row)) & _OPENVSX_NOT_REVIEWED)
        band = row.get("band")
        is_caught = (not unread) and band in CAUGHT_BANDS
        scored += 1
        if unread:
            not_reviewed += 1
        elif is_caught:
            caught += 1
        scored_at = _aware(row.get("created_at"))
        items.append(
            {
                "name": row.get("name"),
                "version": str(row.get("version")),
                "band": band,
                "scored_at": iso(scored_at) if scored_at else None,
                "caught": is_caught,
                "not_reviewed": unread,
                "labels": _label_views(grouped.get(key, [])),
            }
        )
    for key, group in grouped.items():
        if key in seen:
            continue
        items.append(
            {
                "name": key[0],
                "version": key[1],
                "band": None,
                "scored_at": None,
                "caught": False,
                "not_reviewed": False,
                "labels": _label_views(group),
            }
        )
    items.sort(key=lambda item: (str(item["name"]), str(item["version"])))
    summary = {
        "removed": sum(1 for label in labels if label.get("state") == "removed"),
        "inactive": sum(1 for label in labels if label.get("state") == "inactive"),
        "scored": scored,
        "caught": caught,
        "not_reviewed": not_reviewed,
    }
    return items, summary


def _labels_since(labels: list[dict], since: str) -> list[dict]:
    """Labels whose truth time (``changed_at``, else ``first_seen_at``) is inside the window."""
    if not since:
        return list(labels)
    start = _aware(since)
    if start is None:
        return list(labels)
    kept = []
    for label in labels:
        raw = label.get("changed_at") or label.get("first_seen_at")
        when = _aware(str(raw)) if raw else None
        if when is not None and when < start:
            continue
        kept.append(label)
    return kept


def build_report(
    releases: list[dict],
    records: list[MalRecord],
    takedowns: dict[str, datetime],
    *,
    now: datetime | None = None,
    meta: dict | None = None,
    openvsx_labels: list[dict] | None = None,
) -> dict:
    """Label each scored release against the ground truth and compute the metrics.

    `releases` rows need ecosystem, name, version, band, created_at and confirmed_at.
    A release counts as caught when Scout put it in review or alert, or an alert was
    confirmed. Releases still `deferred` are left out of recall and counted apart.
    Open VSX rows are not part of that recall. ``openvsx_labels`` joins them in
    ``openvsx_items``. ``vsx_removed_before_review`` and ``vsx_inactive_before_review``
    count as ``not_reviewed``.
    """
    label_rows = list(openvsx_labels or [])
    openvsx_releases = [row for row in releases if row.get("ecosystem") == "openvsx"]
    releases = [row for row in releases if row.get("ecosystem") != "openvsx"]
    by_package: dict[tuple[str, str], list[MalRecord]] = {}
    for record in records:
        for key in record.affected:
            by_package.setdefault(key, []).append(record)
    items = []
    deferred = 0
    for row in releases:
        ecosystem = row["ecosystem"]
        version = str(row["version"])
        if ecosystem == "npm" and version == NPM_HOLDER_VERSION:
            continue
        name = normalize_name(ecosystem, str(row["name"]))
        matched = [record for record in by_package.get((ecosystem, name), []) if record.affects(ecosystem, name, version)]
        takedown = takedowns.get(name) if ecosystem == "npm" else None
        if not matched and takedown is None:
            continue
        if row.get("band") == "deferred":
            deferred += 1
            continue
        truth_times = [record.published for record in matched if record.published is not None]
        sources = ["osv"] if matched else []
        if takedown is not None:
            truth_times.append(takedown)
            sources.append("npm_takedown")
        truth_at = min(truth_times) if truth_times else None
        scored_at = _aware(row.get("created_at"))
        confirmed_at = _aware(row.get("confirmed_at"))
        confirmed = confirmed_at is not None
        caught = row.get("band") in CAUGHT_BANDS or confirmed
        flag_at = scored_at if row.get("band") in CAUGHT_BANDS else confirmed_at
        items.append(
            {
                "ecosystem": ecosystem,
                "name": row["name"],
                "version": version,
                "band": row.get("band"),
                "scored_at": iso(scored_at) if scored_at else None,
                "confirmed_at": iso(confirmed_at) if confirmed_at else None,
                "caught": caught,
                "confirmed": confirmed,
                "truth_at": iso(truth_at) if truth_at else None,
                "truth_sources": sources,
                "osv_ids": sorted(record.id for record in matched),
                "time_to_detect_hours": _hours(flag_at, truth_at) if caught else None,
                "confirmed_time_to_detect_hours": _hours(confirmed_at, truth_at) if confirmed else None,
            }
        )
    items.sort(key=lambda item: (item["ecosystem"], item["name"], item["version"]))

    def _tally(rows: list[dict]) -> dict:
        caught = sum(1 for item in rows if item["caught"])
        confirmed = sum(1 for item in rows if item["confirmed"])
        return {
            "malicious_seen": len(rows),
            "caught": caught,
            "missed": len(rows) - caught,
            "recall": _ratio(caught, len(rows)),
            "confirmed": confirmed,
            "confirmed_recall": _ratio(confirmed, len(rows)),
        }

    summary = {
        "releases_considered": len(releases),
        "packages_considered": len({(row["ecosystem"], row["name"]) for row in releases}),
        **_tally(items),
        "deferred": deferred,
        "time_to_detect_hours": ttd_stats(
            [item["time_to_detect_hours"] for item in items if item["time_to_detect_hours"] is not None]
        ),
        "confirmed_time_to_detect_hours": ttd_stats(
            [item["confirmed_time_to_detect_hours"] for item in items if item["confirmed_time_to_detect_hours"] is not None]
        ),
        "by_ecosystem": {eco: _tally([item for item in items if item["ecosystem"] == eco]) for eco in ECOSYSTEMS},
        "by_source": {
            source: sum(1 for item in items if source in item["truth_sources"]) for source in ("osv", "npm_takedown")
        },
        "osv_records": len(records),
        "npm_takedowns": len(takedowns),
    }
    openvsx_items, openvsx_summary = _openvsx_registry(openvsx_releases, label_rows)
    summary["openvsx_registry"] = openvsx_summary
    return {
        "generated_at": iso(now or utcnow()),
        **(meta or {}),
        "summary": summary,
        "items": items,
        "openvsx_items": openvsx_items,
    }


def _read_json(path: Path) -> object:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def _write_json(path: Path, payload: object) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(name, path)
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise


def ground_truth_dir(config) -> Path:
    if config.ground_truth_dir:
        return Path(config.ground_truth_dir)
    return Path(config.db_path).resolve().parent / "ground-truth"


def make_source(config, source: str | None = None, *, transport: HttpGet = http_get, post: HttpPost = http_post_json, git: GitRunner = run_git):
    kind = (source or config.ground_truth_source or "api").strip().lower()
    data_dir = ground_truth_dir(config)
    if kind == "git":
        return OsvGitSource(data_dir, config.ground_truth_repo, git=git)
    if kind == "api":
        return OsvApiSource(data_dir, config.osv_api, transport=transport, post=post)
    raise ValueError(f"unknown ground-truth source {kind!r}; use api or git")


def report_is_fresh(config, now: float | None = None) -> bool:
    """True when the last report is younger than the run interval, so a restart does not refetch."""
    path = ground_truth_dir(config) / REPORT_NAME
    try:
        age = (now if now is not None else time.time()) - path.stat().st_mtime
    except OSError:
        return False
    return 0 <= age < config.ground_truth_interval


def run_ground_truth(
    db: Database,
    config,
    *,
    source=None,
    transport: HttpGet = http_get,
    days: int | None = None,
    fetch: bool = True,
    out: Path | None = None,
    now: datetime | None = None,
    stop: threading.Event | None = None,
) -> dict:
    """Fetch the ground truth, label Hunter's releases, write the JSON report, return it."""
    moment = now or utcnow()
    lookback = config.ground_truth_days if days is None else days
    since = iso(moment - timedelta(days=lookback)) if lookback > 0 else ""
    data_dir = ground_truth_dir(config)
    source = source or make_source(config, transport=transport)
    releases = db.ground_truth_releases(since)
    # Registry labels are not OSV packages, and their archives are not fetched.
    packages = {(row["ecosystem"], row["name"]) for row in releases if row["ecosystem"] != "openvsx"}
    errors: list[str] = []
    try:
        records = source.records(packages, fetch=fetch)
    except (FeedError, OSError, ValueError, subprocess.SubprocessError) as exc:
        errors.append(f"osv {source.name}: {exc}")
        log.warning("ground truth: OSV %s source failed: %s", source.name, exc)
        records = source.records(packages, fetch=False)
    npm_names = {name for eco, name in packages if eco == "npm"}
    holders = {row["name"] for row in releases if row["ecosystem"] == "npm" and row["version"] == NPM_HOLDER_VERSION}
    flagged = {
        row["name"]
        for row in releases
        if row["ecosystem"] == "npm" and (row.get("band") in CAUGHT_BANDS or row.get("confirmed_at"))
    }
    takedowns, checked, npm_errors = check_npm_takedowns(
        npm_names - holders,
        flagged=flagged,
        cache_path=data_dir / TAKEDOWN_CACHE,
        registry=config.npm_registry,
        limit=config.ground_truth_npm_checks,
        transport=transport,
        fetch=fetch,
        now=moment,
        stop=stop,
    )
    errors.extend(npm_errors[:50])
    # A holder Hunter saw in the npm feed is a takedown at the time Hunter scored it.
    for row in releases:
        if row["ecosystem"] == "npm" and row["version"] == NPM_HOLDER_VERSION:
            stamp = _aware(row.get("created_at"))
            if stamp is not None and (row["name"] not in takedowns or stamp < takedowns[row["name"]]):
                takedowns[row["name"]] = stamp
    report = build_report(
        releases,
        records,
        takedowns,
        now=moment,
        meta={
            "source": source.name,
            "since": since or None,
            "lookback_days": lookback,
            "fetched": fetch,
            "npm_checked": checked,
            "errors": errors,
        },
        openvsx_labels=_labels_since(db.openvsx_labels(), since),
    )
    target = Path(out) if out else data_dir / REPORT_NAME
    _write_json(target, report)
    summary = report["summary"]
    log.info(
        "ground truth: %s malicious releases seen, %s caught (recall %s), median time-to-detect %sh; report %s",
        summary["malicious_seen"],
        summary["caught"],
        summary["recall"],
        summary["time_to_detect_hours"]["median"],
        target,
    )
    return report
