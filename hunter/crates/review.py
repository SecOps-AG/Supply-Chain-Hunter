"""Review one crates.io release: index, checksum, rules, then routing.

Called by ``service.classify_job`` for ``crates`` jobs. The rules read every
release. Scout reads one only when a weak rule hit and ``HUNTER_CRATES_SCOUT``
is on. A checksum mismatch is deferred and the archive is not scanned. Nothing
in the archive is executed.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import tomllib
from pathlib import Path, PurePosixPath

from hunter.archives import (
    BINARY_MARKER,
    BINARY_SUFFIXES,
    ArchiveError,
    DiskTree,
    aligned_release_trees,
    close_trees,
    extract_archive,
)
from hunter.bands import REVIEW_THRESHOLD
from hunter.crates import ECOSYSTEM, download_url, safe_segment, sparse_path, victim_name
from hunter.crates.feed import index_lines
from hunter.models import Classification, ReleaseMeta, RuleReport
from hunter.registry import PACKAGE_DOWNLOAD_MAX_BYTES, FeedError, HttpGet, fetch_capped, parse_time
from hunter.rules.engine import scan_release
from hunter.rules.scope import rust_build_paths
from hunter.triage import added_lines, changed_diffs, unified_diff

log = logging.getLogger("hunter.crates.review")

MODEL_ID = "deterministic"
_templates: dict[str, str] = {}
_INCLUDE = re.compile(r"""include_bytes!\s*\(\s*(?:r#)?(?P<q>["'])(?P<path>.*?)(?P=q)""")
# Each is one reason to read the release. Two of them, or one with a weak hit, route to Triage.
MEDIUM = frozenset(
    {
        "crate_build_rs_changed",
        "crate_proc_macro_new",
        "crate_include_blob",
        "crate_git_dep",
    }
)
_DEP_KEYS = ("dependencies", "dev-dependencies", "build-dependencies")


class ChecksumMismatch(ArchiveError):
    """The downloaded ``.crate`` bytes do not match the index ``cksum``."""


def _json_bytes(blob: bytes | object) -> bytes:
    if isinstance(blob, bytes):
        return blob
    read = getattr(blob, "read_bytes", None)
    if callable(read):
        return read()
    raise FeedError("crates response was not bytes")


def dl_template(config, transport: HttpGet) -> str:
    """``dl`` from the index ``config.json``, or the static CDN template."""
    key = config.crates_index.rstrip("/")
    if key in _templates:
        return _templates[key]
    fallback = f"{config.crates_static.rstrip('/')}/crates/{{crate}}/{{crate}}-{{version}}.crate"
    try:
        data = json.loads(_json_bytes(transport(f"{key}/config.json", 60)).decode("utf-8"))
        if isinstance(data, dict):
            template = str(data.get("dl") or "")
            if template:
                _templates[key] = template
                return template
    except Exception:
        log.warning("crates index config.json unavailable; using the static download URL")
    return fallback


def fetch_index(config, name: str, transport: HttpGet) -> list[dict]:
    url = f"{config.crates_index.rstrip('/')}/{sparse_path(name)}"
    return index_lines(_json_bytes(transport(url, 60)))


def predecessor(lines: list[dict], version: str) -> dict | None:
    """The previous non-yanked line in index order, or None for a first version."""
    index = next((i for i, line in enumerate(lines) if str(line.get("vers") or "") == version), None)
    if index is None:
        return None
    for line in reversed(lines[:index]):
        if not line.get("yanked"):
            return line
    return None


def _line(lines: list[dict], version: str) -> dict | None:
    for line in lines:
        if str(line.get("vers") or "") == version:
            return line
    return None


def _digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _checked_tree(transport: HttpGet, url: str, checksum: str) -> DiskTree:
    archive = fetch_capped(transport, url, 120, PACKAGE_DOWNLOAD_MAX_BYTES)
    try:
        digest = _digest(archive)
        if not checksum or digest.lower() != str(checksum).lower():
            raise ChecksumMismatch("crate checksum mismatch")
        return extract_archive(archive)
    finally:
        archive.unlink(missing_ok=True)


def _toml(text: str) -> dict:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _cargo_files(files) -> list[tuple[str, str]]:
    found = []
    for path, text in files.items():
        if PurePosixPath(str(path)).name.lower() == "cargo.toml":
            found.append((str(path), text if isinstance(text, str) else ""))
    return found


def proc_macro_enabled(text: str) -> bool:
    lib = _toml(text).get("lib") or {}
    if not isinstance(lib, dict):
        return False
    return bool(lib.get("proc-macro"))


def build_script_paths(files) -> set[str]:
    """``build.rs`` plus a ``[package] build`` path, relative to its ``Cargo.toml``."""
    paths: set[str] = set()
    for path, text in _cargo_files(files):
        package = _toml(text).get("package") or {}
        if not isinstance(package, dict):
            continue
        build = package.get("build")
        if not isinstance(build, str) or not build.strip() or build.strip().lower() == "false":
            continue
        rel = build.strip().replace("\\", "/")
        while rel.startswith("./"):
            rel = rel[2:]
        root = PurePosixPath(path).parent
        full = rel if str(root) in {"", "."} else str(root / rel)
        paths.add(full)
    for path in files:
        if PurePosixPath(str(path)).name.lower() == "build.rs":
            paths.add(str(path))
    return paths


def _any_proc(files) -> bool:
    return any(proc_macro_enabled(text) for _path, text in _cargo_files(files))


def _dep_tables(data: dict) -> list[dict]:
    found: list[dict] = []
    for key in _DEP_KEYS:
        block = data.get(key)
        if isinstance(block, dict):
            found.append(block)
    target = data.get("target")
    if isinstance(target, dict):
        for cfg in target.values():
            if not isinstance(cfg, dict):
                continue
            for key in _DEP_KEYS:
                block = cfg.get(key)
                if isinstance(block, dict):
                    found.append(block)
    return found


def _git_or_url(spec: object) -> bool:
    if isinstance(spec, str):
        text = spec.strip().lower()
        return text.startswith(("http://", "https://", "git+", "git://"))
    if isinstance(spec, dict):
        if spec.get("git") or spec.get("url"):
            return True
        registry = spec.get("registry")
        if isinstance(registry, str) and registry.startswith(("http://", "https://")):
            return True
    return False


def _git_deps(files) -> set[str]:
    names: set[str] = set()
    for _path, text in _cargo_files(files):
        for table in _dep_tables(_toml(text)):
            for name, spec in table.items():
                if _git_or_url(spec):
                    names.add(str(name))
    return names


def _added(path: str, old: str, new: str) -> str:
    if not old:
        return new
    return added_lines(unified_diff(path, old, new))


def _binary(path: str, text: str) -> bool:
    if text.startswith(BINARY_MARKER):
        return True
    return PurePosixPath(path).suffix.lower() in BINARY_SUFFIXES


def _include_blob(old_files, new_files) -> bool:
    for path, new in new_files.items():
        if PurePosixPath(str(path)).suffix.lower() != ".rs":
            continue
        if not isinstance(new, str):
            continue
        old = old_files.get(path, "")
        if not isinstance(old, str):
            old = ""
        added = _added(str(path), old, new)
        root = PurePosixPath(str(path)).parent
        for match in _INCLUDE.finditer(added):
            rel = match.group("path").replace("\\", "/")
            while rel.startswith("./"):
                rel = rel[2:]
            target = rel if str(root) in {"", "."} else str(root / rel)
            body = new_files.get(target)
            if isinstance(body, str) and _binary(target, body):
                return True
    return False


def crate_signals(old_files, new_files) -> list[str]:
    """Manifest and archive signals. ``crate_first_version`` is added by the caller."""
    found: list[str] = []
    scripts = build_script_paths(old_files) | build_script_paths(new_files)
    changed = False
    for path in scripts:
        new = new_files.get(path, "")
        old = old_files.get(path, "")
        if isinstance(new, str) and new and new != old:
            changed = True
            break
    if changed:
        found.append("crate_build_rs_changed")
    if _any_proc(new_files) and not _any_proc(old_files):
        found.append("crate_proc_macro_new")
    if _git_deps(new_files) - _git_deps(old_files):
        found.append("crate_git_dep")
    if _include_blob(old_files, new_files):
        found.append("crate_include_blob")
    return found


def routes(signals: list[str], report: RuleReport | None) -> bool:
    """Triage when a weak rule hit, a typosquat, or two medium signals.

    One medium signal does not route, including ``build.rs`` changed next to an
    info rule. ``crate_first_version`` does not route. A weak hit does, on its own.
    """
    if any(item == "typosquat_name" or str(item).startswith("typosquat_name:") for item in signals):
        return True
    weak = report is not None and bool(report.hits)
    if report is not None and report.verdict == "malicious":
        return True
    if weak:
        return True
    medium = [item for item in signals if item in MEDIUM]
    return len(medium) >= 2


def _row(meta: ReleaseMeta, *, band: str, probability: float, signals: list[str]) -> Classification:
    return Classification(
        ecosystem=meta.ecosystem,
        name=meta.name,
        old_version=meta.old_version,
        new_version=meta.new_version,
        rank=meta.rank,
        registry_url=meta.registry_url,
        band=band,
        malice_probability=probability,
        jev_model_id=MODEL_ID,
        signals=signals,
    )


def _attach(row: Classification, report: RuleReport) -> Classification:
    row.rule_verdict = report.verdict
    row.rule_hits = report.hit_dicts()
    row.rule_pack = report.pack_version
    return row


def review_trees(
    meta: ReleaseMeta,
    old_files,
    new_files,
    extra_signals: list[str],
    *,
    jev=None,
    popular_names: set[str] | None = None,
) -> Classification:
    """Rules and crate signals. Scout only when given and a weak rule hit."""
    old_files, new_files = aligned_release_trees(
        old_files,
        new_files,
        ecosystem=meta.ecosystem,
        name=meta.name,
        old_version=meta.old_version,
        new_version=meta.new_version,
    )
    diffs = changed_diffs(old_files, new_files)
    paths = build_script_paths(old_files) | build_script_paths(new_files)
    try:
        with rust_build_paths(paths):
            report = scan_release(old_files, new_files, ecosystem=ECOSYSTEM, diffs=diffs)
    except Exception:
        log.exception("%s %s: rule scan failed", meta.name, meta.new_version)
        report = RuleReport(verdict="unsure", unscanned=[("", "unscanned:rule_error")])
    signals = list(dict.fromkeys(list(extra_signals) + crate_signals(old_files, new_files) + report.signals()))
    for hit in report.info:
        if hit.rule not in signals:
            signals.append(hit.rule)
    if jev is not None and report.hits:
        from hunter.classify import classify_files

        scout = classify_files(
            meta=meta,
            old_files=old_files,
            new_files=new_files,
            jev=jev,
            popular_names=popular_names,
        )
        scout.signals = list(dict.fromkeys(signals + list(scout.signals)))
        if scout.band == "deferred" or scout.defer_reason:
            return scout
        if routes(scout.signals, report):
            scout.needs_llm_review = True
            if scout.band == "benign":
                scout.band = "review"
                scout.malice_probability = max(scout.malice_probability, REVIEW_THRESHOLD)
        scout.rule_verdict = report.verdict
        scout.rule_hits = report.hit_dicts()
        scout.rule_pack = report.pack_version
        return scout
    if routes(signals, report):
        row = _row(meta, band="review", probability=REVIEW_THRESHOLD, signals=signals)
        row.needs_llm_review = True
    else:
        row = _row(meta, band="benign", probability=0.05, signals=signals)
    return _attach(row, report)


def _registry_url(config, name: str, version: str) -> str:
    return f"{config.crates_api.rstrip('/')}/crates/{name}/{version}"


def load_crate_trees(config, transport: HttpGet, name: str, version: str, rank: int | None, previous: str | None):
    """Download ``version`` and ``previous`` (or the index predecessor). Raises on a bad checksum."""
    if not safe_segment(name) or not safe_segment(version):
        raise ArchiveError("unsafe crate name or version")
    if previous is not None and not safe_segment(previous):
        raise ArchiveError("unsafe crate version")
    lines = fetch_index(config, name, transport)
    current = _line(lines, version)
    if current is None:
        raise FeedError(f"crate {name} {version} is not in the index")
    earlier = _line(lines, previous) if previous else predecessor(lines, version)
    resolved = None if earlier is None else str(earlier.get("vers") or "")
    template = dl_template(config, transport)
    new_files = DiskTree.empty()
    old_files = DiskTree.empty()
    try:
        new_files = _checked_tree(
            transport,
            download_url(template, name, version, str(current.get("cksum") or ""), config.crates_static),
            str(current.get("cksum") or ""),
        )
        if resolved and earlier is not None:
            old_files = _checked_tree(
                transport,
                download_url(template, name, resolved, str(earlier.get("cksum") or ""), config.crates_static),
                str(earlier.get("cksum") or ""),
            )
        meta = ReleaseMeta(
            ecosystem=ECOSYSTEM,
            name=name,
            new_version=version,
            old_version=resolved,
            rank=rank,
            registry_url=_registry_url(config, name, version),
            old_time=parse_time(str(earlier.get("pubtime") or "")) if earlier else None,
            new_time=parse_time(str(current.get("pubtime") or "")),
        )
        return old_files, new_files, meta
    except Exception:
        close_trees(old_files, new_files)
        raise


def _defer(meta: ReleaseMeta, *signals: str) -> Classification:
    row = _row(meta, band="deferred", probability=0.0, signals=list(signals))
    row.defer_reason = "crate_checksum_mismatch"
    row.needs_llm_review = False
    return row


def classify_crate(db, config, job, *, transport: HttpGet, jev=None):
    """Download, check, and route one crates job.

    Returns ``(result, old_files, new_files, meta)``. On a checksum mismatch the
    trees are None and the body is not scanned.
    """
    name = str(job["name"]).lower()
    version = str(job["version"])
    rank = job["rank"]
    if not safe_segment(name) or not safe_segment(version):
        raise ArchiveError("unsafe crate name or version")
    lines = fetch_index(config, name, transport)
    current = _line(lines, version)
    if current is None:
        raise FeedError(f"crate {name} {version} is not in the index")
    earlier = predecessor(lines, version)
    resolved = None if earlier is None else str(earlier.get("vers") or "") or None
    meta = ReleaseMeta(
        ecosystem=ECOSYSTEM,
        name=name,
        new_version=version,
        old_version=resolved,
        rank=rank,
        registry_url=_registry_url(config, name, version),
        old_time=parse_time(str(earlier.get("pubtime") or "")) if earlier else None,
        new_time=parse_time(str(current.get("pubtime") or "")),
    )
    extra: list[str] = []
    if current.get("yanked"):
        extra.append("crate_yanked")
    if earlier is None:
        extra.append("crate_first_version")
    watch = {str(key).lower(): int(value) for key, value in db.watch_names(ECOSYSTEM).items()}
    victim = victim_name(name, watch)
    if victim:
        extra.append(f"typosquat_name:{victim}")
    template = dl_template(config, transport)
    new_files = DiskTree.empty()
    old_files = DiskTree.empty()
    try:
        try:
            new_files = _checked_tree(
                transport,
                download_url(template, name, version, str(current.get("cksum") or ""), config.crates_static),
                str(current.get("cksum") or ""),
            )
        except ChecksumMismatch:
            close_trees(new_files)
            return _defer(meta, *extra, "crate_checksum_mismatch"), None, None, meta
        if earlier is not None and resolved:
            try:
                old_files = _checked_tree(
                    transport,
                    download_url(template, name, resolved, str(earlier.get("cksum") or ""), config.crates_static),
                    str(earlier.get("cksum") or ""),
                )
            except ChecksumMismatch:
                close_trees(old_files, new_files)
                return _defer(meta, *extra, "crate_checksum_mismatch"), None, None, meta
        scout = jev if (jev is not None and getattr(config, "crates_scout", False)) else None
        popular = set(watch)
        result = review_trees(meta, old_files, new_files, extra, jev=scout, popular_names=popular)
    except Exception:
        close_trees(old_files, new_files)
        raise
    return result, old_files, new_files, meta
