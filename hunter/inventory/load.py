"""Find watchlist files on disk, read them with a size cap, and store what they list.

The walk never follows a symlink, never leaves the root it was given, and skips
dependency and build folders. Files are read as bytes and decoded as UTF-8 with
replacement; nothing in them is run. Logs carry paths, formats and counts only.
"""

from __future__ import annotations

import fnmatch
import json
import logging
import os
import stat
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath

from hunter.db import Database, iso, utcnow
from hunter.inventory.parsers import FormatError, parse
from hunter.registry import parse_time

log = logging.getLogger("hunter.inventory")

REFRESH_CHECKPOINT = "user-watch-refresh"
# Labels the last config refresh stored, so a file that disappeared from disk drops its rows.
CONFIG_SOURCES_CHECKPOINT = "user-watch-config-sources"
SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "site-packages", "dist", "build", "vendor"}
EXACT_NAMES = {
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "package.json",
    "poetry.lock",
    "uv.lock",
    "pipfile.lock",
    "gemfile.lock",
    "cargo.lock",
    "bom.json",
    "action.yml",
    "action.yaml",
}
NAME_PATTERNS = ("requirements*.txt", "*.cdx.json", "*.spdx.json", "sbom*.json")
DEFAULT_MAX_BYTES = 20 * 1024 * 1024
DEFAULT_MAX_FILES = 2000


@dataclass
class FileReport:
    path: str
    source: str
    format: str | None = None
    components: int = 0
    skipped: int = 0
    warnings: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class ImportReport:
    files: list[FileReport] = field(default_factory=list)
    partial: bool = False
    dry_run: bool = False
    new_names: list[tuple[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def components(self) -> int:
        return sum(item.components for item in self.files)

    def to_dict(self) -> dict:
        return {
            "files": [asdict(item) for item in self.files],
            "partial": self.partial,
            "dry_run": self.dry_run,
            "components": self.components,
            "new_names": [list(pair) for pair in self.new_names],
            "warnings": list(self.warnings),
        }


def wanted(relative: PurePosixPath) -> bool:
    """True for a file name the directory walk imports."""
    name = relative.name.lower()
    if name in EXACT_NAMES or any(fnmatch.fnmatch(name, pattern) for pattern in NAME_PATTERNS):
        return True
    parent = relative.parent.as_posix().lower()
    return name.endswith((".yml", ".yaml")) and (parent == ".github/workflows" or parent.endswith("/.github/workflows"))


def discover(root: str | Path, max_files: int = DEFAULT_MAX_FILES) -> tuple[list[Path], bool]:
    """Watchlist files under ``root``, sorted. Returns (files, partial); partial means the cap was hit.

    A root that is a regular file is returned as is. Symlinks are never followed.
    """
    base = Path(root)
    try:
        info = os.lstat(base)
    except OSError:
        return [], False
    if stat.S_ISLNK(info.st_mode):
        return [], False
    if stat.S_ISREG(info.st_mode):
        return [base], False
    if not stat.S_ISDIR(info.st_mode):
        return [], False
    found: list[Path] = []
    for current, dirnames, filenames in os.walk(base, followlinks=False):
        here = Path(current)
        dirnames[:] = sorted(
            name for name in dirnames if name.lower() not in SKIP_DIRS and not (here / name).is_symlink()
        )
        for name in sorted(filenames):
            path = here / name
            if path.is_symlink():
                continue
            if not wanted(PurePosixPath(path.relative_to(base).as_posix())):
                continue
            if len(found) >= max(1, int(max_files)):
                return found, True
            found.append(path)
    return found, False


def read_capped(path: str | Path, max_bytes: int = DEFAULT_MAX_BYTES) -> str | None:
    """File text, or None when it is a symlink, not a regular file, or larger than ``max_bytes``."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        handle = os.open(path, flags)
    except OSError:
        return None
    try:
        info = os.fstat(handle)
        if not stat.S_ISREG(info.st_mode) or info.st_size > max_bytes:
            return None
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(handle, min(1024 * 1024, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                return None
    finally:
        os.close(handle)
    return b"".join(chunks).decode("utf-8", errors="replace")


def _label(prefix: str, relative: str) -> str:
    return f"{prefix.rstrip('/')}/{relative}" if prefix else relative


def _rows(result) -> list[tuple[str, str, str, int | None]]:
    return [(item.ecosystem, item.name, item.version, item.direct) for item in result.components]


def _import_text(
    db: Database,
    report: ImportReport,
    text: str | None,
    *,
    path: str,
    label: str,
    filename: str,
    fmt: str | None,
    dry_run: bool,
    max_bytes: int,
) -> None:
    item = FileReport(path=path, source=label)
    report.files.append(item)
    if text is None:
        item.error = f"skipped: over the {max_bytes // (1024 * 1024) or 1} MB cap, a symlink, or unreadable"
        log.warning("watchlist file skipped: %s", path)
        return
    try:
        result = parse(text, filename, fmt)
    except FormatError as exc:
        item.error = str(exc)
        log.info("watchlist file not imported: %s (%s)", path, exc)
        return
    except Exception as exc:
        item.error = f"could not parse ({exc.__class__.__name__})"
        log.warning("watchlist file could not be parsed: %s (%s)", path, exc.__class__.__name__)
        return
    item.format = result.format
    item.components = len(result.components)
    item.skipped = result.skipped
    item.warnings = list(result.warnings)
    if not dry_run:
        report.new_names.extend(db.replace_user_watch_source(label, result.format, _rows(result), result.skipped))
    log.info("watchlist %s: %s, %d components, %d skipped", path, result.format, item.components, item.skipped)


def import_paths(
    db: Database,
    paths: list[str],
    *,
    source: str | None = None,
    fmt: str | None = None,
    dry_run: bool = False,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_files: int = DEFAULT_MAX_FILES,
    prefix_roots: bool | None = None,
    stdin=None,
) -> ImportReport:
    """Import files, directories (walked) or ``-`` (stdin; needs ``fmt``).

    Labels: a directory's files are labeled by their path relative to it, and a
    file argument by the path as given. ``source`` prefixes every label. With no
    ``source`` and more than one path (or ``prefix_roots``), a directory's labels
    are prefixed with the directory as given so two roots cannot collide.
    """
    report = ImportReport(dry_run=dry_run)
    if prefix_roots is None:
        prefix_roots = len(paths) > 1
    for raw in paths:
        if raw == "-":
            if not fmt:
                report.warnings.append("stdin needs --format")
                report.files.append(FileReport(path="-", source=source or "stdin", error="stdin needs --format"))
                continue
            stream = stdin if stdin is not None else sys.stdin
            text = stream.read(max_bytes + 1)
            if len(text) > max_bytes:
                text = None
            _import_text(
                db, report, text, path="-", label=source or "stdin", filename="", fmt=fmt,
                dry_run=dry_run, max_bytes=max_bytes,
            )
            continue
        root = Path(raw)
        typed = PurePosixPath(raw.replace("\\", "/")).as_posix()
        try:
            is_dir = root.is_dir() and not root.is_symlink()
        except OSError:
            is_dir = False
        files, partial = discover(root, max_files)
        if not files:
            message = f"{raw}: not found, a symlink, or holds no watchlist files"
            report.warnings.append(message)
            log.warning("watchlist path has nothing to import: %s", raw)
            continue
        if partial:
            report.partial = True
            report.warnings.append(f"{raw}: stopped at {max_files} files; the import is partial")
        for path in files:
            if is_dir:
                relative = path.relative_to(root).as_posix()
                prefix = source or (typed if prefix_roots else "")
                label = _label(prefix, relative)
            else:
                label = _label(source, path.name) if source else typed
            _import_text(
                db, report, read_capped(path, max_bytes), path=str(path), label=label, filename=str(path),
                fmt=fmt, dry_run=dry_run, max_bytes=max_bytes,
            )
    if not dry_run and report.new_names:
        prime_new_names(db, report.new_names)
    return report


def _poll_cutoff(stamp: str) -> str:
    """Registry version times include fractional seconds. Poll times do not."""
    text = str(stamp)
    if text.endswith("Z") and "." not in text:
        return text[:-1] + ".000Z"
    return text


def prime_new_names(db: Database, new_pairs: list[tuple[str, str]]) -> int:
    """Move an old npm cursor up to the last npm poll for names just added. Returns cursors moved.

    A name removed and added again keeps its old cursor; without this the next
    poll would queue every version published while it was off the list.
    """
    last = db.last_poll().get("npm")
    if not last:
        return 0
    cutoff = _poll_cutoff(str(last))
    cutoff_time = parse_time(cutoff)
    moved = 0
    for ecosystem, name in new_pairs:
        if ecosystem != "npm":
            continue
        version, last_time = db.get_package_cursor("npm", name)
        if not last_time:
            continue
        stored = parse_time(str(last_time))
        if stored is not None and cutoff_time is not None and stored >= cutoff_time:
            continue
        db.set_package_cursor("npm", name, version, cutoff)
        moved += 1
    return moved


def refresh_due(db: Database, config, now=None) -> bool:
    if not getattr(config, "watchlist_paths", ()):
        return False
    stamp = db.get_checkpoint(REFRESH_CHECKPOINT)
    parsed = parse_time(stamp) if stamp else None
    moment = now or utcnow()
    return parsed is None or (moment - parsed).total_seconds() >= float(config.watchlist_refresh)


def refresh_from_config(db: Database, config, now=None) -> ImportReport:
    """Re-import every ``HUNTER_WATCHLIST_PATHS`` entry. Labels are prefixed with the path as configured.

    A source this refresh stored last time but did not see now is removed, unless
    its root was missing or the walk stopped at the file cap.
    """
    moment = now or utcnow()
    paths = list(getattr(config, "watchlist_paths", ()))
    report = import_paths(
        db,
        paths,
        prefix_roots=True,
        max_bytes=int(getattr(config, "watchlist_max_file_bytes", DEFAULT_MAX_BYTES)),
        max_files=int(getattr(config, "watchlist_max_files", DEFAULT_MAX_FILES)),
    )
    seen = {item.source for item in report.files}
    complete_roots = [
        PurePosixPath(raw.replace("\\", "/")).as_posix()
        for raw in paths
        if Path(raw).exists() and not report.partial
    ]
    try:
        previous = json.loads(db.get_checkpoint(CONFIG_SOURCES_CHECKPOINT) or "[]")
    except ValueError:
        previous = []
    kept = set(seen)
    for label in previous if isinstance(previous, list) else []:
        label = str(label)
        if label in seen:
            continue
        if any(label == root or label.startswith(f"{root}/") for root in complete_roots):
            db.remove_user_watch_source(label)
            log.info("watchlist source no longer on disk; removed: %s", label)
        else:
            kept.add(label)
    db.set_checkpoint(CONFIG_SOURCES_CHECKPOINT, json.dumps(sorted(kept)), when=moment)
    db.set_checkpoint(REFRESH_CHECKPOINT, iso(moment), when=moment)
    return report
