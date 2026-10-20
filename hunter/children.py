"""Inspect newly added runtime dependencies. Registry HTTP only; nothing is installed."""

from __future__ import annotations

import http.client
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from hunter.archives import ArchiveError, DiskTree, close_trees, extract_archive
from hunter.classify import classify_files
from hunter.features import runtime_dependency_specs, suspicious_install_command
from hunter.models import Classification, ReleaseMeta
from hunter.registry import DownloadTooLarge, FeedError, fetch_capped, predecessor_version, publishers_npm, parse_time

MAX_CHILDREN = 3
MAX_ARCHIVE_BYTES = 8_000_000
_VERSION = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)")


@dataclass
class ChildFinding:
    name: str
    spec: str
    resolved_version: str | None = None
    previous_version: str | None = None
    band: str | None = None
    malice_probability: float | None = None
    install_hook: bool = False
    young: bool = False
    missing_git_head: bool = False
    missing_provenance: bool = False
    same_day: bool = False
    error: str | None = None
    signals: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "spec": self.spec,
            "resolved_version": self.resolved_version,
            "previous_version": self.previous_version,
            "band": self.band,
            "malice_probability": self.malice_probability,
            "install_hook": self.install_hook,
            "young": self.young,
            "missing_git_head": self.missing_git_head,
            "missing_provenance": self.missing_provenance,
            "same_day": self.same_day,
            "error": self.error,
            "signals": list(self.signals),
        }


def parse_version(text: str) -> tuple[int, int, int] | None:
    match = _VERSION.match(text.strip())
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def resolve_spec(versions: list[str], spec: str, latest: str | None) -> str | None:
    spec = (spec or "").strip()
    parsed = [(key, version) for version in versions if (key := parse_version(version))]
    parsed.sort()
    if not spec or spec in {"*", "latest", "x"}:
        return latest or (parsed[-1][1] if parsed else None)
    if spec.startswith("^") or spec.startswith("~"):
        floor = parse_version(spec[1:])
        if floor is None:
            return latest
        if spec.startswith("^"):
            chosen = [version for key, version in parsed if key >= floor and key[0] == floor[0]]
        else:
            chosen = [version for key, version in parsed if key >= floor and key[:2] == floor[:2]]
        return chosen[-1] if chosen else None
    exact = parse_version(spec)
    for key, version in parsed:
        if version == spec or key == exact:
            return version
    if spec in versions:
        return spec
    return None


def _version_scripts(document: dict) -> dict[str, str]:
    scripts = document.get("scripts") or {}
    if not isinstance(scripts, dict):
        return {}
    return {str(key): str(value or "") for key, value in scripts.items()}


def _young(document: dict, resolved: str, parent_time: datetime | None) -> bool:
    versions = document.get("versions") or {}
    if len(versions) <= 3:
        return True
    times = document.get("time") or {}
    created = parse_time(times.get("created"))
    published = parse_time(times.get(resolved))
    if created and published and (published - created) <= timedelta(days=14):
        return True
    if parent_time and published:
        return abs((published - parent_time).total_seconds()) <= 24 * 3600
    return False


def _same_day(parent_time: datetime | None, stamp: datetime | None) -> bool:
    if parent_time is None or stamp is None:
        return False
    left = parent_time.astimezone(timezone.utc).date()
    right = stamp.astimezone(timezone.utc).date()
    return left == right


def inspect_children(
    meta: ReleaseMeta,
    new_files: dict[str, str],
    names: list[str],
    *,
    jev,
    transport,
    registry: str,
    limit: int = MAX_CHILDREN,
    max_bytes: int = MAX_ARCHIVE_BYTES,
) -> list[ChildFinding]:
    specs = runtime_dependency_specs(new_files)
    findings: list[ChildFinding] = []
    for name in names[: max(0, limit)]:
        findings.append(
            _one(
                meta,
                name,
                specs.get(name, ""),
                jev=jev,
                transport=transport,
                registry=registry,
                max_bytes=max_bytes,
            )
        )
    return findings


def _one(meta, name, spec, *, jev, transport, registry, max_bytes) -> ChildFinding:
    finding = ChildFinding(name=name, spec=spec)
    try:
        document = _json(transport(f"{registry.rstrip('/')}/{quote(name, safe='')}", 30))
    except (FeedError, OSError, ValueError, http.client.HTTPException) as exc:
        finding.error = str(exc)
        return finding
    versions = document.get("versions") or {}
    latest = (document.get("dist-tags") or {}).get("latest")
    resolved = resolve_spec(list(versions), spec, str(latest) if latest else None)
    if not resolved or resolved not in versions:
        finding.error = "unresolved version"
        return finding
    current = versions[resolved] or {}
    finding.resolved_version = resolved
    finding.previous_version = predecessor_version(document, resolved)
    scripts = _version_scripts(current)
    hook = scripts.get("postinstall") or scripts.get("preinstall") or scripts.get("install") or ""
    finding.install_hook = suspicious_install_command(hook)
    published = parse_time((document.get("time") or {}).get(resolved))
    finding.young = _young(document, resolved, meta.new_time)
    finding.same_day = _same_day(meta.new_time, published)
    finding.missing_git_head = not bool(current.get("gitHead"))
    dist = current.get("dist") or {}
    finding.missing_provenance = not bool(dist.get("attestations") or dist.get("signatures"))
    if finding.install_hook:
        finding.signals.append("child_install_hook")
    if finding.young:
        finding.signals.append("child_young")
    if finding.missing_git_head:
        finding.signals.append("child_missing_git_head")
    if finding.missing_provenance:
        finding.signals.append("child_missing_provenance")
    if finding.same_day:
        finding.signals.append("child_same_day")
    old_files = None
    child_files = None
    try:
        try:
            old_files, child_files, child_meta = _load_pair(
                document, name, resolved, finding.previous_version, meta, transport, max_bytes
            )
            child = classify_files(meta=child_meta, old_files=old_files, new_files=child_files, jev=jev)
        except (FeedError, ArchiveError, OSError, ValueError, http.client.HTTPException) as exc:
            finding.error = str(exc)
            finding.signals.append("child_body_unavailable")
            return finding
    finally:
        close_trees(old_files, child_files)
    finding.band = child.band
    finding.malice_probability = child.malice_probability
    finding.signals.extend(child.signals[:16])
    if child.band == "alert" or "compound_install_payload" in child.signals or "static_rule" in child.signals:
        finding.install_hook = True
    return finding


def _json(blob: bytes) -> dict:
    import json

    data = json.loads(blob.decode("utf-8"))
    if not isinstance(data, dict):
        raise FeedError("expected a JSON object")
    return data


def _capped_archive(transport, url: str, max_bytes: int):
    try:
        return fetch_capped(transport, url, 30, max_bytes)
    except DownloadTooLarge as exc:
        raise ArchiveError("archive exceeds inspection byte cap") from exc


def _extract_capped(transport, url: str, max_bytes: int) -> DiskTree:
    archive = _capped_archive(transport, url, max_bytes)
    try:
        return extract_archive(archive)
    finally:
        archive.unlink(missing_ok=True)


def _load_pair(document, name, version, previous, parent: ReleaseMeta, transport, max_bytes):
    versions = document.get("versions") or {}
    current = versions.get(version) or {}
    tarball = (current.get("dist") or {}).get("tarball")
    if not tarball:
        raise ArchiveError(f"no tarball for {name} {version}")
    new_files = DiskTree.empty()
    old_files: DiskTree = DiskTree.empty()
    try:
        new_files = _extract_capped(transport, str(tarball), max_bytes)
        if previous:
            earlier = (versions.get(previous) or {}).get("dist") or {}
            if earlier.get("tarball"):
                try:
                    old_files = _extract_capped(transport, str(earlier["tarball"]), max_bytes)
                except ArchiveError:
                    old_files = DiskTree.empty()
        child_meta = ReleaseMeta(
            ecosystem="npm",
            name=name,
            new_version=version,
            old_version=previous,
            rank=parent.rank,
            registry_url=f"https://www.npmjs.com/package/{name}/v/{version}",
            old_publishers=publishers_npm(versions.get(previous) or {}) if previous else frozenset(),
            new_publishers=publishers_npm(current),
            new_time=parse_time((document.get("time") or {}).get(version)),
            old_time=parse_time((document.get("time") or {}).get(previous or "")),
        )
        return old_files, new_files, child_meta
    except Exception:
        close_trees(old_files, new_files)
        raise


def apply_children(parent: Classification, findings: list[ChildFinding]) -> Classification:
    """Promote a parent when a new dependency's own install hook or verdict is hostile."""
    confirmed = False
    for finding in findings:
        parent.child_findings.append(finding.as_dict())
        if finding.error and finding.band is None and not finding.install_hook:
            parent.signals.append(f"child_unavailable:{finding.name}")
            continue
        if finding.resolved_version:
            parent.signals.append(f"child:{finding.name}@{finding.resolved_version}:{finding.band or 'unknown'}")
        parent.signals.extend(signal for signal in finding.signals if signal.startswith("child_"))
        hostile = finding.install_hook or finding.band == "alert"
        if hostile:
            confirmed = True
            parent.signals.append(f"child_alert:{finding.name}@{finding.resolved_version or finding.spec}")
    if confirmed:
        parent.band = "alert"
        parent.malice_probability = round(max(parent.malice_probability, 0.86), 4)
        if parent.attack_family in ("", "none", "other"):
            parent.attack_family = "dependency_abuse"
            parent.subtype = parent.subtype or "new_unrelated"
        if parent.subtype is None:
            parent.subtype = "new_unrelated"
    return parent
