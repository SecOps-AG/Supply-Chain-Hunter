"""Account-takeover signals from registry metadata, read before Scout.

Only registry JSON is read: no archive is downloaded and no model is called.
Each pending release gets a list of signals and a score. With
HUNTER_TAKEOVER_SIGNALS on, the classify queue takes higher scores first.

Signals:

- ``provenance_lost``: the previous release had a provenance attestation and
  this one has none.
- ``provenance_identity_changed``: both have provenance but the source
  repository or workflow differs.
- ``maintainer_added``: a maintainer or owner that the previous release did
  not list.
- ``publisher_new``: the npm account that published this release never
  published an earlier one.
- ``publisher_email_changed``: the same npm publisher, or the PyPI author and
  maintainer, now use a different email.
- ``dormant_publish``: the previous release is older than the dormant window.
- ``semver_jump``: the major version moved by more than the allowed step.
- ``burst_publish``: many versions published inside a short window.

A metadata read that fails leaves its signal out. An unknown is never a
signal.
"""

from __future__ import annotations

import base64
import json
import logging
import re
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from urllib.parse import quote

from hunter.registry import (
    FeedError,
    HttpGet,
    http_get,
    parse_time,
    predecessor_version,
    pypi_predecessor,
)

log = logging.getLogger("hunter.takeover")

ECOSYSTEMS = ("pypi", "npm")

WEIGHTS: dict[str, int] = {
    "provenance_lost": 40,
    "provenance_identity_changed": 30,
    "publisher_new": 25,
    "maintainer_added": 20,
    "publisher_email_changed": 20,
    "dormant_publish": 15,
    "semver_jump": 10,
    "burst_publish": 10,
}


@dataclass
class TakeoverSignals:
    ecosystem: str
    name: str
    version: str
    old_version: str | None = None
    signals: list[str] = field(default_factory=list)
    detail: dict = field(default_factory=dict)
    error: str = ""

    @property
    def score(self) -> int:
        return sum(WEIGHTS.get(item, 0) for item in self.signals)

    def add(self, signal: str, **detail) -> None:
        if signal not in self.signals:
            self.signals.append(signal)
        if detail:
            self.detail[signal] = detail


@dataclass(frozen=True)
class Thresholds:
    dormant_days: int = 365
    major_jump: int = 2
    burst_count: int = 5
    burst_hours: int = 24

    @classmethod
    def from_config(cls, config) -> Thresholds:
        return cls(
            dormant_days=int(getattr(config, "takeover_dormant_days", cls.dormant_days)),
            major_jump=int(getattr(config, "takeover_major_jump", cls.major_jump)),
            burst_count=int(getattr(config, "takeover_burst_count", cls.burst_count)),
            burst_hours=int(getattr(config, "takeover_burst_hours", cls.burst_hours)),
        )


class _Missing(Exception):
    """The registry answered 404: the document does not exist."""


def _not_found(exc: BaseException) -> bool:
    seen: BaseException | None = exc
    while seen is not None:
        if isinstance(seen, urllib.error.HTTPError) and seen.code == 404:
            return True
        seen = seen.__cause__ or seen.__context__
    return False


def _get_json(transport: HttpGet, url: str, timeout: float = 30.0) -> dict:
    """JSON object at `url`. A 404 raises _Missing; any other failure raises FeedError."""
    try:
        blob = transport(url, timeout)
    except Exception as exc:
        if _not_found(exc):
            raise _Missing(url) from None
        raise FeedError(str(exc)) from exc
    try:
        data = json.loads(bytes(blob).decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise FeedError(f"bad JSON from {url}") from exc
    if not isinstance(data, dict):
        raise FeedError(f"expected a JSON object from {url}")
    return data


# --- shared checks ---------------------------------------------------------

_LEADING_INT = re.compile(r"^\s*v?(\d+)")


def major_of(version: str | None) -> int | None:
    match = _LEADING_INT.match(str(version or ""))
    return int(match.group(1)) if match else None


def check_semver_jump(out: TakeoverSignals, old: str | None, new: str, limit: int) -> None:
    old_major, new_major = major_of(old), major_of(new)
    if old_major is None or new_major is None or limit <= 0:
        return
    if new_major - old_major >= limit:
        out.add("semver_jump", old=old, new=new)


def check_dormant(out: TakeoverSignals, old_time: datetime | None, new_time: datetime | None, days: int) -> None:
    if old_time is None or new_time is None or days <= 0:
        return
    gap = new_time - old_time
    if gap >= timedelta(days=days):
        out.add("dormant_publish", idle_days=gap.days)


def check_burst(out: TakeoverSignals, times: list[datetime], new_time: datetime | None, count: int, hours: int) -> None:
    if new_time is None or count <= 1 or hours <= 0:
        return
    start = new_time - timedelta(hours=hours)
    recent = [stamp for stamp in times if start <= stamp <= new_time]
    if len(recent) >= count:
        out.add("burst_publish", versions=len(recent), hours=hours)


def _email(value) -> str:
    text = str(value or "").strip().lower()
    return text if "@" in text else ""


# --- npm --------------------------------------------------------------------


def _npm_version_times(document: dict) -> dict[str, datetime]:
    found: dict[str, datetime] = {}
    for version, stamp in (document.get("time") or {}).items():
        if version in {"created", "modified"}:
            continue
        moment = parse_time(str(stamp))
        if moment is not None:
            found[str(version)] = moment
    return found


def _npm_people(version_doc: dict) -> set[str]:
    names = set()
    for person in version_doc.get("maintainers") or []:
        if isinstance(person, dict) and person.get("name"):
            names.add(str(person["name"]).strip().lower())
    return names


def _npm_user(version_doc: dict) -> tuple[str, str]:
    user = version_doc.get("_npmUser") or {}
    if not isinstance(user, dict):
        return "", ""
    return str(user.get("name") or "").strip().lower(), _email(user.get("email"))


def _b64(text: str) -> bytes:
    padded = text + "=" * (-len(text) % 4)
    if "-" in padded or "_" in padded:
        return base64.urlsafe_b64decode(padded)
    return base64.b64decode(padded)


def npm_provenance_identity(attestations: dict) -> str | None:
    """Repository and workflow from the SLSA provenance statement, or "" when it has none."""
    for item in attestations.get("attestations") or []:
        if not isinstance(item, dict) or "provenance" not in str(item.get("predicateType") or ""):
            continue
        envelope = (item.get("bundle") or {}).get("dsseEnvelope") or {}
        try:
            statement = json.loads(_b64(str(envelope.get("payload") or "")).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return ""
        predicate = statement.get("predicate") or {} if isinstance(statement, dict) else {}
        build = predicate.get("buildDefinition") or {}
        workflow = (build.get("externalParameters") or {}).get("workflow") or {}
        if isinstance(workflow, dict) and (workflow.get("repository") or workflow.get("path")):
            return f"{workflow.get('repository') or ''}:{workflow.get('path') or ''}".lower()
        return ""
    return None


def _npm_attestation(transport: HttpGet, registry: str, name: str, version: str) -> str | None:
    """Provenance identity ("" when present but unnamed), None when the release has none."""
    url = f"{registry.rstrip('/')}/-/npm/v1/attestations/{quote(name, safe='@')}@{quote(version, safe='')}"
    try:
        document = _get_json(transport, url)
    except _Missing:
        return None
    return npm_provenance_identity(document)


def npm_signals(
    document: dict,
    name: str,
    version: str,
    *,
    transport: HttpGet = http_get,
    registry: str = "https://registry.npmjs.org",
    thresholds: Thresholds = Thresholds(),
) -> TakeoverSignals:
    out = TakeoverSignals("npm", name, version)
    versions = document.get("versions") or {}
    current = versions.get(version) or {}
    times = _npm_version_times(document)
    old = predecessor_version(document, version)
    out.old_version = old
    new_time = times.get(version)
    check_burst(out, list(times.values()), new_time, thresholds.burst_count, thresholds.burst_hours)
    if not old:
        return out
    previous = versions.get(old) or {}
    check_dormant(out, times.get(old), new_time, thresholds.dormant_days)
    check_semver_jump(out, old, version, thresholds.major_jump)

    old_people, new_people = _npm_people(previous), _npm_people(current)
    added = sorted(new_people - old_people)
    if old_people and added:
        out.add("maintainer_added", added=added)

    user, email = _npm_user(current)
    if user:
        earlier = [
            _npm_user(versions.get(other) or {})
            for other, stamp in times.items()
            if other != version and (new_time is None or stamp < new_time)
        ]
        earlier_users = {who for who, _mail in earlier if who}
        if earlier_users and user not in earlier_users:
            out.add("publisher_new", publisher=user)
        old_user, old_email = _npm_user(previous)
        if old_user == user and old_email and email and old_email != email:
            out.add("publisher_email_changed", old=old_email, new=email)

    try:
        old_identity = _npm_attestation(transport, registry, name, old)
        if old_identity is not None:
            new_identity = _npm_attestation(transport, registry, name, version)
            if new_identity is None:
                out.add("provenance_lost", previous=old)
            elif old_identity and new_identity and old_identity != new_identity:
                out.add("provenance_identity_changed", old=old_identity, new=new_identity)
    except FeedError as exc:
        out.error = f"provenance: {exc}"
    return out


# --- PyPI -------------------------------------------------------------------


def _pypi_upload_time(files: list) -> datetime | None:
    stamps = [parse_time(str(item.get("upload_time_iso_8601") or "")) for item in files or [] if isinstance(item, dict)]
    stamps = [stamp for stamp in stamps if stamp is not None]
    return min(stamps) if stamps else None


def _pypi_emails(info: dict) -> set[str]:
    found = set()
    for key in ("author_email", "maintainer_email"):
        for part in str((info or {}).get(key) or "").replace(";", ",").split(","):
            match = re.search(r"[^\s<>\"']+@[^\s<>\"']+", part)
            if match:
                found.add(match.group(0).strip().lower())
    return found


def pypi_owners(info: dict) -> set[str]:
    """Owner and maintainer user names from the JSON API ``ownership`` block."""
    ownership = (info or {}).get("ownership") or {}
    names = set()
    for role in ownership.get("roles") or [] if isinstance(ownership, dict) else []:
        if isinstance(role, dict) and role.get("user"):
            names.add(str(role["user"]).strip().lower())
    return names


def pypi_publisher_identity(provenance: dict) -> str:
    """Trusted-publisher identity (kind, repository, workflow) from an Integrity API answer."""
    names = []
    for bundle in provenance.get("attestation_bundles") or []:
        publisher = (bundle or {}).get("publisher") or {} if isinstance(bundle, dict) else {}
        if not isinstance(publisher, dict):
            continue
        parts = [str(publisher.get(key) or "") for key in ("kind", "repository", "workflow")]
        names.append(":".join(parts).lower())
    return "|".join(sorted(set(names)))


def _integrity_base(pypi_base: str) -> str:
    base = pypi_base.rstrip("/")
    if base.endswith("/pypi"):
        base = base[: -len("/pypi")]
    return f"{base}/integrity"


def _pypi_provenance(transport: HttpGet, pypi_base: str, name: str, version: str, files: list) -> str | None:
    """Publisher identity when any file of the release has provenance, None when none do."""
    for item in files or []:
        filename = str((item or {}).get("filename") or "") if isinstance(item, dict) else ""
        if not filename:
            continue
        url = f"{_integrity_base(pypi_base)}/{quote(name)}/{quote(version)}/{quote(filename)}/provenance"
        try:
            document = _get_json(transport, url)
        except _Missing:
            continue
        return pypi_publisher_identity(document)
    return None


def pypi_signals(
    document: dict,
    name: str,
    version: str,
    *,
    transport: HttpGet = http_get,
    pypi_base: str = "https://pypi.org/pypi",
    previous_owners: set[str] | None = None,
    thresholds: Thresholds = Thresholds(),
) -> TakeoverSignals:
    """`previous_owners` is the owner set recorded for an earlier release of this project."""
    out = TakeoverSignals("pypi", name, version)
    releases = document.get("releases") or {}
    new_files = releases.get(version) or []
    new_time = _pypi_upload_time(new_files)
    times = [stamp for stamp in (_pypi_upload_time(files) for files in releases.values()) if stamp is not None]
    check_burst(out, times, new_time, thresholds.burst_count, thresholds.burst_hours)

    owners = pypi_owners(document.get("info") or {})
    out.detail["owners"] = sorted(owners)
    added = sorted(owners - (previous_owners or set()))
    if previous_owners and added:
        out.add("maintainer_added", added=added)

    old = pypi_predecessor(document, version)
    out.old_version = old
    if not old:
        return out
    old_files = releases.get(old) or []
    check_dormant(out, _pypi_upload_time(old_files), new_time, thresholds.dormant_days)
    check_semver_jump(out, old, version, thresholds.major_jump)

    base = pypi_base.rstrip("/")
    try:
        old_info = _get_json(transport, f"{base}/{quote(name)}/{quote(old)}/json").get("info") or {}
        new_info = _get_json(transport, f"{base}/{quote(name)}/{quote(version)}/json").get("info") or {}
        old_emails, new_emails = _pypi_emails(old_info), _pypi_emails(new_info)
        if old_emails and new_emails and not old_emails & new_emails:
            out.add("publisher_email_changed", old=sorted(old_emails), new=sorted(new_emails))
    except (FeedError, _Missing) as exc:
        out.error = f"metadata: {exc}"

    try:
        old_identity = _pypi_provenance(transport, pypi_base, name, old, old_files)
        if old_identity is not None:
            new_identity = _pypi_provenance(transport, pypi_base, name, version, new_files)
            if new_identity is None:
                out.add("provenance_lost", previous=old)
            elif old_identity and new_identity and old_identity != new_identity:
                out.add("provenance_identity_changed", old=old_identity, new=new_identity)
    except FeedError as exc:
        out.error = "; ".join(item for item in (out.error, f"provenance: {exc}") if item)
    return out


# --- queue ------------------------------------------------------------------


def release_signals(db, config, ecosystem: str, name: str, version: str, transport: HttpGet = http_get) -> TakeoverSignals:
    thresholds = Thresholds.from_config(config)
    try:
        if ecosystem == "npm":
            document = _get_json(transport, f"{config.npm_registry.rstrip('/')}/{quote(name, safe='@')}")
            return npm_signals(
                document,
                name,
                version,
                transport=transport,
                registry=config.npm_registry,
                thresholds=thresholds,
            )
        document = _get_json(transport, f"{config.pypi_base.rstrip('/')}/{quote(name)}/json")
        previous = db.last_takeover_owners(ecosystem, name, exclude_version=version)
        return pypi_signals(
            document,
            name,
            version,
            transport=transport,
            pypi_base=config.pypi_base,
            previous_owners=previous,
            thresholds=thresholds,
        )
    except (FeedError, _Missing) as exc:
        return TakeoverSignals(ecosystem, name, version, error=f"metadata: {exc}")


def score_pending_jobs(db, config, transport: HttpGet = http_get, limit: int | None = None) -> int:
    """Record signals for pending npm and PyPI jobs that have none yet. Returns how many were scored."""
    batch = config.takeover_batch if limit is None else limit
    jobs = db.unscored_pending_jobs(ECOSYSTEMS, limit=max(0, batch))
    for job in jobs:
        ecosystem, name, version = str(job["ecosystem"]), str(job["name"]), str(job["version"])
        try:
            found = release_signals(db, config, ecosystem, name, version, transport)
        except Exception as exc:  # one bad document must not stop the queue
            log.exception("takeover signals failed %s %s %s", ecosystem, name, version)
            found = TakeoverSignals(ecosystem, name, version, error=str(exc) or type(exc).__name__)
        db.save_takeover_signals(
            ecosystem,
            name,
            version,
            found.score,
            found.signals,
            found.detail,
            old_version=found.old_version,
            error=found.error,
        )
        if found.signals:
            log.info(
                "takeover signals %s %s %s -> %s score=%s signals=%s",
                ecosystem,
                name,
                found.old_version or "-",
                version,
                found.score,
                ",".join(found.signals),
            )
    return len(jobs)
