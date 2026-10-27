"""Turn lockfile, manifest, SBOM, plain-list and workflow text into components.

Parse only: ``json.loads``, ``tomllib.loads``, ``yaml.safe_load`` and line
scanning. No file named here is run, imported or resolved, and a version range
is stored as an empty version rather than guessed.

The format is detected from the content first. The filename only breaks ties.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import PurePath

from hunter.actions import ECOSYSTEM as ACTIONS_ECOSYSTEM
from hunter.actions import normalize_name as normalize_action_name
from hunter.actions.manifest import uses_refs
from hunter.inventory import Component, clean_version, component, ecosystem_alias
from hunter.inventory.purl import parse_purl

FORMATS = (
    "npm-lock",
    "yarn-lock",
    "pnpm-lock",
    "package-json",
    "requirements",
    "toml-lock",
    "pipfile-lock",
    "cyclonedx",
    "spdx",
    "plain",
    "workflow",
)
FORMAT_HELP = {
    "npm-lock": "package-lock.json / npm-shrinkwrap.json (lockfile v1, v2, v3)",
    "yarn-lock": "yarn.lock (classic and berry)",
    "pnpm-lock": "pnpm-lock.yaml (v5, v6, v9)",
    "package-json": "package.json dependency maps; only exact pins keep a version",
    "requirements": "requirements*.txt; only == and === pins keep a version",
    "toml-lock": "poetry.lock and uv.lock",
    "pipfile-lock": "Pipfile.lock",
    "cyclonedx": "CycloneDX JSON SBOM (component purls)",
    "spdx": "SPDX JSON SBOM (purl external references)",
    "plain": "one package per line: '<eco> <name> [version]', '<eco>:<name>[@version]' or a pkg: purl",
    "workflow": "GitHub workflow or action.yml 'uses:' lines",
}

NPM_DEP_MAPS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
PNPM_DEP_MAPS = ("dependencies", "devDependencies", "optionalDependencies")
_LOCAL_SPECS = ("workspace:", "link:", "file:", "portal:", "patch:", "exec:")
_REMOTE_SPECS = ("git:", "git+", "github:", "gitlab:", "bitbucket:", "http:", "https:")
_EXACT_SEMVER = re.compile(r"^[=v]?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$")
_REQ_NAME = r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?"
_REQ_OP = r"(?:===|==|~=|!=|<=|>=|<|>)"
_REQ_LINE = re.compile(
    rf"^({_REQ_NAME})\s*(\[[^\]]*\])?\s*"
    rf"({_REQ_OP}\s*[^\s,;]+(?:\s*,\s*{_REQ_OP}\s*[^\s,;]+)*)?\s*(?:;.*)?$"
)
_REQ_URL = re.compile(rf"^({_REQ_NAME})\s*(\[[^\]]*\])?\s*@\s*\S+")
_REQ_PIN = re.compile(r"^(?:===|==)\s*([^\s,;*]+)$")
_PLAIN_SPACED = re.compile(r"^([A-Za-z][A-Za-z-]*)\s+(\S+)(?:\s+(\S+))?$")
_PLAIN_COLON = re.compile(r"^([A-Za-z][A-Za-z-]*):(\S+)$")
_TOML_PACKAGE = re.compile(r"^\[\[package\]\]\s*$", re.MULTILINE)
_PNPM_LOCK = re.compile(r"^lockfileVersion\s*:", re.MULTILINE)
_YARN_BERRY = re.compile(r"^__metadata:\s*$", re.MULTILINE)
_COMMENT = re.compile(r"(^|\s)#.*$")


class FormatError(ValueError):
    """The text is not in the requested or any known format. Never carries file text."""


@dataclass
class ParseResult:
    format: str
    components: list[Component] = field(default_factory=list)
    skipped: int = 0
    warnings: list[str] = field(default_factory=list)


class _Collector:
    """Components in first-seen order, one per (ecosystem, name, version). A direct flag wins."""

    def __init__(self, fmt: str):
        self.result = ParseResult(fmt)
        self._index: dict[tuple[str, str, str], int] = {}

    def add(self, found: Component | None) -> None:
        if found is None:
            self.result.skipped += 1
            return
        key = (found.ecosystem, found.name, found.version)
        at = self._index.get(key)
        if at is None:
            self._index[key] = len(self.result.components)
            self.result.components.append(found)
            return
        kept = self.result.components[at]
        flags = [flag for flag in (kept.direct, found.direct) if flag is not None]
        direct = max(flags) if flags else None
        if direct != kept.direct:
            self.result.components[at] = Component(kept.ecosystem, kept.name, kept.version, direct)

    def skip(self, count: int = 1) -> None:
        self.result.skipped += count

    def warn(self, message: str) -> None:
        if message not in self.result.warnings:
            self.result.warnings.append(message)


def _json_object(text: str) -> dict | None:
    stripped = text.lstrip("﻿ \t\r\n")
    if not stripped.startswith("{"):
        return None
    try:
        data = json.loads(stripped)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _strict_json(text: str, fmt: str) -> dict:
    data = _json_object(text)
    if data is None:
        raise FormatError(f"not a JSON object; cannot read as {fmt}")
    return data


def _npm_alias(spec: str) -> tuple[str, str] | None:
    """``npm:real@range`` -> (``real``, ``range``)."""
    rest = spec[len("npm:") :]
    at = rest.find("@", 1)
    if at < 0:
        return rest, ""
    return rest[:at], rest[at + 1 :]


def _exact_pin(spec: str) -> str:
    match = _EXACT_SEMVER.match((spec or "").strip())
    return match.group(1) if match else ""


def _local_or_remote(spec: str) -> bool:
    lowered = (spec or "").strip().lower()
    if lowered.startswith(_LOCAL_SPECS) or lowered.startswith(_REMOTE_SPECS) or "://" in lowered:
        return True
    # GitHub shorthand such as "user/repo#ref", and local paths.
    return "/" in lowered or lowered.startswith((".", "~"))


# --- npm ---------------------------------------------------------------------


def _npm_root_deps(root: dict) -> set[str]:
    found: set[str] = set()
    for key in NPM_DEP_MAPS:
        deps = root.get(key)
        if isinstance(deps, dict):
            found.update(str(name) for name in deps)
    return found


def _npm_lock_version(raw: object) -> tuple[str, str | None]:
    """(version, real name for an alias). An unusable version comes back as ''."""
    text = str(raw or "").strip()
    if text.startswith("npm:"):
        alias = _npm_alias(text)
        if alias is not None:
            return clean_version(alias[1]), alias[0]
    if not text or ":" in text or "/" in text:
        return "", None
    return clean_version(text), None


def parse_npm_lock(text: str) -> ParseResult:
    data = _strict_json(text, "npm-lock")
    out = _Collector("npm-lock")
    packages = data.get("packages")
    if isinstance(packages, dict) and packages:
        root = packages.get("") if isinstance(packages.get(""), dict) else {}
        direct_names = _npm_root_deps(root)
        for key, entry in packages.items():
            if key == "" or not isinstance(entry, dict):
                continue
            if entry.get("link") or "node_modules/" not in key:
                # Workspace folders and links point at local code, not a registry package.
                out.skip()
                continue
            installed = key.rsplit("node_modules/", 1)[1]
            version, alias_name = _npm_lock_version(entry.get("version"))
            name = entry.get("name") if isinstance(entry.get("name"), str) else alias_name or installed
            resolved = str(entry.get("resolved") or "")
            if resolved.startswith(("file:", "git+", "git:", "github:")):
                out.skip()
                continue
            direct = 1 if key == f"node_modules/{installed}" and installed in direct_names else 0
            out.add(component("npm", name, version, direct))
        return out.result
    dependencies = data.get("dependencies")
    if isinstance(dependencies, dict):
        # Lockfile v1 records the tree but not what the root package.json asked for.
        stack = [dependencies]
        seen = 0
        while stack and seen < 200_000:
            level = stack.pop()
            for name, entry in level.items():
                seen += 1
                if not isinstance(entry, dict):
                    out.skip()
                    continue
                raw = str(entry.get("version") or "")
                if raw.startswith(("file:", "link:", "git", "http")):
                    out.skip()
                else:
                    version, alias_name = _npm_lock_version(raw)
                    out.add(component("npm", alias_name or str(name), version, None))
                nested = entry.get("dependencies")
                if isinstance(nested, dict):
                    stack.append(nested)
    return out.result


def parse_package_json(text: str) -> ParseResult:
    data = _strict_json(text, "package-json")
    out = _Collector("package-json")
    for key in NPM_DEP_MAPS:
        deps = data.get(key)
        if not isinstance(deps, dict):
            continue
        for name, raw in deps.items():
            spec = str(raw if isinstance(raw, str) else "").strip()
            real = str(name)
            if spec.startswith("npm:"):
                alias = _npm_alias(spec)
                if alias is None:
                    out.skip()
                    continue
                real, spec = alias
            elif _local_or_remote(spec):
                out.skip()
                continue
            out.add(component("npm", real, _exact_pin(spec), 1))
    return out.result


def _yarn_header_spec(line: str) -> str:
    header = line.rstrip()[:-1]
    return header.split(",", 1)[0].strip().strip('"').strip("'").strip()


def parse_yarn_lock(text: str) -> ParseResult:
    out = _Collector("yarn-lock")
    current: tuple[str, str] | None = None
    pending_version = False

    def finish():
        if current is not None and pending_version:
            out.add(component("npm", current[0], "", None))

    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            finish()
            current, pending_version = None, False
            if not line.rstrip().endswith(":"):
                continue
            spec = _yarn_header_spec(line)
            if spec == "__metadata":
                continue
            at = spec.find("@", 1)
            if at <= 0:
                out.skip()
                continue
            name, rest = spec[:at], spec[at + 1 :]
            if rest.startswith("npm:"):
                alias = _npm_alias(rest)
                if alias is not None and alias[0] and "@" not in alias[0][1:] and alias[1]:
                    name = alias[0]
                rest = rest[len("npm:") :]
            if rest.lower().startswith(_LOCAL_SPECS) or rest.lower().startswith(_REMOTE_SPECS) or "://" in rest:
                out.skip()
                continue
            current, pending_version = (name, rest), True
            continue
        if current is None or not pending_version:
            continue
        stripped = line.strip()
        if stripped.startswith("version"):
            value = stripped[len("version") :].lstrip(":").strip().strip('"').strip("'")
            out.add(component("npm", current[0], value, None))
            pending_version = False
    finish()
    return out.result


def _pnpm_key(key: str, legacy: bool) -> tuple[str, str] | None:
    text = key[1:] if key.startswith("/") else key
    text = text.split("(", 1)[0]
    if legacy:
        name, _sep, version = text.rpartition("/")
        version = version.split("_", 1)[0]
    else:
        at = text.find("@", 1)
        if at <= 0:
            return None
        name, version = text[:at], text[at + 1 :]
    if not name or not version or ":" in version or "/" in version:
        return None
    return name, version


def _pnpm_lock_number(raw: object) -> float:
    try:
        return float(str(raw).strip().strip("'\""))
    except ValueError:
        return 0.0


def parse_pnpm_lock(text: str) -> ParseResult:
    import yaml

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise FormatError("pnpm-lock.yaml is not valid YAML") from exc
    if not isinstance(data, dict):
        raise FormatError("pnpm-lock.yaml is not a mapping")
    out = _Collector("pnpm-lock")
    legacy = _pnpm_lock_number(data.get("lockfileVersion")) < 6
    direct_names: set[str] = set()
    sections = [data]
    importers = data.get("importers")
    if isinstance(importers, dict):
        sections.extend(item for item in importers.values() if isinstance(item, dict))
    for section in sections:
        for key in PNPM_DEP_MAPS:
            deps = section.get(key)
            if isinstance(deps, dict):
                direct_names.update(str(name) for name in deps)
    for table in ("packages", "snapshots"):
        entries = data.get(table)
        if not isinstance(entries, dict):
            continue
        for key in entries:
            parsed = _pnpm_key(str(key), legacy)
            if parsed is None:
                out.skip()
                continue
            name, version = parsed
            out.add(component("npm", name, version, 1 if name in direct_names else 0))
    return out.result


# --- Python ------------------------------------------------------------------


def _logical_lines(text: str) -> list[str]:
    lines: list[str] = []
    buffer = ""
    for raw in text.splitlines():
        line = _COMMENT.sub("", raw).rstrip()
        if line.endswith("\\"):
            buffer += line[:-1] + " "
            continue
        lines.append((buffer + line).strip())
        buffer = ""
    if buffer.strip():
        lines.append(buffer.strip())
    return [line for line in lines if line]


def _strip_options(line: str) -> str:
    return re.sub(r"\s--[A-Za-z-]+(?:[=\s]\S+)?", "", f" {line}").strip()


def parse_requirements(text: str) -> ParseResult:
    out = _Collector("requirements")
    for line in _logical_lines(text):
        if line.startswith("-"):
            option = line.split(None, 1)[0].split("=", 1)[0]
            if option in {"-r", "--requirement", "-c", "--constraint"}:
                out.warn(f"{option} includes are not followed; import that file too")
            elif option in {"-e", "--editable"}:
                out.skip()
            continue
        line = _strip_options(line)
        url = _REQ_URL.match(line)
        if url:
            out.add(component("pypi", url.group(1), "", None))
            continue
        match = _REQ_LINE.match(line)
        if not match:
            out.skip()
            continue
        pin = _REQ_PIN.match((match.group(3) or "").strip())
        out.add(component("pypi", match.group(1), pin.group(1) if pin else "", None))
    return out.result


def _requirements_like(text: str) -> bool:
    lines = [line for line in _logical_lines(text) if not line.startswith("-")]
    if not lines:
        return False
    hits = sum(1 for line in lines if _REQ_URL.match(line) or _REQ_LINE.match(_strip_options(line)))
    return hits * 2 > len(lines)


def parse_toml_lock(text: str) -> ParseResult:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise FormatError("lock file is not valid TOML") from exc
    packages = data.get("package")
    if not isinstance(packages, list):
        raise FormatError("TOML lock file has no [[package]] array")
    out = _Collector("toml-lock")
    for entry in packages:
        if not isinstance(entry, dict):
            out.skip()
            continue
        source = entry.get("source")
        if isinstance(source, dict) and (
            {"editable", "virtual", "workspace", "path", "directory"} & set(source)
            or str(source.get("type") or "").lower() in {"directory", "file"}
        ):
            out.skip()
            continue
        out.add(component("pypi", str(entry.get("name") or ""), str(entry.get("version") or ""), None))
    return out.result


def parse_pipfile_lock(text: str) -> ParseResult:
    data = _strict_json(text, "pipfile-lock")
    out = _Collector("pipfile-lock")
    for key in ("default", "develop"):
        deps = data.get(key)
        if not isinstance(deps, dict):
            continue
        for name, entry in deps.items():
            if not isinstance(entry, dict) or entry.get("editable") or entry.get("path") or entry.get("file"):
                out.skip()
                continue
            version = str(entry.get("version") or "")
            for prefix in ("===", "=="):
                if version.startswith(prefix):
                    version = version[len(prefix) :]
                    break
            else:
                version = ""
            out.add(component("pypi", str(name), version, None))
    return out.result


# --- SBOMs -------------------------------------------------------------------


def parse_cyclonedx(text: str) -> ParseResult:
    data = _strict_json(text, "cyclonedx")
    out = _Collector("cyclonedx")
    stack = [data.get("components")]
    walked = 0
    while stack and walked < 500_000:
        level = stack.pop()
        if not isinstance(level, list):
            continue
        for item in level:
            walked += 1
            if not isinstance(item, dict):
                continue
            purl = item.get("purl")
            out.add(parse_purl(purl) if isinstance(purl, str) else None)
            stack.append(item.get("components"))
    return out.result


def parse_spdx(text: str) -> ParseResult:
    data = _strict_json(text, "spdx")
    out = _Collector("spdx")
    packages = data.get("packages")
    if not isinstance(packages, list):
        return out.result
    for package in packages:
        if not isinstance(package, dict):
            continue
        refs = package.get("externalRefs") if isinstance(package.get("externalRefs"), list) else []
        purls = [
            ref.get("referenceLocator")
            for ref in refs
            if isinstance(ref, dict)
            and str(ref.get("referenceType") or "").lower() == "purl"
            and isinstance(ref.get("referenceLocator"), str)
        ]
        if not purls:
            out.skip()
            continue
        for purl in purls:
            found = parse_purl(purl)
            if found is not None and not found.version:
                found = Component(found.ecosystem, found.name, clean_version(str(package.get("versionInfo") or "")), None)
            out.add(found)
    return out.result


# --- plain list and workflows ------------------------------------------------


def _plain_lines(text: str) -> list[str]:
    return [line for line in (_COMMENT.sub("", raw).strip() for raw in text.splitlines()) if line]


def _plain_shape(line: str) -> tuple[str, str, str] | None:
    """(ecosystem word, name, version) for one plain-list line, or None when the shape is wrong."""
    match = _PLAIN_SPACED.match(line)
    if match:
        return match.group(1), match.group(2), match.group(3) or ""
    match = _PLAIN_COLON.match(line)
    if match:
        rest = match.group(2)
        at = rest.rfind("@")
        if at > 0:
            return match.group(1), rest[:at], rest[at + 1 :]
        return match.group(1), rest, ""
    return None


def _plain_like(text: str) -> bool:
    lines = _plain_lines(text)
    if not lines:
        return False
    known = False
    for line in lines:
        if line.lower().startswith("pkg:"):
            known = True
            continue
        shape = _plain_shape(line)
        if shape is None:
            return False
        known = known or ecosystem_alias(shape[0]) is not None
    return known


def parse_plain(text: str) -> ParseResult:
    out = _Collector("plain")
    for line in _plain_lines(text):
        if line.lower().startswith("pkg:"):
            out.add(parse_purl(line, direct=1))
            continue
        shape = _plain_shape(line)
        if shape is None:
            out.skip()
            continue
        word, name, version = shape
        ecosystem = ecosystem_alias(word)
        if ecosystem is None:
            out.warn(f"unknown ecosystem {word[:40]!r}; use npm, pypi, github-actions or openvsx")
            out.skip()
            continue
        out.add(component(ecosystem, name, version, 1))
    return out.result


def parse_workflow(text: str) -> ParseResult:
    out = _Collector("workflow")
    for ref in uses_refs(text):
        if ref.startswith(("./", "../", "docker://")) or "@" not in ref:
            out.skip()
            continue
        target, _sep, version = ref.rpartition("@")
        name = normalize_action_name(target)
        if name is None:
            out.skip()
            continue
        out.add(component(ACTIONS_ECOSYSTEM, name, version, 1))
    return out.result


# --- detection ---------------------------------------------------------------

PARSERS = {
    "npm-lock": parse_npm_lock,
    "yarn-lock": parse_yarn_lock,
    "pnpm-lock": parse_pnpm_lock,
    "package-json": parse_package_json,
    "requirements": parse_requirements,
    "toml-lock": parse_toml_lock,
    "pipfile-lock": parse_pipfile_lock,
    "cyclonedx": parse_cyclonedx,
    "spdx": parse_spdx,
    "plain": parse_plain,
    "workflow": parse_workflow,
}


def _format_from_name(filename: str) -> str | None:
    path = PurePath((filename or "").replace("\\", "/"))
    name = path.name.lower()
    if name in {"package-lock.json", "npm-shrinkwrap.json"}:
        return "npm-lock"
    if name == "yarn.lock":
        return "yarn-lock"
    if name == "pnpm-lock.yaml":
        return "pnpm-lock"
    if name == "package.json":
        return "package-json"
    if name.startswith("requirements") and name.endswith(".txt"):
        return "requirements"
    if name in {"poetry.lock", "uv.lock"}:
        return "toml-lock"
    if name == "pipfile.lock":
        return "pipfile-lock"
    if name in {"action.yml", "action.yaml"} or (
        name.endswith((".yml", ".yaml")) and path.parent.as_posix().lower().endswith(".github/workflows")
    ):
        return "workflow"
    return None


def detect_format(text: str, filename: str = "") -> str | None:
    """The format of ``text``, read from its content; the filename only breaks ties. None when unknown."""
    data = _json_object(text)
    if data is not None:
        if "lockfileVersion" in data:
            return "npm-lock"
        if str(data.get("bomFormat") or "") == "CycloneDX":
            return "cyclonedx"
        if "spdxVersion" in data:
            return "spdx"
        if isinstance(data.get("_meta"), dict) and ("default" in data or "develop" in data):
            return "pipfile-lock"
        if "name" in data or any(isinstance(data.get(key), dict) for key in NPM_DEP_MAPS):
            return "package-json"
        by_name = _format_from_name(filename)
        return by_name if by_name in {"package-json", "npm-lock", "pipfile-lock"} else None
    head = "\n".join(text.splitlines()[:5])
    if "# yarn lockfile v1" in head or _YARN_BERRY.search(text):
        return "yarn-lock"
    if _TOML_PACKAGE.search(text):
        try:
            if isinstance(tomllib.loads(text).get("package"), list):
                return "toml-lock"
        except tomllib.TOMLDecodeError:
            pass
    if _PNPM_LOCK.search(text) and re.search(r"^(packages|importers|dependencies)\s*:", text, re.MULTILINE):
        return "pnpm-lock"
    if uses_refs(text):
        return "workflow"
    if _plain_like(text):
        return "plain"
    if _requirements_like(text):
        return "requirements"
    return _format_from_name(filename)


def parse(text: str, filename: str = "", fmt: str | None = None) -> ParseResult:
    """Parse one file. Raises ``FormatError`` when the format is unknown or the text does not fit it."""
    chosen = fmt or detect_format(text, filename)
    if chosen is None:
        raise FormatError("format not recognized")
    parser = PARSERS.get(chosen)
    if parser is None:
        raise FormatError(f"unknown format {chosen!r}; see 'hunter watchlist formats'")
    return parser(text)
