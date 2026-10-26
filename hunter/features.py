"""Code features that stay outside Jev: counts, clocks, and literal hits."""

from __future__ import annotations

import json
import re

from hunter.behavior import find_behavior_chains
from hunter.models import CodeFeatures, FileDiff, ReleaseMeta
from hunter.patterns import (
    CLOUD,
    CREDENTIAL,
    DECODE_EXEC,
    ENCODED_IMPORT,
    ENV_TOKEN,
    PERSISTENCE,
    SHELL,
    SSH,
    XOR,
    high_entropy_line,
    raw_ips,
    shannon_entropy,
    unexpected_hosts,
)
from hunter.triage import pth_import_lines
from hunter.typosquat import COMMON_PACKAGES, NameIndex

LIFECYCLE_SCRIPTS = (
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "prepublish",
    "prepublishOnly",
)
INSTALL_LIFECYCLE = (
    "preinstall",
    "install",
    "postinstall",
    "prepublish",
    "prepublishOnly",
)
RUNTIME_DEP_FIELDS = ("dependencies", "optionalDependencies")
DEP_FIELDS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
_SCRIPT_FILE = re.compile(
    r"""(?:^|[\s;])(?:node|python3?|bash|sh)\s+([A-Za-z0-9_@./-]+\.(?:js|mjs|cjs|py|sh))\b"""
)
_IMPORT = re.compile(
    r"""(?:require|import)\s*(?:\(\s*)?['\"](?P<name>@?[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)?)['\"]"""
    r"""|from\s+['\"](?P<from>@?[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)?)['\"]"""
)
_OBFUSCATED = re.compile(
    r"(atob\s*\(|Buffer\.from\([^)\n]{0,80}base64|charCodeAt\s*\(|fromCharCode\s*\()",
    re.IGNORECASE,
)
_PY_DEP = re.compile(r"""[\"']([A-Za-z0-9_.\-]+)(?:\[[^\]]+\])?(?:[<>=!~,\s]|[\"'])""")


def _load_json(text: str) -> dict:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def npm_lifecycle(text: str) -> dict[str, str]:
    scripts = _load_json(text).get("scripts") or {}
    if not isinstance(scripts, dict):
        return {}
    return {key: str(scripts.get(key) or "") for key in LIFECYCLE_SCRIPTS}


def npm_dependency_names(text: str) -> set[str]:
    return set(_npm_dep_map(text, DEP_FIELDS))


def _npm_dep_map(text: str, fields: tuple[str, ...]) -> dict[str, str]:
    data = _load_json(text)
    found: dict[str, str] = {}
    for field in fields:
        block = data.get(field) or {}
        if isinstance(block, dict):
            for name, spec in block.items():
                found[str(name)] = str(spec)
    return found


def runtime_dependency_specs(files: dict[str, str]) -> dict[str, str]:
    found: dict[str, str] = {}
    for text in _named(files, "package.json"):
        found.update(_npm_dep_map(text, RUNTIME_DEP_FIELDS))
    return found


def python_dependency_names(text: str) -> set[str]:
    names: set[str] = set()
    for match in re.finditer(r"(?is)(install_requires|dependencies)\s*=\s*\[(.*?)\]", text):
        for name in _PY_DEP.findall(match.group(2)):
            if name.lower() not in {"requires", "python"}:
                names.add(name)
    return names


def _manifest_deps(files: dict[str, str]) -> set[str]:
    names: set[str] = set()
    for path, text in files.items():
        name = path.rsplit("/", 1)[-1].lower()
        if name == "package.json":
            names.update(npm_dependency_names(text))
        elif name in {"pyproject.toml", "setup.py", "setup.cfg"}:
            names.update(python_dependency_names(text))
    return names


def _named(files: dict[str, str], filename: str) -> list[str]:
    return [text for path, text in files.items() if path.rsplit("/", 1)[-1].lower() == filename]


def added_install_commands(old_files: dict[str, str], new_files: dict[str, str]) -> list[tuple[str, str]]:
    """Lifecycle commands that were added or changed. Removals do not count."""
    old_scripts: dict[str, str] = {}
    new_scripts: dict[str, str] = {}
    for text in _named(old_files, "package.json"):
        old_scripts.update(npm_lifecycle(text))
    for text in _named(new_files, "package.json"):
        new_scripts.update(npm_lifecycle(text))
    added: list[tuple[str, str]] = []
    for key, command in new_scripts.items():
        if key not in INSTALL_LIFECYCLE:
            continue
        text = command.strip()
        if not text or text == old_scripts.get(key, "").strip():
            continue
        added.append((key, text))
    return added


def lifecycle_edit_count(old_files: dict[str, str], new_files: dict[str, str]) -> int:
    count = len(added_install_commands(old_files, new_files))
    for path in sorted(set(old_files) | set(new_files)):
        base = path.rsplit("/", 1)[-1].lower()
        if base not in {"setup.py", "setup.cfg", "pyproject.toml"}:
            continue
        old = old_files.get(path, "")
        new = new_files.get(path, "")
        if old == new:
            continue
        added = "\n".join(
            line[1:]
            for line in _rough_added(old, new).splitlines()
            if line.startswith("+") and not line.startswith("+++")
        )
        sample = added.lower()
        if any(token in sample for token in ("cmdclass", "install.run", "def run(", "subprocess", "base64", "system(")):
            count += 1
        elif path not in old_files and any(token in new.lower() for token in ("cmdclass", "subprocess", "base64")):
            count += 1
    return count + _rust_lifecycle_edits(old_files, new_files)


def _rough_added(old: str, new: str) -> str:
    import difflib

    return "".join(difflib.unified_diff(old.splitlines(keepends=True), new.splitlines(keepends=True), n=0))


def release_gap_hours(meta: ReleaseMeta) -> float | None:
    if meta.old_time is None or meta.new_time is None:
        return None
    delta = abs((meta.new_time - meta.old_time).total_seconds()) / 3600.0
    return delta


def _source_blob(files: dict[str, str]) -> str:
    parts: list[str] = []
    for path, text in files.items():
        base = path.rsplit("/", 1)[-1].lower()
        if base in {"package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"}:
            continue
        if base.endswith(".md"):
            continue
        parts.append(text)
    return "\n".join(parts)


def _package_of(spec: str) -> str:
    if spec.startswith("@") and "/" in spec:
        scope, name = spec.split("/", 1)
        return f"{scope}/{name.split('/', 1)[0]}"
    return spec.split("/", 1)[0]


def referenced_in_source(package: str, source: str) -> bool:
    if package.startswith("@types/"):
        return True
    for match in _IMPORT.finditer(source):
        imported = match.group("name") or match.group("from") or ""
        if _package_of(imported) == package:
            return True
    return False


def phantom_runtime_dependencies(old_files: dict[str, str], new_files: dict[str, str]) -> list[str]:
    """New runtime dependencies that no source file imports or requires."""
    old_names = set(runtime_dependency_specs(old_files))
    new_specs = runtime_dependency_specs(new_files)
    source = _source_blob(new_files)
    found = []
    for name in sorted(set(new_specs) - old_names):
        if name.startswith("@types/"):
            continue
        if not referenced_in_source(name, source):
            found.append(name)
    return found


def _lookup_source(files: dict[str, str], relative: str) -> str:
    if relative in files:
        return files[relative]
    suffix = "/" + relative
    for path, text in files.items():
        if path.endswith(suffix) or path.rsplit("/", 1)[-1] == relative:
            return text
    return ""


def _hostile_install_text(text: str) -> bool:
    if not text.strip():
        return False
    shell = bool(SHELL.search(text))
    decode = bool(DECODE_EXEC.search(text))
    obfuscated = bool(_OBFUSCATED.search(text))
    credential = bool(CREDENTIAL.search(text))
    long = len(text) >= 400 and shannon_entropy(text) >= 4.4
    entropy = long or any(high_entropy_line(line) for line in text.splitlines())
    if shell and (decode or obfuscated or credential or entropy):
        return True
    if (decode or obfuscated) and (shell or "exec" in text.lower() or credential):
        return True
    return False


def compound_install_payload(old_files: dict[str, str], new_files: dict[str, str]) -> bool:
    """True only when an added install hook and its payload live in the same change."""
    for _name, command in added_install_commands(old_files, new_files):
        blobs = [command]
        for match in _SCRIPT_FILE.finditer(command):
            blobs.append(_lookup_source(new_files, match.group(1)))
        if _hostile_install_text("\n".join(blobs)):
            return True
    for path in sorted(set(old_files) | set(new_files)):
        base = path.rsplit("/", 1)[-1].lower()
        if base not in {"setup.py", "setup.cfg", "pyproject.toml"}:
            continue
        old = old_files.get(path, "")
        new = new_files.get(path, "")
        if old == new:
            continue
        added = "\n".join(
            line[1:]
            for line in _rough_added(old, new).splitlines()
            if line.startswith("+") and not line.startswith("+++")
        )
        sample = added.lower()
        if not any(token in sample for token in ("cmdclass", "install.run", "def run(")):
            continue
        if _hostile_install_text(added):
            return True
    return False


def _long_entropy_line(text: str) -> bool:
    for line in text.splitlines():
        if len(line) >= 180 and high_entropy_line(line):
            return True
    return False


def minified_side_payload(old_files: dict[str, str], new_files: dict[str, str]) -> bool:
    """A new long high-entropy file sitting beside ordinary source."""
    from hunter.triage import is_noise, is_source

    ordinary = False
    for path, text in new_files.items():
        if is_source(path) and not is_noise(path) and not _long_entropy_line(text):
            ordinary = True
            break
    if not ordinary:
        return False
    for path in sorted(set(new_files) - set(old_files)):
        if is_noise(path):
            continue
        if _long_entropy_line(new_files[path]):
            return True
    return False


_NATIVE_REBUILD = re.compile(
    r"^(node-gyp|node-gyp-build|prebuild-install|prebuildify|husky)(\s|$)"
)


_EXECUTABLE_SUFFIXES = {".node", ".so", ".dll", ".dylib", ".exe"}
_EXECUTABLE_HEADERS = {"elf", "pe", "mach-o"}


def _path_suffix(path: str) -> str:
    name = path.rsplit("/", 1)[-1]
    if "." not in name:
        return ""
    return "." + name.rsplit(".", 1)[-1].lower()


def is_executable_binary(path: str, text: str) -> bool:
    """True for ELF, PE, Mach-O, or a native addon extension.

    `.node`, `.so`, `.dll`, `.dylib`, and `.exe` count after the archive reader
    has replaced the bytes with a short marker. Media files do not.
    """
    header = ""
    for line in (text or "").splitlines():
        if line.lower().startswith("header:"):
            header = line.split(":", 1)[1].strip().lower()
            break
    if header in _EXECUTABLE_HEADERS:
        return True
    return _path_suffix(path) in _EXECUTABLE_SUFFIXES


def _lifecycle_commands(files: dict[str, str]) -> list[str]:
    commands: list[str] = []
    for text in _named(files, "package.json"):
        for key, command in npm_lifecycle(text).items():
            if key in INSTALL_LIFECYCLE and command.strip():
                commands.append(command.strip())
    return commands


def new_executable_binary(old_files: dict[str, str], new_files: dict[str, str]) -> bool:
    """A new executable in a package that had none, with no native-rebuild install.

    The check is local. It does not call a model. A lifecycle command that only
    runs node-gyp, node-gyp-build, prebuild-install, prebuildify, or husky may
    ship those files.
    """
    added = any(
        is_executable_binary(path, new_files.get(path, ""))
        for path in set(new_files) - set(old_files)
    )
    if not added:
        return False
    if any(is_executable_binary(path, text) for path, text in old_files.items()):
        return False
    commands = _lifecycle_commands(new_files)
    if commands and all(native_rebuild_command(command) for command in commands):
        return False
    return True


def native_rebuild_command(command: str) -> bool:
    """A lifecycle command that only rebuilds a native addon or installs git hooks.

    A chain (`&&`, `|`, `;`) is not a native rebuild, even when it starts with one.
    """
    text = command.strip()
    if not text or " -e " in f" {text} ":
        return False
    if any(token in text for token in ("&&", ";", "|", "`", "$(")):
        return False
    return bool(_NATIVE_REBUILD.match(text))


def suspicious_install_command(command: str) -> bool:
    """A lifecycle command that runs an interpreter, other than a known native rebuild."""
    text = command.strip()
    if not text or native_rebuild_command(text):
        return False
    return bool(re.search(r"\b(node|python3?|bash|sh)\b", text))


_PRIMARY_JS = {"index.js", "index.mjs", "index.cjs"}
_SCRIPT_SUFFIXES = {".js", ".mjs", ".cjs", ".py", ".sh", ".node"}
_SKIP_PARTS = {"sdist", "wheel", "package"}


def _norm_pkg(value: str) -> str:
    return re.sub(r"[-_.]+", "-", (value or "").strip().lower())


def _suffix(filename: str) -> str:
    if "." not in filename:
        return ""
    return "." + filename.rsplit(".", 1)[-1].lower()


def _display_parts(path: str) -> list[str]:
    return [part for part in path.split("/") if part and part not in _SKIP_PARTS]


def _clean_rel(value: str, *, allow_bare: bool = False) -> str:
    text = value.strip().replace("\\", "/")
    if not text or "://" in text or text.startswith("#"):
        return ""
    while text.startswith("./"):
        text = text[2:]
    text = text.split("?", 1)[0].split("#", 1)[0]
    if not text or text.endswith("/"):
        return ""
    if not allow_bare and _suffix(text.rsplit("/", 1)[-1]) not in _SCRIPT_SUFFIXES:
        return ""
    return text


def _walk_export_values(node, found: set[str]) -> None:
    if isinstance(node, str):
        cleaned = _clean_rel(node)
        if cleaned:
            found.add(cleaned)
        return
    if isinstance(node, list):
        for item in node:
            _walk_export_values(item, found)
        return
    if not isinstance(node, dict):
        return
    for key, value in node.items():
        if str(key) == "types" or str(key).startswith("types"):
            continue
        _walk_export_values(value, found)


def _npm_entry_rels(text: str) -> set[str]:
    data = _load_json(text)
    found: set[str] = set()
    for field in ("main", "module"):
        value = data.get(field)
        if isinstance(value, str):
            cleaned = _clean_rel(value)
            if cleaned:
                found.add(cleaned)
    bin_field = data.get("bin")
    if isinstance(bin_field, str):
        cleaned = _clean_rel(bin_field, allow_bare=True)
        if cleaned:
            found.add(cleaned)
    elif isinstance(bin_field, dict):
        for value in bin_field.values():
            if isinstance(value, str):
                cleaned = _clean_rel(value, allow_bare=True)
                if cleaned:
                    found.add(cleaned)
    _walk_export_values(data.get("exports"), found)
    return found


def _path_matches_entry(path: str, entry: str) -> bool:
    normal = path.replace("\\", "/")
    target = entry.replace("\\", "/").lstrip("/")
    if not target:
        return False
    if normal == target:
        return True
    parts = [part for part in normal.split("/") if part]
    if len(parts) >= 2 and "/".join(parts[1:]) == target:
        return True
    if len(parts) >= 3 and "/".join(parts[2:]) == target:
        return True
    return False


def _is_primary_script(path: str) -> bool:
    parts = _display_parts(path)
    return len(parts) == 1 and parts[0].lower() in _PRIMARY_JS


def _is_bin_script(path: str) -> bool:
    parts = _display_parts(path)
    if len(parts) < 2 or parts[0] != "bin":
        return False
    return _suffix(parts[-1]) in _SCRIPT_SUFFIXES or _suffix(parts[-1]) == ""


def _pypi_entry_paths(paths: set[str], name: str) -> set[str]:
    norm = _norm_pkg(name)
    underscored = norm.replace("-", "_")
    found: set[str] = set()
    shallow_inits: list[str] = []
    for path in paths:
        parts = _display_parts(path)
        if not parts:
            continue
        if any(part.endswith(".dist-info") or part.endswith(".egg-info") for part in parts):
            continue
        if any(part.lower() in {"test", "tests", "docs", "examples"} for part in parts[:-1]):
            continue
        base = parts[-1]
        parents = parts[:-1]
        module_names = {f"{underscored}.py", f"{norm}.py"}
        if base.lower() in module_names and len(parents) <= 1:
            found.add(path)
        if base != "__init__.py":
            continue
        if not parents:
            shallow_inits.append(path)
            found.add(path)
            continue
        if len(parents) > 2 or not (len(parents) == 1 or parents[0] == "src"):
            continue
        shallow_inits.append(path)
        package = parents[-1].lower().replace("-", "_")
        if norm and package.replace("_", "-") in {norm, underscored.replace("_", "-")}:
            found.add(path)
    if not found and len(shallow_inits) == 1:
        found.add(shallow_inits[0])
    return found


def _entrypoint_paths(old_files: dict[str, str], new_files: dict[str, str], meta: ReleaseMeta) -> set[str]:
    declared: set[str] = set()
    for files in (old_files, new_files):
        for text in _named(files, "package.json"):
            declared.update(_npm_entry_rels(text))
    all_paths = set(old_files) | set(new_files)
    found: set[str] = set()
    for rel in declared:
        for path in all_paths:
            if _path_matches_entry(path, rel):
                found.add(path)
    for path in all_paths:
        if _is_primary_script(path) or _is_bin_script(path):
            found.add(path)
    if (meta.ecosystem or "").lower() == "pypi":
        found.update(_pypi_entry_paths(all_paths, meta.name))
    return found


def _added_only(old: str, new: str) -> str:
    if not old:
        return new
    return "\n".join(
        line[1:]
        for line in _rough_added(old, new).splitlines()
        if line.startswith("+") and not line.startswith("+++")
    )


def _entry_replaced_or_grown(old: str, new: str) -> bool:
    """A new file, a large growth, or a rewrite that drops most of the previous body."""
    if not new.strip() or old == new:
        return False
    if not old.strip():
        return True
    if len(new) >= len(old) + 180:
        return True
    old_lines = [line.strip() for line in old.splitlines() if line.strip()]
    if not old_lines:
        return True
    new_lines = {line.strip() for line in new.splitlines() if line.strip()}
    kept = sum(1 for line in old_lines if line in new_lines)
    return kept * 2 <= len(old_lines)


def _entry_change_is_payload(old: str, new: str) -> bool:
    """A new long high-entropy line in a file that was not already minified.

    A 40-character token in ordinary source is not a payload. A bundle that
    already had a long minified line stays a bundle when the next release edits it.
    """
    if _long_entropy_line(old):
        return False
    added = _added_only(old, new)
    return _long_entropy_line(added) or _long_entropy_line(new)


def entrypoint_payload_change(
    old_files: dict[str, str],
    new_files: dict[str, str],
    meta: ReleaseMeta,
) -> bool:
    """True when a changed entrypoint gains a long high-entropy line it did not have."""
    for path in sorted(_entrypoint_paths(old_files, new_files, meta)):
        old = old_files.get(path, "")
        new = new_files.get(path, "")
        if old == new:
            continue
        if _entry_replaced_or_grown(old, new) and _entry_change_is_payload(old, new):
            return True
    return False


def _script_is_new(old_files: dict[str, str], new_files: dict[str, str], relative: str) -> bool:
    rel = relative.replace("\\", "/").strip()
    while rel.startswith("./"):
        rel = rel[2:]
    if not rel:
        return False

    def present(files: dict[str, str]) -> bool:
        if rel in files:
            return True
        suffix = "/" + rel
        if any(path.endswith(suffix) for path in files):
            return True
        if "/" in rel:
            return False
        return any(path.rsplit("/", 1)[-1] == rel for path in files)

    return present(new_files) and not present(old_files)


def install_sidecar_change(
    old_files: dict[str, str],
    new_files: dict[str, str],
    *,
    lifecycle_edits: int,
    binary_media_changes: int,
) -> bool:
    """Lifecycle edit plus a newly added file it names, or a binary change.

    A native rebuild (node-gyp, node-gyp-build, prebuild-install, prebuildify)
    may ship new binary files without counting as a sidecar. A command that
    names a new script still counts. This is not the compound install rule.
    """
    if lifecycle_edits < 1:
        return False
    commands = added_install_commands(old_files, new_files)
    native_only = bool(commands) and all(
        native_rebuild_command(command) for _name, command in commands
    )
    if binary_media_changes and not native_only:
        return True
    for _name, command in commands:
        for match in _SCRIPT_FILE.finditer(command):
            if _script_is_new(old_files, new_files, match.group(1)):
                return True
    return False


# Wheel .data subdirectories that install into site-packages, next to the package.
_WHEEL_LIB_DATA = re.compile(r"^[^/]+\.data/(?:purelib|platlib)/(.+)$")
_COMPILED_SUFFIXES = {".so", ".pyd", ".dll", ".dylib", ".pyc", ".pyo", ".a", ".lib", ".mo"}
_PYTHON_RUN_SUFFIXES = {".py", ".pyw", ".pth"}
# Files a build backend writes into the wheel that the sdist never holds.
_GENERATED_NAMES = {"_version.py", "version.py", "__version__.py", "_build_info.py"}
_GENERATED_ENDINGS = ("_pb2.py", "_pb2_grpc.py")
_TOML_TABLE = re.compile(r"^\s*\[\[?\s*([^\]]+?)\s*\]\]?\s*(?:#.*)?$")
_MATURIN_DATA = re.compile(r"^\s*data\s*=")


def _wheel_tree(files: dict[str, str]) -> dict[str, str]:
    """Wheel paths without the wheel/ root. An unprefixed tree counts when it has a .dist-info directory."""
    wheel = {path[len("wheel/") :]: text for path, text in files.items() if path.startswith("wheel/")}
    if wheel or any(path.startswith("sdist/") for path in files):
        return wheel
    if any(path.split("/", 1)[0].endswith(".dist-info") for path in files):
        return dict(files)
    return {}


def wheel_install_path(path: str) -> str | None:
    """Where a wheel file lands under site-packages. None for metadata and other .data directories."""
    top = path.split("/", 1)[0]
    if top.endswith(".dist-info"):
        return None
    if top.endswith(".data"):
        match = _WHEEL_LIB_DATA.match(path)
        return match.group(1) if match else None
    return path


def _install_paths(wheel: dict[str, str]) -> set[str]:
    return {target for target in (wheel_install_path(path) for path in wheel) if target is not None}


def _install_map(files: dict[str, str]) -> dict[str, str]:
    """Install path to tree path. A tree with no wheel maps as it stands, without the sdist/ root."""
    wheel = _wheel_tree(files)
    if not wheel:
        return {path.removeprefix("sdist/"): path for path in files}
    prefix = "wheel/" if any(path.startswith("wheel/") for path in files) else ""
    found: dict[str, str] = {}
    for path in wheel:
        target = wheel_install_path(path)
        if target is not None:
            found[target] = prefix + path
    return found


def install_target(files: dict[str, str], path: str) -> str | None:
    """Where one tree path lands under site-packages, or None when it does not install there."""
    for target, tree_path in _install_map(files).items():
        if tree_path == path:
            return target
    return None


def is_new_install(old_files: dict[str, str], target: str) -> bool:
    """The previous release installed nothing at this path."""
    return target not in _install_map(old_files)


# A startup hook's module that decodes and runs code, or reaches the network, is a payload.
_PY_RUN = re.compile(r"\b(?:exec|eval)\s*\(")
_PY_DECODE = re.compile(
    r"\b(?:b64decode|b32decode|b85decode|a85decode|decompress|unhexlify|fromhex)\s*\("
    r"|\b(?:marshal|pickle)\.loads\s*\("
)
_PY_FETCH = re.compile(
    r"\b(?:urlopen|urlretrieve|HTTPSConnection|HTTPConnection|create_connection)\s*\("
    r"|\b(?:requests|httpx)\.(?:get|post|request)\s*\(|\bsocket\.socket\s*\("
)
_IMPORT_CALL = re.compile(r"__import__\(\s*['\"]([\w.]+)['\"]")


def payload_indicators(text: str) -> list[str]:
    """decode_exec, fetch_exec, or network, from static text."""
    found: list[str] = []
    runs = bool(_PY_RUN.search(text))
    if runs and _PY_DECODE.search(text):
        found.append("decode_exec")
    if _PY_FETCH.search(text):
        found.append("fetch_exec" if runs else "network")
    return found


def pth_imported_modules(line: str) -> list[str]:
    """Top-level module names one .pth import line loads."""
    names: list[str] = []
    for statement in line.split(";"):
        statement = statement.strip()
        if statement.startswith(("import ", "import\t")):
            parts = [part.strip().split()[0] for part in statement[len("import") :].split(",") if part.strip()]
        elif statement.startswith("from ") and " import " in statement:
            parts = [statement[len("from ") :].split(" import ", 1)[0].strip()]
        else:
            parts = []
        parts += _IMPORT_CALL.findall(statement)
        for part in parts:
            top = part.split(".", 1)[0]
            if top and top not in names:
                names.append(top)
    return names


def new_top_level_module(old_files: dict[str, str], new_files: dict[str, str], module: str) -> list[str]:
    """Tree paths of a top-level module this release adds next to the package, e.g. in .data/purelib.

    Empty when the previous release already installed a module or directory of that name,
    so a hook that loads the package's own code does not count.
    """
    old_tops = {target.split("/", 1)[0] for target in _install_map(old_files)}
    if module in old_tops or f"{module}.py" in old_tops:
        return []
    return [
        path
        for target, path in sorted(_install_map(new_files).items())
        if target == f"{module}.py" or (target.startswith(f"{module}/") and target.endswith(".py"))
    ]


def _is_own_top(top: str, name: str) -> bool:
    stem = top
    for ending in (".py", ".pth", ".libs", "-stubs"):
        if stem.endswith(ending):
            stem = stem[: -len(ending)]
    norm = _norm_pkg(stem).lstrip("-")
    return bool(norm) and norm == _norm_pkg(name)


def outside_package_files(old_files: dict[str, str], new_files: dict[str, str], name: str) -> list[str]:
    """New wheel files that install a top-level module or directory the previous wheel did not have.

    Wheel .data/purelib and .data/platlib land at the top of site-packages, so they count.
    Only compared with a previous wheel. The package's own name, compiled extensions,
    vendored .libs directories, and .pth files with no import line do not count.
    """
    new_wheel = _wheel_tree(new_files)
    old_wheel = _wheel_tree(old_files)
    if not new_wheel or not old_wheel:
        return []
    old_installs = _install_paths(old_wheel)
    old_tops = {target.split("/", 1)[0] for target in old_installs}
    found: list[str] = []
    for path in sorted(new_wheel):
        target = wheel_install_path(path)
        if target is None or target in old_installs:
            continue
        top = target.split("/", 1)[0]
        if top in old_tops or _is_own_top(top, name) or top.endswith(".libs"):
            continue
        if _path_suffix(target) in _COMPILED_SUFFIXES:
            continue
        if target.endswith(".pth") and not pth_import_lines(target, new_wheel[path]):
            continue
        found.append(path)
    return found


def _path_suffixes(paths: set[str]) -> set[str]:
    found: set[str] = set()
    for path in paths:
        parts = path.split("/")
        for index in range(len(parts)):
            found.add("/".join(parts[index:]))
    return found


def wheel_only_files(old_files: dict[str, str], new_files: dict[str, str]) -> list[str]:
    """New Python files in the wheel that the sdist of the same release does not hold.

    Only files the previous wheel did not install count. Compiled extensions,
    generated version and protobuf modules, standard .pth stubs, and non-Python
    build output do not.
    """
    new_wheel = _wheel_tree(new_files)
    old_wheel = _wheel_tree(old_files)
    sdist = {path[len("sdist/") :] for path in new_files if path.startswith("sdist/")}
    if not new_wheel or not old_wheel or not sdist:
        return []
    old_installs = _install_paths(old_wheel)
    in_sdist = _path_suffixes(sdist)
    found: list[str] = []
    for path in sorted(new_wheel):
        target = wheel_install_path(path)
        if target is None or target in old_installs or _path_suffix(target) not in _PYTHON_RUN_SUFFIXES:
            continue
        base = target.rsplit("/", 1)[-1]
        if base in _GENERATED_NAMES or base.endswith(_GENERATED_ENDINGS):
            continue
        if target.endswith(".pth") and not pth_import_lines(target, new_wheel[path]):
            continue
        if target in in_sdist:
            continue
        found.append(path)
    return found


def _maturin_data_lines(text: str) -> set[str]:
    table = ""
    found: set[str] = set()
    for line in text.splitlines():
        head = _TOML_TABLE.match(line)
        if head:
            table = head.group(1).replace('"', "").replace(" ", "")
            continue
        if table == "tool.maturin" and _MATURIN_DATA.match(line):
            found.add(line.strip())
    return found


def build_config_changes(old_files: dict[str, str], new_files: dict[str, str]) -> list[str]:
    """A data directory newly added to [tool.maturin]. Its purelib and platlib land in site-packages."""
    old_lines: set[str] = set()
    for text in _named(old_files, "pyproject.toml"):
        old_lines |= _maturin_data_lines(text)
    found: list[str] = []
    for text in _named(new_files, "pyproject.toml"):
        for line in sorted(_maturin_data_lines(text) - old_lines):
            entry = f"tool.maturin {line}"
            if entry not in found:
                found.append(entry)
    return found


# Popular Rust crates used only when the release ecosystem is crates.
# They stay out of COMMON_PACKAGES so npm and PyPI scoring does not see them.
RUST_PACKAGES = {"rust_decimal", "fast_log"}


def _rust_lifecycle_edits(old_files: dict[str, str], new_files: dict[str, str]) -> int:
    """A changed non-empty build.rs, plus a proc-macro flag that was not there before."""
    count = 0
    for path in set(old_files) | set(new_files):
        if path.rsplit("/", 1)[-1].lower() != "build.rs":
            continue
        new = new_files.get(path, "")
        old = old_files.get(path, "")
        if isinstance(new, str) and new.strip() and new != old:
            count += 1
    if _proc_macro_appeared(new_files) and not _proc_macro_appeared(old_files):
        count += 1
    return count


def _proc_macro_appeared(files: dict[str, str]) -> bool:
    from hunter.crates.review import proc_macro_enabled

    for path, text in files.items():
        if path.rsplit("/", 1)[-1].lower() != "cargo.toml" or not isinstance(text, str):
            continue
        if proc_macro_enabled(text):
            return True
    return False


def _name_index(popular_names: set[str] | None) -> NameIndex:
    names = set(COMMON_PACKAGES)
    if popular_names:
        names.update(str(name).lower() for name in popular_names)
    return NameIndex(names)


def extract_features(
    old_files: dict[str, str],
    new_files: dict[str, str],
    kept: list[FileDiff],
    meta: ReleaseMeta,
    popular_names: set[str] | None = None,
) -> CodeFeatures:
    sample_parts = [item.added_text for item in kept]
    sample_parts.extend(item.new_text for item in kept if item.category == "install_scripts")
    sample = "\n".join(sample_parts)
    entropy_hits = 0
    for item in kept:
        for line in item.added_text.splitlines():
            if high_entropy_line(line):
                entropy_hits += 1
    old_deps = _manifest_deps(old_files)
    new_deps = _manifest_deps(new_files)
    fresh = sorted(new_deps - old_deps)
    gap = release_gap_hours(meta)
    credential = bool(CREDENTIAL.search(sample))
    kind = ""
    if credential:
        if SSH.search(sample):
            kind = "ssh_material"
        elif CLOUD.search(sample):
            kind = "cloud_keys"
        elif ENV_TOKEN.search(sample):
            kind = "env_tokens"
        else:
            kind = "env_tokens"
    # An empty old set means the predecessor publisher is unknown, not that it changed.
    publishers_changed = bool(meta.old_publishers) and (
        set(meta.old_publishers) != set(meta.new_publishers)
    )
    lifecycle_edits = lifecycle_edit_count(old_files, new_files)
    binary_media_changes = sum(1 for item in kept if item.category == "binary_media")
    old_hosts: set[str] = set()
    new_hosts: set[str] = set()
    for item in kept:
        old_hosts.update(unexpected_hosts(item.old_text))
        new_hosts.update(unexpected_hosts(item.added_text))
    behavior_chains, runtime_behavior_chains = find_behavior_chains(old_files, new_files, kept)
    if meta.ecosystem == "crates":
        from hunter.crates import victim_name

        names = set(RUST_PACKAGES)
        if popular_names:
            names.update(str(name).lower() for name in popular_names)
        package_victim = victim_name(meta.name, names)
        dependency_typosquats = []
        for name in fresh:
            victim = victim_name(name, names)
            if victim:
                dependency_typosquats.append(f"{name}~{victim}")
    else:
        index = _name_index(popular_names)
        package_victim = index.match(meta.name)
        dependency_typosquats = []
        for name in fresh:
            victim = index.match(name)
            if victim:
                dependency_typosquats.append(f"{name}~{victim}")
    return CodeFeatures(
        lifecycle_script_edits=lifecycle_edits,
        new_dependency_names=fresh,
        publisher_changed=publishers_changed,
        release_gap_hours=gap,
        short_release_gap=gap is not None and 0 < gap <= 6,
        high_entropy_additions=entropy_hits,
        literal_decode_exec=bool(DECODE_EXEC.search(sample)),
        literal_shell=bool(SHELL.search(sample)),
        literal_raw_ip=bool(raw_ips(sample)),
        literal_credential=credential,
        credential_kind=kind,
        install_paths=[item.path for item in kept if item.category == "install_scripts"],
        phantom_runtime_dependencies=phantom_runtime_dependencies(old_files, new_files),
        compound_install_payload=compound_install_payload(old_files, new_files),
        literal_xor=bool(XOR.search(sample)),
        literal_encoded_import=bool(ENCODED_IMPORT.search(sample)),
        literal_minified_payload=minified_side_payload(old_files, new_files),
        literal_new_host=bool(new_hosts - old_hosts),
        literal_persistence=bool(PERSISTENCE.search(sample)),
        binary_media_changes=binary_media_changes,
        entrypoint_payload=entrypoint_payload_change(old_files, new_files, meta),
        install_sidecar=install_sidecar_change(
            old_files,
            new_files,
            lifecycle_edits=lifecycle_edits,
            binary_media_changes=binary_media_changes,
        ),
        dependency_typosquats=dependency_typosquats,
        package_typosquat=f"{meta.name}~{package_victim}" if package_victim else "",
        behavior_chains=behavior_chains,
        runtime_behavior_chains=runtime_behavior_chains,
        new_binary=new_executable_binary(old_files, new_files),
        outside_package_files=outside_package_files(old_files, new_files, meta.name),
        wheel_only_files=wheel_only_files(old_files, new_files),
        build_config_changes=build_config_changes(old_files, new_files),
    )
