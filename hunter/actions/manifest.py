"""Read ``uses:`` lines and an action's ``action.yml`` without a YAML library.

Only the few keys Hunter needs are read, line by line. The text is untrusted;
nothing here evaluates it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from hunter.actions import normalize_name

ACTION_FILES = ("action.yml", "action.yaml")
_USES = re.compile(r"^[ \t]*(?:-[ \t]*)?uses[ \t]*:[ \t]*['\"]?([^\s'\"#]+)", re.MULTILINE)
_TOP_KEY = re.compile(r"^[A-Za-z_][\w-]*\s*:")
_KEY = re.compile(r"^\s*(?:-\s*)?([A-Za-z_][\w-]*)\s*:\s*(.*)$")


def _value(raw: str) -> str:
    text = raw.strip()
    if text[:1] in {"'", '"'}:
        quote = text[0]
        end = text.find(quote, 1)
        return text[1:end] if end > 0 else text[1:]
    return text.split(" #", 1)[0].strip()


def uses_refs(text: str) -> list[str]:
    """Raw ``uses:`` targets in a workflow or composite action, in order."""
    return [match.group(1) for match in _USES.finditer(text or "")]


def used_actions(text: str) -> list[str]:
    """``owner/repo`` of each remote action or reusable workflow a file uses. Local and docker refs are skipped."""
    found: list[str] = []
    for ref in uses_refs(text):
        if ref.startswith(("./", "../", "docker://")) or "@" not in ref:
            continue
        name = normalize_name(ref.split("@", 1)[0])
        if name and name not in found:
            found.append(name)
    return found


def docker_refs(text: str) -> list[str]:
    return [ref for ref in uses_refs(text) if ref.startswith("docker://")]


@dataclass
class ActionManifest:
    path: str
    using: str = ""
    main: str = ""
    pre: str = ""
    post: str = ""
    image: str = ""
    uses: list[str] = field(default_factory=list)
    run_steps: int = 0

    def entry_files(self) -> list[str]:
        """Repository paths of the scripts this action runs, relative to the repository root."""
        base = PurePosixPath(self.path).parent
        found: list[str] = []
        values = [self.pre, self.main, self.post]
        if self.image and not self.image.startswith("docker://"):
            values.append(self.image)
        for value in values:
            if not value or "://" in value or value.startswith("/"):
                continue
            candidate = str(PurePosixPath(base, value))
            if candidate not in found:
                found.append(candidate)
        return found

    def image_pinned(self) -> bool:
        """True when a docker image is pinned by digest. A Dockerfile in the repo counts as pinned here."""
        if not self.image.startswith("docker://"):
            return True
        return "@sha256:" in self.image


def parse_action(path: str, text: str) -> ActionManifest:
    manifest = ActionManifest(path=path)
    in_runs = False
    for line in (text or "").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if _TOP_KEY.match(line):
            in_runs = line.split(":", 1)[0].strip() == "runs"
            continue
        if not in_runs:
            continue
        match = _KEY.match(line)
        if not match:
            continue
        key, raw = match.group(1), match.group(2)
        value = _value(raw)
        if key == "using" and not manifest.using:
            manifest.using = value.lower()
        elif key in {"main", "pre", "post"} and not getattr(manifest, key):
            setattr(manifest, key, value)
        elif key == "image" and not manifest.image:
            manifest.image = value
        elif key == "uses" and value:
            manifest.uses.append(value)
        elif key == "run":
            manifest.run_steps += 1
    return manifest


def is_action_file(path: str) -> bool:
    return PurePosixPath(path.replace("\\", "/")).name.lower() in ACTION_FILES


def action_manifests(files) -> dict[str, ActionManifest]:
    """Every ``action.yml`` / ``action.yaml`` in a tree, by path."""
    found: dict[str, ActionManifest] = {}
    for path in files:
        if is_action_file(path):
            text = files[path]
            if isinstance(text, str):
                found[path] = parse_action(path, text)
    return found
