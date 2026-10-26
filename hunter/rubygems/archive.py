"""Read a ``.gem`` as an outer tar, a safe spec, and the files in ``data.tar.gz``.

Nothing in the archive is executed. ``metadata.gz`` is YAML with Ruby object
tags. The loader builds dicts, lists, and strings, refuses aliases, and stops
at 1 MiB of uncompressed spec. ``checksums.yaml.gz`` is ignored.
"""

from __future__ import annotations

import gzip
import io
import os
import tarfile
import tempfile
from datetime import date, datetime
from pathlib import PurePosixPath

import yaml

from hunter.archives import ArchiveError, DiskTree, unpack_file

SPEC_LIMIT = 1024 * 1024
METADATA_GZIP_CAP = 2 * 1024 * 1024
_SPEC_DEPTH = 64


class GemSpecLoader(yaml.SafeLoader):
    """Safe YAML loader for a serialized gemspec. Aliases are refused."""

    def compose_node(self, parent, index):
        if self.check_event(yaml.events.AliasEvent):
            event = self.get_event()
            raise yaml.constructor.ConstructorError(None, None, "aliases are not allowed", event.start_mark)
        return super().compose_node(parent, index)


def _ruby_object(loader: GemSpecLoader, _suffix: str, node):
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node, deep=True)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    raise yaml.constructor.ConstructorError(None, None, "unsupported gem spec node", node.start_mark)


def _ruby_sym(loader: GemSpecLoader, node) -> str:
    return str(loader.construct_scalar(node)).lstrip(":")


GemSpecLoader.add_multi_constructor("!ruby/object:", _ruby_object)
GemSpecLoader.add_constructor("!ruby/sym", _ruby_sym)
GemSpecLoader.add_constructor("!ruby/symbol", _ruby_sym)


def _strings_only(value, depth: int = 0):
    """Dicts, lists, and strings. Other scalars become strings."""
    if depth > _SPEC_DEPTH:
        raise ArchiveError("gem spec is too deep")
    if isinstance(value, dict):
        return {str(key): _strings_only(item, depth + 1) for key, item in value.items()}
    if isinstance(value, list):
        return [_strings_only(item, depth + 1) for item in value]
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, str):
        return value
    raise ArchiveError("gem spec has an unsupported value")


def parse_gem_spec(blob: bytes) -> dict:
    """Parse uncompressed gemspec YAML. Aliases and oversize specs are refused."""
    if len(blob) > SPEC_LIMIT:
        raise ArchiveError("gem spec exceeds 1 MiB")
    try:
        text = blob.decode("utf-8")
    except UnicodeError as exc:
        raise ArchiveError("gem spec is not utf-8") from exc
    try:
        loaded = yaml.load(text, Loader=GemSpecLoader)
    except (yaml.YAMLError, RecursionError, ValueError) as exc:
        raise ArchiveError("gem spec could not be read") from exc
    if not isinstance(loaded, dict):
        raise ArchiveError("gem spec is not a mapping")
    return _strings_only(loaded)


def _gunzip_capped(blob: bytes, limit: int) -> bytes:
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(blob)) as handle:
            out = handle.read(limit + 1)
    except (OSError, EOFError, gzip.BadGzipFile) as exc:
        raise ArchiveError("metadata.gz is not readable") from exc
    if len(out) > limit:
        raise ArchiveError("gem spec exceeds 1 MiB")
    return out


def _refuse_member(member: tarfile.TarInfo) -> None:
    name = str(member.name or "").replace("\\", "/")
    parts = PurePosixPath(name).parts
    if member.issym() or member.islnk() or name.startswith("/") or ".." in parts:
        raise ArchiveError(f"refusing gem path {name}")


def _read_member(archive: tarfile.TarFile, member: tarfile.TarInfo, limit: int) -> bytes:
    handle = archive.extractfile(member)
    if handle is None:
        raise ArchiveError(f"gem member {member.name} is not a file")
    blob = handle.read(limit + 1)
    if len(blob) > limit:
        raise ArchiveError(f"gem member {member.name} is too large")
    return blob


def _refuse_data_tar(path) -> None:
    try:
        with tarfile.open(path, mode="r:*") as archive:
            for member in archive:
                _refuse_member(member)
    except ArchiveError:
        raise
    except (tarfile.TarError, OSError) as exc:
        raise ArchiveError(str(exc)) from exc


def extract_gem(source: bytes | os.PathLike) -> tuple[DiskTree, dict]:
    """Outer tar to ``(files, spec)``. ``data.tar.gz`` is unpacked with ``unpack_file``.

    A path that escapes the archive, a symlink, or a spec that uses YAML aliases
    is refused. The returned tree's caller closes it.
    """
    from pathlib import Path

    owned: Path | None = None
    if isinstance(source, Path):
        archive_path = source
    else:
        fd, name = tempfile.mkstemp(prefix="hunter-gem-")
        os.close(fd)
        archive_path = Path(name)
        owned = archive_path
        archive_path.write_bytes(bytes(source))
    data_path: Path | None = None
    try:
        metadata_gz = None
        try:
            with tarfile.open(archive_path, mode="r:*") as outer:
                for member in outer:
                    _refuse_member(member)
                    if not member.isfile():
                        continue
                    base = PurePosixPath(str(member.name).replace("\\", "/")).name
                    if base == "metadata.gz" and metadata_gz is None:
                        metadata_gz = _read_member(outer, member, METADATA_GZIP_CAP)
                    elif base == "data.tar.gz" and data_path is None:
                        fd, name = tempfile.mkstemp(prefix="hunter-gem-data-")
                        os.close(fd)
                        data_path = Path(name)
                        handle = outer.extractfile(member)
                        if handle is None:
                            raise ArchiveError("data.tar.gz is not a file")
                        with data_path.open("wb") as out:
                            while True:
                                chunk = handle.read(1024 * 1024)
                                if not chunk:
                                    break
                                out.write(chunk)
        except ArchiveError:
            raise
        except (tarfile.TarError, OSError) as exc:
            raise ArchiveError(str(exc)) from exc
        if metadata_gz is None or data_path is None:
            raise ArchiveError("gem is missing metadata.gz or data.tar.gz")
        spec = parse_gem_spec(_gunzip_capped(metadata_gz, SPEC_LIMIT))
        _refuse_data_tar(data_path)
        owner = tempfile.TemporaryDirectory(prefix="hunter-gem-tree-")
        try:
            unpack_file(data_path, Path(owner.name))
        except ArchiveError:
            owner.cleanup()
            raise
        except (tarfile.TarError, OSError) as exc:
            owner.cleanup()
            raise ArchiveError(str(exc)) from exc
        return DiskTree(Path(owner.name), own=owner), spec
    finally:
        if data_path is not None:
            data_path.unlink(missing_ok=True)
        if owned is not None:
            owned.unlink(missing_ok=True)
