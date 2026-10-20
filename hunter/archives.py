"""Unpack a registry archive and read it as text. Nothing in the archive is executed."""

from __future__ import annotations

import hashlib
import io
import os
import tarfile
import tempfile
import zipfile
from collections.abc import Iterator, Mapping
from pathlib import Path


class ArchiveError(ValueError):
    """The archive could not be read as package contents."""


# Safety limit for one extracted file. The chunk splitter needs the whole file,
# so this is several megabytes, not the old 200 KB sample. A file past the limit
# is marked cut and the release goes to review unread.
DEFAULT_FILE_READ_BYTES = 8 * 1024 * 1024
# Limits for one unpacked archive. Downloads are capped at 64 MiB, but a
# compressed archive can claim far more on disk (a decompression bomb). Past
# either limit the archive is refused and the release is retried, then lands in
# the human review queue. HUNTER_MAX_EXTRACT_BYTES and HUNTER_MAX_EXTRACT_FILES
# override them.
DEFAULT_MAX_EXTRACT_BYTES = 1024 * 1024 * 1024
DEFAULT_MAX_EXTRACT_FILES = 100_000
FILE_CUT_MARKER = "\n[hunter:file-cut]"
BINARY_MARKER = "[binary-or-media-file]"
MEDIA_SUFFIXES = {
    ".wav",
    ".mp3",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".bmp",
    ".ico",
    ".mp4",
    ".ogg",
    ".flac",
}
BINARY_SUFFIXES = MEDIA_SUFFIXES | {
    ".pdf",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".bin",
    ".pyc",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
}


def unpack(blob: bytes, dest: Path) -> Path:
    """Extract `blob` into `dest`. The bytes are spooled to a file first."""
    fd, name = tempfile.mkstemp(prefix="hunter-unpack-")
    os.close(fd)
    archive_path = Path(name)
    try:
        archive_path.write_bytes(blob)
        return unpack_file(archive_path, dest)
    finally:
        archive_path.unlink(missing_ok=True)


def unpack_file(archive_path: Path, dest: Path) -> Path:
    """Extract an archive that already lives on disk. Nothing inside it is executed."""
    dest.mkdir(parents=True, exist_ok=True)
    with archive_path.open("rb") as handle:
        magic = handle.read(2)
    if magic == b"PK":
        with zipfile.ZipFile(archive_path) as archive:
            _safe_zip(archive, dest)
    else:
        with tarfile.open(archive_path, mode="r:*") as archive:
            _safe_tar(archive, dest)
    return dest


def _env_limit(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def extract_limits() -> tuple[int, int]:
    """Most bytes and most files one archive may unpack to."""
    return (
        _env_limit("HUNTER_MAX_EXTRACT_BYTES", DEFAULT_MAX_EXTRACT_BYTES),
        _env_limit("HUNTER_MAX_EXTRACT_FILES", DEFAULT_MAX_EXTRACT_FILES),
    )


class _Budget:
    """Running total of what an archive has unpacked so far."""

    def __init__(self) -> None:
        self.max_bytes, self.max_files = extract_limits()
        self.bytes = 0
        self.files = 0

    def take(self, size: int) -> None:
        self.bytes += max(0, int(size))
        self.files += 1
        if self.bytes > self.max_bytes:
            raise ArchiveError(f"archive unpacks to more than {self.max_bytes} bytes")
        if self.files > self.max_files:
            raise ArchiveError(f"archive holds more than {self.max_files} files")


def _inside(dest: Path, name: str) -> bool:
    target = (dest / name).resolve()
    root = dest.resolve()
    return target != root and root in target.parents


def _safe_tar(archive: tarfile.TarFile, dest: Path) -> None:
    budget = _Budget()
    for member in archive:
        if member.issym() or member.islnk() or not _inside(dest, member.name):
            continue
        budget.take(member.size if member.isfile() else 0)
        try:
            archive.extract(member, dest, set_attrs=False, filter="data")
        except TypeError:
            archive.extract(member, dest, set_attrs=False)


def _safe_zip(archive: zipfile.ZipFile, dest: Path) -> None:
    budget = _Budget()
    for info in archive.infolist():
        if info.is_dir() or not _inside(dest, info.filename):
            continue
        budget.take(info.file_size)
        archive.extract(info, dest)


def extract_archive(source: bytes | Path) -> DiskTree:
    """Extract one archive onto disk and return a tree that reads a file when asked.

    A bytes source is spooled to a temp file first, so the extractor does not
    keep a second copy in a memory buffer. The caller still owns a Path source.
    """
    owned_archive: Path | None = None
    if isinstance(source, Path):
        archive_path = source
    else:
        fd, name = tempfile.mkstemp(prefix="hunter-blob-")
        os.close(fd)
        archive_path = Path(name)
        owned_archive = archive_path
        archive_path.write_bytes(source)
    owner = tempfile.TemporaryDirectory(prefix="hunter-archive-")
    try:
        try:
            unpack_file(archive_path, Path(owner.name))
        except (tarfile.TarError, zipfile.BadZipFile, OSError) as exc:
            raise ArchiveError(str(exc)) from exc
    except Exception:
        owner.cleanup()
        raise
    finally:
        if owned_archive is not None:
            owned_archive.unlink(missing_ok=True)
    return DiskTree(Path(owner.name), own=owner)


def executable_header_name(sample: bytes) -> str:
    """ELF, PE, or thin Mach-O. Empty when the bytes are not one of those."""
    if sample.startswith(b"\x7fELF"):
        return "elf"
    if sample.startswith(b"MZ"):
        return "pe"
    if len(sample) >= 4 and sample[:4] in (
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe",
    ):
        return "mach-o"
    return ""


def describe_binary(path: Path, sample: bytes, size: int) -> str:
    """Metadata for a file whose bytes are not shown to the classifier."""
    suffix = path.suffix.lower()
    kind = "media" if suffix in MEDIA_SUFFIXES else "binary"
    digest = hashlib.sha256(sample).hexdigest()
    header = executable_header_name(sample) or "none"
    return (
        f"{BINARY_MARKER}\n"
        f"kind: {kind}\n"
        f"bytes: {size}\n"
        f"sampled_bytes: {len(sample)}\n"
        f"sha256_prefix: {digest}\n"
        f"extension: {suffix or 'none'}\n"
        f"header: {header}\n"
    )


def file_read_byte_cap() -> int:
    """Bytes kept from one extracted text file. `HUNTER_FILE_READ_BYTES` overrides the default."""
    raw = os.environ.get("HUNTER_FILE_READ_BYTES", "").strip()
    if not raw:
        return DEFAULT_FILE_READ_BYTES
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"HUNTER_FILE_READ_BYTES={raw!r} is not a number") from exc
    if value <= 0:
        raise ValueError("HUNTER_FILE_READ_BYTES must be greater than zero")
    return value


UTF16_PROBE_BYTES = 4096
UTF16_NUL_SHARE = 0.9


def decode_utf16(sample: bytes) -> str | None:
    """Text of a UTF-16 file, or None when the bytes are not clean UTF-16.

    A file counts as UTF-16 when it starts with a UTF-16 byte order mark, or when
    at least 90% of the odd (or even) bytes near the start are NUL and the whole
    sample decodes without errors.
    """
    if len(sample) < 2:
        return None
    body = sample[: len(sample) - (len(sample) % 2)]
    if body.startswith(b"\xff\xfe") or body.startswith(b"\xfe\xff"):
        codec = "utf-16"
    else:
        probe = body[:UTF16_PROBE_BYTES]
        half = len(probe) // 2
        if half < 4:
            return None
        if probe[1::2].count(0) >= UTF16_NUL_SHARE * half:
            codec = "utf-16-le"
        elif probe[0::2].count(0) >= UTF16_NUL_SHARE * half:
            codec = "utf-16-be"
        else:
            return None
    try:
        text = body.decode(codec)
    except UnicodeDecodeError:
        return None
    if "\x00" in text:
        return None
    return text


def read_file_text_info(path: Path) -> tuple[str, bool]:
    """File text as `read_file_text` gives it, and whether it was decoded from UTF-16."""
    size = path.stat().st_size
    limit = file_read_byte_cap()
    with path.open("rb") as handle:
        sample = handle.read(limit)
    suffix = path.suffix.lower()
    if suffix in BINARY_SUFFIXES:
        return describe_binary(path, sample, size), False
    utf16 = False
    if b"\x00" in sample:
        decoded = decode_utf16(sample)
        if decoded is None:
            return describe_binary(path, sample, size), False
        text, utf16 = decoded, True
    else:
        text = sample.decode("utf-8", errors="replace")
    if len(sample) < size:
        return text + FILE_CUT_MARKER, utf16
    return text, utf16


def read_file_text(path: Path) -> str:
    """Read one extracted file. Binary and media files become a short marker.

    UTF-16 text is decoded, so a UTF-16 script is read like any other.
    A text file longer than the byte cap is cut and ends with FILE_CUT_MARKER
    so the release is sent to review unread instead of scored as a full read.
    """
    return read_file_text_info(path)[0]


class DiskTree(Mapping[str, str]):
    """Extracted package files. Each file is read when asked, then dropped.

    The index stores paths only. File text is not kept on the tree.
    """

    def __init__(self, root: Path, *, own: tempfile.TemporaryDirectory[str] | None = None, empty: bool = False):
        self.root = root
        self._own = own
        self._empty = empty
        self._paths: dict[str, Path] | None = None
        self._closed = False
        # Paths read so far that were decoded from UTF-16.
        self.utf16_paths: set[str] = set()

    @classmethod
    def empty(cls) -> DiskTree:
        return cls(Path("."), empty=True)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._paths = {}
        owner = self._own
        self._own = None
        if owner is not None:
            owner.cleanup()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            return

    def _index(self) -> dict[str, Path]:
        if self._closed or self._empty:
            return {}
        if self._paths is None:
            found: dict[str, Path] = {}
            if self.root.exists():
                for path in self.root.rglob("*"):
                    if not path.is_file():
                        continue
                    relative = str(path.relative_to(self.root)).replace("\\", "/")
                    found[relative] = path
            self._paths = found
        return self._paths

    def __getitem__(self, key: str) -> str:
        text, utf16 = read_file_text_info(self._index()[key])
        if utf16:
            self.utf16_paths.add(key)
        return text

    def __iter__(self) -> Iterator[str]:
        return iter(self._index())

    def __len__(self) -> int:
        return len(self._index())


class PathView(Mapping[str, str]):
    """Renamed paths over a backing tree. Text is loaded one path at a time."""

    def __init__(self, files: Mapping[str, str], keys: dict[str, str]):
        self._files = files
        self._keys = keys

    def __getitem__(self, key: str) -> str:
        return self._files[self._keys[key]]

    @property
    def utf16_paths(self) -> set[str]:
        backing = getattr(self._files, "utf16_paths", None) or set()
        return {key for key, source in self._keys.items() if source in backing}

    def __iter__(self) -> Iterator[str]:
        return iter(self._keys)

    def __len__(self) -> int:
        return len(self._keys)


def align_tree(
    files: Mapping[str, str],
    *,
    ecosystem: str = "",
    name: str = "",
    version: str | None = None,
) -> Mapping[str, str]:
    """Same path alignment as the release diff, without copying file text."""
    if not files:
        return files
    from hunter.triage import _align_one

    pointers = {path: path for path in files}
    aligned = _align_one(pointers, ecosystem=ecosystem, name=name, version=version)
    mapping = {str(key): str(value) for key, value in aligned.items()}
    if set(mapping) == set(files) and all(mapping[key] == key for key in mapping):
        return files
    return PathView(files, mapping)


def aligned_release_trees(
    old_files: Mapping[str, str],
    new_files: Mapping[str, str],
    *,
    ecosystem: str = "",
    name: str = "",
    old_version: str | None = None,
    new_version: str | None = None,
) -> tuple[Mapping[str, str], Mapping[str, str]]:
    """Align both sides. File bodies stay on the backing tree until a path is read."""
    return (
        align_tree(old_files, ecosystem=ecosystem, name=name, version=old_version),
        align_tree(new_files, ecosystem=ecosystem, name=name, version=new_version),
    )


def iter_file_pairs(
    old_files: Mapping[str, str],
    new_files: Mapping[str, str],
) -> Iterator[tuple[str, str, str]]:
    """Yield `(path, old_text, new_text)` one path at a time."""
    for path in sorted(set(old_files) | set(new_files)):
        yield path, old_files.get(path, ""), new_files.get(path, "")


def close_trees(*trees: object) -> None:
    for tree in trees:
        close = getattr(tree, "close", None)
        if callable(close):
            close()


def read_tree(root: Path) -> DiskTree:
    """Index `root`. File text is read when a path is asked for, not stored here."""
    return DiskTree(root)


def _member_key(name: str) -> str:
    text = name.replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return text


def read_archive_member(blob: bytes, name: str) -> str | None:
    """Read one text member in full. Accepts ``name`` or ``package/name``.

    Symlinks, hard links, and any other path are ignored. This does not apply
    the file read cap.
    """
    wanted = {name, f"package/{name}"}
    try:
        if blob[:2] == b"PK":
            payload = _zip_member(blob, wanted)
        else:
            payload = _tar_member(blob, wanted)
    except (tarfile.TarError, zipfile.BadZipFile, OSError) as exc:
        raise ArchiveError(str(exc)) from exc
    if payload is None:
        return None
    return payload.decode("utf-8")


def _tar_member(blob: bytes, wanted: set[str]) -> bytes | None:
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as archive:
        chosen = None
        for member in archive.getmembers():
            key = _member_key(member.name)
            if key not in wanted or not member.isfile():
                continue
            if member.issym() or member.islnk():
                continue
            if chosen is None or key == min(wanted):
                chosen = member
                if key == min(wanted):
                    break
        if chosen is None:
            return None
        extracted = archive.extractfile(chosen)
        if extracted is None:
            return None
        return extracted.read()


def _zip_member(blob: bytes, wanted: set[str]) -> bytes | None:
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        chosen = None
        for info in archive.infolist():
            key = _member_key(info.filename)
            if key not in wanted or info.is_dir():
                continue
            if chosen is None or key == min(wanted):
                chosen = info
                if key == min(wanted):
                    break
        if chosen is None:
            return None
        return archive.read(chosen)
