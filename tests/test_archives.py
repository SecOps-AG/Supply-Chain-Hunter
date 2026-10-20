import io
import tarfile
from pathlib import Path

from hunter.archives import (
    DEFAULT_FILE_READ_BYTES,
    FILE_CUT_MARKER,
    DiskTree,
    extract_archive,
    file_read_byte_cap,
    iter_file_pairs,
    read_tree,
    unpack,
)
from hunter.config import Config
from tests.archives_factory import HOSTILE_NEW, tar_bytes


def test_archive_round_trip_keeps_source(tmp_path: Path):
    root = unpack(tar_bytes(HOSTILE_NEW), tmp_path / "pkg")
    files = read_tree(root)
    assert any(path.endswith("check.js") for path in files)
    assert any("postinstall" in text for text in files.values())


def test_archive_skips_paths_that_escape(tmp_path: Path):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        data = b"outside"
        info = tarfile.TarInfo("../outside.txt")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    unpack(buffer.getvalue(), tmp_path / "safe")
    assert not (tmp_path / "outside.txt").exists()


def test_file_read_cap_defaults_to_several_megabytes(monkeypatch):
    monkeypatch.delenv("HUNTER_FILE_READ_BYTES", raising=False)
    assert file_read_byte_cap() == DEFAULT_FILE_READ_BYTES == 8 * 1024 * 1024


def test_extract_archive_marks_a_file_cut_at_the_byte_cap(monkeypatch):
    monkeypatch.setenv("HUNTER_FILE_READ_BYTES", "1000")
    text = "x" * 2_500
    files = extract_archive(tar_bytes({"package/index.js": text}))
    read = files["package/index.js"]
    assert read.endswith(FILE_CUT_MARKER)
    assert read[: -len(FILE_CUT_MARKER)] == "x" * 1000
    assert all(isinstance(path, Path) for path in files._index().values())
    files.close()


def test_extract_archive_indexes_files_under_node_modules_and_git():
    files = extract_archive(
        tar_bytes(
            {
                "package/index.js": "module.exports = 1;\n",
                "package/node_modules/left-pad/index.js": "module.exports = 2;\n",
                "package/.git/config": "[core]\n",
            }
        )
    )
    try:
        assert files["package/index.js"] == "module.exports = 1;\n"
        assert files["package/node_modules/left-pad/index.js"] == "module.exports = 2;\n"
        assert files["package/.git/config"] == "[core]\n"
    finally:
        files.close()


def test_a_file_under_the_cap_is_not_marked_cut(monkeypatch):
    monkeypatch.setenv("HUNTER_FILE_READ_BYTES", "1000")
    files = extract_archive(tar_bytes({"package/index.js": "x" * 1000}))
    assert files["package/index.js"] == "x" * 1000
    files.close()


def test_iter_file_pairs_reads_one_pair_at_a_time(tmp_path: Path):
    old_root = tmp_path / "old"
    new_root = tmp_path / "new"
    for root, marker in ((old_root, "old"), (new_root, "new")):
        (root / "package").mkdir(parents=True)
        (root / "package" / "same.js").write_text("same\n", encoding="utf-8")
        (root / "package" / "changed.js").write_text(marker + "\n", encoding="utf-8")
    seen: list[str] = []

    class Track(DiskTree):
        def __getitem__(self, key: str) -> str:
            seen.append(key)
            return super().__getitem__(key)

    pairs = iter_file_pairs(Track(old_root), Track(new_root))
    first = next(pairs)
    assert first[0] == "package/changed.js"
    assert len(seen) == 2
    second = next(pairs)
    assert second[0] == "package/same.js"
    assert len(seen) == 4
    assert list(pairs) == []


def test_default_worker_count_is_four(monkeypatch):
    monkeypatch.delenv("HUNTER_WORKERS", raising=False)
    assert Config().workers == 4
    assert Config.from_env().workers == 4


def test_archive_past_the_unpack_byte_limit_is_refused(tmp_path, monkeypatch):
    import io
    import tarfile

    import pytest

    from hunter.archives import ArchiveError, extract_archive

    monkeypatch.setenv("HUNTER_MAX_EXTRACT_BYTES", "1000")
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        data = b"\0" * 5000
        info = tarfile.TarInfo("package/zeros.bin")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    with pytest.raises(ArchiveError):
        extract_archive(buffer.getvalue())


def test_zip_past_the_unpack_file_limit_is_refused(tmp_path, monkeypatch):
    import io
    import zipfile

    import pytest

    from hunter.archives import ArchiveError, extract_archive

    monkeypatch.setenv("HUNTER_MAX_EXTRACT_FILES", "3")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for index in range(5):
            archive.writestr(f"pkg/f{index}.py", "x = 1\n")
    with pytest.raises(ArchiveError):
        extract_archive(buffer.getvalue())


def test_normal_archive_still_unpacks_under_the_limits(monkeypatch):
    import io
    import tarfile

    from hunter.archives import extract_archive

    monkeypatch.delenv("HUNTER_MAX_EXTRACT_BYTES", raising=False)
    monkeypatch.delenv("HUNTER_MAX_EXTRACT_FILES", raising=False)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        data = b"module.exports = 1;\n"
        info = tarfile.TarInfo("package/index.js")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    tree = extract_archive(buffer.getvalue())
    try:
        assert "package/index.js" in set(tree)
    finally:
        tree.close()
