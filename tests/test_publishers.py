"""Predecessor publishers, and an unknown old publisher is not a change."""

import json

from hunter.children import _load_pair
from hunter.config import Config
from hunter.features import extract_features
from hunter.models import ReleaseMeta
from hunter.service import ReleaseLoader
from tests.archives_factory import tar_bytes


def _meta(**kwargs) -> ReleaseMeta:
    values = dict(
        ecosystem="npm",
        name="widget",
        new_version="1.0.1",
        old_version="1.0.0",
        rank=4,
        registry_url="https://example.test/widget",
    )
    values.update(kwargs)
    return ReleaseMeta(**values)


def test_empty_old_publishers_is_not_a_change():
    features = extract_features({}, {}, [], _meta(new_publishers=frozenset({"ada"})))
    assert features.publisher_changed is False


def test_a_filled_predecessor_that_differs_is_a_change():
    features = extract_features(
        {},
        {},
        [],
        _meta(old_publishers=frozenset({"ada"}), new_publishers=frozenset({"bea"})),
    )
    assert features.publisher_changed is True


def test_the_same_publishers_are_not_a_change():
    features = extract_features(
        {},
        {},
        [],
        _meta(old_publishers=frozenset({"ada"}), new_publishers=frozenset({"ada"})),
    )
    assert features.publisher_changed is False


def _npm_document() -> dict:
    return {
        "time": {
            "1.0.0": "2026-01-01T00:00:00.000Z",
            "1.0.1": "2026-02-01T00:00:00.000Z",
        },
        "versions": {
            "1.0.0": {
                "dist": {"tarball": "https://registry.example/old.tgz"},
                "_npmUser": {"name": "Ada"},
                "maintainers": [{"name": "Ada"}],
            },
            "1.0.1": {
                "dist": {"tarball": "https://registry.example/new.tgz"},
                "_npmUser": {"name": "Bea"},
                "maintainers": [{"name": "Bea"}],
            },
        },
    }


def _transport(document):
    old_blob = tar_bytes({"package/index.js": "function add(a, b) { return a + b; }\n"})
    new_blob = tar_bytes({"package/index.js": "function add(a, b) { return a + b; }\n"})

    def transport(url, _timeout):
        if str(url).endswith("old.tgz"):
            return old_blob
        if str(url).endswith("new.tgz"):
            return new_blob
        return json.dumps(document).encode()

    return transport


def test_npm_loader_fills_old_publishers_from_the_predecessor():
    loader = ReleaseLoader(Config(npm_registry="https://registry.example"), _transport(_npm_document()))
    _old, _new, meta = loader.load_versions("npm", "widget", "1.0.0", "1.0.1")
    try:
        assert meta.old_publishers == frozenset({"ada"})
        assert meta.new_publishers == frozenset({"bea"})
    finally:
        _old.close()
        _new.close()


def test_npm_loader_leaves_old_publishers_empty_when_the_predecessor_has_none():
    document = _npm_document()
    document["versions"]["1.0.0"] = {"dist": {"tarball": "https://registry.example/old.tgz"}}
    loader = ReleaseLoader(Config(npm_registry="https://registry.example"), _transport(document))
    _old, _new, meta = loader.load_versions("npm", "widget", "1.0.0", "1.0.1")
    try:
        assert meta.old_publishers == frozenset()
        assert meta.new_publishers == frozenset({"bea"})
    finally:
        _old.close()
        _new.close()


def test_child_loader_fills_old_publishers_from_the_predecessor():
    parent = _meta()
    _old, _new, meta = _load_pair(
        _npm_document(),
        "widget",
        "1.0.1",
        "1.0.0",
        parent,
        _transport(_npm_document()),
        8_000_000,
    )
    try:
        assert meta.old_publishers == frozenset({"ada"})
        assert meta.new_publishers == frozenset({"bea"})
    finally:
        _old.close()
        _new.close()


def _pypi_document(old_files, new_files) -> dict:
    return {
        "info": {"author": "Project Author"},
        "releases": {"1.0.0": old_files, "1.0.1": new_files},
    }


def _file(url: str, **extra) -> dict:
    return {
        "packagetype": "sdist",
        "filename": url.rsplit("/", 1)[-1],
        "url": url,
        "upload_time_iso_8601": "2026-01-01T00:00:00Z",
        **extra,
    }


def _pypi_loader(document):
    blob = tar_bytes({"pkg/__init__.py": "x = 1\n"})

    def transport(url, _timeout):
        if str(url).endswith(".tar.gz"):
            return blob
        return json.dumps(document).encode()

    return ReleaseLoader(Config(pypi_base="https://pypi.example/pypi"), transport)


def test_pypi_project_author_does_not_count_as_a_predecessor_publisher():
    document = _pypi_document(
        [_file("https://files.example/old.tar.gz")],
        [_file("https://files.example/new.tar.gz")],
    )
    loader = _pypi_loader(document)
    _old, _new, meta = loader.load_versions("pypi", "pkg", "1.0.0", "1.0.1")
    try:
        assert meta.old_publishers == frozenset()
        assert meta.new_publishers == frozenset({"project author"})
    finally:
        _old.close()
        _new.close()


def test_pypi_file_uploaders_fill_both_sides():
    document = _pypi_document(
        [_file("https://files.example/old.tar.gz", uploader="Ada")],
        [_file("https://files.example/new.tar.gz", uploader={"username": "Bea"})],
    )
    loader = _pypi_loader(document)
    _old, _new, meta = loader.load_versions("pypi", "pkg", "1.0.0", "1.0.1")
    try:
        assert meta.old_publishers == frozenset({"ada"})
        assert meta.new_publishers == frozenset({"bea"})
    finally:
        _old.close()
        _new.close()


def test_pypi_uploader_on_only_one_side_stays_unknown():
    document = _pypi_document(
        [_file("https://files.example/old.tar.gz", uploader="Ada")],
        [_file("https://files.example/new.tar.gz")],
    )
    loader = _pypi_loader(document)
    _old, _new, meta = loader.load_versions("pypi", "pkg", "1.0.0", "1.0.1")
    try:
        assert meta.old_publishers == frozenset()
        assert "ada" in meta.new_publishers
    finally:
        _old.close()
        _new.close()
