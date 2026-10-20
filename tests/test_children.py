import json

from hunter.children import apply_children, resolve_spec
from hunter.config import Config
from hunter.db import Database
from hunter.fixtures_io import load_fixture
from hunter.service import classify_job
from pathlib import Path
from tests.archives_factory import tar_bytes
from hunter.fake_jev import KeywordJev


ROOT = Path(__file__).resolve().parents[1] / "fixtures"


def test_caret_spec_resolves_inside_the_major():
    assert resolve_spec(["4.2.0", "4.2.1", "5.0.0"], "^4.2.1", "5.0.0") == "4.2.1"
    assert resolve_spec(["1.0.0"], "1.0.0", "1.0.0") == "1.0.0"


class MemoryLoader:
    def __init__(self, meta, old_files, new_files):
        self.meta = meta
        self.old_files = old_files
        self.new_files = new_files
        self.transport = None

    def load(self, ecosystem, name, version, rank):
        return self.old_files, self.new_files, self.meta


def test_child_install_hook_promotes_parent_to_alert(tmp_path):
    meta, old_files, new_files, _label = load_fixture(ROOT / "npm_phantom_manifest.json")
    child_meta, child_old, child_new, _child_label = load_fixture(ROOT / "npm_child_dropper.json")
    old_blob = tar_bytes(child_old)
    new_blob = tar_bytes(child_new)
    document = {
        "dist-tags": {"latest": "4.2.1"},
        "time": {
            "created": "2026-03-31T00:00:00.000Z",
            "4.2.0": "2026-03-31T00:00:00.000Z",
            "4.2.1": "2026-03-31T02:10:00.000Z",
        },
        "versions": {
            "4.2.0": {"version": "4.2.0", "dist": {"tarball": "https://registry.example/old.tgz"}},
            "4.2.1": {
                "version": "4.2.1",
                "scripts": {"postinstall": "node setup.js"},
                "dist": {"tarball": "https://registry.example/new.tgz"},
            },
        },
    }

    def transport(url, _timeout):
        if url.endswith("old.tgz"):
            return old_blob
        if url.endswith("new.tgz"):
            return new_blob
        return json.dumps(document).encode()

    db = Database(tmp_path / "hunter.sqlite3")
    config = Config(
        db_path=db.path,
        webhook_url="https://alerts.example/hook",
        webhook_secret="s",
        npm_registry="https://registry.example",
        inspect_dependencies=True,
        webhook_on_phantom=True,
    )
    loader = MemoryLoader(meta, old_files, new_files)
    loader.transport = transport
    assert db.enqueue_job(meta.ecosystem, meta.name, meta.new_version, meta.rank)
    classify_job(db, config, db.pending_jobs()[0], jev=KeywordJev(), loader=loader, transport=transport)
    row = db.get_release(meta.ecosystem, meta.name, meta.new_version)
    payload = json.loads(row["payload_json"])
    assert payload["band"] == "alert"
    assert payload["attack_family"] == "dependency_abuse"
    assert any(item.startswith("child_alert:codec-pad@") for item in payload["signals"])
    assert db.due_outbox() == []


def test_apply_children_does_not_promote_when_the_child_is_missing():
    meta, old_files, new_files, _label = load_fixture(ROOT / "npm_phantom_manifest.json")
    from hunter.classify import classify_files
    from hunter.head import load_head

    parent = classify_files(
        meta=meta, old_files=old_files, new_files=new_files, jev=KeywordJev(), head=load_head()
    )
    from hunter.children import ChildFinding

    finding = ChildFinding(name="codec-pad", spec="^4.2.1", error="404")
    apply_children(parent, [finding])
    assert parent.band == "review"
    assert any(item.startswith("child_unavailable:codec-pad") for item in parent.signals)
