"""GitHub Actions watcher: tag reads, baseline, signals, review, routing and output.

Every GitHub call is faked. Tarballs are built in memory from made-up files;
nothing is downloaded and nothing is run.
"""

from __future__ import annotations

import json
import logging
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import timedelta

import pytest

from archives_factory import tar_bytes
from hunter.actions import (
    ECOSYSTEM,
    floating_major,
    full_version,
    is_prerelease,
    normalize_name,
    release_version,
    split_version,
)
from hunter.actions.github import (
    GitHubClient,
    RefList,
    ls_refs_body,
    parse_ls_refs,
    tags_query,
)
from hunter.actions.manifest import parse_action, used_actions
from hunter.actions.poller import MAX_MOVE_EVENTS, diff_tags, events_for, poll_actions
from hunter.actions.review import content_signals, review_trees
from hunter.actions.signals import EventFacts, event_facts, predecessor
from hunter.actions.watchlist import build_actions_watchlist, github_repo_from_url, load_top_actions, probe_ecosyste
from hunter.registry import FeedError
from hunter.config import Config
from hunter.db import Database, iso, utcnow
from hunter.investigate import drain_analyst, drain_investigations
from hunter.models import ReleaseMeta
from hunter.public_feed import alert_summary, alert_title, alerts_from_rows, public_alert_from_evidence
from hunter.rules.scope import file_classes
from hunter.service import (
    ReleaseLoader,
    _refresh_actions_watchlist_safely,
    check_ecosyste,
    classify_job,
    health_payload,
    serve,
    start_health,
)
from hunter.webhook import drain_outbox

SHA = {key: (key * 40)[:40] for key in "abcdef0123456789"}


def _pkt(text: str) -> bytes:
    data = text.encode()
    return f"{len(data) + 4:04x}".encode() + data


class FakeGitHub:
    """Stands in for GitHubClient. Tags per repo, compare answers, commits and files are set by the test."""

    def __init__(self, tags=None, *, token: str = "", head: str = "main"):
        self.tags = {name: dict(value) for name, value in (tags or {}).items()}
        self.token = token
        self.head = head
        self.branches: dict[str, dict[str, str]] = {}
        self.compares: dict[tuple[str, str, str], str] = {}
        self.commits: dict[tuple[str, str], dict] = {}
        self.files: dict[tuple[str, str], str] = {}
        self.workflows: dict[str, list[str]] = {}
        self.calls: list[str] = []

    @property
    def has_token(self) -> bool:
        return bool(self.token)

    def ls_refs(self, name, prefixes=None):
        self.calls.append(f"ls_refs {name} {prefixes}")
        if prefixes == ["refs/heads/"]:
            return RefList(branches=dict(self.branches.get(name, {self.head: SHA["f"]})))
        if name not in self.tags:
            return None
        return RefList(tags=dict(self.tags[name]), default_branch=self.head)

    def tags_graphql(self, names):
        self.calls.append(f"graphql {len(names)}")
        return {name: RefList(tags=dict(self.tags[name]), complete=False) if name in self.tags else None for name in names}

    def compare(self, name, base, head):
        self.calls.append(f"compare {name} {base} {head}")
        return self.compares.get((name, base, head))

    def commit(self, name, sha):
        return self.commits.get((name, sha))

    def raw_file(self, name, ref, path):
        return self.files.get((name, path))

    def workflow_uses(self, names, batch=20):
        return {name: self.workflows.get(name, []) for name in names}

    def tarball_url(self, name, sha):
        return f"https://codeload.example/{name}/tar.gz/{sha}"


def _config(tmp_path, **extra) -> Config:
    return Config(db_path=tmp_path / "hunter.sqlite3", actions=True, **extra)


def _watch(db: Database, *names: str) -> None:
    db.replace_watchlist(ECOSYSTEM, [(name, rank, 0) for rank, name in enumerate(names, start=1)])


# --- names and tags -----------------------------------------------------------


def test_names_and_versions():
    assert normalize_name("Actions/Checkout") == "actions/checkout"
    assert normalize_name("github/codeql-action/init") == "github/codeql-action"
    assert normalize_name("https://github.com/tj-actions/changed-files.git") == "tj-actions/changed-files"
    assert normalize_name("./local-action") is None
    assert normalize_name("only-owner") is None
    assert release_version("v4", SHA["a"]) == "v4@aaaaaaaaaaaa"
    assert split_version("v4@aaaaaaaaaaaa") == ("v4", "aaaaaaaaaaaa")
    assert full_version("v1.2.3") == (1, 2, 3)
    assert full_version("1.2.3-rc.1") == (1, 2, 3)
    assert full_version("v4") is None
    assert is_prerelease("1.2.3-rc.1") and not is_prerelease("v1.2.3")
    assert floating_major("v4") == 4 and floating_major("v4.2") == 4 and floating_major("v4.2.1") is None


def test_github_repo_from_package_urls():
    assert github_repo_from_url("git+https://github.com/psf/requests.git") == "psf/requests"
    assert github_repo_from_url("git@github.com:org/tool.git") == "org/tool"
    assert github_repo_from_url("https://gitlab.com/org/tool") is None
    assert github_repo_from_url("org/tool", shorthand=True) == "org/tool"
    assert github_repo_from_url("github:org/tool", shorthand=True) == "org/tool"


def test_ls_refs_request_and_parse():
    body = ls_refs_body(["refs/tags/", "HEAD"])
    assert body.startswith(_pkt("command=ls-refs\n") + b"0001")
    assert body.endswith(b"0000")
    stream = (
        _pkt(f"{SHA['1']} HEAD symref-target:refs/heads/main\n")
        + _pkt(f"{SHA['2']} refs/tags/v1\n")
        + _pkt(f"{SHA['3']} refs/tags/v1.0.0 peeled:{SHA['4']}\n")
        + b"0000"
    )
    refs = parse_ls_refs(stream)
    assert refs.default_branch == "main"
    assert refs.tags == {"v1": SHA["2"], "v1.0.0": SHA["4"]}
    assert refs.complete


def test_client_reads_tags_over_git_without_a_token():
    seen = {}

    def fetch(method, url, body, headers, timeout):
        seen.update(method=method, url=url, headers=headers)
        return 200, _pkt(f"{SHA['2']} refs/tags/v2\n") + b"0000"

    refs = GitHubClient("", fetch=fetch).ls_refs("owner/tool")
    assert refs.tags == {"v2": SHA["2"]}
    assert seen["method"] == "POST"
    assert seen["url"] == "https://github.com/owner/tool.git/git-upload-pack"
    assert seen["headers"]["Git-Protocol"] == "version=2"
    assert "Authorization" not in seen["headers"]
    assert GitHubClient("", fetch=lambda *a: (404, b"")).ls_refs("owner/gone") is None


def test_client_graphql_peels_annotated_tags():
    answer = {
        "data": {
            "r0": {
                "defaultBranchRef": {"name": "main"},
                "refs": {
                    "totalCount": 2,
                    "nodes": [
                        {"name": "v1", "target": {"__typename": "Commit", "oid": SHA["1"]}},
                        {
                            "name": "v1.0.0",
                            "target": {"__typename": "Tag", "oid": SHA["9"], "target": {"__typename": "Commit", "oid": SHA["2"]}},
                        },
                    ],
                },
            },
            "r1": None,
        }
    }
    sent = {}

    def fetch(method, url, body, headers, timeout):
        sent.update(url=url, headers=headers, body=json.loads(body))
        return 200, json.dumps(answer).encode()

    found = GitHubClient("tok", fetch=fetch).tags_graphql(["owner/tool", "owner/gone"])
    assert found["owner/tool"].tags == {"v1": SHA["1"], "v1.0.0": SHA["2"]}
    assert found["owner/tool"].complete
    assert found["owner/gone"] is None
    assert sent["url"] == "https://api.github.com/graphql"
    assert sent["headers"]["Authorization"] == "Bearer tok"
    assert 'r0: repository(owner: "owner", name: "tool")' in sent["body"]["query"]
    assert "TAG_COMMIT_DATE" in tags_query(["a/b"])


# --- manifests ------------------------------------------------------------------


def test_used_actions_and_action_manifest():
    workflow = """
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - uses: "github/codeql-action/init@v3"  # comment
      - uses: ./local
      - uses: docker://alpine:3
      - name: x
        uses: org/reusable/.github/workflows/build.yml@main
"""
    assert used_actions(workflow) == ["actions/checkout", "github/codeql-action", "org/reusable"]
    manifest = parse_action(
        "sub/action.yml",
        """name: demo
inputs:
  main:
    description: not the runs key
runs:
  using: 'node20'
  pre: 'setup.js'
  main: 'dist/index.js'
  post: dist/cleanup.js # comment
""",
    )
    assert manifest.using == "node20"
    assert manifest.entry_files() == ["sub/setup.js", "sub/dist/index.js", "sub/dist/cleanup.js"]
    composite = parse_action(
        "action.yml",
        "runs:\n  using: composite\n  steps:\n    - uses: other/thing@v1\n    - run: echo hi\n      shell: bash\n",
    )
    assert composite.uses == ["other/thing@v1"] and composite.run_steps == 1
    docker = parse_action("action.yml", "runs:\n  using: docker\n  image: docker://ghcr.io/o/i:latest\n")
    assert not docker.image_pinned()


def test_action_yml_is_its_own_rule_scope():
    assert file_classes("action.yml") == frozenset({"action", "workflow"})
    assert file_classes("nested/action.yaml") == frozenset({"action", "workflow"})


# --- watchlist ------------------------------------------------------------------


def test_top_actions_are_ranked_by_dependents_and_merged_by_repo():
    pages = {
        1: [
            {"name": "actions/checkout", "repository_url": "https://github.com/actions/checkout", "dependent_repos_count": 900},
            {"name": "github/codeql-action/init", "repository_url": "https://github.com/github/codeql-action", "dependent_repos_count": 300},
            {"name": "github/codeql-action/analyze", "repository_url": "https://github.com/github/codeql-action", "dependent_repos_count": 500},
            {"name": "small/one", "dependent_repos_count": 10},
        ],
        2: [],
    }

    def transport(url, timeout):
        page = int(url.rsplit("page=", 1)[1])
        return json.dumps(pages.get(page, [])).encode()

    top, subpaths = load_top_actions(10, "https://top.example/list", transport)
    assert top == [("actions/checkout", 900), ("github/codeql-action", 500), ("small/one", 10)]
    assert subpaths["github/codeql-action"] == {"init", "analyze"}


def test_watchlist_adds_package_workflows_and_one_nested_level(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    db.replace_watchlist("npm", [("left-pad", 1, 1)])
    db.replace_watchlist("pypi", [("requests", 1, 1)])
    config = Config(db_path=db.path, actions_top_n=5, actions_extra=("Owner/Pinned",))

    def transport(url, timeout):
        if "top.example" in url or "ecosyste" in url:
            page = int(url.rsplit("page=", 1)[1])
            rows = [{"name": "actions/checkout", "dependent_repos_count": 50}] if page == 1 else []
            return json.dumps(rows).encode()
        if url.endswith("/left-pad/latest"):
            return json.dumps({"repository": {"url": "git+https://github.com/stevemao/left-pad.git"}}).encode()
        if url.endswith("/requests/json"):
            return json.dumps({"info": {"project_urls": {"Source": "https://github.com/psf/requests"}}}).encode()
        raise AssertionError(url)

    config.actions_top_url = "https://top.example/list"
    client = FakeGitHub(token="tok")
    client.workflows = {
        "psf/requests": ["steps:\n  - uses: pypa/gh-action-pypi-publish@release/v1\n  - uses: actions/checkout@v4\n"],
        "stevemao/left-pad": ["steps:\n  - uses: actions/setup-node@v4\n"],
    }
    client.files = {("pypa/gh-action-pypi-publish", "action.yml"): "runs:\n  using: composite\n  steps:\n    - uses: nested/helper@v2\n"}
    rows, meta = build_actions_watchlist(db, config, transport, client)
    names = [row[0] for row in rows]
    assert names[0] == "owner/pinned"
    assert names[1] == "actions/checkout"
    assert set(names) == {"owner/pinned", "actions/checkout", "pypa/gh-action-pypi-publish", "actions/setup-node", "nested/helper"}
    sources = {row[0]: row[1] for row in meta}
    assert sources["actions/checkout"] == "packages,top"
    assert sources["nested/helper"] == "nested"


def test_watchlist_without_a_token_skips_package_repos(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    db.replace_watchlist("npm", [("left-pad", 1, 1)])
    config = Config(db_path=db.path, actions_top_url="https://top.example/list")

    def transport(url, timeout):
        page = int(url.rsplit("page=", 1)[1])
        return json.dumps([{"name": "actions/checkout", "dependent_repos_count": 5}] if page == 1 else []).encode()

    rows, _meta = build_actions_watchlist(db, config, transport, FakeGitHub())
    assert [row[0] for row in rows] == ["actions/checkout"]


# --- poller and baseline ---------------------------------------------------------


def test_first_poll_records_tags_without_events_then_moves_and_new_tags_queue_jobs(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = _config(tmp_path)
    _watch(db, "owner/tool")
    client = FakeGitHub({"owner/tool": {"v1": SHA["1"], "v1.0.0": SHA["1"], "v0.9.0": SHA["0"]}})
    assert poll_actions(db, config, client) == 0
    assert db.pending_count() == 0
    assert set(db.action_tags("owner/tool")) == {"v1", "v1.0.0", "v0.9.0"}

    client.tags["owner/tool"].update({"v1.0.0": SHA["e"], "v1.1.0": SHA["2"]})
    del client.tags["owner/tool"]["v0.9.0"]
    assert poll_actions(db, config, client) == 2
    jobs = {(row["name"], row["version"]) for row in db.pending_jobs()}
    assert jobs == {("owner/tool", release_version("v1.0.0", SHA["e"])), ("owner/tool", release_version("v1.1.0", SHA["2"]))}
    moved = db.action_event("owner/tool", release_version("v1.0.0", SHA["e"]))
    assert moved["kind"] == "moved" and moved["old_sha"] == SHA["1"] and moved["new_sha"] == SHA["e"]
    kinds = sorted(item["kind"] for item in db.action_moves("owner/tool"))
    assert kinds == ["deleted", "moved", "new"]
    assert "v0.9.0" not in db.action_tags("owner/tool")
    # Nothing changed: no new jobs.
    assert poll_actions(db, config, client) == 0


def test_a_missing_repository_is_an_error_not_an_event(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    _watch(db, "owner/gone")
    assert poll_actions(db, _config(tmp_path), FakeGitHub()) == 0
    assert db.action_state("owner/gone")["last_error"] == "repository not found or not public"


def test_an_action_not_polled_for_days_is_recorded_again_silently(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = _config(tmp_path)
    _watch(db, "owner/tool")
    client = FakeGitHub({"owner/tool": {"v1": SHA["1"]}})
    poll_actions(db, config, client, now=utcnow() - timedelta(days=5))
    client.tags["owner/tool"]["v1"] = SHA["2"]
    assert poll_actions(db, config, client) == 0
    assert db.action_tags("owner/tool")["v1"][0] == SHA["2"]


def test_with_a_token_new_actions_seed_over_git_and_known_ones_use_graphql(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = _config(tmp_path)
    _watch(db, "owner/tool")
    client = FakeGitHub({"owner/tool": {"v1": SHA["1"]}}, token="tok")
    poll_actions(db, config, client)
    assert any(call.startswith("ls_refs owner/tool") for call in client.calls)
    client.calls.clear()
    client.tags["owner/tool"]["v1"] = SHA["2"]
    assert poll_actions(db, config, client) == 1
    assert client.calls == ["graphql 1"]


def test_a_tag_burst_queues_only_the_most_used_tags():
    stored = {f"v1.0.{i}": (SHA["1"], "2026-01-01T00:00:00Z") for i in range(10)}
    stored["v1"] = (SHA["1"], "2026-01-01T00:00:00Z")
    refs = RefList(tags={tag: SHA["e"] for tag in stored})
    added, moved, deleted = diff_tags(stored, refs)
    assert not added and not deleted and len(moved) == 11
    events = events_for(stored, added, moved)
    assert len(events) == MAX_MOVE_EVENTS
    assert events[0]["tag"] == "v1"
    assert events[1]["tag"] == "v1.0.9"
    assert all(event["moves_in_poll"] == 11 for event in events)


# --- signals -------------------------------------------------------------------


def _event(kind, tag, new_sha, *, old_sha=None, moves=1, first_seen="2026-01-01T00:00:00Z", seen="2026-10-13T00:00:00Z"):
    return {
        "kind": kind,
        "tag": tag,
        "old_sha": old_sha,
        "new_sha": new_sha,
        "moves_in_poll": moves,
        "tag_first_seen_at": first_seen,
        "seen_at": seen,
    }


def _tags(**pairs):
    return {tag.replace("_", "."): (sha, "2026-01-01T00:00:00Z") for tag, sha in pairs.items()}


def test_a_moved_full_version_tag_is_reviewed():
    client = FakeGitHub()
    client.compares[("o/t", SHA["1"], SHA["e"])] = "diverged"
    client.compares[("o/t", "main", SHA["e"])] = "diverged"
    tags = _tags(v1_0_0=SHA["e"], v1=SHA["1"])
    facts = event_facts(client, "o/t", _event("moved", "v1.0.0", SHA["e"], old_sha=SHA["1"], moves=4), tags, "main")
    assert {"action_semver_tag_moved", "action_many_tags_moved", "action_tag_rewritten", "action_tag_off_branch"} <= set(
        facts.signals
    )
    assert facts.plan == "review"


def test_a_quick_retag_is_medium_only():
    client = FakeGitHub()
    client.compares[("o/t", SHA["1"], SHA["2"])] = "ahead"
    client.compares[("o/t", "main", SHA["2"])] = "behind"
    tags = _tags(v1_0_0=SHA["2"])
    event = _event("moved", "v1.0.0", SHA["2"], old_sha=SHA["1"], first_seen="2026-10-13T00:00:00Z", seen="2026-10-13T00:20:00Z")
    facts = event_facts(client, "o/t", event, tags, "main")
    assert facts.signals == ["action_semver_retagged_quickly"]
    assert facts.plan == "read"


def test_a_major_tag_that_follows_the_newest_release_is_stored_without_a_download():
    client = FakeGitHub()
    tags = _tags(v4=SHA["3"], v4_1_0=SHA["2"], v4_2_0=SHA["3"])
    facts = event_facts(client, "o/t", _event("moved", "v4", SHA["3"], old_sha=SHA["2"]), tags, "main")
    assert facts.signals == ["action_major_tag_followed_release"]
    assert facts.plan == "store"
    assert not [call for call in client.calls if call.startswith("compare")]


def test_a_major_tag_moved_to_an_untagged_commit_off_branch_is_reviewed():
    client = FakeGitHub()
    client.compares[("o/t", SHA["2"], SHA["9"])] = "ahead"
    client.compares[("o/t", "main", SHA["9"])] = "ahead"
    client.branches["o/t"] = {"main": SHA["2"], "releases/v4": SHA["2"]}
    client.compares[("o/t", "releases/v4", SHA["9"])] = "ahead"
    tags = _tags(v4=SHA["9"], v4_1_0=SHA["2"])
    facts = event_facts(client, "o/t", _event("moved", "v4", SHA["9"], old_sha=SHA["2"]), tags, "main")
    assert "action_major_tag_not_release" in facts.signals
    assert "action_tag_off_branch" in facts.signals
    assert facts.plan == "review"
    assert any("releases/v4" in call for call in client.calls)


def test_a_tag_on_a_release_branch_is_not_off_branch():
    client = FakeGitHub()
    client.compares[("o/t", "main", SHA["9"])] = "diverged"
    client.branches["o/t"] = {"main": SHA["2"], "releases/v4": SHA["8"]}
    client.compares[("o/t", "releases/v4", SHA["9"])] = "behind"
    tags = _tags(v4=SHA["9"])
    facts = event_facts(client, "o/t", _event("moved", "v4", SHA["9"], old_sha=SHA["2"]), tags, "main")
    assert "action_tag_off_branch" not in facts.signals


def test_new_tags_diff_against_the_previous_release_or_are_stored():
    client = FakeGitHub()
    tags = _tags(v1_0_0=SHA["1"], v1_1_0=SHA["2"], v2_0_0=SHA["3"], v1=SHA["2"])
    facts = event_facts(client, "o/t", _event("new", "v1.2.0", SHA["4"], first_seen=None), {**tags, "v1.2.0": (SHA["4"], "2026-10-13T00:00:00Z")}, "main")
    assert facts.old_tag == "v1.1.0" and facts.old_sha == SHA["2"] and facts.plan == "read"
    first = event_facts(client, "o/t", _event("new", "v1.0.0", SHA["1"], first_seen=None), {"v1.0.0": (SHA["1"], "2026-10-13T00:00:00Z")}, "main")
    assert first.signals == ["action_first_release"] and first.plan == "store"
    floating = event_facts(client, "o/t", _event("new", "v2", SHA["3"], first_seen=None), tags, "main")
    assert "action_same_commit_as_tag" in floating.signals and floating.plan == "store"
    assert predecessor("v2.0.0", tags) == "v1.1.0"


def test_commit_signals_need_a_token():
    client = FakeGitHub(token="tok")
    client.compares[("o/t", "main", SHA["4"])] = "behind"
    client.commits[("o/t", SHA["2"])] = {"verified": True, "committer_login": "maintainer"}
    client.commits[("o/t", SHA["4"])] = {"verified": False, "committer_login": "stranger"}
    tags = _tags(v1_1_0=SHA["2"])
    facts = event_facts(client, "o/t", _event("new", "v1.2.0", SHA["4"], first_seen=None), tags, "main")
    assert {"action_signing_dropped", "action_committer_changed"} <= set(facts.signals)
    assert facts.plan == "read"


# --- content review --------------------------------------------------------------


def _meta(version="v1.0.0@eeeeeeeeeeee", old="v1.0.0@111111111111") -> ReleaseMeta:
    return ReleaseMeta(ecosystem=ECOSYSTEM, name="o/t", new_version=version, old_version=old, registry_url="https://github.com/o/t/releases/tag/v1.0.0")


def test_content_signals_read_action_yml_and_the_shape_of_the_change():
    old = {
        "action.yml": "runs:\n  using: node20\n  main: dist/index.js\n",
        "src/main.ts": "export function run() {}\n",
        "dist/index.js": "function run(){}\n",
    }
    new = {
        "action.yml": "runs:\n  using: node20\n  pre: dist/setup.js\n  main: dist/index.js\n",
        "src/main.ts": "export function run() {}\n",
        "dist/index.js": "function run(){fetch('https://x.example')}\n",
        "dist/setup.js": "x()\n",
    }
    diffs = {"action.yml": "d", "dist/index.js": "d", "dist/setup.js": "d"}
    found = content_signals(old, new, diffs)
    assert "action_pre_post_added" in found
    assert "action_dist_without_source" in found


def test_content_signals_skip_node_runtime_bumps_and_dependency_rebuilds():
    old = {
        "action.yml": "runs:\n  using: 'node20'\n  main: dist/index.js\n",
        "src/main.ts": "export function run() {}\n",
        "package-lock.json": "{}\n",
        "dist/index.js": "function run(){}\n",
    }
    bumped = dict(old)
    bumped["action.yml"] = "runs:\n  using: 'node24'\n  main: dist/index.js\n"
    bumped["package-lock.json"] = '{"lockfileVersion": 3}\n'
    bumped["dist/index.js"] = "function run(){ return 1 }\n"
    found = content_signals(old, bumped, {"action.yml": "d", "package-lock.json": "d", "dist/index.js": "d"})
    assert "action_entry_changed" not in found
    assert "action_dist_without_source" not in found

    composite = dict(old)
    composite["action.yml"] = "runs:\n  using: composite\n  steps:\n    - run: ./go.sh\n      shell: bash\n"
    assert "action_entry_changed" in content_signals(old, composite, {"action.yml": "d"})


def test_docker_signal_fires_only_when_an_image_stops_being_pinned():
    def docker(image):
        return {"action.yml": f"runs:\n  using: docker\n  image: {image}\n"}

    tag_bump = content_signals(docker("docker://ghcr.io/o/t:v1.0.0"), docker("docker://ghcr.io/o/t:v1.1.0"), {"action.yml": "d"})
    assert "action_docker_unpinned" not in tag_bump
    unpinned = content_signals(
        docker("docker://ghcr.io/o/t@sha256:" + "a" * 64), docker("docker://ghcr.io/o/t:latest"), {"action.yml": "d"}
    )
    assert "action_docker_unpinned" in unpinned
    from_dockerfile = content_signals(docker("Dockerfile"), docker("docker://evil.example/t:1"), {"action.yml": "d"})
    assert "action_docker_unpinned" in from_dockerfile


def test_review_routes_a_rule_hit_with_a_strong_signal_and_keeps_quiet_changes_benign():
    old = {"tool-x/action.yml": "runs:\n  using: node20\n  main: dist/index.js\n", "tool-x/dist/index.js": "run();\n"}
    hostile = dict(old)
    hostile["tool-x/dist/index.js"] = (
        "run();\nconst pid = find('Runner.Worker');\nconst m = read(`/proc/${pid}/maps`);\n"
        "const out = grep(m, /\"isSecret\":true/);\n"
    )
    facts = EventFacts(signals=["action_semver_tag_moved"], plan="review", old_sha=SHA["1"], new_sha=SHA["e"])
    row = review_trees(_meta(), old, hostile, facts, {"tag": "v1.0.0"})
    assert row.band == "review" and row.needs_llm_review
    assert "rule:gha_runner_memory" in row.signals and "rule:gha_secret_marker" in row.signals
    assert row.action_ref == {"tag": "v1.0.0"}

    quiet = dict(old)
    quiet["tool-x/dist/index.js"] = "run();\nlog('done');\n"
    calm = review_trees(_meta(), old, quiet, EventFacts(plan="read", new_sha=SHA["e"]), {"tag": "v1.0.1"})
    assert calm.band == "benign" and not calm.needs_llm_review


# --- end to end ------------------------------------------------------------------


class _Loader(ReleaseLoader):
    def __init__(self, config, github, archives):
        self.config = config
        self.github = github
        self.archives = archives
        self.transport = self.fetch

    def fetch(self, url, timeout):
        sha = url.rsplit("/", 1)[1]
        return tar_bytes({f"tool-{sha[:7]}/{path}": text for path, text in self.archives[sha].items()})


def _verdict_command(verdict: str) -> str:
    return f"{sys.executable} -c \"import sys; sys.stdout.write('Verdict: {verdict}')\""


def test_a_moved_tag_goes_through_triage_and_analyst_to_the_webhook_and_feed(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = _config(
        tmp_path,
        webhook_url="https://alerts.example/hook",
        webhook_secret="s",
        investigate_command=_verdict_command("malicious"),
        analyst_command=_verdict_command("malicious"),
    )
    _watch(db, "o/t")
    github = FakeGitHub({"o/t": {"v1": SHA["1"], "v1.0.0": SHA["1"]}})
    poll_actions(db, config, github, now=utcnow() - timedelta(hours=3))
    github.tags["o/t"] = {"v1": SHA["e"], "v1.0.0": SHA["e"]}
    github.compares[("o/t", SHA["1"], SHA["e"])] = "diverged"
    assert poll_actions(db, config, github) == 2
    archives = {
        SHA["1"]: {"action.yml": "runs:\n  using: node20\n  main: index.js\n", "index.js": "run();\n"},
        SHA["e"]: {
            "action.yml": "runs:\n  using: node20\n  main: index.js\n",
            "index.js": "run();\nconst pid = find('Runner.Worker');\nread(`/proc/${pid}/mem`);\n",
        },
    }
    loader = _Loader(config, github, archives)
    for job in db.pending_jobs():
        classify_job(db, config, job, jev=None, loader=loader, transport=loader.transport)
    version = release_version("v1.0.0", SHA["e"])
    row = db.get_release(ECOSYSTEM, "o/t", version)
    payload = json.loads(row["payload_json"])
    assert payload["band"] == "review"
    assert payload["action"]["old_sha"] == SHA["1"] and payload["action"]["kind"] == "moved"
    assert "action_semver_tag_moved" in payload["signals"]
    assert "rule:gha_runner_memory" in payload["signals"]
    assert db.investigation_depth() == 2
    assert drain_investigations(db, config=config) == 2
    assert drain_analyst(db, config=config) == 2
    posts = []
    assert drain_outbox(db, url=config.webhook_url, secret="s", poster=lambda *args: posts.append(args)) == 2
    bodies = [json.loads(body) for _url, body, _headers in posts]
    sent = next(body for body in bodies if body["new_version"] == version)
    assert sent["kind"] == "smart_analysis" and sent["verdict"] == "malicious"
    assert sent["action"]["new_sha"] == SHA["e"]
    feed = alerts_from_rows(db.public_feed_items(10))
    item = next(alert for alert in feed if alert.version == version)
    assert item.registry_url == "https://github.com/o/t/releases/tag/v1.0.0"
    assert alert_title(item) == f"Malicious GitHub Action: o/t {version}"
    assert f"Pin workflows to the previous commit ({SHA['1'][:12]})" in alert_summary(item)


def test_a_benign_major_tag_move_is_stored_without_triage(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = _config(tmp_path, investigate_command=_verdict_command("benign"))
    _watch(db, "o/t")
    github = FakeGitHub({"o/t": {"v4": SHA["1"], "v4.0.0": SHA["1"]}})
    poll_actions(db, config, github)
    github.tags["o/t"] = {"v4": SHA["2"], "v4.0.0": SHA["1"], "v4.1.0": SHA["2"]}
    poll_actions(db, config, github)
    archives = {
        SHA["1"]: {"action.yml": "runs:\n  using: node20\n  main: index.js\n", "index.js": "run();\n"},
        SHA["2"]: {"action.yml": "runs:\n  using: node20\n  main: index.js\n", "index.js": "run();\nlog('v2');\n"},
    }
    loader = _Loader(config, github, archives)
    for job in db.pending_jobs():
        classify_job(db, config, job, jev=None, loader=loader, transport=loader.transport)
    major = json.loads(db.get_release(ECOSYSTEM, "o/t", release_version("v4", SHA["2"]))["payload_json"])
    assert major["band"] == "benign" and major["signals"] == ["action_major_tag_followed_release"]
    release = json.loads(db.get_release(ECOSYSTEM, "o/t", release_version("v4.1.0", SHA["2"]))["payload_json"])
    assert release["band"] == "benign" and release["old_version"] == release_version("v4.0.0", SHA["1"])
    assert db.investigation_depth() == 0
    assert db.pending_count() == 0


def test_a_failed_download_is_retried(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = _config(tmp_path)
    _watch(db, "o/t")
    github = FakeGitHub({"o/t": {"v1.0.0": SHA["1"]}})
    poll_actions(db, config, github)
    github.tags["o/t"]["v1.1.0"] = SHA["2"]
    poll_actions(db, config, github)
    loader = _Loader(config, github, {})

    def broken(url, timeout):
        raise ConnectionResetError("reset")

    loader.transport = broken
    job = db.pending_jobs()[0]
    classify_job(db, config, job, jev=None, loader=loader, transport=broken)
    assert db.get_release(ECOSYSTEM, "o/t", job["version"])["band"] == "deferred"
    assert db.retry_depth() == 1


# --- output and settings ------------------------------------------------------------


def test_public_feed_accepts_actions_and_keeps_the_github_link_only():
    evidence = {
        "ecosystem": "github-actions",
        "package": "o/t",
        "new_version": "v1@eeeeeeeeeeee",
        "old_version": "v1@111111111111",
        "registry_url": "https://github.com/o/t/releases/tag/v1",
        "attack_family": "credential_theft",
    }
    alert = public_alert_from_evidence(evidence)
    assert alert is not None and alert.registry_url.startswith("https://github.com/")
    evidence["registry_url"] = "https://evil.example/o/t"
    assert public_alert_from_evidence(evidence).registry_url == ""


def test_config_reads_the_actions_settings(monkeypatch):
    monkeypatch.setenv("HUNTER_ACTIONS", "on")
    monkeypatch.setenv("HUNTER_GITHUB_TOKEN", "ghp_example")
    monkeypatch.setenv("HUNTER_ACTIONS_EXTRA", "Owner/One, owner/two owner/one bad")
    monkeypatch.setenv("HUNTER_ACTIONS_SCOUT", "1")
    config = Config.from_env()
    assert config.actions and config.github_token == "ghp_example"
    assert config.actions_extra == ("owner/one", "owner/two")
    assert config.actions_scout and config.actions_scout_per_day == 100
    assert "ghp_example" not in repr(config)


def _top_body() -> bytes:
    return json.dumps(
        [{"name": "actions/checkout", "repository_url": "https://github.com/actions/checkout", "dependent_repos_count": 9}]
    ).encode()


def _raise_oserror(url, timeout):
    raise OSError("x" * 500)


def _raise_feed(url, timeout):
    raise FeedError("connection refused")


def test_ecosyste_probe_accepts_a_json_list_whose_first_row_is_a_repo():
    config = Config(actions_top_url="https://top.example/list")
    calls = []

    def transport(url, timeout):
        calls.append(url)
        assert timeout == 10
        assert url.startswith("https://top.example/list?")
        assert "page=1" in url
        assert "npm" not in url and "pypi.org" not in url
        return _top_body()

    result = probe_ecosyste(config, transport)
    assert calls == [calls[0]]
    assert result["ok"] is True
    assert result["error"] is None
    assert str(result["checked_at"]).endswith("Z")


def test_ecosyste_probe_reports_non_json_and_connection_failure():
    config = Config(actions_top_url="https://top.example/list")
    bad = probe_ecosyste(config, lambda url, timeout: b"<html>nope</html>")
    assert bad["ok"] is False
    assert bad["error"] == "actions top list is not JSON"
    assert str(bad["checked_at"]).endswith("Z")

    down = probe_ecosyste(config, _raise_oserror)
    assert down["ok"] is False
    assert down["error"] is not None
    assert len(str(down["error"])) <= 200
    assert str(down["error"]).startswith("x")

    refused = probe_ecosyste(config, _raise_feed)
    assert refused["ok"] is False
    assert refused["error"] == "connection refused"

    empty = probe_ecosyste(config, lambda url, timeout: b"[]")
    assert empty["ok"] is False
    assert empty["error"] == "actions top list has no owner/repo"
    # A later good row does not count. The first row has to be owner/repo.
    later = probe_ecosyste(
        config,
        lambda url, timeout: json.dumps([{"name": "not-a-repo"}, {"name": "actions/checkout"}]).encode(),
    )
    assert later["ok"] is False


def test_health_reports_actions_counts_when_on(tmp_path, caplog):
    db = Database(tmp_path / "hunter.sqlite3")
    _watch(db, "o/t")
    config = _config(tmp_path, actions_top_url="https://top.example/list")
    with caplog.at_level(logging.WARNING):
        stored = check_ecosyste(config, lambda url, timeout: _top_body())
    assert stored["ok"] is True
    payload = health_payload(db, 0.0, config=config)
    block = payload["github_actions"]
    assert block["watched"] == 1
    assert block["token"] is False
    assert block["ecosyste_ok"] is True
    assert block["ecosyste_checked_at"] == stored["checked_at"]
    assert block["ecosyste_error"] is None
    assert "github_actions" not in health_payload(db, 0.0, config=Config(db_path=db.path))

    with caplog.at_level(logging.WARNING):
        failed = check_ecosyste(config, lambda url, timeout: b"not-json")
    assert failed["ok"] is False
    again = health_payload(db, 0.0, config=config)["github_actions"]
    assert again["ecosyste_ok"] is False
    assert again["ecosyste_checked_at"]
    assert again["ecosyste_error"]
    assert "ecosyste.ms actions probe failed" in caplog.text


def test_watchlist_refresh_probes_ecosyste_before_rebuilding(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    config = _config(tmp_path, actions_top_url="https://top.example/list", actions_from_packages=False)
    calls = []

    def transport(url, timeout):
        calls.append(url)
        assert "npm" not in url and "pypi" not in url
        page = int(url.rsplit("page=", 1)[1])
        if page == 1:
            return _top_body()
        return b"[]"

    _refresh_actions_watchlist_safely(db, config, transport, FakeGitHub())
    assert calls and "page=1" in calls[0]
    assert health_payload(db, 0.0, config=config)["github_actions"]["ecosyste_ok"] is True
    seen = len(calls)
    _refresh_actions_watchlist_safely(db, config, transport, FakeGitHub())
    assert len(calls) == seen


def test_serve_answers_health_when_the_ecosyste_probe_fails(tmp_path, monkeypatch):
    # serve() attaches the process-wide daily log handler. Put the previous
    # handlers back so later tests still get a log file in their own directory.
    root = logging.getLogger()
    previous = list(root.handlers)
    previous_level = root.level
    ready = threading.Event()
    pypi_polled = threading.Event()
    found = {}

    def spy(config, db, started, meter=None):
        server = start_health(config, db, started, meter)
        found["port"] = server.server_address[1]
        ready.set()
        return server

    monkeypatch.setattr("hunter.service.start_health", spy)

    class Feed:
        def last_serial(self):
            pypi_polled.set()
            return 1

        def since(self, _serial):
            return []

    def transport(url, timeout):
        raise OSError("connection refused")

    stop = threading.Event()
    body = {}

    def watcher():
        try:
            if not ready.wait(5):
                return
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{found['port']}/health", timeout=1) as response:
                        payload = json.load(response)
                except (OSError, urllib.error.URLError, json.JSONDecodeError, TimeoutError):
                    time.sleep(0.05)
                    continue
                if payload.get("github_actions", {}).get("ecosyste_error"):
                    body.update(payload)
                    break
                time.sleep(0.05)
            pypi_polled.wait(5)
        finally:
            stop.set()

    threading.Thread(target=watcher, daemon=True).start()
    try:
        serve(
            _config(tmp_path, bind="127.0.0.1", port=0, skip_npm=True, actions_top_url="https://top.example/list"),
            stop=stop,
            jev=object(),
            feed=Feed(),
            transport=transport,
        )
    finally:
        for handler in list(root.handlers):
            if handler not in previous:
                handler.close()
                root.removeHandler(handler)
        root.handlers.clear()
        for handler in previous:
            root.addHandler(handler)
        root.setLevel(previous_level)
    assert body["status"] == "ok"
    assert body["github_actions"]["ecosyste_ok"] is False
    assert "connection refused" in body["github_actions"]["ecosyste_error"]
    assert pypi_polled.is_set()


def test_actions_scout_has_its_own_daily_limit(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    assert db.take_action_scout("2026-10-13", 2)
    assert db.take_action_scout("2026-10-13", 2)
    assert not db.take_action_scout("2026-10-13", 2)
    assert db.take_action_scout("2026-10-14", 2)


@pytest.mark.parametrize("stamp", [iso(utcnow())])
def test_last_poll_lists_actions_only_once_it_has_polled(tmp_path, stamp):
    db = Database(tmp_path / "hunter.sqlite3")
    assert set(db.last_poll()) == {"pypi", "npm"}
    db.mark_poll_success(ECOSYSTEM)
    assert set(db.last_poll()) == {"pypi", "npm", ECOSYSTEM}


def test_a_major_tag_does_not_follow_a_release_tag_that_moved_in_the_same_poll():
    client = FakeGitHub()
    client.compares[("o/t", SHA["1"], SHA["e"])] = "ahead"
    client.compares[("o/t", "main", SHA["e"])] = "behind"
    tags = _tags(v1=SHA["e"], v1_0_0=SHA["e"])
    event = _event("moved", "v1", SHA["e"], old_sha=SHA["1"], moves=2)
    alone = event_facts(client, "o/t", event, tags, "main")
    assert alone.signals == ["action_major_tag_followed_release"]
    together = event_facts(client, "o/t", event, tags, "main", frozenset({"v1", "v1.0.0"}))
    assert "action_major_tag_not_release" in together.signals


def test_scout_reads_new_tags_only_when_switched_on_and_within_the_daily_limit(tmp_path):
    from hunter.fake_jev import KeywordJev

    db = Database(tmp_path / "hunter.sqlite3")
    config = _config(tmp_path, actions_scout=True, actions_scout_per_day=1, smart_analysis=False)
    _watch(db, "o/t")
    github = FakeGitHub({"o/t": {"v1.0.0": SHA["1"]}})
    poll_actions(db, config, github)
    github.tags["o/t"].update({"v1.1.0": SHA["2"], "v1.2.0": SHA["3"]})
    poll_actions(db, config, github)
    archives = {
        SHA["1"]: {"action.yml": "runs:\n  using: node20\n  main: index.js\n", "index.js": "run();\n"},
        SHA["2"]: {"action.yml": "runs:\n  using: node20\n  main: index.js\n", "index.js": "run();\nlog(1);\n"},
        SHA["3"]: {"action.yml": "runs:\n  using: node20\n  main: index.js\n", "index.js": "run();\nlog(2);\n"},
    }
    loader = _Loader(config, github, archives)
    for job in db.pending_jobs():
        classify_job(db, config, job, jev=KeywordJev(), loader=loader, transport=loader.transport)
    models = {
        json.loads(db.get_release(ECOSYSTEM, "o/t", release_version(tag, sha))["payload_json"])["jev_model_id"]
        for tag, sha in (("v1.1.0", SHA["2"]), ("v1.2.0", SHA["3"]))
    }
    assert "deterministic" in models
    assert len(models) == 2
