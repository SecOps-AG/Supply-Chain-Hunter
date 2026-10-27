"""HUNTER_ALERT_SCOPE=watched: the webhook sends only for user-watchlist names, and says how they are listed.

Model calls are fake runners; no webhook is contacted.
"""

from __future__ import annotations

import json
from datetime import timedelta

from hunter.config import Config
from hunter.db import Database, utcnow
from hunter.investigate import build_evidence, drain_analyst, drain_investigations
from hunter.inventory.scope import alert_in_scope, public_publish_blocked, watch_context
from hunter.models import Classification
from hunter.webhook import build_analysis_payload, enqueue_decision_model_down, slack_analysis_text, watch_line

SHA = "0123456789abcdef0123456789abcdef01234567"
HOOK = "https://alerts.example/hook"


def _finding(name: str, version: str = "1.0.1") -> Classification:
    return Classification(
        ecosystem="npm",
        name=name,
        old_version="1.0.0",
        new_version=version,
        rank=None,
        registry_url=f"https://www.npmjs.com/package/{name}/v/{version}",
        band="review",
        malice_probability=0.62,
        jev_model_id="jev-1.13.0",
        signals=["phantom_runtime_dependency:codec-pad"],
        pass_d_ran=True,
        pass_d_agreed=True,
    )


def _queue(db: Database, finding: Classification) -> None:
    evidence = build_evidence(finding)
    assert db.enqueue_investigation(evidence["idempotency_key"], json.dumps(evidence))


def _malicious(_command, _body):
    return "Looks like a credential stealer.\nVerdict: malicious"


def _bodies(db: Database) -> dict[str, dict]:
    return {row["idempotency_key"]: json.loads(row["body"]) for row in db.due_outbox()}


def _listed(db: Database, *rows: tuple[str, str, str, int | None]) -> None:
    db.replace_user_watch_source("api/package-lock.json", "npm-lock", list(rows))


def test_analyst_alert_skips_unlisted_names_and_marks_listed_ones(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    _listed(db, ("npm", "mine", "1.0.1", 1))
    _queue(db, _finding("mine"))
    _queue(db, _finding("stranger"))
    config = Config(db_path=db.path, webhook_url=HOOK, alert_scope="watched")
    assert drain_investigations(db, config=config, runner=_malicious) == 2
    assert drain_analyst(db, config=config, runner=_malicious) == 2
    assert db.analyst_depth() == 0
    bodies = _bodies(db)
    assert set(bodies) == {"npm:mine:1.0.1:analysis"}
    watch = bodies["npm:mine:1.0.1:analysis"]["watch"]
    assert watch["listed"] and watch["direct"] and watch["exact_match"]
    assert watch["pinned_versions"] == ["1.0.1"]
    assert watch["sources"] == ["api/package-lock.json"]
    # The public record of a confirmed release is kept for both; only the webhook is scoped.
    assert {row["name"] for row in db.public_feed_items(10)} == {"mine", "stranger"}


def test_scope_all_sends_for_every_name(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    _queue(db, _finding("stranger"))
    config = Config(db_path=db.path, webhook_url=HOOK)
    drain_investigations(db, config=config, runner=_malicious)
    drain_analyst(db, config=config, runner=_malicious)
    bodies = _bodies(db)
    assert set(bodies) == {"npm:stranger:1.0.1:analysis"}
    assert "watch" not in bodies["npm:stranger:1.0.1:analysis"]


def test_triage_only_path_is_scoped_too(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    _listed(db, ("npm", "mine", "", None))
    _queue(db, _finding("mine"))
    _queue(db, _finding("stranger"))
    config = Config(db_path=db.path, webhook_url=HOOK, alert_scope="watched", analyst=False)
    assert drain_investigations(db, config=config, runner=_malicious) == 2
    assert db.investigation_depth() == 0
    bodies = _bodies(db)
    assert set(bodies) == {"npm:mine:1.0.1:analysis"}
    assert bodies["npm:mine:1.0.1:analysis"]["watch"]["exact_match"] is False


def test_slack_body_carries_the_watch_line(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    _listed(db, ("npm", "mine", "1.0.0", 0), ("npm", "mine", "0.9.0", 0))
    _queue(db, _finding("mine"))
    config = Config(db_path=db.path, webhook_url=HOOK, webhook_format="slack", alert_scope="watched")
    drain_investigations(db, config=config, runner=_malicious)
    drain_analyst(db, config=config, runner=_malicious)
    text = _bodies(db)["npm:mine:1.0.1:analysis"]["text"]
    assert "On your watchlist. Your files list this package at: 0.9.0, 1.0.0 (not this version)." in text


def test_watch_wording_never_says_safe_or_clean():
    cases = [
        ({"listed": True, "direct": True, "exact_match": True, "pinned_versions": ["1.0.1"]}, "On your watchlist (direct). Your files pin this exact version."),
        ({"listed": True, "direct": False, "exact_match": False, "pinned_versions": ["1.2.0", "1.3.1"]}, "On your watchlist. Your files list this package at: 1.2.0, 1.3.1 (not this version)."),
        ({"listed": True, "direct": False, "exact_match": False, "pinned_versions": []}, "On your watchlist. Your files list a range or no version."),
        ({"listed": True, "direct": True, "exact_match": True, "tag_ref": True, "pinned_versions": ["v4"]}, "On your watchlist (direct). Your files use this tag, which pointed at this commit."),
    ]
    for watch, expected in cases:
        line = watch_line(watch)
        assert line == expected
        assert "safe" not in line.lower() and "clean" not in line.lower()
        payload = build_analysis_payload({"ecosystem": "npm", "package": "x", "new_version": "1"}, "Verdict: malicious", analysis_model_id="m", watch=watch)
        assert expected in slack_analysis_text(payload)
    assert watch_line(None) == ""
    assert "On your watchlist" not in slack_analysis_text(
        build_analysis_payload({"ecosystem": "npm", "package": "x", "new_version": "1"}, "Verdict: malicious", analysis_model_id="m")
    )


def test_actions_versions_match_by_sha_pin_or_by_tag(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    confirmed = "v4@" + SHA[:12]
    db.replace_user_watch_source("ci.yml", "workflow", [("github-actions", "actions/checkout", SHA, 1)])
    by_sha = watch_context(db, "github-actions", "actions/checkout", confirmed)
    assert by_sha["exact_match"] and "tag_ref" not in by_sha
    db.replace_user_watch_source("ci.yml", "workflow", [("github-actions", "actions/checkout", "v4", 1)])
    by_tag = watch_context(db, "github-actions", "actions/checkout", confirmed)
    assert by_tag["exact_match"] and by_tag["tag_ref"]
    db.replace_user_watch_source("ci.yml", "workflow", [("github-actions", "actions/checkout", "v3", 1)])
    other = watch_context(db, "github-actions", "actions/checkout", confirmed)
    assert not other["exact_match"] and other["pinned_versions"] == ["v3"]
    assert watch_context(db, "github-actions", "actions/setup-node", confirmed) is None


def test_watch_context_flags_a_stale_import(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    db.replace_user_watch_source("old", "plain", [("pypi", "requests", "2.0", 1)], when=utcnow() - timedelta(days=8))
    context = watch_context(db, "pypi", "requests", "2.0")
    assert context["stale"] and context["exact_match"]


def test_scope_helpers(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    assert alert_in_scope(db, Config(), "npm", "anything")
    assert not alert_in_scope(db, Config(alert_scope="watched"), "npm", "anything")
    assert public_publish_blocked(db, Config()) is None
    assert public_publish_blocked(db, Config(watch_mode="watched"))
    db.add_user_watch("npm", "anything")
    assert alert_in_scope(db, Config(alert_scope="watched"), "npm", "anything")
    assert public_publish_blocked(db, Config())


def test_decision_model_down_alert_is_not_scoped(tmp_path):
    db = Database(tmp_path / "hunter.sqlite3")
    assert enqueue_decision_model_down(db, since="2026-10-26T00:00:00Z", failures=3, waiting=2, waiting_strong=1)
    assert set(_bodies(db)) == {"decision-model-down:2026-10-26T00:00:00Z"}
