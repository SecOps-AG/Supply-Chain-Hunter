import json
import sys
from datetime import timedelta

from hunter.classify import classify_files
from hunter.config import Config
from hunter.db import Database, utcnow
from hunter.fixtures_io import load_fixture
from hunter.head import load_head
from hunter.investigate import drain_investigations, drain_analyst
from hunter.service import classify_job
from hunter.webhook import drain_outbox, enqueue_classification, signature_header
from pathlib import Path
from hunter.fake_jev import KeywordJev


FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "npm_palette_hook.json"


class MemoryLoader:
    def __init__(self, meta, old_files, new_files):
        self.meta = meta
        self.old_files = old_files
        self.new_files = new_files

    def load(self, ecosystem, name, version, rank):
        return self.old_files, self.new_files, self.meta


def test_one_signed_post_and_no_second_post_for_the_same_version(tmp_path):
    meta, old_files, new_files, _label = load_fixture(FIXTURE)
    db = Database(tmp_path / "hunter.sqlite3")
    secret = "test-secret"
    url = "https://alerts.example/hook"
    posts = []

    def poster(target, body, headers):
        posts.append((target, body, dict(headers)))

    config = Config(
        db_path=db.path,
        webhook_url=url,
        webhook_secret=secret,
        webhook_on_review=False,
        investigate_command=f"{sys.executable} -c \"import sys; sys.stdout.write('Verdict: malicious')\"",
        analyst_command=f"{sys.executable} -c \"import sys; sys.stdout.write('Verdict: malicious')\"",
    )
    assert db.enqueue_job(meta.ecosystem, meta.name, meta.new_version, meta.rank)
    job = db.pending_jobs()[0]
    classify_job(db, config, job, jev=KeywordJev(), loader=MemoryLoader(meta, old_files, new_files))
    assert db.due_outbox() == []
    assert drain_investigations(db, config=config) == 1
    assert db.due_outbox() == []
    assert drain_analyst(db, config=config) == 1
    assert drain_outbox(db, url=url, secret=secret, poster=poster) == 1
    # Same version again does not create another outbox row or another POST.
    classify_job(db, config, job, jev=KeywordJev(), loader=MemoryLoader(meta, old_files, new_files))
    assert drain_investigations(db, config=config) == 0
    assert drain_outbox(db, url=url, secret=secret, poster=poster) == 0
    assert len(posts) == 1
    target, body, headers = posts[0]
    assert target == url
    assert headers["X-Hunter-Signature"] == signature_header(secret, body)
    payload = json.loads(body)
    assert payload["kind"] == "smart_analysis"
    assert payload["idempotency_key"] == f"{meta.ecosystem}:{meta.name}:{meta.new_version}:analysis"
    assert payload["verdict"] == "malicious"
    assert payload["primary_band"] == "alert"
    assert payload["analysis_model_id"] == "command"
    assert "Verdict: malicious" in payload["analysis"]
    assert enqueue_classification(
        db,
        classify_files(meta=meta, old_files=old_files, new_files=new_files, jev=KeywordJev(), head=load_head()),
        webhook_on_review=False,
    ) is False


def test_outbox_retries_with_backoff_and_survives_reopen(tmp_path):
    db_path = tmp_path / "hunter.sqlite3"
    db = Database(db_path)
    when = utcnow().replace(microsecond=0)
    assert db.enqueue("npm:color-hex-pad:2.4.1", "{\"idempotency_key\":\"npm:color-hex-pad:2.4.1\"}", when=when)
    calls = {"n": 0}

    def poster(_url, _body, headers):
        calls["n"] += 1
        assert headers["X-Hunter-Signature"].startswith("sha256=")
        if calls["n"] == 1:
            raise RuntimeError("receiver down")

    assert drain_outbox(db, url="https://alerts.example/hook", secret="s", poster=poster, when=when) == 0
    reopened = Database(db_path)
    assert reopened.outbox_depth() == 1
    assert reopened.due_outbox(when) == []
    later = when + timedelta(seconds=1)
    assert drain_outbox(reopened, url="https://alerts.example/hook", secret="s", poster=poster, when=later) == 1
    assert calls["n"] == 2
    assert reopened.outbox_depth() == 0
    assert drain_outbox(reopened, url="https://alerts.example/hook", secret="s", poster=poster, when=later) == 0
