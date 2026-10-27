import json
import re
import time
import urllib.error
import urllib.request
from datetime import timedelta
from pathlib import Path

import pytest

from hunter import dashboard
from hunter.config import Config
from hunter.dashboard.benchmark import load_benchmarks
from hunter.db import Database, utcnow
from hunter.service import dashboard_access, start_health

SECRET_ERROR = "POST https://hooks.example.invalid/secret-path failed"
STATIC = Path(dashboard.__file__).with_name("static")


def _seed(db: Database, now):
    """Invented releases only. Three reach Triage; one is confirmed and alerted."""
    rows = [
        ("npm", "demo-pad", "1.0.1", "benign", 0.02, []),
        ("npm", "<b>demo-html</b>", "2.0.0", "alert", 0.91, ["install_script", "network", "rule:net_oast_host"]),
        ("pypi", "demo-client", "0.3.0", "review", 0.55, ["credential_read", "partial_read"]),
        ("pypi", "demo-yaml", "5.0.0", "review", 0.48, ["network"]),
        ("npm", "old-demo", "9.9.9", "alert", 0.95, ["network"]),
    ]
    for eco, name, version, band, p, signals in rows:
        payload = {"signals": signals, "old_version": "0.0.1", "jev_model_id": "decision-model-x"}
        if "rule:net_oast_host" in signals:
            payload["rule_verdict"] = "malicious"
            payload["rule_hits"] = [{"rule": "net_oast_host", "tier": "strong", "path": "package.json", "line": 3, "matched": "<script>x</script>", "summary": "demo"}]
        when = now - timedelta(days=3) if name == "old-demo" else now - timedelta(minutes=30)
        db.save_release(eco, name, version, band, p, "malicious_intent", None, json.dumps(payload), when=when)
    t0 = now - timedelta(minutes=29)
    db.enqueue_investigation("npm:<b>demo-html</b>:2.0.0", "{}", when=t0)
    db.mark_investigation_reported("npm:<b>demo-html</b>:2.0.0", "looks bad\nVerdict: malicious", when=t0)
    db.enqueue_investigation("pypi:demo-client:0.3.0", "{}", when=t0)
    db.mark_investigation_reported("pypi:demo-client:0.3.0", "fine\nVerdict: benign", when=t0)
    db.enqueue_investigation("pypi:demo-yaml:5.0.0", "{}", when=t0)
    db.enqueue_analyst("npm:<b>demo-html</b>:2.0.0", "{}", when=t0)
    db.mark_analyst_reported("npm:<b>demo-html</b>:2.0.0", "confirmed\nVerdict: malicious", "malicious", None, when=t0)
    db.enqueue("npm:<b>demo-html</b>:2.0.0:analysis", '{"url": "https://hooks.example.invalid/secret-path"}', when=t0)
    row = db.due_outbox(when=now + timedelta(hours=1))[0]
    db.mark_retry(row["id"], 1, SECRET_ERROR, when=t0)
    db.mark_sent(row["id"], when=t0 + timedelta(seconds=5))


@pytest.fixture()
def db(tmp_path):
    database = Database(tmp_path / "hunter.sqlite3")
    _seed(database, utcnow())
    return database


def test_snapshot_counts_each_stage(db):
    snap = dashboard.snapshot(db, health={"pending_jobs": 0}, models=None, range_name="24h")
    assert snap["range"] == "24h"
    assert len(snap["buckets"]) == 24
    assert snap["scanned"]["total"] == 4  # old-demo is outside the range
    assert snap["scanned"]["by_ecosystem"] == {"npm": 2, "pypi": 2}
    assert snap["scout"]["bands"] == {"benign": 1, "alert": 1, "review": 2}
    assert snap["triage"]["total"] == 3
    assert snap["triage"]["verdicts"] == {"malicious": 1, "benign": 1, "pending": 1}
    assert snap["analyst"]["verdicts"] == {"malicious": 1}
    assert snap["webhook"]["alerts_sent"] == 1
    assert snap["confirmed"]["count"] == 1
    assert snap["confirmed"]["latest"]["name"] == "<b>demo-html</b>"
    assert snap["rules"]["top_rules"] == [["net_oast_host", 1]] or snap["rules"]["top_rules"] == [("net_oast_host", 1)]
    assert sum(snap["triage"]["series"]) == 3
    assert snap["usage"]["triage_tokens"] is None  # not recorded yet, never invented


def test_snapshot_never_returns_webhook_bodies_or_errors(db):
    snap = dashboard.snapshot(db, health={}, models=None, range_name="30d")
    text = json.dumps(snap, default=str)
    assert "secret-path" not in text
    assert "hooks.example.invalid" not in text


def test_unknown_range_falls_back_to_24h(db):
    assert dashboard.snapshot(db, health={}, models=None, range_name="1y")["range"] == "24h"


def test_findings_filters_and_pages(db):
    base = {"range": "24h"}
    assert dashboard.findings(db, base)["total"] == 3
    assert dashboard.findings(db, {**base, "scope": "flagged"})["total"] == 3
    assert dashboard.findings(db, {**base, "range": "7d"})["total"] == 3  # old-demo never reached Triage
    assert dashboard.findings(db, {**base, "range": "7d", "scope": "flagged"})["total"] == 4
    malicious = dashboard.findings(db, {**base, "verdict": "malicious"})
    assert [row["name"] for row in malicious["rows"]] == ["<b>demo-html</b>"]
    assert malicious["rows"][0]["stage"] == "webhook"
    assert dashboard.findings(db, {**base, "verdict": "triage benign"})["rows"][0]["name"] == "demo-client"
    assert dashboard.findings(db, {**base, "verdict": "in triage"})["rows"][0]["name"] == "demo-yaml"
    assert dashboard.findings(db, {**base, "ecosystem": "pypi"})["total"] == 2
    assert dashboard.findings(db, {**base, "partial": "1"})["rows"][0]["name"] == "demo-client"
    assert dashboard.findings(db, {**base, "min_p": "0.5"})["total"] == 2
    assert dashboard.findings(db, {**base, "q": "YAML"})["total"] == 1
    assert dashboard.findings(db, {**base, "rule": "net_oast_host"})["total"] == 1
    assert dashboard.findings(db, {**base, "signal": "network"})["total"] == 2
    page = dashboard.findings(db, {**base, "limit": "1", "offset": "1", "sort": "probability"})
    assert page["total"] == 3 and len(page["rows"]) == 1 and page["rows"][0]["name"] == "demo-client"
    assert dashboard.findings(db, {**base, "limit": "x"})["limit"] == 25


def test_release_detail_has_reports_but_not_webhook_text(db):
    detail = dashboard.release(db, "npm", "<b>demo-html</b>", "2.0.0")
    assert detail["triage"]["verdict"] == "malicious"
    assert "looks bad" in detail["triage"]["report"]
    assert detail["analyst"]["verdict"] == "malicious"
    assert detail["release"]["rule_hits"][0]["matched"] == "<script>x</script>"
    assert detail["webhook"] == [
        {
            "kind": "analysis",
            "status": "sent",
            "attempts": 1,
            "created_at": detail["webhook"][0]["created_at"],
            "sent_at": detail["webhook"][0]["sent_at"],
            "had_error": False,  # mark_sent clears the error; the flag is the latest attempt only
        }
    ]
    assert "secret-path" not in json.dumps(detail)
    assert dashboard.release(db, "npm", "missing", "1.0.0") is None


def test_watched_only_keeps_listed_packages(db):
    db.replace_user_watch_source("repo/requirements.txt", "requirements", [("pypi", "demo-client", "0.3.0", None)])
    snap = dashboard.snapshot(db, health={}, models=None, range_name="24h", watched_only=True, watch_mode="watched", alert_scope="watched")
    assert snap["watched_only"] is True
    assert snap["scanned"]["by_ecosystem"] == {"pypi": 1}
    assert snap["scout"]["flagged"] == 1
    assert snap["triage"]["total"] == 1
    assert snap["analyst"]["total"] == 0
    assert snap["webhook"]["alerts_total"] == 0
    assert snap["watchlist"]["total"] == 1 and snap["watchlist"]["mode"] == "watched"
    assert [row["source"] for row in snap["watchlist"]["sources"]] == ["repo/requirements.txt"]
    assert snap["watchlist"]["sources"][0]["stale"] is False

    full = dashboard.snapshot(db, health={}, models=None, range_name="24h")
    assert full["scanned"]["total"] == 4 and full["watched_only"] is False

    rows = dashboard.findings(db, {"range": "24h", "scope": "flagged", "watched": "1"})["rows"]
    assert {row["name"] for row in rows} == {"demo-client"}
    assert len(dashboard.findings(db, {"range": "24h", "scope": "flagged"})["rows"]) == 3


def test_watched_only_still_counts_decision_model_outage_notices(db):
    db.replace_user_watch_source("repo/requirements.txt", "requirements", [("pypi", "demo-client", "0.3.0", None)])
    db.enqueue("decision-model-down:2026-10-27T00:00:00Z", "{}")
    snap = dashboard.snapshot(db, health={}, models=None, range_name="24h", watched_only=True, watch_mode="watched", alert_scope="watched")
    assert snap["webhook"]["outage_notices"] == 1
    assert snap["webhook"]["alerts_total"] == 0


def test_release_carries_the_watch_block_only_when_listed(db):
    assert "watch" not in dashboard.release(db, "pypi", "demo-client", "0.3.0")["release"]
    db.replace_user_watch_source("repo/requirements.txt", "requirements", [("pypi", "demo-client", "0.3.0", None)])
    watch = dashboard.release(db, "pypi", "demo-client", "0.3.0")["release"]["watch"]
    assert watch["exact_match"] and watch["sources"] == ["repo/requirements.txt"]


def test_watchlist_api_and_watched_default(db):
    db.replace_user_watch_source("repo/requirements.txt", "requirements", [("pypi", "demo-client", "0.3.0", None)])
    server = start_health(Config(bind="127.0.0.1", port=0, watch_mode="watched", alert_scope="watched"), db, time.monotonic())
    try:
        port = server.server_address[1]
        _, _, body = _get(port, "/api/watchlist")
        payload = json.loads(body)
        assert payload["pypi"] == 1 and payload["mode"] == "watched"
        assert payload["sources"][0]["source"] == "repo/requirements.txt"
        _, _, body = _get(port, "/api/snapshot?range=24h")
        assert json.loads(body)["scanned"]["total"] == 1
        _, _, body = _get(port, "/api/snapshot?range=24h&watched=0")
        assert json.loads(body)["scanned"]["total"] == 4
        _, _, body = _get(port, "/health")
        assert json.loads(body)["user_watchlist"]["total"] == 1
    finally:
        server.shutdown()
    guarded = start_health(Config(bind="127.0.0.1", port=0, dashboard_token="t0ken"), db, time.monotonic())
    try:
        with pytest.raises(urllib.error.HTTPError) as err:
            _get(guarded.server_address[1], "/api/watchlist")
        assert err.value.code == 403
    finally:
        guarded.shutdown()


def test_static_files_are_an_allow_list():
    assert dashboard.static_file("index.html")[1].startswith("text/html")
    assert dashboard.static_file("app.js")[1].startswith("text/javascript")
    assert dashboard.static_file("github_stars.js")[1].startswith("text/javascript")
    assert dashboard.static_file("../__init__.py") is None
    assert dashboard.static_file("benchmark.py") is None


def test_header_links_to_the_github_repo():
    html = (STATIC / "index.html").read_text()
    assert 'href="https://github.com/SecOps-AG/Supply-Chain-Hunter"' in html
    assert 'id="gh-stars"' in html
    assert 'target="_blank"' in html
    assert 'src="/static/github_stars.js"' in html
    assert "https://api.github.com" in dashboard.CONTENT_SECURITY_POLICY
    assert "connect-src 'self' https://api.github.com" in dashboard.CONTENT_SECURITY_POLICY


def test_page_has_no_inline_code_and_never_writes_html():
    html = (STATIC / "index.html").read_text()
    assert not re.search(r"<script(?![^>]*\bsrc=)", html)
    assert "<style" not in html and " style=" not in html and " on" + "click=" not in html
    js = (STATIC / "app.js").read_text()
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert sink not in js


def _get(port, path, headers=None):
    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=headers or {})
    with urllib.request.urlopen(request, timeout=5) as response:
        return response.status, dict(response.headers), response.read()


def test_http_routes_serve_page_and_api(db, tmp_path):
    server = start_health(Config(bind="127.0.0.1", port=0, bench_dir=""), db, time.monotonic())
    try:
        port = server.server_address[1]
        status, headers, body = _get(port, "/")
        assert status == 200 and b"/static/app.js" in body
        assert "default-src 'self'" in headers["Content-Security-Policy"]
        assert headers["X-Content-Type-Options"] == "nosniff"
        status, headers, body = _get(port, "/static/app.css")
        assert headers["Content-Type"].startswith("text/css")
        status, _, body = _get(port, "/api/snapshot?range=1h")
        assert json.loads(body)["range"] == "1h"
        status, _, body = _get(port, "/api/findings?verdict=malicious")
        assert json.loads(body)["total"] == 1
        status, _, body = _get(port, "/api/release?ecosystem=npm&name=%3Cb%3Edemo-html%3C%2Fb%3E&version=2.0.0")
        assert json.loads(body)["analyst"]["verdict"] == "malicious"
        status, _, body = _get(port, "/api/benchmark")
        assert json.loads(body)["configured"] is False
        for missing in ("/static/../db.py", "/api/nothing", "/api/release?ecosystem=npm&name=x&version=1", "/elsewhere"):
            with pytest.raises(urllib.error.HTTPError) as err:
                _get(port, missing)
            assert err.value.code == 404
        status, _, body = _get(port, "/health")
        assert json.loads(body)["status"] == "ok"
    finally:
        server.shutdown()


def test_dashboard_token_guards_the_api(db):
    server = start_health(Config(bind="127.0.0.1", port=0, dashboard_token="t0ken"), db, time.monotonic())
    try:
        port = server.server_address[1]
        with pytest.raises(urllib.error.HTTPError) as err:
            _get(port, "/api/snapshot")
        assert err.value.code == 403
        with pytest.raises(urllib.error.HTTPError):
            _get(port, "/api/snapshot", {"Authorization": "Bearer wrong"})
        status, _, _ = _get(port, "/api/snapshot", {"Authorization": "Bearer t0ken"})
        assert status == 200
        status, _, _ = _get(port, "/")  # the page itself holds no data
        assert status == 200
    finally:
        server.shutdown()


def test_wide_bind_needs_a_token():
    assert dashboard_access(Config(bind="127.0.0.1"), None) == (True, "")
    assert dashboard_access(Config(bind="::1"), None) == (True, "")
    allowed, reason = dashboard_access(Config(bind="0.0.0.0"), None)
    assert not allowed and "HUNTER_DASHBOARD_TOKEN" in reason
    assert dashboard_access(Config(bind="0.0.0.0", dashboard_token="abc"), "Bearer abc")[0]


def test_config_reads_dashboard_env(monkeypatch):
    monkeypatch.setenv("HUNTER_BENCH_DIR", " /tmp/bench ")
    monkeypatch.setenv("HUNTER_DASHBOARD_TOKEN", "zq-dash-9f3")
    config = Config.from_env()
    assert config.bench_dir == "/tmp/bench"
    assert config.dashboard_token == "zq-dash-9f3"
    assert "zq-dash-9f3" not in repr(config)


# ---------- benchmark results ----------

def _write_run(folder: Path, *, commit="abc1234def", models=None, cases=None, extra=None):
    folder.mkdir(parents=True)
    board = {
        "product_commit": commit,
        "run_date_pt": folder.name[:10],
        "corpus_id": "demo-corpus",
        "models": models
        if models is not None
        else [
            {"model": "alpha", "backend": "demo/alpha", "cases": 3, "bad_n": 2, "clean_n": 1, "catch": 2, "catch_rate": 1.0,
             "false_flags": 0, "false_flag_rate": 0.0, "usd": 0.01, "usd_per_case": 0.0033, "input_tokens": 900, "calls": 3},
            {"model": "gamma", "backend": "skipped", "cases": 0, "catch": None, "usd": 0.0, "skip_reason": "no key"},
        ],
        "pipeline": {"scout": "alpha", "triage": "mid-x", "hits": 2, "triage_malicious": 2, "triage_tokens": "unavailable"},
        **(extra or {}),
    }
    (folder / "leaderboard.json").write_text(json.dumps(board))
    data = folder / "data"
    data.mkdir()
    for name, rows in (cases or {}).items():
        (data / f"{name}-cases.jsonl").write_text("\n".join(json.dumps(row) for row in rows) + "\nnot json\n")


def test_benchmark_unset_means_no_data():
    assert load_benchmarks("") == {"configured": False, "runs": [], "error": None}


def test_benchmark_missing_directory(tmp_path):
    result = load_benchmarks(str(tmp_path / "nope"))
    assert result["configured"] is True and result["runs"] == [] and result["error"]


def test_benchmark_reads_runs_in_order_and_keeps_skips_honest(tmp_path):
    case = {"id": "demo_case_1", "label": "malicious", "band": "deferred", "p": 0.0, "status": "ok", "to_triage": False,
            "fixture": "/private/path/demo.json", "signals": ["x"]}
    _write_run(tmp_path / "2026-10-20-run", commit="bbbbbbbcccc", cases={"alpha": [case]})
    _write_run(tmp_path / "2026-10-09-run", commit="aaaaaaabbbb")
    (tmp_path / "2026-10-10-not-a-run").mkdir()
    result = load_benchmarks(str(tmp_path))
    assert [run["id"] for run in result["runs"]] == ["2026-10-09-run", "2026-10-20-run"]
    latest = result["runs"][1]
    assert latest["product_commit_short"] == "bbbbbbb"
    alpha, gamma = latest["models"]
    assert alpha["status"] == "ok" and alpha["catch"] == 2 and alpha["deferred"] == 1
    assert alpha["output_tokens"] is None
    assert gamma["status"] == "skipped" and gamma["usd"] is None and gamma["catch_rate"] is None
    assert gamma["skip_reason"] == "no key"
    assert latest["cases"]["alpha"][0]["id"] == "demo_case_1"
    assert "fixture" not in latest["cases"]["alpha"][0]
    assert "/private/path" not in json.dumps(result)
    assert latest["pipeline"]["triage_tokens"] == "unavailable"
    assert result["runs"][0]["cases"] == {}


def test_benchmark_folder_can_be_one_run(tmp_path):
    _write_run(tmp_path / "2026-10-09-run")
    result = load_benchmarks(str(tmp_path / "2026-10-09-run"))
    assert len(result["runs"]) == 1


def test_benchmark_drops_bad_values(tmp_path):
    models = [{"model": "alpha", "catch": True, "catch_rate": "93%", "false_flags": 1, "usd": float("nan"), "calls": 2.0}]
    _write_run(tmp_path / "2026-10-09-run", models=models)
    (tmp_path / "2026-10-10-broken").mkdir()
    (tmp_path / "2026-10-10-broken" / "leaderboard.json").write_text("{not json")
    result = load_benchmarks(str(tmp_path))
    assert len(result["runs"]) == 1
    model = result["runs"][0]["models"][0]
    assert model["catch"] is None and model["catch_rate"] is None and model["usd"] is None
    assert model["false_flags"] == 1 and model["calls"] == 2


def test_benchmark_api_uses_configured_folder(db, tmp_path):
    _write_run(tmp_path / "bench" / "2026-10-09-run")
    server = start_health(Config(bind="127.0.0.1", port=0, bench_dir=str(tmp_path / "bench"), scout_model="jev"), db, time.monotonic())
    try:
        _, _, body = _get(server.server_address[1], "/api/benchmark")
    finally:
        server.shutdown()
    payload = json.loads(body)
    assert payload["configured"] is True
    assert payload["production_scout"] == "jev"
    assert payload["runs"][0]["models"][0]["model"] == "alpha"
