"""Scout spend ledger and the test spend cap. Made-up usage numbers; no network."""

import threading
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from hunter.classify import classification_incomplete, classify_files
from hunter.config import Config
from hunter.db import Database
from hunter.jev import JevClient
from hunter.models import ReleaseMeta
from hunter.scout_model import ScoutModelUnavailable, Usage
from hunter.service import health_payload
from hunter.spend import SpendMeter, cap_from_env, pacific_day, price_key, prices_from_env


class Clock:
    def __init__(self, moment: datetime):
        self.moment = moment

    def __call__(self) -> datetime:
        return self.moment


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "spend.sqlite3")
    yield database
    database.close()


def _meter(db, cap=None, clock=None, stop=None) -> SpendMeter:
    return SpendMeter(
        db,
        cap_usd=cap,
        clock=clock or Clock(datetime(2026, 10, 3, 18, 0, tzinfo=timezone.utc)),
        stop=stop,
        wait_seconds=0.01,
    )


def test_pacific_day_rolls_over_at_local_midnight():
    assert pacific_day(datetime(2026, 10, 4, 6, 59, tzinfo=timezone.utc)) == "2026-10-03"
    assert pacific_day(datetime(2026, 10, 4, 7, 0, tzinfo=timezone.utc)) == "2026-10-04"


def test_record_prices_reported_input_tokens(db):
    meter = _meter(db)
    assert meter.record("jev", "typesafe-ai/jev", Usage(1_000_000, 900)) == pytest.approx(0.042)
    assert meter.record("clef", "clef", Usage(1_000_000, 0)) == pytest.approx(0.24)
    assert meter.record("clef", "clef-flash", Usage(1_000_000, 0)) == pytest.approx(0.038)
    rows = {row["model"]: row for row in db.scout_usage_rows("2026-10-03")}
    assert rows["typesafe-ai/jev"]["calls"] == 1
    assert rows["typesafe-ai/jev"]["output_tokens"] == 900
    assert meter.spent_today() == pytest.approx(0.042 + 0.24 + 0.038)


def test_calls_add_up_per_day_and_model(db):
    clock = Clock(datetime(2026, 10, 3, 18, 0, tzinfo=timezone.utc))
    meter = _meter(db, clock=clock)
    meter.record("jev", "jev-1.13.0", Usage(500_000, 0))
    meter.record("jev", "jev-1.13.0", Usage(500_000, 0))
    clock.moment += timedelta(days=1)
    meter.record("jev", "jev-1.13.0", Usage(250_000, 0))
    first = db.scout_usage_rows("2026-10-03")[0]
    assert first["calls"] == 2
    assert first["input_tokens"] == 1_000_000
    assert db.scout_usage_rows("2026-10-04")[0]["calls"] == 1


def test_missing_usage_falls_back_to_the_local_estimate(db):
    meter = _meter(db)
    usd = meter.record("jev", "jev-1.13.0", Usage(), state={"diff_excerpt": "x" * 4_000}, questions={"a": {}})
    row = db.scout_usage_rows()[0]
    assert row["estimated_calls"] == 1
    assert row["input_tokens"] > 0
    assert usd > 0


def test_no_cap_never_stops(db):
    meter = _meter(db)
    meter.record("clef", "clef", Usage(100_000_000, 0))
    assert meter.stopped() is False
    meter.before_call()


def test_cap_stops_and_does_not_resume_at_midnight(db):
    clock = Clock(datetime(2026, 10, 3, 18, 0, tzinfo=timezone.utc))
    meter = _meter(db, cap=1.0, clock=clock)
    meter.record("clef", "clef", Usage(3_000_000, 0))
    assert meter.stopped() is False
    meter.record("clef", "clef", Usage(2_000_000, 0))
    assert meter.stopped() is True
    clock.moment += timedelta(days=2)
    assert meter.spent_today() == 0
    assert meter.stopped() is True
    assert db.scout_spend_stop()["day"] == "2026-10-03"


def test_a_new_cap_value_clears_the_stop(db):
    clock = Clock(datetime(2026, 10, 3, 18, 0, tzinfo=timezone.utc))
    _meter(db, cap=1.0, clock=clock).record("clef", "clef", Usage(5_000_000, 0))
    assert _meter(db, cap=1.0, clock=clock).stopped() is True
    raised = _meter(db, cap=5.0, clock=clock)
    assert raised.stopped() is False
    assert db.scout_spend_stop() is None


def test_shutdown_while_stopped_fails_the_call_instead_of_dropping_it(db):
    stop = threading.Event()
    stop.set()
    meter = _meter(db, cap=0.01, stop=stop)
    meter.record("clef", "clef", Usage(1_000_000, 0))
    with pytest.raises(ScoutModelUnavailable, match="spend_cap_reached"):
        meter.before_call()


def test_cap_setting(monkeypatch):
    monkeypatch.delenv("HUNTER_SCOUT_DAILY_USD_CAP", raising=False)
    assert cap_from_env() is None
    monkeypatch.setenv("HUNTER_SCOUT_DAILY_USD_CAP", "0")
    assert cap_from_env() is None
    monkeypatch.setenv("HUNTER_SCOUT_DAILY_USD_CAP", "2.50")
    assert cap_from_env() == 2.5
    assert Config.from_env().scout_daily_usd_cap == 2.5
    monkeypatch.setenv("HUNTER_SCOUT_DAILY_USD_CAP", "two dollars")
    with pytest.raises(ValueError, match="HUNTER_SCOUT_DAILY_USD_CAP"):
        cap_from_env()


def test_price_settings(monkeypatch):
    monkeypatch.setenv("HUNTER_CLEF_USD_PER_M_INPUT", "0.30")
    prices = prices_from_env()
    assert prices["clef"] == 0.30
    assert prices["jev"] == 0.042
    assert price_key("clef", "@cf/cloudflare/clef-flash") == "clef-flash"
    assert price_key("jev", "jev-1.13.0") == "jev"


class FakeSdk:
    def __init__(self):
        self.calls = 0

    def system_one(self, *, state, questions, model):
        del state, model
        self.calls += 1
        return SimpleNamespace(
            model="jev-1.13.0",
            nouls={key: SimpleNamespace(noul=0.05) for key in questions},
            choices={},
            scores={},
            usage=SimpleNamespace(input_tokens=2_000, output_tokens=1),
        )


def _jev_with(meter) -> tuple[JevClient, FakeSdk]:
    client = JevClient(api_key="test-key", model="jev-1.13.0", retries=1)
    sdk = FakeSdk()
    client._client = sdk
    client.meter = meter
    return client, sdk


def _meta() -> ReleaseMeta:
    return ReleaseMeta(
        ecosystem="npm",
        name="widget",
        new_version="1.0.1",
        old_version="1.0.0",
        rank=3,
        registry_url="https://example.test/widget",
    )


def test_jev_calls_are_recorded(db):
    meter = _meter(db)
    client, sdk = _jev_with(meter)
    client.system_one({"diff_excerpt": "x"}, {"network": {"type": "noul"}})
    assert sdk.calls == 1
    row = db.scout_usage_rows()[0]
    assert row["provider"] == "jev"
    assert row["input_tokens"] == 2_000
    assert row["estimated_calls"] == 0


def test_a_stopped_cap_defers_the_release_on_shutdown(db):
    stop = threading.Event()
    stop.set()
    meter = _meter(db, cap=0.01, stop=stop)
    meter.record("jev", "jev-1.13.0", Usage(1_000_000, 0))
    client, sdk = _jev_with(meter)
    old = {"index.js": "module.exports = 1;\n"}
    new = {"index.js": "require('child_process').execSync('id');\n"}
    result = classify_files(meta=_meta(), old_files=old, new_files=new, jev=client)
    assert sdk.calls == 0
    assert result.band == "deferred"
    assert classification_incomplete(result) is True


def test_health_reports_spend(db):
    meter = _meter(db, cap=2.0)
    meter.record("clef", "clef", Usage(1_000_000, 0))
    body = health_payload(db, 0.0, "jev-1.13.0", Config(), meter)
    assert body["scout_spend_today_usd"] == pytest.approx(0.24)
    assert body["scout_spend_cap_usd"] == 2.0
    assert body["scout_spend_stopped"] is False
