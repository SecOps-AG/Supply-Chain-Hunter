// Node tests for public_dashboard/replay.js. Synthetic, hand-written data only; no network.
// Run: node --test tests/js/replay.test.js
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const R = require(path.join(__dirname, "..", "..", "public_dashboard", "replay.js"));

const FIELDS = ["t", "kind", "eco", "name", "version", "result"];
const T0 = Date.parse("2026-10-11T07:30:00Z");
const DELAY = R.DEFAULTS.delayMs;
const iso = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
const sec = (ms) => Math.floor(ms / 1000);

function snap(totals, extra) {
  return Object.assign({
    range: "1h",
    scanned: { total: totals.scanned || 0, by_ecosystem: totals.by_ecosystem || {} },
    scout: { bands: totals.bands || {}, flagged: totals.flagged || 0 },
    triage: { total: totals.triage || 0 },
    analyst: { total: totals.analyst || 0 },
    webhook: { alerts_sent: totals.alerts || 0 },
    confirmed: { count: totals.confirmed || 0 },
    feeds: { last_success: totals.polls || {} },
    activity: totals.activity || [],
  }, extra || {});
}

function doc(untilMs, totals, rows, opts) {
  const s = snap(totals);
  return {
    published_at: iso(untilMs),
    snapshots: { "1h": s, "24h": s },
    stream: Object.assign({
      v: 1,
      until: iso(untilMs),
      since: iso(untilMs - 180000),
      window_s: 180,
      max_events: 250,
      truncated: false,
      poll_interval_s: 120,
      fields: FIELDS,
      events: rows,
    }, opts || {}),
  };
}

const scan = (ms, name, band) => [sec(ms), "scan", "npm", name, "1.0.0", band || "benign"];

test("parseStream drops malformed rows and unknown versions", () => {
  const good = R.parseStream({ v: 1, until: iso(T0), fields: FIELDS, events: [
    scan(T0 - 5000, "demo-a"),
    [sec(T0), "bogus", "npm", "x", "1", null],
    ["soon", "scan", "npm", "x", "1", null],
    [sec(T0), "scan", "npm", null, "1", null],
    "not a row",
    [sec(T0), "poll", "pypi", null, null, null],
  ] });
  assert.deepEqual(good.events.map((e) => e.kind), ["scan", "poll"]);
  assert.equal(good.untilMs, T0);
  assert.equal(R.parseStream({ v: 2, fields: FIELDS, events: [scan(T0, "a")] }).events.length, 0);
  assert.equal(R.parseStream({ v: 1, fields: ["t"], events: [scan(T0, "a")] }).events.length, 0);
  assert.equal(R.parseStream(null).events.length, 0);
});

test("events sharing a second are spaced inside that second only", () => {
  const rows = [];
  for (let i = 0; i < 15; i++) rows.push(scan(T0, "burst-" + i));
  rows.push(scan(T0 + 1000, "next"));
  const spread = R.spreadWithinSecond(R.parseStream({ v: 1, fields: FIELDS, events: rows }).events);
  for (const ev of spread) {
    assert.ok(ev.at >= ev.t && ev.at < ev.t + 1000, "stays in its second");
  }
  const burst = spread.filter((e) => e.t === T0).map((e) => e.at);
  assert.equal(new Set(burst).size, 15);
  assert.deepEqual(burst, [...burst].sort((a, b) => a - b));
});

test("clock skew is the median of Date header samples", () => {
  assert.equal(R.estimateSkew([]), 0);
  const samples = [
    { serverMs: 10000, clientMs: 7500 },
    { serverMs: 20000, clientMs: 17500 },
    { serverMs: 30000, clientMs: 99999 },
  ];
  assert.equal(R.estimateSkew(samples), 3000);
});

test("catch-up plan: play, speed up, or jump", () => {
  assert.equal(R.planCatchUp(0).mode, "play");
  assert.equal(R.planCatchUp(200).mode, "play");
  assert.equal(R.planCatchUp(5000).mode, "catchup");
  assert.equal(R.planCatchUp(5000).speed, R.DEFAULTS.maxSpeed);
  assert.equal(R.planCatchUp(60000).mode, "jump");
});

// Two uploads 35 s apart; the second brings three real scans.
function twoUploads() {
  const d1 = doc(T0, { scanned: 10, by_ecosystem: { npm: 10 }, bands: { benign: 10 }, polls: { npm: iso(T0 - 20000) } }, [scan(T0 - 60000, "older")]);
  const d2 = doc(T0 + 35000, { scanned: 13, by_ecosystem: { npm: 13 }, bands: { benign: 12, alert: 1 }, flagged: 1, confirmed: 1 }, [
    scan(T0 - 60000, "older"),
    scan(T0 + 5000, "demo-a"),
    scan(T0 + 12000, "demo-b", "alert"),
    scan(T0 + 30000, "demo-c"),
    [sec(T0 + 31000), "poll", "npm", null, null, null],
  ]);
  return { d1, d2 };
}

test("counters tick once per real event and end at the snapshot totals", () => {
  const { d1, d2 } = twoUploads();
  const r = R.createReplay();
  r.ingest(d1);
  r.advance(T0 + DELAY);
  assert.equal(r.viewAt("1h").scanned.total, 10);
  r.ingest(d2);
  const seen = [];
  const played = [];
  let last = 10;
  for (let now = T0 + DELAY; now <= T0 + 40000 + DELAY; now += 100) {
    const step = r.advance(now);
    played.push(...step.due, ...step.skipped);
    const total = r.viewAt("1h").scanned.total;
    assert.ok(total >= last && total - last <= 1, "moves by at most one per frame");
    if (total !== last) seen.push(r.playhead - T0);
    last = total;
  }
  assert.equal(seen.length, 3);
  assert.ok(seen[0] >= 5000 && seen[0] < 6000);
  const final = r.viewAt("1h");
  assert.equal(final.scanned.total, 13);
  assert.deepEqual(final.scanned.by_ecosystem, { npm: 13 });
  assert.deepEqual(final.scout.bands, { benign: 12, alert: 1 });
  assert.equal(final.scout.flagged, 1);
  // Every played event is one the server sent; none twice.
  const ids = played.map((e) => e.id);
  assert.equal(new Set(ids).size, ids.length);
  const sent = new Set(R.parseStream(d2.stream).events.map((e) => e.id));
  for (const id of ids) assert.ok(sent.has(id));
  assert.deepEqual(played.map((e) => e.name), ["demo-a", "demo-b", "demo-c", null]);
});

test("other panels switch to an upload only once playback reaches it", () => {
  const { d1, d2 } = twoUploads();
  const r = R.createReplay();
  r.ingest(d1);
  r.advance(T0 + DELAY);
  r.ingest(d2);
  r.advance(T0 + 20000 + DELAY);
  assert.equal(r.viewAt("1h").confirmed.count, 0);
  assert.equal(r.viewAt("1h").scanned.total, 12);
  r.advance(T0 + 35000 + DELAY);
  assert.equal(r.viewAt("1h").confirmed.count, 1);
  assert.equal(r.viewAt("1h").scanned.total, 13);
  assert.equal(r.displayDoc(), d2);
});

test("first load starts behind the upload and plays the rest", () => {
  const d = doc(T0, { scanned: 10 }, [scan(T0 - 30000, "a"), scan(T0 - 10000, "b"), scan(T0 - 5000, "c")]);
  const r = R.createReplay();
  r.ingest(d);
  const start = r.advance(T0 - 20000 + DELAY);
  assert.equal(start.mode, "start");
  assert.equal(start.due.length, 0, "history before the playhead is not animated");
  assert.equal(r.viewAt("1h").scanned.total, 8);
  const later = r.advance(T0 - 20000 + DELAY + 200);
  assert.equal(later.due.length, 0);
  const due = [];
  for (let now = T0 - 20000 + DELAY; now <= T0 + DELAY; now += 200) due.push(...r.advance(now).due);
  assert.deepEqual(due.map((e) => e.name), ["b", "c"]);
  assert.equal(r.viewAt("1h").scanned.total, 10);
});

test("an event that arrives after its time plays at once", () => {
  const r = R.createReplay();
  r.ingest(doc(T0, { scanned: 1 }, []));
  r.advance(T0 + 40000 + DELAY);
  r.ingest(doc(T0 + 42000, { scanned: 2 }, [scan(T0 + 38000, "late")]));
  const step = r.advance(T0 + 40100 + DELAY);
  assert.deepEqual(step.due.map((e) => e.name), ["late"]);
  assert.equal(r.viewAt("1h").scanned.total, 2);
});

test("a short gap is closed by playing faster; nothing is skipped", () => {
  const r = R.createReplay();
  r.ingest(doc(T0 + 30000, { scanned: 2 }, [scan(T0 + 2000, "a"), scan(T0 + 4000, "b")]));
  r.advance(T0 + DELAY);
  const gap = r.advance(T0 + 6000 + DELAY);
  assert.equal(gap.mode, "catchup");
  const due = [...gap.due];
  let now = T0 + 6000 + DELAY;
  let frames = 0;
  while (r.playhead < now - DELAY && frames < 200) {
    now += 100;
    const step = r.advance(now);
    assert.equal(step.skipped.length, 0);
    due.push(...step.due);
    frames++;
  }
  assert.ok(frames < 30, "caught up within a few seconds");
  assert.deepEqual(due.map((e) => e.name), ["a", "b"]);
});

test("a long hidden tab jumps to now and lists skipped events without replaying them", () => {
  const rows = [];
  for (let i = 1; i <= 40; i++) rows.push(scan(T0 + i * 1000, "away-" + i));
  const r = R.createReplay();
  r.ingest(doc(T0, { scanned: 5 }, []));
  r.advance(T0 + DELAY);
  r.ingest(doc(T0 + 60000, { scanned: 45, confirmed: 2 }, rows));
  const step = r.advance(T0 + 90000 + DELAY);
  assert.equal(step.mode, "jump");
  assert.equal(step.due.length, 0);
  assert.equal(step.skipped.length, 40);
  assert.equal(r.viewAt("1h").scanned.total, 45);
  assert.equal(r.viewAt("1h").confirmed.count, 2);
});

test("heartbeat uses real registry checks only", () => {
  const r = R.createReplay();
  r.ingest(doc(T0, { polls: { npm: iso(T0 - 50000), pypi: iso(T0 - 400000) } }, [[sec(T0 - 20000), "poll", "pypi", null, null, null]]));
  r.advance(T0 + DELAY);
  const hb = r.heartbeatAt();
  assert.equal(hb.state, "watching");
  assert.equal(hb.lastCheckMs, T0 - 20000);
  assert.equal(hb.byEco.npm, T0 - 50000);
  const quiet = R.createReplay();
  quiet.ingest(doc(T0, { polls: { npm: iso(T0 - 400000) } }, []));
  quiet.advance(T0 + DELAY);
  assert.equal(quiet.heartbeatAt().state, "quiet");
  const none = R.createReplay();
  none.ingest(doc(T0, {}, []));
  none.advance(T0 + DELAY);
  assert.equal(none.heartbeatAt().state, "quiet");
  assert.equal(none.heartbeatAt().lastCheckMs, null);
});

test("activity merges upload rows with replayed flags and verdicts, no duplicates", () => {
  const existing = { ts: iso(T0 - 50000), kind: "scout", text: "review", item: { key: "npm:old-flag:1.0.0", ecosystem: "npm", name: "old-flag", version: "1.0.0" } };
  const d = doc(T0, { activity: [existing] }, [
    [sec(T0 - 50000), "scan", "npm", "old-flag", "1.0.0", "review"],
    scan(T0 - 40000, "quiet-benign"),
    [sec(T0 - 30000), "triage", "npm", "old-flag", "1.0.0", "malicious"],
    [sec(T0 - 20000), "analyst", "npm", "old-flag", "1.0.0", "benign"],
    [sec(T0 - 10000), "alert", "npm", "old-flag", "1.0.0", "sent"],
  ]);
  const r = R.createReplay();
  r.ingest(d);
  r.advance(T0 + DELAY);
  const rows = r.activityAt("1h");
  assert.deepEqual(rows.map((a) => a.kind), ["alert", "analyst", "triage", "scout"]);
  assert.deepEqual(r.recentScans().map((e) => e.name), ["quiet-benign", "old-flag"]);
  assert.deepEqual(r.activityAt("1h", T0 - 25000).map((a) => a.kind), ["triage", "scout"]);
});

test("bad documents are ignored", () => {
  const r = R.createReplay();
  assert.equal(r.ingest(null), false);
  assert.equal(r.ingest({ snapshots: {} }), false);
  assert.equal(r.viewAt("1h"), null);
  assert.equal(r.ingest({ published_at: iso(T0), snapshots: { "1h": snap({ scanned: 3 }) } }), true);
  r.advance(T0 + DELAY);
  assert.equal(r.viewAt("1h").scanned.total, 3);
});
