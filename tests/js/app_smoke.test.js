// Smoke test for public_dashboard/app.js with replay.js: runs the real page scripts against a
// tiny fake DOM, fake clock and fake fetch. Synthetic, hand-written data only; no network.
// Run: node --test tests/js/app_smoke.test.js
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const DASH = path.join(__dirname, "..", "..", "public_dashboard");
const UPLOAD_S = 35;

// ---------- fake DOM: just what app.js touches ----------
class Node {
  constructor() { this.parentNode = null; this.childNodes = []; }
  get isConnected() { let n = this; while (n.parentNode) n = n.parentNode; return n.isRoot === true; }
  get textContent() { return this.childNodes.map((c) => c.textContent).join(""); }
  set textContent(v) { this.replaceChildren(); if (v !== "") this.append(String(v)); }
  append(...kids) {
    for (const kid of kids) {
      const node = kid instanceof Node ? kid : new Text(String(kid));
      if (node.parentNode) node.remove();
      node.parentNode = this;
      this.childNodes.push(node);
    }
  }
  prepend(...kids) { const rest = this.childNodes.splice(0); this.append(...kids); for (const r of rest) { r.parentNode = null; this.append(r); } }
  replaceChildren(...kids) { for (const c of this.childNodes) c.parentNode = null; this.childNodes = []; this.append(...kids); }
  remove() { if (!this.parentNode) return; const p = this.parentNode; p.childNodes = p.childNodes.filter((c) => c !== this); this.parentNode = null; }
}
class Text extends Node {
  constructor(text) { super(); this.text = text; }
  get textContent() { return this.text; }
}
class Element extends Node {
  constructor(tag) {
    super();
    this.tagName = tag.toUpperCase();
    this.attrs = {};
    this.listeners = {};
    this.style = { setProperty(k, v) { this[k] = v; } };
    this.hidden = false;
    this.disabled = false;
    this.value = "";
    this.elements = [];
    this.offsetWidth = 0;
    const self = this;
    this.classList = {
      list() { return (self.attrs.class || "").split(/\s+/).filter(Boolean); },
      contains(c) { return this.list().includes(c); },
      add(c) { if (!this.contains(c)) self.attrs.class = this.list().concat(c).join(" "); },
      remove(c) { self.attrs.class = this.list().filter((x) => x !== c).join(" "); },
      toggle(c, on) { const want = on === undefined ? !this.contains(c) : on; if (want) this.add(c); else this.remove(c); return want; },
    };
  }
  get id() { return this.attrs.id || ""; }
  get options() { return this.childNodes.filter((c) => c.tagName === "OPTION"); }
  get tBodies() { if (!this._tbody) { this._tbody = new Element("tbody"); this.append(this._tbody); } return [this._tbody]; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
  addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }
  dispatch(type, ev) { for (const fn of this.listeners[type] || []) fn(ev || {}); }
  getBoundingClientRect() { return { left: 0, top: 0, width: 100, height: 100 }; }
  scrollIntoView() {}
  showModal() {}
  close() {}
  matches(sel) {
    if (sel.startsWith(".")) return this.classList.contains(sel.slice(1));
    if (sel.startsWith("#")) return this.id === sel.slice(1);
    const m = /^\[([\w-]+)="([^"]*)"\]$/.exec(sel);
    return m ? this.attrs[m[1]] === m[2] : false;
  }
  querySelectorAll(sel) {
    if (/\s/.test(sel)) return []; // descendant selectors (tab and range buttons) are not built here
    const out = [];
    const walk = (n) => { for (const c of n.childNodes) if (c instanceof Element) { if (c.matches(sel)) out.push(c); walk(c); } };
    walk(this);
    return out;
  }
  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
}

function setup(docAt) {
  const clock = { now: Date.parse("2026-10-11T07:30:00Z") };
  const timers = [];
  const frames = [];
  const root = new Element("html");
  root.isRoot = true;
  const byId = {};
  const make = (id, parent, tag, cls) => {
    const el = new Element(tag || "div");
    el.setAttribute("id", id);
    if (cls) el.setAttribute("class", cls);
    (parent || root).append(el);
    byId[id] = el;
    return el;
  };
  const rail = new Element("section");
  rail.setAttribute("class", "tile rail");
  root.append(rail);
  make("flow", rail);
  make("beat", rail, "span", "beat off");
  make("beat-text", byId.beat, "span");
  for (const sel of ["f-signal", "f-rule"]) { const s = make(sel, null, "select"); const o = new Element("option"); s.append(o); }
  const document = {
    hidden: false,
    listeners: {},
    documentElement: root,
    getElementById(id) { return byId[id] || make(id); },
    createElement(tag) { return new Element(tag); },
    createElementNS(_ns, tag) { return new Element(tag); },
    createTextNode(t) { return new Text(t); },
    querySelector(sel) { return root.querySelector(sel); },
    querySelectorAll(sel) { return root.querySelectorAll(sel); },
    addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); },
    dispatch(type) { for (const fn of this.listeners[type] || []) fn({}); },
  };
  class FakeDate extends Date {
    constructor(...args) { if (args.length) super(...args); else super(clock.now); }
    static now() { return clock.now; }
  }
  const fetches = [];
  const ctx = {
    console, Intl, Math, JSON, Promise, Map, Set, Object, Array, Number, String, Error, URLSearchParams,
    Date: FakeDate,
    Node,
    document,
    location: { hash: "" },
    HUNTER_PUBLIC: { dataBase: "" },
    localStorage: { getItem() { return null; }, setItem() {} },
    matchMedia() { return { matches: false }; },
    getComputedStyle() { return { getPropertyValue() { return "#888"; } }; },
    requestAnimationFrame(fn) { frames.push(fn); return frames.length; },
    setTimeout(fn, ms) { timers.push({ at: clock.now + (ms || 0), fn }); return timers.length; },
    clearTimeout() {},
    setInterval(fn, ms) { timers.push({ at: clock.now + ms, fn, every: ms }); return timers.length; },
    async fetch(url) {
      fetches.push(url);
      if (!String(url).endsWith("live/live.json")) return { ok: false, status: 404, headers: { get: () => null }, json: async () => ({}) };
      const untilS = Math.floor(clock.now / 1000 / UPLOAD_S) * UPLOAD_S;
      const doc = docAt(untilS);
      const headers = { date: new Date(clock.now).toUTCString(), "last-modified": new Date(untilS * 1000 + 2000).toUTCString() };
      return { ok: true, status: 200, headers: { get: (k) => headers[k.toLowerCase()] || null }, json: async () => JSON.parse(JSON.stringify(doc)), body: { cancel() {} } };
    },
  };
  ctx.window = ctx;
  ctx.self = ctx;
  vm.createContext(ctx);
  vm.runInContext(fs.readFileSync(path.join(DASH, "replay.js"), "utf8"), ctx, { filename: "replay.js" });
  vm.runInContext(fs.readFileSync(path.join(DASH, "app.js"), "utf8"), ctx, { filename: "app.js" });

  const flush = () => new Promise((resolve) => setImmediate(resolve));
  async function run(ms, step = 100) {
    for (let t = 0; t < ms; t += step) {
      clock.now += step;
      for (const timer of timers.filter((x) => x.at <= clock.now)) {
        if (timer.every) timer.at += timer.every; else timers.splice(timers.indexOf(timer), 1);
        timer.fn();
      }
      // Browsers hold animation frames while the tab is hidden.
      if (!document.hidden) for (const fn of frames.splice(0)) fn(clock.now);
      await flush();
    }
  }
  return { clock, document, byId, rail, run, flush, fetches, start: () => document.dispatch("DOMContentLoaded") };
}

// ---------- invented timeline: one scan every 7 s, a review flag every 35 s ----------
const iso = (s) => new Date(s * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
const BASE = Date.parse("2026-10-11T07:30:00Z") / 1000 - 600;
const BASE_SCANNED = 1000;

function timeline(untilS) {
  const out = [];
  for (let s = BASE; s <= untilS; s++) {
    const i = s - BASE;
    if (i % 7 === 0) out.push([s, "scan", i % 14 === 0 ? "npm" : "pypi", "demo-pkg-" + i, "1.0.0", i % 35 === 0 ? "review" : "benign"]);
    if (i % 35 === 10) out.push([s, "triage_in", "npm", "demo-pkg-" + (i - 10), "1.0.0", null]);
    if (i % 60 === 0) out.push([s, "poll", "npm", null, null, null]);
  }
  return out;
}

function snapshotAt(untilS, events) {
  const scans = events.filter((e) => e[1] === "scan");
  const flagged = scans.filter((e) => e[5] === "review");
  const byEco = { npm: 0, pypi: 0 };
  for (const e of scans) byEco[e[2]] += 1;
  const polls = events.filter((e) => e[1] === "poll");
  const buckets = Array.from({ length: 24 }, (_, k) => iso(untilS - (23 - k) * 3600).slice(0, 13));
  const zeros = buckets.map(() => 0);
  const activity = flagged.map((e) => ({ ts: iso(e[0]), kind: "scout", text: "review", item: { key: e[2] + ":" + e[3] + ":1.0.0", ecosystem: e[2], name: e[3], version: e[4] } })).reverse();
  return {
    range: "24h", since: iso(untilS - 86400), bucket_seconds: 3600, buckets,
    health: { status: "ok", last_successful_poll: { npm: polls.length ? iso(polls[polls.length - 1][0]) : null } },
    models: { decision_model: { label: "decision model", role: "Scout" } },
    feeds: { last_success: { npm: polls.length ? iso(polls[polls.length - 1][0]) : null }, last_error: {} },
    scanned: { total: BASE_SCANNED + scans.length, by_ecosystem: { npm: BASE_SCANNED + byEco.npm, pypi: byEco.pypi }, series: { npm: zeros, pypi: zeros } },
    scout: { bands: { benign: BASE_SCANNED + scans.length - flagged.length, review: flagged.length }, flagged: flagged.length, top_signals: [] },
    rules: { enabled: false, releases_with_hits: 0, top_rules: [] },
    triage: { total: events.filter((e) => e[1] === "triage_in").length, verdicts: {}, series: zeros, share_of_scanned: null },
    analyst: { total: 0, verdicts: {}, series: zeros },
    webhook: { alerts_sent: 0, alerts_waiting: 0, outage_notices: 0, series: zeros, last_sent_at: null },
    confirmed: { count: 0, latest: null, uncertain: 0, cleared: 0, series: zeros },
    detections: [], activity: activity.slice(0, 40),
  };
}

function docAt(untilS) {
  const events = timeline(untilS);
  const snap = snapshotAt(untilS, events);
  return {
    published_at: iso(untilS),
    snapshots: { "1h": snap, "24h": snap, "7d": snap, "30d": snap },
    findings: {},
    stream: { v: 1, until: iso(untilS), since: iso(untilS - 180), window_s: 180, max_events: 250, truncated: false, poll_interval_s: 120,
      fields: ["t", "kind", "eco", "name", "version", "result"], events: events.filter((e) => e[0] > untilS - 180) },
    disclaimers: { scout_triage: "under review, not a verdict", analyst: "AI verdict (may be wrong)" },
  };
}

const scannedShown = (page) => Number(/Releases scanned([\d,]+)/.exec(page.byId["kpi-scanned"].textContent)[1].replace(/,/g, ""));
function expectedRange(nowMs) {
  // What a viewer should see: every real scan at or before the playhead, within its second.
  // The HTTP Date header has one-second precision, so the clock estimate is within ±0.5 s.
  const playhead = nowMs / 1000 - 45;
  const all = timeline(Math.floor(playhead) + 2).filter((e) => e[1] === "scan");
  return [BASE_SCANNED + all.filter((e) => e[0] + 1 <= playhead - 0.5).length, BASE_SCANNED + all.filter((e) => e[0] <= playhead + 0.5).length];
}

test("page replays real events smoothly and lands on the real totals", async () => {
  const page = setup(docAt);
  page.start();
  await page.run(500);
  assert.equal(page.byId["live-text"].textContent, "Live");
  const values = new Set();
  for (let i = 0; i < 40; i++) {
    await page.run(1000);
    const shown = scannedShown(page);
    const [lo, hi] = expectedRange(page.clock.now);
    assert.ok(shown >= lo && shown <= hi, `scanned ${shown} within real range ${lo}-${hi}`);
    values.add(shown);
  }
  assert.ok(values.size >= 5, "the counter ticks between uploads instead of jumping once per upload");
  assert.equal(page.byId["beat-text"].textContent, "Watching npm and PyPI");
  assert.doesNotMatch(page.byId.flow.textContent, /polled /);
  assert.doesNotMatch(page.byId.flow.textContent + page.byId["rail-foot"].textContent, /queue|spend|budget|outbox|retries|human review|Waiting:/i);
  assert.match(page.byId["rail-foot"].textContent, /Last feed read: npm /);
  assert.doesNotMatch(page.document.documentElement.textContent, /launch bar|45 s replay|holdout|own cutoff/i);
  assert.match(page.byId.activity.textContent, /demo-pkg-\d+/);
  const rows = page.byId.activity.childNodes[0].childNodes.map((r) => r.textContent.replace(/\d+[smh]( \d+m)? ago$/, ""));
  assert.equal(new Set(rows).size, rows.length, "no duplicate activity rows");
  assert.match(page.byId.flow.textContent, /Just scored/);
  assert.ok(page.fetches.length >= 8 && page.fetches.length <= 10, "polls about every 5 s: " + page.fetches.length);
  assert.equal(page.byId.offbar.textContent, "");
});

test("a long hidden tab jumps to the present and says what it skipped", async () => {
  const page = setup(docAt);
  page.start();
  await page.run(3000);
  page.document.hidden = true;
  page.document.dispatch("visibilitychange");
  await page.run(120000, 1000);
  page.document.hidden = false;
  page.document.dispatch("visibilitychange");
  await page.run(1000);
  const shown = scannedShown(page);
  const [lo, hi] = expectedRange(page.clock.now);
  assert.ok(shown >= lo && shown <= hi, `scanned ${shown} within real range ${lo}-${hi}`);
  assert.doesNotMatch(page.byId.activity.textContent, /Caught up|while away|replay/);
});

test("the stale banner still shows when the data stops coming", async () => {
  const page = setup(() => { throw new Error("offline"); });
  page.start();
  await page.run(2000);
  assert.match(page.byId["live-text"].textContent, /^Disconnected: offline/);
  assert.ok(page.byId.offbar.classList.contains("show"));
});
