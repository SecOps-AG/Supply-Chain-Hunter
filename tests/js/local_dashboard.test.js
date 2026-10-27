// Tests for the local dashboard script, hunter/dashboard/static/app.js. Loads the real file in a
// vm context with a tiny fake DOM and fake fetch. Synthetic data only; no network, init() not run.
// Run: node --test tests/js/local_dashboard.test.js
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const APP = path.join(__dirname, "..", "..", "hunter", "dashboard", "static", "app.js");

class Node {
  constructor() { this.parentNode = null; this.childNodes = []; }
  get textContent() { return this.childNodes.map((c) => c.textContent).join(""); }
  set textContent(v) { this.replaceChildren(); if (v !== "") this.append(String(v)); }
  append(...kids) {
    for (const kid of kids) {
      const node = kid instanceof Node ? kid : new Text(String(kid));
      node.parentNode = this;
      this.childNodes.push(node);
    }
  }
  replaceChildren(...kids) { this.childNodes = []; this.append(...kids); }
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
    this.style = {};
    this.hidden = false;
    this.checked = false;
    const classes = new Set();
    this.classList = {
      toggle: (c, on) => { if (on) classes.add(c); else classes.delete(c); },
      contains: (c) => classes.has(c),
    };
  }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
  addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); }
  get innerHTML() { throw new Error("innerHTML must not be read"); }
  set innerHTML(_v) { throw new Error("innerHTML must not be used"); }
  findAll(pred, out = []) {
    for (const c of this.childNodes) if (c instanceof Element) { if (pred(c)) out.push(c); c.findAll(pred, out); }
    return out;
  }
}

function load({ hash = "", stored = {}, fetchImpl } = {}) {
  const byId = {};
  const storage = { ...stored };
  const calls = [];
  const document = {
    documentElement: new Element("html"),
    hidden: false,
    getElementById: (id) => (byId[id] ||= new Element("div")),
    createElement: (tag) => new Element(tag),
    createElementNS: (_ns, tag) => new Element(tag),
    createTextNode: (t) => new Text(t),
    querySelectorAll: () => [],
    addEventListener: () => {},
  };
  const replaced = [];
  const ctx = {
    document,
    Node,
    location: { hash, pathname: "/", search: "" },
    history: { replaceState: (...a) => replaced.push(a) },
    sessionStorage: { getItem: (k) => (k in storage ? storage[k] : null), setItem: (k, v) => { storage[k] = String(v); } },
    localStorage: { getItem: () => null, setItem: () => {} },
    fetch: async (url, opts) => { calls.push({ url, opts }); return fetchImpl ? fetchImpl(url, opts) : { ok: true, status: 200, json: async () => ({}) }; },
    setInterval: () => 0, setTimeout: () => 0, clearTimeout: () => {},
    matchMedia: () => ({ matches: false }),
    getComputedStyle: () => ({ getPropertyValue: () => "" }),
    Intl, Date, Math, Number, String, Object, Array, Set, Map, JSON, Error, Promise, URLSearchParams,
    encodeURIComponent, decodeURIComponent, console,
  };
  vm.createContext(ctx);
  vm.runInContext(fs.readFileSync(APP, "utf8"), ctx, { filename: APP });
  return { ctx, byId, storage, calls, replaced };
}

test("number, percent, money and duration formatting", () => {
  const { ctx } = load();
  assert.equal(ctx.n(null), "—");
  assert.equal(ctx.n(1234567), "1,234,567");
  assert.equal(ctx.pct(0.1234), "12.3%");
  assert.equal(ctx.pct(undefined), "—");
  assert.equal(ctx.usd(0.01234), "$0.0123");
  assert.equal(ctx.usd(12.5), "$12.50");
  assert.equal(ctx.usd(null), "—");
  assert.equal(ctx.prob("0.456"), "0.46");
  assert.equal(ctx.dur(59), "0m 59s");
  assert.equal(ctx.dur(3725), "1h 02m");
  assert.equal(ctx.dur(90000), "1d 01h");
  assert.equal(ctx.dur(null), "—");
  assert.equal(ctx.sum([1, null, 2]), 3);
  assert.equal(ctx.sum(undefined), 0);
});

test("ago and parseTs handle bad and recent timestamps", () => {
  const { ctx } = load();
  assert.equal(ctx.parseTs("not a date"), null);
  assert.equal(ctx.ago(""), "—");
  const fiveMin = new Date(Date.now() - 5 * 60 * 1000).toISOString();
  assert.equal(ctx.ago(fiveMin), "5m ago");
  const future = new Date(Date.now() + 60 * 1000).toISOString();
  assert.equal(ctx.ago(future), "0s ago");
});

test("model names map to the comparison slots", () => {
  const { ctx } = load();
  assert.equal(ctx.modelLabel("clef"), "clef-flash");
  assert.equal(ctx.modelLabel("LUNA"), "Luna");
  assert.equal(ctx.modelLabel("jev"), "Jev");
  assert.equal(ctx.modelLabel("openai_api"), "OpenAI API");
  assert.equal(ctx.modelSlot("clef-holdout"), null);
  assert.equal(ctx.shownDecisionModel("vendor/clef"), "clef-flash");
  assert.equal(ctx.shownDecisionModel("  "), "—");
  const run = { models: [{ model: "luna" }, { model: "clef" }, { model: "jev" }, { model: "other" }] };
  assert.equal(ctx.comparisonRuns({ runs: [run, { models: [{ model: "luna" }] }] }).length, 1);
  assert.deepEqual(Array.from(ctx.modelsForRun(run), (m) => m.model), ["luna", "clef", "jev"]);
});

test("unknown ecosystems fall back to a plain label", () => {
  const { ctx } = load();
  assert.equal(ctx.ecoInfo("pypi").label, "PyPI");
  assert.equal(ctx.ecoInfo("crates").label, "crates");
  assert.deepEqual(Array.from(ctx.ecoList({ scanned: { by_ecosystem: { npm: 1 } } })), ["npm", "pypi"]);
  assert.deepEqual(Array.from(ctx.ecoList({ feeds: { last_success: { "github-actions": "x" } } })), ["npm", "pypi", "github-actions"]);
});

test("a token in the URL hash is stored, removed from the URL, and sent as a bearer header", async () => {
  const { ctx, storage, calls, replaced } = load({ hash: "#token=abc%20123" });
  assert.equal(storage["hunter-dashboard-token"], "abc 123");
  assert.equal(replaced.length, 1);
  await ctx.api("/api/snapshot");
  assert.equal(calls[0].opts.headers.Authorization, "Bearer abc 123");
  assert.equal(calls[0].opts.credentials, "same-origin");
});

test("no token means no Authorization header", async () => {
  const { ctx, calls } = load();
  await ctx.api("/api/x");
  assert.equal(calls[0].opts.headers.Authorization, undefined);
});

test("api raises the server error text on a failed response", async () => {
  const { ctx } = load({ fetchImpl: async () => ({ ok: false, status: 401, json: async () => ({ error: "bad token" }) }) });
  await assert.rejects(ctx.api("/api/x"), /bad token/);
  const { ctx: ctx2 } = load({ fetchImpl: async () => ({ ok: false, status: 502, json: async () => { throw new Error("not json"); } }) });
  await assert.rejects(ctx2.api("/api/x"), /HTTP 502/);
});

test("refresh sends the watched toggle and shows a disconnect banner on error", async () => {
  const { ctx, byId, calls } = load({ fetchImpl: async () => ({ ok: false, status: 500, json: async () => ({ error: "boom" }) }) });
  await ctx.refresh();
  assert.match(calls[0].url, /^\/api\/snapshot\?range=24h$/);
  assert.equal(byId["live-text"].textContent, "Disconnected: boom");
  assert.equal(byId.offbar.classList.contains("show"), true);
});

test("watchlist card stays hidden with no list in the default mode", () => {
  const { ctx, byId } = load();
  ctx.renderWatchlist({ watchlist: { total: 0, mode: "all" } });
  assert.equal(byId["watched-wrap"].hidden, true);
  assert.equal(byId["wl-card"].hidden, true);
});

test("watched mode with an empty list shows the toggle but not the card", () => {
  const { ctx, byId } = load();
  ctx.renderWatchlist({ watchlist: { total: 0, mode: "watched" }, watched_only: true });
  assert.equal(byId["watched-wrap"].hidden, false);
  assert.equal(byId["watched-only"].checked, true);
  assert.equal(byId["wl-card"].hidden, true);
});

test("watchlist sources render as text, never as markup", () => {
  const { ctx, byId } = load();
  const evil = "<img src=x onerror=alert(1)>/package-lock.json";
  ctx.renderWatchlist({
    watched_only: false,
    watchlist: {
      total: 3, mode: "watched", alert_scope: "watched", npm: 2, openvsx: 1,
      sources: [{ source: evil, format: "npm-lock", components: 3, skipped: 1, imported_at: "2026-01-01T00:00:00Z", stale: true }],
    },
  });
  assert.equal(byId["wl-card"].hidden, false);
  assert.equal(byId["wl-hint"].textContent, "mode watched, alert scope watched; 3 names from 1 sources");
  const body = byId["wl-body"];
  assert.match(body.textContent, /Npm 2 · Openvsx 1/);
  const cells = body.findAll((el) => el.tagName === "TD");
  assert.equal(cells[0].textContent, evil);
  assert.equal(cells[2].textContent, "3 (1 skipped)");
  assert.match(cells[4].textContent, /older than 7 days/);
  assert.equal(body.findAll((el) => el.tagName === "IMG").length, 0);
});
