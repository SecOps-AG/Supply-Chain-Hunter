// The benchmark tab shows one comparison: Luna, clef-flash, and Jev.
// Side modes (holdout-only, own cutoff) are not a second run.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const DASH = path.join(__dirname, "..", "..", "public_dashboard");

class Node {
  constructor() { this.parentNode = null; this.childNodes = []; }
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
    this.tagName = String(tag).toUpperCase();
    this.attrs = {};
    this.listeners = {};
    this.style = { setProperty() {} };
    this.hidden = false;
    this.disabled = false;
    this.value = "";
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
  getBoundingClientRect() { return { left: 0, top: 0, width: 100, height: 40 }; }
  scrollIntoView() {}
  showModal() {}
  close() {}
  matches() { return false; }
  querySelectorAll() { return []; }
  querySelector() { return null; }
}

function row(model, extra) {
  return Object.assign({
    model, backend: model, model_id: model, rules: "on", status: "ok",
    cases: 156, bad_n: 27, clean_n: 129, catch: 27, false_flags: 1,
    catch_rate: 1, false_flag_rate: 1 / 129, alert_bad: 1, alert_clean: 0, deferred: 0,
    input_tokens: 1000, output_tokens: null, calls: 10, usd: 0.1, usd_per_case: 0.001,
    skip_reason: null,
  }, extra);
}

function benchDoc() {
  return {
    configured: true,
    production_scout: "clef",
    error: null,
    runs: [
      {
        id: "subset-run",
        run_date: "2026-10-09",
        corpus: "subset",
        corpus_note: "holdout clean only",
        models: [row("jev", { cases: 30, bad_n: 10, clean_n: 20, catch: 10, false_flags: 0 })],
      },
      {
        id: "2026-10-11-three-model",
        run_date: "2026-10-11",
        corpus: "standard-set",
        corpus_note: "should not be shown",
        product_release: "local worktree note",
        models: [
          row("jev", { false_flags: 6, false_flag_rate: 6 / 129, catch: 27 }),
          row("clef", { catch: 26, catch_rate: 26 / 27, false_flags: 25, false_flag_rate: 25 / 129, backend: "cloudflare/clef" }),
          row("luna", { false_flags: 10, false_flag_rate: 10 / 129, backend: "openrouter/decisions, own cutoff note" }),
          row("luna-own-cutoff", { cases: 59, bad_n: 27, clean_n: 32, false_flags: 1, false_flag_rate: 1 / 32 }),
          row("luna-heldout-clean-only", { cases: 59, bad_n: 27, clean_n: 32, false_flags: 1, false_flag_rate: 1 / 32, backend: "holdout clean only and own cutoff" }),
        ],
        cases: {
          jev: [{ id: "bad-1", label: "malicious", band: "alert", p: 0.9, status: "ok", to_triage: true }],
          clef: [{ id: "bad-1", label: "malicious", band: "review", p: 0.7, status: "ok", to_triage: true }],
          luna: [{ id: "bad-1", label: "malicious", band: "alert", p: 0.8, status: "ok", to_triage: true }],
          "luna-own-cutoff": [{ id: "bad-1", label: "malicious", band: "alert", p: 0.8, status: "ok", to_triage: true }],
        },
      },
    ],
  };
}

function loadPage(doc) {
  const root = new Element("html");
  const byId = {};
  const make = (id) => {
    const el = new Element("div");
    el.setAttribute("id", id);
    root.append(el);
    byId[id] = el;
    return el;
  };
  for (const id of ["bench-body", "live", "live-text", "offbar", "beat", "beat-text", "flow", "hero", "theme"]) make(id);
  const document = {
    hidden: false,
    listeners: {},
    documentElement: root,
    getElementById(id) { return byId[id] || make(id); },
    createElement(tag) { return new Element(tag); },
    createElementNS(_ns, tag) { return new Element(tag); },
    createTextNode(t) { return new Text(t); },
    querySelector() { return null; },
    querySelectorAll() { return []; },
    addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); },
  };
  const ctx = {
    console, Intl, Math, JSON, Promise, Map, Set, Object, Array, Number, String, Error, URLSearchParams, Date, Node,
    document,
    location: { hash: "" },
    HUNTER_PUBLIC: { dataBase: "" },
    localStorage: { getItem() { return null; }, setItem() {} },
    matchMedia() { return { matches: false }; },
    getComputedStyle() { return { getPropertyValue() { return "#888"; } }; },
    requestAnimationFrame() { return 0; },
    setTimeout() { return 0; },
    clearTimeout() {},
    setInterval() { return 0; },
    fetch: async (url) => {
      if (String(url).endsWith("live/benchmark.json")) {
        return { ok: true, status: 200, headers: { get: () => null }, json: async () => doc };
      }
      return { ok: false, status: 404, headers: { get: () => null }, json: async () => ({}) };
    },
  };
  ctx.window = ctx;
  ctx.self = ctx;
  vm.createContext(ctx);
  vm.runInContext(fs.readFileSync(path.join(DASH, "replay.js"), "utf8"), ctx, { filename: "replay.js" });
  vm.runInContext(fs.readFileSync(path.join(DASH, "app.js"), "utf8"), ctx, { filename: "app.js" });
  return { ctx, byId };
}

test("one run shows Luna, clef-flash, and Jev and drops the split", async () => {
  const page = loadPage(benchDoc());
  assert.equal(page.ctx.modelSlot("clef"), "clef-flash");
  assert.equal(page.ctx.modelSlot("luna-heldout-clean-only"), null);
  assert.equal(page.ctx.modelSlot("luna-own-cutoff"), null);
  assert.equal(page.ctx.modelLabel("clef"), "clef-flash");
  assert.equal(page.ctx.shownDecisionModel("@cf/cloudflare/clef"), "clef-flash");
  assert.equal(page.ctx.shownDecisionModel("typesafe-ai/jev"), "typesafe-ai/jev");
  await page.ctx.loadBench();
  const text = page.byId["bench-body"].textContent;
  assert.match(text, /clef-flash/);
  assert.match(text, /Luna/);
  assert.match(text, /Jev/);
  assert.match(text, /27 of 27 bad/);
  assert.match(text, /26 of 27 bad/);
  assert.match(text, /6 of 129 clean/);
  assert.match(text, /25 of 129 clean/);
  assert.match(text, /10 of 129 clean/);
  assert.doesNotMatch(text, /holdout|cutoff|launch bar|openrouter|subset-run|local worktree/i);
  assert.equal(text.includes("Clef"), false);
  assert.equal(/clef(?!-flash)/i.test(text), false);
  assert.match(text, /Luna caught 27 of 27 bad/);
  assert.doesNotMatch(text, /of 32|of 20|of 59|59 of/);
});

test("a clef decision model on the pipeline is labeled clef-flash", async () => {
  const page = loadPage(benchDoc());
  assert.equal(page.ctx.shownDecisionModel("clef"), "clef-flash");
  assert.equal(page.ctx.shownDecisionModel("Clef"), "clef-flash");
});
