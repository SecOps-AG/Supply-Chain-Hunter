// Header star control: link target, count from a fixture response, blank when the fetch fails.
// Run: node --test tests/js/github_stars.test.js
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const ROOT = path.join(__dirname, "..", "..");
const REPO = "https://github.com/SecOps-AG/Supply-Chain-Hunter";
const API = "https://api.github.com/repos/SecOps-AG/Supply-Chain-Hunter";
const SCRIPT = fs.readFileSync(path.join(ROOT, "public_dashboard", "github_stars.js"), "utf8");
const OPERATOR_SCRIPT = fs.readFileSync(path.join(ROOT, "hunter", "dashboard", "static", "github_stars.js"), "utf8");

function header(html) {
  const start = html.indexOf('<header class="top">');
  const end = html.indexOf("</header>", start);
  assert.ok(start >= 0 && end > start);
  return html.slice(start, end);
}

function starLink(html) {
  const block = header(html);
  const match = block.match(/<a\b[^>]*\bid="gh-stars"[^>]*>[\s\S]*?<\/a>/);
  assert.ok(match, "star control is one link in the header");
  return match[0];
}

test("operator and public pages use the same star script", () => {
  assert.equal(OPERATOR_SCRIPT, SCRIPT);
  assert.doesNotMatch(SCRIPT, /setInterval|setTimeout/);
  assert.match(SCRIPT, /api\.github\.com\/repos\/SecOps-AG\/Supply-Chain-Hunter/);
  assert.doesNotMatch(SCRIPT, /Authorization|token|Bearer/i);
});

test("the header link opens the repository", () => {
  const pages = [
    path.join(ROOT, "public_dashboard", "index.html"),
    path.join(ROOT, "hunter", "dashboard", "static", "index.html"),
  ];
  for (const file of pages) {
    const html = fs.readFileSync(file, "utf8");
    const link = starLink(html);
    assert.match(link, new RegExp('href="' + REPO.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + '"'));
    assert.match(link, /target="_blank"/);
    assert.match(link, /rel="noopener noreferrer"/);
    assert.match(link, /class="gh-star"/);
    assert.match(link, /class="gh-label">Stars</);
    assert.match(link, /id="gh-star-count"[^>]*><\/span>/);
    assert.doesNotMatch(link, /<button/i);
    assert.doesNotMatch(link, />\s*\d/);
    const scripts = file.endsWith(path.join("static", "index.html"))
      ? '/static/github_stars.js'
      : 'src="github_stars.js"';
    assert.ok(html.includes(scripts));
  }
});

function mount() {
  const link = {
    attrs: { href: REPO, "aria-label": "GitHub stars" },
    setAttribute(name, value) { this.attrs[name] = String(value); },
    getAttribute(name) { return this.attrs[name]; },
  };
  const countEl = { textContent: "" };
  const listeners = {};
  const document = {
    readyState: "interactive",
    getElementById(id) {
      if (id === "gh-stars") return link;
      if (id === "gh-star-count") return countEl;
      return null;
    },
    addEventListener(type, fn) { (listeners[type] = listeners[type] || []).push(fn); },
  };
  return { link, countEl, document, listeners };
}

async function runScript(fetchImpl, readyState) {
  const page = mount();
  if (readyState) page.document.readyState = readyState;
  const calls = [];
  const ctx = {
    document: page.document,
    Intl,
    fetch(url, opts) {
      calls.push({ url, opts });
      return Promise.resolve(fetchImpl(url, opts));
    },
  };
  vm.createContext(ctx);
  vm.runInContext(SCRIPT, ctx, { filename: "github_stars.js" });
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
  return { ...page, calls };
}

test("a fixture response fills the star count once", async () => {
  const page = await runScript(() => ({
    ok: true,
    json: async () => ({ stargazers_count: 1280, full_name: "SecOps-AG/Supply-Chain-Hunter" }),
  }));
  assert.equal(page.calls.length, 1);
  assert.equal(page.calls[0].url, API);
  assert.equal(page.calls[0].opts.credentials, "omit");
  assert.equal(page.calls[0].opts.cache, "no-store");
  assert.equal(page.calls[0].opts.method, "GET");
  assert.equal(page.calls[0].opts.headers, undefined);
  assert.equal(page.countEl.textContent, "1,280");
  assert.equal(page.link.getAttribute("aria-label"), "1,280 GitHub stars");
  assert.equal(page.link.getAttribute("href"), REPO);
});

test("a failed fetch leaves the link and no number", async () => {
  const cases = [
    () => { throw new Error("offline"); },
    () => ({ ok: false, status: 403, json: async () => ({ message: "rate limit" }) }),
    () => ({ ok: true, json: async () => ({}) }),
    () => ({ ok: true, json: async () => ({ stargazers_count: null }) }),
    () => ({ ok: true, json: async () => ({ stargazers_count: "12" }) }),
    () => ({ ok: true, json: async () => { throw new Error("not json"); } }),
  ];
  for (const fetchImpl of cases) {
    const page = await runScript(fetchImpl);
    assert.equal(page.countEl.textContent, "");
    assert.equal(page.link.getAttribute("aria-label"), "GitHub stars");
    assert.equal(page.link.getAttribute("href"), REPO);
    assert.equal(page.calls.length, 1);
  }
});

test("the count waits for DOMContentLoaded and does not fetch again", async () => {
  const page = mount();
  page.document.readyState = "loading";
  const calls = [];
  const ctx = {
    document: page.document,
    Intl,
    fetch(url) {
      calls.push(url);
      return Promise.resolve({ ok: true, json: async () => ({ stargazers_count: 4 }) });
    },
    setInterval() { throw new Error("star count must not poll"); },
    setTimeout() { throw new Error("star count must not schedule a retry"); },
  };
  vm.createContext(ctx);
  vm.runInContext(SCRIPT, ctx, { filename: "github_stars.js" });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(calls.length, 0);
  page.listeners.DOMContentLoaded[0]();
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(calls, [API]);
  assert.equal(page.countEl.textContent, "4");
});
