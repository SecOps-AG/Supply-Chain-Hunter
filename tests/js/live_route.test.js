// The Pages function returns the object release_object_key wrote, at the app.js URL.
// Run: node --test tests/js/live_route.test.js
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const ROOT = path.join(__dirname, "..", "..");
const FN = path.join(ROOT, "public_dashboard", "functions", "live", "[[path]].js");

function loadOnRequest() {
  const src = fs.readFileSync(FN, "utf8").replace(
    "export async function onRequest",
    "async function onRequest"
  );
  const ctx = {
    URL,
    Response,
    Headers,
    Request,
    caches: { default: { async match() { return undefined; }, async put() {} } },
  };
  vm.createContext(ctx);
  vm.runInContext(src + "\nthis.onRequest = onRequest;\n", ctx);
  return ctx.onRequest;
}

function pythonKey(ecosystem, name, version) {
  const script = [
    "from hunter.public_dash import release_object_key",
    `print(release_object_key(${JSON.stringify(ecosystem)}, ${JSON.stringify(name)}, ${JSON.stringify(version)}))`,
  ].join("\n");
  return execFileSync("python3", ["-c", script], {
    cwd: ROOT,
    encoding: "utf8",
    env: { ...process.env, PYTHONPATH: ROOT },
  }).trim();
}

function pageKey() {
  const source = fs.readFileSync(path.join(ROOT, "public_dashboard", "app.js"), "utf8");
  const start = source.indexOf("function releaseSegment(");
  const end = source.indexOf("function releaseObjectKey(");
  const close = source.indexOf("\n}\n", end);
  const ctx = { encodeURIComponent };
  vm.createContext(ctx);
  vm.runInContext(source.slice(start, close + 3) + "\nthis.releaseObjectKey = releaseObjectKey;\n", ctx);
  return ctx.releaseObjectKey;
}

const onRequest = loadOnRequest();
const releaseObjectKey = pageKey();

async function request(bucket, href) {
  const url = new URL(href);
  const rel = url.pathname.startsWith("/live/") ? url.pathname.slice("/live/".length) : "";
  const response = await onRequest({
    request: new Request(url),
    env: { DASH_BUCKET: bucket },
    params: { path: rel ? rel.split("/") : "" },
    waitUntil() {},
  });
  return {
    status: response.status,
    body: Buffer.from(await response.arrayBuffer()).toString("utf8"),
    cacheControl: response.headers.get("cache-control"),
  };
}

test("slash-containing release keys round-trip, including a decoded bang", async () => {
  const cases = [
    ["github-actions", "actions/checkout", "v4@0123456789ab"],
    ["npm", "@malloy-publisher/server", "0.9.5"],
    ["pypi", "tox", "4.64.10"],
    ["pypi", "epochpkg", "1!2.0.0"],
  ];
  const objects = new Map();
  for (const [eco, name, version] of cases) {
    const key = pythonKey(eco, name, version);
    assert.equal(releaseObjectKey(eco, name, version), key);
    assert.equal(key.includes("%2F") || key.includes("%2f"), false);
    objects.set(key, JSON.stringify({ eco, name, version }));
  }
  const bucket = {
    async get(key) {
      const body = objects.get(key);
      if (body === undefined) return null;
      return { body: Buffer.from(body), httpMetadata: { contentType: "application/json", cacheControl: "public, max-age=2" } };
    },
  };
  for (const [eco, name, version] of cases) {
    const key = pythonKey(eco, name, version);
    const hit = await request(bucket, "https://hunter.test/" + key);
    assert.equal(hit.status, 200);
    assert.equal(hit.body, objects.get(key));
  }
  const decoded = await request(bucket, "https://hunter.test/live/r/pypi/epochpkg/1!2.0.0.json");
  assert.equal(decoded.status, 200);
  assert.equal(decoded.body, objects.get(pythonKey("pypi", "epochpkg", "1!2.0.0")));
  const missing = await request(bucket, "https://hunter.test/live/r/github-actions");
  assert.equal(missing.status, 404);
  assert.equal(missing.body, "Not found");
  assert.equal(missing.body.length, 9);
  assert.equal(missing.cacheControl, "no-store");
  const slash = await request(bucket, "https://hunter.test/live/r/npm/%40scope%2Fpkg/1.0.0.json");
  assert.equal(slash.status, 404);
  assert.equal(slash.body, "Not found");
});
