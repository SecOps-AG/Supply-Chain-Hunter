// Release object keys in public_dashboard/app.js match hunter.public_dash.release_object_key.
// Run: node --test tests/js/release_key.test.js
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const ROOT = path.join(__dirname, "..", "..");
const SOURCE = fs.readFileSync(path.join(ROOT, "public_dashboard", "app.js"), "utf8");

function loadReleaseObjectKey() {
  const start = SOURCE.indexOf("function releaseSegment(");
  const end = SOURCE.indexOf("function releaseObjectKey(");
  assert.ok(start >= 0 && end > start, "release helpers are in app.js");
  const close = SOURCE.indexOf("\n}\n", end);
  assert.ok(close > end);
  const snippet = SOURCE.slice(start, close + 3);
  const ctx = { encodeURIComponent };
  vm.createContext(ctx);
  vm.runInContext(snippet + "\nthis.releaseObjectKey = releaseObjectKey;\n", ctx);
  return ctx.releaseObjectKey;
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

const releaseObjectKey = loadReleaseObjectKey();

test("actions and scoped npm keys match release_object_key and contain no %2F", () => {
  const cases = [
    ["github-actions", "actions/checkout", "v4@0123456789ab"],
    ["npm", "@scope/pkg", "1.2.3"],
    ["pypi", "tox", "4.64.10"],
    ["npm", "vite", "8.3.4"],
    ["pypi", "epochpkg", "1!2.0.0"],
    ["npm", "a(b)", "1.0.0"],
  ];
  for (const [eco, name, version] of cases) {
    const key = releaseObjectKey(eco, name, version);
    assert.equal(key, pythonKey(eco, name, version));
    assert.equal(key.includes("%2F") || key.includes("%2f"), false);
    assert.equal(key.split("/").length, 5);
  }
  const actions = releaseObjectKey("github-actions", "actions/checkout", "v4@0123456789ab");
  assert.match(actions, /actions~checkout/);
  assert.match(actions, /v4%400123456789ab\.json$/);
  const scoped = releaseObjectKey("npm", "@scope/pkg", "1.2.3");
  assert.match(scoped, /%40scope~pkg/);
  assert.match(releaseObjectKey("pypi", "epochpkg", "1!2.0.0"), /1%212\.0\.0\.json$/);
  assert.match(releaseObjectKey("npm", "a(b)", "1.0.0"), /a%28b%29/);
});
