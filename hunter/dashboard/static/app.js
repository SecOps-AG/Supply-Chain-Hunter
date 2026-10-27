// Hunter dashboard. Read-only. Every value from the server is placed with textContent or
// setAttribute, never as HTML: package names, signals and reports are attacker-controlled.
"use strict";

const REFRESH_MS = 10000;
const state = {
  tab: "dash",
  range: "24h",
  snap: null,
  lastOk: 0,
  detFilter: "all",
  findOffset: 0,
  findLimit: 25,
  bench: null,
  benchRun: null,
  matrixSet: "all",
  matrixShow: "all",
  historyMetric: "catch_rate",
  // null until the user flips "Watched only"; the server default applies until then.
  watched: null,
};

// ---------- small helpers ----------
const $ = (id) => document.getElementById(id);
const SVGNS = "http://www.w3.org/2000/svg";

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  applyAttrs(el, attrs);
  append(el, kids);
  return el;
}
function s(tag, attrs, ...kids) {
  const el = document.createElementNS(SVGNS, tag);
  applyAttrs(el, attrs);
  append(el, kids);
  return el;
}
function applyAttrs(el, attrs) {
  if (!attrs) return;
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "text") el.textContent = String(v);
    else if (k === "class") el.setAttribute("class", v);
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "style") Object.assign(el.style, v);
    else el.setAttribute(k, String(v));
  }
}
function append(el, kids) {
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
}
function clear(el, ...kids) { el.replaceChildren(); append(el, kids); return el; }

const nf = new Intl.NumberFormat("en-US");
function n(v) { return v === null || v === undefined ? "—" : nf.format(v); }
function pct(v, digits = 1) { return v === null || v === undefined ? "—" : (v * 100).toFixed(digits) + "%"; }
function usd(v, digits) {
  if (v === null || v === undefined) return "—";
  const d = digits !== undefined ? digits : (Math.abs(v) < 0.1 ? 4 : 2);
  return "$" + v.toFixed(d);
}
function prob(v) { return v === null || v === undefined ? "—" : Number(v).toFixed(2); }
function parseTs(ts) { if (!ts) return null; const t = Date.parse(ts); return Number.isNaN(t) ? null : t; }
function ago(ts) {
  const t = parseTs(ts);
  if (t === null) return "—";
  let sec = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (sec < 60) return sec + "s ago";
  const m = Math.floor(sec / 60); if (m < 60) return m + "m ago";
  const hr = Math.floor(m / 60); if (hr < 48) return hr + "h " + (m % 60) + "m ago";
  return Math.floor(hr / 24) + "d ago";
}
function dur(sec) {
  if (sec === null || sec === undefined) return "—";
  sec = Math.round(sec);
  const d = Math.floor(sec / 86400), hr = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  if (d) return d + "d " + String(hr).padStart(2, "0") + "h";
  if (hr) return hr + "h " + String(m).padStart(2, "0") + "m";
  return m + "m " + String(sec % 60).padStart(2, "0") + "s";
}
function clock(ts) {
  const t = parseTs(ts); if (t === null) return "—";
  return new Date(t).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}
function sum(arr) { return (arr || []).reduce((a, b) => a + (b || 0), 0); }
function cssVar(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }
const WORD_CASE = { openai: "OpenAI", api: "API", llm: "LLM" };
function titleCase(key) { return String(key || "").split(/[-_]/).map((w) => WORD_CASE[w.toLowerCase()] || w.charAt(0).toUpperCase() + w.slice(1)).join(" "); }

// The benchmark comparison is one run of these three on the same releases.
// clef and clef-flash are the same slot; the label is always clef-flash.
const COMPARISON_SLOTS = ["luna", "clef-flash", "jev"];
function modelSlot(name) {
  const key = String(name || "").toLowerCase();
  if (!key || key.includes("holdout") || key.includes("heldout") || key.includes("cutoff")) return null;
  if (key === "luna") return "luna";
  if (key === "clef" || key === "clef-flash") return "clef-flash";
  if (key === "jev") return "jev";
  return null;
}
function modelLabel(name) {
  const slot = modelSlot(name);
  if (slot === "clef-flash") return "clef-flash";
  if (slot === "luna") return "Luna";
  if (slot === "jev") return "Jev";
  return titleCase(name);
}
function shownDecisionModel(raw) {
  const text = String(raw == null ? "" : raw).trim();
  if (!text) return "—";
  const key = text.toLowerCase();
  if (key === "clef" || key === "clef-flash" || key.includes("clef-flash") || /(^|[/@])clef$/.test(key)) return "clef-flash";
  return text;
}
function comparisonRuns(bench) {
  return ((bench && bench.runs) || []).filter((run) => {
    const slots = new Set(run.models.map((m) => modelSlot(m.model)).filter(Boolean));
    return COMPARISON_SLOTS.every((slot) => slots.has(slot));
  });
}
function modelsForRun(run) {
  const picked = {};
  for (const m of (run && run.models) || []) {
    const slot = modelSlot(m.model);
    if (slot && !picked[slot]) picked[slot] = m;
  }
  return COMPARISON_SLOTS.map((slot) => picked[slot]).filter(Boolean);
}
function findSlot(run, slot) {
  if (!run || !slot) return null;
  return run.models.find((m) => modelSlot(m.model) === slot) || null;
}


// Ecosystems on the pipeline. GitHub Actions shows only when Hunter has data for it.
const ECOS = {
  npm: { label: "npm", feed: "changes feed", color: "--s-npm" },
  pypi: { label: "PyPI", feed: "serial feed", color: "--s-pypi" },
  "github-actions": { label: "Actions", feed: "tag watcher", color: "--s-gha" },
};
function ecoInfo(eco) { return ECOS[eco] || { label: eco, feed: "feed", color: "--s-scout" }; }
function ecoList(snap) {
  const seen = Object.keys((snap.scanned || {}).by_ecosystem || {}).concat(Object.keys(((snap.feeds || {}).last_success) || {}));
  return seen.includes("github-actions") ? ["npm", "pypi", "github-actions"] : ["npm", "pypi"];
}
function ecoTag(eco) { return h("span", { class: "eco " + (ECOS[eco] ? eco : "pypi"), text: ecoInfo(eco).label }); }
function relName(item) { return item.name + "@" + item.version; }

function verdictChip(v) {
  if (!v) return h("span", { class: "faint", text: "—" });
  const cls = v === "malicious" ? "crit" : v === "uncertain" ? "warn" : v === "benign" ? "ok" : "";
  return h("span", { class: "chip " + cls, text: v });
}
function bandChip(b) {
  const cls = b === "alert" ? "crit" : b === "review" ? "warn" : b === "benign" ? "ok" : "";
  return h("span", { class: "chip " + cls, text: b || "—" });
}

// Line chart for a series. Values are counts per bucket.
function spark(values, color, opts = {}) {
  const w = 100, hgt = 30;
  const svg = s("svg", { class: "spark", viewBox: `0 0 ${w} ${hgt}`, preserveAspectRatio: "none", "aria-hidden": "true" });
  if (!values || values.length < 2) return svg;
  const max = Math.max(1, ...values);
  const step = w / (values.length - 1);
  const pts = values.map((v, i) => [i * step, hgt - 2 - (v / max) * (hgt - 6)]);
  const line = pts.map((p, i) => (i ? "L" : "M") + p[0].toFixed(2) + " " + p[1].toFixed(2)).join(" ");
  if (opts.fill !== false) {
    svg.append(s("path", { d: line + ` L ${w} ${hgt} L 0 ${hgt} Z`, fill: color, "fill-opacity": "0.12", stroke: "none" }));
  }
  svg.append(s("path", { d: line, fill: "none", stroke: color, "stroke-width": "1.6", "vector-effect": "non-scaling-stroke", "stroke-linejoin": "round" }));
  return svg;
}

// ---------- fetching ----------
function token() {
  const m = /(?:^|[#&])token=([^&]+)/.exec(location.hash || "");
  if (m) {
    try { sessionStorage.setItem("hunter-dashboard-token", decodeURIComponent(m[1])); } catch (e) { /* storage blocked */ }
    history.replaceState(null, "", location.pathname + location.search);
    return decodeURIComponent(m[1]);
  }
  try { return sessionStorage.getItem("hunter-dashboard-token") || ""; } catch (e) { return ""; }
}
const TOKEN = token();

async function api(path) {
  const headers = { Accept: "application/json" };
  if (TOKEN) headers.Authorization = "Bearer " + TOKEN;
  const res = await fetch(path, { headers, cache: "no-store", credentials: "same-origin" });
  let body = null;
  try { body = await res.json(); } catch (e) { body = null; }
  if (!res.ok) throw new Error((body && body.error) || "HTTP " + res.status);
  return body;
}

function setLive(ok, message) {
  const live = $("live");
  live.classList.toggle("off", false);
  live.classList.toggle("err", !ok);
  $("live-text").textContent = message;
  const bar = $("offbar");
  bar.classList.toggle("show", !ok);
  bar.textContent = ok ? "" : message;
}

async function refresh() {
  try {
    const watched = state.watched === null ? "" : "&watched=" + (state.watched ? "1" : "0");
    const snap = await api("/api/snapshot?range=" + encodeURIComponent(state.range) + watched);
    state.snap = snap;
    state.lastOk = Date.now();
    renderDashboard();
  } catch (err) {
    setLive(false, "Disconnected: " + err.message);
  }
}
function tickLive() {
  if (!state.lastOk) return;
  const age = Math.round((Date.now() - state.lastOk) / 1000);
  const fresh = age <= REFRESH_MS / 1000 * 2 + 2;
  setLive(fresh, fresh ? "Live" : "Not updating");
}

// ---------- dashboard ----------
function renderDashboard() {
  const snap = state.snap;
  if (!snap) return;
  tickLive();
  renderWatchlist(snap);
  renderHero(snap);
  renderKpis(snap);
  renderFlow(snap);
  renderDetections();
  renderActivity(snap);
  renderSignals(snap);
  renderCost(snap);
}

// The user watchlist card and the "Watched only" toggle. Shown only when a list was imported
// or watched mode is on. Source labels are file paths the operator chose; shown as text.
function renderWatchlist(snap) {
  const wl = snap.watchlist || {};
  const total = wl.total || 0;
  $("watched-wrap").hidden = !(total > 0 || wl.mode === "watched");
  $("watched-only").checked = Boolean(snap.watched_only);
  $("wl-card").hidden = !(total > 0);
  if (!(total > 0)) return;
  $("wl-hint").textContent = `mode ${wl.mode}, alert scope ${wl.alert_scope}; ${n(total)} names from ${n((wl.sources || []).length)} sources`;
  const eco = ["npm", "pypi", "github-actions", "openvsx"].filter((k) => wl[k]).map((k) => titleCase(k) + " " + n(wl[k])).join(" · ");
  const rows = (wl.sources || []).map((src) => h("tr", {},
    h("td", { class: "pkg", text: src.source }),
    h("td", { class: "mono", text: src.format }),
    h("td", { text: n(src.components) + (src.skipped ? " (" + n(src.skipped) + " skipped)" : "") }),
    h("td", {}, clock(src.imported_at), h("span", { class: "sub", text: ago(src.imported_at) })),
    h("td", {}, src.stale ? h("span", { class: "chip warn", text: "older than 7 days" }) : h("span", { class: "faint", text: "—" }))));
  clear($("wl-body"),
    h("div", { class: "faint", text: eco }),
    h("div", { class: "tablewrap" }, h("table", { class: "grid" },
      h("thead", {}, h("tr", {}, h("th", { text: "Source" }), h("th", { text: "Format" }), h("th", { text: "Packages" }), h("th", { text: "Imported" }), h("th", { text: "Stale" }))),
      h("tbody", {}, ...rows))));
}

function rangeWord(r) { return { "1h": "hour", "24h": "24 hours", "7d": "7 days", "30d": "30 days" }[r] || r; }

function renderHero(snap) {
  const el = $("hero");
  const c = snap.confirmed;
  el.classList.toggle("hot", c.count > 0);
  const acts = h("div", { class: "acts" });
  if (c.latest) acts.append(h("button", { type: "button", class: "ibtn", text: "Open latest", onclick: () => openRelease(c.latest) }));
  acts.append(h("button", { type: "button", class: "ibtn", text: "Go to findings", onclick: () => $("find-form").scrollIntoView({ behavior: "smooth" }) }));
  const title = c.count
    ? `${c.count} malicious release${c.count === 1 ? "" : "s"} confirmed in the last ${rangeWord(snap.range)}`
    : `No releases confirmed malicious in the last ${rangeWord(snap.range)}`;
  const sub = c.latest
    ? h("span", {}, "Latest: ", c.latest.ecosystem, " ", h("span", { class: "mono", text: relName(c.latest) }), ", ", ago(c.latest.analyst_at), ". Alert ", c.latest.alert_status === "sent" ? "delivered to the webhook." : (c.latest.alert_status || "not queued") + ".")
    : h("span", { text: `${n(snap.scanned.total)} releases scanned; ${n(snap.triage.total)} sent to Triage.` });
  clear(el, h("div", { class: "ic", text: c.count ? "!" : "✓", "aria-hidden": "true" }), h("div", { class: "m" }, h("b", { text: title }), sub, acts));
}

function kpi(el, label, value, subText, series, color, opts = {}) {
  clear(el,
    h("div", { class: "l", text: label }),
    h("div", { class: "v" + (opts.crit ? " crit" : "") + (opts.na ? " na" : ""), text: value }),
    h("div", { class: "s", text: subText }),
    h("div", { class: "sp" }, series ? spark(series, color) : null));
}

function renderKpis(snap) {
  const eco = snap.scanned.series || {};
  const keys = Object.keys(eco);
  const total = snap.buckets.map((_, i) => keys.reduce((a, k) => a + (eco[k][i] || 0), 0));
  kpi($("kpi-scanned"), "Releases scanned", n(snap.scanned.total), "last " + rangeWord(snap.range), total, cssVar("--accent"));
  kpi($("kpi-triage"), "Escalated to Triage", n(snap.triage.total),
    snap.triage.share_of_scanned === null ? "no releases scanned" : pct(snap.triage.share_of_scanned) + " of scanned",
    snap.triage.series, cssVar("--accent"));
  const c = snap.confirmed;
  kpi($("kpi-confirmed"), "Confirmed malicious", n(c.count), `${n(c.uncertain)} uncertain · ${n(c.cleared)} cleared`, c.series, cssVar("--crit"), { crit: c.count > 0 });
  kpi($("kpi-latency"), "Publish to verdict", "Not recorded yet", "", null, null, { na: true });
}

function nodeHead(no, title, endText, tag) {
  return h("div", { class: "nh" }, h("span", { class: "no", text: String(no).padStart(2, "0") }), tag || null, h("span", { text: title }), endText ? h("span", { class: "end", text: endText }) : null);
}
function row(label, value) { return h("div", { class: "row" }, h("span", { text: label }), h("span", { text: value })); }
function stackBar(parts) {
  const total = sum(parts.map((p) => p[1]));
  const bar = h("div", { class: "bar" });
  const lgd = h("div", { class: "lgd" });
  for (const [label, count, cls] of parts) {
    if (!count) continue;
    bar.append(h("i", { class: cls, style: { width: (100 * count / total).toFixed(2) + "%" } }));
    lgd.append(h("span", {}, h("i", { class: cls }), label + " " + n(count)));
  }
  if (!total) lgd.append(h("span", { text: "nothing in range" }));
  return [bar, lgd];
}
function verdictParts(counts) {
  const known = ["benign", "malicious", "uncertain"];
  const parts = [["benign", counts.benign || 0, "c-benign"], ["malicious", counts.malicious || 0, "c-malicious"], ["uncertain", counts.uncertain || 0, "c-uncertain"]];
  let other = 0;
  for (const [k, v] of Object.entries(counts || {})) if (!known.includes(k)) other += v;
  parts.push(["pending or failed", other, "c-other"]);
  return parts;
}
function perBucket(total, snap) {
  const minutes = (snap.bucket_seconds * snap.buckets.length) / 60;
  return minutes ? total / minutes : 0;
}
function rate(v) { return v >= 10 ? v.toFixed(0) : v >= 1 ? v.toFixed(1) : v.toFixed(2); }

function renderFlow(snap) {
  const hlth = snap.health || {};
  const models = snap.models || {};
  const flow = $("flow");
  const feeds = h("div", { class: "feeds" });
  for (const eco of ecoList(snap)) {
    const series = (snap.scanned.series || {})[eco] || snap.buckets.map(() => 0);
    const total = (snap.scanned.by_ecosystem || {})[eco] || 0;
    const err = (snap.feeds.last_error || {})[eco];
    feeds.append(h("div", { class: "node" },
      nodeHead(1, ecoInfo(eco).feed, null, h("span", { class: "tag", style: { color: cssVar(ecoInfo(eco).color) }, text: ecoInfo(eco).label })),
      h("div", { class: "big" }, h("b", { text: rate(perBucket(total, snap)) }), h("span", { text: "/min scanned" }), h("span", { class: "grow" }), h("span", { text: "total " + n(total) })),
      h("div", { class: "ch" }, spark(series, cssVar(ecoInfo(eco).color))),
      err ? h("div", { class: "err", text: "Feed error: " + err }) : null));
  }
  const rules = snap.rules || {};
  const filter = h("div", { class: "node" },
    nodeHead(2, "Filter", rules.enabled ? "rule pack on" : "rule pack off"),
    h("div", { class: "tier", text: "Deterministic rules on each release diff" }),
    h("div", { class: "big" }, h("b", { text: n(rules.releases_with_hits) }), h("span", { text: "flagged releases with rule hits" })),
    h("div", { class: "sec" }, h("span", { text: "Top rules" }), h("span", { text: "releases" })),
    ...(rules.top_rules && rules.top_rules.length ? rules.top_rules.slice(0, 6).map(([r, c]) => row(r, n(c))) : [h("div", { class: "note", text: "No rule hits in range." })]));

  const scoutModel = models.decision_model || {};
  const bands = snap.scout.bands || {};
  const scoutTotal = sum(Object.values(bands));
  const scout = h("div", { class: "node" },
    nodeHead(3, "Scout", "queue " + n(hlth.pending_jobs)),
    h("div", { class: "tier", text: "Decision model" }),
    h("div", { class: "mid", text: shownDecisionModel(scoutModel.model) }),
    h("div", { class: "big" }, h("b", { text: rate(perBucket(scoutTotal, snap)) }), h("span", { text: "/min" }), h("span", { class: "grow" }), h("span", { text: "scored " + n(scoutTotal) })),
    h("div", { class: "ch" }, spark(snap.buckets.map((_, i) => sum(Object.values(snap.scanned.series || {}).map((sr) => sr[i]))), cssVar("--s-scout"))),
    ...stackBar([["benign", bands.benign || 0, "c-benign"], ["review", bands.review || 0, "c-review"], ["alert", bands.alert || 0, "c-alert"], ["deferred", bands.deferred || 0, "c-deferred"]]),
    h("div", { class: "ft" }, h("span", { text: "retries " + n(hlth.classify_retries) }),
      h("span", { text: hlth.scout_spend_today_usd === undefined ? "spend —" : "today " + usd(hlth.scout_spend_today_usd) + (hlth.scout_spend_cap_usd ? " / " + usd(hlth.scout_spend_cap_usd, 2) : "") }),
      hlth.scout_spend_stopped ? h("span", { class: "err", text: "spend cap reached" }) : null));

  const tModel = models.mid_tier_model || {};
  const triage = h("div", { class: "node" },
    nodeHead(4, "Triage", "queue " + n(hlth.investigations)),
    h("div", { class: "tier", text: "Mid-tier model" + (tModel.backend ? " · " + tModel.backend : "") }),
    h("div", { class: "mid", text: tModel.model || "—" }),
    h("div", { class: "big" }, h("b", { text: n(snap.triage.total) }), h("span", { text: "escalated" })),
    h("div", { class: "ch" }, spark(snap.triage.series, cssVar("--s-triage"))),
    ...stackBar(verdictParts(snap.triage.verdicts)),
    h("div", { class: "ft" }, h("span", { text: "runs " + n(hlth.triage_budget_used) + (hlth.triage_budget_limit ? " / " + n(hlth.triage_budget_limit) : "") })));

  const aModel = models.frontier_model || models.analyst_model || {};
  const analyst = h("div", { class: "node" },
    nodeHead(5, "Analyst", "queue " + n(hlth.analyst_queue)),
    h("div", { class: "tier", text: "Frontier model" + (aModel.backend ? " · " + aModel.backend : "") }),
    h("div", { class: "mid", text: aModel.model || "—" }),
    h("div", { class: "big" }, h("b", { text: n(snap.analyst.total) }), h("span", { text: "reviews" })),
    h("div", { class: "ch" }, spark(snap.analyst.series, cssVar("--s-analyst"))),
    ...stackBar(verdictParts(snap.analyst.verdicts)),
    h("div", { class: "ft" }, h("span", { text: "runs " + n(hlth.analyst_budget_used) + (hlth.analyst_budget_limit ? " / " + n(hlth.analyst_budget_limit) : "") }), h("span", { text: "human review " + n(hlth.human_review_queue) })));

  const wh = snap.webhook;
  const recent = (snap.detections || []).filter((d) => d.alert_status === "sent").slice(0, 4);
  const webhook = h("div", { class: "node" + (wh.alerts_sent ? " hot" : "") },
    nodeHead(6, "Webhook", "outbox " + n(hlth.outbox_depth)),
    h("div", { class: "tier", text: "Alert delivery" }),
    h("div", { class: "big" }, h("b", { text: n(wh.alerts_sent) }), h("span", { text: "alerts sent" }), h("span", { class: "grow" }), h("span", { text: "last " + ago(wh.last_sent_at) })),
    h("div", { class: "ch" }, spark(wh.series, cssVar("--s-webhook"))),
    h("div", { class: "sec" }, h("span", { text: "Recent alerts" })),
    ...(recent.length ? recent.map((d) => row(relName(d), ago(d.analyst_at))) : [h("div", { class: "note", text: "No alerts in range." })]),
    h("div", { class: "ft" }, h("span", { text: "waiting " + n(wh.alerts_waiting) }), wh.outage_notices ? h("span", { class: "err", text: n(wh.outage_notices) + " model-down notice" }) : null));

  clear(flow, feeds, filter, scout, triage, analyst, webhook);
  $("rail-hint").textContent = "lines show releases per " + (snap.bucket_seconds >= 86400 ? "day" : snap.bucket_seconds >= 3600 ? "hour" : "minute") + " over the last " + rangeWord(snap.range);
  clear($("rail-foot"),
    h("span", { text: `Waiting: ${n(hlth.pending_jobs)} for Scout · ${n(hlth.investigations)} for Triage · ${n(hlth.analyst_queue)} for Analyst` }));
}

function renderDetections() {
  const snap = state.snap;
  if (!snap) return;
  let rows = snap.detections || [];
  const f = state.detFilter;
  if (f === "malicious") rows = rows.filter((d) => d.analyst_verdict === "malicious");
  else if (f === "uncertain") rows = rows.filter((d) => d.analyst_verdict === "uncertain");
  else if (f === "cleared") rows = rows.filter((d) => d.triage_verdict === "malicious" && d.analyst_verdict === "benign");
  const list = h("div", { class: "list" });
  for (const d of rows.slice(0, 12)) {
    list.append(h("div", { class: "li click", tabindex: "0", role: "button", onclick: () => openRelease(d), onkeydown: (e) => { if (e.key === "Enter") openRelease(d); } },
      ecoTag(d.ecosystem), h("span", { class: "nm", text: relName(d) }),
      d.partial ? h("span", { class: "chip warn", text: "partial read" }) : null,
      verdictChip(d.analyst_verdict || (d.triage_verdict ? "triage " + d.triage_verdict : null)),
      h("span", { class: "tm", text: ago(d.analyst_at || d.created_at) })));
  }
  clear($("detections"), rows.length ? list : h("div", { class: "empty", text: "Nothing here in this range." }));
}

function renderActivity(snap) {
  const list = h("div", { class: "list" });
  const label = { scout: "Scout", triage: "Triage", analyst: "Analyst", alert: "Alert" };
  for (const ev of (snap.activity || []).slice(0, 14)) {
    const chip = ev.kind === "scout" ? bandChip(ev.text) : ev.kind === "alert" ? h("span", { class: "chip crit", text: "alert sent" }) : verdictChip(ev.text);
    list.append(h("div", { class: "li click", onclick: () => openRelease(ev.item) },
      h("span", { class: "chip acc", text: label[ev.kind] || ev.kind }), h("span", { class: "nm", text: relName(ev.item) }), chip, h("span", { class: "tm", text: ago(ev.ts) })));
  }
  clear($("activity"), (snap.activity || []).length ? list : h("div", { class: "empty", text: "No Scout flags or verdicts in this range." }));
}

function renderSignals(snap) {
  const top = snap.scout.top_signals || [];
  const max = Math.max(1, ...top.map((t) => t[1]));
  const wrap = h("div", { class: "hbars" });
  for (const [sig, c] of top.slice(0, 10)) {
    wrap.append(h("div", { class: "hbar" }, h("span", { text: sig }), h("span", { class: "mono", text: n(c) }), h("div", { class: "track" }, h("i", { style: { width: (100 * c / max).toFixed(1) + "%" } }))));
  }
  clear($("signals"), top.length ? wrap : h("div", { class: "empty", text: "No flagged releases in this range." }));
}

function renderCost(snap) {
  const u = snap.usage || {};
  const models = snap.models || {};
  const rows = u.scout || [];
  const today = new Date().toISOString().slice(0, 10);
  const byDay = {};
  let calls = 0, tokens = 0, cost = 0, estimated = 0;
  for (const r of rows) {
    byDay[r.day] = (byDay[r.day] || 0) + r.usd;
    calls += r.calls; tokens += r.input_tokens + r.output_tokens; cost += r.usd; estimated += r.estimated_calls || 0;
  }
  const days = Object.keys(byDay).sort();
  const scoutCard = h("div", { class: "costcard" },
    h("div", { class: "role", text: "Scout · decision model" }),
    h("div", { class: "mono muted", text: shownDecisionModel((models.decision_model || {}).model) }),
    h("dl", { class: "kv" },
      h("dt", { text: "Spend today" }), h("dd", { text: usd((snap.health || {}).scout_spend_today_usd) }),
      h("dt", { text: "Calls since " + u.since_day }), h("dd", { text: n(calls) }),
      h("dt", { text: "Tokens since " + u.since_day }), h("dd", { text: n(tokens) }),
      h("dt", { text: "Spend since " + u.since_day }), h("dd", { text: usd(cost) + (estimated ? " (" + n(estimated) + " calls estimated)" : "") })),
    h("div", { class: "ch" }, days.length > 1 ? spark(days.map((d) => byDay[d]), cssVar("--accent")) : h("span", { class: "faint", text: days.length ? "one day of usage so far" : "no Scout usage recorded" })));
  const roleCard = (title, model, callsN) => h("div", { class: "costcard" },
    h("div", { class: "role", text: title }),
    h("div", { class: "mono muted", text: (model || {}).model || "—" }),
    h("dl", { class: "kv" },
      h("dt", { text: "Reports in range" }), h("dd", { text: n(callsN) }),
      h("dt", { text: "Tokens" }), h("dd", { text: "not recorded yet" }),
      h("dt", { text: "Cost" }), h("dd", { text: "not recorded yet" })));
  clear($("cost"), scoutCard,
    roleCard("Triage · mid-tier model", models.mid_tier_model, u.triage_calls),
    roleCard("Analyst · frontier model", models.frontier_model || models.analyst_model, u.analyst_calls));
  $("cost-hint").textContent = "Scout spend is measured per call";
}

// ---------- findings ----------
function findParams() {
  const form = $("find-form");
  const p = new URLSearchParams();
  p.set("range", state.range);
  for (const el of form.elements) {
    if (!el.name) continue;
    if (el.type === "checkbox") { if (el.checked) p.set(el.name, el.value); continue; }
    if (el.value) p.set(el.name, el.value);
  }
  p.set("offset", String(state.findOffset));
  p.set("limit", String(state.findLimit));
  if (state.watched !== null) p.set("watched", state.watched ? "1" : "0");
  return p;
}

function fillFacet(select, facets) {
  const cur = select.value;
  const keep = select.options[0];
  select.replaceChildren(keep);
  for (const [name, c] of facets) select.append(h("option", { value: name, text: name + " (" + c + ")" }));
  if ([...select.options].some((o) => o.value === cur)) select.value = cur;
}

async function loadFindings() {
  let data;
  try { data = await api("/api/findings?" + findParams().toString()); } catch (err) {
    clear($("find-table").tBodies[0], h("tr", {}, h("td", { colspan: "7", class: "empty", text: "Could not load findings: " + err.message })));
    return;
  }
  fillFacet($("f-signal"), data.facets.signals);
  fillFacet($("f-rule"), data.facets.rules);
  const body = $("find-table").tBodies[0];
  body.replaceChildren();
  for (const r of data.rows) {
    const sigs = h("div", { class: "sigs" }, ...r.signals.filter((x) => !x.startsWith("rule:")).slice(0, 5).map((x) => h("span", { class: "chip", text: x })));
    if (r.partial_reasons.length) sigs.prepend(h("span", { class: "chip warn", text: "partial read" }));
    body.append(h("tr", { class: "click", tabindex: "0", onclick: () => openRelease(r), onkeydown: (e) => { if (e.key === "Enter") openRelease(r); } },
      h("td", { class: "mono", text: clock(r.created_at) }),
      h("td", { class: "pkg" }, ecoTag(r.ecosystem), " ", r.name, h("span", { class: "sub", text: (r.old_version ? r.old_version + " → " : "") + r.version })),
      h("td", {}, bandChip(r.band), h("span", { class: "sub mono", text: "p " + prob(r.p) })),
      h("td", {}, verdictChip(r.triage_verdict || r.triage_status)),
      h("td", {}, verdictChip(r.analyst_verdict || r.analyst_status)),
      h("td", { text: r.alert_status || "—" }),
      h("td", {}, sigs)));
  }
  if (!data.rows.length) body.append(h("tr", {}, h("td", { colspan: "7", class: "empty", text: "No findings match these filters in the last " + rangeWord(data.range) + "." })));
  const end = Math.min(data.total, data.offset + data.rows.length);
  $("find-count").textContent = data.total ? `Showing ${data.offset + 1}–${end} of ${n(data.total)}` : "";
  $("find-prev").disabled = data.offset === 0;
  $("find-next").disabled = end >= data.total;
  $("find-hint").textContent = data.scope === "triage" ? "every release that reached Triage, malicious and benign" : "every release Scout flagged (review, alert or deferred)";
}

// ---------- release dialog ----------
async function openRelease(item) {
  const dlg = $("dlg");
  $("dlg-title").textContent = item.ecosystem + " " + relName(item);
  clear($("dlg-body"), h("div", { class: "empty", text: "Loading…" }));
  if (!dlg.open) dlg.showModal();
  let d;
  try {
    d = await api("/api/release?" + new URLSearchParams({ ecosystem: item.ecosystem, name: item.name, version: item.version }).toString());
  } catch (err) {
    clear($("dlg-body"), h("div", { class: "empty", text: "Could not load this release: " + err.message }));
    return;
  }
  const r = d.release;
  const kv = (pairs) => h("dl", { class: "kvg" }, ...pairs.map(([k, v]) => h("div", {}, h("dt", { text: k }), h("dd", { text: v === null || v === undefined || v === "" ? "—" : String(v) }))));
  const secs = [];
  secs.push(h("div", { class: "dsec" }, h("h4", { text: "Scout" }), kv([
    ["Versions", (r.old_version || "?") + " → " + r.version], ["Band", r.band], ["P(malice)", prob(r.p)], ["Family", r.family],
    ["Subtype", r.subtype], ["Rule verdict", r.rule_verdict], ["Decision model", shownDecisionModel(r.scout_model_id)], ["Scored", clock(r.created_at)],
    ["Risk score", r.risk_score === null || r.risk_score === undefined ? null : r.risk_score + " / 100"],
    ["Partial read", r.partial_reasons.length ? r.partial_reasons.join(", ") : "no"], ["Deferred because", r.defer_reason]])));
  if (r.risk_why && r.risk_why.length) {
    secs.push(h("div", { class: "dsec" }, h("h4", { text: "Why this risk score" }), h("div", { class: "sigs" }, ...r.risk_why.map((x) => h("span", { class: "chip", text: "+" + x.points + " " + x.text })))));
  }
  if (r.registry_url && /^https:\/\//.test(r.registry_url)) {
    secs.push(h("div", {}, h("a", { href: r.registry_url, rel: "noopener noreferrer", target: "_blank", text: "Open the registry page" })));
  }
  if (r.watch) {
    const w = r.watch;
    secs.push(h("div", { class: "dsec" }, h("h4", { text: "Your watchlist" }), kv([
      ["Direct", w.direct ? "yes" : "no"], ["Your files list", (w.pinned_versions || []).join(", ") || "a range or no version"],
      ["This exact version", w.exact_match ? (w.tag_ref ? "yes (the tag you use pointed at this commit)" : "yes") : "no"],
      ["Sources", (w.sources || []).join(", ")], ["Imported", clock(w.oldest_import_at) + (w.stale ? " (older than 7 days)" : "")]])));
  }
  secs.push(h("div", { class: "dsec" }, h("h4", { text: "Signals" }), h("div", { class: "sigs" }, ...r.signals.map((x) => h("span", { class: "chip", text: x })))));
  if (r.rule_hits.length) {
    secs.push(h("div", { class: "dsec" }, h("h4", { text: "Rule hits" }), h("div", { class: "tablewrap" }, h("table", { class: "grid" },
      h("thead", {}, h("tr", {}, h("th", { text: "Rule" }), h("th", { text: "Tier" }), h("th", { text: "Where" }), h("th", { text: "Matched text" }))),
      h("tbody", {}, ...r.rule_hits.map((x) => h("tr", {}, h("td", { class: "mono", text: x.rule }), h("td", { text: x.tier }), h("td", { class: "pkg", text: x.path + (x.line ? ":" + x.line : "") }), h("td", { class: "pkg", text: x.matched }))))))));
  }
  for (const [title, st] of [["Triage", d.triage], ["Analyst", d.analyst]]) {
    if (!st) { secs.push(h("div", { class: "dsec" }, h("h4", { text: title }), h("div", { class: "faint", text: "Did not reach this stage." }))); continue; }
    secs.push(h("div", { class: "dsec" }, h("h4", { text: title }),
      kv([["Status", st.status], ["Verdict", st.verdict], ["Attempts", st.attempts], ["Queued", clock(st.created_at)], ["Updated", clock(st.updated_at)]]),
      st.report ? h("pre", { class: "report", text: st.report }) : null));
  }
  secs.push(h("div", { class: "dsec" }, h("h4", { text: "Webhook" }), d.webhook.length
    ? kv(d.webhook.flatMap((w) => [[w.kind + " status", w.status + (w.had_error ? " (last attempt failed)" : "")], ["attempts", w.attempts], ["sent", clock(w.sent_at)]]))
    : h("div", { class: "faint", text: "No alert queued for this release." })));
  secs.push(h("div", { class: "faint", text: "Reports are model output built from package contents, shown as plain text." }));
  clear($("dlg-body"), ...secs);
}

// ---------- benchmark ----------
const MODEL_COLORS = ["--m1", "--m2", "--m3", "--m4", "--m5", "--m6"];
function modelColor(key) {
  const slot = modelSlot(key);
  const i = slot ? COMPARISON_SLOTS.indexOf(slot) : 0;
  return cssVar(MODEL_COLORS[(i < 0 ? 0 : i) % MODEL_COLORS.length]);
}
function modelNote(m) {
  const rules = m.rules ? "rules " + m.rules : "";
  const slot = modelSlot(m.model);
  if (slot === "luna") return ["OpenAI Decisions", rules].filter(Boolean).join(" · ");
  if (slot === "clef-flash") return rules;
  return [m.backend || "", rules].filter(Boolean).join(" · ");
}
function inServe(m) {
  const prod = state.bench && state.bench.production_scout;
  if (!prod) return false;
  return m.model === prod || (modelSlot(m.model) !== null && modelSlot(m.model) === modelSlot(prod));
}
function previousComparison(run) {
  const runs = comparisonRuns(state.bench);
  const i = runs.findIndex((r) => r.id === run.id);
  return i > 0 ? runs[i - 1] : null;
}
function delta(cur, prev, digits, unit, betterHigh) {
  if (cur === null || cur === undefined || prev === null || prev === undefined) return null;
  const d = cur - prev;
  if (Math.abs(d) < 1e-9) return h("span", { class: "faint", text: " no change" });
  const good = betterHigh ? d > 0 : d < 0;
  return h("span", { class: good ? "verdict-ok" : "verdict-no", text: " " + (d > 0 ? "+" : "−") + Math.abs(d * (unit === "pts" ? 100 : 1)).toFixed(digits) + (unit === "pts" ? " pts" : "") });
}
function tpLine(m) { return n(m.catch) + " of " + n(m.bad_n) + " bad (" + pct(m.catch_rate) + ")"; }
function fpLine(m) { return n(m.false_flags) + " of " + n(m.clean_n) + " clean (" + pct(m.false_flag_rate) + ")"; }

async function loadBench() {
  const body = $("bench-body");
  clear(body, h("div", { class: "empty", text: "Loading benchmark results…" }));
  try { state.bench = await api("/api/benchmark"); } catch (err) {
    clear(body, h("div", { class: "tile" }, h("div", { class: "tb empty", text: "Could not load benchmark results: " + err.message })));
    return;
  }
  const runs = comparisonRuns(state.bench);
  if (!runs.length) {
    clear(body, h("div", { class: "tile" }, h("div", { class: "tb empty", text: "No benchmark comparison of Luna, clef-flash, and Jev yet." })));
    return;
  }
  if (!state.benchRun || !runs.some((r) => r.id === state.benchRun)) state.benchRun = runs[runs.length - 1].id;
  renderBench();
}

function renderBench() {
  const runs = comparisonRuns(state.bench);
  const run = runs.find((r) => r.id === state.benchRun) || runs[runs.length - 1];
  if (!run) return;
  const models = modelsForRun(run);
  const prev = previousComparison(run);
  const body = $("bench-body");
  const shared = models.length === 3 && models.every((m) => m.bad_n === models[0].bad_n && m.clean_n === models[0].clean_n && m.cases === models[0].cases);
  const strip = h("div", { class: "strip" },
    h("span", {}, "Run ", h("b", { text: run.run_date || run.id })),
    shared
      ? h("span", {}, h("b", { text: n(models[0].bad_n) + " malicious and " + n(models[0].clean_n) + " clean releases" }))
      : null,
    h("span", { text: "Luna, clef-flash, and Jev" }));
  const lines = models.filter((m) => m.status === "ok").map((m) =>
    h("span", { text: modelLabel(m.model) + " caught " + tpLine(m) + " and flagged " + fpLine(m) + "." }));
  const hero = h("div", { class: "tile hero k-hero s12" },
    h("div", { class: "m" }, h("b", { text: "True positives and false positives" }), ...lines));
  clear(body, strip, h("section", { class: "bento" }, hero),
    leaderboard(models, prev),
    h("section", { class: "bento" }, scatterTile(models, prev), historyTile()),
    matrixTile(run, models),
    h("section", { class: "bento" }, pipelineTile(run), extrasTile(run)),
    costTile(models),
    runHistoryTile());
}

function leaderboard(models, prev) {
  const rows = models.map((m, i) => {
    const p = findSlot(prev, modelSlot(m.model));
    const color = modelColor(m.model);
    const label = modelLabel(m.model);
    if (m.status !== "ok") {
      return h("tr", {}, h("td", { text: "—" }),
        h("td", {}, h("div", { class: "mrow" }, h("b", {}, h("span", { class: "dot", style: { background: color } }), label))),
        h("td", { colspan: "5", text: "No results recorded." }));
    }
    return h("tr", {},
      h("td", { class: "mono", text: String(i + 1) }),
      h("td", {}, h("div", { class: "mrow" }, h("b", {}, h("span", { class: "dot", style: { background: color } }), label, inServe(m) ? h("span", { class: "chip ok", text: "in serve" }) : null), modelNote(m) ? h("span", { text: modelNote(m) }) : null)),
      h("td", {}, h("div", { class: "meter" }, h("div", { class: "track" }, h("i", { style: { width: (100 * (m.catch_rate || 0)).toFixed(1) + "%", background: color } })), h("span", { class: "mono", text: pct(m.catch_rate) }), p ? delta(m.catch_rate, p.catch_rate, 1, "pts", true) : null), h("span", { class: "sub mono", text: n(m.catch) + " of " + n(m.bad_n) + " bad" })),
      h("td", { class: "num mono" }, pct(m.false_flag_rate), p ? delta(m.false_flag_rate, p.false_flag_rate, 1, "pts", false) : null, h("span", { class: "sub", text: n(m.false_flags) + " of " + n(m.clean_n) + " clean" })),
      h("td", { class: "num mono" }, m.input_tokens === null || !m.cases ? "—" : n(Math.round(m.input_tokens / m.cases))),
      h("td", { class: "num mono", text: m.usd_per_case === null ? "—" : usd(m.usd_per_case * 1000, 2) }),
      h("td", { class: "num mono", text: usd(m.usd) }));
  });
  return h("section", { class: "tile" },
    h("div", { class: "th" }, h("h2", { text: "Luna, clef-flash, and Jev" }), h("span", { class: "hint", text: "bad releases caught, and clean releases flagged" })),
    h("div", { class: "tb" }, h("div", { class: "tablewrap" }, h("table", { class: "grid" },
      h("thead", {}, h("tr", {}, ...["#", "Model", "True positives", "False positives", "Tokens / release", "$ / 1k releases", "Run spend"].map((t, i) => h("th", { class: i >= 3 ? "num" : null, text: t })))),
      h("tbody", {}, ...rows)))));
}

function scatterTile(models, prev) {
  const W = 520, H = 260, L = 44, R = 12, T = 16, B = 34;
  const ok = models.filter((m) => m.status === "ok" && m.catch_rate !== null && m.false_flag_rate !== null);
  const svg = s("svg", { class: "chart", viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "True positives against false positives" });
  if (!ok.length) {
    svg.append(s("text", { x: L, y: H / 2, text: "No measured results yet." }));
  } else {
    const maxFp = Math.max(0.02, ...ok.map((m) => m.false_flag_rate * 1.25));
    const minCatch = Math.min(0.6, ...ok.map((m) => m.catch_rate - 0.05));
    const x0 = -maxFp * 0.06, y1 = 1.03;
    const x = (v) => L + ((v - x0) / (maxFp - x0)) * (W - L - R);
    const y = (v) => T + (1 - (v - minCatch) / (y1 - minCatch)) * (H - T - B);
    for (let i = 0; i <= 4; i++) {
      const cv = minCatch + (1 - minCatch) * i / 4;
      svg.append(s("line", { class: "gridl", x1: L, x2: W - R, y1: y(cv), y2: y(cv) }), s("text", { x: 4, y: y(cv) + 3, text: pct(cv, 0) }));
      const fv = maxFp * i / 4;
      svg.append(s("text", { x: x(fv) - 10, y: H - 18, text: pct(fv, 1) }));
    }
    svg.append(s("text", { x: L, y: H - 4, text: "false positives (clean releases flagged) →" }));
    svg.append(s("text", { x: 4, y: 12, text: "true positives" }));
    for (const m of ok) {
      const color = modelColor(m.model);
      const p = findSlot(prev, modelSlot(m.model));
      if (p && p.status === "ok" && p.catch_rate !== null && p.false_flag_rate !== null) {
        svg.append(s("line", { x1: x(p.false_flag_rate), y1: y(p.catch_rate), x2: x(m.false_flag_rate), y2: y(m.catch_rate), stroke: color, "stroke-dasharray": "3 3" }));
        svg.append(s("circle", { cx: x(p.false_flag_rate), cy: y(p.catch_rate), r: 3, fill: "none", stroke: color }));
      }
      svg.append(s("circle", { cx: x(m.false_flag_rate), cy: y(m.catch_rate), r: 7, fill: color, "fill-opacity": "0.85" }, s("title", { text: modelLabel(m.model) + ": " + tpLine(m) + ", " + fpLine(m) })));
      svg.append(s("text", { x: x(m.false_flag_rate) + 11, y: y(m.catch_rate) + 4, text: modelLabel(m.model) }));
    }
  }
  return h("div", { class: "tile s6" },
    h("div", { class: "th" }, h("h2", { text: "True positives against false positives" })),
    h("div", { class: "tb" }, svg));
}

const HISTORY_METRICS = {
  catch_rate: { rate: true, label: "True positives", get: (run, m) => m.catch_rate, fmt: (v) => pct(v), pipeline: false },
  false_flag_rate: { rate: true, label: "False positives", get: (run, m) => m.false_flag_rate, fmt: (v) => pct(v), pipeline: false },
  cost: { label: "$ / 1k releases", get: (run, m) => (m.usd_per_case === null ? null : m.usd_per_case * 1000), fmt: (v) => usd(v, 2), pipeline: false },
  triage: { rate: true, label: "Triage confirms", get: (run) => pipeRate(run, "triage_malicious"), fmt: (v) => pct(v), pipeline: true },
  analyst: { rate: true, label: "Analyst confirms", get: (run) => pipeRate(run, "analyst_malicious"), fmt: (v) => pct(v), pipeline: true },
};
function pipeRate(run, key) {
  const p = run.pipeline;
  if (!p || typeof p[key] !== "number" || typeof p.hits !== "number" || !p.hits) return null;
  return p[key] / p.hits;
}

function historyTile() {
  const runs = comparisonRuns(state.bench);
  const metric = HISTORY_METRICS[state.historyMetric];
  const seg = h("div", { class: "seg small end", role: "group", "aria-label": "History metric" },
    ...Object.entries(HISTORY_METRICS).map(([key, def]) => h("button", { type: "button", "aria-pressed": String(key === state.historyMetric), text: def.label, onclick: () => { state.historyMetric = key; renderBench(); } })));
  const series = [];
  if (metric.pipeline) {
    series.push({ name: metric.label, color: cssVar(state.historyMetric === "triage" ? "--s-triage" : "--s-analyst"), pts: runs.map((r) => metric.get(r)) });
  } else {
    for (const slot of COMPARISON_SLOTS) series.push({ name: modelLabel(slot), color: modelColor(slot), pts: runs.map((r) => { const m = findSlot(r, slot); return m && m.status === "ok" ? metric.get(r, m) : null; }) });
  }
  const W = 520, H = 260, L = 48, R = 12, T = 12, B = 28;
  const vals = series.flatMap((sr) => sr.pts).filter((v) => v !== null);
  const svg = s("svg", { class: "chart", viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": metric.label + " for Luna, clef-flash, and Jev" });
  if (!vals.length) {
    svg.append(s("text", { x: L, y: H / 2, text: "No measured values for this metric yet." }));
  } else {
    let lo = Math.min(...vals), hi = Math.max(...vals);
    if (hi - lo < 1e-9) { lo = Math.max(0, lo - (hi || 1) * 0.1); hi = hi + (hi || 1) * 0.1; }
    if (metric.rate) { hi = Math.min(1, hi); lo = Math.max(0, Math.min(lo, hi - 0.1)); }
    const x = (i) => runs.length === 1 ? (L + W - R) / 2 : L + (i / (runs.length - 1)) * (W - L - R);
    const y = (v) => T + (1 - (v - lo) / (hi - lo)) * (H - T - B);
    for (let i = 0; i <= 4; i++) { const v = lo + (hi - lo) * i / 4; svg.append(s("line", { class: "gridl", x1: L, x2: W - R, y1: y(v), y2: y(v) }), s("text", { x: 2, y: y(v) + 3, text: metric.fmt(v) })); }
    runs.forEach((r, i) => svg.append(s("text", { x: x(i) - 18, y: H - 8, text: r.run_date || r.id })));
    for (const sr of series) {
      let d = "";
      sr.pts.forEach((v, i) => { if (v === null) return; d += (d ? " L" : "M") + x(i).toFixed(1) + " " + y(v).toFixed(1); });
      if (d.includes("L")) svg.append(s("path", { d, fill: "none", stroke: sr.color, "stroke-width": "2" }));
      sr.pts.forEach((v, i) => { if (v !== null) svg.append(s("circle", { cx: x(i), cy: y(v), r: 4.5, fill: sr.color }, s("title", { text: sr.name + ": " + metric.fmt(v) }))); });
    }
  }
  return h("div", { class: "tile s6" },
    h("div", { class: "th" }, h("h2", { text: "Same comparison over time" }), seg),
    h("div", { class: "tb" }, svg,
      h("div", { class: "legend" }, ...series.map((sr) => h("span", {}, h("span", { class: "dot", style: { background: sr.color } }), sr.name)))));
}

function caseCell(c, label) {
  if (!c) return h("span", { class: "cell na", text: "—" });
  if (c.status && c.status !== "ok") return h("span", { class: "cell deferred", text: c.status });
  const bad = label === "malicious";
  let cls = c.band || "benign";
  if (bad && !c.to_triage) cls = "missed";
  if (!bad && c.to_triage) cls = "fp";
  return h("span", { class: "cell " + cls }, h("span", { text: cls === "missed" ? "missed" : cls === "fp" ? "false flag" : c.band }), h("span", { text: prob(c.p) }));
}

function matrixTile(run, models) {
  const keys = models.map((m) => m.model);
  const pipeById = {};
  for (const pc of run.pipeline_cases || []) if (pc.id) pipeById[pc.id] = pc;
  const ids = [];
  const info = {};
  for (const key of keys) for (const c of (run.cases && run.cases[key]) || []) { if (!info[c.id]) { ids.push(c.id); info[c.id] = c; } }
  const caught = (c) => c && c.to_triage === true;
  let rows = ids.filter((id) => {
    const lab = info[id].label;
    if (state.matrixSet === "bad" && lab !== "malicious") return false;
    if (state.matrixSet === "clean" && lab === "malicious") return false;
    const cells = keys.map((m) => ((run.cases && run.cases[m]) || []).find((c) => c.id === id));
    if (state.matrixShow === "missed") return lab === "malicious" && cells.some((c) => c && !caught(c));
    if (state.matrixShow === "flagged") return lab !== "malicious" && cells.some((c) => caught(c));
    if (state.matrixShow === "disagree") return new Set(cells.map((c) => (c ? String(caught(c)) : "none"))).size > 1;
    return true;
  });
  const segBtn = (group, key, label) => h("button", { type: "button", "aria-pressed": String(state[group] === key), text: label, onclick: () => { state[group] = key; renderBench(); } });
  const hasPipe = Object.keys(pipeById).length > 0;
  const pipe = run.pipeline || {};
  const head = h("tr", {}, h("th", { text: "Release" }), h("th", { text: "Label" }),
    ...models.map((m) => h("th", {}, h("span", { class: "dot", style: { background: modelColor(m.model) } }), modelLabel(m.model))),
    hasPipe ? h("th", { text: "Triage" }) : null,
    hasPipe ? h("th", { text: "Analyst" }) : null);
  const body = rows.map((id) => {
    const lab = info[id].label;
    const pc = pipeById[id];
    return h("tr", {}, h("td", { class: "pkg", text: id }), h("td", {}, h("span", { class: "chip " + (lab === "malicious" ? "crit" : "ok"), text: lab === "malicious" ? "malicious" : "clean" })),
      ...keys.map((m) => h("td", {}, caseCell(((run.cases && run.cases[m]) || []).find((c) => c.id === id), lab))),
      hasPipe ? h("td", {}, pc ? h("span", { class: "cell " + (pc.triage_verdict === "malicious" ? "mal" : "benign"), text: pc.triage_verdict || pc.triage_status || "—" }) : h("span", { class: "cell na", text: "—" })) : null,
      hasPipe ? h("td", {}, pc ? h("span", { class: "cell " + (pc.analyst_verdict === "malicious" ? "mal" : "benign"), text: pc.analyst_verdict || pc.analyst_status || "—" }) : h("span", { class: "cell na", text: "—" })) : null);
  });
  return h("section", { class: "tile" },
    h("div", { class: "th" }, h("h2", { text: "Release by release" }), h("span", { class: "hint", text: "how Luna, clef-flash, and Jev scored each release" }),
      h("div", { class: "end" }, h("div", { class: "seg small", role: "group", "aria-label": "Cases" }, segBtn("matrixSet", "all", "All"), segBtn("matrixSet", "bad", "Malicious"), segBtn("matrixSet", "clean", "Clean")), " ",
        h("div", { class: "seg small", role: "group", "aria-label": "Show" }, segBtn("matrixShow", "all", "All"), segBtn("matrixShow", "missed", "Missed by any"), segBtn("matrixShow", "flagged", "False positive by any"), segBtn("matrixShow", "disagree", "Models disagree")))),
    h("div", { class: "tb" }, keys.length && ids.length
      ? h("div", { class: "tablewrap" }, h("table", { class: "grid" }, h("thead", {}, head), h("tbody", {}, ...(body.length ? body : [h("tr", {}, h("td", { colspan: String(2 + keys.length + (hasPipe ? 2 : 0)), class: "empty", text: "No releases match." }))]))))
      : h("div", { class: "empty", text: "This run has no per-release results." })));
}

function pipelineTile(run) {
  const p = run.pipeline;
  if (!p) return h("div", { class: "tile s6" }, h("div", { class: "th" }, h("h2", { text: "Triage and Analyst" })), h("div", { class: "tb empty", text: "This run scored the decision models only." }));
  const val = (v) => (v === null || v === undefined ? "—" : typeof v === "number" ? n(v) : String(v));
  const est = (v) => (typeof v === "number" ? h("span", {}, usd(v, 2), h("span", { class: "est", text: "EST" })) : val(v));
  const kv = (pairs) => h("dl", { class: "kvg" }, ...pairs.map(([k, v]) => h("div", {}, h("dt", { text: k }), h("dd", {}, v))));
  return h("div", { class: "tile s6" },
    h("div", { class: "th" }, h("h2", { text: "Triage and Analyst" })),
    h("div", { class: "tb" }, kv([
      ["Triage model", val(p.triage)], ["Analyst model", val(p.analyst)],
      ["Releases sent on", val(p.hits)], ["Triage said malicious", val(p.triage_malicious) + (typeof p.hits === "number" ? " of " + n(p.hits) : "")],
      ["Analyst said malicious", val(p.analyst_malicious) + (typeof p.hits === "number" ? " of " + n(p.hits) : "")], ["Would alert", val(p.would_discord)],
      ["Clean releases flagged", val(p.clean_to_triage)],
      ["Triage cost", est(p.triage_usd_est)], ["Analyst cost", est(p.analyst_usd_est)]])));
}

function extrasTile(run) {
  const items = [];
  const r = run.rules_on_vs_off && run.rules_on_vs_off.rules_on;
  if (r && typeof r === "object") {
    items.push(h("li", { text: `Rules on: malicious ${val0(r.bad_malicious)} caught, ${val0(r.bad_unsure)} unsure, ${val0(r.bad_nothing)} missed (of ${val0(r.bad_n)}); clean ${val0(r.clean_malicious)} flagged, ${val0(r.clean_unsure)} unsure, ${val0(r.clean_nothing)} clear (of ${val0(r.clean_n)}).` }));
  }
  const f = run.fallback;
  if (f && typeof f === "object" && f.backup_model) {
    const name = shownDecisionModel(f.backup_model);
    items.push(h("li", { text: `Backup decision model ${name}.` }));
  }
  if (!items.length) return null;
  return h("div", { class: "tile s6" },
    h("div", { class: "th" }, h("h2", { text: "Rules and backup" })),
    h("div", { class: "tb" }, h("ul", { class: "notes" }, ...items)));
}
function val0(v) { return v === null || v === undefined ? "—" : n(v); }

function costTile(models) {
  const ok = models.filter((m) => m.status === "ok");
  const max = Math.max(1e-9, ...ok.map((m) => m.usd_per_case || 0));
  const rows = models.map((m) => h("div", { class: "hbar" },
    h("span", {}, h("span", { class: "dot", style: { background: modelColor(m.model) } }), modelLabel(m.model)),
    h("span", { class: "mono", text: m.status !== "ok" || m.usd_per_case === null ? "—" : usd(m.usd_per_case * 1000, 2) + " / 1k" }),
    h("div", { class: "track" }, m.status === "ok" && m.usd_per_case !== null ? h("i", { style: { width: (100 * m.usd_per_case / max).toFixed(1) + "%", background: modelColor(m.model) } }) : null),
    h("span", { class: "faint", text: m.status !== "ok" ? "" : n(m.input_tokens) + " input tokens · " + usd(m.usd) })));
  return h("section", { class: "tile" },
    h("div", { class: "th" }, h("h2", { text: "Tokens and cost" })),
    h("div", { class: "tb" }, h("div", { class: "hbars" }, ...rows)));
}

function runHistoryTile() {
  const runs = comparisonRuns(state.bench).slice().reverse();
  if (runs.length < 2) return null;
  const rows = [];
  for (const run of runs) {
    for (const m of modelsForRun(run)) {
      rows.push(h("tr", { class: "click", onclick: () => { state.benchRun = run.id; renderBench(); window.scrollTo({ top: 0, behavior: "smooth" }); } },
        h("td", { text: run.run_date || run.id }),
        h("td", {}, h("span", { class: "dot", style: { background: modelColor(m.model) } }), modelLabel(m.model)),
        h("td", { class: "num mono", text: m.status === "ok" ? n(m.catch) + " of " + n(m.bad_n) : "—" }),
        h("td", { class: "num mono", text: m.status === "ok" ? n(m.false_flags) + " of " + n(m.clean_n) : "—" }),
        h("td", { class: "num mono", text: usd(m.usd) })));
    }
  }
  return h("section", { class: "tile" },
    h("div", { class: "th" }, h("h2", { text: "Earlier runs" }), h("span", { class: "hint", text: "the same three models" })),
    h("div", { class: "tb" }, h("div", { class: "tablewrap" }, h("table", { class: "grid" },
      h("thead", {}, h("tr", {}, ...["Run date", "Model", "True positives", "False positives", "Spend"].map((t, i) => h("th", { class: i >= 2 ? "num" : null, text: t })))),
      h("tbody", {}, ...rows)))));
}

// ---------- wiring ----------
function setTab(tab) {
  state.tab = tab;
  for (const b of document.querySelectorAll(".tabs button")) b.setAttribute("aria-current", b.dataset.tab === tab ? "page" : "false");
  $("page-dash").hidden = tab !== "dash";
  $("page-bench").hidden = tab !== "bench";
  try { localStorage.setItem("hunter-dashboard-tab", tab); } catch (e) { /* storage blocked */ }
  if (tab === "bench") loadBench();
}

function initTheme() {
  let saved = null;
  try { saved = localStorage.getItem("hunter-dashboard-theme"); } catch (e) { saved = null; }
  if (saved) document.documentElement.setAttribute("data-theme", saved);
  $("theme").addEventListener("click", () => {
    const dark = document.documentElement.getAttribute("data-theme") === "dark" ||
      (!document.documentElement.getAttribute("data-theme") && matchMedia("(prefers-color-scheme: dark)").matches);
    const next = dark ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("hunter-dashboard-theme", next); } catch (e) { /* storage blocked */ }
    renderDashboard();
    if (state.bench && state.tab === "bench") renderBench();
  });
}

function init() {
  initTheme();
  for (const b of document.querySelectorAll(".tabs button")) b.addEventListener("click", () => setTab(b.dataset.tab));
  for (const b of document.querySelectorAll("#range button")) {
    b.addEventListener("click", () => {
      state.range = b.dataset.range;
      for (const o of document.querySelectorAll("#range button")) o.setAttribute("aria-pressed", String(o === b));
      state.findOffset = 0;
      refresh();
      loadFindings();
    });
  }
  for (const b of document.querySelectorAll("#det-filter button")) {
    b.addEventListener("click", () => {
      state.detFilter = b.dataset.f;
      for (const o of document.querySelectorAll("#det-filter button")) o.setAttribute("aria-pressed", String(o === b));
      renderDetections();
    });
  }
  $("watched-only").addEventListener("change", (e) => {
    state.watched = e.target.checked;
    state.findOffset = 0;
    refresh();
    loadFindings();
  });
  let timer = null;
  const onFilter = () => { clearTimeout(timer); timer = setTimeout(() => { state.findOffset = 0; loadFindings(); }, 250); };
  $("find-form").addEventListener("input", onFilter);
  $("find-form").addEventListener("change", onFilter);
  $("find-form").addEventListener("submit", (e) => e.preventDefault());
  $("find-prev").addEventListener("click", () => { state.findOffset = Math.max(0, state.findOffset - state.findLimit); loadFindings(); });
  $("find-next").addEventListener("click", () => { state.findOffset += state.findLimit; loadFindings(); });
  $("dlg-close").addEventListener("click", () => $("dlg").close());
  $("dlg").addEventListener("click", (e) => { if (e.target === $("dlg")) $("dlg").close(); });
  const benchPick = $("bench-run");
  if (benchPick) benchPick.addEventListener("change", (e) => { state.benchRun = e.target.value; renderBench(); });

  let tab = "dash";
  try { tab = localStorage.getItem("hunter-dashboard-tab") || "dash"; } catch (e) { tab = "dash"; }
  if (/(^|[#&])bench\b/.test(location.hash || "")) tab = "bench";
  setTab(tab === "bench" ? "bench" : "dash");
  refresh();
  loadFindings();
  setInterval(() => { if (!document.hidden) { refresh(); } }, REFRESH_MS);
  setInterval(() => { if (!document.hidden && state.tab === "dash") loadFindings(); }, REFRESH_MS * 3);
  setInterval(tickLive, 1000);
}

document.addEventListener("DOMContentLoaded", init);
