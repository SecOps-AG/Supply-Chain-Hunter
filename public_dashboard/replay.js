// Hunter dashboard replay. Pure logic: no DOM, no network, no timers, so it runs the same
// in the page and under node tests.
//
// Serve uploads live.json in batches (about every 35 s while idle, a few seconds after each
// busy round). Each upload carries `stream`: the real pipeline events of the last few minutes
// with their stored timestamps. The page plays those events at their real times, a fixed
// delay behind serve, so the pipeline moves steadily instead of jumping. Nothing here
// invents an event: counters are a snapshot total plus or minus real events, and they equal
// the newest snapshot once playback reaches it.
"use strict";

(function (root) {
  const DEFAULTS = {
    delayMs: 45000, // covers the ~36 s idle upload gap + 2 s edge cache + 5 s poll
    jumpAfterMs: 10000, // further behind than this (hidden tab, sleep): jump, don't replay
    maxSpeed: 4, // smaller gaps are closed by playing faster
    frameMs: 250, // a gap up to one slow frame is normal playback
    keepMs: 60000, // events kept behind the playhead for late arrivals and counters
    maxDocs: 24,
  };
  const KINDS = ["poll", "scan", "triage_in", "triage", "analyst_in", "analyst", "alert"];
  const FLAGGED_BANDS = ["review", "alert", "deferred"];
  const FIELDS = ["t", "kind", "eco", "name", "version", "result"];

  function parseTime(ts) {
    if (!ts) return null;
    const t = Date.parse(ts);
    return Number.isNaN(t) ? null : t;
  }

  function eventId(kind, eco, name, version, tSec) {
    return [kind, eco, name || "", version || "", tSec].join("|");
  }

  // Validate the stream block and turn rows into event objects. Malformed rows are dropped.
  function parseStream(stream) {
    const out = { untilMs: null, sinceMs: null, truncated: false, pollIntervalS: null, events: [] };
    if (!stream || stream.v !== 1 || !Array.isArray(stream.fields) || !Array.isArray(stream.events)) return out;
    const idx = {};
    for (const f of FIELDS) {
      idx[f] = stream.fields.indexOf(f);
      if (idx[f] < 0) return out;
    }
    out.untilMs = parseTime(stream.until);
    out.sinceMs = parseTime(stream.since);
    out.truncated = stream.truncated === true;
    out.pollIntervalS = typeof stream.poll_interval_s === "number" && stream.poll_interval_s > 0 ? stream.poll_interval_s : null;
    for (const row of stream.events) {
      if (!Array.isArray(row)) continue;
      const tSec = row[idx.t];
      const kind = row[idx.kind];
      const eco = row[idx.eco];
      if (typeof tSec !== "number" || !Number.isFinite(tSec) || !KINDS.includes(kind) || typeof eco !== "string") continue;
      const str = (v) => (typeof v === "string" ? v : null);
      const name = str(row[idx.name]);
      const version = str(row[idx.version]);
      if (kind !== "poll" && (!name || !version)) continue;
      out.events.push({
        id: eventId(kind, eco, name, version, tSec),
        t: tSec * 1000,
        at: tSec * 1000,
        kind,
        eco,
        name,
        version,
        result: str(row[idx.result]),
      });
    }
    return out;
  }

  // Timestamps have one-second precision. Events sharing a second are spaced evenly inside
  // that second so a burst plays as a quick run, never outside its real second.
  function spreadWithinSecond(events) {
    const groups = new Map();
    for (const ev of events) {
      if (!groups.has(ev.t)) groups.set(ev.t, []);
      groups.get(ev.t).push(ev);
    }
    const out = [];
    for (const [t, group] of groups) {
      group.forEach((ev, i) => out.push(Object.assign({}, ev, { at: t + Math.floor((1000 * i) / group.length) })));
    }
    out.sort((a, b) => a.at - b.at || KINDS.indexOf(a.kind) - KINDS.indexOf(b.kind));
    return out;
  }

  // Server clock minus client clock, from (HTTP Date, local receive time) pairs. Date is
  // truncated to the second, so +500 ms centers it. Median of the recent samples.
  function estimateSkew(samples) {
    const diffs = (samples || [])
      .filter((s) => s && Number.isFinite(s.serverMs) && Number.isFinite(s.clientMs))
      .map((s) => s.serverMs + 500 - s.clientMs)
      .sort((a, b) => a - b);
    if (!diffs.length) return 0;
    const mid = diffs.length >> 1;
    return diffs.length % 2 ? diffs[mid] : Math.round((diffs[mid - 1] + diffs[mid]) / 2);
  }

  // How to close the gap between where playback is and where it should be.
  function planCatchUp(lagMs, opts) {
    const o = Object.assign({}, DEFAULTS, opts || {});
    if (!(lagMs > o.frameMs)) return { mode: "play", speed: 1 };
    if (lagMs > o.jumpAfterMs) return { mode: "jump", speed: Infinity };
    return { mode: "catchup", speed: o.maxSpeed };
  }

  // Which counters an event moves. Paths are into a range snapshot.
  function counterPaths(ev) {
    switch (ev.kind) {
      case "scan": {
        const band = ev.result || "unknown";
        const paths = ["scanned.total", "scanned.by_ecosystem." + ev.eco, "scout.bands." + band];
        if (FLAGGED_BANDS.includes(band)) paths.push("scout.flagged");
        return paths;
      }
      case "triage_in": return ["triage.total"];
      case "analyst_in": return ["analyst.total"];
      case "alert": return ["webhook.alerts_sent"];
      default: return [];
    }
  }

  function bump(snap, path, delta) {
    const parts = path.split(".");
    let node = snap;
    for (let i = 0; i < parts.length - 1; i++) {
      if (!node[parts[i]] || typeof node[parts[i]] !== "object") node[parts[i]] = {};
      node = node[parts[i]];
    }
    const last = parts[parts.length - 1];
    node[last] = Math.max(0, (Number(node[last]) || 0) + delta);
  }

  // Copy only the blocks counters write to, so held snapshots are never changed.
  function counterCopy(snap) {
    const copy = Object.assign({}, snap);
    copy.scanned = Object.assign({}, snap.scanned, { by_ecosystem: Object.assign({}, (snap.scanned || {}).by_ecosystem) });
    copy.scout = Object.assign({}, snap.scout, { bands: Object.assign({}, (snap.scout || {}).bands) });
    copy.triage = Object.assign({}, snap.triage);
    copy.analyst = Object.assign({}, snap.analyst);
    copy.webhook = Object.assign({}, snap.webhook);
    return copy;
  }

  const ACTIVITY_KIND = { triage: "triage", analyst: "analyst", alert: "alert" };
  function activityId(kind, eco, name, version, tMs) {
    return [kind, eco, name, version, Math.floor(tMs / 1000)].join("|");
  }
  function activityFromEvent(ev) {
    let kind = ACTIVITY_KIND[ev.kind];
    if (ev.kind === "scan" && FLAGGED_BANDS.includes(ev.result)) kind = "scout";
    if (!kind || ev.kind === "poll") return null;
    const key = ev.eco + ":" + ev.name + ":" + ev.version;
    return {
      id: activityId(kind, ev.eco, ev.name, ev.version, ev.t),
      atMs: ev.at,
      ts: new Date(ev.t).toISOString().replace(/\.\d{3}Z$/, "Z"),
      kind,
      text: ev.result,
      item: { key, ecosystem: ev.eco, name: ev.name, version: ev.version },
    };
  }

  function createReplay(options) {
    const o = Object.assign({}, DEFAULTS, options || {});
    const docs = []; // { untilMs, doc, pollIntervalS }, oldest first
    const events = new Map(); // id -> event
    const played = new Set();
    const skewSamples = [];
    let playhead = null;
    let lastNow = null;

    function serverNow(clientMs) {
      return clientMs + estimateSkew(skewSamples);
    }

    function noteClock(httpDate, clientMs) {
      const serverMs = parseTime(httpDate);
      if (serverMs === null) return;
      skewSamples.push({ serverMs, clientMs });
      if (skewSamples.length > 5) skewSamples.shift();
    }

    function ingest(doc) {
      if (!doc || typeof doc !== "object") return false;
      const parsed = parseStream(doc.stream);
      const untilMs = parsed.untilMs !== null ? parsed.untilMs : parseTime(doc.published_at);
      if (untilMs === null) return false;
      const fresh = [];
      // `seenUntil` is the first upload that counted the event; counters use it to know
      // whether a held snapshot already includes it.
      for (const ev of parsed.events) if (!events.has(ev.id)) fresh.push(Object.assign(ev, { seenUntil: untilMs }));
      // Re-space the whole second each new event lands in, so late arrivals in a second
      // keep the even spacing. Already played events keep their slot.
      const touched = new Set(fresh.map((ev) => ev.t));
      for (const ev of fresh) events.set(ev.id, ev);
      if (touched.size) {
        const group = [...events.values()].filter((ev) => touched.has(ev.t));
        for (const ev of spreadWithinSecond(group)) if (!played.has(ev.id)) events.set(ev.id, ev);
      }
      if (!docs.some((d) => d.untilMs === untilMs)) {
        docs.push({ untilMs, doc, pollIntervalS: parsed.pollIntervalS });
        docs.sort((a, b) => a.untilMs - b.untilMs);
      }
      prune();
      return true;
    }

    function displayEntry(at) {
      if (!docs.length) return null;
      let pick = docs[0];
      for (const d of docs) if (d.untilMs <= at) pick = d;
      return pick;
    }

    function prune() {
      const ref = playhead === null ? null : displayEntry(playhead);
      if (ref) {
        while (docs.length > 1 && docs[0] !== ref && docs[0].untilMs < ref.untilMs) docs.shift();
      }
      while (docs.length > o.maxDocs) docs.shift();
      if (playhead === null) return;
      const floor = Math.min(playhead, ref ? ref.untilMs : playhead) - o.keepMs;
      for (const [id, ev] of events) {
        if (ev.at < floor) {
          events.delete(id);
          played.delete(id);
        }
      }
    }

    // Move playback to `nowServerMs - delay`. Returns the events to animate (`due`, oldest
    // first) and the ones passed over without animation (`skipped`).
    function advance(nowServerMs) {
      const target = nowServerMs - o.delayMs;
      let mode = "play";
      if (playhead === null) {
        // First run: anything already behind the playhead is history, not news.
        playhead = target;
        for (const ev of events.values()) if (ev.at <= playhead) played.add(ev.id);
        mode = "start";
      } else {
        // A long pause between calls (hidden tab, sleep) counts as one frame, so the gap
        // it leaves is closed by playing faster or by a jump, not in a single step.
        const step = lastNow === null ? 0 : Math.min(o.frameMs, Math.max(0, nowServerMs - lastNow));
        const plan = planCatchUp(target - playhead, o);
        if (plan.mode === "jump") {
          playhead = target;
          mode = "jump";
        } else if (plan.mode === "catchup") {
          playhead = Math.min(target, playhead + step * plan.speed);
          mode = "catchup";
        } else {
          playhead = Math.max(playhead, target);
        }
      }
      lastNow = nowServerMs;
      const due = [];
      const skipped = [];
      for (const ev of events.values()) {
        if (played.has(ev.id) || ev.at > playhead) continue;
        played.add(ev.id);
        // Late arrivals play now; ones far behind (or passed by a jump) are listed only.
        if (mode === "jump" || ev.at < playhead - o.jumpAfterMs) skipped.push(ev);
        else due.push(ev);
      }
      due.sort((a, b) => a.at - b.at);
      skipped.sort((a, b) => a.at - b.at);
      prune();
      return { playhead, mode, due, skipped };
    }

    // The snapshot for `range` as it stood at the playhead: the newest held upload at or
    // before the playhead, with stream events between that upload and the playhead added
    // (or, on first load when the upload is ahead, the not-yet-played ones taken away).
    function viewAt(range, at) {
      const when = at === undefined ? playhead : at;
      const entry = displayEntry(when === null ? Infinity : when);
      if (!entry) return null;
      const base = entry.doc.snapshots && entry.doc.snapshots[range];
      if (!base) return null;
      if (when === null) return base;
      const view = counterCopy(base);
      for (const ev of events.values()) {
        const inDoc = ev.seenUntil <= entry.untilMs;
        const shown = ev.at <= when;
        if (inDoc === shown) continue;
        for (const path of counterPaths(ev)) bump(view, path, shown ? 1 : -1);
      }
      const scanned = view.scanned.total || 0;
      view.triage.share_of_scanned = scanned ? Math.round((10000 * (view.triage.total || 0)) / scanned) / 10000 : null;
      return view;
    }

    // Scout flags, verdicts and alerts up to the playhead, newest first.
    function activityAt(range, at, limit) {
      const when = at === undefined ? playhead : at;
      const entry = displayEntry(when === null ? Infinity : when);
      const base = (entry && entry.doc.snapshots && entry.doc.snapshots[range] && entry.doc.snapshots[range].activity) || [];
      const rows = new Map();
      for (const a of base) {
        const t = parseTime(a.ts);
        if (t === null || !a.item || (when !== null && t > when)) continue;
        const id = activityId(a.kind, a.item.ecosystem, a.item.name, a.item.version, t);
        rows.set(id, Object.assign({}, a, { id, atMs: t }));
      }
      for (const ev of events.values()) {
        if (when !== null && ev.at > when) continue;
        const row = activityFromEvent(ev);
        if (row && !rows.has(row.id)) rows.set(row.id, row);
      }
      return [...rows.values()].sort((a, b) => b.atMs - a.atMs).slice(0, limit || 14);
    }

    // Newest releases Scout scored, any band, up to the playhead.
    function recentScans(at, limit) {
      const when = at === undefined ? playhead : at;
      return [...events.values()]
        .filter((ev) => ev.kind === "scan" && (when === null || ev.at <= when))
        .sort((a, b) => b.at - a.at)
        .slice(0, limit || 3);
    }

    // Honest idle state: when the registries were last really checked, as of the playhead.
    function heartbeatAt(at) {
      const when = at === undefined ? playhead : at;
      const entry = displayEntry(when === null ? Infinity : when);
      if (!entry) return { state: "unknown", lastCheckMs: null, ageMs: null };
      const byEco = {};
      const snaps = entry.doc.snapshots || {};
      const anySnap = snaps[Object.keys(snaps)[0]] || {};
      const feeds = (anySnap.feeds && anySnap.feeds.last_success) || {};
      for (const [eco, ts] of Object.entries(feeds)) {
        const t = parseTime(ts);
        if (t !== null && (when === null || t <= when)) byEco[eco] = t;
      }
      for (const ev of events.values()) {
        if (ev.kind !== "poll" || (when !== null && ev.at > when)) continue;
        if (!(ev.eco in byEco) || byEco[ev.eco] < ev.t) byEco[ev.eco] = ev.t;
      }
      const times = Object.values(byEco);
      if (!times.length) return { state: "quiet", lastCheckMs: null, ageMs: null, byEco };
      const lastCheckMs = Math.max(...times);
      const ageMs = when === null ? 0 : Math.max(0, when - lastCheckMs);
      const interval = (entry.pollIntervalS || 300) * 1000;
      return { state: ageMs <= 2 * interval + 60000 ? "watching" : "quiet", lastCheckMs, ageMs, byEco };
    }

    return {
      options: o,
      noteClock,
      serverNow,
      ingest,
      advance,
      viewAt,
      activityAt,
      recentScans,
      heartbeatAt,
      get playhead() { return playhead; },
      get newestUntilMs() { return docs.length ? docs[docs.length - 1].untilMs : null; },
      latestDoc() { return docs.length ? docs[docs.length - 1].doc : null; },
      displayDoc(at) { const e = displayEntry(at === undefined ? (playhead === null ? Infinity : playhead) : at); return e ? e.doc : null; },
    };
  }

  const api = { DEFAULTS, KINDS, parseStream, spreadWithinSecond, estimateSkew, planCatchUp, counterPaths, createReplay };
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.HunterReplay = api;
})(typeof self !== "undefined" ? self : this);
