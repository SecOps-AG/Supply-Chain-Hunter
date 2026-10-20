# Public dashboard

The local Hunter dashboard (Dashboard and Benchmark tabs) can be mirrored on Cloudflare without opening `serve` to the internet. A static site in `public_dashboard/` reads JSON that `serve` pushes to the **same R2 bucket as the public alert feed** (the examples below call it `hunter-public`).

## Architecture

```text
serve (127.0.0.1) ──S3 PUT──► R2 bucket `hunter-public` (live/* objects)
                                      ▲
                                      │ GET /live/…
Cloudflare Pages (public_dashboard/) ─┘  same origin, or a separate data host
```

**Same origin (simplest):** the Pages project serves the static UI from this repo and also answers `/live/*` from the bucket, using a small Pages Function or Worker that you deploy yourself (it is not part of this repository). It should allow only `GET` and `HEAD` on the keys listed under "R2 object layout". The shipped `config.js` leaves `dataBase` empty, so the browser reads the `live/` objects relative to the Pages host.

**Separate data host:** set `window.HUNTER_PUBLIC.dataBase` to a dedicated HTTPS origin (for example `https://data.example.com`) to read JSON directly from an R2 custom domain without going through Pages.

- **Same R2 credentials** as the public feed: `HUNTER_FEED_R2_*`, the same bucket, and `pip install -e ".[feed]"` (boto3).
- **Publishing** on `serve` stays off until `HUNTER_DASH_PUBLISH=on`, feed R2 settings are complete, and `HUNTER_DASH_PUBLIC_BASE_URL` is set to the origin browsers read from (your Pages host for the same-origin setup, or your data host).

A background thread debounces changes (2 s) and uploads with a 5 s timeout. Upload failures do not stop `serve`; `/health` exposes `dash_last_published_at` and `dash_last_error`.

## R2 object layout

| Key | Contents | Cache-Control (origin) |
| --- | --- | --- |
| `live/live.json` | All range snapshots, findings catalogs, recent events `stream`, disclaimers, `published_at` | `public, max-age=2` |
| `live/benchmark.json` | Same shape as `/api/benchmark` | `public, max-age=60` |
| `live/history/YYYY-MM-DD.json` | Daily pipeline rollup | `max-age=60` for today; `immutable` for past days |
| `live/confirmed/YYYY-MM-DD.json` | That day’s findings rows with stage labels | same |
| `live/r/<eco>/<name>/<version>.json` | Same shape as `/api/release` (pop-out) | `immutable` |

Scout/Triage rows carry `public_stage_note`: **under review, not a verdict**. Analyst verdicts carry **AI verdict (may be wrong): …**. Package names, signals, rule IDs, and model reports match the local dashboard. The public health block carries only `status` and the last successful read of each feed, and each pipeline role is published by its label (for example "decision model", Scout) without the model behind it. Queue sizes, budgets, spend, spend caps, uptime, and model ids stay on the local dashboard. Secrets, webhook URLs, internal filesystem paths, raw error strings, and environment values are stripped.

## Recent events stream

`live.json` carries one `stream` block (not one per range) so the page can replay events at their real times instead of jumping when a new upload lands:

```json
"stream": {
  "v": 1, "until": "<published_at>", "since": "<until minus 180 s>",
  "window_s": 180, "max_events": 250, "truncated": false, "poll_interval_s": 120,
  "fields": ["t", "kind", "eco", "name", "version", "result"],
  "events": [[1791702000, "scan", "npm", "demo-pkg", "1.0.0", "benign"]]
}
```

- `t` is epoch seconds from the stored timestamp (one-second precision). Events are oldest first.
- Kinds: `poll` (a registry check; name and version are null), `scan` (Scout scored the release; result is the band), `triage_in` and `analyst_in` (queued for that stage), `triage` and `analyst` (reported; result is the verdict), `alert` (webhook sent). Model-down notices are not listed.
- Only the newest 250 events in the last 180 s are kept. `truncated` is true when older ones may be missing. Typical size is a few KB.
- The window covers the page's playback delay plus the longest normal gap between uploads (about 35 s while idle).

## Deploy the static site

1. Deploy the `public_dashboard/` folder to **Cloudflare Pages** (no build step). **`config.js` defaults to same-origin** (`dataBase: ""` → `/live/live.json`).
2. Wire `/live/*` to the bucket (for example with your own Pages Function on the same Pages project; not in this repo).
3. Optional override before deploy:

   ```javascript
   window.HUNTER_PUBLIC = { dataBase: "https://data.example.com" };
   ```

4. Enable **`_headers`** (strict CSP). `connect-src` allows `'self'` and `https:` so the page can read same-origin `/live/*` and the public GitHub star count. An external `dataBase` must be `https:` as well.

The header links to the GitHub repository. The star count is `stargazers_count` from `https://api.github.com/repos/SecOps-AG/Supply-Chain-Hunter`, requested once when the page loads, with no token. If that request fails, the link stays and the number is left blank. The local dashboard uses the same header control; its Content-Security-Policy allows `https://api.github.com` for that one request.

The page polls `/live/live.json` every 5 s with `cache: 'no-store'` (skipping the parse when `Last-Modified` is unchanged), refreshes on `visibilitychange`, and shows a stale banner when the response `Date` header is older than 30 s.

## Live replay

`serve` uploads in batches: about every 35 s while idle (the publisher's 30 s idle tick, 2 s debounce and about 2 s to build and upload), and about 2 s after each busy round. Registry checks happen every `HUNTER_POLL_INTERVAL` seconds per ecosystem (300 s by default). To avoid a page that jumps every upload, `public_dashboard/replay.js` replays the `stream` events at their real timestamps, **45 s behind serve**:

- **Delay 45 s** covers the longest normal wait between an event and the browser seeing it (36 s idle upload gap + 2 s edge cache + 5 s poll), so events are buffered before their play time. An event that still arrives late plays at once; none are dropped or moved later.
- **Poll 5 s**: with a 45 s buffer, faster polling shows nothing new and costs more requests.
- **Pacing**: events that share a second (timestamps are second-precision) are spaced inside that second. Releases fly from the feed to Scout, Scout to Triage, Triage to Analyst, and Analyst to Webhook. There is at most one particle per route per 100 ms step, labelled "+N" for a burst, and at most 8 in flight. Counters still tick per event. `prefers-reduced-motion` turns the motion off.
- **Counters** are the newest upload at or before the playhead, plus or minus real stream events between that upload and the playhead. They equal the upload's totals once playback reaches it. Panels that are not replayed (verdict bars, detections, the hero) switch when playback reaches their upload. On the 1h range an event that ages out of the hour during playback is corrected at the next upload.
- **Idle**: the heartbeat only pulses on real registry checks (`poll` events). It turns grey (no pulse) when no check is newer than twice the poll interval plus a minute, or when the page is not updating. The page does not show the replay delay, a last-check clock, or how long ago the data was fetched.
- **Hidden tab**: there are no polls or animation while hidden. On return, a gap up to 10 s plays at 4× speed. A longer gap jumps to the present and lists the skipped events in Activity without animation.
- **Clock**: event times are server times. The page estimates its clock offset from the response `Date` header (median of the last five).

Tests: `tests/js/replay.test.js` (engine) and `tests/js/app_smoke.test.js` (the real page scripts on a small fake DOM) run with `node --test`, and through `pytest` when node is installed.

## Cloudflare rules

Apply on whichever hostname serves **`/live/*`** to browsers (R2 custom domain and/or the Pages proxy):

1. **Cache Rule — eligible**  
   - Match: URI Path starts with `/live/`  
   - Cache eligibility: eligible for cache  
   - **Ignore query string** on cache key  

2. **Origin cache TTL**  
   - Respect origin `Cache-Control` (do not override with a long fixed edge TTL).  
   - `live/live.json` uses `max-age=2`; benchmark and today’s history/confirmed use `max-age=60`; immutable objects use `max-age=31536000, immutable`.

3. **Rate limiting**  
   - **60 requests / minute / IP** on `GET` and `HEAD` for `/live/*`.

4. **Methods**  
   - Allow **GET** and **HEAD** only on public routes.

5. **Smart Tiered Cache**  
   - Enable for the zone to reduce origin reads.

6. **CORS**  
   - Required only when the static site and JSON host differ (external `dataBase`). Allow `GET` from your Pages origin on `/live/*`.

See [configuration.md](configuration.md) for environment variables.
