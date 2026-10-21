# Configuration

Hunter is configured with environment variables. On a server, put them in `/etc/hunter.env` (read by `deploy/hunter.service`) and never commit that file.

## Decision model (Scout)

Jev is the default and uses its own API. Clef is the other decision-model provider and uses the Cloudflare API. OpenRouter is not used for either.

| Variable | Default | What it does |
| --- | --- | --- |
| `TYPESAFE_API_KEY` | | Jev API key. Without it, Scout can still score with the shipped weights, but `train` won't refit. |
| `AI_GATEWAY_API_KEY` | | Use Jev through the Vercel AI Gateway instead. Set together with `TYPESAFE_BASE_URL`. |
| `TYPESAFE_BASE_URL` | | Set to `https://ai-gateway.vercel.sh/typesafe` to use the gateway. |
| `HUNTER_JEV_MODEL` | `jev-1.13.0` (`typesafe-ai/jev-1.13.0` via the gateway) | Jev model id. Pin a version; `jev-latest` and `jev-preview` change under you. |
| `HUNTER_JEV_RETRIES` | `5` | Attempts per Jev call. Requests that are too long are split instead of retried. |
| `HUNTER_SCOUT_RELEASE_TOKENS` | `10000000` | Most tokens Scout will send for one release (about $0.42). Bigger releases get a risk-first partial read. `0` turns the cap off. |
| `HUNTER_SCOUT_PARTIAL_TOKENS` | `1000000` | Tokens for the partial read of a release over the cap (about $0.04): install and manifest files, workflows, entry points, suspicious files, then new files. The row is marked as a partial read. `0` sends over-cap releases to Triage unread. |
| `HUNTER_SCOUT_DAILY_USD_CAP` | off | Daily Scout spend cap, by Pacific day. When reached, Scout stops and releases wait in the queue. It does **not** restart at midnight: change the value and restart Hunter. |
| `HUNTER_JEV_USD_PER_M_INPUT` | `0.042` | Jev price per million input tokens, used for the spend count. |
| `HUNTER_FILE_READ_BYTES` | `8388608` (8 MiB) | Most bytes read from one file. Longer files are cut and the release is marked as partly read. |
| `HUNTER_SCOUT_MODEL` | `jev` | Decision model provider: `jev` or `clef`. Clef is experimental; see [detection.md](detection.md#clef-experimental). An OpenRouter model id is rejected here. |
| `HUNTER_SCOUT_FALLBACK` | off | Backup decision model: `jev` or `clef` (it needs its own scoring-layer file). When the main decision model cannot answer for a release, the whole release is read again on the backup and gets the `backup_decision_model` signal. A spend-cap stop does not use the backup. If neither model answers, the release waits as `deferred` with the `decision_model_down` signal, and exactly one webhook is sent per outage once it has lasted 10 minutes or failed 5 releases. That webhook has counts only, never package names. The outage is kept in the database, so a restart does not send it again, and it ends when a model answers. |

## Mid-tier, balanced model (Triage) and Frontier model (Analyst)

The default backend is `cursor`. OpenRouter is optional: set `HUNTER_SMART_BACKEND=openrouter` or `HUNTER_ANALYST_BACKEND=openrouter` to use it for that role. A key named `OpenRouter` does not switch the backend. The decision model does not use these variables. Jev uses its own API. Clef uses the Cloudflare API.

| Variable | Default | What it does |
| --- | --- | --- |
| `HUNTER_SMART_ANALYSIS` | `1` | `0` turns off the mid-tier, balanced model and the Frontier model. No alerts are sent. |
| `HUNTER_SMART_BACKEND` | `cursor` | How the mid-tier, balanced model is called: `openrouter`, `openai` (any OpenAI-compatible API), `anthropic`, or `cursor` (Cursor Agent CLI). `api_key` is an old name for `openai`. |
| `HUNTER_SMART_MODEL` | none for HTTP backends, including `openrouter` | Mid-tier, balanced model id. Any OpenRouter id is allowed. The `cursor` backend has its own default. |
| `HUNTER_SMART_BASE_URL` | `https://openrouter.ai/api/v1`, `https://api.openai.com/v1`, or `https://api.anthropic.com` | API base URL for the HTTP backends. OpenRouter defaults to `https://openrouter.ai/api/v1` and refuses a `/cursor` URL. |
| `HUNTER_SMART_API_KEY` | | API key for the HTTP backends. Optional for local servers. For `openrouter`, this overrides the shared key below. |
| `OpenRouter` | | OpenRouter key, checked first. Never commit it. |
| `OPENROUTER_API_KEY` | | OpenRouter key if `OpenRouter` is unset. |
| `HUNTER_OPENROUTER_API_KEY` | | OpenRouter key if the two names above are unset. |
| `HUNTER_ANALYST` | `1` | `0` skips the Frontier model, so a mid-tier `malicious` verdict alone sends the alert. |
| `HUNTER_ANALYST_MODEL` | | Frontier model id. Required when the Frontier model is on. Any OpenRouter id is allowed. On the Cursor agent CLI only, names containing `fast` are refused unless `HUNTER_ANALYST_ALLOW_FAST=1`. |
| `HUNTER_ANALYST_BACKEND` | same as the mid-tier model | Backend for the Frontier model, so it can use a different provider. |
| `HUNTER_ANALYST_BASE_URL` / `HUNTER_ANALYST_API_KEY` | the mid-tier model's, when the backend is the same | Base URL and key for the Frontier model. On `openrouter`, an empty key uses the shared OpenRouter key. |
| `HUNTER_MODEL_MAX_PROMPT_CHARS` | `400000` | Longest prompt sent to an HTTP backend. The filtered diff is cut to fit, and the cut is flagged as `triage_diff_cut`. |
| `HUNTER_MODEL_MAX_OUTPUT_TOKENS` | `4096` | Reply limit for OpenRouter and the Anthropic API. |
| `CURSOR_API_KEY` | | Key for the Cursor Agent CLI (`agent`). Not needed if `agent` is already logged in. |
| `HUNTER_TRIAGE_BUDGET` | unlimited | Total Triage runs allowed, counted across restarts. When used up, releases wait. |
| `HUNTER_SMART_BUDGET` | | Old name for `HUNTER_TRIAGE_BUDGET`. |
| `HUNTER_INVESTIGATE_BATCH` | `20` | Releases sent to Triage per loop. |
| `HUNTER_OUTBOX_BATCH` | `50` | Pending alerts delivered per loop. |
| `HUNTER_ESCALATE_UNCERTAIN` | `0` | Reserved for a future path that sends Triage-uncertain releases to Analyst. Leave off. |
| `HUNTER_ESCALATE_UNCERTAIN_BUDGET` | `5` | Cap for that path. `0` means unlimited. |
| `HUNTER_TEACH_FIXTURE` | | Default fixture for `teach-until-catch` when `--fixture` is not passed. |
| `HUNTER_ANALYST_BUDGET` | unlimited | Same, for the Analyst. |
| `HUNTER_INVESTIGATE_TIMEOUT` | `300` | Seconds before a mid-tier, balanced model run is stopped. |
| `HUNTER_ANALYST_TIMEOUT` | `900` | Seconds before a Frontier model run is stopped. |
| `HUNTER_AI_MAX_ATTEMPTS` | `5` | Failures before a release goes to the human review queue. |
| `HUNTER_INVESTIGATE_COMMAND` | | Use your own Triage program: it gets the evidence JSON on stdin and prints a report ending in a `Verdict:` line. |
| `HUNTER_ANALYST_COMMAND` | | Same, for the Analyst. |
| `HUNTER_INVESTIGATE_URL` / `HUNTER_INVESTIGATE_SECRET` | | Optionally POST each evidence bundle to a URL, signed with the secret, before analysis. |
| `HUNTER_TRIAGE_LESSONS` | `triage-lessons.md` next to the database | Lessons file Triage reads. |
| `HUNTER_SCOUT_LESSONS` | `scout-lessons.md` next to the database | Lessons file written by `teach-scout`. |
| `HUNTER_SCOUT_LESSONS_APPLY` | `0` | `1` lets a matching Scout lesson skip Triage (never for an alert). |
| `HUNTER_SCOUT_TEACH_BUDGET` | `5` | Total Analyst runs `teach-scout` may use. `0` is unlimited. |

## Alerts

| Variable | Default | What it does |
| --- | --- | --- |
| `ALERT_WEBHOOK_URL` | | Where alerts are POSTed. Optional: unset, confirmed verdicts are stored and logged only. |
| `ALERT_WEBHOOK_SECRET` | | Adds an `X-Hunter-Signature: sha256=<hex>` HMAC of the body. |
| `ALERT_WEBHOOK_FORMAT` | `json` | `slack` (alias `discord`) sends a `{"text": ...}` message for chat tools. Discord URLs always get text. |
| `ALERT_WEBHOOK_HEADERS` | | Extra request headers as a JSON object, for example `{"Authorization": "Bearer ..."}`. |

`ALERT_WEBHOOK_MIN_PROBABILITY`, `ALERT_WEBHOOK_ON_REVIEW`, and `ALERT_WEBHOOK_ON_PHANTOM` are still read for compatibility but no longer do anything. Only a confirmed malicious verdict sends an alert.

## Public feed

Optional. Hunter writes `feed.json` (JSON Feed) and `feed.xml` (RSS) to a Cloudflare R2 bucket. Readers use the custom domain. The hunter process does not serve the feed. Install the upload client with `pip install -e ".[feed]"` (boto3).

Publishing stays off until every required variable is set. A confirmed malicious release is still stored for the feed when `ALERT_WEBHOOK_URL` is unset. `teach`, `eval`, and `score` do not publish.

| Variable | Default | What it does |
| --- | --- | --- |
| `HUNTER_FEED_PUBLIC_BASE_URL` | | Public origin, such as `https://alerts.example.com`. HTTPS, no path, no userinfo. The R2 S3 host is rejected. |
| `HUNTER_FEED_R2_ACCOUNT_ID` | | Cloudflare account id. The S3 endpoint is `https://<account_id>.r2.cloudflarestorage.com`. |
| `HUNTER_FEED_R2_BUCKET` | | Bucket that holds only the two feed files. |
| `HUNTER_FEED_R2_ACCESS_KEY_ID` | | R2 S3 access key. Not `CLOUDFLARE_API_TOKEN`. |
| `HUNTER_FEED_R2_SECRET_ACCESS_KEY` | | R2 S3 secret. Keep it in `/etc/hunter.env`. |
| `HUNTER_FEED_LIMIT` | `200` | Newest alerts included in the files. Older rows stay in SQLite. Values above 1000 are capped. |
| `HUNTER_FEED_CACHE_MAX_AGE` | `60` | `Cache-Control: public, max-age` on each upload, in seconds. `0` is allowed. Values above 86400 are capped. |
| `HUNTER_FEED_TITLE` | `Supply Chain Hunter alerts` | Title in both feed files. |

Use a bucket-scoped R2 token with object read and write. Connect a custom domain for public reads. Do not use the `r2.dev` URL as the feed. On that hostname, cache the objects with the origin `Cache-Control` lifetime. A long fixed edge TTL keeps a replaced feed stale after a successful upload.

The files list the ecosystem, package, version, previous version, registry page, and a short behavior label. They omit analyst write-ups, prompts, scores, and signal names. Localhost `/health` adds `feed_last_published_at` and `feed_last_error`.

## Public dashboard (R2 JSON + Pages)

Optional. Pushes the same dashboard data as localhost `/api/snapshot`, `/api/findings`, `/api/release`, and `/api/benchmark` to the **same R2 bucket** as the public feed (objects under `live/*`). Install boto3 with `pip install -e ".[feed]"`. Deploy the static UI from `public_dashboard/` to Cloudflare Pages; see [public-dashboard.md](public-dashboard.md).

Publishing stays off until the feed R2 settings are set **and** the variables below are set.

| Variable | Default | What it does |
| --- | --- | --- |
| `HUNTER_DASH_PUBLISH` | off | `on` enables the debounced R2 publisher thread. |
| `HUNTER_DASH_PUBLIC_BASE_URL` | | HTTPS origin where browsers read JSON: your Pages host when it also serves `/live/*` from the bucket, or a separate data host such as `https://data.example.com` (then set `public_dashboard/config.js` `dataBase` to match). No path, no userinfo. The static site defaults to same-origin (`dataBase: ""`) when unset in `config.js`. |

Localhost `/health` adds `dash_last_published_at` and `dash_last_error`.

## What to watch

| Variable | Default | What it does |
| --- | --- | --- |
| `HUNTER_TOP_N` | `15000` | Packages watched per ecosystem. |
| `HUNTER_NPM_TOP_N` | same as `HUNTER_TOP_N` | A different size for npm. |
| `HUNTER_SKIP_PYPI` / `HUNTER_SKIP_NPM` | | `1` turns off that ecosystem. |
| `HUNTER_POLL_INTERVAL` | `300` | Seconds between polls. |
| `HUNTER_WATCHLIST_REFRESH` | `21600` | Seconds between watchlist refreshes. |
| `HUNTER_SKIP_DEP_INSPECT` | | `1` skips checking new dependencies. |
| `HUNTER_DEP_INSPECT_LIMIT` | `3` | New dependencies checked per release. |

The PyPI watchlist comes from the top-pypi-packages dataset and the npm one from the download-counts dataset (falling back to the npm search API).

## GitHub Actions

How it works: [github-actions.md](github-actions.md).

| Variable | Default | What it does |
| --- | --- | --- |
| `HUNTER_ACTIONS` | off | `on` watches the tags of popular GitHub Actions. |
| `HUNTER_GITHUB_TOKEN` | unset | Any GitHub token; a fine-grained token with no repository access is enough. Without it, tags are read over git and the package-repo watchlist source is skipped. |
| `HUNTER_ACTIONS_TOP_N` | `3000` | Most-used actions taken from the ecosyste.ms list. |
| `HUNTER_ACTIONS_MAX` | `5000` | Most actions watched in total. |
| `HUNTER_ACTIONS_TOP_URL` | ecosyste.ms `github actions` packages API | Source of the most-used list. |
| `HUNTER_ACTIONS_EXTRA` | unset | `owner/repo` names always watched, comma or space separated. |
| `HUNTER_ACTIONS_FROM_PACKAGES` | `on` | Add the actions used by the npm and PyPI watchlist's source repositories (needs the token). |
| `HUNTER_ACTIONS_POLL_INTERVAL` | `300` | Seconds between tag polls. |
| `HUNTER_ACTIONS_POLL_WORKERS` | `8` | Parallel tag reads over git. |
| `HUNTER_ACTIONS_SWEEP_INTERVAL` | `86400` | With a token, seconds between full reads of every tag. |
| `HUNTER_ACTIONS_WATCHLIST_REFRESH` | `604800` | Seconds between watchlist refreshes. |
| `HUNTER_ACTIONS_SCOUT` | off | `on` lets Scout read new action tags. |
| `HUNTER_ACTIONS_SCOUT_PER_DAY` | `100` | Most new action tags Scout reads per day. |

Localhost `/health` adds a `github_actions` block with watched actions, recorded tags, tag events in the last day, and whether a token is set.

## Ground truth (OSV `MAL-` and npm takedowns)

Measures recall and time-to-detect on live traffic. For the npm and PyPI releases Hunter scored, it looks up OpenSSF malicious-packages (`MAL-` ids in OSV JSON) and checks whether npm replaced the package with its `0.0.1-security` holder. It only reads JSON: no package archive is downloaded and nothing is run.

Run it by hand any time with `hunter ground-truth` (`--offline` uses the cached records only, `--days N` sets the window, `--full` prints every labeled release, `--out PATH` moves the report). `serve` runs it on a timer only when `HUNTER_GROUND_TRUTH` is on.

| Variable | Default | What it does |
| --- | --- | --- |
| `HUNTER_GROUND_TRUTH` | off | `on` runs the job in `serve` every interval. A report younger than the interval is not redone after a restart. |
| `HUNTER_GROUND_TRUTH_SOURCE` | `api` | `api`: OSV.dev `querybatch` for the scored package names, then one fetch per new or changed `MAL-` record (cached). `git`: shallow, sparse clone of the malicious-packages repo (npm and PyPI folders only), updated with a depth-1 fetch. Needs `git`. |
| `HUNTER_GROUND_TRUTH_DIR` | `ground-truth` next to the database | Record cache, git checkout, npm takedown cache, and `ground-truth-report.json`. |
| `HUNTER_GROUND_TRUTH_INTERVAL` | `86400` | Seconds between runs (at least `3600`). |
| `HUNTER_GROUND_TRUTH_DAYS` | `30` | Look-back window over scored releases. `0` means all. |
| `HUNTER_GROUND_TRUTH_NPM_CHECKS` | `200` | Most npm names checked for a takedown per run; flagged and never-checked names first. `0` turns the registry checks off. A holder version seen in the npm feed still counts. |
| `HUNTER_OSV_API` | `https://api.osv.dev` | OSV API base. |
| `HUNTER_GROUND_TRUTH_REPO` | the OpenSSF malicious-packages repo | Git URL for the `git` source. |

How releases are labeled:

- **Malicious**: an OSV `MAL-` record lists the version or a range covers it, or the npm package was taken down (every version Hunter saw counts).
- **Caught**: Scout put it in `review` or `alert`, or an alert was confirmed. **Confirmed** counts only confirmed alerts. Releases still `deferred` are left out and counted apart.
- **Time-to-detect**: Hunter's flag time (Scout score time, or the confirmed-alert time) minus the earliest `MAL-` `published` time or takedown time, in hours. Negative means Hunter was first; `hunter_first` counts those.

The summary has `malicious_seen`, `caught`, `missed`, `recall`, `confirmed`, `confirmed_recall`, time-to-detect stats (count, median, p90, mean, min, max), and the same counts per ecosystem and per source.

## MCP registry

Off by default. When on, Hunter polls the official MCP server registry (`/v0.1/servers?updated_since=...`, following `metadata.nextCursor`) about once an hour. The first poll reads the whole registry. Each server entry's npm and PyPI packages join the npm and PyPI watch whatever their download rank, so their new releases go through the usual rules, Scout, Triage and Analyst. Docker/OCI images, `.mcpb` bundles, remote-only servers and packages hosted on other registries are skipped. Names are kept after a ranked watchlist refresh and are never removed. They are not counted as popular names in the typosquat check.

| Variable | Default | What it does |
| --- | --- | --- |
| `HUNTER_MCP_REGISTRY` | off | `on` adds MCP server packages to the npm and PyPI watch. |
| `HUNTER_MCP_REGISTRY_URL` | `https://registry.modelcontextprotocol.io` | Registry origin. |
| `HUNTER_MCP_POLL_INTERVAL` | `3600` | Seconds between polls (at least 300). |

Localhost `/health` adds an `mcp_registry` block with the number of npm and PyPI names it added.

## Open VSX

Off by default. When on, Hunter reads the Open VSX changes feed (`/api/-/version-changes`) and diffs each new extension version's `.vsix` against the previous version of the same build (universal first, else one platform build). The first poll starts the feed at the current time. The npm rules read every release, plus checks on `extension/package.json`: a new `extensionPack` or `extensionDependencies` entry, eager activation (`*` or `onStartupFinished`), a changed `main` or `browser` entry, and a different publisher. A malicious rule verdict, two of those checks, or one with a rule hit sends the release to Triage; everything else is stored without a model call. Removals in the feed (`state: REMOVED`) are recorded with their extension and version as ground truth.

| Variable | Default | What it does |
| --- | --- | --- |
| `HUNTER_OPENVSX` | off | `on` watches Open VSX releases. |
| `HUNTER_OPENVSX_URL` | `https://open-vsx.org` | Registry origin. |
| `HUNTER_OPENVSX_POLL_INTERVAL` | `300` | Seconds between feed polls (at least 60). |
| `HUNTER_OPENVSX_PAGE_SIZE` | `200` | Changes per feed page (at most 1000). |
| `HUNTER_OPENVSX_SCOUT` | off | `on` lets Scout read an Open VSX release, only when a rule hit. |

Localhost `/health` adds an `openvsx` block with recorded active, removed and other versions. `HUNTER_MAX_PENDING` applies: a full queue pauses the feed at that page.

## Performance and storage

| Variable | Default | What it does |
| --- | --- | --- |
| `HUNTER_WORKERS` | `4` | Releases processed in parallel. Each one can unpack four archives at once, so raise this only with spare disk and memory. |
| `HUNTER_MAX_PENDING` | `2000` | Most releases held in the queue. Polling waits when it's full. |
| `HUNTER_CLASSIFY_BATCH` | `25` | Releases classified per slice of the work loop. |
| `HUNTER_CLASSIFY_CYCLE_CAP` | `100` | Releases classified per poll cycle. |
| `HUNTER_MAX_EXTRACT_BYTES` | `1073741824` (1 GiB) | Most bytes one archive may unpack to. A bigger archive (for example a decompression bomb) is refused, retried, and then sent to the human review queue. |
| `HUNTER_MAX_EXTRACT_FILES` | `100000` | Most files one archive may unpack to. |
| `HUNTER_DB` | `./hunter.sqlite3` | SQLite database. |
| `HUNTER_LOG_DIR` | `./logs` | Daily log files, `hunter_YYYYMMDD.log`. |
| `HUNTER_BIND` / `HUNTER_PORT` | `127.0.0.1` / `8080` | Health endpoint and dashboard address. |
| `HUNTER_BENCH_DIR` | unset | Folder of decision-model benchmark runs (one subfolder per run with a `leaderboard.json`, optional `data/<model>-cases.jsonl`). The Benchmark tab shows one comparison of Luna, clef-flash, and Jev on the same releases. Unset means that tab says there is no comparison yet. Files are only read as JSON. |
| `HUNTER_DASHBOARD_TOKEN` | unset | Bearer token for the dashboard API (`/api/*`). Required when `HUNTER_BIND` is not a loopback address; without it the API refuses requests on a wide bind. |

## Clef (experimental)

These only matter with `HUNTER_SCOUT_MODEL=clef`. Clef uses `hunter/logistic_head_clef.json`. Clef-flash has no scoring-layer file yet, so it can't start.

| Variable | Default | What it does |
| --- | --- | --- |
| `HUNTER_CLEF_MODEL` | `clef` | `clef` (27B), `clef-flash` (9B), or `clef-omni`. Each has its own context window: flash 24,576 tokens, clef and clef-omni 65,536. A call is sized to the window less 2,048 tokens for the answer, counting the questions. A release too large for the model is read by Clef Omni or Jev when one is set up, and otherwise goes to review unread with a `context_overflow` signal. |
| `CLOUDFLARE_API_TOKEN` / `CLOUDFLARE_ACCOUNT_ID` | | Cloudflare Workers AI credentials. |
| `HUNTER_CLEF_BASE_URL` | | Use your own Clef server instead of Cloudflare. It must accept `POST <base>/v1/systemone`. |
| `HUNTER_CLEF_API_TOKEN` | | Bearer token for that server, or an override for `CLOUDFLARE_API_TOKEN`. |
| `HUNTER_CLEF_STATE_TOKENS` | `1900` | Tokens per hosted Clef call. Hosted Clef silently drops anything past 2,048. |
| `HUNTER_CLEF_CONTEXT_TOKENS` | the model's window; `16384` with a base URL | Context size override, for your own server. |
| `HUNTER_CLEF_MAX_RPM` | `240` | Requests per minute across all workers. |
| `HUNTER_CLEF_RETRIES` | `5` | Attempts per call. |
| `HUNTER_CLEF_RELEASE_TOKENS` / `HUNTER_CLEF_RELEASE_USD` | off | Per-release token and dollar caps. A release over either goes to review. Set one when you run hosted Clef. The calibration used 150000 tokens. |
| `HUNTER_CLEF_USD_PER_M_INPUT` / `HUNTER_CLEF_FLASH_USD_PER_M_INPUT` | `0.24` / `0.09` | Prices for the spend count. |

## Deterministic rules

A YARA and Python rule pack under `hunter/rules/` reads the text each release added, before Scout. Rules read files as text only; nothing is run. With `HUNTER_RULES=on`:

- A file a rule hits is always kept for Scout, and a hit or a file the rules cannot read skips the Pass A quick check.
- A hit by a promoted (strong) rule sets the score floor to review (`rule_strong`, 0.62), so the release always reaches Triage. Triage and Analyst see the findings.
- Promoted rules are listed in `hunter/rules/promoted.json`, each with its unit test and a note on the evidence the maintainers reviewed. Setting a rule's `floor` to `null` there, or a `rule:<id>` floor of `null` in the head file, switches that one rule back to weak.

| Variable | Default | What it does |
|---|---|---|
| `HUNTER_RULES` | `off` | `on` turns the rule pack on in the classifier. |
