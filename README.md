# Supply Chain Hunter

[![CI](https://github.com/SecOps-AG/Supply-Chain-Hunter/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/SecOps-AG/Supply-Chain-Hunter/actions/workflows/ci.yml)

Supply Chain Hunter monitors for software supply chain attacks. It watches the most popular PyPI and npm packages (top 15,000 per ecosystem by default, configurable) for new releases, diffs each new release against the previous version without installing or running it, and uses a decision model plus layered checks (detection rules and follow-up AI review) to determine whether malicious code was injected. Confirmed findings trigger a webhook alert and appear on the dashboard.

> **Status: beta.** It works, but the public instance is currently paused because it is expensive to run.

## At a glance

- **Watches:** new releases of the top 15,000 PyPI and npm packages per ecosystem, plus lookalike names. GitHub Actions monitoring is optional.
- **Checks:** a diff against the previous release, a rule pack, the Scout decision model (Jev by default, Clef supported), then Triage and Analyst models for suspicious releases.
- **Reports:** a webhook alert (JSON or Slack-compatible), a local dashboard, an optional public dashboard and feed, and a SQLite record of every release.

## How it works

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/pipeline-dark.svg">
  <img alt="Pipeline: PyPI and npm feeds, watchlist filter and diff, then the rule pack, Scout, Triage and Analyst, then SQLite, the dashboard, the alert webhook and the public feed" src="docs/images/pipeline-light.svg">
</picture>

1. **Intake.** Hunter polls the PyPI and npm release feeds and queues releases of watched packages (top 15,000 per ecosystem by default) and of lookalike names. Each release is diffed against its previous version.
2. **Rules.** An optional rule pack of YARA and Python rules looks for known-bad patterns in the added code. A strong rule hit always escalates the release to Triage. Rules never raise an alert on their own.
3. **Scout.** The decision model (Jev by default, or Clef) answers many narrow yes/no questions about the diff. Local checks add signals such as new install scripts, new executables, typosquats, and unused dependencies. The result is a band: `benign`, `review`, or `alert`.
4. **Triage.** A mid-tier model reads a filtered diff of releases Scout flags (plus `benign` ones with a new warning sign) and gives a verdict.
5. **Analyst.** A frontier model reviews the same diff only when Triage returns malicious. An Analyst malicious verdict is the only condition that sends an alert.

Every release and verdict is saved in SQLite. More detail is in [docs/detection.md](docs/detection.md), and GitHub Actions coverage is described in [docs/github-actions.md](docs/github-actions.md).

## Models

Each role is configured independently.

| Role | Runs on | Options |
| --- | --- | --- |
| Scout | every watched release | Jev (default) or Clef. It needs a probability per question, so chat models can't fill this role. |
| Triage | `review`, `alert`, and flagged `benign` releases | Cursor Agent CLI (default), any OpenAI-compatible API, the Anthropic API, OpenRouter, or your own command |
| Analyst | releases Triage calls malicious | Same choices as Triage, set separately |

Scout processes every watched release, so its per-call cost dominates. Triage handles a small share and the Analyst fewer still.

## Quick start

Requires Python 3.11 or newer.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Run with the defaults (Jev for Scout, the Cursor Agent CLI for Triage and Analyst):

```bash
export TYPESAFE_API_KEY=...                                  # Scout
export CURSOR_API_KEY=...                                    # Triage and Analyst
export HUNTER_ANALYST_MODEL=<frontier model id>
export ALERT_WEBHOOK_URL=https://example.com/hooks/hunter    # optional
python -m hunter serve
```

On first start, Hunter records the current position of each feed and does not replay history; later starts resume from the saved checkpoint. Use `--since-hours 6` to replay the last six hours.

Commands:

| Command | What it does |
| --- | --- |
| `python -m hunter scan --once` | Poll once, process the queue, send pending alerts, and exit. |
| `python -m hunter score --ecosystem npm --name left-pad --old 1.0.0 --new 1.0.1` | Score a single release (or two local archives with `--old-archive` / `--new-archive`). |
| `python -m hunter report exhausted` | List releases that failed analysis too many times. |
| `python -m hunter eval` | Score the bundled synthetic fixtures offline and print precision and recall. |
| `python -m hunter models` | Show which models are configured for each role. |

## Configuration

All settings are environment variables. To use an OpenAI-compatible provider for Triage and Analyst instead of the Cursor Agent CLI:

```bash
export HUNTER_SMART_BACKEND=openai                           # or anthropic, openrouter
export HUNTER_SMART_BASE_URL=https://api.example.com/v1
export HUNTER_SMART_API_KEY=...
export HUNTER_SMART_MODEL=<mid-tier model id>
export HUNTER_ANALYST_MODEL=<frontier model id>
```

Commonly used settings:

- `HUNTER_SCOUT_MODEL`: `jev` (default) or `clef`.
- `HUNTER_DB` (default `./hunter.sqlite3`): where releases, verdicts, and the alert outbox are stored.
- `ALERT_WEBHOOK_URL`: receives a POST for each confirmed malicious release, as JSON or a Slack-compatible message. Set `ALERT_WEBHOOK_SECRET` to sign it with an HMAC. Failed deliveries are retried across restarts.
- `HUNTER_LOG_DIR` (default `./logs`): one log line per release.
- `HUNTER_ACTIONS=on`: also watch GitHub Actions.
- `HUNTER_MCP_REGISTRY=on`: also watch the npm and PyPI packages listed in the official MCP server registry.
- `HUNTER_OPENVSX=on`: also watch Open VSX extension releases.
- `HUNTER_RUBYGEMS=on`: also watch RubyGems releases.

The full list, with defaults, is in [docs/configuration.md](docs/configuration.md).

Example JSON alert (some fields left out):

```json
{
  "kind": "smart_analysis",
  "ecosystem": "npm",
  "package": "color-hex-pad",
  "old_version": "2.4.0",
  "new_version": "2.4.1",
  "registry_url": "https://www.npmjs.com/package/color-hex-pad/v/2.4.1",
  "primary_band": "review",
  "malice_probability": 0.62,
  "signals": ["phantom_runtime_dependency:codec-pad"],
  "analysis": "…the analyst write-up…\nVerdict: malicious",
  "verdict": "malicious",
  "partial_read": false
}
```

## Dashboard

While running, Hunter serves a read-only dashboard at `http://127.0.0.1:8080/` showing the pipeline, findings, per-release reports, and a benchmark tab. `/health` reports service status and queue depths.

Hunter can also publish a read-only public copy of the dashboard. `serve` uploads sanitized data to a Cloudflare R2 bucket, and the static page in `public_dashboard/` reads it from Cloudflare Pages. Confirmed malicious releases are also published as `feed.json` and `feed.xml`. Releases still under review are labeled "under review, not a verdict", and Analyst verdicts are labeled as AI verdicts that may be wrong. The public copy leaves out secrets, webhook addresses, internal paths, raw errors, and operational details. Setup is in [docs/public-dashboard.md](docs/public-dashboard.md).

## Deploy

`deploy/hunter.service` is a systemd unit. Copy it to `/etc/systemd/system/`, create `/var/lib/hunter`, put your settings in `/etc/hunter.env` (never commit keys or webhook URLs), then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now hunter
curl -s http://127.0.0.1:8080/health
```

## Tests

```bash
pytest
python -m hunter eval
```

The test suite makes no network calls; the model APIs are mocked. Files under `fixtures/` are short synthetic diffs, not real malware.

## Security

Hunter reads untrusted package contents and sends parts of them to the models you configure. It never runs them. To report a vulnerability in Hunter itself, see [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE). Vendored files keep their own licenses: `hunter/clef_tokenizer/` (Apache-2.0, with its own NOTICE) and `hunter/jev_count/` (MIT).
