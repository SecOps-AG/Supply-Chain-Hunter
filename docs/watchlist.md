# Your watchlist

Hunter watches the most popular npm, PyPI and GitHub Actions packages by default. A user watchlist adds the packages one environment actually uses (npm, PyPI, GitHub Actions, Open VSX, RubyGems and crates.io), read from its lockfiles, SBOMs, manifests, workflow files or a typed list. With `HUNTER_WATCH_MODE=watched`, Hunter watches only those packages.

v1 serves one environment per deployment. Every alert goes to the one `ALERT_WEBHOOK_URL`.

## Importing

```bash
hunter watchlist import PATH [PATH ...] [--source LABEL] [--format FMT] [--dry-run] [--json]
```

`PATH` is a file, a directory, or `-` for stdin (stdin needs `--format`). Each file's format is worked out from its content; the file name only breaks a tie. Run `hunter watchlist formats` for the list.

| Format | Files | What is kept |
| --- | --- | --- |
| `npm-lock` | `package-lock.json`, `npm-shrinkwrap.json` (lockfile v1, v2, v3) | Every installed package and its version. Direct when the root `package.json` names it. Links and workspace folders are skipped. |
| `yarn-lock` | `yarn.lock` (classic and berry) | Every entry and its version. `workspace:`, `link:`, `file:`, `portal:` and `patch:` entries are skipped. |
| `pnpm-lock` | `pnpm-lock.yaml` (v5, v6, v9) | Every package key. Direct when an importer names it. |
| `package-json` | `package.json` | The four dependency maps. Only an exact version (`1.2.3`) is kept; a range is stored with no version. `npm:` aliases are stored under the real name. Local, git and URL specs are skipped. |
| `requirements` | `requirements*.txt` | Names, with the version only for `==` or `===`. `-r` and `-c` includes are not followed (import those files too); `-e` lines are skipped. |
| `toml-lock` | `poetry.lock`, `uv.lock` | Every `[[package]]`. Editable, virtual and local packages are skipped. |
| `pipfile-lock` | `Pipfile.lock` | `default` and `develop`. |
| `gemfile-lock` | `Gemfile.lock` | Specs under `GEM` sections whose remote is rubygems.org, with a platform suffix kept (`1.13.9-x86_64-linux`). Direct when `DEPENDENCIES` names the gem. `GIT`, `PATH` and other gem servers are skipped. |
| `cargo-lock` | `Cargo.lock` | `[[package]]` entries whose source is the crates.io registry (git, path and other-registry packages are skipped). |
| `cyclonedx` | `*.cdx.json`, `bom.json` | Component purls, including nested components. Purl types: `npm`, `pypi`, `githubactions`, `openvsx`, `gem` and `cargo`. |
| `spdx` | `*.spdx.json`, `sbom*.json` | Package purls from `externalRefs`. |
| `plain` | any | One package per line: `npm lodash 4.17.21`, `pypi:requests@2.31.0`, `actions actions/checkout v4`, `vscode ms-python.python`, or a `pkg:` purl. Ecosystem names: `npm`; `pypi` or `pip`; `github-actions`, `actions` or `gha`; `openvsx` or `vscode`; `rubygems` or `gem`; `crates` or `cargo`. |
| `workflow` | `.github/workflows/*.yml`, `action.yml` | Every remote `uses:` with its tag or commit sha. Local (`./`) and `docker://` steps are skipped. |

A directory is walked for the file names in the table. `node_modules`, `.git`, `.venv`, `venv`, `site-packages`, `dist`, `build` and `vendor` are skipped, and no symlink is followed.

Every file is a **source**. A directory's files are labeled by their path inside it, and a file argument by the path as given; `--source acme` turns `api/package-lock.json` into `acme/api/package-lock.json`. Importing a source again replaces only that source's rows. The import report lists, for each file, the format, the number of packages, the number skipped, any warnings and the label.

Import only parses. Hunter never installs, imports or runs anything it reads, and never asks npm, pip, poetry or yarn to resolve a range. File contents, resolved URLs, integrity hashes and registry hosts are not stored or logged.

## Editing by hand

```bash
hunter watchlist add ECOSYSTEM NAME [VERSION]     # source "manual"
hunter watchlist remove --source LABEL            # drop one source
hunter watchlist remove ECOSYSTEM NAME            # drop a name from every source
hunter watchlist list [--ecosystem E] [--json]
hunter watchlist status
```

A name removed by hand comes back the next time a source that lists it is imported.

`status` prints the mode, the alert scope, counts and sources, and warns when:

- the mode is `all` and a watchlist exists (Hunter also watches and alerts on the popular lists);
- GitHub Actions are listed but `HUNTER_ACTIONS` is off, Open VSX extensions are listed but `HUNTER_OPENVSX` is off, gems are listed but `HUNTER_RUBYGEMS` is off, or crates are listed but `HUNTER_CRATES` is off;
- a source was imported more than 7 days ago;
- the mode is `watched` but the watchlist is empty.

To keep the list current from files on disk, set `HUNTER_WATCHLIST_PATHS`; `serve` imports them again every `HUNTER_WATCHLIST_REFRESH` seconds.

## Watched mode

`HUNTER_WATCH_MODE=watched`:

- The npm, PyPI, GitHub Actions, Open VSX, RubyGems and crates.io polls queue releases only for listed names. GitHub Actions still needs `HUNTER_ACTIONS=on`, Open VSX `HUNTER_OPENVSX=on`, RubyGems `HUNTER_RUBYGEMS=on` and crates.io `HUNTER_CRATES=on`.
- The popular lists are not downloaded and no lookalike (typosquat) names are checked. MCP registry names are left out.
- The RubyGems and crates.io polls still read their whole feeds (RubyGems timeframe versions, crates.io RSS) and keep only listed names; their checkpoints move past the rest. A crates.io gap backfill reads the index only for listed crates, and the download-rank list is not fetched.
- Gem and crate names are matched without regard to case.
- The alert scope defaults to `watched`, and the local dashboard opens with "Watched only" on.

Scout cost then follows how often your listed packages publish. The Triage and Analyst gates do not change.

In the default mode, `all`, your names are added to the popular lists. They share `HUNTER_MAX_PENDING` with them; when the queue is full a release waits, it is not dropped.

A name that comes back on the list after being removed does not queue every version published while it was off: its npm cursor is moved up to the last npm poll.

## Alerts

With `HUNTER_ALERT_SCOPE=watched`, the webhook sends only for listed names, after the Analyst confirms (or Triage, when the Analyst is off). A confirmed release that is not listed is still stored and logged.

An alert for a listed package has a `watch` block:

```json
"watch": {
  "listed": true,
  "direct": true,
  "pinned_versions": ["1.2.0"],
  "exact_match": false,
  "sources": ["acme/api/package-lock.json"],
  "oldest_import_at": "2026-10-26T18:00:00Z",
  "stale": false
}
```

The Slack text adds one line, for example "On your watchlist (direct). Your files pin this exact version." or "On your watchlist. Your files list this package at: 1.2.0 (not this version)." A range in your files means the name is listed, not that the confirmed version is installed.

Version matching is plain text: PyPI `1.0` does not match `1.0.0`. For GitHub Actions, a listed commit sha that starts with the confirmed sha is an exact match, and a listed tag equal to the confirmed tag is a match too (`tag_ref`): your workflow's tag pointed at this commit.

## Dashboard and public pages

The local dashboard has a "Watched only" toggle and a card listing your sources, when each was imported, and which are older than 7 days. A release that is listed shows how your files list it. `/api/watchlist` returns the sources and counts behind the usual dashboard access check.

While any watchlist exists, or the mode is `watched`, the public feed and the public dashboard do not publish, so your package list never leaves the machine. `/health` shows `disabled: private watchlist present` as their last error.
