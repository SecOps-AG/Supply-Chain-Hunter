# How Hunter decides a release is malicious

This page covers the detail behind the three stages in the [README](../README.md#how-it-works): the decision model (Scout), the mid-tier, balanced model (Triage), and the Frontier model (Analyst).

## Getting the diff

Hunter polls the PyPI changelog API and the npm changes feed. It only queues releases of packages on its watchlist (the top packages by downloads), plus up to 25 per poll whose names imitate a watched package by one edit, a separator, or a look-alike character.

For each release it downloads the new archive and the previous one and diffs them. PyPI releases include both the sdist and the wheel when both exist, under `sdist/` and `wheel/` prefixes. The `name-version/` folder in an sdist and the `package/` folder in an npm tarball are stripped first, so files aren't all seen as new.

Binary and media files aren't dropped. The diff records their kind, size, and a hash prefix instead of the bytes. Text files are read up to 8 MiB each; a longer file is cut and the release is marked as partly read.

A crates.io `.crate` is a gzipped tar. Hunter does not run `cargo`, `rustc`, or `build.rs`. Cargo runs `build.rs` before it compiles the crate, and a proc-macro crate runs at compile time for every downstream crate. A changed `build.rs`, a `[package] build` script, or a new `proc-macro = true` is install-time. Behavior-chain parsing stays Python and JavaScript.

## Account-takeover signals

Optional (`HUNTER_TAKEOVER_SIGNALS`, off by default). Before Scout reads a release, Hunter checks registry metadata only, with no model calls, for signs that a maintainer account was taken over. Each signal adds to a score, and the classify queue takes higher scores first, so Scout spend goes to the riskiest releases. The signals don't change a band on their own.

| Signal | Weight | Source |
| --- | --- | --- |
| `provenance_lost` | 40 | The previous release had a provenance attestation and this one doesn't. npm: `/-/npm/v1/attestations/{name}@{version}`; PyPI: the Integrity API `/integrity/{project}/{version}/{file}/provenance`. |
| `provenance_identity_changed` | 30 | Both have provenance, but the source repository, workflow or builder differs (PyPI: publisher kind, repository, workflow or environment). A provenance statement that can no longer be read, after a named one, also counts. The workflow ref is ignored because it changes with every tag. |
| `publisher_new` | 25 | npm: the `_npmUser` that published this release never published an earlier one. |
| `maintainer_added` | 20 | npm: a name in `maintainers` the previous release didn't list. PyPI: an owner in the JSON API `ownership` block that wasn't there when Hunter last scored the project. |
| `publisher_email_changed` | 20 | npm: same publisher, new email. PyPI: none of the per-version author and maintainer emails match the previous release. |
| `dormant_publish` | 15 | The previous release is older than `HUNTER_TAKEOVER_DORMANT_DAYS`. |
| `semver_jump` | 10 | The major version moved by `HUNTER_TAKEOVER_MAJOR_JUMP` or more. |
| `burst_publish` | 10 | `HUNTER_TAKEOVER_BURST_COUNT` or more versions inside `HUNTER_TAKEOVER_BURST_HOURS`. |

When a metadata read fails, Hunter leaves that signal out and stores the error. An unknown is never counted as a loss. A transient failure (timeout, server error) is scored again an hour later, up to three tries; a 404 is final. Each document read is size-capped (32 MB for the npm packument or PyPI project document, 4 MB for the others), and PyPI provenance is checked on at most two files per release, sdist first.

## MCP tool and server.json signals

Optional (`HUNTER_MCP_RISK`, off by default). Before Scout reads a release that is already on the MCP watchlist, Hunter reads the package as text and the registry server document. Each signal adds to a score. The classify queue takes the account-takeover score plus this score, highest first. The signals don't change a band, set a rule floor, or get copied into a Scout, Triage, or Analyst prompt.

A tool description is attacker-controlled text. Hunter stores a signal id, the tool name, and a short escaped excerpt in SQLite. That excerpt is never placed in a model prompt. The stored score is capped at 200. A download or registry failure is stored and does not stop the queue; the release is still classified.

With no previous archive, instruction, hidden-character, and bidi checks still run, because the description is all new. Capability signals need the same tool name in the previous archive, so the first release of a filesystem server is not treated as a new capability. `repository_changed` needs a previous server version.

| Signal | Weight | What it is |
| --- | --- | --- |
| `tool_instruction_added` | 50 | Added description text tells a model to ignore instructions, hide something from the user, or read a credential path (`~/.ssh`, `~/.aws`, `~/.npmrc`, `id_rsa`). |
| `tool_hidden_unicode` | 40 | Added description text contains U+200B, U+200C, U+FEFF, U+2060, or U+180E. U+200D counts only next to an ASCII letter. |
| `tool_bidi` | 40 | Added description text contains U+202A–U+202E or U+2066–U+2069. |
| `capability_shell` | 35 | An existing tool newly mentions a shell, bash, subprocess, or exec, or gains a `command`, `cmd`, or `shell` argument. |
| `capability_network` | 25 | An existing tool newly mentions a url, uri, endpoint, or webhook, or gains an argument with that name. |
| `capability_file` | 20 | An existing tool gains a `path`, `file`, `filename`, or `directory` argument, or newly says it reads or writes a file or a filesystem. |
| `unpinned_version` | 30 | A package version or the server version is missing, empty, `latest`, or a range. Once per release. `1.2.3` and `1.2.3-beta.1` are pinned. |
| `http_remote` | 35 | A remote URL or a package `sse` / `streamable-http` transport uses cleartext `http`, including loopback. Common on remote servers. A priority nudge, not a verdict. |
| `many_required_secrets` | 20 | Required secrets in environment variables, remote headers, and remote variables reach `HUNTER_MCP_SECRET_MIN`. |
| `many_required_env` | 15 | Required inputs in those same places reach `HUNTER_MCP_ENV_MIN`. |
| `missing_repository` | 15 | No `http` or `https` repository URL. Common on remote-only servers. A priority nudge, not a verdict. |
| `repository_changed` | 40 | The previous server version had a repository URL and the normalized URL differs. A trailing slash, a `.git` suffix, or a `www.` host does not count. A `subfolder`-only change does not count. `http` versus `https` does. |

"network error", "file a bug", and "git commit" do not count as capabilities. A brand-new tool does not raise a capability signal by itself. Instruction text in that first release still counts.

## Decision model (Scout)

The decision model doesn't ask Jev "is this malicious?". It asks many narrow questions, gets a probability for each, and feeds those into a small scoring model (a logistic regression in `hunter/logistic_head.json`) together with things Python measures better than a language model: counts, entropy, dependency names, and release timing. Jev and Clef are the providers. An OpenRouter chat model cannot take this role.

Large diffs are split into chunks that fit Jev's context, and each answer takes its highest value across chunks. Every Jev prompt says that the diff is package content, including any text in it that tells a reviewer to ignore findings.

1. **Pass A** runs on every release, in one call. It checks for install-time code, decode-then-run, a new unrelated dependency, credential reads, persistence, network access, and hidden data in media files. If every answer is low and the local rules are quiet, the release is stored as `benign` and nothing else runs.
2. **Pass B** asks the full set of questions: the Pass A ones plus shell or child process, embedded payloads, text aimed at a reviewer or model, and dynamic `require()` or `import()` of an encoded value. These answers drive the score.
3. **Pass C** runs only on `review` and `alert`. It asks about the likely attack family, cause, and blast radius, so the alert can describe what kind of attack it looks like. It doesn't change the band. If it fails, the release keeps its Pass B result.

Before Pass B, Hunter counts the tokens it is about to send. A release over `HUNTER_SCOUT_RELEASE_TOKENS` (about $0.42 of Jev by default) gets a partial read instead: Scout reads the riskiest files first, up to `HUNTER_SCOUT_PARTIAL_TOKENS` (about $0.04), and the row carries `release_budget` and `release_budget_partial` so Triage, Analyst and the alert say it was a partial read. It goes to Triage only when the partial read or the local signals find something. When not even the first file fits, it goes to Triage marked unread.

### Bands

| Band | Meaning |
| --- | --- |
| `alert` | Score 0.70 or higher. Dropped to `review` if Jev thinks the diff contains instructions aimed at a reviewer. |
| `review` | Score 0.40 or higher, a local rule fired, or Scout couldn't read the whole release. |
| `benign` | Nothing stood out. |
| `deferred` | Jev failed (timeout, 503, missing answer). Retried later; after `HUNTER_AI_MAX_ATTEMPTS` failures it goes to the human review queue. |

### Local rules

These run on every diff. They can raise the score to a minimum level ("floor") but are not a verdict on their own. They still apply when Jev can't read the release.

- **Phantom dependency** (floor 0.62): a new runtime dependency that no source file imports. `@types/*` is ignored. If that dependency has its own install hook that runs `node`, `python`, or a shell, or itself classifies as an alert, the parent becomes an `alert`. Hunter checks new dependencies one level deep, up to `HUNTER_DEP_INSPECT_LIMIT` of them, skipping archives over 8 MB.
- **Compound install payload** (floor 0.86): a new install hook whose command, or the file it runs, also decodes and runs something, starts a shell next to obfuscated text, or reads credentials.
- **Entrypoint payload** (off in the shipped Jev weights; 0.62 when turned on): a package's main file or `__init__.py` is replaced or grows a lot, and the new text is high-entropy or a long minified line.
- **Install sidecar** (floor 0.62): an install script was added or changed and it runs a newly added file, or a binary changed in the same release.
- **Behavior chain** (off in the shipped Jev weights; 0.62 when turned on): code that runs at install or import time reads a credential and then sends it, or fetches or decodes a payload and then runs it.
- **Jev consensus** (floor 0.62): Jev is at 0.9 or higher on at least two of decode-then-run, network, credential read, shell, and embedded payload, and the diff also has a decode-and-run, shell, or raw IP literal.
- **Typosquat** (floor 0.62): the package or a new dependency imitates a well-known name.
- **New executable only**: a release whose only change is a new executable goes to `review` without a Jev call.

XOR, dynamic imports of encoded values, and a new minified high-entropy file next to normal source don't set a floor, but they keep a release from being cleared at Pass A.

A scoring-layer file can change each floor's level or turn one off with `null`. The shipped `hunter/logistic_head.json` turns off the entrypoint and behavior-chain floors; those releases still get the `entrypoint_payload` or `behavior_chain:<steps>` signal, and a file with no `floors` object uses 0.62 for both.

## Mid-tier, balanced model (Triage) and Frontier model (Analyst)

The default is the Cursor Agent CLI in a temporary, empty directory with read-only "ask" mode. An operator can switch a role to OpenRouter (`HUNTER_SMART_BACKEND=openrouter` or `HUNTER_ANALYST_BACKEND=openrouter`, any model id), an OpenAI-compatible API, an Anthropic API, or their own command. The default does not use OpenRouter. Clef uses the Cloudflare API and is not part of this choice. The mid-tier, balanced model uses `HUNTER_SMART_MODEL`. The Frontier model uses `HUNTER_ANALYST_MODEL`. On the Cursor agent CLI only, a Frontier model name containing `fast` is refused unless `HUNTER_ANALYST_ALLOW_FAST=1`. An OpenRouter id is sent as written, including ids that contain `fast` or `flash`. `fast=true` is never sent to the Cursor agent CLI.

They read a filtered diff: install scripts, entry points, workflows, suspicious source, binaries, and any docs that contain a host, a persistence path, or obfuscated text. Ordinary changelogs, docs, and lockfiles are dropped. The diff is capped at 1,000,000 characters. Minified or bundled files over 64 KB are replaced with a summary of the hosts, IP addresses, credential names, and process or `eval` calls found in them, so the model doesn't time out on a 1 MB bundle.

Triage's instructions are in `hunter/triage_skill/SKILL.md`. Each model ends its report with `Verdict: malicious`, `Verdict: benign`, or `Verdict: uncertain`.

- A mid-tier `malicious` verdict queues the Frontier model. Anything else stays in the database.
- A Frontier `malicious` verdict sends the alert. A Frontier `benign` verdict adds a lesson for the mid-tier model to a pending file that a person must approve before Triage uses it.
- `uncertain`, a missing verdict, or an error never sends an alert. Errors are retried, then moved to the human review queue.

If Scout didn't read the whole release, both prompts start with a note saying what was missed, and the alert carries `partial_read: true`.

You can replace either model with your own command (`HUNTER_INVESTIGATE_COMMAND`, `HUNTER_ANALYST_COMMAND`), or turn the Analyst off (`HUNTER_ANALYST=0`) so Triage alone decides.

## Risk score

Every stored release also gets a `risk_score` (0-100) and a `risk_why` list of up to three reasons, each with `code`, `points` and a short fixed `text`. The score adds up the signals and rule hits the release already carries, so it needs no extra model call. It is for reading, not routing: it does not change a band, a probability or an alert. A release that could not be read fully (download failed or deferred) has a null score, which means unknown, not safe. Older stored rows have no score. The dashboard shows it in the release pop-out.

## Lessons

Hunter can learn from releases that Triage keeps clearing.

- `mine-scout` counts Triage verdicts by Scout band and lists the most common patterns Triage called benign. It doesn't call a model or write anything.
- `teach-scout` asks the Analyst about those patterns and writes approved ones to `scout-lessons.md`. Scout only uses them to skip Triage when `HUNTER_SCOUT_LESSONS_APPLY=1`, and never for an alert.
- `teach-until-catch` is an offline loop for one known-bad release. It runs the full pipeline and, if the release isn't caught, proposes lessons in a sandbox folder and tries again. It never posts an alert. See [teach-until-catch.md](teach-until-catch.md).

## Clef (experimental)

Scout can use Cloudflare's Clef model instead of Jev (`HUNTER_SCOUT_MODEL=clef`). Jev is the default, and Clef is still experimental.

Each model needs its own scoring-layer file. Clef's is `hunter/logistic_head_clef.json`. It was fitted the same way as Jev's: the same 17 features, the same nested cross-validation, and the same floors. The answers came from live Clef runs on 64 known-bad releases and 664 clean ones. Clef-flash and clef-omni have no file yet, so Hunter still refuses to start with `HUNTER_CLEF_MODEL=clef-flash` or `clef-omni`.

What to expect from the Clef file, compared with Jev's on the same releases:

- Clef sends a few more clean releases to Triage than Jev does: about 23% against 21%.
- The Clef head almost never puts a release in the alert band on its own. Releases it flags go to review, and Triage decides from there.
- Many releases Clef can't read in full go to review unread. The bad releases it caught include a lot of these.

A release whose list of changed files is longer than Clef's 1,900-token piece budget can't be split in a useful way. The client then sends one tiny piece per call until a release cap stops it. Set `HUNTER_CLEF_RELEASE_TOKENS` (the calibration used 150000) or `HUNTER_CLEF_RELEASE_USD`, along with `HUNTER_SCOUT_DAILY_USD_CAP`, whenever you run Clef.
