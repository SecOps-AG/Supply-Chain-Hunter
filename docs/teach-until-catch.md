# Teach until catch

Offline loop for one known-malicious package release. The decision model (Scout) classifies the inert trees, the mid-tier, balanced model (`HUNTER_SMART_MODEL`) reads a ranked excerpt, and the Frontier model (`HUNTER_ANALYST_MODEL`) confirms. Success means the alert gate would open: the decision-model band is `review` or `alert`, the mid-tier model says malicious, and the Frontier model says malicious. Nothing is posted.

The loop does not set `ALERT_WEBHOOK_URL`. If that variable is already set, `teach-until-catch` removes it for the process and still does not post.

Teacher patches go to a sandbox copy of the SOP and Triage lessons. Production `scout-lessons.md` is not written. Scout suppression proposals for a compromised-library label are rejected. Deterministic floor proposals are recorded and left off.

Teacher uses the Frontier model and its backend. On the Cursor agent CLI, model names containing `fast` are refused for the mid-tier model, Teacher, and the Frontier model. `HUNTER_ANALYST_ALLOW_FAST` does not apply to this command. An OpenRouter model id is used as set, including ids that contain `fast` or `flash`.

## Fixture

`--fixture` takes a directory with `old/` and `new/` text trees, or a `meta.json` with `old_dir` and `new_dir`. A JSON file in the same shape as `fixtures/*.json` also works. `meta.json` can set `ecosystem`, `name`, `old_version`, `new_version`, and `label` (default `compromised_lib`). Do not `npm install` the trees and do not execute package code.

Without `--fixture`, `HUNTER_TEACH_FIXTURE` is used, then a `teach-fixture.md` file in the working directory with a `fixture: /absolute/path` line.

`--allow-distill` writes an inert, synthetic tree shaped like the axios 1.14.1 compromise instead: a long changelog that used to fill the 12k Triage window, plus `package.json` adding `plain-crypto-js` with no import. It contains no payload.

```bash
python -m hunter teach-until-catch \
  --allow-distill \
  --distill-dir /tmp/axios-1.14.1-inert \
  --out teach-out/axios \
  --max-rounds 5 \
  --mode auto \
  --with-ablation
```

`--mode auto` calls the models only when both roles have a model set and their backend is reachable (for the `cursor` backend, the `agent` CLI and `CURSOR_API_KEY`). Otherwise it uses the in-process dry run and says so in `REPORT.md`. `--mode live` refuses instead of falling back. `--mode mock` never calls the network.

`--with-ablation` repeats the loop after removing the compromised-library section from the sandbox SOP, so Teacher has to propose a lesson. The main run keeps that section.

Do not commit the trees or the output directory.

## What the excerpt change does

`excerpt_for` puts a dependency preface and the manifest diff ahead of changelog and other docs, and it caps doc windows. Jev chunking is unchanged. The preface is how a new dependency stays inside the 12k triage window when release notes are huge.

## Escalation (not enabled)

`HUNTER_ESCALATE_UNCERTAIN` defaults off. The proposed production rule is: when the flag is on, Triage `uncertain` goes to Analyst only if Scout's band is `alert`, the family is `dependency_abuse`, or a phantom dependency signal is present, and only until `HUNTER_ESCALATE_UNCERTAIN_BUDGET` (default 5, `0` unlimited). An alert still requires Analyst `malicious` after Scout finished. `serve` does not consult the flag.

The teach loop is stricter about its own offline path: a strong Scout hit with Triage `benign` or `uncertain` is shown to Analyst inside the sandbox run. That still does not post.

## Add the next package

1. Put inert old and new trees outside the repo, or a small JSON distillation under `fixtures/` if the files are tiny. Do not commit full registry trees.
2. Add `meta.json` with `ecosystem`, `name`, `old_version`, `new_version`, and `label`.
3. Pass `--fixture /path`, or set `HUNTER_TEACH_FIXTURE`.
4. Run with a new `--out` directory, for example `teach-out/<name>/`.
5. Read `REPORT.md`. On success, Scout is `review` or `alert`, both verdicts are `malicious`, and `alert_sent` is false.
6. Leave sandbox lessons in place until someone copies a specific lesson into the packaged `LESSONS.md` or the runtime triage lessons file. Do not flip `HUNTER_SCOUT_LESSONS_APPLY` from this loop.

Models for a live run use the same settings as `serve`:

```bash
export HUNTER_SMART_BACKEND=cursor          # default; or openai, anthropic
export HUNTER_SMART_MODEL=<mid-tier model id>
export HUNTER_ANALYST_MODEL=<Frontier model id>
unset ALERT_WEBHOOK_URL
python -m hunter teach-until-catch --fixture /path/to/trees --mode live --max-rounds 5 --out teach-out/<name>
```

`HUNTER_SMART_BACKEND=openrouter` is an optional backend for operators who want any OpenRouter model id. Leave it unset to keep the Cursor agent CLI. Clef, when the decision model is set to it, still uses the Cloudflare API.
