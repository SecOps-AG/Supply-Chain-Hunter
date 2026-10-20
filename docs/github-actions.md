# GitHub Actions

Hunter can watch popular GitHub Actions the way it watches npm and PyPI packages. It is off by default (`HUNTER_ACTIONS=on` turns it on). Settings are in [configuration.md](configuration.md#github-actions).

## What a release is

An action has no registry. Workflows run it with `uses: owner/repo@tag`, and a tag is only a pointer to a commit that the owner can move at any time. Hunter treats each change of a tag as a release:

- **New tag**: a tag Hunter has not seen before, such as a fresh `v4.2.1`.
- **Moved tag**: a known tag that now points at a different commit.

In Hunter's tables the release is ecosystem `github-actions`, name `owner/repo`, version `<tag>@<first 12 characters of the commit>`. The commit is part of the version because a moved tag is a new release under the same tag name.

## Watchlist

Refreshed weekly (`HUNTER_ACTIONS_WATCHLIST_REFRESH`), up to `HUNTER_ACTIONS_MAX` actions:

1. The most-used actions by number of dependent repositories, from ecosyste.ms (`HUNTER_ACTIONS_TOP_N`).
2. Every action used in the workflows of the source repositories behind the npm and PyPI watchlists. A compromised publishing action can poison a package. This source needs `HUNTER_GITHUB_TOKEN`.
3. The actions those actions call from their own `action.yml`, one level down.

`HUNTER_ACTIONS_EXTRA` adds names that are always watched.

## Baseline and polling

Hunter records which commit every tag of every watched action points at. That record is the baseline. Git keeps old commits but not tag history, so once a tag moves GitHub cannot say where it used to point; the baseline can. Both sides of a change are then downloaded by commit from `codeload.github.com` when the job runs. No archives are stored ahead of time.

- Every `HUNTER_ACTIONS_POLL_INTERVAL` seconds Hunter reads the tags of every watched action.
- With `HUNTER_GITHUB_TOKEN`, one GraphQL query reads the newest 100 tags of 50 actions, and a daily sweep reads every tag. A moved tag points at a newer commit, so it sorts into the newest page.
- Without a token, every poll reads every tag over git's own HTTP protocol (what `git ls-remote` does). Nothing is cloned.
- The first read of an action records its tags and raises nothing. So does a read after the action went unpolled for two days.
- A burst (more than 5 moved or 20 new tags in one poll) queues jobs for the most-used tags and records the rest.

## Review

Each tag event gets signals computed from the tag history, with no model:

| Signal | Strength | Meaning |
|---|---|---|
| `action_semver_tag_moved` | strong | A full version tag such as `v1.2.3` was moved. |
| `action_many_tags_moved` | strong | Three or more tags of one action moved in one poll. |
| `action_tag_off_branch` | strong | A moved tag's new commit is not on the default branch or a release branch. |
| `action_semver_retagged_quickly` | medium | A full version tag moved within an hour of being created. |
| `action_major_tag_not_latest` / `action_major_tag_not_release` | medium | A major tag such as `v4` moved to an older release or to a commit with no release tag. |
| `action_tag_moved_back` / `action_tag_rewritten` | medium | The new commit is older than the old one, or on unrelated history. |
| `action_new_tag_off_branch` | medium | A new tag's commit is not on any release branch (token only). |
| `action_signing_dropped` / `action_committer_changed` | weak | Old commit was signed and the new one is not; a different committer (token only). |
| `action_major_tag_followed_release` | benign | A major tag moved to the newest release in its line, the normal release flow. |

Then:

- **Benign only** (a major tag following its release, a new tag on a commit another tag already names, an action's first tag): stored as benign. Nothing is downloaded.
- **Otherwise** both commits are downloaded and the rule pack reads the added text, including rules that read only Actions (runner memory reads, the `isSecret` marker, runtime tokens sent off the runner, `NODE_OPTIONS` or `LD_PRELOAD` written to `GITHUB_ENV`, `toJSON(secrets)`). Hunter also reads `action.yml` for a new `pre:` or `post:` step, a changed entry point (a Node version bump alone does not count), or a docker image that was pinned (or built from the repo) and no longer is, and flags a bundled `dist/` file that changed when neither its source nor its dependencies did.
- **Triage** gets the release when there is a strong signal, a malicious rule verdict, two medium signals, or a rule hit with one medium signal. Analyst must confirm before anything reaches the webhook or the public feed, the same as npm and PyPI.

Scout (the decision model) does not read moved tags. It reads new tags only when `HUNTER_ACTIONS_SCOUT=on`, up to `HUNTER_ACTIONS_SCOUT_PER_DAY` releases a day. Its scoring was fit on package diffs, so this stays off until it has been measured on Actions.

## Output

A confirmed action appears in the webhook, `feed.json`/`feed.xml` and the dashboards next to npm and PyPI. The feed entry links the tag on GitHub and says which commit to pin to instead. The webhook body has an `action` object with the tag, the old and new commit, and the event kind.

`hunter actions refresh`, `hunter actions poll` and `hunter actions status` run the watchlist refresh, one poll, or a count by hand.

## Limits

- If a repository is deleted or made private before the job runs, the old code cannot be fetched and the job is retried, then sent to the human review queue.
- Branch references (`uses: owner/repo@main`) are not watched; only tags are.
- Repositories over the 64 MB download cap are not read in full.
