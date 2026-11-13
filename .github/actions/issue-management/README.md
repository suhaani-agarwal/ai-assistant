# Shared issue management

Reusable composite action that keeps an issue tracker tidy without closing real work. Runs on `ubuntu-latest` with
Python 3.9+ and `gh`; no packages. The script is loaded from `GITHUB_ACTION_PATH`, not the consuming checkout.

## Rules

| Rule | When | Action |
| --- | --- | --- |
| possibly resolved | A merged PR mentions the issue without closing it, `resolved_grace_days` passed, no human commented since the merge, and no open PR mentions it either | Adds `possibly-resolved` and comments. Never closes. |
| waiting on reporter | The issue has a `needs_info_labels` label and its author has not replied since it was applied | After `warning_days` of quiet, adds `stale-issue` and posts a warning. Once that warning is `close_days` old and the label is still there, closes as not planned. **The only rule that closes.** |
| idle untriaged | The issue has `triage_label`, no label starting with `priority_prefix`, and no human activity for `idle_days` | Adds `stale-issue` and comments. Never closes. **Off unless `triage_label` is set.** |

- A human comment after `stale-issue` or `possibly-resolved` removes it. A reply from the reporter removes the
  needs-info label too, so a later request starts a fresh clock. A maintainer's comment is not a reply, but it does
  restart the quiet period before a warning.
- Issues with an `exempt_labels` label or a milestone are never labelled or closed, and lose `stale-issue`, so lifting
  the exemption later cannot close on an old clock.
- **A close needs proof of a warning.** The action only closes if the bot's own warning comment for the current
  request exists and is `close_days` old. A `stale-issue` label set by hand is not enough, and a maintainer who removes
  the label after the warning is respected.
- **A close re-reads the live issue first** and is abandoned (and logged) if it is no longer open, no longer waiting
  and stale, has become exempt, or has a comment the run did not see.
- Bot comments never count as activity.

## How it works

1. **Candidates come from searches, not a scan of every issue**: issues carrying a managed or needs-info label;
   untriaged issues not updated for `idle_days` (idle rule); and issues updated within `resolved_window_days` that a
   merged PR mentions (a light first look rules most out, so they are not read at all). Exempt issues are left out of
   the last two searches.
2. **Each candidate is read once.** Comments and label events arrive newest first, 100 at a time, and are paged
   backwards only as far as a decision needs: to the event that applied each relevant label, to the comments since
   then, and to the newest human comment. Paging stops at a cursor that does not move, and a malformed page is an
   error.
3. **Decisions are pure and stateless.** Labels, the timeline and hidden markers (`<!-- issue-management: … -->`) in
   the bot's own comments are the state. Only a Bot's comment counts as a marker, so a user cannot plant one. A step
   already marked for the same state is not repeated.
4. **One guard makes every write.** In a dry run it prints and does nothing; otherwise it waits a second before each
   write, to stay under GitHub's secondary rate limit. Reads retry; writes never do, so a comment cannot double. A
   GraphQL answer with `errors` or no `data` is rejected.
5. **One failing issue does not stop the rest.** Failures are counted, logged as `::error::`, and make the run exit 1
   at the end.

A preview lists the comments a live run would post. If something cannot be decided, such as a label whose event is no
longer in the history, the issue is skipped and the report says why.

With `triage_label` set, the report also ends with an **untriaged queue**: the `digest_limit` issues with the triage
label, no priority label and no milestone that were updated least recently, with their days since update. It labels
and comments on nothing; it gives whoever is on triage duty a list to work from. Its days count includes bot activity,
which a search can give without reading each issue.

## Interface

| Input | Default | Meaning |
| --- | --- | --- |
| `config` | `.github/issue-management.json` | Repository-specific JSON; the file and every key are optional |
| `dry-run` | `'true'` | Exactly `'true'` or `'false'`; preview never mutates GitHub |
| `validate` | `'false'` | `'true'` only checks the config, offline: no token, no API call. Safe on pull requests from forks |
| `max-actions` | `'30'` | With `dry-run: 'false'`, the most issues one run changes; the rest are listed as skipped |

Supply `GH_TOKEN` in the caller step's environment. It needs `issues: write` and `contents: read`. The report goes
to the job summary.

## Configuration

Unknown keys, non-integer days, label names containing a double quote (they go into searches) and comment templates
with unknown `{fields}` fail the run.

| Key | Default |
| --- | --- |
| `stale_label` / `resolved_label` | `stale-issue` / `possibly-resolved` (created if missing when live) |
| `triage_label` / `priority_prefix` | empty: idle rule off |
| `needs_info_labels` | `["needs-info"]` |
| `exempt_labels` | `["no-stale", "hold", "security"]` |
| `warning_days` / `close_days` | `14` / `14` |
| `idle_days` / `resolved_grace_days` | `180` / `3` |
| `resolved_window_days` | `30`: a mention only makes an issue a candidate while the issue was updated this recently |
| `digest_limit` | `25`; `0` turns the queue list off, and it is also off without `triage_label` |
| `warning_comment`, `close_comment`, `resolved_comment`, `idle_comment` | generic text; `{days}`, `{pr}` and `{label}` allowed where they make sense |

## Limits

- Search returns at most 1000 issues; the run warns when a search hits that.
- `possibly-resolved` only sees mentions on issues updated within `resolved_window_days`, and an issue mentioned by
  more than 100 PRs is skipped with a note.
- The idle rule only looks at issues whose last update is older than `idle_days`, so an issue that only had label or
  bot activity recently is not flagged until that too is old.
- Search results can lag a little behind recent changes.

`stale-issue` is deliberately not `stale`: the PR automation owns `stale`, and an issue and a PR should not share a
label. An issue that still carries a plain `stale` label from an older bot is ignored.

## Tests

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s .github/actions/issue-management/tests -v
```
