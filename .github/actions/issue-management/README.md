# Shared issue management

Reusable composite action that keeps an issue tracker tidy without closing real work. Runs on `ubuntu-latest` with
Python 3.9+ and `gh`; no packages. The script is loaded from `GITHUB_ACTION_PATH`, not the consuming checkout.

## Rules

| Rule | When | Action |
| --- | --- | --- |
| possibly resolved | A merged PR mentions the issue without closing it, `resolved_grace_days` passed, no human commented since the merge, and no open PR mentions it either | Adds `possibly-resolved` and comments. Never closes. |
| waiting on reporter | The issue has a `needs_info_labels` label and its author has not replied since it was applied | After `warning_days`, adds `stale-issue` and comments. After `close_days` more, closes as not planned. **The only rule that closes.** |
| idle untriaged | The issue has `triage_label`, no label starting with `priority_prefix`, and no human activity for `idle_days` | Adds `stale-issue` and comments. Never closes. **Off unless `triage_label` is set.** |

A human comment after `stale-issue` or `possibly-resolved` removes it, even on an exempt issue. A reply from the reporter
removes the needs-info label too, so the next request starts a fresh clock. A `stale-issue` label that predates a request
(from the idle rule) never leads to a close: the waiting rule drops it and warns for the request. Issues with an
`exempt_labels` label or a milestone are never labelled or closed. Bot comments never count as activity, and a
maintainer's comment is not a reply from the reporter. The action keeps no state: labels and the issue timeline
are the state.

With `triage_label` set, the report also ends with an **untriaged queue**: the oldest `digest_limit` issues that
have the triage label, no priority label and no milestone, with their idle days. It labels and comments on nothing;
it gives whoever is on triage duty a list to work from.

## Interface

| Input | Default | Meaning |
| --- | --- | --- |
| `config` | `.github/issue-management.json` | Repository-specific JSON; the file and every key are optional |
| `dry-run` | `'true'` | Exactly `'true'` or `'false'`; preview never mutates GitHub |
| `validate` | `'false'` | `'true'` only checks the config, offline: no token, no API call. Safe on pull requests from forks |
| `max-actions` | `'30'` | With `dry-run: 'false'`, the most issues one run changes; the rest are listed as skipped |

Supply `GH_TOKEN` in the caller step's environment. It needs `issues: write` and `contents: read`. The report goes
to the job summary. A live run waits a second between writes, to stay under GitHub's secondary rate limit.

## Configuration

Unknown keys, non-integer days and comment templates with unknown `{fields}` fail the run.

| Key | Default |
| --- | --- |
| `stale_label` / `resolved_label` | `stale-issue` / `possibly-resolved` (created if missing when live) |
| `triage_label` / `priority_prefix` | empty: idle rule off |
| `needs_info_labels` | `["needs-info"]` |
| `exempt_labels` | `["no-stale", "hold", "security"]` |
| `warning_days` / `close_days` | `14` / `14` |
| `idle_days` / `resolved_grace_days` | `180` / `3` |
| `digest_limit` | `25`; `0` turns the queue list off, and it is also off without `triage_label` |
| `warning_comment`, `close_comment`, `resolved_comment`, `idle_comment` | generic text; `{days}`, `{pr}` and `{label}` allowed where they make sense |

## Tests

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s .github/actions/issue-management/tests -v
```

`stale-issue` is deliberately not `stale`: the PR automation owns `stale`, and an issue and a PR should not share a label.
An issue that still carries a plain `stale` label from an older bot is ignored.
