#!/usr/bin/env python3
"""Entry point for the shared issue management: labels, and in one case closes, issues that are resolved or
waiting on their reporter.

The rules, configured in the repository's issue-management.json (every key is optional):

  possibly-resolved    A merged PR references the issue without closing it and nobody commented since the
                       merge. Labels and comments; never closes.
  waiting-on-reporter  An issue with a needs-info label and no reply from its author. Warns with `stale-issue`, then
                       closes as not planned. The only rule that closes.
  idle-untriaged       An untriaged issue with no priority and no human activity for a long time. Labels with
                       `stale-issue` and comments; never closes. Off unless triage_label is set.

Any human comment after `stale-issue` or `possibly-resolved` removes it, and a reply from the reporter removes the
needs-info label so a later request starts a fresh clock. Exempt labels and milestoned issues are never labelled or
closed. The script stores no state: labels and timelines are the state.

With triage_label set, the report also lists the oldest untriaged issues, so someone on triage duty has a queue.

Dry-run unless DRY_RUN is the string false. With VALIDATE=true it only checks the config. Prints a Markdown report on stdout.
Exit codes: 0 on success, 1 on an error.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

DEFAULTS = {
    # Not `stale`: PR automation owns that label, and a PR and an issue should never share one.
    "stale_label": "stale-issue",
    "resolved_label": "possibly-resolved",
    # Empty disables the idle-untriaged rule, so only repositories that triage with a label opt in.
    "triage_label": "",
    "priority_prefix": "",
    "needs_info_labels": ["needs-info"],
    "exempt_labels": ["no-stale", "hold", "security"],
    "warning_days": 14,
    "close_days": 14,
    "idle_days": 180,
    "resolved_grace_days": 3,
    # Untriaged issues listed in the report, oldest first; 0 turns the list off.
    "digest_limit": 25,
    "warning_comment": (
        "This issue is waiting on more information from the reporter and has had no reply. It will be closed in "
        "{days} days unless there is a response. Any comment removes the `{label}` label."
    ),
    "close_comment": (
        "Closing as not planned: no reply from the reporter for {days} days. Please reopen with the requested "
        "information if this is still a problem."
    ),
    "resolved_comment": (
        "A merged PR (#{pr}) references this issue but did not close it, and nothing has been said since. Is this "
        "resolved? A maintainer or the reporter can close it, or comment to remove the `{label}` label."
    ),
    "idle_comment": (
        "This issue has had no activity for {days} days and has not been triaged. A maintainer should set a "
        "priority or close it. Any comment removes the `{label}` label."
    ),
}
LIST_KEYS = {"needs_info_labels", "exempt_labels"}
DAY_KEYS = {"warning_days", "close_days", "idle_days", "resolved_grace_days"}
COMMENT_FIELDS = {
    "warning_comment": {"days", "label"},
    "close_comment": {"days"},
    "resolved_comment": {"pr", "label"},
    "idle_comment": {"days", "label"},
}
LABEL_INFO = {
    "stale-issue": ("CFD3D7", "Issue with no activity, or waiting on the reporter"),
    "possibly-resolved": ("0E8A16", "A merged PR references this issue; needs confirmation that it is resolved"),
}

QUERY = """
query($owner: String!, $name: String!, $after: String) {
  repository(owner: $owner, name: $name) {
    issues(states: OPEN, first: 50, after: $after) {
      pageInfo { hasNextPage endCursor }
      nodes {
        number
        title
        createdAt
        author { login __typename }
        labels(first: 30) { nodes { name } }
        milestone { title }
        comments(last: 10) { nodes { createdAt author { login __typename } } }
        timelineItems(last: 100, itemTypes: [LABELED_EVENT, CROSS_REFERENCED_EVENT]) {
          nodes {
            __typename
            ... on LabeledEvent { createdAt label { name } }
            ... on CrossReferencedEvent {
              willCloseTarget
              source { ... on PullRequest { number state merged mergedAt } }
            }
          }
        }
      }
    }
  }
}
"""


def log(message):
    print(f"[issue-management] {message}", file=sys.stderr)


def load_config(path):
    """Merges the repository's config over DEFAULTS, rejecting unknown keys and bad values."""
    config = dict(DEFAULTS)
    if path.exists():
        given = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(given, dict):
            raise ValueError("config must be a JSON object")
        unknown = set(given) - set(DEFAULTS)
        if unknown:
            raise ValueError(f"unknown config keys: {', '.join(sorted(unknown))}")
        config.update(given)
    for key in LIST_KEYS:
        if not isinstance(config[key], list) or not all(isinstance(v, str) and v for v in config[key]):
            raise ValueError(f"{key} must be a list of label names")
    for key in DAY_KEYS:
        value = config[key]
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 3650:
            raise ValueError(f"{key} must be a whole number of days from 1 to 3650")
    limit = config["digest_limit"]
    if isinstance(limit, bool) or not isinstance(limit, int) or not 0 <= limit <= 200:
        raise ValueError("digest_limit must be a whole number from 0 to 200")
    for key in ("stale_label", "resolved_label", "triage_label", "priority_prefix"):
        if not isinstance(config[key], str):
            raise ValueError(f"{key} must be a string")
    if not config["stale_label"] or not config["resolved_label"]:
        raise ValueError("stale_label and resolved_label must not be empty")
    for key, fields in COMMENT_FIELDS.items():
        if set(re.findall(r"{(\w*)}", config[key])) - fields:
            raise ValueError(f"{key} may only use {', '.join('{' + f + '}' for f in sorted(fields))}")
        config[key].format(**dict.fromkeys(fields, 0))
    return config


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def is_bot(author):
    return author is None or author["__typename"] == "Bot" or author["login"].endswith("[bot]")


def gh(*args):
    result = subprocess.run(["gh", *args], capture_output=True, text=True, encoding="utf-8")
    if result.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args[:3])} failed: {result.stderr.strip()}")
    return result.stdout


def fetch_issues(repo):
    owner, name = repo.split("/")
    issues, after = [], None
    while True:
        args = ["api", "graphql", "-f", f"query={QUERY}", "-F", f"owner={owner}", "-F", f"name={name}"]
        if after:
            args += ["-F", f"after={after}"]
        page = json.loads(gh(*args))["data"]["repository"]["issues"]
        issues += page["nodes"]
        if not page["pageInfo"]["hasNextPage"]:
            return issues
        after = page["pageInfo"]["endCursor"]


def label_time(issue, name):
    """When `name` was last applied, or None."""
    times = [
        parse_time(n["createdAt"])
        for n in issue["timelineItems"]["nodes"]
        if n["__typename"] == "LabeledEvent" and n["label"]["name"] == name
    ]
    return max(times, default=None)


def last_human_comment(issue, after=None, by_author=False):
    """Latest non-bot comment (optionally only by the issue author) newer than `after`."""
    author = issue["author"]["login"] if issue["author"] else None
    times = [
        parse_time(c["createdAt"])
        for c in issue["comments"]["nodes"]
        if not is_bot(c["author"]) and (not by_author or c["author"]["login"] == author)
    ]
    times = [t for t in times if after is None or t > after]
    return max(times, default=None)


def merged_references(issue):
    """Merged PRs that mention the issue without closing it. A PR merged before the issue was opened can only
    have been edited to mention it later, so it says nothing about a fix."""
    created = parse_time(issue["createdAt"])
    return [
        (n["source"]["number"], parse_time(n["source"]["mergedAt"]))
        for n in issue["timelineItems"]["nodes"]
        if n["__typename"] == "CrossReferencedEvent"
        and not n["willCloseTarget"]
        and n["source"].get("merged")
        and parse_time(n["source"]["mergedAt"]) > created
    ]


def has_open_reference(issue):
    """True while an open PR mentions the issue: a merged PR then is a step of work still in flight."""
    return any(
        n["__typename"] == "CrossReferencedEvent" and n["source"].get("state") == "OPEN"
        for n in issue["timelineItems"]["nodes"]
    )


def decide(issue, now, cfg):
    """Returns the actions for one issue: ("label", name, comment), ("unlabel", name) or ("close", comment).
    Pure, so the tests can cover every rule."""
    labels = {n["name"] for n in issue["labels"]["nodes"]}
    managed = {cfg["stale_label"], cfg["resolved_label"]}
    actions = []

    # A human comment after a managed label removes it, even on an exempt issue.
    for name in sorted(labels & managed):
        applied = label_time(issue, name)
        if applied and last_human_comment(issue, after=applied):
            actions.append(("unlabel", name))
            labels.discard(name)

    # A reply from the reporter answers the request, so the label goes: the next request then starts a fresh clock.
    for name in sorted(labels & set(cfg["needs_info_labels"])):
        asked = label_time(issue, name)
        if asked and last_human_comment(issue, after=asked, by_author=True):
            actions.append(("unlabel", name))
            labels.discard(name)

    if labels & set(cfg["exempt_labels"]) or issue["milestone"]:
        return actions

    created = parse_time(issue["createdAt"])
    activity = max(filter(None, [created, last_human_comment(issue)]))

    def days(t):
        return (now - t).days

    # Rule: waiting on the reporter. The only rule that closes.
    waiting = labels & set(cfg["needs_info_labels"])
    if waiting:
        asked = max(label_time(issue, name) or created for name in waiting)
        if not last_human_comment(issue, after=asked, by_author=True):
            stale_at = label_time(issue, cfg["stale_label"]) if cfg["stale_label"] in labels else None
            if stale_at and stale_at <= asked:
                # This `stale` came from another rule before the request, so it warned of nothing. Drop it: the
                # next branch then warns for this request.
                actions.append(("unlabel", cfg["stale_label"]))
                stale_at = None
            if stale_at and days(stale_at) >= cfg["close_days"]:
                actions.append(("close", cfg["close_comment"].format(days=cfg["warning_days"] + cfg["close_days"])))
            elif not stale_at and days(asked) >= cfg["warning_days"]:
                actions.append(("label", cfg["stale_label"], cfg["warning_comment"].format(days=cfg["close_days"], label=cfg["stale_label"])))
        return actions

    # Rule: possibly resolved. Never closes.
    if cfg["resolved_label"] not in labels and not has_open_reference(issue):
        for number, merged in sorted(merged_references(issue), key=lambda r: r[1], reverse=True):
            if days(merged) >= cfg["resolved_grace_days"] and activity < merged:
                actions.append(("label", cfg["resolved_label"], cfg["resolved_comment"].format(pr=number, label=cfg["resolved_label"])))
                return actions

    # Rule: idle and untriaged. Never closes. Off unless the repository names its triage label.
    if (
        cfg["triage_label"]
        and cfg["triage_label"] in labels
        and cfg["stale_label"] not in labels
        and not (cfg["priority_prefix"] and any(n.startswith(cfg["priority_prefix"]) for n in labels))
        and days(activity) >= cfg["idle_days"]
    ):
        actions.append(("label", cfg["stale_label"], cfg["idle_comment"].format(days=days(activity), label=cfg["stale_label"])))
    return actions


def untriaged_queue(issues, now, cfg):
    """(issue, idle days) for issues with the triage label and no priority label, oldest first."""
    queue = []
    for issue in issues:
        labels = {n["name"] for n in issue["labels"]["nodes"]}
        if cfg["triage_label"] not in labels or issue["milestone"]:
            continue
        if cfg["priority_prefix"] and any(n.startswith(cfg["priority_prefix"]) for n in labels):
            continue
        activity = max(filter(None, [parse_time(issue["createdAt"]), last_human_comment(issue)]))
        queue.append((issue, (now - activity).days))
    return sorted(queue, key=lambda entry: -entry[1])


def ensure_label(repo, name):
    color, description = LABEL_INFO.get(name, ("EDEDED", ""))
    try:
        gh("label", "create", name, "-R", repo, "--color", color, "--description", description)
    except RuntimeError as err:
        if "already exists" not in str(err):
            raise


def apply(repo, number, action):
    kind = action[0]
    # GitHub's secondary rate limit asks for about a second between writes that create content.
    time.sleep(1)
    if kind == "label":
        ensure_label(repo, action[1])
        gh("issue", "edit", str(number), "-R", repo, "--add-label", action[1])
        gh("issue", "comment", str(number), "-R", repo, "--body", action[2])
    elif kind == "unlabel":
        gh("issue", "edit", str(number), "-R", repo, "--remove-label", action[1])
    elif kind == "close":
        gh("issue", "comment", str(number), "-R", repo, "--body", action[1])
        gh("issue", "close", str(number), "-R", repo, "--reason", "not planned")


def describe(action):
    return action[0] if action[0] == "close" else f"{action[0]} {action[1]}"


def main():
    if os.environ.get("VALIDATE") == "true":
        # Parses the config only: no API call and no token, so it is safe on a pull request from a fork.
        try:
            load_config(Path(os.environ.get("ISSUE_CONFIG", ".github/issue-management.json")))
        except (ValueError, OSError) as err:
            print(f"::error title=Invalid issue-management config::{type(err).__name__}: {err}")
            return 1
        print("issue-management config is valid")
        return 0
    dry_run = os.environ.get("DRY_RUN", "true")
    if dry_run not in ("true", "false"):
        log("DRY_RUN must be true or false")
        return 1
    apply_changes = dry_run == "false"
    try:
        max_actions = int(os.environ.get("MAX_ACTIONS", "30"))
        config_path = Path(os.environ.get("ISSUE_CONFIG", ".github/issue-management.json"))
        cfg = load_config(config_path)
        issues = fetch_issues(os.environ["GITHUB_REPOSITORY"])
    except (ValueError, KeyError, RuntimeError) as err:
        log(f"{type(err).__name__}: {err}")
        return 1

    now = datetime.now(timezone.utc)
    rows, changed = [], 0
    for issue in issues:
        actions = decide(issue, now, cfg)
        if not actions:
            continue
        if apply_changes and changed >= max_actions:
            rows.append(f"| #{issue['number']} | skipped: max-actions reached | |")
            continue
        changed += 1
        for action in actions:
            rows.append(f"| #{issue['number']} | {describe(action)} | {issue['title'][:70].replace('|', '/')} |")
            if apply_changes:
                try:
                    apply(os.environ["GITHUB_REPOSITORY"], issue["number"], action)
                except RuntimeError as err:
                    log(str(err))
                    return 1

    print(f"## Issue management ({'applied' if apply_changes else 'dry-run'})\n")
    print(f"Scanned {len(issues)} open issues, {changed} with actions.\n")
    if rows:
        print("| Issue | Action | Title |\n|---|---|---|")
        print("\n".join(rows))
    if cfg["triage_label"] and cfg["digest_limit"]:
        queue = untriaged_queue(issues, now, cfg)
        print(f"\n## Untriaged queue\n\n{len(queue)} issues have `{cfg['triage_label']}` and no priority.\n")
        if queue:
            print(f"Oldest {min(len(queue), cfg['digest_limit'])} first:\n")
            print("| Issue | Idle days | Title |\n|---|---|---|")
            for issue, idle in queue[: cfg["digest_limit"]]:
                print(f"| #{issue['number']} | {idle} | {issue['title'][:70].replace('|', '/')} |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
