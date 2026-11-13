#!/usr/bin/env python3
"""Entry point for the shared issue management: labels, and in one case closes, issues that are resolved or
waiting on their reporter.

The rules, configured in the repository's issue-management.json (every key is optional):

  possibly-resolved    A merged PR references the issue without closing it, no open PR does, and nobody
                       commented since the merge. Labels and comments; never closes.
  waiting-on-reporter  An issue with a needs-info label and no reply from its author. Warns with `stale-issue`,
                       then closes as not planned once that warning is `close_days` old. The only closing rule.
  idle-untriaged       An untriaged issue with no priority and no human activity for a long time. Labels with
                       `stale-issue` and comments; never closes. Off unless triage_label is set.

How it works, in the order the code does it:

  1. Candidates come from searches, one per rule, not from a scan of every issue: the issues carrying a managed or
     needs-info label, the idle untriaged ones, and the recently updated ones a merged PR mentions.
  2. Each candidate is read once. Comments and label events are paged backwards only as far as a decision needs.
  3. `decide` turns what was read into actions. It is pure and stores no state: labels, the timeline and hidden
     markers in the bot's own comments are the state. Only a Bot's comment counts as a marker.
  4. A single guard makes every write: in a dry run it prints and does nothing, otherwise it waits between writes.
     A close re-reads the live issue first and gives up if anything changed.

A human comment after `stale-issue` or `possibly-resolved` removes it; a reply from the reporter removes the
needs-info label, so a later request starts a fresh clock. An exempt label or a milestone means the issue is never
labelled or closed and loses `stale-issue`, so lifting the exemption cannot close it on an old clock. One failing
issue is counted and the rest continue; any failure makes the exit code 1.

Dry-run unless DRY_RUN is the string false. With VALIDATE=true it only checks the config. Prints a Markdown report
on stdout.
"""

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import shlex
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
    # A mention only makes an issue a candidate while the issue was updated this recently.
    "resolved_window_days": 30,
    # Untriaged issues listed in the report, oldest update first; 0 turns the list off.
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
DAY_KEYS = {"warning_days", "close_days", "idle_days", "resolved_grace_days", "resolved_window_days"}
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
MARKER = "<!-- issue-management: {} -->"
MARKER_RE = re.compile(r"<!-- issue-management: (.+?) -->")
# Search stops at 1000 results; a connection is paged at most this many times.
SEARCH_CAP = 1000
MAX_PAGES = 100

ISSUE_QUERY = """
query($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    issue(number: $number) {
      number
      title
      createdAt
      author { login __typename }
      labels(first: 100) { pageInfo { hasNextPage } nodes { name } }
      milestone { title }
      comments(last: 100) {
        totalCount
        pageInfo { hasPreviousPage startCursor }
        nodes { createdAt body author { login __typename } }
      }
      labelEvents: timelineItems(last: 100, itemTypes: [LABELED_EVENT]) {
        pageInfo { hasPreviousPage startCursor }
        nodes { ... on LabeledEvent { createdAt label { name } } }
      }
      refEvents: timelineItems(last: 100, itemTypes: [CROSS_REFERENCED_EVENT]) {
        pageInfo { hasPreviousPage startCursor }
        nodes {
          ... on CrossReferencedEvent {
            willCloseTarget
            source { ... on PullRequest { number state merged mergedAt } }
          }
        }
      }
    }
  }
}
"""

PAGE_QUERY = """
query($owner: String!, $name: String!, $number: Int!, $cursor: String!) {
  repository(owner: $owner, name: $name) {
    issue(number: $number) {
      %s
    }
  }
}
"""
PAGES = {
    "comments": """comments(last: 100, before: $cursor) {
        pageInfo { hasPreviousPage startCursor }
        nodes { createdAt body author { login __typename } }
      }""",
    "labelEvents": """labelEvents: timelineItems(last: 100, before: $cursor, itemTypes: [LABELED_EVENT]) {
        pageInfo { hasPreviousPage startCursor }
        nodes { ... on LabeledEvent { createdAt label { name } } }
      }""",
}

SEARCH_QUERY = """
query($q: String!, $after: String) {
  search(query: $q, type: ISSUE, first: 100, after: $after) {
    issueCount
    pageInfo { hasNextPage endCursor }
    nodes { %s }
  }
}
"""
NUMBER_FRAGMENT = "... on Issue { number }"
# A light first look, enough for `worth_reading` to rule most mentioned issues out without reading them in full.
MENTION_FRAGMENT = """... on Issue {
  number
  createdAt
  comments(last: 1) { nodes { createdAt author { login __typename } } }
  timelineItems(last: 30, itemTypes: [CROSS_REFERENCED_EVENT]) {
    nodes { ... on CrossReferencedEvent { willCloseTarget source { ... on PullRequest { state merged mergedAt } } } }
  }
}"""
DIGEST_FRAGMENT = """... on Issue {
  number title createdAt updatedAt
  labels(first: 100) { nodes { name } }
  milestone { title }
}"""


def log(message):
    print(f"[issue-management] {message}", file=sys.stderr)


class GhError(Exception):
    """A GitHub call that failed, or an answer that is incomplete."""


def run_gh(args):
    result = subprocess.run(["gh", *args], capture_output=True, text=True, encoding="utf-8")
    return result.returncode, result.stdout, result.stderr


class Gh:
    """The one place that talks to GitHub. Reads retry and reject incomplete GraphQL answers. Writes go through
    `write`, which in a dry run only prints, and otherwise waits first: GitHub's secondary rate limit asks for
    about a second between writes that create content. A write is never retried, so a comment cannot double."""

    def __init__(self, dry_run, runner=run_gh, delay=1.0, sleep=time.sleep, retries=3, retry_wait=2.0):
        self.dry_run = dry_run
        self.runner = runner
        self.delay = delay
        self.sleep = sleep
        self.retries = retries
        self.retry_wait = retry_wait

    def read(self, *args):
        for attempt in range(1, self.retries + 1):
            code, out, err = self.runner(list(args))
            if code == 0:
                return out
            if attempt == self.retries:
                raise GhError(f"gh {' '.join(args[:3])} failed: {err.strip()}")
            self.sleep(self.retry_wait)

    def graphql(self, query, **variables):
        args = ["api", "graphql", "-f", f"query={query}"]
        for key, value in variables.items():
            if value is None:
                continue
            args += ["-F" if isinstance(value, int) else "-f", f"{key}={value}"]
        try:
            response = json.loads(self.read(*args))
        except json.JSONDecodeError as err:
            raise GhError(f"GraphQL answer is not JSON: {err}") from err
        if response.get("errors") or not isinstance(response.get("data"), dict):
            raise GhError(f"incomplete GraphQL answer: {json.dumps(response.get('errors'))[:300]}")
        return response["data"]

    def write(self, *args):
        if self.dry_run:
            log("[dry-run] gh " + " ".join(shlex.quote(a) for a in args))
            return ""
        self.sleep(self.delay)
        code, out, err = self.runner(list(args))
        if code != 0:
            raise GhError(f"gh {' '.join(args[:3])} failed: {err.strip()}")
        return out


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
        if not isinstance(config[key], list) or not all(isinstance(v, str) and v and '"' not in v for v in config[key]):
            raise ValueError(f"{key} must be a list of label names without double quotes")
    for key in DAY_KEYS:
        value = config[key]
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 3650:
            raise ValueError(f"{key} must be a whole number of days from 1 to 3650")
    limit = config["digest_limit"]
    if isinstance(limit, bool) or not isinstance(limit, int) or not 0 <= limit <= 200:
        raise ValueError("digest_limit must be a whole number from 0 to 200")
    for key in ("stale_label", "resolved_label", "triage_label", "priority_prefix"):
        if not isinstance(config[key], str) or '"' in config[key]:
            raise ValueError(f"{key} must be a string without double quotes")
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


def search_nodes(gh, query, fragment):
    """All nodes of a search, paged, plus whether results beyond the 1000 search allows were left out."""
    nodes, after = [], None
    for _ in range(SEARCH_CAP // 100):
        data = gh.graphql(SEARCH_QUERY % fragment, q=query, after=after)["search"]
        nodes += [n for n in data["nodes"] if n]
        if not data["pageInfo"]["hasNextPage"]:
            return nodes, False
        after = data["pageInfo"]["endCursor"]
    return nodes, True


class IssueData:
    """One issue as read from GitHub, with the means to read further back. Comments and label events arrive
    newest first in a window of 100; `more` pages backwards, only when a decision needs older history."""

    def __init__(self, gh, repo, node):
        self.gh = gh
        self.owner, self.name = repo.split("/")
        self.node = node
        self.comments = node["comments"]["nodes"]
        self.label_events = node["labelEvents"]["nodes"]
        self.page = {
            "comments": node["comments"]["pageInfo"],
            "labelEvents": node["labelEvents"]["pageInfo"],
        }
        self.pages_read = {"comments": 0, "labelEvents": 0}

    def more(self, which):
        """Reads the page before the oldest one held. False when there is none."""
        info = self.page[which]
        if not info["hasPreviousPage"]:
            return False
        self.pages_read[which] += 1
        cursor = info["startCursor"]
        if self.pages_read[which] > MAX_PAGES or not cursor:
            raise GhError(f"issue #{self.node['number']}: {which} paging did not end")
        query = PAGE_QUERY % PAGES[which]
        data = self.gh.graphql(query, owner=self.owner, name=self.name, number=self.node["number"], cursor=cursor)
        issue = data["repository"]["issue"]
        connection = issue.get(which)
        if not isinstance(connection, dict) or "pageInfo" not in connection:
            raise GhError(f"issue #{self.node['number']}: malformed {which} page")
        if connection["pageInfo"]["hasPreviousPage"] and connection["pageInfo"]["startCursor"] == cursor:
            raise GhError(f"issue #{self.node['number']}: {which} cursor did not move")
        older = connection["nodes"]
        if which == "comments":
            self.comments = older + self.comments
        else:
            self.label_events = older + self.label_events
        self.page[which] = connection["pageInfo"]
        return True

    def label_time(self, name):
        times = [parse_time(e["createdAt"]) for e in self.label_events if e["label"]["name"] == name]
        return max(times, default=None)

    def oldest_comment(self):
        return parse_time(self.comments[0]["createdAt"]) if self.comments else None

    def has_human_comment(self):
        return any(not is_bot(c["author"]) for c in self.comments)

    def complete(self, cfg):
        """Reads back only as far as the rules need: to each relevant label's event, to the comments from the
        oldest of those events on, and to the newest human comment."""
        labels = {n["name"] for n in self.node["labels"]["nodes"]}
        relevant = labels & ({cfg["stale_label"], cfg["resolved_label"]} | set(cfg["needs_info_labels"]))
        for name in sorted(relevant):
            while self.label_time(name) is None and self.more("labelEvents"):
                pass
        since = min((t for t in (self.label_time(n) for n in relevant) if t), default=None)
        while since and (self.oldest_comment() is None or self.oldest_comment() > since) and self.more("comments"):
            pass
        while not self.has_human_comment() and self.more("comments"):
            pass


def normalize(data):
    """The plain structure `decide` works on."""
    node = data.node
    refs = [
        {
            "number": e["source"]["number"],
            "state": e["source"]["state"],
            "merged_at": parse_time(e["source"]["mergedAt"]) if e["source"].get("merged") else None,
            "closes": e["willCloseTarget"],
        }
        for e in node["refEvents"]["nodes"]
        if e and e.get("source")
    ]
    return {
        "number": node["number"],
        "title": node["title"],
        "created": parse_time(node["createdAt"]),
        "author": node["author"]["login"] if node["author"] else None,
        "labels": {n["name"] for n in node["labels"]["nodes"]},
        "labels_complete": not node["labels"]["pageInfo"]["hasNextPage"],
        "milestone": node["milestone"] is not None,
        "comments": [
            {
                "at": parse_time(c["createdAt"]),
                "login": c["author"]["login"] if c["author"] else None,
                "bot": is_bot(c["author"]),
                "body": c["body"] or "",
            }
            for c in data.comments
        ],
        "comment_total": node["comments"]["totalCount"],
        "label_events": [(e["label"]["name"], parse_time(e["createdAt"])) for e in data.label_events],
        "refs": refs,
        "refs_complete": not node["refEvents"]["pageInfo"]["hasPreviousPage"],
    }


def label_time(issue, name):
    """When `name` was last applied, or None when no event for it was read."""
    return max((t for n, t in issue["label_events"] if n == name), default=None)


def last_human_comment(issue, after=None, by_author=False):
    """Latest non-bot comment (optionally only the issue author's) newer than `after`."""
    times = [
        c["at"]
        for c in issue["comments"]
        if not c["bot"] and (not by_author or c["login"] == issue["author"]) and (after is None or c["at"] > after)
    ]
    return max(times, default=None)


def marker_time(issue, key):
    """When the bot posted the comment marked `key`, or None. Only a Bot's comment counts, so a user cannot plant
    a marker to suppress or force a step."""
    marker = MARKER.format(key)
    return max((c["at"] for c in issue["comments"] if c["bot"] and marker in c["body"]), default=None)


def with_marker(key, text):
    return f"{MARKER.format(key)}\n{text}"


def epoch(t):
    return int(t.timestamp()) if t else 0


def decide(issue, now, cfg):
    """Returns (actions, notes) for one issue. Actions are ("label", name, comment), ("unlabel", name) or
    ("close", comment_or_None); a comment already posted for the same state is not posted again. Notes say why an
    issue was skipped. Pure, so the tests can cover every rule."""
    labels = set(issue["labels"])
    stale, resolved = cfg["stale_label"], cfg["resolved_label"]
    actions, notes = [], []
    number = issue["number"]

    def days(t):
        return (now - t).days

    if not issue["labels_complete"]:
        return actions, [f"#{number}: more than 100 labels, skipped"]

    # A human comment after a managed label removes it.
    for name in sorted(labels & {stale, resolved}):
        applied = label_time(issue, name)
        if applied is None:
            notes.append(f"#{number}: when `{name}` was applied is not known, left alone")
        elif last_human_comment(issue, after=applied):
            actions.append(("unlabel", name))
            labels.discard(name)

    # A reply from the reporter answers the request, so the label goes: the next request then starts a fresh clock.
    for name in sorted(labels & set(cfg["needs_info_labels"])):
        asked = label_time(issue, name)
        if asked and last_human_comment(issue, after=asked, by_author=True):
            actions.append(("unlabel", name))
            labels.discard(name)

    # An exemption resets the cycle: lifting it later must not close on the old stale clock.
    if labels & set(cfg["exempt_labels"]) or issue["milestone"]:
        if stale in labels:
            actions.append(("unlabel", stale))
        return actions, notes

    activity = max(filter(None, [issue["created"], last_human_comment(issue)]))

    # Rule: waiting on the reporter. The only rule that closes.
    waiting = labels & set(cfg["needs_info_labels"])
    if waiting:
        times = [label_time(issue, name) for name in waiting]
        if None in times:
            return actions, notes + [f"#{number}: when the request for information was made is not known, skipped"]
        asked = max(times)
        human = last_human_comment(issue)
        quiet_since = max(asked, human or asked)
        state = f"{epoch(asked)} {epoch(human)}"
        warned_at = marker_time(issue, f"warn {state}")
        if warned_at is None:
            if days(quiet_since) >= cfg["warning_days"]:
                text = cfg["warning_comment"].format(days=cfg["close_days"], label=stale)
                actions.append(("label", stale, with_marker(f"warn {state}", text)))
        elif stale in labels and days(warned_at) >= cfg["close_days"]:
            text = None
            if marker_time(issue, f"close {state}") is None:
                text = with_marker(f"close {state}", cfg["close_comment"].format(days=days(asked)))
            actions.append(("close", text))
        return actions, notes

    # Rule: possibly resolved. Never closes.
    if resolved not in labels:
        if not issue["refs_complete"]:
            notes.append(f"#{number}: mentioned by more than 100 PRs, not checked for a fix")
        elif not any(r["state"] == "OPEN" for r in issue["refs"]):
            merged = [
                r for r in issue["refs"]
                if r["merged_at"] and not r["closes"] and r["merged_at"] > issue["created"]
            ]
            for ref in sorted(merged, key=lambda r: r["merged_at"], reverse=True):
                key = f"resolved {ref['number']}"
                if days(ref["merged_at"]) >= cfg["resolved_grace_days"] and activity < ref["merged_at"]:
                    if marker_time(issue, key) is None:
                        text = cfg["resolved_comment"].format(pr=ref["number"], label=resolved)
                        actions.append(("label", resolved, with_marker(key, text)))
                    return actions, notes

    # Rule: idle and untriaged. Never closes. Off unless the repository names its triage label.
    key = f"idle {epoch(activity)}"
    if (
        cfg["triage_label"]
        and cfg["triage_label"] in labels
        and stale not in labels
        and not (cfg["priority_prefix"] and any(n.startswith(cfg["priority_prefix"]) for n in labels))
        and days(activity) >= cfg["idle_days"]
        and marker_time(issue, key) is None
    ):
        text = cfg["idle_comment"].format(days=days(activity), label=stale)
        actions.append(("label", stale, with_marker(key, text)))
    return actions, notes


def worth_reading(node, cfg, now):
    """Whether a mentioned issue could get `possibly-resolved`, judged from the light first look: a merged PR
    that does not close it, merged after it was opened and past the grace period, no open PR in flight, and not
    already discussed by a person since the merge. `decide` still has the last word."""
    created = parse_time(node["createdAt"])
    events = [e for e in node["timelineItems"]["nodes"] if e and e.get("source")]
    if any(e["source"].get("state") == "OPEN" for e in events):
        return False
    merged = []
    for event in events:
        source = event["source"]
        if event["willCloseTarget"] or not source.get("merged"):
            continue
        when = parse_time(source["mergedAt"])
        if when > created and (now - when).days >= cfg["resolved_grace_days"]:
            merged.append(when)
    if not merged:
        return False
    newest = (node["comments"]["nodes"] or [None])[-1]
    return not (newest and not is_bot(newest["author"]) and parse_time(newest["createdAt"]) > max(merged))


def exempt_terms(cfg):
    return ["no:milestone"] + [f'-label:"{name}"' for name in cfg["exempt_labels"]]


def discover(gh, repo, cfg, now):
    """The issue numbers worth reading, one search per rule. Returns (numbers, failures)."""
    day = lambda n: (now - timedelta(days=n)).strftime("%Y-%m-%d")  # noqa: E731
    base = f"repo:{repo}"
    searches = [(f'{base} is:issue is:open label:"{cfg["stale_label"]}"', NUMBER_FRAGMENT),
                (f'{base} is:issue is:open label:"{cfg["resolved_label"]}"', NUMBER_FRAGMENT)]
    searches += [(f'{base} is:issue is:open label:"{name}"', NUMBER_FRAGMENT) for name in cfg["needs_info_labels"]]
    exempt = " ".join(exempt_terms(cfg))
    if cfg["triage_label"]:
        idle = f'{base} is:issue is:open label:"{cfg["triage_label"]}" updated:<{day(cfg["idle_days"])} {exempt}'
        searches.append((idle, NUMBER_FRAGMENT))
    mentioned = (f'{base} is:issue is:open updated:>={day(cfg["resolved_window_days"])} '
                 f'-label:"{cfg["resolved_label"]}" {exempt}')
    numbers, failures = set(), 0
    for query, fragment in searches:
        try:
            nodes, capped = search_nodes(gh, query, fragment)
        except GhError as err:
            log(f"::error::search failed: {err}")
            failures += 1
            continue
        if capped:
            log(f"::warning::'{query[:80]}' matched more than {SEARCH_CAP} issues; the rest are not examined")
        numbers |= {n["number"] for n in nodes}
    try:
        nodes, capped = search_nodes(gh, mentioned, MENTION_FRAGMENT)
        if capped:
            log(f"::warning::more than {SEARCH_CAP} issues were updated in the window; the rest are not examined")
        numbers |= {node["number"] for node in nodes if worth_reading(node, cfg, now)}
    except GhError as err:
        log(f"::error::search failed: {err}")
        failures += 1
    return numbers, failures


def untriaged_queue(gh, repo, cfg, now):
    """(number, title, days since update) for issues with the triage label and no priority label, least recently
    updated first. The update time includes bot activity, which a search can give without reading each issue."""
    query = f'repo:{repo} is:issue is:open label:"{cfg["triage_label"]}" sort:updated-asc'
    nodes, capped = search_nodes(gh, query, DIGEST_FRAGMENT)
    if capped:
        log(f"::warning::more than {SEARCH_CAP} issues have `{cfg['triage_label']}`; the queue is the oldest {SEARCH_CAP}")
    queue = []
    for node in nodes:
        labels = {n["name"] for n in node["labels"]["nodes"]}
        if node["milestone"]:
            continue
        if cfg["priority_prefix"] and any(n.startswith(cfg["priority_prefix"]) for n in labels):
            continue
        queue.append((node["number"], node["title"], (now - parse_time(node["updatedAt"])).days))
    return queue


def ensure_label(gh, repo, name, known):
    if name in known or gh.dry_run:
        return
    try:
        gh.read("api", f"repos/{repo}/labels/{name}")
    except GhError:
        color, description = LABEL_INFO.get(name, ("EDEDED", ""))
        gh.write("label", "create", name, "-R", repo, "--color", color, "--description", description)
    known.add(name)


def still_closable(gh, repo, issue, cfg):
    """Re-reads the live issue just before a close: it must still be open, still waiting and marked stale, not
    exempt, and nobody may have commented since it was read."""
    live = json.loads(gh.read("api", f"repos/{repo}/issues/{issue['number']}"))
    names = {label["name"] for label in live["labels"]}
    return (
        live["state"] == "open"
        and cfg["stale_label"] in names
        and bool(names & set(cfg["needs_info_labels"]))
        and not names & set(cfg["exempt_labels"])
        and live["milestone"] is None
        and live["comments"] == issue["comment_total"]
    )


def apply(gh, repo, issue, action, cfg, known_labels):
    """Carries out one action; returns False when a close was abandoned because the issue changed."""
    kind, number = action[0], str(issue["number"])
    if kind == "label":
        ensure_label(gh, repo, action[1], known_labels)
        gh.write("issue", "edit", number, "-R", repo, "--add-label", action[1])
        gh.write("issue", "comment", number, "-R", repo, "--body", action[2])
    elif kind == "unlabel":
        gh.write("issue", "edit", number, "-R", repo, "--remove-label", action[1])
    elif kind == "close":
        if not still_closable(gh, repo, issue, cfg):
            log(f"#{number}: changed since it was read, not closing")
            return False
        if action[1]:
            gh.write("issue", "comment", number, "-R", repo, "--body", action[1])
        gh.write("issue", "close", number, "-R", repo, "--reason", "not planned")
    return True


def describe(action):
    return action[0] if action[0] == "close" else f"{action[0]} {action[1]}"


def short(title):
    return title[:70].replace("|", "/")


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
    try:
        max_actions = int(os.environ.get("MAX_ACTIONS", "30"))
        cfg = load_config(Path(os.environ.get("ISSUE_CONFIG", ".github/issue-management.json")))
        repo = os.environ["GITHUB_REPOSITORY"]
    except (ValueError, KeyError) as err:
        log(f"{type(err).__name__}: {err}")
        return 1
    return sweep(Gh(dry_run == "true"), repo, cfg, max_actions, datetime.now(timezone.utc))


def sweep(gh, repo, cfg, max_actions, now):
    numbers, failed = discover(gh, repo, cfg, now)
    rows, comments, notes, known_labels, changed, read = [], [], [], set(), 0, 0
    for number in sorted(numbers):
        try:
            owner, name = repo.split("/")
            node = gh.graphql(ISSUE_QUERY, owner=owner, name=name, number=number)["repository"]["issue"]
            if node is None:
                continue
            data = IssueData(gh, repo, node)
            data.complete(cfg)
            issue = normalize(data)
            read += 1
            actions, why = decide(issue, now, cfg)
            notes += why
            if not actions:
                continue
            if not gh.dry_run and changed >= max_actions:
                rows.append(f"| #{number} | skipped: max-actions reached | |")
                continue
            changed += 1
            for action in actions:
                done = apply(gh, repo, issue, action, cfg, known_labels)
                rows.append(f"| #{number} | {describe(action)}{'' if done else ' (abandoned)'} | {short(issue['title'])} |")
                body = action[2] if action[0] == "label" else (action[1] if action[0] == "close" else None)
                if body and gh.dry_run:
                    comments.append((number, describe(action), MARKER_RE.sub("", body).strip()))
        except GhError as err:
            log(f"::error::#{number}: {err}")
            failed += 1

    print(f"## Issue management ({'dry-run' if gh.dry_run else 'applied'})\n")
    print(f"Read {read} candidate issues, {changed} with actions.\n")
    if rows:
        print("| Issue | Action | Title |\n|---|---|---|")
        print("\n".join(rows))
    if notes:
        print("\nSkipped:\n\n" + "\n".join(f"- {n}" for n in notes))
    if comments:
        print("\n<details><summary>Comments a live run would post</summary>\n")
        for number, what, body in comments[:30]:
            print(f"**#{number}** ({what}):\n\n> " + body.replace("\n", "\n> ") + "\n")
        if len(comments) > 30:
            print(f"…and {len(comments) - 30} more.\n")
        print("</details>")
    if cfg["triage_label"] and cfg["digest_limit"]:
        try:
            queue = untriaged_queue(gh, repo, cfg, now)
        except GhError as err:
            log(f"::error::untriaged queue failed: {err}")
            failed += 1
            queue = []
        print(f"\n## Untriaged queue\n\n{len(queue)} issues have `{cfg['triage_label']}` and no priority.\n")
        if queue:
            print(f"Least recently updated {min(len(queue), cfg['digest_limit'])} first:\n")
            print("| Issue | Days since update | Title |\n|---|---|---|")
            for number, title, idle in queue[: cfg["digest_limit"]]:
                print(f"| #{number} | {idle} | {short(title)} |")
    if failed:
        log(f"::error::{failed} operation(s) failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
