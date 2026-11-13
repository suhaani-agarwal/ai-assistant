#!/usr/bin/env python3
"""Offline tests for run.py: every rule, exemption and reset, the GitHub guard, paging, discovery and the sweep."""

from datetime import datetime, timedelta, timezone
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("run", Path(__file__).resolve().parents[1] / "run.py")
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

# A repository that triages with labels, as Kyverno does. The defaults leave the idle rule off.
KYVERNO = {
    "triage_label": "triage",
    "priority_prefix": "release-",
    "needs_info_labels": ["needs-info", "cannot reproduce", "waiting for status update"],
    "exempt_labels": ["no-stale", "hold", "security", "good first issue", "release-critical", "release-high"],
}
CFG = {**run.DEFAULTS, **KYVERNO}
NOW = datetime(2026, 11, 11, tzinfo=timezone.utc)


def at(days):
    return NOW - timedelta(days=days)


def iso(days):
    return at(days).isoformat()


def state(asked_days, human_days=None):
    """The marker state `decide` derives for a request made `asked_days` ago, last human comment `human_days` ago."""
    return f"{run.epoch(at(asked_days))} {run.epoch(at(human_days)) if human_days is not None else 0}"


def bot_marker(key, days):
    return (days, "bot", run.with_marker(key, "text"))


def issue(labels=(), created=400, comments=(), events=(), refs=(), milestone=False, author="reporter",
          labels_complete=True, refs_complete=True, comment_total=None):
    """Normalized issue. comments: (days_ago, "reporter"|"maint"|"bot"[, body]); events: (label, days_ago);
    refs: (pr, state, merged_days_ago or None[, closes])."""
    built = []
    for c in comments:
        who = c[1]
        built.append({
            "at": at(c[0]), "login": {"reporter": author, "maint": "maint", "bot": "github-actions[bot]"}[who],
            "bot": who == "bot", "body": c[2] if len(c) > 2 else "",
        })
    built.sort(key=lambda c: c["at"])
    return {
        "number": 1, "title": "t", "created": at(created), "author": author, "labels": set(labels),
        "labels_complete": labels_complete, "milestone": milestone, "comments": built,
        "comment_total": len(built) if comment_total is None else comment_total,
        "label_events": sorted(((n, at(d)) for n, d in events), key=lambda e: e[1]),
        "refs": [{"number": r[0], "state": r[1], "merged_at": at(r[2]) if r[2] is not None else None,
                  "closes": r[3] if len(r) > 3 else False} for r in refs],
        "refs_complete": refs_complete,
    }


def decide(i, cfg=CFG):
    return run.decide(i, NOW, cfg)


def kinds(i, cfg=CFG):
    return [(a[0], a[1]) if a[0] != "close" else ("close",) for a in decide(i, cfg)[0]]


class WaitingOnReporter(unittest.TestCase):
    def test_warns_with_a_marker_after_warning_days(self):
        acts, _ = decide(issue(["needs-info"], events=[("needs-info", 15)]))
        self.assertEqual([(a[0], a[1]) for a in acts], [("label", "stale-issue")])
        self.assertIn(run.MARKER.format(f"warn {state(15)}"), acts[0][2])
        self.assertIn("`stale-issue`", acts[0][2])

    def test_no_action_before_warning_days(self):
        self.assertEqual(kinds(issue(["needs-info"], events=[("needs-info", 5)])), [])

    def test_warning_is_not_repeated(self):
        i = issue(["needs-info", "stale-issue"], events=[("needs-info", 20), ("stale-issue", 5)],
                  comments=[bot_marker(f"warn {state(20)}", 5)])
        self.assertEqual(kinds(i), [])

    def test_closes_after_the_warning_is_old_enough(self):
        i = issue(["needs-info", "stale-issue"], events=[("needs-info", 40), ("stale-issue", 15)],
                  comments=[bot_marker(f"warn {state(40)}", 15)])
        acts, _ = decide(i)
        self.assertEqual([a[0] for a in acts], ["close"])
        self.assertIn(run.MARKER.format(f"close {state(40)}"), acts[0][1])

    def test_no_close_before_the_warning_is_old_enough(self):
        i = issue(["needs-info", "stale-issue"], events=[("needs-info", 40), ("stale-issue", 5)],
                  comments=[bot_marker(f"warn {state(40)}", 5)])
        self.assertEqual(kinds(i), [])

    def test_a_manual_stale_label_alone_never_closes(self):
        # No bot warning exists: the label might have been set by hand, so the reporter was never warned.
        i = issue(["needs-info", "stale-issue"], events=[("needs-info", 60), ("stale-issue", 40)])
        acts, _ = decide(i)
        self.assertEqual([a[0] for a in acts], ["label"])

    def test_a_warning_for_an_earlier_request_does_not_count(self):
        i = issue(["needs-info", "stale-issue"], events=[("needs-info", 20), ("stale-issue", 100)],
                  comments=[bot_marker(f"warn {state(90)}", 100)])
        self.assertEqual([a[0] for a in decide(i)[0]], ["label"])

    def test_close_comment_is_not_repeated_after_a_failed_close(self):
        i = issue(["needs-info", "stale-issue"], events=[("needs-info", 40), ("stale-issue", 15)],
                  comments=[bot_marker(f"warn {state(40)}", 15), bot_marker(f"close {state(40)}", 1)])
        acts, _ = decide(i)
        self.assertEqual(acts, [("close", None)])

    def test_reporter_reply_removes_needs_info(self):
        i = issue(["needs-info", "stale-issue"], comments=[(3, "reporter")],
                  events=[("needs-info", 40), ("stale-issue", 15)])
        # The reply also came after `stale-issue` was applied, so that goes too.
        self.assertEqual(kinds(i), [("unlabel", "stale-issue"), ("unlabel", "needs-info")])

    def test_maintainer_comment_removes_stale_and_restarts_the_clock(self):
        i = issue(["needs-info", "stale-issue"], comments=[bot_marker(f"warn {state(40)}", 15), (3, "maint")],
                  events=[("needs-info", 40), ("stale-issue", 15)])
        self.assertEqual(kinds(i), [("unlabel", "stale-issue")])

    def test_maintainer_comment_is_not_a_reply(self):
        # Not a reply, so needs-info stays and the warning still comes once the quiet period is over.
        i = issue(["needs-info"], comments=[(20, "maint")], events=[("needs-info", 40)])
        self.assertEqual(kinds(i), [("label", "stale-issue")])

    def test_a_recent_maintainer_comment_delays_the_warning(self):
        i = issue(["needs-info"], comments=[(5, "maint")], events=[("needs-info", 40)])
        self.assertEqual(kinds(i), [])

    def test_second_request_starts_a_fresh_clock(self):
        # Asked 60 days ago, answered 50 days ago, asked again 20 days ago with no reply since.
        i = issue(["needs-info"], comments=[(50, "reporter")], events=[("needs-info", 60), ("needs-info", 20)])
        self.assertEqual(kinds(i), [("label", "stale-issue")])

    def test_a_label_removed_by_hand_after_the_warning_is_respected(self):
        i = issue(["needs-info"], events=[("needs-info", 40)], comments=[bot_marker(f"warn {state(40)}", 20)])
        self.assertEqual(kinds(i), [])

    def test_exempt_issue_is_never_closed_and_loses_stale(self):
        i = issue(["needs-info", "stale-issue", "release-high"], events=[("needs-info", 40), ("stale-issue", 15)],
                  comments=[bot_marker(f"warn {state(40)}", 15)])
        self.assertEqual(kinds(i), [("unlabel", "stale-issue")])

    def test_reply_removes_needs_info_even_when_exempt(self):
        i = issue(["needs-info", "no-stale"], comments=[(3, "reporter")], events=[("needs-info", 20)])
        self.assertEqual(kinds(i), [("unlabel", "needs-info")])


class PossiblyResolved(unittest.TestCase):
    def test_labels_after_grace_with_a_marker(self):
        acts, _ = decide(issue(refs=[(99, "MERGED", 10)], created=30))
        self.assertEqual([(a[0], a[1]) for a in acts], [("label", "possibly-resolved")])
        self.assertIn(run.MARKER.format("resolved 99"), acts[0][2])

    def test_within_grace_period(self):
        self.assertEqual(kinds(issue(refs=[(99, "MERGED", 1)], created=30)), [])

    def test_closing_reference_ignored(self):
        self.assertEqual(kinds(issue(refs=[(99, "MERGED", 10, True)], created=30)), [])

    def test_comment_after_merge_blocks(self):
        self.assertEqual(kinds(issue(refs=[(99, "MERGED", 10)], created=30, comments=[(5, "maint")])), [])

    def test_bot_comment_does_not_block(self):
        self.assertEqual(len(decide(issue(refs=[(99, "MERGED", 10)], created=30, comments=[(5, "bot")]))[0]), 1)

    def test_open_pr_in_flight_blocks(self):
        i = issue(refs=[(99, "MERGED", 10), (100, "OPEN", None)], created=30)
        self.assertEqual(kinds(i), [])

    def test_pr_merged_before_the_issue_existed_is_ignored(self):
        self.assertEqual(kinds(issue(refs=[(99, "MERGED", 40)], created=30)), [])

    def test_not_repeated_once_marked_even_if_the_label_was_removed(self):
        i = issue(refs=[(99, "MERGED", 10)], created=30, comments=[bot_marker("resolved 99", 5)])
        self.assertEqual(kinds(i), [])

    def test_comment_removes_the_label(self):
        i = issue(["possibly-resolved"], comments=[(2, "reporter")], events=[("possibly-resolved", 5)])
        self.assertEqual(kinds(i), [("unlabel", "possibly-resolved")])

    def test_more_than_100_mentions_is_skipped_with_a_note(self):
        acts, notes = decide(issue(refs=[(99, "MERGED", 10)], created=30, refs_complete=False))
        self.assertEqual(acts, [])
        self.assertIn("more than 100 PRs", notes[0])

    def test_never_closes(self):
        acts, _ = decide(issue(refs=[(99, "MERGED", 400)], created=500))
        self.assertTrue(all(a[0] != "close" for a in acts))


class IdleUntriaged(unittest.TestCase):
    def test_labels_idle_untriaged(self):
        acts, _ = decide(issue(["triage"], created=200))
        self.assertEqual([(a[0], a[1]) for a in acts], [("label", "stale-issue")])
        self.assertIn("`stale-issue`", acts[0][2])

    def test_recent_activity(self):
        self.assertEqual(kinds(issue(["triage"], created=200, comments=[(10, "maint")])), [])

    def test_priority_label_skips(self):
        self.assertEqual(kinds(issue(["triage", "release-low"], created=400)), [])

    def test_milestone_skips(self):
        self.assertEqual(kinds(issue(["triage"], created=400, milestone=True)), [])

    def test_not_repeated_once_marked(self):
        i = issue(["triage"], created=200, comments=[bot_marker(f"idle {run.epoch(at(200))}", 5)])
        self.assertEqual(kinds(i), [])

    def test_never_closes(self):
        acts, _ = decide(issue(["triage", "stale-issue"], created=900, events=[("stale-issue", 400)]))
        self.assertTrue(all(a[0] != "close" for a in acts))


class Truncation(unittest.TestCase):
    def test_unknown_stale_time_is_noted_and_never_closes(self):
        i = issue(["needs-info", "stale-issue"], events=[("needs-info", 300)])
        acts, notes = decide(i)
        self.assertTrue(all(a[0] != "close" for a in acts))
        self.assertIn("`stale-issue` was applied is not known", notes[0])

    def test_unknown_request_time_skips_the_issue(self):
        acts, notes = decide(issue(["needs-info"]))
        self.assertEqual(acts, [])
        self.assertIn("not known", notes[0])

    def test_more_than_100_labels_skips_the_issue(self):
        acts, notes = decide(issue(["needs-info"], labels_complete=False))
        self.assertEqual(acts, [])
        self.assertIn("more than 100 labels", notes[0])


class StaleLabel(unittest.TestCase):
    def test_default_is_not_the_pr_label(self):
        self.assertEqual(run.DEFAULTS["stale_label"], "stale-issue")

    def test_pr_stale_label_is_left_alone(self):
        i = issue(["needs-info", "stale"], events=[("needs-info", 40), ("stale", 20)])
        self.assertEqual(kinds(i), [("label", "stale-issue")])

    def test_comments_name_the_configured_label(self):
        cfg = {**CFG, "stale_label": "no-activity"}
        acts, _ = decide(issue(["needs-info"], events=[("needs-info", 20)]), cfg)
        self.assertIn("`no-activity`", acts[0][2])


class Config(unittest.TestCase):
    def load(self, content=None):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "issue-management.json"
            if content is not None:
                path.write_text(json.dumps(content))
            return run.load_config(path)

    def test_missing_file_uses_defaults(self):
        self.assertEqual(self.load(), run.DEFAULTS)

    def test_overrides_merge_over_defaults(self):
        cfg = self.load({"idle_days": 90})
        self.assertEqual((cfg["idle_days"], cfg["close_days"]), (90, 14))

    def test_rejects_unknown_key(self):
        with self.assertRaisesRegex(ValueError, "unknown config keys: idel_days"):
            self.load({"idel_days": 90})

    def test_rejects_bad_days(self):
        for key in ("warning_days", "resolved_window_days"):
            for bad in (0, -1, "14", True, 99999):
                with self.assertRaises(ValueError, msg=(key, bad)):
                    self.load({key: bad})

    def test_rejects_unknown_comment_field(self):
        with self.assertRaisesRegex(ValueError, "warning_comment"):
            self.load({"warning_comment": "closes in {when}"})

    def test_rejects_bad_digest_limit(self):
        for bad in (-1, 201, "25", True):
            with self.assertRaises(ValueError, msg=bad):
                self.load({"digest_limit": bad})
        self.assertEqual(self.load({"digest_limit": 0})["digest_limit"], 0)

    def test_rejects_empty_managed_label(self):
        with self.assertRaises(ValueError):
            self.load({"stale_label": ""})

    def test_rejects_double_quotes_in_labels_because_they_go_into_searches(self):
        with self.assertRaises(ValueError):
            self.load({"exempt_labels": ['bad"label']})


class OptIn(unittest.TestCase):
    def test_idle_rule_off_by_default(self):
        self.assertEqual(kinds(issue(["triage"], created=400), run.DEFAULTS), [])

    def test_defaults_do_not_exempt_priority_labels(self):
        i = issue(["needs-info", "stale-issue", "release-high"], events=[("needs-info", 40), ("stale-issue", 15)],
                  comments=[bot_marker(f"warn {state(40)}", 15)])
        self.assertEqual(kinds(i, run.DEFAULTS), [("close",)])


class Validate(unittest.TestCase):
    def run_main(self, content):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c.json"
            path.write_text(content)
            old = {k: os.environ.get(k) for k in ("VALIDATE", "ISSUE_CONFIG")}
            os.environ.update(VALIDATE="true", ISSUE_CONFIG=str(path))
            try:
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    code = run.main()
            finally:
                for k, v in old.items():
                    os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
        return code, out.getvalue()

    def test_valid_config(self):
        self.assertEqual(self.run_main('{"idle_days": 90}')[0], 0)

    def test_invalid_config_fails_without_api_access(self):
        code, out = self.run_main('{"idle_days": 0}')
        self.assertEqual(code, 1)
        self.assertIn("::error", out)

    def test_malformed_json_fails(self):
        self.assertEqual(self.run_main("{")[0], 1)


# --- the GitHub guard, paging, discovery and the sweep, against a fake GitHub ------------------------------------

def parse_args(args):
    """The query and variables of a `gh api graphql` call."""
    variables, i = {}, 4
    while i < len(args):
        key, _, value = args[i + 1].partition("=")
        variables[key] = int(value) if args[i] == "-F" else value
        i += 2
    return args[3].partition("=")[2], variables


def conn(nodes, prev=False, cursor=None):
    return {"pageInfo": {"hasPreviousPage": prev, "startCursor": cursor}, "nodes": nodes}


def gql_comment(days, who="bot", body=""):
    return {"createdAt": iso(days), "body": body,
            "author": {"login": {"reporter": "reporter", "maint": "maint", "bot": "github-actions[bot]"}[who],
                       "__typename": "Bot" if who == "bot" else "User"}}


def gql_issue(number, labels, comments=(), label_events=(), refs=(), created=400, total=None, **extra):
    node = {
        "number": number, "title": f"issue {number}", "createdAt": iso(created),
        "author": {"login": "reporter", "__typename": "User"},
        "labels": {"pageInfo": {"hasNextPage": False}, "nodes": [{"name": n} for n in labels]},
        "milestone": None,
        "comments": {"totalCount": len(comments) if total is None else total, **conn(list(comments))},
        "labelEvents": conn([{"createdAt": iso(d), "label": {"name": n}} for n, d in label_events]),
        "refEvents": conn([{"willCloseTarget": False,
                            "source": {"number": r[0], "state": r[1], "merged": r[1] == "MERGED",
                                       "mergedAt": iso(r[2]) if r[2] is not None else None}} for r in refs]),
    }
    node.update(extra)
    return node


class FakeGitHub:
    """Answers the calls run.py makes, and records them. `searches` maps a substring of the search query to the
    nodes it returns; `issues` holds the full nodes; `pages` the older pages of an issue's connection."""

    def __init__(self):
        self.issues, self.searches, self.pages, self.live, self.calls = {}, [], {}, {}, []
        self.fail_issue = set()

    def __call__(self, args):
        self.calls.append(list(args))
        if args[0] == "api" and args[1] == "graphql":
            query, v = parse_args(args)
            return 0, json.dumps({"data": self.graphql(query, v)}), ""
        if args[0] == "api":
            path = args[1]
            if "/labels/" in path:
                return (0, "{}", "") if path.rsplit("/", 1)[1] in self.live.get("labels", []) else (1, "", "404")
            return 0, json.dumps(self.live[int(path.rsplit("/", 1)[1])]), ""
        return 0, "", ""

    def graphql(self, query, v):
        if "search(" in query:
            q = v["q"]
            for part, nodes in self.searches:
                if part in q:
                    return {"search": {"issueCount": len(nodes), "pageInfo": {"hasNextPage": False}, "nodes": nodes}}
            return {"search": {"issueCount": 0, "pageInfo": {"hasNextPage": False}, "nodes": []}}
        number = v["number"]
        if number in self.fail_issue:
            raise_error = {"errors": [{"message": "boom"}]}
            self.fail_issue.discard(number)
            raise FakeError(raise_error)
        if "cursor" in v:
            which = "comments" if "comments(last: 100, before" in query else "labelEvents"
            return {"repository": {"issue": {which: self.pages[(number, which)][v["cursor"]]}}}
        return {"repository": {"issue": self.issues[number]}}

    def writes(self):
        return [c for c in self.calls if c[0] in ("issue", "label")]


class FakeError(Exception):
    pass


class FakeRunner:
    """Wraps FakeGitHub so a GraphQL `errors` answer comes back as one, like the real API."""

    def __init__(self, fake):
        self.fake = fake

    def __call__(self, args):
        try:
            return self.fake(args)
        except FakeError as err:
            return 0, json.dumps({"errors": err.args[0]["errors"], "data": None}), ""


def make_gh(fake, dry_run=True, sleeps=None):
    sleeps = sleeps if sleeps is not None else []
    return run.Gh(dry_run, runner=FakeRunner(fake), delay=1.0, sleep=sleeps.append, retries=3, retry_wait=2.0), sleeps


class GhGuard(unittest.TestCase):
    def test_dry_run_never_writes(self):
        calls = []
        gh = run.Gh(True, runner=lambda a: calls.append(a) or (0, "", ""), sleep=lambda s: None)
        with contextlib.redirect_stderr(io.StringIO()) as err:
            gh.write("issue", "comment", "1", "--body", "hi")
        self.assertEqual(calls, [])
        self.assertIn("[dry-run]", err.getvalue())

    def test_every_write_waits_first(self):
        sleeps = []
        gh = run.Gh(False, runner=lambda a: (0, "", ""), sleep=sleeps.append, delay=1.0)
        for _ in range(3):
            gh.write("issue", "edit", "1")
        self.assertEqual(sleeps, [1.0, 1.0, 1.0])

    def test_reads_retry_then_raise(self):
        sleeps, calls = [], []
        gh = run.Gh(True, runner=lambda a: calls.append(a) or (1, "", "boom"), sleep=sleeps.append, retries=3, retry_wait=2.0)
        with self.assertRaises(run.GhError):
            gh.read("api", "x")
        self.assertEqual((len(calls), sleeps), (3, [2.0, 2.0]))

    def test_a_failed_write_is_not_retried(self):
        calls = []
        gh = run.Gh(False, runner=lambda a: calls.append(a) or (1, "", "boom"), sleep=lambda s: None)
        with self.assertRaises(run.GhError):
            gh.write("issue", "comment", "1")
        self.assertEqual(len(calls), 1)

    def test_graphql_errors_are_rejected(self):
        gh = run.Gh(True, runner=lambda a: (0, json.dumps({"errors": [{"message": "x"}], "data": {}}), ""), sleep=lambda s: None)
        with self.assertRaises(run.GhError):
            gh.graphql("query { x }")

    def test_graphql_without_data_is_rejected(self):
        gh = run.Gh(True, runner=lambda a: (0, json.dumps({"data": None}), ""), sleep=lambda s: None)
        with self.assertRaises(run.GhError):
            gh.graphql("query { x }")


class Paging(unittest.TestCase):
    def read(self, fake, number, cfg=CFG):
        gh, _ = make_gh(fake)
        data = run.IssueData(gh, "o/r", fake.issues[number])
        data.complete(cfg)
        return run.normalize(data)

    def test_a_reply_beyond_the_newest_window_is_found_instead_of_closing(self):
        # The reporter replied 40 days ago, after the request. Ten newer bot comments push it out of the window.
        fake = FakeGitHub()
        newest = [gql_comment(d, "bot") for d in range(10, 0, -1)]
        older = [gql_comment(40, "reporter")]
        fake.issues[1] = gql_issue(1, ["needs-info", "stale-issue"], newest,
                                   [("needs-info", 60), ("stale-issue", 20)], total=11)
        fake.issues[1]["comments"]["pageInfo"] = {"hasPreviousPage": True, "startCursor": "c1"}
        fake.pages[(1, "comments")] = {"c1": conn(older)}
        issue_ = self.read(fake, 1)
        actions, _ = run.decide(issue_, NOW, CFG)
        self.assertEqual([a[0] for a in actions], ["unlabel"])
        self.assertEqual(actions[0][1], "needs-info")

    def test_pages_stop_once_the_needed_history_is_reached(self):
        fake = FakeGitHub()
        # The window already reaches back past the request (30 days ago, against 20), so no older page is read.
        fake.issues[1] = gql_issue(1, ["needs-info"], [gql_comment(30, "maint"), gql_comment(1, "maint")],
                                   [("needs-info", 20)])
        fake.issues[1]["comments"]["pageInfo"] = {"hasPreviousPage": True, "startCursor": "c1"}
        fake.pages[(1, "comments")] = {"c1": conn([gql_comment(50, "maint")])}
        self.read(fake, 1)
        self.assertEqual([c for c in fake.calls if "cursor=c1" in " ".join(c)], [])

    def test_label_events_are_paged_until_the_label_is_found(self):
        fake = FakeGitHub()
        fake.issues[1] = gql_issue(1, ["needs-info", "stale-issue"], [], [("needs-info", 300)])
        fake.issues[1]["labelEvents"]["pageInfo"] = {"hasPreviousPage": True, "startCursor": "e1"}
        fake.pages[(1, "labelEvents")] = {"e1": conn([{"createdAt": iso(30), "label": {"name": "stale-issue"}}])}
        issue_ = self.read(fake, 1)
        self.assertEqual(run.label_time(issue_, "stale-issue"), at(30))

    def test_the_newest_human_comment_is_found_behind_a_wall_of_bot_comments(self):
        fake = FakeGitHub()
        fake.issues[1] = gql_issue(1, ["triage"], [gql_comment(d, "bot") for d in range(100, 0, -1)], [])
        fake.issues[1]["comments"]["pageInfo"] = {"hasPreviousPage": True, "startCursor": "c1"}
        fake.pages[(1, "comments")] = {"c1": conn([gql_comment(5, "maint")])}
        issue_ = self.read(fake, 1)
        self.assertEqual(run.last_human_comment(issue_), at(5))

    def test_a_cursor_that_does_not_move_is_an_error(self):
        fake = FakeGitHub()
        fake.issues[1] = gql_issue(1, ["needs-info"], [gql_comment(1, "bot")], [("needs-info", 20)])
        fake.issues[1]["comments"]["pageInfo"] = {"hasPreviousPage": True, "startCursor": "c1"}
        fake.pages[(1, "comments")] = {"c1": conn([gql_comment(2, "bot")], prev=True, cursor="c1")}
        with self.assertRaises(run.GhError):
            self.read(fake, 1)

    def test_a_missing_cursor_is_an_error(self):
        fake = FakeGitHub()
        fake.issues[1] = gql_issue(1, ["needs-info"], [gql_comment(1, "bot")], [("needs-info", 20)])
        fake.issues[1]["comments"]["pageInfo"] = {"hasPreviousPage": True, "startCursor": None}
        with self.assertRaises(run.GhError):
            self.read(fake, 1)


class Discovery(unittest.TestCase):
    def numbers(self, cfg, searches):
        fake = FakeGitHub()
        fake.searches = searches
        gh, _ = make_gh(fake)
        found, failures = run.discover(gh, "o/r", cfg, NOW)
        queries = [parse_args(c)[1]["q"] for c in fake.calls]
        return found, failures, queries

    def test_one_search_per_rule(self):
        found, failures, queries = self.numbers(CFG, [])
        text = "\n".join(queries)
        self.assertEqual(failures, 0)
        for expected in ('label:"stale-issue"', 'label:"possibly-resolved"', 'label:"needs-info"',
                         'label:"cannot reproduce"', 'label:"triage" updated:<2026-05-15', "updated:>=2026-10-12"):
            self.assertIn(expected, text)

    def test_exempt_issues_are_left_out_of_the_idle_and_mention_searches(self):
        _, _, queries = self.numbers(CFG, [])
        for q in queries:
            if "updated:" in q:
                self.assertIn('-label:"security"', q)
                self.assertIn("no:milestone", q)

    def test_no_idle_search_without_a_triage_label(self):
        _, _, queries = self.numbers(run.DEFAULTS, [])
        self.assertFalse(any("updated:<" in q for q in queries))

    def test_only_issues_a_merged_mention_could_resolve_are_read(self):
        def mention(number, merged_days=10, closes=False, state="MERGED", created=30, newest=None):
            merged = state == "MERGED"
            return {
                "number": number, "createdAt": iso(created),
                "comments": {"nodes": [newest] if newest else []},
                "timelineItems": {"nodes": [{"willCloseTarget": closes, "source": {
                    "state": state, "merged": merged, "mergedAt": iso(merged_days) if merged else None}}]},
            }
        searches = [("updated:>=", [
            mention(1),                                                # read
            mention(2, state="OPEN"),                                   # not merged
            mention(3, closes=True),                                    # it closes the issue
            mention(4, merged_days=1),                                  # inside the grace period
            mention(5, merged_days=40, created=30),                     # merged before the issue existed
            mention(6, newest=gql_comment(2, "maint")),                 # a person spoke since the merge
            mention(7, newest=gql_comment(2, "bot")),                   # only a bot did: still read
        ])]
        found, _, _ = self.numbers(CFG, searches)
        self.assertEqual(found, {1, 7})

    def test_a_failed_search_is_counted_and_the_others_still_run(self):
        fake = FakeGitHub()
        real = fake.graphql
        calls = {"n": 0}

        def flaky(query, v):
            calls["n"] += 1
            if calls["n"] == 1:
                raise FakeError({"errors": [{"message": "x"}]})
            return real(query, v)
        fake.graphql = flaky
        fake.searches = [('label:"needs-info"', [{"number": 7}])]
        gh, _ = make_gh(fake)
        found, failures = run.discover(gh, "o/r", CFG, NOW)
        self.assertEqual(failures, 1)
        self.assertEqual(found, {7})


class Sweep(unittest.TestCase):
    def setUp(self):
        self.fake = FakeGitHub()
        self.fake.live["labels"] = ["stale-issue", "possibly-resolved"]
        self.needs_info = []
        self.fake.searches.append(('label:"needs-info"', self.needs_info))

    def go(self, dry_run, max_actions=30):
        gh, sleeps = make_gh(self.fake, dry_run)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = run.sweep(gh, "o/r", CFG, max_actions, NOW)
        return code, out.getvalue(), sleeps

    def warn_case(self, number):
        self.needs_info.append({"number": number})
        self.fake.issues[number] = gql_issue(number, ["needs-info"], [], [("needs-info", 20)])

    def test_a_dry_run_makes_no_write_and_shows_the_comment(self):
        self.warn_case(1)
        code, report, _ = self.go(dry_run=True)
        self.assertEqual((code, self.fake.writes()), (0, []))
        self.assertIn("| #1 | label stale-issue |", report)
        self.assertIn("Comments a live run would post", report)
        self.assertNotIn("<!-- issue-management", report)

    def test_a_live_run_waits_before_every_write(self):
        self.warn_case(1)
        code, _, sleeps = self.go(dry_run=False)
        writes = self.fake.writes()
        self.assertEqual(code, 0)
        self.assertEqual(len(writes), 2)  # the label exists; one edit and one comment
        self.assertEqual(sleeps, [1.0] * len(writes))

    def test_a_missing_label_is_created_once(self):
        self.fake.live["labels"] = []
        self.warn_case(1)
        self.warn_case(2)
        self.go(dry_run=False)
        creates = [c for c in self.fake.calls if c[:2] == ["label", "create"]]
        self.assertEqual(len(creates), 1)

    def test_one_failing_issue_does_not_stop_the_rest(self):
        self.warn_case(1)
        self.warn_case(2)
        self.fake.fail_issue.add(1)
        code, report, _ = self.go(dry_run=True)
        self.assertEqual(code, 1)
        self.assertIn("| #2 |", report)

    def close_case(self, live_comments=2, live_labels=("needs-info", "stale-issue")):
        self.needs_info.append({"number": 5})
        comments = [gql_comment(15, "bot", run.with_marker(f"warn {state(40)}", "text")), gql_comment(14, "bot")]
        self.fake.issues[5] = gql_issue(5, ["needs-info", "stale-issue"], comments,
                                        [("needs-info", 40), ("stale-issue", 15)])
        self.fake.live[5] = {"state": "open", "labels": [{"name": n} for n in live_labels], "milestone": None,
                             "comments": live_comments}

    def test_a_close_rereads_the_issue_and_closes_with_a_comment(self):
        self.close_case()
        code, _, _ = self.go(dry_run=False)
        verbs = [c[1] for c in self.fake.writes()]
        self.assertEqual((code, verbs), (0, ["comment", "close"]))

    def test_a_close_is_abandoned_when_a_comment_arrived_after_the_read(self):
        self.close_case(live_comments=3)
        code, report, _ = self.go(dry_run=False)
        self.assertEqual(self.fake.writes(), [])
        self.assertIn("(abandoned)", report)

    def test_a_close_is_abandoned_when_the_issue_became_exempt(self):
        self.close_case(live_labels=("needs-info", "stale-issue", "security"))
        self.go(dry_run=False)
        self.assertEqual(self.fake.writes(), [])

    def test_max_actions_limits_a_live_run_only(self):
        for n in (1, 2, 3):
            self.warn_case(n)
        self.go(dry_run=False, max_actions=1)
        self.assertEqual(len([c for c in self.fake.writes() if c[1] == "comment"]), 1)

    def test_the_untriaged_queue_lists_the_least_recently_updated_first(self):
        def node(number, labels, updated, milestone=None):
            return {"number": number, "title": f"t{number}", "createdAt": iso(500), "updatedAt": iso(updated),
                    "labels": {"nodes": [{"name": n} for n in labels]}, "milestone": milestone}
        self.fake.searches.append(('sort:updated-asc', [
            node(1, ["triage"], 300), node(2, ["triage", "release-low"], 250), node(3, ["triage"], 200),
            node(4, ["triage"], 100, milestone={"title": "m"})]))
        _, report, _ = self.go(dry_run=True)
        self.assertIn("2 issues have `triage` and no priority", report)
        self.assertLess(report.index("| #1 | 300 |"), report.index("| #3 | 200 |"))
        self.assertNotIn("| #2 |", report)


if __name__ == "__main__":
    unittest.main()
