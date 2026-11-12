#!/usr/bin/env python3
"""Offline tests for run.py: one case per rule, exemption and reset, plus config handling."""

from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("run", Path(__file__).resolve().parents[1] / "run.py")
lifecycle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lifecycle)

# A repository that triages with labels, as Kyverno does. The defaults leave the idle rule off.
KYVERNO = {
    "triage_label": "triage",
    "priority_prefix": "release-",
    "needs_info_labels": ["needs-info", "cannot reproduce", "waiting for status update"],
    "exempt_labels": ["no-stale", "hold", "security", "good first issue", "release-critical", "release-high"],
}
CFG = {**lifecycle.DEFAULTS, **KYVERNO}
NOW = datetime(2026, 11, 11, tzinfo=timezone.utc)
USER = {"login": "reporter", "__typename": "User"}
MAINT = {"login": "maint", "__typename": "User"}
BOT = {"login": "github-actions[bot]", "__typename": "Bot"}


def ago(days):
    return (NOW - timedelta(days=days)).isoformat()


def issue(labels=(), created=400, comments=(), events=(), milestone=None):
    """comments: (days_ago, author); events: ("label", name, days_ago) or ("ref", pr, merged_days_ago, closes)."""
    nodes = []
    for e in events:
        if e[0] == "label":
            nodes.append({"__typename": "LabeledEvent", "createdAt": ago(e[2]), "label": {"name": e[1]}})
        else:
            nodes.append({
                "__typename": "CrossReferencedEvent",
                "willCloseTarget": e[3] if len(e) > 3 else False,
                "source": {
                    "number": e[1],
                    "state": e[4] if len(e) > 4 else "MERGED",
                    "merged": (e[4] if len(e) > 4 else "MERGED") == "MERGED",
                    "mergedAt": ago(e[2]) if (e[4] if len(e) > 4 else "MERGED") == "MERGED" else None,
                },
            })
    return {
        "number": 1,
        "title": "t",
        "createdAt": ago(created),
        "author": USER,
        "labels": {"nodes": [{"name": n} for n in labels]},
        "milestone": milestone,
        "comments": {"nodes": [{"createdAt": ago(d), "author": a} for d, a in comments]},
        "timelineItems": {"nodes": nodes},
    }


def decide(i):
    return lifecycle.decide(i, NOW, CFG)


class WaitingOnReporter(unittest.TestCase):
    def test_warns_after_warning_days(self):
        acts = decide(issue(["needs-info"], events=[("label", "needs-info", 15)]))
        self.assertEqual([(a[0], a[1]) for a in acts], [("label", "stale-issue")])

    def test_no_action_before_warning_days(self):
        self.assertEqual(decide(issue(["needs-info"], events=[("label", "needs-info", 5)])), [])

    def test_closes_after_stale_period(self):
        i = issue(["needs-info", "stale-issue"], events=[("label", "needs-info", 40), ("label", "stale-issue", 15)])
        self.assertEqual([a[0] for a in decide(i)], ["close"])

    def test_no_close_before_stale_period(self):
        i = issue(["needs-info", "stale-issue"], events=[("label", "needs-info", 40), ("label", "stale-issue", 5)])
        self.assertEqual(decide(i), [])

    def test_reporter_reply_resets(self):
        i = issue(["needs-info", "stale-issue"], comments=[(3, USER)],
                  events=[("label", "needs-info", 40), ("label", "stale-issue", 15)])
        self.assertEqual(decide(i), [("unlabel", "stale-issue"), ("unlabel", "needs-info")])

    def test_reply_removes_needs_info_even_when_exempt(self):
        i = issue(["needs-info", "no-stale"], comments=[(3, USER)], events=[("label", "needs-info", 20)])
        self.assertEqual(decide(i), [("unlabel", "needs-info")])

    def test_second_request_starts_a_fresh_clock(self):
        # Asked 60 days ago, answered 50 days ago, asked again 20 days ago with no reply since.
        i = issue(["needs-info"], comments=[(50, USER)],
                  events=[("label", "needs-info", 60), ("label", "needs-info", 20)])
        self.assertEqual([(a[0], a[1]) for a in decide(i)], [("label", "stale-issue")])

    def test_maintainer_comment_is_not_a_reply(self):
        i = issue(["needs-info"], comments=[(10, MAINT)], events=[("label", "needs-info", 15)])
        self.assertEqual([a[0] for a in decide(i)], ["label"])

    def test_stale_from_another_rule_does_not_close(self):
        # Idle-untriaged marked it stale 100 days ago; needs-info was asked 20 days ago with no reply.
        i = issue(["needs-info", "stale-issue"], events=[("label", "stale-issue", 100), ("label", "needs-info", 20)])
        acts = decide(i)
        self.assertEqual([a[0] for a in acts], ["unlabel", "label"])
        self.assertTrue(all(a[0] != "close" for a in acts))

    def test_exempt_never_closes(self):
        i = issue(["needs-info", "stale-issue", "release-high"],
                  events=[("label", "needs-info", 40), ("label", "stale-issue", 15)])
        self.assertEqual(decide(i), [])


class PossiblyResolved(unittest.TestCase):
    def test_labels_after_grace(self):
        acts = decide(issue(events=[("ref", 99, 10)], created=30))
        self.assertEqual([(a[0], a[1]) for a in acts], [("label", "possibly-resolved")])

    def test_within_grace_period(self):
        self.assertEqual(decide(issue(events=[("ref", 99, 1)], created=30)), [])

    def test_closing_reference_ignored(self):
        self.assertEqual(decide(issue(events=[("ref", 99, 10, True)], created=30)), [])

    def test_comment_after_merge_blocks(self):
        self.assertEqual(decide(issue(events=[("ref", 99, 10)], created=30, comments=[(5, MAINT)])), [])

    def test_bot_comment_does_not_block(self):
        acts = decide(issue(events=[("ref", 99, 10)], created=30, comments=[(5, BOT)]))
        self.assertEqual(len(acts), 1)

    def test_comment_removes_label(self):
        i = issue(["possibly-resolved"], comments=[(2, USER)], events=[("label", "possibly-resolved", 5)])
        self.assertEqual(decide(i), [("unlabel", "possibly-resolved")])

    def test_open_pr_in_flight_blocks(self):
        i = issue(events=[("ref", 99, 10), ("ref", 100, 0, False, "OPEN")], created=30)
        self.assertEqual(decide(i), [])

    def test_pr_merged_before_the_issue_existed_is_ignored(self):
        self.assertEqual(decide(issue(events=[("ref", 99, 40)], created=30)), [])

    def test_never_closes(self):
        acts = decide(issue(events=[("ref", 99, 400)], created=500))
        self.assertTrue(all(a[0] != "close" for a in acts))


class IdleUntriaged(unittest.TestCase):
    def test_labels_idle_untriaged(self):
        acts = decide(issue(["triage"], created=200))
        self.assertEqual([(a[0], a[1]) for a in acts], [("label", "stale-issue")])

    def test_recent_activity(self):
        self.assertEqual(decide(issue(["triage"], created=200, comments=[(10, MAINT)])), [])

    def test_priority_label_skips(self):
        self.assertEqual(decide(issue(["triage", "release-low"], created=400)), [])

    def test_milestone_skips(self):
        self.assertEqual(decide(issue(["triage"], created=400, milestone={"title": "Kyverno Release 1.20"})), [])

    def test_no_stale_exempts(self):
        self.assertEqual(decide(issue(["triage", "no-stale"], created=400)), [])

    def test_never_closes(self):
        acts = decide(issue(["triage", "stale-issue"], created=900, events=[("label", "stale-issue", 400)]))
        self.assertTrue(all(a[0] != "close" for a in acts))


class Digest(unittest.TestCase):
    def queue(self, issues, cfg=CFG):
        return [(i["number"], idle) for i, idle in lifecycle.untriaged_queue(issues, NOW, cfg)]

    def numbered(self, number, **kwargs):
        i = issue(**kwargs)
        i["number"] = number
        return i

    def test_lists_untriaged_oldest_first(self):
        issues = [self.numbered(1, labels=["triage"], created=10), self.numbered(2, labels=["triage"], created=90)]
        self.assertEqual(self.queue(issues), [(2, 90), (1, 10)])

    def test_skips_prioritised_milestoned_and_untriaged_issues(self):
        issues = [
            self.numbered(1, labels=["triage", "release-low"]),
            self.numbered(2, labels=["triage"], milestone={"title": "m"}),
            self.numbered(3, labels=["bug"]),
        ]
        self.assertEqual(self.queue(issues), [])

    def test_human_comment_resets_idle_days(self):
        issues = [self.numbered(1, labels=["triage"], created=90, comments=[(5, MAINT)])]
        self.assertEqual(self.queue(issues), [(1, 5)])

    def test_exempt_issue_is_still_untriaged(self):
        self.assertEqual(self.queue([self.numbered(1, labels=["triage", "no-stale"], created=20)]), [(1, 20)])


class Config(unittest.TestCase):
    def load(self, content=None):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "issue-management.json"
            if content is not None:
                path.write_text(json.dumps(content))
            return lifecycle.load_config(path)

    def test_missing_file_uses_defaults(self):
        self.assertEqual(self.load(), lifecycle.DEFAULTS)

    def test_overrides_merge_over_defaults(self):
        cfg = self.load({"idle_days": 90})
        self.assertEqual((cfg["idle_days"], cfg["close_days"]), (90, 14))

    def test_rejects_unknown_key(self):
        with self.assertRaisesRegex(ValueError, "unknown config keys: idel_days"):
            self.load({"idel_days": 90})

    def test_rejects_bad_days(self):
        for bad in (0, -1, "14", True, 99999):
            with self.assertRaises(ValueError, msg=bad):
                self.load({"warning_days": bad})

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


class StaleLabel(unittest.TestCase):
    def test_default_is_not_the_pr_label(self):
        self.assertEqual(lifecycle.DEFAULTS["stale_label"], "stale-issue")

    def test_pr_stale_label_is_left_alone(self):
        # An issue carrying `stale` (a PR-style or legacy label) is not ours: no removal, no close.
        i = issue(["needs-info", "stale"], comments=[(3, MAINT)],
                  events=[("label", "needs-info", 40), ("label", "stale", 20)])
        self.assertEqual([(a[0], a[1]) for a in decide(i)], [("label", "stale-issue")])

    def test_comments_name_the_configured_label(self):
        cfg = {**CFG, "stale_label": "no-activity"}
        acts = lifecycle.decide(issue(["needs-info"], events=[("label", "needs-info", 20)]), NOW, cfg)
        self.assertIn("`no-activity`", acts[0][2])


class Validate(unittest.TestCase):
    def run_main(self, content):
        import contextlib, io, os
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c.json"
            path.write_text(content)
            old = {k: os.environ.get(k) for k in ("VALIDATE", "ISSUE_CONFIG")}
            os.environ.update(VALIDATE="true", ISSUE_CONFIG=str(path))
            try:
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    code = lifecycle.main()
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


class OptIn(unittest.TestCase):
    def test_idle_rule_off_by_default(self):
        i = issue(["triage"], created=400)
        self.assertEqual(lifecycle.decide(i, NOW, lifecycle.DEFAULTS), [])

    def test_defaults_do_not_exempt_priority_labels(self):
        i = issue(["needs-info", "stale-issue", "release-high"], events=[("label", "needs-info", 40), ("label", "stale-issue", 15)])
        self.assertEqual([a[0] for a in lifecycle.decide(i, NOW, lifecycle.DEFAULTS)], ["close"])


if __name__ == "__main__":
    unittest.main()
