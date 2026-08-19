#!/usr/bin/env python3
"""
Tests for verify.py --over-blocks.

Run: python3 tests/test_over_blocks.py

This mode makes an accusation — "your gate blocked N things it did not need
to" — so the property that matters is not that it finds over-blocks. It is
that it CANNOT find one it has not earned. Every test below is aimed at a way
the count could be inflated:

  * a rule the model has no declared requirement for must never be counted
    against the gate, and must not quietly vanish from the denominator either
  * an unrecognised tool must be treated as unknown, not as harmless
  * verify.py's own probe blocks must not be counted as the gate misfiring
  * an empty or missing log must exit non-zero, because "no data" reading the
    same as "no problems" is exactly how a dead gate looks healthy

The one test that asserts a positive finding uses the case the whole mode
exists for: a fund-movement rule firing on a Write. A file write cannot move
money, whatever the text says.

Note on the fixtures: the blocked-action text in these tests is deliberately
inert filler rather than a realistic payload. Writing a realistic one into
this file trips a live gate's own rules while the file is being saved — which
happened while writing it, and is itself an instance of what this mode counts.
"""

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import verify  # noqa: E402


def write_log(path, entries):
    with open(path, "w") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")


def block(rule, tool, ts="2026-01-01T00:00:00+00:00", attempted="x"):
    return {"ts": ts, "rule": rule, "tool": tool, "attempted": attempted,
            "trust_tier_at_block": 0}


class AdjudicationTests(unittest.TestCase):
    def setUp(self):
        self.tools = verify.TOOL_CAPABILITIES
        self.rules = verify.RULE_REQUIRES

    def adj(self, rule, tool):
        return verify.adjudicate_block(rule, tool, self.tools, self.rules)[0]

    def test_a_file_write_cannot_move_funds(self):
        self.assertEqual(self.adj("FUND_MOVEMENT", "Write"), "over_block")
        self.assertEqual(self.adj("FUND_MOVEMENT", "Edit"), "over_block")

    def test_a_read_only_fetch_cannot_open_an_account(self):
        self.assertEqual(self.adj("ACCOUNT_SIGNUP_FLOW", "WebFetch"),
                         "over_block")

    def test_a_shell_call_is_capable_of_every_gated_action(self):
        for rule in verify.RULE_REQUIRES:
            self.assertEqual(self.adj(rule, "Bash"), "capable", rule)

    def test_writing_key_material_to_a_file_is_a_correct_block(self):
        # The harm of key material is that it exists at all, so a Write is
        # exactly the tool that causes it. This must never read as a misfire.
        self.assertEqual(self.adj("KEY_MATERIAL", "Write"), "capable")
        self.assertEqual(self.adj("PROTECTED_FILE", "Edit"), "capable")

    def test_an_undeclared_rule_is_never_counted_against_the_gate(self):
        self.assertEqual(self.adj("SOME_LOCAL_RULE", "Write"),
                         "undeclared_rule")

    def test_an_unknown_tool_is_unknown_not_harmless(self):
        # The tempting bug: treat anything not in the map as incapable, which
        # would score every custom MCP tool as an over-block.
        self.assertEqual(self.adj("FUND_MOVEMENT", "mcp__custom__do"),
                         "undeclared_tool")


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="overblock-")
        self.log = os.path.join(self.dir, "blocked.jsonl")

    def report(self, entries):
        write_log(self.log, entries)
        return verify.over_block_report(self.dir, self.log)

    def test_counts_and_rate_use_only_adjudicable_records(self):
        r = self.report([
            block("FUND_MOVEMENT", "Write"),   # over-block
            block("FUND_MOVEMENT", "Bash"),    # capable
            block("MY_RULE", "Write"),         # undeclared rule
        ])
        self.assertEqual(r["counts"]["over_block"], 1)
        self.assertEqual(r["counts"]["capable"], 1)
        self.assertEqual(r["counts"]["undeclared_rule"], 1)
        self.assertEqual(r["analysed"], 3)
        # 1 of 2 adjudicable, not 1 of 3 — the undeclared record leaves the
        # ratio entirely rather than being scored either way.
        self.assertEqual(r["rates"]["over_block_of_adjudicable"], 0.5)
        self.assertAlmostEqual(r["rates"]["over_block_of_all"], 0.3333, 3)

    def test_verify_probe_blocks_are_excluded(self):
        # verify.py's own probes deliberately trip the rules. Counting them
        # would let the tool manufacture the finding it reports.
        r = self.report([
            block("FUND_MOVEMENT", "Bash",
                  attempted=f"inert probe payload {verify.PROBE_MARKER}"),
            block("FUND_MOVEMENT", "Write"),
        ])
        self.assertEqual(r["analysed"], 1)
        self.assertEqual(r["log"]["probes_excluded"], 1)

    def test_malformed_lines_are_reported_not_silently_dropped(self):
        with open(self.log, "w") as f:
            f.write(json.dumps(block("FUND_MOVEMENT", "Write")) + "\n")
            f.write("{not json\n")
        r = verify.over_block_report(self.dir, self.log)
        self.assertEqual(r["log"]["malformed"], 1)
        self.assertEqual(r["analysed"], 1)

    def test_config_can_declare_a_local_rule_into_the_count(self):
        # A project with its own rule ids must be able to make this analysis
        # apply without editing verify.py.
        tools, rules, over = verify.capability_model(
            {"rule_requires": {"MY_RULE": "exec"},
             "tool_capabilities": {"mcp__custom__do": ["exec", "persist"]}})
        self.assertEqual(rules["MY_RULE"], "exec")
        self.assertEqual(
            verify.adjudicate_block("MY_RULE", "Write", tools, rules)[0],
            "over_block")
        self.assertEqual(
            verify.adjudicate_block("MY_RULE", "mcp__custom__do",
                                    tools, rules)[0], "capable")
        self.assertIn("MY_RULE", over["rules"])

    def test_config_overrides_do_not_leak_into_the_defaults(self):
        verify.capability_model({"rule_requires": {"LEAKY": "exec"}})
        self.assertNotIn("LEAKY", verify.RULE_REQUIRES)

    def test_empty_log_reports_nothing_to_adjudicate(self):
        r = self.report([])
        self.assertTrue(r["log"]["present"])
        self.assertEqual(r["analysed"], 0)
        self.assertIsNone(r["rates"]["over_block_of_adjudicable"])

    def test_missing_log_is_not_a_clean_bill_of_health(self):
        r = verify.over_block_report(self.dir,
                                     os.path.join(self.dir, "nope.jsonl"))
        self.assertFalse(r["log"]["present"])
        self.assertEqual(r["analysed"], 0)


class ExitCodeTests(unittest.TestCase):
    """The exit code is what a scheduled job reads, so each branch is pinned."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="overblock-exit-")
        self.log = os.path.join(self.dir, "blocked.jsonl")

    def run_check(self, max_rate=None, fmt="md"):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = verify.check_over_blocks(self.dir, fmt, None, self.log,
                                            max_rate)
        return code, buf.getvalue()

    def test_missing_log_exits_one(self):
        code, out = self.run_check()
        self.assertEqual(code, 1)
        self.assertIn("not a clean bill of health", out)

    def test_empty_log_exits_one(self):
        write_log(self.log, [])
        code, _ = self.run_check()
        self.assertEqual(code, 1)

    def test_clean_history_exits_zero(self):
        write_log(self.log, [block("FUND_MOVEMENT", "Bash")])
        code, out = self.run_check()
        self.assertEqual(code, 0)
        self.assertIn("over-block            0", out)

    def test_rate_over_the_allowance_exits_one(self):
        write_log(self.log, [block("FUND_MOVEMENT", "Write"),
                             block("FUND_MOVEMENT", "Bash")])
        self.assertEqual(self.run_check(max_rate=10.0)[0], 1)
        self.assertEqual(self.run_check(max_rate=90.0)[0], 0)

    def test_rate_exactly_at_the_allowance_passes(self):
        write_log(self.log, [block("FUND_MOVEMENT", "Write"),
                             block("FUND_MOVEMENT", "Bash")])
        self.assertEqual(self.run_check(max_rate=50.0)[0], 0)

    def test_json_form_carries_the_same_numbers_as_the_text(self):
        write_log(self.log, [block("FUND_MOVEMENT", "Write"),
                             block("FUND_MOVEMENT", "Bash")])
        _, text = self.run_check()
        _, raw = self.run_check(fmt="json")
        data = json.loads(raw)
        self.assertEqual(data["counts"]["over_block"], 1)
        self.assertEqual(data["rates"]["over_block_of_adjudicable"], 0.5)
        self.assertIn("50.0%", text)

    def test_text_output_prints_the_model_it_rests_on(self):
        # The report claims the model is "printed above so you can argue with
        # it". If it is not, that sentence is false in shipped output.
        write_log(self.log, [block("FUND_MOVEMENT", "Write")])
        _, text = self.run_check()
        self.assertIn("THE MODEL THIS RESTS ON", text)
        self.assertIn("rule FUND_MOVEMENT", text)
        self.assertIn("tool Write", text)


class CliTests(unittest.TestCase):
    def test_flag_runs_end_to_end_against_a_log(self):
        d = tempfile.mkdtemp(prefix="overblock-cli-")
        log = os.path.join(d, "blocked.jsonl")
        write_log(log, [block("FUND_MOVEMENT", "Write"),
                        block("PROTECTED_FILE", "Edit")])
        p = subprocess.run(
            [sys.executable, os.path.join(ROOT, "verify.py"),
             "--over-blocks", "--target", d, "--log", log],
            capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("1 of 2 adjudicable blocks", p.stdout)
        self.assertIn("Write cannot exec", p.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
