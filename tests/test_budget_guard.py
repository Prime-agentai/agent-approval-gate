#!/usr/bin/env python3
"""
Tests for budget_guard.py.

Run: python3 tests/test_budget_guard.py

The cases that matter most here are the ones where a naive implementation
looks correct and silently reports the wrong number: transcript duplicates
(overstates spend ~2x), cache reads priced at the full input rate
(overstates ~10x), and an unrecognized model priced at zero (a ceiling that
never trips). Each has a test below.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import budget_guard  # noqa: E402


def assistant_line(msg_id, model, **usage):
    full_usage = {
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_read_input_tokens": 0,
        "cache_creation_input_tokens": 0,
    }
    full_usage.update(usage)
    return json.dumps({
        "type": "assistant",
        "message": {"id": msg_id, "model": model, "usage": full_usage},
    })


class BaseCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.config = budget_guard.load_config()
        self.config["_project_root"] = self.tmp

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_transcript(self, lines):
        path = os.path.join(self.tmp, "transcript.jsonl")
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")
        return path


class TestPricing(BaseCase):
    def test_input_and_output_priced_at_table_rates(self):
        cost = budget_guard.price_usage(
            "claude-opus-5",
            {"input_tokens": 1_000_000, "output_tokens": 1_000_000},
            self.config,
        )
        self.assertAlmostEqual(cost, 30.0, places=6)  # $5 in + $25 out

    def test_cache_reads_are_a_tenth_of_the_input_rate(self):
        cost = budget_guard.price_usage(
            "claude-opus-5", {"cache_read_input_tokens": 1_000_000}, self.config
        )
        self.assertAlmostEqual(cost, 0.5, places=6)

    def test_cache_writes_split_by_ttl(self):
        cost = budget_guard.price_usage(
            "claude-opus-5",
            {"cache_creation": {"ephemeral_5m_input_tokens": 1_000_000,
                                "ephemeral_1h_input_tokens": 1_000_000}},
            self.config,
        )
        self.assertAlmostEqual(cost, 5 * 1.25 + 5 * 2.0, places=6)

    def test_flat_cache_creation_falls_back_to_the_5m_rate(self):
        cost = budget_guard.price_usage(
            "claude-opus-5", {"cache_creation_input_tokens": 1_000_000}, self.config
        )
        self.assertAlmostEqual(cost, 6.25, places=6)

    def test_unknown_model_is_priced_at_the_highest_configured_rate(self):
        # A model released after this table was written must not cost $0 --
        # that would be a ceiling that never trips.
        cost = budget_guard.price_usage(
            "claude-something-unreleased", {"output_tokens": 1_000_000}, self.config
        )
        priciest = max(r["output"] for r in self.config["pricing_usd_per_mtok"].values())
        self.assertAlmostEqual(cost, priciest, places=6)

    def test_unknown_model_policy_ignore_is_honoured(self):
        self.config["unknown_model_policy"] = "ignore"
        cost = budget_guard.price_usage(
            "claude-something-unreleased", {"output_tokens": 1_000_000}, self.config
        )
        self.assertEqual(cost, 0.0)

    def test_suffixed_model_id_matches_by_prefix(self):
        self.assertEqual(
            budget_guard.model_rates("claude-opus-5-experimental", self.config),
            (5.0, 25.0),
        )


class TestTranscriptParsing(BaseCase):
    def test_streamed_duplicates_are_deduplicated_by_message_id(self):
        # A streamed message is rewritten as it grows. Summing line by line
        # would double-count; the last line for an id is the final usage.
        path = self.write_transcript([
            assistant_line("msg_1", "claude-opus-5", output_tokens=100),
            assistant_line("msg_1", "claude-opus-5", output_tokens=500),
            assistant_line("msg_1", "claude-opus-5", output_tokens=1_000_000),
        ])
        costs = budget_guard.read_transcript_costs(path, self.config)
        self.assertEqual(len(costs), 1)
        self.assertAlmostEqual(sum(c for _m, c in costs.values()), 25.0, places=6)

    def test_non_assistant_and_malformed_lines_are_skipped(self):
        path = self.write_transcript([
            json.dumps({"type": "user", "message": {"content": "hi"}}),
            "{not json at all",
            json.dumps({"type": "assistant", "message": {"id": "x"}}),  # no usage
            assistant_line("msg_1", "claude-haiku-4-5", output_tokens=1_000_000),
        ])
        costs = budget_guard.read_transcript_costs(path, self.config)
        self.assertEqual(len(costs), 1)
        self.assertAlmostEqual(sum(c for _m, c in costs.values()), 5.0, places=6)

    def test_missing_transcript_returns_none_not_zero(self):
        # None means "unknown"; 0.0 would mean "measured, and it was free".
        self.assertIsNone(
            budget_guard.read_transcript_costs(
                os.path.join(self.tmp, "nope.jsonl"), self.config
            )
        )


class TestBudgetCeilings(BaseCase):
    def payload(self, transcript, session="s1", tool="Bash", tool_input=None):
        return {
            "session_id": session,
            "transcript_path": transcript,
            "tool_name": tool,
            "tool_input": tool_input if tool_input is not None else {"command": "ls"},
        }

    def test_under_ceiling_allows(self):
        path = self.write_transcript(
            [assistant_line("m1", "claude-opus-5", output_tokens=1000)]
        )
        hit, _s, _d = budget_guard.evaluate(self.payload(path), self.config)
        self.assertIsNone(hit)

    def test_session_ceiling_blocks(self):
        self.config["session_cost_ceiling_usd"] = 1.0
        path = self.write_transcript(
            [assistant_line("m1", "claude-opus-5", output_tokens=1_000_000)]
        )
        hit, session_cost, _d = budget_guard.evaluate(self.payload(path), self.config)
        self.assertEqual(hit[0], "SESSION_BUDGET")
        self.assertAlmostEqual(session_cost, 25.0, places=6)

    def test_daily_ceiling_blocks_across_sessions(self):
        self.config["session_cost_ceiling_usd"] = None
        self.config["daily_cost_ceiling_usd"] = 30.0
        first = self.write_transcript(
            [assistant_line("m1", "claude-opus-5", output_tokens=1_000_000)]
        )
        hit, _s, _d = budget_guard.evaluate(
            self.payload(first, session="s1"), self.config
        )
        self.assertIsNone(hit)  # $25 of $30, under on its own

        second_path = os.path.join(self.tmp, "second.jsonl")
        with open(second_path, "w") as f:
            f.write(assistant_line("m2", "claude-opus-5", output_tokens=1_000_000) + "\n")
        hit, _s, day = budget_guard.evaluate(
            self.payload(second_path, session="s2"), self.config
        )
        self.assertEqual(hit[0], "DAILY_BUDGET")
        self.assertAlmostEqual(day, 50.0, places=6)

    def test_daily_rollup_overwrites_rather_than_accumulates_per_session(self):
        # The same session re-reporting on every tool call must not inflate
        # the day's total.
        path = self.write_transcript(
            [assistant_line("m1", "claude-opus-5", output_tokens=1_000_000)]
        )
        for _ in range(5):
            _hit, _s, day = budget_guard.evaluate(self.payload(path), self.config)
        self.assertAlmostEqual(day, 25.0, places=6)

    def test_unreadable_transcript_fails_open(self):
        self.config["session_cost_ceiling_usd"] = 0.0001
        hit, _s, _d = budget_guard.evaluate(
            self.payload(os.path.join(self.tmp, "missing.jsonl")), self.config
        )
        self.assertIsNone(hit)

    def test_null_ceiling_disables_the_check(self):
        self.config["session_cost_ceiling_usd"] = None
        self.config["daily_cost_ceiling_usd"] = None
        path = self.write_transcript(
            [assistant_line("m1", "claude-fable-5", output_tokens=10_000_000)]
        )
        hit, session_cost, _d = budget_guard.evaluate(self.payload(path), self.config)
        self.assertIsNone(hit)
        self.assertAlmostEqual(session_cost, 500.0, places=6)


class TestLoopDetector(BaseCase):
    def call(self, tool="Bash", tool_input=None, session="s1"):
        return budget_guard.check_loop(
            session, tool,
            tool_input if tool_input is not None else {"command": "ls"},
            self.config,
        )

    def test_blocks_on_the_nth_consecutive_identical_call(self):
        limit = self.config["loop_detector"]["consecutive_repeats"]
        for _ in range(limit - 1):
            self.assertIsNone(self.call())
        self.assertEqual(self.call()[0], "LOOP_CONSECUTIVE")

    def test_alternating_calls_still_trip_the_window_rule(self):
        # A,B,A,B... never repeats consecutively, which is exactly why a
        # consecutive-only detector misses the common stuck-agent shape.
        self.config["loop_detector"]["consecutive_repeats"] = 0
        self.config["loop_detector"]["max_repeats"] = 3
        results = []
        for _ in range(3):
            results.append(self.call(tool_input={"command": "a"}))
            results.append(self.call(tool_input={"command": "b"}))
        self.assertEqual(results[-2][0], "LOOP_WINDOW")

    def test_different_arguments_are_different_calls(self):
        for i in range(10):
            self.assertIsNone(self.call(tool_input={"command": f"ls {i}"}))

    def test_key_order_does_not_change_the_fingerprint(self):
        self.assertEqual(
            budget_guard.fingerprint("Edit", {"a": 1, "b": 2}),
            budget_guard.fingerprint("Edit", {"b": 2, "a": 1}),
        )

    def test_sessions_have_independent_windows(self):
        limit = self.config["loop_detector"]["consecutive_repeats"]
        for _ in range(limit):
            self.call(session="s1")
        self.assertIsNone(self.call(session="s2"))

    def test_ignore_tools_is_honoured(self):
        self.config["loop_detector"]["ignore_tools"] = ["TodoWrite"]
        for _ in range(20):
            self.assertIsNone(self.call(tool="TodoWrite"))

    def test_disabled_detector_never_blocks(self):
        self.config["loop_detector"]["enabled"] = False
        for _ in range(20):
            self.assertIsNone(self.call())


class TestConfig(BaseCase):
    def test_user_config_merges_one_level_deep(self):
        path = os.path.join(self.tmp, "budget-guard.config.json")
        with open(path, "w") as f:
            json.dump({"loop_detector": {"max_repeats": 99}}, f)
        os.environ["BUDGET_GUARD_CONFIG"] = path
        try:
            config = budget_guard.load_config()
        finally:
            del os.environ["BUDGET_GUARD_CONFIG"]
        self.assertEqual(config["loop_detector"]["max_repeats"], 99)
        # Overriding one field must not delete the siblings.
        self.assertIn("window", config["loop_detector"])
        self.assertTrue(config["loop_detector"]["enabled"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
