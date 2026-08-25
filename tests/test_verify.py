#!/usr/bin/env python3
"""
Tests for verify.py.

Run: python3 tests/test_verify.py

verify.py is the thing you trust when you have stopped reading the guards
themselves, so the case that matters here is not "does it print PASS" — it is
"does it print FAIL when the guard is broken". A verifier that green-lights a
broken hook is worse than no verifier, because it converts an unknown into a
false certainty.

So the end-to-end tests below install a real project, break budget_guard.py
in one specific way each time, and assert that the run fails. Each mutation
corresponds to an accounting rule a plausible implementation gets wrong:
transcript duplicates, cache-read pricing, unknown models, and a loop window
that silently fails to persist.

The other property tested end to end is isolation. Budget probes write
synthetic spend, and budget_guard keys a shared daily rollup by session id —
so a probe run against the real state_dir would leave imaginary spend in
today's total and could block the operator's actual agent for the rest of the
day. `test_probes_do_not_touch_real_spend_state` is what keeps that honest.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import verify  # noqa: E402


class TokensForTests(unittest.TestCase):
    def test_rounds_up_so_a_probe_clears_the_boundary(self):
        # $10 at $5/Mtok is exactly 2,000,000 tokens. A probe aimed *above* a
        # ceiling that lands exactly on it is a coin flip against a >= check.
        self.assertGreater(verify.tokens_for(10.0, 5.0), 2_000_000)

    def test_multiplier_lowers_the_effective_rate(self):
        # Cache reads bill at 0.1x, so the same dollar buys 10x the tokens.
        plain = verify.tokens_for(1.0, 5.0)
        cached = verify.tokens_for(1.0, 5.0, 0.1)
        self.assertAlmostEqual(cached / plain, 10.0, places=2)

    def test_zero_rate_does_not_divide_by_zero(self):
        self.assertEqual(verify.tokens_for(1.0, 0.0), 0)


class WithConfigTests(unittest.TestCase):
    def test_rewrites_the_env_assignment_install_py_writes(self):
        command = 'env BUDGET_GUARD_CONFIG="/p/budget-guard.config.json" python3 "/p/bin/budget_guard.py"'
        out = verify.with_config(command, "/tmp/probe/c.json")
        self.assertIn('BUDGET_GUARD_CONFIG="/tmp/probe/c.json"', out)
        self.assertNotIn("/p/budget-guard.config.json", out)
        self.assertIn("/p/bin/budget_guard.py", out)

    def test_adds_an_assignment_when_the_command_has_none(self):
        out = verify.with_config("python3 /p/bin/budget_guard.py", "/tmp/c.json")
        self.assertTrue(out.startswith('env BUDGET_GUARD_CONFIG="/tmp/c.json" '))

    def test_only_one_assignment_survives_a_rewrite(self):
        command = "env BUDGET_GUARD_CONFIG=/a.json python3 /p/budget_guard.py"
        out = verify.with_config(command, "/b.json")
        self.assertEqual(out.count("BUDGET_GUARD_CONFIG="), 1)


class FindHookCommandTests(unittest.TestCase):
    def setUp(self):
        self.target = tempfile.mkdtemp(prefix="verify-hook-")
        self.addCleanup(shutil.rmtree, self.target, ignore_errors=True)
        os.makedirs(os.path.join(self.target, ".claude"))

    def write_settings(self, commands):
        path = os.path.join(self.target, ".claude", "settings.json")
        with open(path, "w") as f:
            json.dump({"hooks": {"PreToolUse": [
                {"hooks": [{"type": "command", "command": c}]} for c in commands
            ]}}, f)

    def test_each_guard_finds_its_own_hook_among_several(self):
        self.write_settings([
            "python3 /p/bin/gate_guard.py",
            "python3 /p/bin/other_hook.py",
            "python3 /p/bin/budget_guard.py",
        ])
        gate, _ = verify.find_hook_command(self.target, "gate_guard.py")
        budget, _ = verify.find_hook_command(self.target, "budget_guard.py")
        self.assertIn("gate_guard.py", gate)
        self.assertIn("budget_guard.py", budget)

    def test_missing_guard_reports_which_one(self):
        self.write_settings(["python3 /p/bin/gate_guard.py"])
        command, err = verify.find_hook_command(self.target, "budget_guard.py")
        self.assertIsNone(command)
        self.assertIn("budget_guard.py", err)

    def test_hyphenated_filename_is_recognised(self):
        self.write_settings(["python3 /p/bin/budget-guard.py"])
        command, _ = verify.find_hook_command(self.target, "budget_guard.py")
        self.assertIsNotNone(command)


class MergeBudgetConfigTests(unittest.TestCase):
    class FakeModule:
        DEFAULT_CONFIG = {
            "session_cost_ceiling_usd": 10.0,
            "loop_detector": {"enabled": True, "window": 20, "max_repeats": 6},
        }

    def test_nested_block_merges_one_level_rather_than_replacing(self):
        merged = verify.merge_budget_config(
            self.FakeModule, {"loop_detector": {"max_repeats": 3}})
        self.assertEqual(merged["loop_detector"]["max_repeats"], 3)
        self.assertEqual(merged["loop_detector"]["window"], 20)
        self.assertTrue(merged["loop_detector"]["enabled"])

    def test_comment_keys_are_ignored(self):
        # The shipped example config documents itself with _comment keys.
        merged = verify.merge_budget_config(
            self.FakeModule, {"_comment": "hi", "session_cost_ceiling_usd": 2.0})
        self.assertNotIn("_comment", merged)
        self.assertEqual(merged["session_cost_ceiling_usd"], 2.0)

    def test_defaults_are_not_mutated_by_a_merge(self):
        verify.merge_budget_config(self.FakeModule, {"loop_detector": {"window": 1}})
        self.assertEqual(self.FakeModule.DEFAULT_CONFIG["loop_detector"]["window"], 20)


class ResolveBudgetConfigTests(unittest.TestCase):
    def setUp(self):
        self.target = tempfile.mkdtemp(prefix="verify-cfg-")
        self.addCleanup(shutil.rmtree, self.target, ignore_errors=True)

    def test_env_assignment_in_the_command_wins(self):
        path, origin = verify.resolve_budget_config(
            'env BUDGET_GUARD_CONFIG="/x/c.json" python3 /g.py',
            self.target, "/g.py")
        self.assertEqual(path, "/x/c.json")
        self.assertEqual(origin, "hook command")

    def test_falls_back_to_the_project_root(self):
        expected = os.path.join(self.target, "budget-guard.config.json")
        with open(expected, "w") as f:
            f.write("{}")
        path, origin = verify.resolve_budget_config(
            "python3 /g.py", self.target, "/g.py")
        self.assertEqual(path, expected)
        self.assertEqual(origin, "project root")

    def test_no_config_anywhere_reports_built_in_defaults(self):
        path, origin = verify.resolve_budget_config(
            "python3 /g.py", self.target, "/g.py")
        self.assertIsNone(path)
        self.assertEqual(origin, "built-in defaults")


class WritableTests(unittest.TestCase):
    def test_reports_false_for_a_read_only_directory(self):
        if os.geteuid() == 0:
            self.skipTest("root ignores the mode bits")
        parent = tempfile.mkdtemp(prefix="verify-ro-")
        self.addCleanup(shutil.rmtree, parent, ignore_errors=True)
        target = os.path.join(parent, "locked")
        os.makedirs(target)
        os.chmod(target, 0o500)
        self.addCleanup(os.chmod, target, 0o700)
        self.assertFalse(verify.writable(target))

    def test_creates_and_reports_true_for_a_missing_directory(self):
        parent = tempfile.mkdtemp(prefix="verify-rw-")
        self.addCleanup(shutil.rmtree, parent, ignore_errors=True)
        target = os.path.join(parent, "nested", "deep")
        self.assertTrue(verify.writable(target))
        self.assertTrue(os.path.isdir(target))


class EndToEndTests(unittest.TestCase):
    """Install a real project, run verify.py against it as a subprocess, and
    assert on the exit code. Nothing is imported or stubbed."""

    def setUp(self):
        self.target = tempfile.mkdtemp(prefix="verify-e2e-")
        self.addCleanup(shutil.rmtree, self.target, ignore_errors=True)
        self.install()
        self.guard = os.path.join(self.target, "bin", "budget_guard.py")
        self.config = os.path.join(self.target, "budget-guard.config.json")

    def install(self, *extra):
        subprocess.run(
            [sys.executable, os.path.join(ROOT, "install.py"),
             "--target", self.target, *extra],
            capture_output=True, text=True, check=True)

    def run_verify(self, *extra):
        return subprocess.run(
            [sys.executable, os.path.join(ROOT, "verify.py"),
             "--target", self.target, *extra],
            capture_output=True, text=True, timeout=300)

    def mutate(self, old, new):
        with open(self.guard) as f:
            source = f.read()
        self.assertIn(old, source, "mutation target no longer exists in "
                                   "budget_guard.py; update this test")
        with open(self.guard, "w") as f:
            f.write(source.replace(old, new))

    def edit_config(self, **changes):
        with open(self.config) as f:
            config = json.load(f)
        config.update(changes)
        with open(self.config, "w") as f:
            json.dump(config, f)

    def assert_probe_failed(self, result, fragment):
        self.assertEqual(result.returncode, 1, result.stdout)
        lines = [l for l in result.stdout.splitlines()
                 if fragment in l and l.strip().startswith("FAIL")]
        self.assertTrue(lines, f"expected a FAIL mentioning {fragment!r}:\n"
                               f"{result.stdout}")

    # --- the healthy case ---

    def test_a_correct_install_passes_and_exits_zero(self):
        result = self.run_verify()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertNotIn("FAIL", result.stdout)
        for section in ("WIRING -- approval gate", "BEHAVIOR -- approval gate",
                        "WIRING -- budget guard", "BEHAVIOR -- budget guard"):
            self.assertIn(section, result.stdout)

    def test_probes_do_not_touch_real_spend_state(self):
        """The isolation guarantee. Budget probes book thousands of dollars of
        synthetic spend; none of it may land in the project's own rollup,
        because that rollup decides whether the next real call is blocked."""
        self.run_verify()
        state = os.path.join(self.target, ".budget-guard")
        leaked = [n for n in os.listdir(state) if n.startswith(("daily-", "loop-"))]
        self.assertEqual(leaked, [], f"probe state leaked into {state}")
        self.assertFalse(os.path.exists(
            os.path.join(self.target, "approvals", "budget-blocked.jsonl")))

    # --- broken guards must fail ---

    def test_catches_a_guard_that_double_counts_streamed_messages(self):
        self.mutate("costs[message_id] = (model, price_usage(model, usage, config))",
                    "costs[len(costs)] = (model, price_usage(model, usage, config))")
        self.assert_probe_failed(self.run_verify(), "streamed message")

    def test_catches_a_guard_that_bills_cache_reads_at_the_input_rate(self):
        self.mutate('* in_rate * mult["cache_read"]', "* in_rate * 1.0")
        self.assert_probe_failed(self.run_verify(), "cache reads priced")

    def test_catches_a_guard_that_prices_unknown_models_at_zero(self):
        self.mutate('    priciest = max(table.values(), key=lambda r: r["output"])\n'
                    '    return priciest["input"], priciest["output"]',
                    "    return 0.0, 0.0")
        self.assert_probe_failed(self.run_verify(), "unrecognised model")

    def test_catches_a_loop_window_that_silently_fails_to_persist(self):
        self.mutate('        with open(path, "w") as f:\n'
                    "            json.dump(history, f)\n"
                    "    except OSError:\n        pass",
                    "        raise OSError\n    except OSError:\n        pass")
        self.assert_probe_failed(self.run_verify(), "times in a row")

    def test_catches_a_guard_that_fails_closed_on_an_unreadable_transcript(self):
        self.mutate("        return None, 0.0, 0.0\n\n    session_cost",
                    '        return ("SESSION_BUDGET", "x"), 0.0, 0.0\n\n    session_cost')
        self.assert_probe_failed(self.run_verify(), "fails open")

    def test_catches_a_missing_hook_script(self):
        os.remove(self.guard)
        result = self.run_verify()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("FAIL", result.stdout)

    # --- the operator's config is theirs; skip, do not fail ---

    def test_uninstalled_budget_guard_skips_rather_than_fails(self):
        shutil.rmtree(self.target)
        os.makedirs(self.target)
        self.install("--no-budget-guard")
        result = self.run_verify()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("SKIP", result.stdout)
        self.assertNotIn("BEHAVIOR -- budget guard", result.stdout)

    def test_skip_budget_flag_omits_the_section(self):
        result = self.run_verify("--skip-budget")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertNotIn("budget guard", result.stdout)

    def test_disabled_loop_detector_skips_its_probes(self):
        self.edit_config(loop_detector={"enabled": False})
        result = self.run_verify()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("loop detector probes", result.stdout)

    def test_no_ceiling_configured_skips_the_cost_probes_and_warns(self):
        self.edit_config(session_cost_ceiling_usd=None, daily_cost_ceiling_usd=None)
        result = self.run_verify()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("WARN", result.stdout)
        self.assertIn("cost ceiling probes", result.stdout)

    def test_ignore_policy_skips_the_unknown_model_probe(self):
        self.edit_config(unknown_model_policy="ignore")
        result = self.run_verify()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("unknown_model_policy is 'ignore'", result.stdout)

    def test_a_non_default_cache_multiplier_is_probed_at_its_own_value(self):
        """The probe tests that the configured multiplier is applied, not that
        it equals 0.1 — otherwise anyone with contracted rates gets a spurious
        failure."""
        self.edit_config(cache_multipliers={"cache_read": 0.5,
                                            "cache_write_5m": 1.25,
                                            "cache_write_1h": 2.0})
        result = self.run_verify()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("configured 0.5x rate", result.stdout)


class HookMatcherTests(unittest.TestCase):
    """The matcher decides which tools ever reach the guard.

    These exist because the subagent-coverage procedure told operators to
    probe with "a file read", which on a narrowed matcher generates no hook
    call at all and reads as a harness bug that isn't there.
    """

    def setUp(self):
        self.target = tempfile.mkdtemp(prefix="verify-matcher-")
        self.addCleanup(shutil.rmtree, self.target, ignore_errors=True)
        os.makedirs(os.path.join(self.target, ".claude"))

    def write_entries(self, entries):
        path = os.path.join(self.target, ".claude", "settings.json")
        with open(path, "w") as f:
            json.dump({"hooks": {"PreToolUse": entries}}, f)

    def entry(self, command, matcher=None):
        e = {"hooks": [{"type": "command", "command": command}]}
        if matcher is not None:
            e["matcher"] = matcher
        return e

    def test_absent_matcher_key_means_everything(self):
        self.write_entries([self.entry("python3 /p/gate_guard.py")])
        self.assertEqual(verify.find_hook_matcher(self.target), "*")

    def test_narrowed_matcher_is_returned_verbatim(self):
        self.write_entries([
            self.entry("python3 /p/gate_guard.py", "Bash|Write|Edit")])
        self.assertEqual(
            verify.find_hook_matcher(self.target), "Bash|Write|Edit")

    def test_matcher_comes_from_the_entry_registering_this_guard(self):
        self.write_entries([
            self.entry("python3 /p/other_hook.py", "*"),
            self.entry("python3 /p/gate_guard.py", "Bash"),
        ])
        self.assertEqual(verify.find_hook_matcher(self.target), "Bash")

    def test_unreadable_settings_is_unknown_not_a_warning(self):
        self.assertIsNone(verify.find_hook_matcher(self.target))
        # Unknown must not fire the warning: noise on a healthy install.
        self.assertTrue(verify.matcher_covers_everything(None))

    def test_covers_everything(self):
        for m in ("*", "", "  ", None):
            self.assertTrue(verify.matcher_covers_everything(m), m)
        for m in ("Bash", "Bash|Write", "Edit|Write"):
            self.assertFalse(verify.matcher_covers_everything(m), m)


class SubagentRowMatcherTests(unittest.TestCase):
    UNPROVEN = {"identity": {"agents": {}, "subagent_coverage": "unproven"}}
    OBSERVED = {"identity": {
        "agents": {"agent_type=Explore": {"invocations": 3, "subagent": True}},
        "subagent_coverage": "observed"}}

    def test_narrowed_matcher_is_named_in_the_warning(self):
        status, _, detail = verify.subagent_row(self.UNPROVEN, "Bash|Write")
        self.assertEqual(status, verify.WARN)
        self.assertIn("Bash|Write", detail)

    def test_wildcard_matcher_adds_no_noise(self):
        _, _, detail = verify.subagent_row(self.UNPROVEN, "*")
        self.assertNotIn("matcher", detail)

    def test_unknown_matcher_adds_no_noise(self):
        _, _, detail = verify.subagent_row(self.UNPROVEN, None)
        self.assertNotIn("matcher", detail)

    def test_observed_still_passes_regardless_of_matcher(self):
        status, _, detail = verify.subagent_row(self.OBSERVED, "Bash")
        self.assertEqual(status, verify.PASS)
        self.assertIn("agent_type=Explore", detail)
        self.assertNotIn("matcher", detail)


class AllowlistRowTests(unittest.TestCase):
    """A present-but-empty allowlist blocks every push exactly as a missing
    one does. Reporting it PASS because the file exists is the failure this
    row is here to avoid."""

    NAME = "approved-remotes.txt"

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def row(self):
        return verify.allowlist_row(self.tmp, {})

    def write(self, text):
        with open(os.path.join(self.tmp, self.NAME), "w") as f:
            f.write(text)

    def test_missing_file_warns(self):
        status, _, detail = self.row()
        self.assertEqual(status, verify.WARN)
        self.assertIn("missing", detail)

    def test_populated_file_passes_with_a_count(self):
        self.write("# comment\ngithub.com/example-org/\n")
        status, _, detail = self.row()
        self.assertEqual(status, verify.PASS)
        self.assertIn("1 approved remote", detail)

    def test_comments_only_file_warns_rather_than_passing(self):
        self.write("# nothing approved yet\n\n")
        status, _, detail = self.row()
        self.assertEqual(status, verify.WARN)
        self.assertIn("0 remotes", detail)
        self.assertIn("same as if it were missing", detail)

    def test_a_directory_in_its_place_is_not_reported_as_missing(self):
        os.mkdir(os.path.join(self.tmp, self.NAME))
        status, _, detail = self.row()
        self.assertEqual(status, verify.WARN)
        self.assertIn("not a readable file", detail)

    def test_config_can_rename_the_allowlist(self):
        with open(os.path.join(self.tmp, "remotes.allow"), "w") as f:
            f.write("github.com/example-org/\n")
        status, _, detail = verify.allowlist_row(
            self.tmp, {"approved_remotes_file": "remotes.allow"})
        self.assertEqual(status, verify.PASS)
        self.assertIn("1 approved remote", detail)


class TrustTierRowTests(unittest.TestCase):
    """A state file with no trust-tier field in it behaves exactly like a
    missing one: the guard assumes 0 and every tier-gated rule blocks.
    Reporting `PASS ... trust tier 0` because the file parsed is the same
    failure AllowlistRowTests exists to prevent, one row up."""

    NAME = "STATE.json"

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.path = os.path.join(self.tmp, self.NAME)

    def row(self, config=None):
        return verify.trust_tier_row(self.path, self.NAME, config or {})

    def write(self, text):
        with open(self.path, "w") as f:
            f.write(text)

    def test_missing_state_file_warns_and_says_it_was_assumed(self):
        status, _, detail = self.row()
        self.assertEqual(status, verify.WARN)
        self.assertIn("not found", detail)
        self.assertIn("ASSUMED", detail)
        self.assertIn("plugin install", detail)

    def test_a_real_tier_zero_passes(self):
        self.write(json.dumps({"trust_tier": 0}))
        status, _, detail = self.row()
        self.assertEqual(status, verify.PASS)
        self.assertIn("trust tier 0", detail)
        self.assertIn("tier-gated rules are ON", detail)

    def test_missing_field_warns_rather_than_passing_as_tier_zero(self):
        self.write(json.dumps({"phase": "build"}))
        status, _, detail = self.row()
        self.assertEqual(status, verify.WARN)
        self.assertIn("no trust-tier field", detail)
        self.assertNotIn("trust tier 0", detail)

    def test_malformed_json_warns_without_claiming_the_file_is_absent(self):
        self.write("{not json,")
        status, _, detail = self.row()
        self.assertEqual(status, verify.WARN)
        self.assertIn("invalid JSON", detail)
        self.assertNotIn("not found", detail)

    def test_a_quoted_tier_does_not_read_as_a_granted_tier(self):
        self.write(json.dumps({"trust_tier": "1"}))
        status, _, detail = self.row()
        self.assertEqual(status, verify.WARN)
        self.assertIn("not an integer", detail)

    def test_a_tier_above_the_threshold_says_the_rules_are_off(self):
        self.write(json.dumps({"trust_tier": 2}))
        status, _, detail = self.row()
        self.assertEqual(status, verify.PASS)
        self.assertIn("tier-gated rules are OFF", detail)

    def test_config_can_rename_the_tier_field(self):
        self.write(json.dumps({"tier": 1}))
        status, _, detail = self.row({"trust_tier_field": "tier"})
        self.assertEqual(status, verify.PASS)
        self.assertIn("trust tier 1", detail)

    def test_read_trust_tier_matches_the_guards_fallback(self):
        """Whatever the state, the number handed to the probe logic is the
        same 0 the guard would use -- the row's job is the label, not the
        behaviour."""
        for content in (None, "{not json,", "[]", '{"phase":"x"}',
                        '{"trust_tier":"1"}'):
            if content is None:
                if os.path.exists(self.path):
                    os.remove(self.path)
            else:
                self.write(content)
            state, tier, _detail = verify.read_trust_tier(self.path, {})
            self.assertEqual(tier, 0, content)
            self.assertNotEqual(state, verify.TIER_OK, content)


if __name__ == "__main__":
    unittest.main(verbosity=2)
