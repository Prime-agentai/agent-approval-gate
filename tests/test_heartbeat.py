#!/usr/bin/env python3
"""
Tests for the liveness heartbeat: gate_guard.py's record_heartbeat() and
verify.py --live.

Run: python3 tests/test_heartbeat.py

What this feature is for, and therefore what these tests have to protect:

A PreToolUse hook that is registered but never invoked is indistinguishable,
from inside a session, from one that is invoked and allows everything. The
heartbeat is the only evidence that separates them, so the tests that matter
most here are the ones asserting `--live` FAILS -- when nothing ran, when only
verify.py's own probes ran, when the run is stale, and when the harness turns
out to be executing a different copy of the guard than the one in settings.json.
A liveness check that passes on an inert hook is worse than none, because it
converts an unknown into a false certainty.

The probe-isolation test is the subtle one. verify.py drives the hook command
directly, which necessarily invokes gate_guard.py. If those invocations counted
as harness activity, running verify.py would satisfy the liveness check it is
supposed to be performing, and `--live` would only ever confirm its own probes.
GATE_GUARD_PROBE keeps the two apart; `test_probe_does_not_count_as_liveness`
is what stops that separation from silently regressing.

Fixture strings are concatenated from fragments for the same reason the other
suites do it: a strict content-scanning guard pointed at this repository would
otherwise match the fixtures themselves.
"""

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import verify  # noqa: E402

GUARD = os.path.join(ROOT, "gate_guard.py")
HEARTBEAT = os.path.join("approvals", "heartbeat.json")

_FUND_MOVE = "solana transfer --amount 5 " + "usd" + "c --to acct"


def project(tmp, config_overrides=None, guard_path=GUARD):
    """Lay out a minimal project the way install.py would: a settings.json
    registering the hook, a config beside it, and a state file."""
    os.makedirs(os.path.join(tmp, ".claude"), exist_ok=True)
    config = {"state_path": "STATE.json"}
    config.update(config_overrides or {})
    config_path = os.path.join(tmp, "gate-guard.config.json")
    with open(config_path, "w") as f:
        json.dump(config, f)
    with open(os.path.join(tmp, "STATE.json"), "w") as f:
        json.dump({"trust_tier": 0}, f)
    command = f'env GATE_GUARD_CONFIG="{config_path}" python3 "{guard_path}"'
    with open(os.path.join(tmp, ".claude", "settings.json"), "w") as f:
        json.dump({"hooks": {"PreToolUse": [
            {"matcher": "*", "hooks": [{"type": "command", "command": command}]}
        ]}}, f)
    return config_path


def invoke(tmp, config_path, payload, probe=False):
    """Run the guard exactly as the registered hook command would."""
    env = dict(os.environ, GATE_GUARD_CONFIG=config_path)
    if probe:
        env["GATE_GUARD_PROBE"] = "1"
    proc = subprocess.run(
        [sys.executable, GUARD], input=json.dumps(payload),
        capture_output=True, text=True, cwd=tmp, env=env, timeout=60,
    )
    return proc.returncode


def bash(command):
    return {"tool_name": "Bash", "tool_input": {"command": command}}


def read_heartbeat(tmp):
    with open(os.path.join(tmp, HEARTBEAT)) as f:
        return json.load(f)


def write_heartbeat(tmp, **fields):
    """A heartbeat as gate_guard.py would have left it, with fields overridden
    so `--live` can be pointed at a specific situation."""
    entry = {
        "schema": 1,
        "first_invocation": datetime.now(timezone.utc).isoformat(),
        "last_invocation": datetime.now(timezone.utc).isoformat(),
        "invocations": 4,
        "probe_invocations": 0,
        "blocks": 1,
        "last_tool": "Bash",
        "last_decision": "allow",
        "last_rule": None,
        "guard_path": GUARD,
        "config_path": os.path.join(tmp, "gate-guard.config.json"),
        "guard_mtime": datetime.fromtimestamp(
            os.path.getmtime(GUARD), timezone.utc).isoformat(),
    }
    entry.update(fields)
    path = os.path.join(tmp, HEARTBEAT)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(entry, f)
    return entry


def live(tmp, max_age_hours=24.0):
    """Run check_live, returning (exit_code, printed_output)."""
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = verify.check_live(os.path.abspath(tmp), max_age_hours)
    return code, buf.getvalue()


class RecordHeartbeatTests(unittest.TestCase):
    def test_allowed_call_still_leaves_evidence(self):
        # The whole point: an allow is the case with no other trace anywhere.
        with tempfile.TemporaryDirectory() as tmp:
            config_path = project(tmp)
            self.assertEqual(invoke(tmp, config_path, bash("ls -la")), 0)
            hb = read_heartbeat(tmp)
            self.assertEqual(hb["invocations"], 1)
            self.assertEqual(hb["blocks"], 0)
            self.assertEqual(hb["last_tool"], "Bash")
            self.assertEqual(hb["last_decision"], "allow")
            self.assertIsNone(hb["last_rule"])

    def test_block_is_counted_and_named(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = project(tmp)
            self.assertEqual(invoke(tmp, config_path, bash(_FUND_MOVE)), 2)
            hb = read_heartbeat(tmp)
            self.assertEqual(hb["invocations"], 1)
            self.assertEqual(hb["blocks"], 1)
            self.assertEqual(hb["last_decision"], "block")
            self.assertEqual(hb["last_rule"], "FUND_MOVEMENT")

    def test_counters_accumulate_across_invocations(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = project(tmp)
            for _ in range(3):
                invoke(tmp, config_path, bash("ls"))
            invoke(tmp, config_path, bash(_FUND_MOVE))
            hb = read_heartbeat(tmp)
            self.assertEqual(hb["invocations"], 4)
            self.assertEqual(hb["blocks"], 1)
            self.assertEqual(hb["first_invocation"] < hb["last_invocation"], True)

    def test_probe_does_not_count_as_liveness(self):
        # verify.py's probes prove the script runs. They must not be able to
        # answer the question "is the harness calling it", or --live would be
        # confirming its own work.
        with tempfile.TemporaryDirectory() as tmp:
            config_path = project(tmp)
            invoke(tmp, config_path, bash("ls"))
            first = read_heartbeat(tmp)

            invoke(tmp, config_path, bash(_FUND_MOVE), probe=True)
            after = read_heartbeat(tmp)

            self.assertEqual(after["invocations"], 1)
            self.assertEqual(after["probe_invocations"], 1)
            self.assertEqual(after["last_invocation"], first["last_invocation"])
            self.assertEqual(after["last_decision"], "allow")
            self.assertIsNotNone(after["last_probe_invocation"])
            # A probed block is still a block that happened, and the audit
            # trail should say so.
            self.assertEqual(after["blocks"], 1)

    def test_records_which_copy_ran_and_which_config_it_loaded(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = project(tmp)
            invoke(tmp, config_path, bash("ls"))
            hb = read_heartbeat(tmp)
            self.assertEqual(os.path.realpath(hb["guard_path"]),
                             os.path.realpath(GUARD))
            self.assertEqual(os.path.realpath(hb["config_path"]),
                             os.path.realpath(config_path))

    def test_empty_path_disables_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = project(tmp, {"heartbeat_path": ""})
            self.assertEqual(invoke(tmp, config_path, bash("ls")), 0)
            self.assertFalse(os.path.exists(os.path.join(tmp, HEARTBEAT)))

    def test_unwritable_heartbeat_never_turns_a_block_into_an_allow(self):
        # Bookkeeping that can raise is a guard that can fail open. Point the
        # heartbeat at a path that cannot be created and assert the decision
        # is unchanged in both directions.
        with tempfile.TemporaryDirectory() as tmp:
            blocker = os.path.join(tmp, "notadir")
            with open(blocker, "w") as f:
                f.write("")
            config_path = project(tmp, {"heartbeat_path": "notadir/hb.json"})
            self.assertEqual(invoke(tmp, config_path, bash(_FUND_MOVE)), 2)
            self.assertEqual(invoke(tmp, config_path, bash("ls")), 0)

    def test_corrupt_heartbeat_is_replaced_not_fatal(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = project(tmp)
            path = os.path.join(tmp, HEARTBEAT)
            os.makedirs(os.path.dirname(path))
            with open(path, "w") as f:
                f.write("{ this is not json")
            self.assertEqual(invoke(tmp, config_path, bash("ls")), 0)
            self.assertEqual(read_heartbeat(tmp)["invocations"], 1)


class CheckLiveTests(unittest.TestCase):
    def test_fails_when_no_hook_is_registered(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out = live(tmp)
            self.assertEqual(code, 1)
            self.assertIn("FAIL", out)

    def test_fails_when_the_hook_has_never_run(self):
        # Registered, correct, and completely inert. This is the failure the
        # feature exists for, so it is the one that must not report PASS.
        with tempfile.TemporaryDirectory() as tmp:
            project(tmp)
            code, out = live(tmp)
            self.assertEqual(code, 1)
            self.assertIn("no evidence it has ever run", out)

    def test_fails_when_only_probes_have_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = project(tmp)
            invoke(tmp, config_path, bash("ls"), probe=True)
            code, out = live(tmp)
            self.assertEqual(code, 1)
            self.assertIn("probe invocation", out)

    def test_passes_on_a_fresh_consistent_heartbeat(self):
        with tempfile.TemporaryDirectory() as tmp:
            project(tmp)
            write_heartbeat(tmp)
            code, out = live(tmp)
            self.assertEqual(code, 0)
            self.assertNotIn("FAIL", out)
            self.assertIn("The harness is calling the guard", out)

    def test_end_to_end_a_real_invocation_satisfies_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = project(tmp)
            invoke(tmp, config_path, bash("ls"))
            code, _ = live(tmp)
            self.assertEqual(code, 0)

    def test_stale_heartbeat_is_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            project(tmp)
            old = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
            write_heartbeat(tmp, last_invocation=old)
            code, out = live(tmp)
            self.assertEqual(code, 1)
            self.assertIn("older than", out)

    def test_max_age_is_configurable(self):
        with tempfile.TemporaryDirectory() as tmp:
            project(tmp)
            old = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
            write_heartbeat(tmp, last_invocation=old)
            self.assertEqual(live(tmp, max_age_hours=72.0)[0], 0)

    def test_detects_the_harness_running_a_different_copy(self):
        # The confusing one in the wild: rules edited here, a stale copy
        # enforcing there, and every symptom reads as "my change did nothing".
        with tempfile.TemporaryDirectory() as tmp:
            project(tmp)
            write_heartbeat(tmp, guard_path="/somewhere/else/gate_guard.py")
            code, out = live(tmp)
            self.assertEqual(code, 1)
            self.assertIn("FAIL", out)
            self.assertIn("/somewhere/else/gate_guard.py", out)

    def test_detects_a_different_config_being_loaded(self):
        with tempfile.TemporaryDirectory() as tmp:
            project(tmp)
            write_heartbeat(tmp, config_path="/somewhere/else/gate-guard.config.json")
            code, out = live(tmp)
            self.assertEqual(code, 1)
            self.assertIn("the config it loaded", out)

    def test_flags_a_guard_edited_since_it_last_ran(self):
        with tempfile.TemporaryDirectory() as tmp:
            project(tmp)
            stale = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
            write_heartbeat(tmp, guard_mtime=stale)
            code, out = live(tmp)
            self.assertEqual(code, 1)
            self.assertIn("restart the session", out)

    def test_disabled_heartbeat_is_reported_not_passed(self):
        with tempfile.TemporaryDirectory() as tmp:
            project(tmp, {"heartbeat_path": ""})
            code, out = live(tmp)
            self.assertEqual(code, 1)
            self.assertIn("disabled", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
