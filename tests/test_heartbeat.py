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


class SubagentCoverageTests(unittest.TestCase):
    """Who the harness routes through the hook.

    The claim these protect against is the tempting one: "no agent marker in
    the payload, therefore the main session made the call, therefore subagents
    are covered too." That inference is invalid -- a harness that fires the
    hook for subagents without labelling them produces an identical payload,
    and so does a harness that never fires it for subagents at all. Only a
    positive marker proves coverage, so the tests below assert on BOTH sides:
    that a marker is recorded when present, and that its absence is reported
    as unproven rather than resolved either way.
    """

    def test_an_unmarked_call_is_unattributed_not_main_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = project(tmp)
            invoke(tmp, config_path, bash("ls"))
            identity = read_heartbeat(tmp)["identity"]
            self.assertEqual(identity["subagent_coverage"], "unproven")
            self.assertEqual(list(identity["agents"]), ["unattributed"])
            self.assertFalse(identity["agents"]["unattributed"]["subagent"])

    def test_a_subagent_marker_is_recorded_and_proves_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = project(tmp)
            payload = dict(bash("ls"), agent_type="builder",
                           session_id="s-1", permission_mode="default")
            invoke(tmp, config_path, payload)
            identity = read_heartbeat(tmp)["identity"]
            self.assertEqual(identity["subagent_coverage"], "observed")
            self.assertIn("agent_type=builder", identity["agents"])
            self.assertTrue(identity["agents"]["agent_type=builder"]["subagent"])
            self.assertIn("permission_mode", identity["identity_keys_seen"])
            self.assertIn("agent_type", identity["payload_keys_seen"])

    def test_coverage_survives_later_unmarked_calls(self):
        # Cumulative by design: the question is "has this EVER happened", so a
        # main-session call after a subagent call must not erase the evidence.
        with tempfile.TemporaryDirectory() as tmp:
            config_path = project(tmp)
            invoke(tmp, config_path, dict(bash("ls"), agent_type="builder"))
            for _ in range(2):
                invoke(tmp, config_path, bash("ls"))
            identity = read_heartbeat(tmp)["identity"]
            self.assertEqual(identity["subagent_coverage"], "observed")
            self.assertEqual(identity["agents"]["unattributed"]["invocations"], 2)
            self.assertEqual(
                identity["agents"]["agent_type=builder"]["invocations"], 1)

    def test_per_agent_blocks_are_counted(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = project(tmp)
            payload = dict(bash(_FUND_MOVE), agent_type="marketer")
            self.assertEqual(invoke(tmp, config_path, payload), 2)
            row = read_heartbeat(tmp)["identity"]["agents"]["agent_type=marketer"]
            self.assertEqual(row["blocks"], 1)
            self.assertEqual(row["invocations"], 1)

    def test_probes_do_not_invent_a_caller(self):
        # Same reasoning as probe isolation for the counters: verify.py can
        # send any payload it likes, so a probe must never be able to make
        # subagent coverage look proven.
        with tempfile.TemporaryDirectory() as tmp:
            config_path = project(tmp)
            invoke(tmp, config_path, dict(bash("ls"), agent_type="builder"),
                   probe=True)
            identity = read_heartbeat(tmp)["identity"]
            self.assertEqual(identity["agents"], {})
            self.assertEqual(identity["subagent_coverage"], "unproven")

    def test_permission_mode_is_accumulated(self):
        # A bypassPermissions call reaching the hook is the single most
        # load-bearing thing a user can learn about their own setup.
        with tempfile.TemporaryDirectory() as tmp:
            config_path = project(tmp)
            invoke(tmp, config_path, dict(bash("ls"), permission_mode="default"))
            invoke(tmp, config_path,
                   dict(bash("ls"), permission_mode="bypassPermissions"))
            modes = read_heartbeat(tmp)["identity"]["permission_modes_seen"]
            self.assertEqual(modes, ["bypassPermissions", "default"])

    def test_hostile_marker_cannot_corrupt_the_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = project(tmp)
            invoke(tmp, config_path,
                   dict(bash("ls"), agent_type="a" * 400 + "\n/etc/passwd"))
            identity = read_heartbeat(tmp)["identity"]
            bucket = [k for k in identity["agents"] if k != "unattributed"][0]
            self.assertLessEqual(len(bucket), len("agent_type=") + 48)
            self.assertNotIn("/", bucket)

    def test_agent_buckets_are_capped(self):
        # A harness minting a fresh agent id per call must not be able to grow
        # this file without bound.
        with tempfile.TemporaryDirectory() as tmp:
            config_path = project(tmp)
            for i in range(30):
                invoke(tmp, config_path, dict(bash("ls"), agent_id=f"a{i}"))
            agents = read_heartbeat(tmp)["identity"]["agents"]
            self.assertLessEqual(len(agents), 25)
            self.assertIn("other", agents)
            self.assertEqual(agents["other"]["invocations"], 6)

    def test_live_reports_unproven_with_guidance_but_still_passes(self):
        # A fresh install has never seen a subagent. That is not a wiring
        # fault, and failing the check for it would train people to ignore the
        # lines here that ARE wiring faults.
        with tempfile.TemporaryDirectory() as tmp:
            project(tmp)
            write_heartbeat(tmp, identity={
                "agents": {"unattributed": {"invocations": 4, "blocks": 1,
                                            "subagent": False}},
                "subagent_coverage": "unproven",
            })
            code, out = live(tmp)
            self.assertEqual(code, 0)
            self.assertIn("subagent coverage", out)
            self.assertIn("unproven", out)
            self.assertIn("do not delegate", out)

    def test_live_names_an_observed_subagent(self):
        with tempfile.TemporaryDirectory() as tmp:
            project(tmp)
            write_heartbeat(tmp, identity={
                "agents": {"agent_type=builder": {"invocations": 3, "blocks": 0,
                                                  "subagent": True}},
                "subagent_coverage": "observed",
            })
            code, out = live(tmp)
            self.assertEqual(code, 0)
            self.assertIn("observed: agent_type=builder (3 calls)", out)
            self.assertNotIn("do not delegate", out)

    def test_live_tolerates_a_heartbeat_written_before_this_feature(self):
        with tempfile.TemporaryDirectory() as tmp:
            project(tmp)
            write_heartbeat(tmp)  # no identity block at all
            code, out = live(tmp)
            self.assertEqual(code, 0)
            self.assertIn("guard predates identity tracking", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
