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
        # The recorded mtime is offset from the guard's ACTUAL mtime, not from
        # now. Anchoring it to now made this a time bomb: it asserts that the
        # file on disk is newer than the heartbeat says, which was only true
        # while the checkout itself was under two days old. A contributor with
        # an older working copy saw this one test fail for no reason they
        # could act on -- and our own copy started failing at exactly the
        # 48-hour mark.
        with tempfile.TemporaryDirectory() as tmp:
            project(tmp)
            on_disk = datetime.fromtimestamp(os.path.getmtime(GUARD), timezone.utc)
            write_heartbeat(tmp, guard_mtime=(on_disk - timedelta(days=2)).isoformat())
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


class EvidenceReportTests(unittest.TestCase):
    """verify.py --evidence.

    --live is read by the person who just changed something; --evidence is
    read by someone who was not there, possibly months later, possibly
    adversarially. That difference sets what these tests protect:

      * It must never claim an operating control it cannot evidence. The
        first three tests here are the ones that matter -- a report that says
        ACTIVE for a hook which never ran would be worse than no report,
        because it converts "unknown" into a documented false assurance.
      * The Markdown and the JSON are two renderings of one gather. If they
        can disagree about a number, the artifact is not evidence of
        anything, so they are asserted against each other.
      * Probe blocks -- the ones verify.py writes itself -- must never be
        counted as enforcement events. Otherwise running the verifier inflates
        the evidence the verifier produces.
      * The limits section is load-bearing content, not boilerplate, and is
        asserted present. An artifact that drops its own caveats while
        keeping its numbers is the failure mode worth a test.
    """

    def report(self, tmp, **kw):
        return verify.evidence_report(os.path.abspath(tmp),
                                      kw.pop("max_age_hours", 24.0), **kw)

    def test_never_claims_active_when_the_hook_never_ran(self):
        with tempfile.TemporaryDirectory() as tmp:
            project(tmp)  # no heartbeat at all
            report = self.report(tmp)
            self.assertFalse(report["body"]["status"]["control_active"])
            self.assertEqual(report["body"]["status"]["reason"], "never-ran")
            md = verify.render_evidence_markdown(report)
            self.assertIn("NOT ESTABLISHED", md)
            self.assertNotIn("| Control status at report time | **ACTIVE** |", md)

    def test_a_missing_heartbeat_does_not_report_zero_blocks(self):
        # Found by running --evidence against a real project: the summary read
        # "Calls blocked by the gate | 0" while section 4 of the same report
        # listed 224 blocks, the most recent four minutes earlier. Both
        # counters live in the heartbeat, and there wasn't one -- so 0 was the
        # default, not a measurement. A reader who stops after section 1, which
        # is what a summary is for, walks away with a false sentence.
        with tempfile.TemporaryDirectory() as tmp:
            project(tmp)  # deliberately no heartbeat
            log = os.path.join(tmp, "approvals", "blocked.jsonl")
            os.makedirs(os.path.dirname(log), exist_ok=True)
            now = datetime.now(timezone.utc).isoformat()
            with open(log, "w") as f:
                for _ in range(3):
                    f.write(json.dumps({"ts": now, "rule": "FUND_MOVEMENT",
                                        "tool": "Bash",
                                        "attempted": _FUND_MOVE}) + "\n")
            body = self.report(tmp)["body"]
            self.assertFalse(body["activity"]["counters_known"])
            # null, not 0 -- a consumer testing `== 0` must not read "never
            # fired" out of "never measured".
            self.assertIsNone(body["activity"]["blocks_recorded_by_guard"])
            self.assertIsNone(body["activity"]["harness_invocations"])

            md = verify.render_evidence_markdown(self.report(tmp))
            self.assertNotIn("| Calls blocked by the gate | 0 |", md)
            self.assertNotIn(
                "| Tool calls the harness routed through the gate | 0 |", md)
            # and it sends the reader to the records that do exist
            self.assertIn("3 record(s) in the block log", md)

    def test_a_present_heartbeat_still_reports_a_true_zero(self):
        # The guard against overcorrecting the test above. A heartbeat that has
        # been written and says zero blocks is a measurement, and "0" is the
        # honest rendering of it. Only an absent counter becomes "unknown".
        with tempfile.TemporaryDirectory() as tmp:
            project(tmp)
            write_heartbeat(tmp, blocks=0)
            body = self.report(tmp)["body"]
            self.assertTrue(body["activity"]["counters_known"])
            self.assertEqual(body["activity"]["blocks_recorded_by_guard"], 0)
            md = verify.render_evidence_markdown(self.report(tmp))
            self.assertIn("| Calls blocked by the gate | 0 |", md)

    def test_with_neither_source_the_report_claims_nothing(self):
        # Section 4's no-log branch used to reassure the reader that "section
        # 1's block count still stands". With no heartbeat either, that sent
        # them back to a number which is itself unknown -- two absences reading
        # as if they corroborated each other.
        with tempfile.TemporaryDirectory() as tmp:
            project(tmp)
            log = os.path.join(tmp, "approvals", "blocked.jsonl")
            if os.path.exists(log):
                os.remove(log)
            md = verify.render_evidence_markdown(self.report(tmp))
            self.assertNotIn("section 1's block count still stands", md)
            self.assertIn("can say nothing about whether the gate has ever "
                          "blocked anything", md)

    def test_no_discrepancy_note_when_there_is_only_one_source(self):
        # The discrepancy note compares the heartbeat counter against the log.
        # With no heartbeat there is one source, not two, and reporting a
        # conflict would manufacture one out of a missing file.
        with tempfile.TemporaryDirectory() as tmp:
            project(tmp)
            log = os.path.join(tmp, "approvals", "blocked.jsonl")
            os.makedirs(os.path.dirname(log), exist_ok=True)
            with open(log, "w") as f:
                f.write(json.dumps(
                    {"ts": datetime.now(timezone.utc).isoformat(),
                     "rule": "FUND_MOVEMENT", "tool": "Bash",
                     "attempted": _FUND_MOVE}) + "\n")
            md = verify.render_evidence_markdown(self.report(tmp))
            self.assertNotIn("Note a discrepancy", md)

    def test_never_claims_active_on_probe_invocations_alone(self):
        # verify.py's own probes prove the script runs and prove nothing about
        # the harness. An artifact built only from them evidences nothing.
        with tempfile.TemporaryDirectory() as tmp:
            project(tmp)
            write_heartbeat(tmp, invocations=0, probe_invocations=9,
                            last_invocation=None)
            report = self.report(tmp)
            self.assertFalse(report["body"]["status"]["control_active"])
            self.assertEqual(report["body"]["status"]["reason"], "never-ran")

    def test_never_claims_active_when_a_different_copy_ran(self):
        with tempfile.TemporaryDirectory() as tmp:
            project(tmp)
            write_heartbeat(tmp, guard_path="/somewhere/else/gate_guard.py")
            report = self.report(tmp)
            self.assertFalse(report["body"]["status"]["control_active"])
            self.assertTrue(report["body"]["status"]["checks_failed"])

    def test_reports_active_on_a_healthy_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            project(tmp)
            write_heartbeat(tmp)
            report = self.report(tmp)
            self.assertTrue(report["body"]["status"]["control_active"])
            self.assertEqual(report["body"]["activity"]["harness_invocations"], 4)
            md = verify.render_evidence_markdown(report)
            self.assertIn("**ACTIVE**", md)

    def test_window_is_the_recorded_span_not_the_report_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            project(tmp)
            first = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
            write_heartbeat(tmp, first_invocation=first)
            body = self.report(tmp)["body"]
            self.assertEqual(body["window"]["first_invocation"], first)
            self.assertGreater(body["window"]["seconds"], 29 * 86400)
            self.assertIn("days", body["window"]["human"])

    def test_markdown_and_json_cannot_disagree(self):
        with tempfile.TemporaryDirectory() as tmp:
            project(tmp)
            write_heartbeat(tmp, invocations=1234, blocks=7)
            report = self.report(tmp)
            md = verify.render_evidence_markdown(report)
            self.assertEqual(report["body"]["activity"]["harness_invocations"], 1234)
            self.assertIn("1,234", md)
            self.assertIn("| Calls blocked by the gate | 7 |", md)

    def test_digest_is_reproducible_and_covers_the_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            project(tmp)
            write_heartbeat(tmp)
            report = self.report(tmp)
            body = dict(report["body"])
            canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
            import hashlib
            self.assertEqual(
                report["digest"],
                "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest())
            body["activity"] = dict(body["activity"], harness_invocations=999999)
            tampered = json.dumps(body, sort_keys=True, separators=(",", ":"))
            self.assertNotEqual(
                report["digest"],
                "sha256:" + hashlib.sha256(tampered.encode("utf-8")).hexdigest())

    def test_probe_blocks_are_excluded_from_enforcement_events(self):
        # Running the verifier must not inflate the evidence it produces.
        with tempfile.TemporaryDirectory() as tmp:
            project(tmp)
            write_heartbeat(tmp)
            log = os.path.join(tmp, "approvals", "blocked.jsonl")
            now = datetime.now(timezone.utc).isoformat()
            with open(log, "w") as f:
                f.write(json.dumps({"ts": now, "rule": "FUND_MOVEMENT",
                                    "tool": "Bash", "attempted": _FUND_MOVE,
                                    "trust_tier_at_block": 0}) + "\n")
                f.write(json.dumps({"ts": now, "rule": "FUND_MOVEMENT",
                                    "tool": "Bash",
                                    "attempted": _FUND_MOVE + "  # gate-verify-probe",
                                    "trust_tier_at_block": 0}) + "\n")
            e = self.report(tmp)["body"]["enforcement"]
            self.assertEqual(e["lines"], 2)
            self.assertEqual(e["probes"], 1)
            self.assertEqual(e["in_window"], 1)
            self.assertEqual(e["by_rule"], {"FUND_MOVEMENT": 1})

    def test_blocked_command_text_is_held_back_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            project(tmp)
            write_heartbeat(tmp)
            log = os.path.join(tmp, "approvals", "blocked.jsonl")
            with open(log, "w") as f:
                f.write(json.dumps({"ts": datetime.now(timezone.utc).isoformat(),
                                    "rule": "FUND_MOVEMENT", "tool": "Bash",
                                    "attempted": _FUND_MOVE}) + "\n")
            md = verify.render_evidence_markdown(self.report(tmp))
            self.assertNotIn(_FUND_MOVE, md)
            self.assertIn("FUND_MOVEMENT", md)

            md2 = verify.render_evidence_markdown(
                self.report(tmp, include_attempts=True))
            self.assertIn(_FUND_MOVE, md2)

    def test_events_before_the_window_are_excluded_not_silently_dropped(self):
        with tempfile.TemporaryDirectory() as tmp:
            project(tmp)
            first = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
            write_heartbeat(tmp, first_invocation=first)
            old = (datetime.now(timezone.utc) - timedelta(days=40)).isoformat()
            log = os.path.join(tmp, "approvals", "blocked.jsonl")
            with open(log, "w") as f:
                f.write(json.dumps({"ts": old, "rule": "SPEND",
                                    "tool": "Bash", "attempted": "x"}) + "\n")
            e = self.report(tmp)["body"]["enforcement"]
            self.assertEqual(e["in_window"], 0)
            self.assertEqual(e["before_window"], 1)
            md = verify.render_evidence_markdown(self.report(tmp))
            self.assertIn("predating this window", md)

    def test_blocks_are_unattributed_when_no_window_could_be_established(self):
        # The report must not present a tally that reads like enforcement
        # history when section 2 could not evidence the control ran at all.
        with tempfile.TemporaryDirectory() as tmp:
            project(tmp)  # no heartbeat -> no window
            log = os.path.join(tmp, "approvals", "blocked.jsonl")
            os.makedirs(os.path.dirname(log), exist_ok=True)
            with open(log, "w") as f:
                f.write(json.dumps({"ts": datetime.now(timezone.utc).isoformat(),
                                    "rule": "SPEND", "tool": "Bash",
                                    "attempted": "x"}) + "\n")
            report = self.report(tmp)
            self.assertFalse(report["body"]["status"]["control_active"])
            self.assertFalse(report["body"]["enforcement"]["window_known"])
            md = verify.render_evidence_markdown(report)
            self.assertIn("UNATTRIBUTED", md)
            self.assertIn("not attributed to an operating period", md)
            self.assertNotIn("fired in the window", md)

    def test_a_malformed_log_line_is_counted_not_fatal(self):
        with tempfile.TemporaryDirectory() as tmp:
            project(tmp)
            write_heartbeat(tmp)
            log = os.path.join(tmp, "approvals", "blocked.jsonl")
            with open(log, "w") as f:
                f.write("{not json\n")
                f.write(json.dumps({"ts": datetime.now(timezone.utc).isoformat(),
                                    "rule": "SPEND", "tool": "Bash",
                                    "attempted": "x"}) + "\n")
            e = self.report(tmp)["body"]["enforcement"]
            self.assertEqual(e["malformed"], 1)
            self.assertEqual(e["in_window"], 1)

    def test_a_missing_block_log_is_reported_not_treated_as_zero_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            project(tmp)
            write_heartbeat(tmp, blocks=3)
            md = verify.render_evidence_markdown(self.report(tmp))
            self.assertIn("No blocked-action log", md)
            self.assertIn("| Calls blocked by the gate | 3 |", md)

    def test_counter_and_log_disagreement_is_surfaced(self):
        with tempfile.TemporaryDirectory() as tmp:
            project(tmp)
            write_heartbeat(tmp, blocks=5)
            log = os.path.join(tmp, "approvals", "blocked.jsonl")
            with open(log, "w") as f:
                f.write(json.dumps({"ts": datetime.now(timezone.utc).isoformat(),
                                    "rule": "SPEND", "tool": "Bash",
                                    "attempted": "x"}) + "\n")
            md = verify.render_evidence_markdown(self.report(tmp))
            self.assertIn("discrepancy", md)

    def test_the_limits_section_is_present_and_not_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            project(tmp)
            write_heartbeat(tmp)
            report = self.report(tmp)
            self.assertGreaterEqual(len(report["body"]["limits"]), 5)
            md = verify.render_evidence_markdown(report)
            self.assertIn("What this evidence does not prove", md)
            self.assertIn("lower bound", md)
            self.assertIn("not tamper-proof", md)

    def test_records_the_digest_of_the_guard_that_actually_ran(self):
        with tempfile.TemporaryDirectory() as tmp:
            project(tmp)
            write_heartbeat(tmp)
            artifacts = self.report(tmp)["body"]["artifacts"]
            ran = artifacts["guard_that_ran"]
            self.assertTrue(ran["present"])
            self.assertTrue(ran["sha256"].startswith("sha256:"))
            self.assertEqual(ran["sha256"], verify.sha256_file(GUARD))
            self.assertEqual(ran["bytes"], os.path.getsize(GUARD))

    def test_subagent_coverage_is_carried_into_the_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            project(tmp)
            write_heartbeat(tmp, identity={
                "subagent_coverage": "observed",
                "permission_modes_seen": ["default", "bypassPermissions"],
                "agents": {"researcher": {"invocations": 3, "blocks": 1,
                                          "subagent": True,
                                          "first_seen": "2026-01-01T00:00:00+00:00",
                                          "last_seen": "2026-01-02T00:00:00+00:00"}}})
            body = self.report(tmp)["body"]
            self.assertEqual(body["activity"]["subagent_coverage"], "observed")
            self.assertTrue(body["activity"]["callers_seen"]["researcher"]["subagent"])
            md = verify.render_evidence_markdown(self.report(tmp))
            self.assertIn("bypassPermissions", md)
            self.assertIn("researcher", md)

    def test_unproven_subagent_coverage_is_never_rendered_as_proven(self):
        with tempfile.TemporaryDirectory() as tmp:
            project(tmp)
            write_heartbeat(tmp)  # no identity block
            body = self.report(tmp)["body"]
            self.assertEqual(body["activity"]["subagent_coverage"], "unproven")
            md = verify.render_evidence_markdown(self.report(tmp))
            self.assertIn("| Subagent coverage | unproven |", md)
            # The one place the phrase may appear is section 5, explaining why
            # the report refuses to make that claim.
            self.assertNotIn("main session only", md.split("## 5.")[0])

    def test_cli_writes_a_file_and_exit_code_carries_the_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            project(tmp)
            write_heartbeat(tmp)
            out = os.path.join(tmp, "out", "evidence.md")
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = verify.check_evidence(os.path.abspath(tmp), 24.0,
                                             "md", out, False)
            self.assertEqual(code, 0)
            self.assertTrue(os.path.isfile(out))
            with open(out) as f:
                self.assertIn("# Gate enforcement evidence", f.read())
            self.assertIn("digest sha256:", buf.getvalue())

    def test_cli_exits_nonzero_when_no_control_can_be_evidenced(self):
        # So a nightly job that produces a report but cannot evidence the
        # control fails loudly rather than filing a reassuring artifact.
        with tempfile.TemporaryDirectory() as tmp:
            project(tmp)
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = verify.check_evidence(os.path.abspath(tmp), 24.0,
                                             "md", None, False)
            self.assertEqual(code, 1)

    def test_json_form_parses_and_carries_the_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            project(tmp)
            write_heartbeat(tmp)
            out = os.path.join(tmp, "evidence.json")
            buf = io.StringIO()
            with redirect_stdout(buf):
                verify.check_evidence(os.path.abspath(tmp), 24.0, "json",
                                      out, False)
            with open(out) as f:
                loaded = json.load(f)
            self.assertEqual(loaded["report"], "gate-enforcement-evidence")
            self.assertTrue(loaded["report_digest"].startswith("sha256:"))
            self.assertIn("limits", loaded)

    def test_end_to_end_against_a_real_invocation(self):
        # Everything above uses a synthesised heartbeat. This one drives the
        # registered hook command for real, blocks on a real rule, and builds
        # the artifact from what the guard itself wrote -- the only test here
        # that would catch the two halves agreeing on a format neither the
        # guard nor the harness actually produces.
        with tempfile.TemporaryDirectory() as tmp:
            config_path = project(tmp)
            invoke(tmp, config_path,
                   {"tool_name": "Bash", "tool_input": {"command": "ls"}})
            invoke(tmp, config_path,
                   {"tool_name": "Bash", "tool_input": {"command": _FUND_MOVE}})
            body = self.report(tmp)["body"]
            self.assertTrue(body["status"]["control_active"])
            self.assertEqual(body["activity"]["harness_invocations"], 2)
            self.assertEqual(body["activity"]["blocks_recorded_by_guard"], 1)
            self.assertEqual(body["enforcement"]["in_window"], 1)
            self.assertIn("FUND_MOVEMENT", body["enforcement"]["by_rule"])
            md = verify.render_evidence_markdown(self.report(tmp))
            self.assertIn("**ACTIVE**", md)
            self.assertNotIn(_FUND_MOVE, md)


if __name__ == "__main__":
    unittest.main(verbosity=2)
