#!/usr/bin/env python3
"""
demo.py -- see the gate block a real spend, in about 60 seconds, without
installing anything into a project you care about.

    python3 demo.py

It builds a throwaway agent project in a temporary directory, installs the
gate into it with the real install.py, fires real tool-call payloads through
the hook exactly as a harness would, and shows you what blocked, what was
allowed, and what the human ends up reading. Then it deletes the directory.

Nothing outside that temp directory is written. No network calls are made --
the payloads never execute, they are only ever handed to the hook as JSON on
stdin, which is the whole point: the hook decides before the command runs.

    --keep      leave the temp project in place and print its path
    --quiet     drop the narration, keep the results table

Exit status is 0 only if every probe decided the way this script says it
will, so this doubles as a smoke test of install.py + gate_guard.py together
on a clean machine.

A note on the probe strings below: several are assembled from fragments at
runtime rather than written as single literals. That is not obfuscation. A
gate pointed at a codebase containing this file will block an agent from
writing this file, because the payloads match the rules they exercise. It is
a real, permanent property of content-matching guards; the fix is to split
the literal, never to loosen the rule. verify.py carries the same note.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

# --- payload fragments (see the docstring's note on the splits) ---
_STRIPE = "api." + "stri" + "pe.com"
_AMOUNT = "5 " + "usd" + "c"

CHARGE = ("curl -X POST https://" + _STRIPE + "/v1/charges "
          "-d amount=4900 -d currency=usd  # aag-demo")
SIGNUP = "curl https://aag-demo.invalid/" + "signup -d email=agent@example.com  # aag-demo"
FUND_MOVE = "solana transfer --amount " + _AMOUNT + " --to 9xQe...  # aag-demo"
PKG_INSTALL = "npm" + " install some-package  # aag-demo"
UNAPPROVED_PUSH = "git push https://github.com/someone-else/their-repo.git main  # aag-demo"
READ_PRICES = "curl -s https://" + _STRIPE + "/v1/prices  # aag-demo"
ORDINARY = "python3 -m pytest tests/  # aag-demo"

# (narration, payload, expectation). Blocks first: the point of the product
# is the thing that doesn't happen. The allows are here because over-blocking
# is its own failure mode and a demo that only shows blocks is a demo of a
# guard nobody can work next to.
SCENES = [
    ("charges a card to 'test the billing integration'",
     {"tool_name": "Bash", "tool_input": {"command": CHARGE}}, "block"),
    ("signs itself up for a SaaS account",
     {"tool_name": "Bash", "tool_input": {"command": SIGNUP}}, "block"),
    ("moves funds out of a wallet",
     {"tool_name": "Bash", "tool_input": {"command": FUND_MOVE}}, "block"),
    ("installs a dependency nobody reviewed",
     {"tool_name": "Bash", "tool_input": {"command": PKG_INSTALL}}, "block"),
    ("pushes your code to a remote that is not yours",
     {"tool_name": "Bash", "tool_input": {"command": UNAPPROVED_PUSH}}, "block"),
    ("rewrites the state file a human owns",
     {"tool_name": "Write",
      "tool_input": {"file_path": "STATE.json", "content": '{"trust_tier": 3}'}},
     "block"),
    ("reads the pricing API -- research, not a charge",
     {"tool_name": "Bash", "tool_input": {"command": READ_PRICES}}, "allow"),
    ("runs the test suite",
     {"tool_name": "Bash", "tool_input": {"command": ORDINARY}}, "allow"),
]

STATE_SEED = {
    "trust_tier": 0,
    "note": "Throwaway state file for the demo. trust_tier 0 = tightest rules.",
}


def say(quiet, *args):
    if not quiet:
        print(*args)


def build_project(root):
    """A minimal but realistic agent project: a state file, a source dir, and
    somewhere for scratch notes. install.py finds STATE.json on its own."""
    os.makedirs(os.path.join(root, "notes"), exist_ok=True)
    os.makedirs(os.path.join(root, "src"), exist_ok=True)
    with open(os.path.join(root, "STATE.json"), "w") as f:
        json.dump(STATE_SEED, f, indent=2)
    with open(os.path.join(root, "src", "agent.py"), "w") as f:
        f.write("# your agent goes here\n")


def run_installer(root, quiet):
    proc = subprocess.run(
        [sys.executable, os.path.join(HERE, "install.py"), "--target", root],
        capture_output=True, text=True, timeout=120,
    )
    if proc.returncode != 0:
        print("install.py failed -- the demo can't continue:\n")
        print(proc.stdout or proc.stderr)
        return False
    if not quiet:
        for line in proc.stdout.splitlines():
            if line.strip():
                print("      " + line)
    return True


def hook_command(root):
    """Read back the command the harness would actually run. Probing anything
    else would be probing a hook your harness isn't running."""
    path = os.path.join(root, ".claude", "settings.json")
    with open(path) as f:
        settings = json.load(f)
    for entry in (settings.get("hooks") or {}).get("PreToolUse") or []:
        for hook in entry.get("hooks", []) or []:
            cmd = str(hook.get("command", ""))
            if "gate_guard.py" in cmd or "gate-guard.py" in cmd:
                return cmd
    return None


def fire(command, payload, root):
    proc = subprocess.run(
        ["sh", "-c", command], input=json.dumps(payload),
        capture_output=True, text=True, cwd=root, timeout=60,
    )
    return proc.returncode, proc.stderr


def rule_from(stderr):
    m = re.search(r"\[([A-Z][A-Z0-9_]+)\]", stderr)
    return m.group(1) if m else ""


def first_line(text):
    for line in text.splitlines():
        if line.strip():
            return line.strip()
    return ""


def show_queue_workflow(root, quiet):
    """A block is not a dead end. This is the half of the loop that turns one
    into something a human can answer."""
    approve = os.path.join(root, "bin", "approve.py")
    env = dict(os.environ, GATE_GUARD_CONFIG=os.path.join(root, "gate-guard.config.json"))
    req = subprocess.run(
        [sys.executable, approve, "request",
         "--tier", "SPEND",
         "--ask", "Charge $49 to the test card to exercise the billing path",
         "--why", "The integration test needs one real charge to assert against",
         "--cost", "$49",
         "--reversible", "yes -- refundable within 24h",
         "--blocked-if-denied", "Billing tests stay mocked; nothing else stalls"],
        capture_output=True, text=True, cwd=root, env=env, timeout=60,
    )
    if req.returncode != 0:
        say(quiet, "      (approve.py request failed: " + first_line(req.stderr) + ")")
        return False
    say(quiet, "      $ approve.py request --tier SPEND --ask '...' --why '...'")
    for line in req.stdout.splitlines():
        if line.strip():
            say(quiet, "      " + line)

    queue_path = os.path.join(root, "approvals", "queue.jsonl")
    if not os.path.isfile(queue_path):
        return False
    with open(queue_path) as f:
        lines = [l for l in f if l.strip()]
    say(quiet, "")
    say(quiet, "      approvals/queue.jsonl now holds one reviewable ticket:")
    say(quiet, "      " + json.dumps(json.loads(lines[-1]), indent=2)[:600].replace(
        "\n", "\n      "))

    dec = subprocess.run(
        [sys.executable, approve, "decide", "1", "deny",
         "Use the sandbox card, not a live charge"],
        capture_output=True, text=True, cwd=root, env=env, timeout=60,
    )
    say(quiet, "")
    say(quiet, "      A human answers it -- append-only, nothing edited in place:")
    say(quiet, "      $ approve.py decide 1 deny 'Use the sandbox card, not a live charge'")
    for line in dec.stdout.splitlines():
        if line.strip():
            say(quiet, "      " + line)
    return dec.returncode == 0


def main():
    ap = argparse.ArgumentParser(
        description="Watch agent-approval-gate block a real spend, in a throwaway project.")
    ap.add_argument("--keep", action="store_true",
                    help="Leave the temp project in place instead of deleting it")
    ap.add_argument("--quiet", action="store_true",
                    help="Results table only, no narration")
    args = ap.parse_args()
    quiet = args.quiet

    root = tempfile.mkdtemp(prefix="aag-demo-")
    ok = True
    try:
        say(quiet, "agent-approval-gate -- 60-second demo\n")
        say(quiet, "Nothing outside the temp directory below is written, and none of the")
        say(quiet, "commands below are ever executed -- they are handed to the hook as JSON,")
        say(quiet, "which is the point: the gate decides before the command runs.\n")

        say(quiet, "[1/4] A throwaway agent project")
        say(quiet, "      " + root)
        build_project(root)

        say(quiet, "\n[2/4] Installing the gate into it, with the real installer")
        if not run_installer(root, quiet):
            return 1

        command = hook_command(root)
        if not command:
            print("No PreToolUse hook was registered -- install.py did not wire it up.")
            return 1

        print("\n[3/4] Firing real tool calls through the registered hook\n")
        print(f"      {'The agent tries to...':<52}  {'The gate':<8}  rule")
        print(f"      {'-' * 52}  {'-' * 8}  {'-' * 20}")
        failures = []
        for label, payload, expect in SCENES:
            code, stderr = fire(command, payload, root)
            blocked = code != 0
            got = "block" if blocked else "allow"
            verdict = "BLOCKED" if blocked else "allowed"
            rule = rule_from(stderr) if blocked else ""
            flag = "" if got == expect else "   <-- UNEXPECTED"
            if got != expect:
                failures.append((label, expect, got))
            print(f"      {label[:52]:<52}  {verdict:<8}  {rule}{flag}".rstrip())

        say(quiet, "\n      A blocked call exits non-zero and the harness never runs it. The")
        say(quiet, "      agent is told why, and told to file a request rather than retry:\n")
        _, stderr = fire(command, SCENES[0][1], root)
        for line in stderr.splitlines()[:6]:
            if line.strip():
                say(quiet, "      | " + line.strip())

        blocked_log = os.path.join(root, "approvals", "blocked.jsonl")
        if os.path.isfile(blocked_log):
            with open(blocked_log) as f:
                entries = [l for l in f if l.strip()]
            say(quiet, "\n      Every block is evidence. approvals/blocked.jsonl, "
                       f"{len(entries)} entries:")
            say(quiet, "      " + json.dumps(json.loads(entries[0]), indent=2).replace(
                "\n", "\n      "))

        say(quiet, "\n[4/4] What the human actually sees")
        if not show_queue_workflow(root, quiet):
            ok = False

        if failures:
            ok = False
            print("\nSome probes did not decide as expected:")
            for label, expect, got in failures:
                print(f"  - {label}: expected {expect}, got {got}")
            print("\nThat is a real result, not a demo glitch -- please open an issue.")
        else:
            say(quiet, "\nEvery probe decided as expected. Nothing here was mocked: that was")
            say(quiet, "install.py, gate_guard.py and approve.py doing the real thing.\n")
            say(quiet, "Install it into your own project:")
            say(quiet, "  python3 install.py --target /path/to/your-agent-project")
            say(quiet, "  python3 verify.py  --target /path/to/your-agent-project")
    finally:
        if args.keep:
            print(f"\nTemp project kept at: {root}")
        else:
            shutil.rmtree(root, ignore_errors=True)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
