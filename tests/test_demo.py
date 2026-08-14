#!/usr/bin/env python3
"""
Tests for demo.py -- the first thing a stranger runs.

demo.py is the front door: it is the one command in the README that someone
runs before they trust anything else here, and it makes three promises that
are easy to break by accident. It writes nothing outside its temp directory.
It deletes that directory unless asked not to. And its exit status is honest
-- 0 only when every probe decided the way the README says it will, so a
regression in the guards shows up as a failing demo rather than a demo that
prints a reassuring table anyway.

These cases run the real script end to end. That is slower than testing
functions in isolation and it is the point: a demo that passes its unit
tests but fails when invoked is exactly the failure this file exists to
catch.

    python3 tests/test_demo.py
"""

import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO = os.path.join(ROOT, "demo.py")

sys.path.insert(0, ROOT)

from demo import SCENES, rule_from  # noqa: E402

results = []


def check(name, condition, detail=""):
    results.append((name, bool(condition), detail))


def run(*args, cwd=None):
    return subprocess.run(
        [sys.executable, DEMO, *args],
        capture_output=True, text=True, timeout=300,
        cwd=cwd or tempfile.gettempdir(),
    )


# --- the scene list itself -------------------------------------------------
# Every row is narrated to a human in the results table, so a malformed one
# is a wrong claim on screen, not just a broken test.
check("every scene has a narration, payload and expectation",
      all(len(s) == 3 for s in SCENES))
check("every scene payload names a tool",
      all(s[1].get("tool_name") for s in SCENES))
check("expectations are only block or allow",
      all(s[2] in ("block", "allow") for s in SCENES))
check("the demo shows allows too, not just blocks",
      any(s[2] == "allow" for s in SCENES) and any(s[2] == "block" for s in SCENES))
check("narrations fit the results column (52 chars)",
      all(len(s[0]) <= 52 for s in SCENES),
      str([s[0] for s in SCENES if len(s[0]) > 52]))

check("rule id is parsed out of a real block message",
      rule_from("BLOCKED BY APPROVAL GATE [PAYMENT_API_WRITE]\nbecause...")
      == "PAYMENT_API_WRITE")
check("no rule id in ordinary text", rule_from("nothing to see") == "")

# --- the real run ----------------------------------------------------------
before = set(os.listdir(tempfile.gettempdir()))
proc = run()
after = set(os.listdir(tempfile.gettempdir()))

check("demo.py exits 0 on a clean checkout", proc.returncode == 0,
      f"exit {proc.returncode}: {proc.stdout[-400:]}{proc.stderr[-400:]}")
check("no probe decided unexpectedly", "UNEXPECTED" not in proc.stdout,
      proc.stdout[-400:])
check("the temp project is cleaned up",
      not any(d.startswith("aag-demo-") for d in after - before),
      str(sorted(d for d in after - before if d.startswith("aag-demo-"))))

# Each scene must appear in the table with the verdict the scene list claims,
# because the table is the whole output a reader judges the product on.
for label, _payload, expect in SCENES:
    want = "BLOCKED" if expect == "block" else "allowed"
    row = next((l for l in proc.stdout.splitlines() if l.strip().startswith(label)), "")
    check(f"table row: {label[:38]} -> {want}", want in row, row.strip() or "row missing")

blocked_rows = [l for l in proc.stdout.splitlines() if "BLOCKED" in l and "  " in l]
rules = {m.group(1) for l in blocked_rows for m in [re.search(r"([A-Z][A-Z0-9_]{4,})\s*$", l)] if m}
check("blocks are attributed to distinct named rules", len(rules) >= 5, str(sorted(rules)))

# The queue half of the loop: a block has to become something answerable, or
# the product is just a wall.
check("the run shows a queued approval ticket", '"status": "pending"' in proc.stdout)
check("the run shows a human decision being recorded", "#0001 deny" in proc.stdout)
check("the run shows the block audit log", "blocked.jsonl" in proc.stdout)

# --- flags -----------------------------------------------------------------
kept = run("--keep")
m = re.search(r"Temp project kept at: (\S+)", kept.stdout)
check("--keep reports where it left the project", bool(m), kept.stdout[-200:])
if m:
    path = m.group(1)
    check("--keep really leaves it on disk", os.path.isdir(path), path)
    check("--keep left a wired settings.json",
          os.path.isfile(os.path.join(path, ".claude", "settings.json")))
    check("--keep left the installed guard",
          os.path.isfile(os.path.join(path, "bin", "gate_guard.py")))
    subprocess.run(["rm", "-rf", path], timeout=60)

quiet = run("--quiet")
check("--quiet still exits 0", quiet.returncode == 0, quiet.stdout[-300:])
check("--quiet keeps the results table", "The agent tries to..." in quiet.stdout)
check("--quiet drops the narration", "60-second demo" not in quiet.stdout)
check("--quiet is genuinely shorter",
      len(quiet.stdout) < len(proc.stdout),
      f"{len(quiet.stdout)} vs {len(proc.stdout)}")

# --- nothing outside the temp dir ------------------------------------------
# Run it from a directory we own and assert it stayed out of it. A demo that
# writes into your cwd is a demo nobody should paste into a terminal.
with tempfile.TemporaryDirectory() as cwd:
    sentinel = set(os.listdir(cwd))
    r = run(cwd=cwd)
    check("running from another directory leaves it untouched",
          set(os.listdir(cwd)) == sentinel, str(set(os.listdir(cwd)) - sentinel))
    check("...and still exits 0", r.returncode == 0, f"exit {r.returncode}")

# --- report ----------------------------------------------------------------
failed = [r for r in results if not r[1]]
for name, ok, detail in results:
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   ({detail})" if detail and not ok else ""))
print(f"\n{len(results) - len(failed)}/{len(results)} passed")
sys.exit(1 if failed else 0)
