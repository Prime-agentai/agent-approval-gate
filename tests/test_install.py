#!/usr/bin/env python3
"""
Tests for install.py's settings merge -- the step most likely to destroy
something a user cares about.

Pasting the example hook block over an existing .claude/settings.json is the
natural manual move and it silently deletes whatever hooks were already
there. These cases pin down that install.py adds to that file rather than
replacing it, and that re-running it is a no-op rather than a duplicate
registration.

    python3 tests/test_install.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from install import merge_settings, build_config, hook_command  # noqa: E402

CMD = 'env GATE_GUARD_CONFIG="/p/gate-guard.config.json" python3 "/p/bin/gate_guard.py"'

results = []


def check(name, condition, detail=""):
    results.append((name, bool(condition), detail))


# --- empty / missing settings file ---------------------------------------
settings, action = merge_settings(None, CMD)
check("empty settings -> create", action == "create", action)
check("empty settings registers the hook",
      settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == CMD)

# --- a settings file that already has unrelated content ------------------
existing = {
    "permissions": {"allow": ["Bash(ls:*)"]},
    "env": {"FOO": "bar"},
    "hooks": {
        "PreToolUse": [
            {"matcher": "Bash",
             "hooks": [{"type": "command", "command": "echo pre-existing"}]}
        ],
        "Stop": [
            {"matcher": "*",
             "hooks": [{"type": "command", "command": "echo done"}]}
        ],
    },
}
merged, action = merge_settings(existing, CMD)
check("existing settings -> add", action == "add", action)
check("unrelated top-level keys survive",
      merged["permissions"] == existing["permissions"] and merged["env"]["FOO"] == "bar")
check("other hook events survive",
      merged["hooks"]["Stop"][0]["hooks"][0]["command"] == "echo done")
check("pre-existing PreToolUse hook survives",
      any(h.get("command") == "echo pre-existing"
          for e in merged["hooks"]["PreToolUse"] for h in e["hooks"]))
check("our hook was appended",
      any(h.get("command") == CMD
          for e in merged["hooks"]["PreToolUse"] for h in e["hooks"]))
check("caller's object was not mutated",
      len(existing["hooks"]["PreToolUse"]) == 1)

# --- re-running the installer is a no-op ---------------------------------
again, action = merge_settings(merged, CMD)
check("second run -> same", action == "same", action)
check("second run does not duplicate the hook",
      sum(1 for e in again["hooks"]["PreToolUse"] for h in e["hooks"]
          if h.get("command") == CMD) == 1)

# --- upgrading an install that moved paths -------------------------------
stale = {"hooks": {"PreToolUse": [
    {"matcher": "*", "hooks": [
        {"type": "command", "command": "python3 /old/path/gate_guard.py"}]}]}}
upgraded, action = merge_settings(stale, CMD)
check("stale hook path -> update", action == "update", action)
check("stale hook path is rewritten, not duplicated",
      len(upgraded["hooks"]["PreToolUse"]) == 1
      and upgraded["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == CMD)

# --- malformed settings are refused, never silently overwritten ----------
for bad, label in [({"hooks": "nope"}, "hooks not an object"),
                   ({"hooks": {"PreToolUse": "nope"}}, "PreToolUse not a list")]:
    try:
        merge_settings(bad, CMD)
        check(f"refuses malformed settings ({label})", False, "no error raised")
    except ValueError:
        check(f"refuses malformed settings ({label})", True)

# --- generated config -----------------------------------------------------
repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
config = build_config(repo, "agent-state.json")
check("config points at the detected state file",
      config["state_path"] == "agent-state.json")
for entry in ("agent-state.json", "gate_guard.py", "approved-remotes.txt",
              os.path.join(".claude", "settings.json")):
    check(f"config protects {entry}", entry in config["protected_paths"])

# --- the hook command carries an explicit config path ---------------------
cmd = hook_command("python3", "/p/gate-guard.config.json", "/p/bin/gate_guard.py")
check("hook command pins GATE_GUARD_CONFIG",
      "GATE_GUARD_CONFIG=" in cmd and "/p/gate-guard.config.json" in cmd)
check("hook command quotes paths", '"' in cmd)

# --- report ---------------------------------------------------------------
failed = [r for r in results if not r[1]]
for name, ok, detail in results:
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   ({detail})" if detail and not ok else ""))
print(f"\n{len(results) - len(failed)}/{len(results)} passed")
sys.exit(1 if failed else 0)
