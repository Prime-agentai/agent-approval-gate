#!/usr/bin/env python3
"""
install.py -- one-command setup for agent-approval-gate.

Run this from the cloned repo, pointing at the agent project you want to
protect:

    python3 install.py --target /path/to/your-agent-project

It does the four things the manual instructions used to ask you to do by
hand, and it does them idempotently -- running it twice is safe, and running
it after a `git pull` is how you upgrade:

  1. Copies gate_guard.py, approve.py and state.py into <target>/bin/
  2. Writes <target>/gate-guard.config.json if it doesn't exist yet, with
     state_path pointed at whatever state file you actually have
  3. Creates <target>/approved-remotes.txt (empty = every git push blocked,
     which is the correct default) and the directories the queue, decision
     log, blocked log and ledger get written to
  4. Registers the hook in <target>/.claude/settings.json, MERGING into any
     hooks you already have rather than overwriting the file

Nothing here is destructive by default: an existing config file, an existing
remotes allowlist and an existing settings.json are all preserved. Pass
--dry-run first if you want to see the plan before anything is written.

The registered hook command carries an explicit GATE_GUARD_CONFIG path. That
matters: without it the hook resolves its config relative to the working
directory it happens to be invoked in, and a hook that silently falls back to
built-in defaults because it couldn't find your config is a hook you think is
enforcing your rules when it is enforcing someone else's.

After installing, run verify.py -- it fires real probe payloads through the
hook exactly as your harness would and shows you what actually blocked.
"""

import argparse
import json
import os
import shutil
import sys

SCRIPTS = ("gate_guard.py", "approve.py", "state.py")

# Checked in order; the first one that exists wins. If none exist we fall
# back to STATE.json and say so -- gate_guard.py fails closed to tier 0 when
# it can't read a state file, so a wrong guess here over-restricts rather
# than under-restricts.
STATE_CANDIDATES = (
    "STATE.json",
    "state.json",
    "agent-state.json",
    os.path.join(".agent", "state.json"),
)

REMOTES_TEMPLATE = """\
# git remotes this agent is allowed to push to, one per line.
# Substring match against the push command, so a line like
#   github.com/your-org/
# allows every repo under that org and nothing else.
#
# THIS FILE IS INTENTIONALLY EMPTY. An empty or missing allowlist blocks
# every git push, unconditionally. Add a line only when you mean it.
"""


class Planned:
    """One filesystem change, printed before it happens and skipped in a dry
    run. Collecting them up front is what makes --dry-run honest: the plan you
    see is the plan that executes."""

    def __init__(self, action, path, note=""):
        self.action = action  # create | update | skip | same
        self.path = path
        self.note = note

    def line(self, root):
        rel = os.path.relpath(self.path, root)
        tag = f"[{self.action}]".ljust(9)
        return f"  {tag} {rel}" + (f"   -- {self.note}" if self.note else "")


def detect_state_path(target):
    for cand in STATE_CANDIDATES:
        if os.path.isfile(os.path.join(target, cand)):
            return cand, True
    return "STATE.json", False


def build_config(source_dir, state_path):
    """Start from the shipped example, then point it at the state file we
    actually found and make sure the four files that must never be agent-
    writable are listed."""
    example = os.path.join(source_dir, "gate-guard.config.example.json")
    with open(example) as f:
        config = json.load(f)

    config["state_path"] = state_path

    must_protect = [
        os.path.basename(state_path),
        "gate_guard.py",
        "approved-remotes.txt",
        os.path.join(".claude", "settings.json"),
    ]
    protected = list(config.get("protected_paths", []))
    for entry in must_protect:
        if entry not in protected:
            protected.append(entry)
    config["protected_paths"] = protected
    return config


def hook_command(python_bin, config_path, guard_path):
    return (
        f"env GATE_GUARD_CONFIG={json.dumps(config_path)} "
        f"{python_bin} {json.dumps(guard_path)}"
    )


def merge_settings(existing, command):
    """Add our PreToolUse hook to a Claude Code settings object without
    disturbing anything else in it.

    Returns (new_settings, action) where action is 'create', 'update' (an
    older gate_guard registration was rewritten), 'add' (we appended a new
    matcher) or 'same'.

    This is the step people get wrong by hand -- settings.json usually
    already has hooks in it, and the natural move of pasting the example over
    the top silently deletes them.
    """
    settings = json.loads(json.dumps(existing)) if existing else {}
    hooks = settings.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError("`hooks` in settings.json is not an object")

    pre = hooks.setdefault("PreToolUse", [])
    if not isinstance(pre, list):
        raise ValueError("`hooks.PreToolUse` in settings.json is not a list")

    for entry in pre:
        for hook in entry.get("hooks", []) or []:
            if "gate_guard.py" in str(hook.get("command", "")):
                if hook["command"] == command:
                    return settings, "same"
                hook["command"] = command
                return settings, "update"

    pre.append({
        "matcher": "*",
        "hooks": [{"type": "command", "command": command}],
    })
    return settings, ("create" if not existing else "add")


def main():
    ap = argparse.ArgumentParser(
        description="Install agent-approval-gate into an agent project.")
    ap.add_argument("--target", default=os.getcwd(),
                    help="Project root to protect (default: current directory)")
    ap.add_argument("--bin-dir", default="bin",
                    help="Directory under the target for the scripts (default: bin)")
    ap.add_argument("--python", default="python3",
                    help="Interpreter written into the hook command (default: python3)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Print the plan without writing anything")
    ap.add_argument("--force", action="store_true",
                    help="Allow installing into the repo directory itself")
    args = ap.parse_args()

    source_dir = os.path.dirname(os.path.abspath(__file__))
    target = os.path.abspath(args.target)

    for name in SCRIPTS:
        if not os.path.isfile(os.path.join(source_dir, name)):
            sys.exit(f"error: {name} not found next to install.py -- run this "
                     f"from inside the cloned repo")

    if not os.path.isdir(target):
        sys.exit(f"error: target directory does not exist: {target}")

    if target == source_dir and not args.force:
        sys.exit("error: --target is the repo itself. Point it at the agent "
                 "project you want to protect, or pass --force if you really "
                 "mean to install in place.")

    bin_dir = os.path.join(target, args.bin_dir)
    config_path = os.path.join(target, "gate-guard.config.json")
    remotes_path = os.path.join(target, "approved-remotes.txt")
    settings_path = os.path.join(target, ".claude", "settings.json")

    state_path, state_found = detect_state_path(target)
    plan = []

    # 1. the three scripts
    for name in SCRIPTS:
        src = os.path.join(source_dir, name)
        dst = os.path.join(bin_dir, name)
        if os.path.isfile(dst):
            with open(src, "rb") as a, open(dst, "rb") as b:
                identical = a.read() == b.read()
            plan.append(Planned("same" if identical else "update", dst,
                                "" if identical else "newer version copied over"))
        else:
            plan.append(Planned("create", dst))

    # 2. config
    if os.path.isfile(config_path):
        plan.append(Planned("skip", config_path, "already exists, left untouched"))
    else:
        note = (f"state_path -> {state_path}" if state_found
                else f"state_path -> {state_path} (not found; edit this if wrong)")
        plan.append(Planned("create", config_path, note))

    # 3. allowlist + the directories the logs land in
    if os.path.isfile(remotes_path):
        plan.append(Planned("skip", remotes_path, "already exists, left untouched"))
    else:
        plan.append(Planned("create", remotes_path, "empty = all pushes blocked"))

    config_for_dirs = (json.load(open(config_path)) if os.path.isfile(config_path)
                       else build_config(source_dir, state_path))
    log_dirs = set()
    for key in ("blocked_log", "queue_path", "decisions_path", "ledger_path"):
        rel = config_for_dirs.get(key)
        if rel:
            d = os.path.dirname(os.path.join(target, rel))
            if d and not os.path.isdir(d):
                log_dirs.add(d)
    for d in sorted(log_dirs):
        plan.append(Planned("create", d, "log directory"))

    # 4. hook registration
    command = hook_command(args.python, config_path,
                           os.path.join(bin_dir, "gate_guard.py"))
    existing_settings = None
    if os.path.isfile(settings_path):
        try:
            with open(settings_path) as f:
                existing_settings = json.load(f)
        except json.JSONDecodeError as e:
            sys.exit(f"error: {settings_path} is not valid JSON ({e}). "
                     f"Refusing to touch it -- fix or move it and re-run.")
    try:
        new_settings, action = merge_settings(existing_settings, command)
    except ValueError as e:
        sys.exit(f"error: {settings_path}: {e}. Refusing to touch it.")
    notes = {
        "same": "hook already registered, unchanged",
        "update": "existing gate_guard hook command rewritten",
        "add": "hook appended, your other hooks preserved",
        "create": "new settings file with the hook registered",
    }
    plan.append(Planned("skip" if action == "same" else
                        ("update" if action in ("update", "add") else "create"),
                        settings_path, notes[action]))

    # ---- report, then execute ----
    print(f"agent-approval-gate -> {target}\n")
    for p in plan:
        print(p.line(target))
    print()

    if args.dry_run:
        print("dry run: nothing written. Re-run without --dry-run to apply.")
        return

    os.makedirs(bin_dir, exist_ok=True)
    for name in SCRIPTS:
        shutil.copy2(os.path.join(source_dir, name), os.path.join(bin_dir, name))

    if not os.path.isfile(config_path):
        with open(config_path, "w") as f:
            json.dump(build_config(source_dir, state_path), f, indent=2)
            f.write("\n")

    if not os.path.isfile(remotes_path):
        with open(remotes_path, "w") as f:
            f.write(REMOTES_TEMPLATE)

    for d in sorted(log_dirs):
        os.makedirs(d, exist_ok=True)

    if action != "same":
        os.makedirs(os.path.dirname(settings_path), exist_ok=True)
        with open(settings_path, "w") as f:
            json.dump(new_settings, f, indent=2)
            f.write("\n")

    print("Installed. Next:")
    print(f"  1. Read {os.path.relpath(config_path, target)} and adjust "
          f"protected_paths for your project.")
    if not state_found:
        print(f"  2. No state file was found. If your agent has one, set "
              f"state_path in the config -- until then the hook fails closed "
              f"at trust tier 0, which blocks tier-gated rules.")
    print(f"  {'3' if not state_found else '2'}. "
          f"python3 {os.path.relpath(os.path.join(source_dir, 'verify.py'), target)} "
          f"--target {os.path.relpath(target, os.getcwd()) or '.'}")
    print("     -- fires real probes through the hook and shows what blocks.")
    print("  Then restart your harness session so it reloads settings.json.")


if __name__ == "__main__":
    main()
