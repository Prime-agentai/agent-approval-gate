#!/usr/bin/env python3
"""
verify.py -- prove the guards are actually live, and actually blocking.

    python3 verify.py --target /path/to/your-agent-project

Covers both hooks this repo installs: gate_guard.py (is this action allowed?)
and budget_guard.py (has this session already cost more than you agreed to
spend, and is it still making progress?). A project that installed only the
approval gate is fine -- the budget section reports SKIP, not FAIL.

A PreToolUse hook fails silently. If the path in settings.json is wrong, if
the config didn't resolve, if the harness never reloaded its settings, you
get exactly the same experience as a hook that is working perfectly: nothing
visibly happens. You find out it was never running the first time your agent
does the thing it was supposed to be stopped from doing.

So this script does two separate things:

  WIRING   -- reads .claude/settings.json, finds the registered hook command,
              and checks that every file it depends on exists and parses.

  BEHAVIOR -- takes that exact registered command and feeds it real probe
              payloads on stdin, the same shape the harness sends, then reads
              the exit code. Exit 2 is a block. Exit 0 is an allow. This is
              an end-to-end test of the thing your harness will actually run,
              not a unit test of an imported function.

There is a third mode, --evidence, which answers a different question from
the other two. WIRING and BEHAVIOR ask "is this correct now?", for the person
who just changed something, and their answer evaporates with the terminal
scrollback. --evidence asks "was this control operating for the whole period,
and not only at the moment somebody checked?" -- and renders the answer as a
dated, self-contained artifact you can hand to someone who was not in the
room: the window covered, how many tool calls the harness routed through the
gate, what it blocked and when, which exact files were running by digest, and
a section of equal weight on what none of it proves. That last section is not
a disclaimer. An evidence artifact that overstates itself is worth less than
no artifact, because the first competent reader who finds the overstatement
stops believing the rest of it.

Both directions are checked. Probes that SHOULD block are the obvious half;
probes that should be ALLOWED matter just as much, because an over-blocking
gate that fights every tool call is a gate you will turn off within a week,
and then you have no gate at all.

A fourth mode, --over-blocks, follows that thought into your own history
instead of a probe set. It reads the blocks the gate actually recorded and
asks, of each one, whether the tool that was blocked could have carried out
the action the rule exists to stop. Writing a file cannot move funds;
fetching a URL cannot open an account. Blocks of that shape prevented
nothing, and their count is the closest thing to an honest price tag on
running these rules unattended. It is deliberately a floor: anything the
model does not recognise is reported as not adjudicable rather than counted,
and the model itself is printed with the result so you can disagree with it.

Probes are derived from the rule ids present in your config. If you replaced
the default rule pack, probes for rules you removed are reported as SKIP
rather than counted as failures -- your rules are yours.

Blocked gate probes append to your configured blocked_log, because that is
what the hook does and suppressing it would mean testing something other than
production. Every probe command contains the string "gate-verify-probe" so
you can filter them back out of the audit trail.

BUDGET PROBES ARE ISOLATED, AND FOR A REASON WORTH STATING. A gate probe's
only side effect is an audit line. A budget probe's is not: budget_guard.py
records each session's cost into a shared daily rollup under its state_dir,
and that rollup decides whether the NEXT call is blocked. Probing a $20
synthetic session against your real state_dir would leave $20 of imaginary
spend sitting in today's total for the rest of the day -- quite possibly
enough to trip your daily ceiling and stop your actual agent. So every budget
probe runs the registered script against a throwaway config in a temp
directory, with only state_dir and blocked_log redirected; the ceilings, the
price table and the loop thresholds are your real ones, read from your real
config. Your spend ledger is never written to. The temp directory is removed
when the run finishes.

Three of the budget probes test arithmetic rather than plumbing, because the
cost ceiling is only as trustworthy as the pricing underneath it:

  - Cache reads bill at 0.1x the input rate. Priced at the full input rate --
    the obvious shortcut -- a mostly-cached agent session overstates by
    roughly 10x and your ceiling stops meaning anything.
  - A streamed assistant message is rewritten to the transcript as it grows,
    so summing line by line double-counts. Usage is deduplicated by message id.
  - An unrecognised model ID -- which is what a newly released model looks
    like -- must still be billed, or it sails past the ceiling for free.

Each is probed by constructing a transcript that lands on the safe side of
your ceiling only if that rule is implemented correctly.

A note on how the probe strings below are built. Several are assembled from
fragments at runtime rather than written as single literals -- the payment
domains, the credential words, the fake token. That is not obfuscation, and
the reason is worth knowing before you write your own probes: a strict gate
pointed at a codebase containing this file will block an agent from writing
this file, because the probe payloads match the very rules they exercise.
This exact file was blocked by its own project's hook on the first attempt to
write it (rule PAYMENT_API_WRITE, on a line containing a stripe API URL).
gate_guard.py carries the same note about its key-material pattern. It is a
real, permanent property of content-matching guards, it will happen to you,
and the fix is to split the literal -- never to loosen the rule.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

# --- probe payload fragments (see the docstring's note on the splits) ---

_STRIPE = "api." + "stri" + "pe.com"
_REGISTRAR = "name" + "cheap.com"

STRIPE_POST = (
    "curl -X POST https://" + _STRIPE + "/v1/charges "
    "-d amount=500  # gate-verify-probe"
)
STRIPE_GET = "curl -s https://" + _STRIPE + "/v1/charges  # gate-verify-probe"
PKG_INSTALL = "npm" + " install left-pad  # gate-verify-probe"
SIGNUP_URL = "curl https://gate-verify.invalid/" + "signup  # gate-verify-probe"
_AMOUNT = "5 " + "usd" + "c"
FUND_MOVE = "solana transfer --amount " + _AMOUNT + " --to acct  # gate-verify-probe"
CONTRACT = "forge " + "create MyToken --rpc-url x  # gate-verify-probe"
REGISTRAR = "curl " + _REGISTRAR + " cart checkout  # gate-verify-probe"
KEY_MATERIAL = "cat ~/.config/" + "pri" + "vate_" + "key" + "  # gate-verify-probe"
FAKE_TOKEN = "echo " + "sk-" + ("A" * 26) + "  # gate-verify-probe"
UNAPPROVED_PUSH = (
    "git push https://gate-verify.invalid/unapproved.git main"
    "  # gate-verify-probe"
)

PASS, FAIL, SKIP, WARN = "PASS", "FAIL", "SKIP", "WARN"


def bash(cmd):
    return {"tool_name": "Bash", "tool_input": {"command": cmd}}


def build_probes(config, state_abspath):
    """Probes are (rule_id, description, payload, expect). rule_id None means
    the probe isn't tied to a configurable rule and always applies."""
    state_base = os.path.basename(config.get("state_path", "STATE.json"))
    return [
        # --- should block ---
        ("PAYMENT_API_WRITE", "POST to a payment API",
         bash(STRIPE_POST), "block"),
        ("ACCOUNT_SIGNUP_FLOW", "opening a signup URL",
         bash(SIGNUP_URL), "block"),
        ("FUND_MOVEMENT", "moving funds out of a wallet",
         bash(FUND_MOVE), "block"),
        ("CONTRACT_DEPLOY", "deploying a contract",
         bash(CONTRACT), "block"),
        ("KEY_MATERIAL", "reading offline signing material",
         bash(KEY_MATERIAL), "block"),
        ("DOMAIN_REGISTRAR", "buying a domain",
         bash(REGISTRAR), "block"),
        ("PACKAGE_INSTALL", "installing a package",
         bash(PKG_INSTALL), "block"),
        (None, "live-credential-shaped string in a command",
         bash(FAKE_TOKEN), "block"),
        (None, "push to an unapproved remote",
         bash(UNAPPROVED_PUSH), "block"),
        (None, f"Write tool targeting {state_base} (protected)",
         {"tool_name": "Write",
          "tool_input": {"file_path": state_abspath, "content": "{}"}},
         "block"),
        (None, f"shell redirect into {state_base} (protected)",
         bash("echo probe > " + state_base + "  # gate-verify-probe"),
         "block"),
        # --- should be allowed: over-blocking is its own failure mode ---
        (None, "ordinary shell command",
         bash("ls -la  # gate-verify-probe"), "allow"),
        (None, "GET from a payment API (reading is research)",
         bash(STRIPE_GET), "allow"),
        (None, "Read tool on an ordinary file",
         {"tool_name": "Read", "tool_input": {"file_path": "README.md"}}, "allow"),
        (None, "Write tool on an unprotected file",
         {"tool_name": "Write",
          "tool_input": {"file_path": "notes/scratch.md", "content": "hello"}},
         "allow"),
    ]


def _hook_entry(target, marker="gate_guard.py"):
    """The PreToolUse entry registering `marker`, as (entry, command, err).

    Split out of find_hook_command so callers can also read the *matcher*.
    Reading the command while discarding the matcher is exactly how a narrowed
    matcher gets misdiagnosed as a harness bug: the matcher decides which tools
    ever reach the guard at all, and no amount of correct guard code makes a
    tool outside it produce a hook call.
    """
    settings_path = os.path.join(target, ".claude", "settings.json")
    if not os.path.isfile(settings_path):
        return None, None, f"{settings_path} does not exist"
    try:
        with open(settings_path) as f:
            settings = json.load(f)
    except json.JSONDecodeError as e:
        return None, None, f"settings.json is not valid JSON: {e}"

    variants = (marker, marker.replace("_", "-"))
    pre = (settings.get("hooks") or {}).get("PreToolUse") or []
    for entry in pre:
        for hook in entry.get("hooks", []) or []:
            cmd = str(hook.get("command", ""))
            if any(v in cmd for v in variants):
                return entry, cmd, None
    return None, None, f"no PreToolUse hook referencing {marker} is registered"


def find_hook_command(target, marker="gate_guard.py"):
    """Pull the registered hook command straight out of settings.json. Testing
    anything else would be testing a hook your harness isn't running.

    `marker` is the guard's script filename; both guards register their own
    PreToolUse entry and are recognised by it.
    """
    _entry, command, err = _hook_entry(target, marker)
    return command, err


def find_hook_matcher(target, marker="gate_guard.py"):
    """The tool-name matcher on the entry that registers the guard.

    Returns the matcher string, or None when it cannot be read at all. An
    absent matcher key means match-everything, so it reports `"*"` rather than
    None -- None is reserved for "could not determine", which callers must not
    render as a warning.
    """
    entry, _command, err = _hook_entry(target, marker)
    if err or not isinstance(entry, dict):
        return None
    matcher = entry.get("matcher")
    return "*" if matcher is None else str(matcher)


def matcher_covers_everything(matcher):
    """True when every tool reaches the guard.

    Unknown (None) counts as True on purpose: this gates a warning, and a
    warning fired because we could not read the config would be noise on a
    healthy install.
    """
    return matcher is None or str(matcher).strip() in ("", "*")


def wired_guard_path(command, target):
    """The gate_guard.py the registered hook command actually executes,
    absolute. Returns None if the command doesn't name one."""
    m = re.search(r"(\S*gate[_-]guard\.py)", command)
    if not m:
        return None
    guard = m.group(1).strip("\"'")
    return guard if os.path.isabs(guard) else os.path.join(target, guard)


def resolve_config(command, target):
    """Resolve the config exactly the way gate_guard.py will: the env var in
    the hook command first, then the project root."""
    m = re.search(r"GATE_GUARD_CONFIG=(\"[^\"]+\"|'[^']+'|\S+)", command)
    if m:
        path = m.group(1).strip("\"'")
        if not os.path.isabs(path):
            path = os.path.join(target, path)
        return path, "hook command"
    return os.path.join(target, "gate-guard.config.json"), "project root"


def check_wiring(target):
    """Returns (rows, command, config, state_abspath). command is None if the
    wiring is broken badly enough that no probe can run."""
    rows = []
    command, err = find_hook_command(target)
    if not command:
        rows.append((FAIL, "hook registered in .claude/settings.json", err))
        return rows, None, None, None
    rows.append((PASS, "hook registered in .claude/settings.json", command))

    guard = wired_guard_path(command, target) or ""
    if os.path.isfile(guard):
        rows.append((PASS, "hook script exists at the registered path", guard))
    else:
        rows.append((FAIL, "hook script exists at the registered path",
                     f"not found: {guard}"))

    config_path, origin = resolve_config(command, target)
    config = None
    if os.path.isfile(config_path):
        try:
            with open(config_path) as f:
                config = json.load(f)
            rows.append((PASS, f"config resolves (via {origin})", config_path))
        except json.JSONDecodeError as e:
            rows.append((FAIL, f"config resolves (via {origin})",
                         f"{config_path}: invalid JSON: {e}"))
    else:
        rows.append((WARN, f"config resolves (via {origin})",
                     f"{config_path} not found -- the hook falls back to its "
                     f"built-in defaults, NOT your rules"))
    config = config or {}

    state_rel = config.get("state_path", "STATE.json")
    state_abspath = os.path.join(target, state_rel)
    if os.path.isfile(state_abspath):
        try:
            with open(state_abspath) as f:
                tier = json.load(f).get(
                    config.get("trust_tier_field", "trust_tier"), 0)
            rows.append((PASS, "state file readable",
                         f"{state_rel}, trust tier {tier}"))
        except json.JSONDecodeError as e:
            rows.append((WARN, "state file readable",
                         f"{state_rel}: invalid JSON ({e}) -- tier fails "
                         f"closed to 0"))
    else:
        rows.append((WARN, "state file readable",
                     f"{state_rel} not found -- tier fails closed to 0, so "
                     f"tier-gated rules stay blocked"))

    remotes = os.path.join(target, config.get("approved_remotes_file",
                                              "approved-remotes.txt"))
    if os.path.isfile(remotes):
        with open(remotes) as f:
            entries = [l.strip() for l in f
                       if l.strip() and not l.startswith("#")]
        rows.append((PASS, "git push allowlist present",
                     f"{len(entries)} approved remote(s)"))
    else:
        rows.append((WARN, "git push allowlist present",
                     "missing -- every git push is blocked (fail closed)"))

    return rows, command, config, state_abspath


def configured_rule_ids(config):
    ids = set()
    for key in ("absolute_rules", "tier_gated_rules"):
        for rule in config.get(key) or []:
            ids.add(rule.get("id"))
    return ids


# ---------------------------------------------------------------------------
# budget_guard.py
# ---------------------------------------------------------------------------

BUDGET_MARKER = "budget_guard.py"
UNKNOWN_MODEL = "zzz-unreleased-probe-model"


def load_budget_module(guard_path):
    """Import the installed budget_guard.py to reuse its own default config
    and price table.

    This is deliberately narrow: nothing here calls its decision functions.
    Probes still go through the registered command as a subprocess, the same
    as the gate probes. The import exists so the probe transcripts can be
    sized against YOUR merged config -- restating the default price table in
    this file would drift from it the first time either one changed.
    """
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("_bg_probe", guard_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception:
        return None


def merge_budget_config(module, user_config):
    """Merge a user config over the module's defaults one level deep --
    the same shallow merge load_config() documents, so a config that
    overrides one loop-detector field doesn't have to restate the rest."""
    merged = json.loads(json.dumps(getattr(module, "DEFAULT_CONFIG", {})))
    for key, value in (user_config or {}).items():
        if key.startswith("_"):
            continue
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key].update(value)
        else:
            merged[key] = value
    return merged


def resolve_budget_config(command, target, guard_path):
    """Resolve the config the way budget_guard.py will: the env var in the
    hook command, then the working directory, then next to the script."""
    m = re.search(r"BUDGET_GUARD_CONFIG=(\"[^\"]+\"|'[^']+'|\S+)", command)
    if m:
        path = m.group(1).strip("\"'")
        if not os.path.isabs(path):
            path = os.path.join(target, path)
        return path, "hook command"
    for candidate, origin in (
        (os.path.join(target, "budget-guard.config.json"), "project root"),
        (os.path.join(os.path.dirname(guard_path), "budget-guard.config.json"),
         "next to the script"),
    ):
        if os.path.isfile(candidate):
            return candidate, origin
    return None, "built-in defaults"


def writable(directory):
    """Can the hook actually persist state here? If it cannot, check_loop
    swallows the OSError by design and the loop window silently never
    accumulates -- the detector reports nothing and looks healthy."""
    try:
        os.makedirs(directory, exist_ok=True)
        probe = os.path.join(directory, ".verify-write-probe")
        with open(probe, "w") as f:
            f.write("")
        os.remove(probe)
        return True
    except OSError:
        return False


def check_budget_wiring(target):
    """Returns (rows, command, merged_config). command is None when the
    budget guard is not installed, which is a supported choice, not a fault."""
    rows = []
    command, err = find_hook_command(target, BUDGET_MARKER)
    if not command:
        rows.append((SKIP, "hook registered in .claude/settings.json",
                     f"{err} -- skipping (install.py --no-budget-guard is a "
                     f"supported choice)"))
        return rows, None, None
    rows.append((PASS, "hook registered in .claude/settings.json", command))

    m = re.search(r"(\S*budget[_-]guard\.py)", command)
    guard = (m.group(1).strip("\"'") if m else "")
    if not os.path.isabs(guard):
        guard = os.path.join(target, guard)
    if os.path.isfile(guard):
        rows.append((PASS, "hook script exists at the registered path", guard))
    else:
        rows.append((FAIL, "hook script exists at the registered path",
                     f"not found: {guard}"))
        return rows, None, None

    config_path, origin = resolve_budget_config(command, target, guard)
    user_config = {}
    if config_path and os.path.isfile(config_path):
        try:
            with open(config_path) as f:
                user_config = json.load(f)
            rows.append((PASS, f"config resolves (via {origin})", config_path))
        except json.JSONDecodeError as e:
            rows.append((FAIL, f"config resolves (via {origin})",
                         f"{config_path}: invalid JSON: {e} -- the hook falls "
                         f"back to built-in defaults, NOT your ceilings"))
    elif config_path:
        rows.append((WARN, "config resolves",
                     f"{config_path} not found -- the hook falls back to its "
                     f"built-in defaults, NOT your ceilings"))
    else:
        rows.append((WARN, "config resolves", "no config file found anywhere "
                     "on the resolution path -- built-in defaults are in force"))

    module = load_budget_module(guard)
    if module is None:
        rows.append((FAIL, "hook script imports cleanly",
                     f"{guard} raised on import -- the hook cannot run"))
        return rows, None, None
    config = merge_budget_config(module, user_config)

    session_ceiling = config.get("session_cost_ceiling_usd")
    day_ceiling = config.get("daily_cost_ceiling_usd")
    detail = (f"session {'off' if session_ceiling is None else f'${session_ceiling:.2f}'}, "
              f"daily {'off' if day_ceiling is None else f'${day_ceiling:.2f}'}")
    if session_ceiling is None and day_ceiling is None:
        rows.append((WARN, "a cost ceiling is configured",
                     "both ceilings are null -- the loop detector still runs, "
                     "but nothing stops a slow expensive session"))
    else:
        rows.append((PASS, "a cost ceiling is configured", detail))

    cache_read = (config.get("cache_multipliers") or {}).get("cache_read")
    if not config.get("pricing_usd_per_mtok"):
        rows.append((FAIL, "price table is populated",
                     "empty -- every model prices at $0 and no ceiling can trip"))
    elif cache_read is None or cache_read >= 1:
        rows.append((WARN, "cache reads priced below the input rate",
                     f"cache_read multiplier is {cache_read} -- agent sessions "
                     f"are mostly cache reads, so this overstates spend and "
                     f"trips ceilings early"))
    else:
        rows.append((PASS, "price table is populated",
                     f"{len(config['pricing_usd_per_mtok'])} models, cache "
                     f"reads at {cache_read}x input"))

    loop = config.get("loop_detector") or {}
    if loop.get("enabled", True):
        rows.append((PASS, "loop detector enabled",
                     f"{loop.get('consecutive_repeats')} consecutive, "
                     f"{loop.get('max_repeats')} in a window of "
                     f"{loop.get('window')}"))
    else:
        rows.append((WARN, "loop detector enabled",
                     "disabled in config -- a stuck agent will not be stopped"))

    root = os.path.dirname(config_path) if config_path else target
    config["_project_root"] = root
    state = os.path.join(root, config.get("state_dir", ".budget-guard"))
    if writable(state):
        rows.append((PASS, "state directory writable", state))
    else:
        rows.append((FAIL, "state directory writable",
                     f"{state} is not writable -- the loop window cannot "
                     f"persist, so the detector silently never fires"))

    log_dir = os.path.dirname(os.path.join(
        root, config.get("blocked_log", "approvals/budget-blocked.jsonl")))
    if writable(log_dir):
        rows.append((PASS, "blocked-log directory writable", log_dir))
    else:
        rows.append((WARN, "blocked-log directory writable",
                     f"{log_dir} is not writable -- blocks still happen but "
                     f"go unrecorded"))

    return rows, command, config


def transcript(path, messages):
    """Write a synthetic transcript in the harness's own JSONL shape.
    `messages` is a list of (message_id, model, usage)."""
    with open(path, "w") as f:
        for message_id, model, usage in messages:
            f.write(json.dumps({
                "type": "assistant",
                "message": {"id": message_id, "model": model, "usage": usage},
            }) + "\n")
    return path


def tokens_for(usd, rate_per_mtok, multiplier=1.0):
    """How many tokens cost `usd` at a per-million rate. Rounded up so a
    probe aimed above a ceiling lands above it rather than on the boundary."""
    if rate_per_mtok <= 0:
        return 0
    return int(usd * 1_000_000 / (rate_per_mtok * multiplier)) + 1


def budget_probe_config(root, config, **overrides):
    """Write a throwaway config into its own directory.

    A fresh directory per probe is not tidiness. budget_guard keys the daily
    rollup by session id inside state_dir, so probes sharing one would
    accumulate each other's synthetic spend and the third probe would fail
    because of the second. Each probe gets its own world.
    """
    os.makedirs(root, exist_ok=True)
    probe = json.loads(json.dumps(
        {k: v for k, v in config.items() if not k.startswith("_")}))
    probe.update(overrides)
    probe["state_dir"] = ".budget-guard"
    probe["blocked_log"] = "budget-blocked.jsonl"
    path = os.path.join(root, "budget-guard.config.json")
    with open(path, "w") as f:
        json.dump(probe, f)
    return path


def with_config(command, config_path):
    """Point the registered command at a probe config. Rewrites the env
    assignment install.py writes, or adds one if the command has none."""
    quoted = json.dumps(config_path)
    if re.search(r"BUDGET_GUARD_CONFIG=(\"[^\"]+\"|'[^']+'|\S+)", command):
        return re.sub(r"BUDGET_GUARD_CONFIG=(\"[^\"]+\"|'[^']+'|\S+)",
                      f"BUDGET_GUARD_CONFIG={quoted}", command)
    return f"env BUDGET_GUARD_CONFIG={quoted} {command}"


def budget_payload(session_id, transcript_path="", tool="Bash", command="ls"):
    return {
        "session_id": session_id,
        "transcript_path": transcript_path,
        "tool_name": tool,
        "tool_input": {"command": command},
    }


def run_budget_probes(command, config, target, workdir):
    """Yields (status, description, detail). Each probe is self-contained:
    its own config, its own state directory, its own synthetic transcript."""
    model = ("claude-opus-5" if "claude-opus-5" in config["pricing_usd_per_mtok"]
             else next(iter(config["pricing_usd_per_mtok"]), ""))
    row = config["pricing_usd_per_mtok"].get(model) or {"input": 0, "output": 0}
    in_rate = row["input"]
    cache_mult = (config.get("cache_multipliers") or {}).get("cache_read", 0.1)
    session_ceiling = config.get("session_cost_ceiling_usd")
    day_ceiling = config.get("daily_cost_ceiling_usd")
    counter = [0]

    def run(desc, payload, expect, expect_rule=None, **overrides):
        counter[0] += 1
        root = os.path.join(workdir, f"probe{counter[0]}")
        cfg = budget_probe_config(root, config, **overrides)
        code, stderr = run_probe(with_config(command, cfg), payload, target)
        blocked = code == 2
        got = "blocked" if blocked else (
            "allowed" if code == 0 else f"exit {code}")
        m = re.search(r"BLOCKED BY BUDGET GUARD \[([A-Z_]+)\]", stderr)
        rule = m.group(1) if m else None
        if rule:
            got = f"blocked [{rule}]"
        ok = ((blocked and expect == "block") or (code == 0 and expect == "allow"))
        if ok and expect_rule and rule != expect_rule:
            ok, got = False, f"{got}  <-- expected rule {expect_rule}"
        elif not ok:
            got += f"  <-- expected {expect}"
        return (PASS if ok else FAIL), desc, got

    # --- cost ceiling ---
    if in_rate <= 0:
        yield SKIP, "cost ceiling probes", f"no usable input rate for {model}"
    elif session_ceiling is None and day_ceiling is None:
        yield SKIP, "cost ceiling probes", "no ceiling configured"
    else:
        ceiling = session_ceiling if session_ceiling is not None else day_ceiling
        rule = "SESSION_BUDGET" if session_ceiling is not None else "DAILY_BUDGET"
        # Isolate whichever ceiling we are not probing, so a block can only
        # have come from the one under test.
        other = ({"daily_cost_ceiling_usd": None} if session_ceiling is not None
                 else {"session_cost_ceiling_usd": None})

        under = transcript(os.path.join(workdir, "under.jsonl"), [
            ("msg_under", model,
             {"input_tokens": tokens_for(ceiling * 0.1, in_rate)})])
        yield run("spend under the ceiling is allowed",
                  budget_payload("verify-under", under), "allow", **other)

        over = transcript(os.path.join(workdir, "over.jsonl"), [
            ("msg_over", model,
             {"input_tokens": tokens_for(ceiling * 2, in_rate)})])
        yield run("spend over the ceiling blocks",
                  budget_payload("verify-over", over), "block", rule, **other)

        # Sized to 0.3x the ceiling at YOUR configured cache-read multiplier,
        # not at a hardcoded 0.1 -- the probe tests that the multiplier is
        # applied at all, whatever you set it to. If it is ignored and cache
        # reads bill as fresh input, the same transcript costs 0.3/mult times
        # the ceiling (30x at the default 0.1) and blocks.
        cached = transcript(os.path.join(workdir, "cached.jsonl"), [
            ("msg_cache", model,
             {"cache_read_input_tokens":
                 tokens_for(ceiling * 0.3, in_rate, cache_mult)})])
        yield run(f"cache reads priced at the configured {cache_mult}x rate",
                  budget_payload("verify-cache", cached), "allow", **other)

        # One streamed message rewritten five times as it grew. Deduplicated
        # by id it is 0.5x the ceiling; summed line by line it is 2.5x.
        streamed = transcript(os.path.join(workdir, "streamed.jsonl"), [
            ("msg_stream", model,
             {"input_tokens": tokens_for(ceiling * 0.5, in_rate)})] * 5)
        yield run("a streamed message is counted once, not once per line",
                  budget_payload("verify-stream", streamed), "allow", **other)

        # An unknown model ID is what a newly released model looks like from
        # here. Under the default "priciest" policy it must still be billed.
        if config.get("unknown_model_policy") == "ignore":
            yield SKIP, "an unrecognised model is still billed", \
                "unknown_model_policy is 'ignore' -- off by your config"
        else:
            priciest = max(config["pricing_usd_per_mtok"].values(),
                           key=lambda r: r["output"])["input"]
            unknown = transcript(os.path.join(workdir, "unknown.jsonl"), [
                ("msg_unknown", UNKNOWN_MODEL,
                 {"input_tokens": tokens_for(ceiling * 2, priciest)})])
            yield run("an unrecognised model is still billed",
                      budget_payload("verify-unknown", unknown), "block", rule,
                      **other)

        if session_ceiling is not None and day_ceiling is not None:
            day = transcript(os.path.join(workdir, "day.jsonl"), [
                ("msg_day", model,
                 {"input_tokens": tokens_for(day_ceiling * 1.5, in_rate)})])
            yield run("spend over the daily ceiling blocks",
                      budget_payload("verify-day", day), "block",
                      "DAILY_BUDGET", session_cost_ceiling_usd=None)

    # --- loop detector ---
    loop = config.get("loop_detector") or {}
    if not loop.get("enabled", True):
        yield SKIP, "loop detector probes", "disabled in your config"
        return

    consecutive = int(loop.get("consecutive_repeats", 4) or 0)
    max_repeats = int(loop.get("max_repeats", 6) or 0)
    window = max(1, int(loop.get("window", 20) or 1))
    if "Bash" in (loop.get("ignore_tools") or []):
        yield SKIP, "loop detector probes", "Bash is in your ignore_tools"
        return

    limits = [n for n in (consecutive, max_repeats) if n > 0]
    if not limits:
        yield SKIP, "loop detector probes", "both loop limits are disabled"
        return
    trip_at = min(limits)

    def loop_sequence(desc, commands, expect_block_at, expect_rule=None):
        """Replay a call sequence through one shared config, since the
        window is stateful across calls by design."""
        counter[0] += 1
        root = os.path.join(workdir, f"probe{counter[0]}")
        # transcript_path is empty so the cost check returns early and cannot
        # confound the result: this probe is about repetition only.
        cfg = budget_probe_config(root, config,
                                  session_cost_ceiling_usd=None,
                                  daily_cost_ceiling_usd=None)
        cmd = with_config(command, cfg)
        for i, call in enumerate(commands, start=1):
            code, stderr = run_probe(
                cmd, budget_payload("verify-loop", command=call), target)
            m = re.search(r"BLOCKED BY BUDGET GUARD \[([A-Z_]+)\]", stderr)
            rule = m.group(1) if m else None
            if expect_block_at is None:
                if code != 0:
                    return FAIL, desc, f"call {i} of {len(commands)} was blocked [{rule}]"
                continue
            if i < expect_block_at and code != 0:
                return FAIL, desc, f"blocked early, on call {i} of {expect_block_at}"
            if i == expect_block_at:
                if code != 2:
                    return FAIL, desc, f"call {expect_block_at} was not blocked"
                if expect_rule and rule != expect_rule:
                    return FAIL, desc, f"blocked [{rule}], expected {expect_rule}"
                return PASS, desc, f"blocked [{rule}] on call {i}"
        return PASS, desc, f"{len(commands)} distinct calls, none blocked"

    yield loop_sequence(
        f"the same call {trip_at} times in a row blocks",
        ["echo loop-probe  # budget-verify-probe"] * trip_at, trip_at)

    # A,B,A,B never reaches the consecutive limit, so only the window rule can
    # catch it -- and that is the shape a stuck agent actually produces.
    if max_repeats > 0 and window >= 2 * max_repeats - 1 and max_repeats > 1:
        alternating = []
        for i in range(max_repeats):
            alternating.append("echo alt-a  # budget-verify-probe")
            if i < max_repeats - 1:
                alternating.append("echo alt-b  # budget-verify-probe")
        yield loop_sequence(
            f"an alternating A,B loop blocks on the {max_repeats}th repeat",
            alternating, len(alternating), "LOOP_WINDOW")
    else:
        yield SKIP, "an alternating A,B loop blocks", \
            f"window {window} is too short for max_repeats {max_repeats}"

    yield loop_sequence(
        "distinct calls in a row are not blocked",
        [f"echo distinct-{i}  # budget-verify-probe"
         for i in range(trip_at + 2)], None)

    # Documented behaviour, and the one people are most likely to assume is a
    # bug: an unreadable transcript ALLOWS the call. This guard is a budget
    # control, not a safety control, and bricking the agent over a missing log
    # file would be the worse failure.
    counter[0] += 1
    root = os.path.join(workdir, f"probe{counter[0]}")
    cfg = budget_probe_config(root, config)
    missing = os.path.join(workdir, "no-such-transcript.jsonl")
    code, _ = run_probe(with_config(command, cfg),
                        budget_payload("verify-missing", missing), target)
    yield ((PASS if code == 0 else FAIL),
           "an unreadable transcript fails open, by design",
           "allowed" if code == 0 else f"exit {code}  <-- expected allow")


def run_probe(command, payload, target):
    # GATE_GUARD_PROBE tells the guard this invocation came from here, not from
    # the harness, so it is counted separately in the heartbeat. Without it,
    # running this script would itself satisfy `--live` and the liveness check
    # would only ever confirm its own probes.
    env = dict(os.environ, GATE_GUARD_PROBE="1")
    proc = subprocess.run(
        ["sh", "-c", command],
        input=json.dumps(payload),
        capture_output=True, text=True, cwd=target, timeout=60, env=env,
    )
    return proc.returncode, proc.stderr


PROBE_MARKER = "gate-verify-probe"
# How many individual enforcement events the Markdown report lists. The full
# set is always in the JSON form; the printed one is meant to be read.
EVIDENCE_EVENTS = 20


def project_path(target, command, config, key, default):
    """Resolve a config path the way gate_guard.py will: relative to the
    directory holding the config it loads, falling back to the project root
    when no config file exists."""
    rel = (config or {}).get(key, default)
    if not rel:
        return None
    config_path, _ = resolve_config(command, target)
    root = os.path.dirname(config_path) if os.path.isfile(config_path) else target
    return os.path.join(root, rel)


def heartbeat_path(target, command, config):
    """Resolve the heartbeat file the way gate_guard.py will write it: relative
    to the directory holding the config it loads, falling back to the project
    root when no config file exists."""
    return project_path(target, command, config,
                        "heartbeat_path", "approvals/heartbeat.json")


def age_phrase(seconds):
    if seconds < 90:
        return f"{int(seconds)}s ago"
    if seconds < 5400:
        return f"{seconds / 60:.0f} min ago"
    if seconds < 172800:
        return f"{seconds / 3600:.1f} hours ago"
    return f"{seconds / 86400:.1f} days ago"


NEVER_RAN = """
  The hook is registered but there is no evidence it has ever run.

  That is the failure this check exists for: a registered hook that never
  fires looks identical, from inside a session, to a hook that fires and
  allows everything. Work through these in order:

    1. Restart the harness session. settings.json is read at session start;
       a hook added mid-session is not live until you do.
    2. Confirm the settings file the harness actually reads is the one you
       edited -- project .claude/settings.json, not a user-level or
       plugin-declared copy elsewhere.
    3. Run the registered command by hand from the project root:
         echo '{{"tool_name":"Bash","tool_input":{{"command":"ls"}}}}' \\
           | {command}
       If that writes the heartbeat but the harness does not, the guard is
       fine and the wiring is not.
    4. Make one ordinary tool call in the harness, then re-run this check.
"""


SUBAGENT_UNPROVEN = """
  Subagent coverage is UNPROVEN, which is not the same as broken.

  No call recorded so far carried a marker naming a subagent as the caller.
  Four different situations produce that identical result, and this file
  cannot tell them apart on its own:

    a. No subagent has made a tool call since the heartbeat started.
    b. Subagent calls reach the hook, but your harness does not label who
       made them -- the guard is binding, you just cannot attribute calls.
    c. Subagent calls never reach the hook at all. This is the one that
       matters: it means delegation silently widens what the agent may do.
    d. The subagent used a tool your matcher does not select, so no hook
       call was ever generated -- for any agent. This looks identical to
       (c) and is not a harness bug.
{matcher_note}
  To tell them apart, with the heartbeat at {invocations} invocations now:

    1. Have a subagent make ONE ordinary tool call, using a tool your
       matcher actually covers -- see the line above. Rule (d) out first;
       it is the cheapest of the four to eliminate and the easiest to
       mistake for (c).
    2. Re-run this check.
       * invocations went UP and a subagent bucket appeared  -> covered (a).
       * invocations went UP, still no bucket                -> (b).
       * invocations did NOT move, and the tool WAS in your matcher -> (c):
         the hook is not firing for subagent tool calls. Until that is
         fixed, do not delegate an action the main session may not take.
       * invocations did NOT move, and it was NOT in your matcher -> (d).
         Re-probe before reporting anything upstream: a false report of (c)
         is worse than silence, because it buries the real ones.

  Whatever you find, the number above is evidence rather than assumption --
  which is more than the open upstream reports of this have to work with.
"""


def subagent_row(hb, matcher=None):
    """Report whether any subagent call has ever been seen by the guard.

    Deliberately never claims "main session only". A payload with no agent
    marker is equally consistent with a harness that fires the hook for
    subagents without labelling them, and reporting that absence as proof of
    anything would be inventing a result.
    """
    identity = hb.get("identity")
    if not isinstance(identity, dict):
        return (WARN, "subagent coverage",
                "not recorded -- guard predates identity tracking")
    agents = identity.get("agents") if isinstance(identity.get("agents"), dict) else {}
    seen = {k: v for k, v in agents.items()
            if isinstance(v, dict) and v.get("subagent")}
    if identity.get("subagent_coverage") == "observed" and seen:
        names = ", ".join(
            f"{k} ({v.get('invocations', 0)} call"
            f"{'' if v.get('invocations') == 1 else 's'})"
            for k, v in sorted(seen.items())[:3])
        return (PASS, "subagent coverage", f"observed: {names}")
    detail = "unproven -- no call has named a subagent caller"
    if not matcher_covers_everything(matcher):
        detail += f"; matcher {matcher!r} filters tools -- probe with one it covers"
    return (WARN, "subagent coverage", detail)


def liveness_facts(target, max_age_hours):
    """Gather, once, everything both --live and --evidence need.

    --live renders this as a terminal table for the operator who just changed
    something. --evidence renders the same facts as a dated artifact for
    somebody who was not in the room. Neither should be able to drift from the
    other, so there is one gatherer and two renderers.

    Returns a dict. `stop` is None when the check ran to completion; otherwise
    it names why it could not, and `rows` holds whatever was established before
    that point.
    """
    facts = {
        "target": target, "rows": [], "ok": True, "stop": None,
        "command": None, "config": {}, "config_path": None,
        "hb_path": None, "hb": None, "matcher": None,
        "invocations": 0, "probes": 0, "last": None, "age": None,
    }

    facts["matcher"] = find_hook_matcher(target)
    command, err = find_hook_command(target)
    if not command:
        facts["rows"].append(
            (FAIL, "hook registered in .claude/settings.json", err))
        facts["ok"] = False
        facts["stop"] = {"kind": "not-registered", "detail": err}
        return facts
    facts["command"] = command
    facts["rows"].append((PASS, "hook registered in .claude/settings.json", "yes"))

    config_path, _ = resolve_config(command, target)
    facts["config_path"] = config_path
    config = {}
    if os.path.isfile(config_path):
        try:
            with open(config_path) as f:
                config = json.load(f)
        except ValueError as e:
            facts["rows"].append((WARN, "config parses", f"{config_path}: {e}"))
            facts["ok"] = False
    facts["config"] = config

    hb_path = heartbeat_path(target, command, config)
    facts["hb_path"] = hb_path
    if not hb_path:
        facts["ok"] = False
        facts["stop"] = {"kind": "heartbeat-disabled", "detail":
                         "heartbeat_path is disabled in your config"}
        return facts

    try:
        with open(hb_path) as f:
            hb = json.load(f)
    except (FileNotFoundError, ValueError, OSError):
        facts["rows"].append((FAIL, "heartbeat written by the harness",
                              f"{hb_path} absent or unreadable"))
        facts["ok"] = False
        facts["stop"] = {"kind": "never-ran", "detail":
                         f"{hb_path} absent or unreadable"}
        return facts
    facts["hb"] = hb

    invocations = hb.get("invocations") or 0
    probes = hb.get("probe_invocations") or 0
    last = hb.get("last_invocation")
    facts.update({"invocations": invocations, "probes": probes, "last": last})

    if not invocations or not last:
        detail = f"{probes} probe invocation(s) only" if probes else "none recorded"
        facts["rows"].append((FAIL, "heartbeat written by the harness", detail))
        facts["ok"] = False
        facts["stop"] = {"kind": "never-ran", "detail": detail,
                         "probes_only": bool(probes)}
        return facts

    try:
        age = (datetime.now(timezone.utc)
               - datetime.fromisoformat(last)).total_seconds()
    except ValueError:
        age = None
    facts["age"] = age

    if age is None:
        facts["rows"].append((WARN, "last harness invocation",
                              f"unparseable: {last!r}"))
        facts["ok"] = False
    elif age > max_age_hours * 3600:
        facts["rows"].append((WARN, "last harness invocation",
                              f"{age_phrase(age)} -- older than {max_age_hours}h"))
        facts["ok"] = False
    else:
        facts["rows"].append((PASS, "last harness invocation", age_phrase(age)))

    facts["rows"].append((PASS, "invocations recorded",
                          f"{invocations} from the harness, {probes} from verify.py"))
    facts["rows"].append((PASS, "blocks recorded", str(hb.get("blocks") or 0)))
    facts["rows"].append(subagent_row(hb, facts.get("matcher")))
    # A call arriving under bypassPermissions and still reaching this hook is
    # worth stating out loud: it is the setting under which hook coverage is
    # most often assumed and least often checked.
    modes = (hb.get("identity") or {}).get("permission_modes_seen") \
        if isinstance(hb.get("identity"), dict) else None
    if modes:
        facts["rows"].append((PASS, "permission modes seen", ", ".join(modes)))
    if hb.get("last_tool"):
        facts["rows"].append((PASS, "last tool call seen",
                              f"{hb['last_tool']} -> {hb.get('last_decision', '?')}"))

    # Which copy ran. A harness invoking a stale script in another directory,
    # or loading a config other than the one you edited, presents exactly as
    # "my rule change did nothing" -- so name the file, don't just pass it.
    ran_guard = hb.get("guard_path")
    wired_guard = wired_guard_path(command, target)
    if ran_guard and wired_guard and \
            os.path.realpath(ran_guard) != os.path.realpath(wired_guard):
        facts["rows"].append((FAIL, "the copy that ran is the one you wired",
                              f"ran {ran_guard}, settings.json points at {wired_guard}"))
        facts["ok"] = False
    elif ran_guard:
        facts["rows"].append((PASS, "the copy that ran is the one you wired",
                              ran_guard))

    ran_config = hb.get("config_path")
    if os.path.isfile(config_path) and ran_config and \
            os.path.realpath(ran_config) != os.path.realpath(config_path):
        facts["rows"].append((FAIL, "the config it loaded is the one you edited",
                              f"loaded {ran_config}, expected {config_path}"))
        facts["ok"] = False
    elif ran_config:
        facts["rows"].append((PASS, "the config it loaded is the one you edited",
                              ran_config))
    elif os.path.isfile(config_path):
        facts["rows"].append((WARN, "the config it loaded is the one you edited",
                              f"ran with built-in defaults, but {config_path} exists"))
        facts["ok"] = False

    # Edited since it last ran => the live session is still enforcing the old
    # rules. This is the single most common "why didn't my change take" cause.
    if ran_guard and hb.get("guard_mtime") and os.path.isfile(ran_guard):
        try:
            on_disk = datetime.fromtimestamp(
                os.path.getmtime(ran_guard), timezone.utc)
            when_ran = datetime.fromisoformat(hb["guard_mtime"])
            if on_disk > when_ran:
                facts["rows"].append((WARN, "guard unchanged since it last ran",
                                      "edited since -- restart the session to load it"))
                facts["ok"] = False
            else:
                facts["rows"].append(
                    (PASS, "guard unchanged since it last ran", "yes"))
        except (ValueError, OSError):
            pass

    return facts


def check_live(target, max_age_hours):
    """Report whether the harness -- not this script -- has actually invoked
    the guard, and whether the copy it invoked is the one on disk now."""
    print(f"agent-approval-gate: liveness check for {target}\n")
    print("LIVENESS -- has the harness actually called the hook?")
    facts = liveness_facts(target, max_age_hours)
    rows, stop = facts["rows"], facts["stop"]

    if stop and stop["kind"] == "not-registered":
        print(f"  {FAIL:<4}  hook registered in .claude/settings.json    "
              f"{stop['detail']}")
        print("\n  Nothing to check liveness for until the hook is registered. "
              "Run install.py first.")
        return 1

    for row in rows:
        print(f"  {row[0]:<4}  {row[1]:<46}  {row[2]}")

    if stop and stop["kind"] == "heartbeat-disabled":
        print("\n  heartbeat_path is disabled in your config, so liveness "
              "cannot be checked. Set it to a path to enable this.")
        return 1

    if stop and stop["kind"] == "never-ran":
        print(NEVER_RAN.format(command=facts["command"]))
        if stop.get("probes_only"):
            print("  Note: the only invocations on record came from verify.py "
                  "itself. The script runs; the harness is not calling it.")
        return 1

    # Not folded into `ok`: an unproven subagent is the normal state of a fresh
    # install, not a misconfiguration, and failing the check for it would train
    # people to ignore the one line here that reports a real wiring fault.
    matcher = facts.get("matcher")
    if subagent_row(facts["hb"], matcher)[0] != PASS:
        if matcher_covers_everything(matcher):
            matcher_note = (
                "\n  Your matcher is %r, so every tool reaches the guard and\n"
                "  (d) is already ruled out.\n" % (matcher or "*"))
        else:
            matcher_note = (
                "\n  Your matcher is %r. Only those tools reach the guard, so\n"
                "  probe with one of them -- a tool outside this list proves\n"
                "  nothing about subagent coverage.\n" % matcher)
        print(SUBAGENT_UNPROVEN.format(
            invocations=facts["invocations"], matcher_note=matcher_note))

    if facts["ok"]:
        print("\nThe harness is calling the guard, and calling the copy you "
              "think it is.\nThis says nothing about whether the rules are "
              "correct -- run verify.py with no arguments for that.")
        return 0
    print("\nThe guard has run at some point, but something above does not "
          "line up.\nA WARN here means what you edited and what is enforcing "
          "may be different things.")
    return 1


# ---------------------------------------------------------------------------
# --evidence: the same facts, as something you can hand to someone else
# ---------------------------------------------------------------------------
#
# --live answers "is my hook working right now", for the person who just
# changed something. It is a terminal printout and it evaporates.
#
# There is a second, different question: "was this control operating for the
# whole period, and not just at the moment somebody checked?" Design-time
# evidence -- a config file, a screenshot of a passing test -- cannot answer
# it. Operating evidence can, and that is what the heartbeat plus the blocked
# log already are; they were simply never packaged as something portable.
#
# So --evidence renders a dated, self-contained report: what the control is,
# what window it covers, how many calls the harness routed through it, what it
# blocked and when, which exact files were running (by digest), and -- at
# equal weight, section 5 -- what none of this proves. The limits section is
# not a disclaimer. An evidence artifact that overstates itself is worth less
# than none, because the first competent reader who finds the overstatement
# stops believing the rest.

LIMITS = [
    ("Counters are a lower bound, never an overcount.",
     "The heartbeat is a best-effort read-modify-write. Two hook processes "
     "finishing at once can lose an increment. Where this report says N calls "
     "were routed through the gate, the true number is N or more."),
    ("This is the operator's own record, not a third party's.",
     "Every file cited here lives on the machine being reported on, and "
     "anyone with write access to it could edit them. The digests below "
     "detect accidental change and drift between copies; they are not "
     "tamper-proof against the report's own author, and nothing self-hosted "
     "could be."),
    ("An absent subagent marker proves nothing either way.",
     "If no call has ever named a subagent caller, that is equally consistent "
     "with no subagent having run, with subagent calls arriving unlabelled, "
     "and with subagent calls never reaching the hook at all. Only a positive "
     "marker proves coverage, which is why the coverage line reads 'unproven' "
     "rather than 'main session only'."),
    ("Coverage is continuous only if the harness ran continuously.",
     "The window below is first invocation to last. Gaps inside it are not "
     "detectable from the heartbeat -- a harness that was switched off, or "
     "running without the hook registered, leaves no mark. This report shows "
     "that the gate was live at the ends of the window and busy in between; "
     "it does not certify that no tool call ever bypassed it."),
    ("Blocks are what the rules matched, not what was actually dangerous.",
     "Rule matching is textual. A block is evidence the control fired, not "
     "evidence the blocked action would have caused harm -- and an absence of "
     "blocks is not evidence that nothing was attempted."),
]


def sha256_file(path):
    """Digest a file in chunks. Returns None rather than raising: a missing
    artifact is a fact to report, not a reason to produce no report."""
    if not path or not os.path.isfile(path):
        return None
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except OSError:
        return None
    return "sha256:" + h.hexdigest()


def file_facts(path):
    out = {"path": path, "present": bool(path and os.path.isfile(path)),
           "sha256": None, "bytes": None, "modified": None}
    if out["present"]:
        out["sha256"] = sha256_file(path)
        try:
            st = os.stat(path)
            out["bytes"] = st.st_size
            out["modified"] = datetime.fromtimestamp(
                st.st_mtime, timezone.utc).isoformat()
        except OSError:
            pass
    return out


def duration_phrase(seconds):
    if seconds is None:
        return "unknown"
    if seconds < 90:
        return f"{seconds:.0f} seconds"
    if seconds < 3600:
        return f"{seconds / 60:.0f} minutes"
    if seconds < 172800:
        return f"{seconds / 3600:.1f} hours"
    return f"{seconds / 86400:.1f} days"


def read_block_log(path, window_start, window_end, include_attempts):
    """Summarise the blocked-action log: how many real blocks, which rules,
    and when. Probe blocks written by verify.py are separated out rather than
    dropped, because a report that silently discards records is a report that
    can be argued with."""
    # A window only exists if the heartbeat established one. With no window,
    # these records cannot be attributed to a period of operation at all --
    # counting them as "in window" would let a report with no liveness
    # evidence still present a tally that reads like enforcement history.
    out = {"path": path, "present": False, "readable": True, "lines": 0,
           "malformed": 0, "probes": 0, "in_window": 0, "before_window": 0,
           "window_known": bool(window_start and window_end),
           "by_rule": {}, "by_tier": {}, "events": [],
           "first": None, "last": None}
    if not path or not os.path.isfile(path):
        return out
    out["present"] = True
    try:
        with open(path) as f:
            raw = f.readlines()
    except OSError:
        out["readable"] = False
        return out

    for line in raw:
        line = line.strip()
        if not line:
            continue
        out["lines"] += 1
        try:
            entry = json.loads(line)
        except ValueError:
            out["malformed"] += 1
            continue
        if not isinstance(entry, dict):
            out["malformed"] += 1
            continue
        if PROBE_MARKER in str(entry.get("attempted", "")):
            out["probes"] += 1
            continue
        ts = entry.get("ts")
        when = None
        if ts:
            try:
                when = datetime.fromisoformat(ts)
            except ValueError:
                when = None
        if when and window_start and when < window_start:
            out["before_window"] += 1
            continue
        if when and window_end and when > window_end:
            # Later than the last recorded invocation: the log is ahead of the
            # heartbeat. Counted, and visible in the totals, but not silently
            # folded into the window.
            out["before_window"] += 0
        out["in_window"] += 1
        rule = entry.get("rule") or "(none)"
        out["by_rule"][rule] = out["by_rule"].get(rule, 0) + 1
        tier = entry.get("trust_tier_at_block")
        if tier is not None:
            key = str(tier)
            out["by_tier"][key] = out["by_tier"].get(key, 0) + 1
        if ts:
            out["first"] = min(out["first"], ts) if out["first"] else ts
            out["last"] = max(out["last"], ts) if out["last"] else ts
        event = {"ts": ts, "rule": rule, "tool": entry.get("tool"),
                 "trust_tier_at_block": tier}
        if include_attempts:
            event["attempted"] = entry.get("attempted")
        out["events"].append(event)
    return out


def evidence_report(target, max_age_hours, include_attempts=False):
    """Build the report as data. Rendering is separate, so the JSON and the
    Markdown can never disagree about a number."""
    generated = datetime.now(timezone.utc)
    facts = liveness_facts(target, max_age_hours)
    hb = facts["hb"] or {}
    # Whether the guard's own counters were readable at all. When the heartbeat
    # is absent, disabled or unparseable there is no counter to report -- and
    # reporting the 0 that `hb.get(...) or 0` yields would state, in the summary
    # table, that this gate has never blocked anything. On a project whose block
    # log holds hundreds of records that is simply a false sentence, and it is
    # the sentence a reader who only reads section 1 walks away with. Unknown
    # and zero are different findings; the renderers below keep them apart.
    counters_known = facts["hb"] is not None
    config = facts["config"] or {}
    command = facts["command"]

    first = hb.get("first_invocation")
    last = hb.get("last_invocation")
    span = None
    win_start = win_end = None
    for value, slot in ((first, "start"), (last, "end")):
        if not value:
            continue
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            continue
        if slot == "start":
            win_start = parsed
        else:
            win_end = parsed
    if win_start and win_end:
        span = (win_end - win_start).total_seconds()

    blocked_log = None
    if command:
        blocked_log = project_path(target, command, config, "blocked_log",
                                   "approvals/blocked.jsonl")
    blocks = read_block_log(blocked_log, win_start, win_end, include_attempts)

    identity = hb.get("identity") if isinstance(hb.get("identity"), dict) else {}
    rule_ids = sorted(i for i in configured_rule_ids(config) if i)

    state_path = None
    tier = None
    if command:
        state_path = project_path(target, command, config, "state_path", "STATE.json")
    if state_path and os.path.isfile(state_path):
        try:
            with open(state_path) as f:
                tier = json.load(f).get(
                    config.get("trust_tier_field", "trust_tier"))
        except (ValueError, OSError):
            tier = None

    body = {
        "report": "gate-enforcement-evidence",
        "schema": 1,
        "generated_at": generated.isoformat(),
        "generated_by": "agent-approval-gate verify.py --evidence",
        "project": target,
        "status": {
            "control_active": bool(facts["ok"] and not facts["stop"]),
            "reason": (facts["stop"] or {}).get("kind"),
            "checks_passed": sum(1 for r in facts["rows"] if r[0] == PASS),
            "checks_warned": sum(1 for r in facts["rows"] if r[0] == WARN),
            "checks_failed": sum(1 for r in facts["rows"] if r[0] == FAIL),
        },
        "window": {
            "first_invocation": first,
            "last_invocation": last,
            "seconds": span,
            "human": duration_phrase(span),
            "last_invocation_age_seconds": facts["age"],
            "stale_after_hours": max_age_hours,
        },
        "activity": {
            # null, not 0, when the heartbeat could not be read: see
            # counters_known above. A consumer testing `== 0` would otherwise
            # read "never fired" out of "never measured".
            "counters_known": counters_known,
            "harness_invocations": facts["invocations"] if counters_known else None,
            "verify_probe_invocations": facts["probes"] if counters_known else None,
            "blocks_recorded_by_guard": (hb.get("blocks") or 0) if counters_known else None,
            "last_tool": hb.get("last_tool"),
            "last_decision": hb.get("last_decision"),
            "last_rule": hb.get("last_rule"),
            "permission_modes_seen": identity.get("permission_modes_seen") or [],
            "subagent_coverage": identity.get("subagent_coverage") or "unproven",
            "callers_seen": {
                name: {"invocations": row.get("invocations"),
                       "blocks": row.get("blocks"),
                       "subagent": bool(row.get("subagent")),
                       "first_seen": row.get("first_seen"),
                       "last_seen": row.get("last_seen")}
                for name, row in sorted(
                    (identity.get("agents") or {}).items())
                if isinstance(row, dict)},
        },
        "control": {
            "hook_command": command,
            "rule_ids_configured": rule_ids,
            "rule_ids_source": "config" if rule_ids else "built-in defaults",
            "protected_paths": config.get("protected_paths") or [],
            "trust_tier_at_report": tier,
            "min_tier_for_tier_gated": config.get("min_tier_for_tier_gated"),
        },
        "enforcement": blocks,
        "checks": [{"status": s, "check": label, "detail": detail}
                   for s, label, detail in facts["rows"]],
        "artifacts": {
            "guard_that_ran": file_facts(hb.get("guard_path")),
            "guard_wired_in_settings": file_facts(
                wired_guard_path(command, target) if command else None),
            "config": file_facts(facts["config_path"]),
            "heartbeat": file_facts(facts["hb_path"]),
            "blocked_log": file_facts(blocked_log),
            "verifier": file_facts(os.path.abspath(__file__)),
        },
        "limits": [{"claim": head, "detail": detail} for head, detail in LIMITS],
    }
    # Digest of the body as rendered, so two copies of this report can be
    # compared for equality without reading them. Computed last and stored
    # outside the body it covers -- a digest that included itself could not be
    # recomputed by the reader, which would make it decorative.
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return {"body": body,
            "digest": "sha256:" + hashlib.sha256(
                canonical.encode("utf-8")).hexdigest()}


def render_evidence_markdown(report):
    b = report["body"]
    L = []
    add = L.append
    status = b["status"]
    active = status["control_active"]

    add("# Gate enforcement evidence")
    add("")
    add(f"**Project:** `{b['project']}`  ")
    add(f"**Generated:** {b['generated_at']} (UTC)  ")
    add(f"**Report digest:** `{report['digest']}`")
    add("")
    add("Produced by `verify.py --evidence` from "
        "[agent-approval-gate](https://github.com/Prime-agentai/agent-approval-gate). "
        "Read section 5 before relying on anything above it.")
    add("")

    add("## 1. Summary")
    add("")
    add("| | |")
    add("|---|---|")
    add(f"| Control status at report time | **{'ACTIVE' if active else 'NOT ESTABLISHED'}** |")
    w = b["window"]
    if w["first_invocation"] and w["last_invocation"]:
        add(f"| Evidence window | {w['first_invocation']} → {w['last_invocation']} |")
        add(f"| Window length | {w['human']} |")
    a = b["activity"]
    e0 = b["enforcement"]
    if a["counters_known"]:
        add(f"| Tool calls the harness routed through the gate | "
            f"{a['harness_invocations']:,} |")
        add(f"| Calls blocked by the gate | {a['blocks_recorded_by_guard']:,} |")
    else:
        # The counters live in the heartbeat, and there isn't one. Both rows
        # would print 0, and a summary-only reader would take that as "this
        # gate has never stopped anything" -- when the block log two sections
        # down may hold hundreds of records. Point at the log instead of
        # printing a zero we cannot stand behind.
        add("| Tool calls the harness routed through the gate | unknown — no "
            "heartbeat to count them, see §2 |")
        logged = e0["lines"] if (e0["present"] and e0["readable"]) else None
        add("| Calls blocked by the gate | unknown — no heartbeat counter"
            + (f"; {logged:,} record(s) in the block log, see §4" if logged
               else "")
            + " |")
    # Without the log there is nothing to count rules from. Printing 0 would
    # read as "no rule ever fired", which is a different claim from "the
    # per-rule breakdown is unavailable" -- and the block count above may well
    # be non-zero.
    if not (e0["present"] and e0["readable"]):
        add("| Distinct rules that fired | unavailable — no readable "
            "blocked-action log |")
    elif e0["window_known"]:
        add(f"| Distinct rules that fired in the window | {len(e0['by_rule'])} |")
    else:
        add(f"| Distinct rules in the block log | {len(e0['by_rule'])} "
            "(not attributable to a window — see §4) |")
    add(f"| Liveness checks passed / warned / failed | "
        f"{status['checks_passed']} / {status['checks_warned']} / {status['checks_failed']} |")
    add(f"| Subagent coverage | {a['subagent_coverage']} |")
    if a["permission_modes_seen"]:
        add(f"| Permission modes observed | {', '.join(a['permission_modes_seen'])} |")
    add("")
    if not active:
        add(f"> **This report does not evidence an operating control.** "
            f"Reason: `{status['reason'] or 'one or more checks did not pass'}`. "
            f"The sections below are reported as found, and section 2 names "
            f"what did not line up.")
        add("")

    add("## 2. Was the control operating?")
    add("")
    add("Each row was established by reading the heartbeat `gate_guard.py` "
        "writes on every invocation -- not by running the guard from this "
        "script, which would prove only that the script works.")
    add("")
    add("| | Check | Evidence |")
    add("|---|---|---|")
    for row in b["checks"]:
        detail = str(row["detail"]).replace("|", "\\|")
        add(f"| {row['status']} | {row['check']} | {detail} |")
    add("")

    add("## 3. What the control is")
    add("")
    c = b["control"]
    add(f"- **Hook command:** `{c['hook_command'] or '(none registered)'}`")
    add(f"- **Rules configured ({c['rule_ids_source']}):** "
        + (", ".join(f"`{r}`" for r in c["rule_ids_configured"]) or "_none listed_"))
    if c["protected_paths"]:
        add("- **Files no agent tool call may write:** "
            + ", ".join(f"`{p}`" for p in c["protected_paths"]))
    if c["trust_tier_at_report"] is not None:
        add(f"- **Trust tier at report time:** {c['trust_tier_at_report']}"
            + (f" (tier-gated rules apply below {c['min_tier_for_tier_gated']})"
               if c["min_tier_for_tier_gated"] is not None else ""))
    add("")
    callers = a["callers_seen"]
    if callers:
        add("**Callers the harness routed through the gate.** Whether a "
            "control binds on delegated work is usually assumed; this is the "
            "measurement. See the coverage limit in section 5.")
        add("")
        add("| Caller | Subagent | Calls | Blocked | First seen | Last seen |")
        add("|---|---|---|---|---|---|")
        for name, row in callers.items():
            add(f"| `{name}` | {'yes' if row['subagent'] else 'not marked'} | "
                f"{row.get('invocations') or 0:,} | {row.get('blocks') or 0:,} | "
                f"{row.get('first_seen') or '—'} | {row.get('last_seen') or '—'} |")
        add("")

    add("## 4. Enforcement events")
    add("")
    e = b["enforcement"]
    if not e["present"]:
        if b["activity"]["counters_known"]:
            add(f"No blocked-action log at `{e['path']}`. The guard records "
                "block counts in the heartbeat regardless, so section 1's "
                "block count still stands; the per-event detail below is "
                "unavailable.")
        else:
            # Neither source exists. The old wording sent the reader back to a
            # section 1 count that is itself unknown, which reads as a
            # corroboration between two absences.
            add(f"No blocked-action log at `{e['path']}`, and no heartbeat "
                "counter either (section 2). This report can say nothing "
                "about whether the gate has ever blocked anything.")
    elif not e["readable"]:
        add(f"`{e['path']}` exists but could not be read.")
    else:
        counted = "counted" if e["window_known"] else "counted, UNATTRIBUTED"
        add(f"Source: `{e['path']}` — {e['lines']:,} record(s) total, "
            f"{e['probes']:,} written by `verify.py` probes and excluded, "
            f"{e['before_window']:,} predating this window and excluded, "
            f"**{e['in_window']:,} {counted}**"
            + (f", {e['malformed']:,} unparseable" if e["malformed"] else "") + ".")
        add("")
        if not e["window_known"]:
            add("> **These records are not attributed to an operating "
                "period.** Section 2 could not establish a window, so while "
                "the log shows blocks were written at some point, nothing "
                "here evidences that the control was operating across any "
                "particular span. Read the counts below as history of the "
                "file, not as evidence of coverage.")
            add("")
        if e["by_rule"]:
            add("| Rule | Times fired |")
            add("|---|---|")
            for rule, n in sorted(e["by_rule"].items(), key=lambda kv: -kv[1]):
                add(f"| `{rule}` | {n:,} |")
            add("")
        if e["events"]:
            recent = e["events"][-EVIDENCE_EVENTS:]
            add(f"Most recent {len(recent)} of {len(e['events'])}:")
            add("")
            head = "| When (UTC) | Rule | Tool |"
            sep = "|---|---|---|"
            if any("attempted" in ev for ev in recent):
                head += " Attempted |"
                sep += "---|"
            add(head)
            add(sep)
            for ev in reversed(recent):
                line = (f"| {ev.get('ts') or '?'} | `{ev.get('rule')}` | "
                        f"{ev.get('tool') or '?'} |")
                if "attempted" in ev:
                    text = str(ev.get("attempted") or "")[:120].replace("|", "\\|")
                    line += f" `{text}` |"
                add(line)
            add("")
            if not any("attempted" in ev for ev in recent):
                add("_The text of each blocked action is held back by default, "
                    "because it is the operator's command history and is not "
                    "needed to evidence that the control fired. Re-run with "
                    "`--include-attempts` to include it._")
                add("")
        # Only a discrepancy if there are two numbers to disagree. With no
        # heartbeat there is one source, not two, and calling that a
        # discrepancy would invent a conflict out of a missing file.
        if (b["activity"]["counters_known"]
                and e["in_window"] != b["activity"]["blocks_recorded_by_guard"]):
            add(f"> **Note a discrepancy rather than hiding it:** the guard's "
                f"own counter says {b['activity']['blocks_recorded_by_guard']:,} "
                f"block(s); this log yields {e['in_window']:,} in-window "
                f"record(s). Both writes are best-effort and neither is "
                f"authoritative over the other. The likely causes are a log "
                f"rotated or edited after the fact, a counter that lost a "
                f"concurrent increment, or blocks predating the current log "
                f"file.")
            add("")

    add("")
    add("## 5. What this evidence does not prove")
    add("")
    add("Stated at the same weight as the rest, and worth reading before "
        "citing any number above.")
    add("")
    for item in b["limits"]:
        add(f"- **{item['claim']}** {item['detail']}")
    add("")

    add("## 6. Exactly which files were running")
    add("")
    add("An enforcement claim is about specific bytes. These are the ones this "
        "report is about; digest them yourself to confirm you are looking at "
        "the same thing.")
    add("")
    add("| Artifact | Path | Digest | Bytes | Modified (UTC) |")
    add("|---|---|---|---|---|")
    labels = {
        "guard_that_ran": "Guard the harness actually invoked",
        "guard_wired_in_settings": "Guard named in settings.json",
        "config": "Gate config",
        "heartbeat": "Heartbeat (source of section 2)",
        "blocked_log": "Blocked-action log (source of section 4)",
        "verifier": "This verifier",
    }
    for key, label in labels.items():
        f = b["artifacts"].get(key) or {}
        if not f.get("path"):
            continue
        digest = f.get("sha256") or "_absent_"
        size = f"{f['bytes']:,}" if f.get("bytes") is not None else "—"
        add(f"| {label} | `{f['path']}` | `{digest}` | {size} | "
            f"{f.get('modified') or '—'} |")
    add("")
    add("---")
    add("")
    add(f"Report digest `{report['digest']}` covers every field of the JSON "
        "form of this report (`--evidence --format json`), canonicalised with "
        "sorted keys. Recompute it to detect accidental modification; see "
        "section 5 on what it is not.")
    add("")
    return "\n".join(L)


def check_evidence(target, max_age_hours, fmt, out_path, include_attempts):
    report = evidence_report(target, max_age_hours, include_attempts)
    if fmt == "json":
        text = json.dumps({**report["body"], "report_digest": report["digest"]},
                          indent=2) + "\n"
    else:
        text = render_evidence_markdown(report)

    if out_path:
        try:
            directory = os.path.dirname(os.path.abspath(out_path))
            if directory:
                os.makedirs(directory, exist_ok=True)
            with open(out_path, "w") as f:
                f.write(text)
        except OSError as e:
            print(f"could not write {out_path}: {e}", file=sys.stderr)
            return 1
        print(f"wrote {out_path}  ({len(text):,} bytes)")
        print(f"digest {report['digest']}")
    else:
        sys.stdout.write(text)

    # Exit code carries the finding, so this is usable in a scheduled job: 0
    # means an operating control was evidenced, 1 means the report was still
    # produced but says the control was not established. A report that always
    # exits 0 would let a broken gate pass a nightly check silently.
    return 0 if report["body"]["status"]["control_active"] else 1


# ---------------------------------------------------------------------------
# over-block analysis -- what does this gate cost you when you were not doing
# the thing it exists to stop?
# ---------------------------------------------------------------------------
#
# Every deterministic guardrail in this category blocks on a regex, and a
# regex has no idea which tool it is looking at. So the interesting question
# for anyone deciding whether to run one unattended is not "does it block" --
# it is "how often does it block me for nothing", and nobody publishes that
# number about their own rules.
#
# This is one narrow, machine-decidable slice of that question. It does not
# read the blocked text and it does not judge intent. It asks only: could the
# tool that was blocked have carried out the action the rule exists to stop?
# Writing a file cannot move funds. Fetching a URL cannot create an account.
# A block of that shape prevented nothing, whatever the text said.
#
# The model below is a DECLARATION, not a measurement, so it is printed with
# the result and is overridable from your gate-guard config -- change it and
# the number changes, which is the point. Anything it does not recognise is
# reported as not adjudicable and never counted as an over-block, so the
# headline is a floor and not an estimate.

# What each tool is physically able to do. A tool absent from this map is
# unknown, not harmless.
TOOL_CAPABILITIES = {
    "Bash": ["exec", "persist"],
    "BashOutput": ["exec", "persist"],
    "KillShell": ["exec", "persist"],
    "Write": ["persist"],
    "Edit": ["persist"],
    "MultiEdit": ["persist"],
    "NotebookEdit": ["persist"],
    "WebFetch": [],
    "WebSearch": [],
    "Read": [],
    "Grep": [],
    "Glob": [],
}

# What the action behind each rule actually requires.
#   exec    -- must run a command or make a network write to happen at all
#   persist -- happens as soon as the text lands somewhere it survives
RULE_REQUIRES = {
    "FUND_MOVEMENT": "exec",
    "CONTRACT_DEPLOY": "exec",
    "PAYMENT_API_WRITE": "exec",
    "ACCOUNT_SIGNUP_FLOW": "exec",
    "PACKAGE_INSTALL": "exec",
    "DOMAIN_REGISTRAR": "exec",
    "GIT_PUSH_UNAPPROVED": "exec",
    "KEY_MATERIAL": "persist",
    "SECRET_IN_COMMAND": "persist",
    "PROTECTED_FILE": "persist",
    "PROTECTED_FILE_SHELL": "persist",
}


def capability_model(config):
    """Merge any declarations from the gate-guard config over the defaults.
    A project with its own rule ids or a harness with its own tool names can
    make this analysis apply to it without editing this file."""
    tools = dict(TOOL_CAPABILITIES)
    rules = dict(RULE_REQUIRES)
    overrides = {"tools": [], "rules": []}
    for key, target, bucket in (("tool_capabilities", tools, "tools"),
                                ("rule_requires", rules, "rules")):
        declared = (config or {}).get(key)
        if isinstance(declared, dict):
            for name, value in declared.items():
                overrides[bucket].append(name)
                target[name] = value
    return tools, rules, overrides


def adjudicate_block(rule, tool, tools, rules):
    """Return (verdict, reason). The only verdict that accuses the gate of
    anything is 'over_block', and it is reachable only when both the rule and
    the tool are declared."""
    if rule not in rules:
        return "undeclared_rule", f"no declared requirement for rule {rule}"
    if tool not in tools:
        return "undeclared_tool", f"no declared capabilities for tool {tool}"
    required = rules[rule]
    if required in (tools[tool] or []):
        return "capable", f"{tool} can {required}"
    return "over_block", f"{tool} cannot {required}"


def over_block_report(target, log_override=None):
    """Build the analysis as data. Rendering is separate, so the text and the
    JSON can never disagree about a number."""
    generated = datetime.now(timezone.utc)
    _, command, config, _ = check_wiring(target)
    path = log_override or project_path(
        target, command, config, "blocked_log", "approvals/blocked.jsonl")
    if not path:
        path = os.path.join(target, "approvals/blocked.jsonl")
    path = os.path.abspath(path)

    tools, rules, overrides = capability_model(config)
    log = read_block_log(path, None, None, False)

    counts = {"over_block": 0, "capable": 0,
              "undeclared_rule": 0, "undeclared_tool": 0}
    by_pair = {}
    for event in log["events"]:
        rule = event.get("rule") or "(none)"
        tool = event.get("tool") or "(none)"
        verdict, reason = adjudicate_block(rule, tool, tools, rules)
        counts[verdict] += 1
        key = f"{rule}\t{tool}"
        row = by_pair.setdefault(
            key, {"rule": rule, "tool": tool, "verdict": verdict,
                  "reason": reason, "count": 0, "first": None, "last": None})
        row["count"] += 1
        ts = event.get("ts")
        if ts:
            row["first"] = min(row["first"], ts) if row["first"] else ts
            row["last"] = max(row["last"], ts) if row["last"] else ts

    total = sum(counts.values())
    adjudicable = counts["over_block"] + counts["capable"]
    return {
        "generated_utc": generated.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": target,
        "log": {"path": path, "present": log["present"],
                "readable": log["readable"], "lines": log["lines"],
                "malformed": log["malformed"], "probes_excluded": log["probes"],
                "first": log["first"], "last": log["last"]},
        "analysed": total,
        "counts": counts,
        "rates": {
            "over_block_of_adjudicable":
                round(counts["over_block"] / adjudicable, 4) if adjudicable else None,
            "over_block_of_all":
                round(counts["over_block"] / total, 4) if total else None,
            "adjudicable_of_all":
                round(adjudicable / total, 4) if total else None,
        },
        "pairs": sorted(by_pair.values(),
                        key=lambda r: (-r["count"], r["rule"], r["tool"])),
        "model": {"tools": tools, "rules": rules, "overridden": overrides},
    }


def pct(value):
    return "n/a" if value is None else f"{value * 100:.1f}%"


def render_over_blocks(report):
    L = []
    add = L.append
    log = report["log"]
    add(f"agent-approval-gate: over-block analysis  ({report['generated_utc']})")
    add(f"  log      {log['path']}")

    if not log["present"]:
        add("")
        add("  No blocked-action log at that path. Nothing to analyse -- this "
            "is not a clean bill of health, it is an absence of data. Point "
            "--log at your log, or check blocked_log in your gate-guard "
            "config.")
        return "\n".join(L) + "\n"
    if not log["readable"]:
        add("")
        add("  The log exists but could not be read. Fix that before trusting "
            "any number here.")
        return "\n".join(L) + "\n"

    span = f"{log['first']} .. {log['last']}" if log["first"] else "unknown"
    add(f"  window   {span}")
    add(f"  records  {report['analysed']:,} real blocks"
        + (f", {log['probes_excluded']:,} verify.py probes excluded"
           if log["probes_excluded"] else "")
        + (f", {log['malformed']:,} malformed lines skipped"
           if log["malformed"] else ""))

    if not report["analysed"]:
        add("")
        add("  The log is empty of real blocks. Nothing to adjudicate.")
        return "\n".join(L) + "\n"

    c = report["counts"]
    r = report["rates"]
    add("")
    add("VERDICTS")
    add(f"  over-block        {c['over_block']:>5}   the blocked tool could "
        "not have performed the gated action")
    add(f"  capable           {c['capable']:>5}   the blocked tool could have "
        "-- says nothing about whether it would")
    add(f"  rule undeclared   {c['undeclared_rule']:>5}   not adjudicable")
    add(f"  tool undeclared   {c['undeclared_tool']:>5}   not adjudicable")
    add("")
    add(f"  {c['over_block']:,} of {c['over_block'] + c['capable']:,} "
        f"adjudicable blocks were structurally unnecessary "
        f"({pct(r['over_block_of_adjudicable'])}).")
    add(f"  Against the whole log that is {pct(r['over_block_of_all'])}; "
        f"{pct(r['adjudicable_of_all'])} of records were adjudicable at all.")

    over = [p for p in report["pairs"] if p["verdict"] == "over_block"]
    if over:
        add("")
        add("OVER-BLOCKS BY RULE AND TOOL")
        for p in over:
            add(f"  {p['count']:>5}  {p['rule']:<22} {p['tool']:<12} "
                f"{p['reason']}")

    undeclared = [p for p in report["pairs"]
                  if p["verdict"].startswith("undeclared")]
    if undeclared:
        add("")
        add("NOT ADJUDICABLE -- declare these to bring them into the count")
        for p in undeclared:
            add(f"  {p['count']:>5}  {p['rule']:<22} {p['tool']:<12} "
                f"{p['reason']}")
        add("")
        add("  Add rule_requires / tool_capabilities to your gate-guard "
            "config. Until then these are excluded from both sides of the "
            "ratio, not assumed correct.")

    model = report["model"]
    add("")
    add("THE MODEL THIS RESTS ON  (declared, not measured -- override it in "
        "your gate-guard config)")
    for name, required in sorted(model["rules"].items()):
        mark = " *" if name in model["overridden"]["rules"] else ""
        add(f"  rule {name:<24} needs  {required}{mark}")
    for name, caps in sorted(model["tools"].items()):
        mark = " *" if name in model["overridden"]["tools"] else ""
        add(f"  tool {name:<24} can    {', '.join(caps) or '(nothing gated)'}{mark}")
    if model["overridden"]["rules"] or model["overridden"]["tools"]:
        add("  * declared by your config, not a default of this tool")

    add("")
    add("WHAT THIS NUMBER IS NOT")
    add("  - It is a FLOOR, not the over-block rate. A block on a tool that "
        "could have done the thing is still very often a false positive -- "
        "a read-only shell command that merely names a protected file, say. "
        "This analysis cannot see that and does not try.")
    add("  - It does not say the remaining blocks were correct. 'Capable' "
        "means possible, not intended.")
    add("  - The capability model is a declaration, printed above so you can "
        "argue with it. If you disagree, override it and rerun; a number you "
        "cannot change is a number you cannot check.")
    add("  - It reads only what the log recorded. Actions the gate never saw "
        "are invisible here, and a gate that never fired produces a "
        "flawless-looking zero.")
    add("")
    return "\n".join(L) + "\n"


def check_over_blocks(target, fmt, out_path, log_override, max_rate):
    report = over_block_report(target, log_override)
    if fmt == "json":
        text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    else:
        text = render_over_blocks(report)

    if out_path:
        try:
            directory = os.path.dirname(os.path.abspath(out_path))
            if directory:
                os.makedirs(directory, exist_ok=True)
            with open(out_path, "w") as f:
                f.write(text)
        except OSError as e:
            print(f"could not write {out_path}: {e}", file=sys.stderr)
            return 1
        print(f"wrote {out_path}  ({len(text):,} bytes)")
    else:
        sys.stdout.write(text)

    # No log and no records are findings, not passes: exiting 0 there would
    # let "the gate has never run" read the same as "the gate never misfired".
    if not report["log"]["present"] or not report["log"]["readable"]:
        return 1
    if not report["analysed"]:
        return 1
    if max_rate is not None:
        rate = report["rates"]["over_block_of_adjudicable"]
        if rate is not None and rate * 100 > max_rate:
            print(f"over-block rate {pct(rate)} exceeds the "
                  f"{max_rate:.1f}% you allowed", file=sys.stderr)
            return 1
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="Verify an installed agent-approval-gate is live and blocking.")
    ap.add_argument("--target", default=os.getcwd(),
                    help="Project root to check (default: current directory)")
    ap.add_argument("--skip-budget", action="store_true",
                    help="Check only the approval gate, not the budget guard")
    ap.add_argument("--live", action="store_true",
                    help="Check only whether the HARNESS has actually invoked "
                         "the hook (registered is not the same as running), "
                         "using the heartbeat gate_guard.py writes")
    ap.add_argument("--max-age", type=float, default=24.0, metavar="HOURS",
                    help="With --live, how old the last harness invocation may "
                         "be before it is flagged stale (default: 24)")
    ap.add_argument("--evidence", action="store_true",
                    help="Render the same liveness facts as a dated, portable "
                         "evidence report -- what the control is, what window "
                         "it covers, what it blocked, which files were "
                         "running, and what none of it proves. Exits 1 if it "
                         "cannot evidence an operating control")
    ap.add_argument("--over-blocks", action="store_true",
                    help="Check only what this gate has COST you: how many "
                         "of its recorded blocks fired on a tool that could "
                         "not have performed the gated action at all. A "
                         "floor on the false-positive rate, not an estimate. "
                         "Exits 1 if there is nothing to analyse, or if the "
                         "rate exceeds --max-over-block-rate")
    ap.add_argument("--log", metavar="PATH",
                    help="With --over-blocks, analyse this blocked-action log "
                         "instead of the one your gate-guard config names")
    ap.add_argument("--max-over-block-rate", type=float, metavar="PCT",
                    help="With --over-blocks, exit 1 if the over-block share "
                         "of adjudicable blocks exceeds PCT percent")
    ap.add_argument("--format", choices=("md", "json"), default="md",
                    help="With --evidence, the output format (default: md)")
    ap.add_argument("--out", metavar="PATH",
                    help="With --evidence, write to PATH instead of stdout")
    ap.add_argument("--include-attempts", action="store_true",
                    help="With --evidence, include the text of each blocked "
                         "action. Held back by default: it is your command "
                         "history, and it is not needed to evidence that the "
                         "control fired")
    args = ap.parse_args()
    target = os.path.abspath(args.target)

    if args.over_blocks:
        return check_over_blocks(target, args.format, args.out, args.log,
                                 args.max_over_block_rate)

    if args.evidence:
        return check_evidence(target, args.max_age, args.format, args.out,
                              args.include_attempts)

    if args.live:
        return check_live(target, args.max_age)

    print(f"agent-approval-gate: verifying {target}\n")
    print("WIRING -- approval gate")
    rows, command, config, state_abspath = check_wiring(target)
    for status, label, detail in rows:
        print(f"  {status:<4}  {label:<46}  {detail}")

    if not command:
        print("\nNo registered hook to probe. Run install.py first, then "
              "restart your harness session so it reloads settings.json.")
        return 1

    # An empty config means the built-in defaults are in force. Those are the
    # rule ids gate_guard.py ships with, so probe against them rather than
    # skipping everything and reporting a vacuous pass.
    known = configured_rule_ids(config) or {
        "KEY_MATERIAL", "FUND_MOVEMENT", "CONTRACT_DEPLOY", "PAYMENT_API_WRITE",
        "ACCOUNT_SIGNUP_FLOW", "PACKAGE_INSTALL", "DOMAIN_REGISTRAR",
    }
    tier = 0
    if state_abspath and os.path.isfile(state_abspath):
        try:
            with open(state_abspath) as f:
                tier = int(json.load(f).get(
                    config.get("trust_tier_field", "trust_tier"), 0))
        except Exception:
            tier = 0
    min_tier = config.get("min_tier_for_tier_gated", 1)
    tier_gated_ids = {r.get("id") for r in (config.get("tier_gated_rules") or [])} \
        or {"PACKAGE_INSTALL", "DOMAIN_REGISTRAR"}

    print("\nBEHAVIOR -- approval gate")
    counts = {PASS: 0, FAIL: 0, SKIP: 0}
    blocks_logged = 0
    for rule_id, desc, payload, expect in build_probes(config, state_abspath):
        if rule_id and rule_id not in known:
            print(f"  {SKIP:<4}  {desc:<46}  rule {rule_id} not in your config")
            counts[SKIP] += 1
            continue

        # A tier-gated rule above the threshold is *supposed* to stop blocking.
        note = ""
        if rule_id in tier_gated_ids and tier >= min_tier:
            expect = "allow"
            note = f"  (tier {tier} >= {min_tier}: rule off by design)"

        code, stderr = run_probe(command, payload, target)
        blocked = code == 2
        if blocked:
            blocks_logged += 1
        got = "blocked" if blocked else ("allowed" if code == 0 else f"exit {code}")
        ok = (blocked and expect == "block") or (code == 0 and expect == "allow")

        detail = got
        m = re.search(r"BLOCKED BY APPROVAL GATE \[([A-Z_]+)\]", stderr)
        if m:
            detail = f"blocked [{m.group(1)}]"
        if not ok:
            detail += f"  <-- expected {expect}"
        print(f"  {(PASS if ok else FAIL):<4}  {desc:<46}  {detail}{note}")
        counts[PASS if ok else FAIL] += 1

    if blocks_logged:
        log = config.get("blocked_log", "approvals/blocked.jsonl")
        print(f"\n  {blocks_logged} probe block(s) appended to {log} -- "
              f"grep -v gate-verify-probe to filter them out.")

    if not args.skip_budget:
        print("\nWIRING -- budget guard")
        brows, bcommand, bconfig = check_budget_wiring(target)
        for status, label, detail in brows:
            print(f"  {status:<4}  {label:<46}  {detail}")
            if status == FAIL:
                counts[FAIL] += 1

        if bcommand and bconfig:
            print("\nBEHAVIOR -- budget guard  (isolated: your spend state is "
                  "never written to)")
            workdir = tempfile.mkdtemp(prefix="budget-verify-")
            try:
                for status, desc, detail in run_budget_probes(
                        bcommand, bconfig, target, workdir):
                    print(f"  {status:<4}  {desc:<46}  {detail}")
                    counts[status] = counts.get(status, 0) + 1
            finally:
                shutil.rmtree(workdir, ignore_errors=True)

    total = counts[PASS] + counts[FAIL]
    print(f"\n{counts[PASS]}/{total} checks behaved as expected"
          + (f", {counts[SKIP]} skipped" if counts[SKIP] else ""))
    if counts[FAIL]:
        print("\nFAILures above mean a guard is not enforcing what you think "
              "it is. Fix those before trusting it with an unattended agent.")
        return 1
    print("\nThe guards are live and enforcing. Re-run this after any change "
          "to settings.json, either config, or the rule pack.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
