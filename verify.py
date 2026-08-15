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

Both directions are checked. Probes that SHOULD block are the obvious half;
probes that should be ALLOWED matter just as much, because an over-blocking
gate that fights every tool call is a gate you will turn off within a week,
and then you have no gate at all.

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


def find_hook_command(target, marker="gate_guard.py"):
    """Pull the registered hook command straight out of settings.json. Testing
    anything else would be testing a hook your harness isn't running.

    `marker` is the guard's script filename; both guards register their own
    PreToolUse entry and are recognised by it.
    """
    settings_path = os.path.join(target, ".claude", "settings.json")
    if not os.path.isfile(settings_path):
        return None, f"{settings_path} does not exist"
    try:
        with open(settings_path) as f:
            settings = json.load(f)
    except json.JSONDecodeError as e:
        return None, f"settings.json is not valid JSON: {e}"

    variants = (marker, marker.replace("_", "-"))
    pre = (settings.get("hooks") or {}).get("PreToolUse") or []
    for entry in pre:
        for hook in entry.get("hooks", []) or []:
            cmd = str(hook.get("command", ""))
            if any(v in cmd for v in variants):
                return cmd, None
    return None, f"no PreToolUse hook referencing {marker} is registered"


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


def heartbeat_path(target, command, config):
    """Resolve the heartbeat file the way gate_guard.py will write it: relative
    to the directory holding the config it loads, falling back to the project
    root when no config file exists."""
    rel = (config or {}).get("heartbeat_path", "approvals/heartbeat.json")
    if not rel:
        return None
    config_path, _ = resolve_config(command, target)
    root = os.path.dirname(config_path) if os.path.isfile(config_path) else target
    return os.path.join(root, rel)


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


def check_live(target, max_age_hours):
    """Report whether the harness -- not this script -- has actually invoked
    the guard, and whether the copy it invoked is the one on disk now."""
    print(f"agent-approval-gate: liveness check for {target}\n")
    print("LIVENESS -- has the harness actually called the hook?")
    rows = []
    ok = True

    command, err = find_hook_command(target)
    if not command:
        print(f"  {FAIL:<4}  hook registered in .claude/settings.json    {err}")
        print("\n  Nothing to check liveness for until the hook is registered. "
              "Run install.py first.")
        return 1
    rows.append((PASS, "hook registered in .claude/settings.json", "yes"))

    config_path, _ = resolve_config(command, target)
    config = {}
    if os.path.isfile(config_path):
        try:
            with open(config_path) as f:
                config = json.load(f)
        except ValueError as e:
            rows.append((WARN, "config parses", f"{config_path}: {e}"))

    hb_path = heartbeat_path(target, command, config)
    if not hb_path:
        for row in rows:
            print(f"  {row[0]:<4}  {row[1]:<46}  {row[2]}")
        print("\n  heartbeat_path is disabled in your config, so liveness "
              "cannot be checked. Set it to a path to enable this.")
        return 1

    try:
        with open(hb_path) as f:
            hb = json.load(f)
    except (FileNotFoundError, ValueError, OSError):
        rows.append((FAIL, "heartbeat written by the harness",
                     f"{hb_path} absent or unreadable"))
        for row in rows:
            print(f"  {row[0]:<4}  {row[1]:<46}  {row[2]}")
        print(NEVER_RAN.format(command=command))
        return 1

    invocations = hb.get("invocations") or 0
    probes = hb.get("probe_invocations") or 0
    last = hb.get("last_invocation")

    if not invocations or not last:
        detail = f"{probes} probe invocation(s) only" if probes else "none recorded"
        rows.append((FAIL, "heartbeat written by the harness", detail))
        for row in rows:
            print(f"  {row[0]:<4}  {row[1]:<46}  {row[2]}")
        print(NEVER_RAN.format(command=command))
        if probes:
            print("  Note: the only invocations on record came from verify.py "
                  "itself. The script runs; the harness is not calling it.")
        return 1

    try:
        age = (datetime.now(timezone.utc)
               - datetime.fromisoformat(last)).total_seconds()
    except ValueError:
        age = None

    if age is None:
        rows.append((WARN, "last harness invocation", f"unparseable: {last!r}"))
        ok = False
    elif age > max_age_hours * 3600:
        rows.append((WARN, "last harness invocation",
                     f"{age_phrase(age)} -- older than {max_age_hours}h"))
        ok = False
    else:
        rows.append((PASS, "last harness invocation", age_phrase(age)))

    rows.append((PASS, "invocations recorded",
                 f"{invocations} from the harness, {probes} from verify.py"))
    rows.append((PASS, "blocks recorded", str(hb.get("blocks") or 0)))
    if hb.get("last_tool"):
        rows.append((PASS, "last tool call seen",
                     f"{hb['last_tool']} -> {hb.get('last_decision', '?')}"))

    # Which copy ran. A harness invoking a stale script in another directory,
    # or loading a config other than the one you edited, presents exactly as
    # "my rule change did nothing" -- so name the file, don't just pass it.
    ran_guard = hb.get("guard_path")
    wired_guard = wired_guard_path(command, target)
    if ran_guard and wired_guard and \
            os.path.realpath(ran_guard) != os.path.realpath(wired_guard):
        rows.append((FAIL, "the copy that ran is the one you wired",
                     f"ran {ran_guard}, settings.json points at {wired_guard}"))
        ok = False
    elif ran_guard:
        rows.append((PASS, "the copy that ran is the one you wired", ran_guard))

    ran_config = hb.get("config_path")
    if os.path.isfile(config_path) and ran_config and \
            os.path.realpath(ran_config) != os.path.realpath(config_path):
        rows.append((FAIL, "the config it loaded is the one you edited",
                     f"loaded {ran_config}, expected {config_path}"))
        ok = False
    elif ran_config:
        rows.append((PASS, "the config it loaded is the one you edited",
                     ran_config))
    elif os.path.isfile(config_path):
        rows.append((WARN, "the config it loaded is the one you edited",
                     f"ran with built-in defaults, but {config_path} exists"))
        ok = False

    # Edited since it last ran => the live session is still enforcing the old
    # rules. This is the single most common "why didn't my change take" cause.
    if ran_guard and hb.get("guard_mtime") and os.path.isfile(ran_guard):
        try:
            on_disk = datetime.fromtimestamp(
                os.path.getmtime(ran_guard), timezone.utc)
            when_ran = datetime.fromisoformat(hb["guard_mtime"])
            if on_disk > when_ran:
                rows.append((WARN, "guard unchanged since it last ran",
                             "edited since -- restart the session to load it"))
                ok = False
            else:
                rows.append((PASS, "guard unchanged since it last ran", "yes"))
        except (ValueError, OSError):
            pass

    for row in rows:
        print(f"  {row[0]:<4}  {row[1]:<46}  {row[2]}")

    if ok:
        print("\nThe harness is calling the guard, and calling the copy you "
              "think it is.\nThis says nothing about whether the rules are "
              "correct -- run verify.py with no arguments for that.")
        return 0
    print("\nThe guard has run at some point, but something above does not "
          "line up.\nA WARN here means what you edited and what is enforcing "
          "may be different things.")
    return 1


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
    args = ap.parse_args()
    target = os.path.abspath(args.target)

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
