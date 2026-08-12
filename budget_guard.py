#!/usr/bin/env python3
"""
budget_guard.py -- spend ceiling and runaway-loop detector for autonomous agents.

Register this as a PreToolUse hook alongside gate_guard.py. It answers the
question the approval gate does not: not "is this action allowed?" but "has
this session already cost more than you agreed to spend, and is it still
making progress?"

Two independent checks, either of which blocks the pending tool call:

  1. COST CEILING. Reads the harness's own transcript file (the JSONL path
     the hook payload hands us), sums the token usage the API actually
     reported, prices it against a configurable table, and blocks once the
     session -- or the rolling day -- crosses a ceiling you set.
  2. LOOP DETECTOR. Fingerprints each pending tool call and blocks when the
     same call repeats too many times in a row, or too many times inside a
     short window. The window check is the one that matters: a stuck agent
     usually alternates A, B, A, B rather than repeating A four times, so a
     consecutive-only check misses the common case.

Why measure instead of estimate. An agent cannot be trusted to report its own
spend -- it has no reliable view of its own token usage, and a runaway loop is
exactly the state in which its self-report is least reliable. Every number
here comes from `message.usage` in the transcript, which is what the API
returned, not what the agent believes.

HONESTY NOTE, and it is a real one: the dollar figures are LIST PRICE
ESTIMATES. If you are running on a subscription plan rather than metered API
credit, no invoice matches this number -- it is notional spend, useful as a
proportional signal ("this session cost 6x the last one") and as a ceiling,
not as an accounting record. The prices ship in config precisely so you can
replace them with your own contracted rates. Do not put this number in a
financial report, and do not let an agent quote it as a fact about your bill.

Cache accounting, since it dominates agentic workloads: cache reads bill at
0.1x the input rate, 5-minute cache writes at 1.25x, and 1-hour cache writes
at 2x. A long agent session is mostly cache reads, so pricing them at the
full input rate -- the obvious shortcut -- overstates cost by roughly an
order of magnitude and makes any ceiling you set meaningless.

Configuration:
  Resolution order for the config path:
    1. $BUDGET_GUARD_CONFIG environment variable, if set
    2. budget-guard.config.json in the current working directory
    3. budget-guard.config.json next to this script
    4. built-in defaults (DEFAULT_CONFIG below)

Standalone use:
  python3 budget_guard.py report [transcript.jsonl]   cost breakdown by model
  python3 budget_guard.py hook                        read a hook payload on stdin

`report` is useful on its own, with no hook installed: point it at any
transcript to see where a session's tokens went.

FAIL-OPEN, deliberately, and differently from gate_guard.py. If the transcript
is missing or unparseable, this hook ALLOWS the call and logs why. gate_guard
fails closed because the cost of over-blocking a payment is small; this one
fails open because an unreadable transcript would otherwise brick the agent
completely, turning a bookkeeping problem into a total outage. The ceiling is
a budget control, not a safety control -- do not repurpose it as one.
"""

import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone

# Per-million-token list prices, verified against Anthropic's published
# pricing on 2026-08-12. Two numbers per model; the cache rates are derived
# from them by CACHE_MULTIPLIERS below rather than being listed four times
# per row, because they are fixed ratios of the input price.
DEFAULT_CONFIG = {
    "pricing_usd_per_mtok": {
        "claude-fable-5":    {"input": 10.0, "output": 50.0},
        "claude-mythos-5":   {"input": 10.0, "output": 50.0},
        "claude-opus-5":     {"input": 5.0,  "output": 25.0},
        "claude-opus-4-8":   {"input": 5.0,  "output": 25.0},
        "claude-opus-4-7":   {"input": 5.0,  "output": 25.0},
        "claude-opus-4-6":   {"input": 5.0,  "output": 25.0},
        "claude-sonnet-5":   {"input": 3.0,  "output": 15.0},
        "claude-sonnet-4-6": {"input": 3.0,  "output": 15.0},
        "claude-haiku-4-5":  {"input": 1.0,  "output": 5.0},
    },
    # Multipliers on the model's input rate. Fixed by the API's pricing
    # model, not by which model you're running.
    "cache_multipliers": {
        "cache_read": 0.1,
        "cache_write_5m": 1.25,
        "cache_write_1h": 2.0,
    },
    # What to do about a model ID that isn't in the table -- which is what a
    # newly released model looks like from here. "priciest" charges it at the
    # highest rate you've configured, so an unrecognized model over-reports
    # rather than silently costing zero and sailing past the ceiling.
    # "ignore" is the alternative and is a bad default for a spend control.
    "unknown_model_policy": "priciest",
    # null disables a ceiling. Both are USD; both are list-price estimates.
    "session_cost_ceiling_usd": 10.0,
    "daily_cost_ceiling_usd": 40.0,
    # Emit a warning to stderr once spend crosses this fraction of a ceiling.
    "warn_at_fraction": 0.75,
    "loop_detector": {
        "enabled": True,
        # Block on the Nth identical call in a row.
        "consecutive_repeats": 4,
        # Block when the same call appears max_repeats times inside the last
        # `window` calls, consecutive or not. This catches A,B,A,B,A,B.
        "window": 20,
        "max_repeats": 6,
        # Tools whose repetition is meaningful rather than stuck. Empty by
        # default: an identical call with identical arguments is suspicious
        # regardless of which tool it is.
        "ignore_tools": [],
    },
    # Where per-session fingerprint windows and daily spend rollups live,
    # relative to the project root.
    "state_dir": ".budget-guard",
    "blocked_log": "approvals/budget-blocked.jsonl",
    # State files older than this are pruned on write.
    "state_ttl_days": 7,
}

# Kept out of config: this is the shape of the harness's transcript, not a
# preference. Claude Code writes one JSON object per line; assistant lines
# carry message.usage. Streaming means the same message.id is written several
# times as it grows, so the last line for an id wins.
ASSISTANT_TYPE = "assistant"


def find_config_path():
    env_path = os.environ.get("BUDGET_GUARD_CONFIG")
    if env_path and os.path.isfile(env_path):
        return env_path
    cwd_path = os.path.join(os.getcwd(), "budget-guard.config.json")
    if os.path.isfile(cwd_path):
        return cwd_path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    local_path = os.path.join(script_dir, "budget-guard.config.json")
    if os.path.isfile(local_path):
        return local_path
    return None


def load_config():
    """Merge a user config file over DEFAULT_CONFIG, one level deep so a
    config that overrides a single loop-detector field doesn't have to
    restate the rest of the block."""
    config = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy
    path = find_config_path()
    if path:
        try:
            with open(path) as f:
                user = json.load(f)
            for key, value in user.items():
                if isinstance(value, dict) and isinstance(config.get(key), dict):
                    config[key].update(value)
                else:
                    config[key] = value
        except Exception as e:
            sys.stderr.write(f"budget_guard: failed to load {path}: {e}\n")
    config["_project_root"] = os.path.dirname(path) if path else os.getcwd()
    return config


def model_rates(model, config):
    """(input, output) per-million rates for a model ID, applying the
    unknown-model policy. Falls back to a substring match first, so
    `claude-opus-5-some-suffix` still prices as an Opus rather than
    immediately hitting the unknown path."""
    table = config["pricing_usd_per_mtok"]
    if model in table:
        row = table[model]
        return row["input"], row["output"]
    for known, row in table.items():
        if model and model.startswith(known):
            return row["input"], row["output"]
    if config.get("unknown_model_policy") == "ignore":
        return 0.0, 0.0
    priciest = max(table.values(), key=lambda r: r["output"])
    return priciest["input"], priciest["output"]


def price_usage(model, usage, config):
    """Price one message's usage dict. Returns USD.

    `cache_creation` splits writes by TTL when the harness reports it; when
    it doesn't, the flat cache_creation_input_tokens is billed at the 5m rate,
    which is the cheaper of the two -- an under-estimate that is visible and
    bounded, rather than an over-estimate that trips ceilings for no reason.
    """
    in_rate, out_rate = model_rates(model, config)
    mult = config["cache_multipliers"]

    creation = usage.get("cache_creation") or {}
    write_1h = creation.get("ephemeral_1h_input_tokens", 0) or 0
    write_5m = creation.get("ephemeral_5m_input_tokens", 0) or 0
    if not creation:
        write_5m = usage.get("cache_creation_input_tokens", 0) or 0

    tokens_usd = (
        (usage.get("input_tokens", 0) or 0) * in_rate
        + (usage.get("output_tokens", 0) or 0) * out_rate
        + (usage.get("cache_read_input_tokens", 0) or 0) * in_rate * mult["cache_read"]
        + write_5m * in_rate * mult["cache_write_5m"]
        + write_1h * in_rate * mult["cache_write_1h"]
    )
    return tokens_usd / 1_000_000.0


def read_transcript_costs(transcript_path, config):
    """Parse a transcript into {message_id: (model, cost_usd)}.

    Deduplication is the whole reason this returns a dict keyed by message
    id. A streamed assistant message is written to the transcript repeatedly
    as it grows -- in a real session this produced 49 lines for 25 messages,
    so summing line by line would have overstated spend by roughly 2x. The
    last line for an id carries the final usage, so later lines overwrite.
    """
    costs = {}
    try:
        with open(transcript_path, errors="replace") as f:
            for line in f:
                if '"usage"' not in line:
                    continue  # cheap pre-filter; most lines aren't assistant turns
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                if entry.get("type") != ASSISTANT_TYPE:
                    continue
                message = entry.get("message") or {}
                usage = message.get("usage")
                message_id = message.get("id")
                if not usage or not message_id:
                    continue
                model = message.get("model") or ""
                costs[message_id] = (model, price_usage(model, usage, config))
    except OSError:
        return None  # caller decides; see the fail-open note in the docstring
    return costs


def state_dir(config):
    path = os.path.join(config["_project_root"], config["state_dir"])
    os.makedirs(path, exist_ok=True)
    return path


def prune_state(directory, ttl_days):
    cutoff = time.time() - ttl_days * 86400
    try:
        for name in os.listdir(directory):
            path = os.path.join(directory, name)
            try:
                if os.path.isfile(path) and os.path.getmtime(path) < cutoff:
                    os.remove(path)
            except OSError:
                pass
    except OSError:
        pass


def record_daily_spend(session_id, session_cost, config):
    """Write this session's cost into today's rollup and return the day's
    total across every session.

    Keyed by session so re-running this on every tool call overwrites rather
    than accumulates -- the session's own cost is always recomputed from the
    transcript, and other sessions' entries persist from their last write.
    """
    directory = state_dir(config)
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    path = os.path.join(directory, f"daily-{day}.json")
    try:
        with open(path) as f:
            day_state = json.load(f)
    except Exception:
        day_state = {}
    if not isinstance(day_state, dict):
        day_state = {}
    day_state[session_id or "unknown-session"] = round(session_cost, 6)
    try:
        with open(path, "w") as f:
            json.dump(day_state, f)
    except OSError:
        pass  # a bookkeeping failure must not turn into a block or a crash
    return sum(v for v in day_state.values() if isinstance(v, (int, float)))


def fingerprint(tool_name, tool_input):
    """Stable hash of a tool call. sort_keys matters: two dicts that differ
    only in key order are the same call, and without it an agent repeating
    itself would look like fresh work every time."""
    try:
        payload = json.dumps(tool_input, sort_keys=True, default=str)
    except Exception:
        payload = str(tool_input)
    digest = hashlib.sha256(f"{tool_name}\x00{payload}".encode()).hexdigest()
    return digest[:16]


def check_loop(session_id, tool_name, tool_input, config):
    """Record this call in the session's rolling window and report whether it
    looks stuck. Returns (rule_id, explanation) or None."""
    settings = config["loop_detector"]
    if not settings.get("enabled", True):
        return None
    if tool_name in (settings.get("ignore_tools") or []):
        return None

    directory = state_dir(config)
    safe_id = "".join(c for c in (session_id or "unknown") if c.isalnum() or c in "-_")
    path = os.path.join(directory, f"loop-{safe_id or 'unknown'}.json")
    try:
        with open(path) as f:
            history = json.load(f)
    except Exception:
        history = []
    if not isinstance(history, list):
        history = []

    current = fingerprint(tool_name, tool_input)
    window = max(1, int(settings.get("window", 20)))
    history = (history + [current])[-window:]
    try:
        with open(path, "w") as f:
            json.dump(history, f)
    except OSError:
        pass

    consecutive_limit = int(settings.get("consecutive_repeats", 4))
    run = 0
    for entry in reversed(history):
        if entry != current:
            break
        run += 1
    if consecutive_limit > 0 and run >= consecutive_limit:
        return (
            "LOOP_CONSECUTIVE",
            f"That is the same {tool_name} call with the same arguments "
            f"{run} times in a row. Repeating it again will not produce a "
            "different result. Change the approach, or stop and report what "
            "is blocking you.",
        )

    max_repeats = int(settings.get("max_repeats", 6))
    occurrences = history.count(current)
    if max_repeats > 0 and occurrences >= max_repeats:
        return (
            "LOOP_WINDOW",
            f"That exact {tool_name} call has run {occurrences} times in the "
            f"last {len(history)} tool calls. That is a loop even though the "
            "repeats are not back to back. Change the approach, or stop and "
            "report what is blocking you.",
        )
    return None


def check_budget(transcript_path, session_id, config):
    """Returns ((rule_id, explanation) or None, session_cost, day_cost)."""
    if not transcript_path:
        return None, 0.0, 0.0
    costs = read_transcript_costs(transcript_path, config)
    if costs is None:
        sys.stderr.write(
            f"budget_guard: could not read transcript {transcript_path}; "
            "allowing the call and skipping the cost check.\n"
        )
        return None, 0.0, 0.0

    session_cost = sum(cost for _model, cost in costs.values())
    day_cost = record_daily_spend(session_id, session_cost, config)

    session_ceiling = config.get("session_cost_ceiling_usd")
    if session_ceiling is not None and session_cost >= session_ceiling:
        return (
            "SESSION_BUDGET",
            f"This session has spent an estimated ${session_cost:.2f} of its "
            f"${session_ceiling:.2f} ceiling (list-price estimate from "
            f"{len(costs)} API responses). Stop here and report what you "
            "finished and what is left. Raising the ceiling is the operator's "
            "call, not yours.",
        ), session_cost, day_cost

    day_ceiling = config.get("daily_cost_ceiling_usd")
    if day_ceiling is not None and day_cost >= day_ceiling:
        return (
            "DAILY_BUDGET",
            f"Estimated spend across all sessions today is ${day_cost:.2f}, "
            f"at or over the ${day_ceiling:.2f} daily ceiling. Stop and report. "
            "Raising the ceiling is the operator's call, not yours.",
        ), session_cost, day_cost

    warn_at = config.get("warn_at_fraction")
    if warn_at:
        for label, spent, ceiling in (
            ("session", session_cost, session_ceiling),
            ("daily", day_cost, day_ceiling),
        ):
            if ceiling and spent >= ceiling * warn_at:
                sys.stderr.write(
                    f"budget_guard: {label} spend ${spent:.2f} is "
                    f"{spent / ceiling:.0%} of the ${ceiling:.2f} ceiling.\n"
                )
    return None, session_cost, day_cost


def log_block(rule_id, tool_name, session_cost, day_cost, config):
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "rule": rule_id,
        "tool": tool_name,
        "session_cost_usd_est": round(session_cost, 4),
        "day_cost_usd_est": round(day_cost, 4),
    }
    log_path = os.path.join(config["_project_root"], config["blocked_log"])
    try:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        with open(log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass  # never let bookkeeping failure turn a block into an allow


def evaluate(payload, config):
    """Pure-ish decision function: (payload, config) -> (hit, session_cost,
    day_cost). Kept separate from main() so it can be unit tested without
    stdin or exit codes. It does touch the state directory, because the loop
    detector's window is inherently stateful across calls."""
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}
    session_id = payload.get("session_id", "")

    hit, session_cost, day_cost = check_budget(
        payload.get("transcript_path", ""), session_id, config
    )
    if not hit:
        hit = check_loop(session_id, tool_name, tool_input, config)
    return hit, session_cost, day_cost


def report(transcript_path, config):
    """Standalone cost breakdown. Useful with no hook installed at all."""
    costs = read_transcript_costs(transcript_path, config)
    if costs is None:
        print(f"Could not read transcript: {transcript_path}", file=sys.stderr)
        return 1

    by_model = {}
    for model, cost in costs.values():
        entry = by_model.setdefault(model or "(unknown)", {"messages": 0, "usd": 0.0})
        entry["messages"] += 1
        entry["usd"] += cost

    total = sum(entry["usd"] for entry in by_model.values())
    print(f"Transcript: {transcript_path}")
    print(f"{len(costs)} API responses (deduplicated by message id)\n")
    print(f"{'model':<24}{'responses':>11}{'est. USD':>12}")
    print("-" * 47)
    for model, entry in sorted(by_model.items(), key=lambda kv: -kv[1]["usd"]):
        print(f"{model:<24}{entry['messages']:>11}{entry['usd']:>12.4f}")
    print("-" * 47)
    print(f"{'total':<24}{len(costs):>11}{total:>12.4f}\n")
    print("List-price estimate. If you are on a subscription plan this is")
    print("notional spend, not a bill. Prices are configurable; check them")
    print("against current published rates before quoting this anywhere.")
    return 0


def main():
    args = sys.argv[1:]
    config = load_config()
    prune_state(state_dir(config), config.get("state_ttl_days", 7))

    if args and args[0] == "report":
        if len(args) < 2:
            print("usage: budget_guard.py report <transcript.jsonl>", file=sys.stderr)
            return 2
        return report(args[1], config)

    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0  # malformed hook input is not the agent's doing

    hit, session_cost, day_cost = evaluate(payload, config)
    if not hit:
        return 0

    rule_id, explanation = hit
    log_block(rule_id, payload.get("tool_name", ""), session_cost, day_cost, config)
    print(
        f"BLOCKED BY BUDGET GUARD [{rule_id}]\n\n"
        f"{explanation}\n\n"
        f"This block is logged to {config['blocked_log']}. Do not retry it and "
        f"do not attempt to disable this hook. If the ceiling genuinely needs "
        f"to move, say so in your summary and let a human decide.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
