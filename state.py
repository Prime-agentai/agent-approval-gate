#!/usr/bin/env python3
"""
state.py — the only sanctioned way to modify an agent's state file.

Pair this with gate_guard.py's protected_paths list (add your state file's
name to it, and add state.py itself to your harness's write-tool denylist so
the agent cannot bypass this script and edit the state file directly). That
gives one chokepoint where the fields you decide a human owns are actually
protected, instead of "protected" only by an instruction the agent could
talk itself out of three hundred tool calls into a long session.

Usage:
  state.py show                          # print current state
  state.py get <dotted.path>             # read one field
  state.py set <dotted.path> <value>     # write one field (JSON or literal)
  state.py session <type>                # bump a session counter + timestamp
  state.py revenue <amount> <source> <ref>   # append a verified ledger entry
  state.py blocker add|clear [text]      # track what's stalling progress

Configuration:
  Reads gate-guard.config.json if present (same file gate_guard.py and
  approve.py use) for:
    state_path        -- where the state JSON file lives (default STATE.json)
    ledger_path        -- where verified revenue/value entries are appended
                          (default ledger/ledger.jsonl)
    immutable_fields   -- top-level fields this script refuses to write, ever
                          (default: ["trust_tier"])
    trust_threshold_usd -- cumulative verified amount at which the tool
                          prints an eligibility notice (default: none)

The eligibility notice is informational only: crossing the threshold does
not change trust_tier. Only a human, editing the state file by hand (this
script's own IMMUTABLE guard refuses to do it), can do that.
"""

import json
import os
import sys
from datetime import datetime, timezone

DEFAULT_IMMUTABLE = ["trust_tier"]
DEFAULT_STATE_PATH = "STATE.json"
DEFAULT_LEDGER_PATH = "ledger/ledger.jsonl"


def find_config_path():
    env_path = os.environ.get("GATE_GUARD_CONFIG")
    if env_path and os.path.isfile(env_path):
        return env_path
    for candidate in (
        os.path.join(os.getcwd(), "gate-guard.config.json"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "gate-guard.config.json"),
    ):
        if os.path.isfile(candidate):
            return candidate
    return None


def load_settings():
    root = os.getcwd()
    immutable = set(DEFAULT_IMMUTABLE)
    state_rel = DEFAULT_STATE_PATH
    ledger_rel = DEFAULT_LEDGER_PATH
    threshold = None
    path = find_config_path()
    if path:
        root = os.path.dirname(path)
        try:
            with open(path) as f:
                cfg = json.load(f)
            immutable = set(cfg.get("immutable_fields", DEFAULT_IMMUTABLE))
            state_rel = cfg.get("state_path", state_rel)
            ledger_rel = cfg.get("ledger_path", ledger_rel)
            threshold = cfg.get("trust_threshold_usd")
        except Exception:
            pass
    return {
        "state": os.path.join(root, state_rel),
        "ledger": os.path.join(root, ledger_rel),
        "immutable": immutable,
        "threshold": threshold,
    }


def load(state_path):
    with open(state_path) as f:
        return json.load(f)


def save(state_path, state):
    tmp = state_path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=2)
        f.write("\n")
    os.replace(tmp, state_path)  # atomic; a crashed run never truncates state


def dig(state, path, immutable, value=None, write=False):
    parts = path.split(".")
    if parts[0] in immutable:
        sys.exit(
            f"REFUSED: '{parts[0]}' is a human-owned field and cannot be set "
            f"through this script. Edit the state file by hand if this is "
            f"genuinely a human making the change."
        )
    node = state
    for p in parts[:-1]:
        node = node.setdefault(p, {})
    if write:
        node[parts[-1]] = value
        return value
    return node.get(parts[-1])


def parse(raw):
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


def now():
    return datetime.now(timezone.utc).isoformat()


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    settings = load_settings()
    cmd, args = sys.argv[1], sys.argv[2:]
    state = load(settings["state"])
    immutable = settings["immutable"]

    if cmd == "show":
        print(json.dumps(state, indent=2))
        return

    if cmd == "get":
        print(json.dumps(dig(state, args[0], immutable), indent=2))
        return

    if cmd == "set":
        dig(state, args[0], immutable, parse(" ".join(args[1:])), write=True)
        save(settings["state"], state)
        print(f"set {args[0]}")
        return

    if cmd == "session":
        state.setdefault("sessions", {})
        state["sessions"]["count"] = state["sessions"].get("count", 0) + 1
        state["sessions"]["last_type"] = args[0] if args else "unspecified"
        state["sessions"]["last_run"] = now()
        save(settings["state"], state)
        print(f"session #{state['sessions']['count']} ({state['sessions']['last_type']}) recorded")
        return

    if cmd == "revenue":
        # Verified means a confirmed inbound receipt: not a projection, not
        # paper value, not a pledge. ref is what makes the entry auditable.
        if len(args) < 3:
            sys.exit("usage: state.py revenue <amount> <source> <verification_ref>")
        amount, source, ref = float(args[0]), args[1], " ".join(args[2:])
        entry = {"ts": now(), "amount": amount, "source": source,
                 "verification_ref": ref, "confidence": "VERIFIED"}
        os.makedirs(os.path.dirname(settings["ledger"]) or ".", exist_ok=True)
        with open(settings["ledger"], "a") as f:
            f.write(json.dumps(entry) + "\n")

        state.setdefault("metrics", {})
        m = state["metrics"]
        m["revenue_verified"] = round(m.get("revenue_verified", 0) + amount, 2)
        if m.get("first_dollar_date") is None and m["revenue_verified"] > 0:
            m["first_dollar_date"] = now()
        save(settings["state"], state)

        total = m["revenue_verified"]
        print(f"logged {amount:.2f} ({source}) -- verified total {total:,.2f}")
        threshold = settings["threshold"]
        if threshold and total >= threshold and state.get("trust_tier", 0) < 1:
            print(f"\nThreshold reached: {threshold:,.2f} verified. Eligible to "
                  f"REQUEST a trust-tier change in the next review. This does NOT "
                  f"promote automatically -- only a human sets trust_tier, and "
                  f"only by hand.")
        return

    if cmd == "blocker":
        if args and args[0] == "clear":
            state["blockers"] = []
        else:
            state.setdefault("blockers", []).append(
                {"ts": now(), "text": " ".join(args[1:] if args and args[0] == "add" else args)})
        save(settings["state"], state)
        print(f"blockers: {len(state.get('blockers', []))}")
        return

    sys.exit(f"unknown command: {cmd}\n{__doc__}")


if __name__ == "__main__":
    main()
