#!/usr/bin/env python3
"""
approve.py — the approval-gate request queue.

gate_guard.py stops a tool call and prints instructions. This is the tool
that turns "I was stopped" into "here is what I need and why", in a fixed
format a human can scan quickly, decide on, and record a decision for.

The queue is an append-only JSONL file; decisions are a separate append-only
JSONL file. Nothing is ever edited or deleted in place, so the full history
of what was asked and what was decided is always reconstructable.

Usage:
  approve.py request --tier ACCOUNT_CREATION --ask "..." --why "..." \
      [--cost "$0"] [--reversible yes] [--blocked-if-denied "..."]
  approve.py pending                              # itemized list for review
  approve.py decide <id> approve|deny [note...]    # HUMAN ONLY

Configuration:
  Reads the same gate-guard.config.json used by gate_guard.py, if present, to
  pick up custom queue/decisions paths and tier names. Falls back to sane
  defaults (approvals/queue.jsonl, approvals/decisions.jsonl, and the TIERS
  list below) if no config is found.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

DEFAULT_TIERS = [
    "SPEND", "ACCOUNT_CREATION", "LEGAL_ENTITY", "CONTRACT_DEPLOY",
    "FUND_MOVEMENT", "PUBLIC_CLAIM", "TOOLING", "OTHER",
]

DEFAULT_QUEUE_PATH = "approvals/queue.jsonl"
DEFAULT_DECISIONS_PATH = "approvals/decisions.jsonl"

# Printed on every ACCOUNT_CREATION request as a standing reminder of the
# handoff contract: the agent proposes, a human executes and holds secrets.
ACCOUNT_HANDOFF_NOTE = (
    "Agent proposes the username/handle only. A human creates the account "
    "and sets the password in their own password manager. The agent never "
    "generates, stores, or sees password material. Any session token or "
    "cookie is placed by the human, out of band, after the account exists."
)


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
    tiers = DEFAULT_TIERS
    queue_rel = DEFAULT_QUEUE_PATH
    decisions_rel = DEFAULT_DECISIONS_PATH
    path = find_config_path()
    if path:
        root = os.path.dirname(path)
        try:
            with open(path) as f:
                cfg = json.load(f)
            tiers = cfg.get("approval_tiers", tiers)
            queue_rel = cfg.get("queue_path", queue_rel)
            decisions_rel = cfg.get("decisions_path", decisions_rel)
        except Exception:
            pass
    return {
        "tiers": tiers,
        "queue": os.path.join(root, queue_rel),
        "decisions": os.path.join(root, decisions_rel),
    }


def read(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [json.loads(l) for l in f if l.strip()]


def append(path, entry):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a") as f:
        f.write(json.dumps(entry) + "\n")


def next_id(queue_path):
    return max((e.get("id", 0) for e in read(queue_path)), default=0) + 1


def cmd_request(a, settings):
    entry = {
        "id": next_id(settings["queue"]),
        "ts": datetime.now(timezone.utc).isoformat(),
        "tier": a.tier,
        "ask": a.ask,
        "why": a.why,
        "cost": a.cost,
        "reversible": a.reversible,
        "blocked_if_denied": a.blocked_if_denied,
        "handoff": ACCOUNT_HANDOFF_NOTE if a.tier == "ACCOUNT_CREATION" else "n/a",
        "status": "pending",
    }
    append(settings["queue"], entry)
    print(f"queued APPROVAL #{entry['id']:04d} ({a.tier})")
    print("Now continue with work that is NOT blocked. Never idle on an approval.")


def decided_ids(settings):
    return {d["id"]: d for d in read(settings["decisions"])}


def cmd_pending(_a, settings):
    done = decided_ids(settings)
    pending = [e for e in read(settings["queue"]) if "id" in e and e["id"] not in done]
    if not pending:
        print("No pending approval requests.")
        return
    for e in pending:
        print(f"\n[APPROVAL #{e['id']:04d}] Tier: {e['tier']}")
        print(f"Ask:        {e['ask']}")
        print(f"Why:        {e['why']}")
        print(f"Cost:       {e.get('cost', '$0')}")
        print(f"Reversible: {e.get('reversible', 'unknown')}")
        if e.get("handoff") not in (None, "n/a"):
            print(f"Handoff:    {e['handoff']}")
        print(f"Blocked if denied: {e.get('blocked_if_denied', 'unspecified')}")


def cmd_decide(a, settings):
    append(settings["decisions"], {
        "id": int(a.id),
        "ts": datetime.now(timezone.utc).isoformat(),
        "decision": a.decision,
        "note": " ".join(a.note),
    })
    print(f"#{int(a.id):04d} {a.decision}")


def main():
    settings = load_settings()

    p = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("request")
    r.add_argument("--tier", required=True, choices=settings["tiers"])
    r.add_argument("--ask", required=True)
    r.add_argument("--why", required=True)
    r.add_argument("--cost", default="$0")
    r.add_argument("--reversible", default="unknown")
    r.add_argument("--blocked-if-denied", dest="blocked_if_denied", default="unspecified")
    r.set_defaults(func=cmd_request)

    sub.add_parser("pending").set_defaults(func=cmd_pending)

    d = sub.add_parser("decide")
    d.add_argument("id")
    d.add_argument("decision", choices=["approve", "deny"])
    d.add_argument("note", nargs="*")
    d.set_defaults(func=cmd_decide)

    a = p.parse_args()
    a.func(a, settings)


if __name__ == "__main__":
    main()
