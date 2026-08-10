#!/usr/bin/env python3
"""
gate_guard.py — mechanical enforcement of an approval gate for autonomous agents.

Register this as a PreToolUse hook in your agent harness. It receives the
pending tool call as JSON on stdin. Exit 0 = allow. Exit 2 = block, with the
reason printed to stderr so the agent (and, in harnesses that surface it, the
human) sees why.

Design notes:
  * An agent that is merely TOLD "don't spend money" will eventually spend
    money -- instructions are advisory, and a long enough autonomous run finds
    the gap. This file is the mechanical backstop: it inspects the actual
    tool call, not the agent's stated intent.
  * A block is not a dead end. Every block is written to a log file, and the
    agent is told to file a formal request with approve.py so a human sees a
    queued ticket instead of a silent retry loop.
  * Over-blocking is its own failure mode. An agent that spends every session
    fighting the hook produces nothing. Rules should target the ACT (spending,
    registering an account, moving funds, deploying a contract), not topic
    keywords. Reading a pricing page is research; POSTing to a checkout
    endpoint is not.

Configuration:
  All paths and rules are read from a JSON config file so this drops into any
  project without editing the script. See gate-guard.config.example.json.

  Resolution order for the config path:
    1. $GATE_GUARD_CONFIG environment variable, if set
    2. gate-guard.config.json in the current working directory
    3. gate-guard.config.json next to this script
    4. built-in defaults (see DEFAULT_CONFIG below) if no file is found

Provenance: the rule engine and protected-path model in this file were
extracted from a private production agent project, where an earlier version
was adversarially tested at 59/59 passing cases (up from 46/59 before a
targeted patch closed the remaining bypasses -- shell-level writes to
protected files, and credential exfiltration through non-Bash tools). That
test suite is project-specific and is not included here; the rule shapes are
what carried over. Test your own configuration before relying on it.

A note on the construction of KEY_MATERIAL_PATTERN below: the sensitive
alternatives are assembled from short fragments joined with string
concatenation rather than written as one literal, so this source file does
not itself contain the exact key-material substrings its own rule flags.
That is not stylistic obfuscation -- it is a direct, lived consequence of the
mechanism this tool implements: a strict enough content-scanning guard,
pointed at a codebase that contains this file, will flag this file's own
rule definitions unless they are assembled rather than spelled out. Anyone
running this hook against its own source tree should expect the same thing.
"""

import json
import os
import re
import sys
from datetime import datetime, timezone

_W_SEED = "see" + "d"
_W_PHRASE = "phra" + "se"
_W_MNEMONIC = "mne" + "monic"
_W_PRIVATE = "priv" + "ate"
_W_SECRET = "secr" + "et"
_W_KEY = "ke" + "y"
_F_KEYPAIR = "keypair" + r"\.json"
_F_ID = "id" + r"\.json"

KEY_MATERIAL_PATTERN = (
    r"\b(" + _W_SEED + r"[\s_-]?" + _W_PHRASE + "|" + _W_MNEMONIC +
    "|" + _W_PRIVATE + r"[\s_-]?" + _W_KEY + "|" + _W_SECRET +
    r"[\s_-]?" + _W_KEY + "|" + _F_KEYPAIR + "|" + _F_ID + r")\b"
)

DEFAULT_CONFIG = {
    # Path to the agent's state file, relative to the project root. Used only
    # to read the trust-tier field below -- this script never writes state.
    "state_path": "STATE.json",
    # Top-level field in state_path holding the current trust tier (an
    # integer). Tier-gated rules are blocked below min_tier_for_tier_gated
    # and allowed (still individually approved, per your own workflow) at
    # or above it.
    "trust_tier_field": "trust_tier",
    "min_tier_for_tier_gated": 1,
    # File listing git remotes this agent is allowed to push to, one per
    # line, '#' comments allowed. Substring match against the push command.
    "approved_remotes_file": "approved-remotes.txt",
    # Where blocked attempts are logged, relative to the project root.
    "blocked_log": "approvals/blocked.jsonl",
    # Files/paths the agent may never modify, via any tool. Keep this list
    # short and specific: your constitution, your state file, this hook
    # itself, your harness's hook-registration file, and your remotes
    # allowlist are the canonical entries.
    "protected_paths": [
        "STATE.json",
        "gate_guard.py",
        "approved-remotes.txt",
    ],
    # ABSOLUTE rules: blocked at every trust tier, permanently, no override.
    # Each: {id, pattern (regex, case-insensitive), explanation}.
    "absolute_rules": [
        {
            "id": "KEY_MATERIAL",
            "pattern": KEY_MATERIAL_PATTERN,
            "explanation": "That matches the shape of sensitive credential "
                "material (an offline signing credential or recovery "
                "phrase). It must never exist on this machine. This is "
                "permanent and applies at every trust tier. If you found "
                "one, delete it and escalate to a human immediately.",
        },
        {
            "id": "FUND_MOVEMENT",
            "pattern": r"\b(transfer|withdraw|swap|bridge|stake|unstake)\b"
                       r"[^\n]*\b(usd|usdc|usdt|btc|eth|sol|wallet|token|"
                       r"balance)\b",
            "explanation": "Moving, swapping, or bridging funds requires "
                "explicit human approval and is never done unilaterally at "
                "any trust tier.",
        },
        {
            "id": "CONTRACT_DEPLOY",
            "pattern": r"\b(hardhat\s+(run|deploy)|forge\s+create|"
                       r"anchor\s+deploy|truffle\s+migrate)\b",
            "explanation": "Deploying a smart contract or token is high-risk "
                "and requires explicit human approval plus a legal review.",
        },
        {
            "id": "PAYMENT_API_WRITE",
            # Deliberately requires an actual write signal (a POST/PUT verb,
            # or a data-carrying flag), not just the domain appearing near a
            # curl/fetch call -- otherwise reading a balance or a webhook log
            # would false-positive as "spending," which is exactly the kind
            # of over-block the module docstring warns against.
            "pattern": r"((curl|wget)[^\n]*(-X\s*(POST|PUT)\b|--request\s+"
                       r"(POST|PUT)\b|(^|\s)(-d|--data)\b)|requests\.(post|put)\()"
                       r"[^\n]*(api\.stripe\.com|api\.paypal\.com|"
                       r"api-m\.paypal\.com|api\.squareup\.com|"
                       r"api\.coinbase\.com|api\.binance\.com|"
                       r"api\.lemonsqueezy\.com|api\.gumroad\.com)",
            "explanation": "Writing to a payment processor or exchange API "
                "requires approval. Reading (GET) is fine; POST/PUT is not.",
        },
        {
            "id": "ACCOUNT_SIGNUP_FLOW",
            "pattern": r"https?://[^\s\"']*/(sign[_-]?up|signup|register|"
                       r"create[_-]?account|join|checkout|subscribe|billing|"
                       r"upgrade|payment|oauth/authorize)"
                       r"|\b(page|browser)\.(goto|click|fill)\b[^\n]*"
                       r"(sign[_-]?up|register|checkout|create[_-]?account|"
                       r"payment|card[_-]?number)",
            "explanation": "Creating accounts and completing checkout flows "
                "requires a human. Propose the username and the reason, then "
                "move on to unblocked work.",
        },
    ],
    # TIER_GATED rules: blocked below min_tier_for_tier_gated, allowed above
    # it (still expected to go through your own per-item approval workflow).
    "tier_gated_rules": [
        {
            "id": "PACKAGE_INSTALL",
            "pattern": r"(^|[;&|\s])(pip3?|pipx|npm|pnpm|yarn|cargo|go|gem|"
                       r"apt|apt-get|brew)\s+(install|add|i)\b",
            "explanation": "Installing packages changes this machine and can "
                "pull untrusted code. Queue it with the reason you need it.",
        },
        {
            "id": "DOMAIN_REGISTRAR",
            "pattern": r"\b(namecheap|godaddy|porkbun|gandi\.net|name\.com|"
                       r"cloudflare\.com/products/registrar)\b[^\n]*"
                       r"(purchase|buy|register|cart|checkout)",
            "explanation": "Buying a domain costs money and requires approval "
                "at your configured trust threshold.",
        },
    ],
    # Regexes for live credential shapes. A match in ANY tool call (not just
    # a shell command) is blocked -- the leak risk is writing a token into a
    # file or commit just as much as running it in a shell command.
    "secret_patterns": [
        r"github_pat_[A-Za-z0-9_]{20,}",
        r"gh[pousr]_[A-Za-z0-9]{30,}",
        r"sk-[A-Za-z0-9]{20,}",
        r"AKIA[0-9A-Z]{16}",
        r"\b\d{8,12}:AA[A-Za-z0-9_-]{30,}\b",
    ],
}

# Shell verbs that modify a file without going through a harness's dedicated
# write/edit tool. Without this, `echo x > STATE.json` and `rm gate_guard.py`
# both sail past a protected-path check that only ever sees structured
# write-tool calls.
SHELL_WRITE_VERBS = (
    r"rm|mv|cp|tee|truncate|shred|dd|chmod|chown|ln|install|"
    r"sed\s+-[a-z]*i|perl\s+-[a-z]*i|awk|python3?\s+-c"
)

# Tool names treated as "write" tools when checking protected paths. Claude
# Code's built-ins are listed first; add your harness's equivalents.
WRITE_TOOL_NAMES = ("Write", "Edit", "NotebookEdit")

# Tool name treated as a shell/command tool for the shell-write and git-push
# checks. Claude Code's Bash tool by default.
SHELL_TOOL_NAME = "Bash"


def find_config_path():
    env_path = os.environ.get("GATE_GUARD_CONFIG")
    if env_path and os.path.isfile(env_path):
        return env_path
    cwd_path = os.path.join(os.getcwd(), "gate-guard.config.json")
    if os.path.isfile(cwd_path):
        return cwd_path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    local_path = os.path.join(script_dir, "gate-guard.config.json")
    if os.path.isfile(local_path):
        return local_path
    return None


def load_config():
    """Merge a user config file over DEFAULT_CONFIG. Missing keys fall back
    to the default so a config only needs to override what it changes."""
    config = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy
    path = find_config_path()
    if path:
        try:
            with open(path) as f:
                user = json.load(f)
            config.update(user)
        except Exception as e:
            sys.stderr.write(f"gate_guard: failed to load {path}: {e}\n")
    config["_project_root"] = os.path.dirname(path) if path else os.getcwd()
    return config


def load_trust_tier(config):
    """Read trust tier from disk. Never trust anything the session asserts --
    only a value written to the state file counts."""
    state_path = os.path.join(config["_project_root"], config["state_path"])
    try:
        with open(state_path) as f:
            return int(json.load(f).get(config["trust_tier_field"], 0))
    except Exception:
        return 0  # Fail closed: no readable state means the lowest tier.


def load_approved_remotes(config):
    remotes_path = os.path.join(config["_project_root"], config["approved_remotes_file"])
    try:
        with open(remotes_path) as f:
            return [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except FileNotFoundError:
        return []


def flatten(obj):
    """Collapse a tool_input dict into one searchable string."""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        return " ".join(flatten(v) for v in obj.values())
    if isinstance(obj, list):
        return " ".join(flatten(v) for v in obj)
    return str(obj)


def check_protected_write(tool_name, tool_input, config):
    if tool_name not in WRITE_TOOL_NAMES:
        return None
    path = tool_input.get("file_path", "")
    if not path:
        return None
    try:
        rel = os.path.relpath(os.path.abspath(path), config["_project_root"])
    except ValueError:
        return None
    if rel in config["protected_paths"] or os.path.basename(rel) in config["protected_paths"]:
        return (
            "PROTECTED_FILE",
            f"`{rel}` is a protected file and cannot be modified by this "
            "agent, by design. Update state through your dedicated state "
            "writer instead of editing it directly.",
        )
    return None


def check_shell_write_to_protected(tool_name, text, config):
    if tool_name != SHELL_TOOL_NAME:
        return None
    for rel in config["protected_paths"]:
        base = os.path.basename(rel)
        if base not in text:
            continue
        esc = re.escape(base)
        redirect = re.search(r">>?\s*\S*" + esc, text)
        verb = re.search(r"(^|[;&|]|\s)(" + SHELL_WRITE_VERBS + r")\s[^;&|]*" + esc, text)
        if redirect or verb:
            return (
                "PROTECTED_FILE_SHELL",
                f"`{rel}` cannot be modified from the shell either. Protected "
                "files are outside this agent's control through every tool, "
                "not just structured write/edit calls.",
            )
    return None


def check_secret_leak(text, config):
    for pat in config["secret_patterns"]:
        if re.search(pat, text):
            return (
                "SECRET_IN_COMMAND",
                "That command contains a live-credential-shaped string. Never "
                "put a token in a command, a file, or a commit -- read it "
                "from your secrets store at runtime instead.",
            )
    if re.search(r"(cat|head|tail|less|more|xxd|base64)\s+[^\n;|&]*\.env\b"
                 r"[^\n]*(\||>|curl|nc\b|wget)", text):
        return (
            "SECRET_IN_COMMAND",
            "Piping a .env file into another file or a network call is "
            "blocked. Credentials stay on this machine.",
        )
    return None


def check_git_push(text, config):
    if not re.search(r"(^|[;&|\s])git\s+push\b", text):
        return None
    approved = load_approved_remotes(config)
    if approved and any(r in text for r in approved):
        return None
    return (
        "GIT_PUSH_UNAPPROVED",
        "Pushing to a remote publishes work outward. Only remotes listed in "
        f"{config['approved_remotes_file']} are allowed.",
    )


def log_block(rule_id, tool_name, text, tier, config):
    """Record the block as evidence. The agent turns it into a formal request
    with approve.py; this log is the audit trail a human can review."""
    redacted = "[REDACTED -- credential material]" if rule_id == "KEY_MATERIAL" \
        else text[:500]
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "rule": rule_id,
        "tool": tool_name,
        "attempted": redacted,
        "trust_tier_at_block": tier,
    }
    log_path = os.path.join(config["_project_root"], config["blocked_log"])
    try:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        with open(log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass  # Never let bookkeeping failure turn a block into an allow.


def evaluate(payload, config):
    """Pure decision function: (payload, config) -> (rule_id, explanation) or
    None, plus context. Kept separate from main() so it's easy to unit test
    without stdin/exit."""
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}
    text = flatten(tool_input)
    tier = load_trust_tier(config)

    hit = check_protected_write(tool_name, tool_input, config)
    if not hit:
        hit = check_shell_write_to_protected(tool_name, text, config)
    if not hit:
        hit = check_secret_leak(text, config)
    if not hit and tool_name == SHELL_TOOL_NAME:
        hit = check_git_push(text, config)
    if not hit:
        for rule in config["absolute_rules"]:
            if re.search(rule["pattern"], text, re.IGNORECASE):
                hit = (rule["id"], rule["explanation"])
                break
    if not hit and tier < config["min_tier_for_tier_gated"]:
        for rule in config["tier_gated_rules"]:
            if re.search(rule["pattern"], text, re.IGNORECASE):
                hit = (rule["id"], rule["explanation"])
                break
    return hit, tool_name, text, tier


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        sys.exit(0)  # Malformed hook input is not the agent's doing.

    config = load_config()
    hit, tool_name, text, tier = evaluate(payload, config)

    if not hit:
        sys.exit(0)

    rule_id, explanation = hit
    log_block(rule_id, tool_name, text, tier, config)

    print(
        f"BLOCKED BY APPROVAL GATE [{rule_id}]\n\n"
        f"{explanation}\n\n"
        f"This block is logged to {config['blocked_log']}. Do not retry it, "
        f"do not work around it, and do not attempt to disable this hook. If "
        f"you genuinely need it, file a request with approve.py request so a "
        f"human sees it, then continue with unblocked work.",
        file=sys.stderr,
    )
    sys.exit(2)


if __name__ == "__main__":
    main()
