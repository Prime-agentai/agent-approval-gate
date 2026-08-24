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
_W_WORDS = "wor" + "ds"
_W_MNEMONIC = "mne" + "monic"
_W_PRIVATE = "priv" + "ate"
_W_SECRET = "secr" + "et"
_W_RECOVERY = "recov" + "ery"
_W_BACKUP = "back" + "up"
_W_KEY = "ke" + "y"
_F_KEYPAIR = "keypair" + r"\.json"
_F_ID = "id" + r"\.json"

# The label words a wallet actually prints next to this material. Vendor
# wording is not "see"+"d phrase" -- MetaMask says "Secret Recovery Phrase",
# Ledger and Trezor say "recovery phrase", Coinbase says "recovery phrase".
# A rule that only knew the developer's word for it would miss every one of
# them, which is the failure this list exists to prevent. See the limits
# section in README.md: this matches the LABEL, never the material itself.
_LABELLED_PHRASE = (
    r"(" + _W_SEED + "|" + _W_RECOVERY + "|" + _W_BACKUP + r")"
    r"[\s_-]?(" + _W_PHRASE + "|" + _W_WORDS + r")"
)

KEY_MATERIAL_PATTERN = (
    r"\b(" + _LABELLED_PHRASE + "|" + _W_MNEMONIC +
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
    # Where the liveness heartbeat is written, relative to the project root.
    # Rewritten on EVERY invocation, allow or block, so `verify.py --live` can
    # tell "the hook is registered" apart from "the hook actually ran". Set to
    # "" to disable. See record_heartbeat() for why this exists.
    "heartbeat_path": "approvals/heartbeat.json",
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


# The states the git-push allowlist can be in. They are not the same thing
# and must not produce the same message. "the file does not exist" is an
# installation state a human has to fix; "the file exists and lists nothing"
# is a configuration mistake; "your remote is not on the list" is the rule
# doing its job. Collapsing the first two into the third reports an ABSENCE as
# a DECISION -- it sends the operator looking for a rule that is not the
# problem. The README's "four ways a push gets blocked" table is the
# user-facing version of this list; keep the two in step.
ALLOWLIST_OK = "ok"
ALLOWLIST_MISSING = "missing"
ALLOWLIST_EMPTY = "empty"
ALLOWLIST_UNREADABLE = "unreadable"


def read_approved_remotes(config):
    """Read the git-push allowlist. Returns (state, entries, path, detail).

    `entries` is always a list and is empty for every state except OK, so a
    caller that only wants the remotes can ignore the rest. `state` is what
    lets the block message say which of the three no-push situations the
    operator is actually in."""
    path = os.path.join(config["_project_root"], config["approved_remotes_file"])
    try:
        with open(path) as f:
            lines = f.readlines()
    except FileNotFoundError:
        return ALLOWLIST_MISSING, [], path, ""
    except OSError as exc:
        # Present but unreadable (permissions, a directory, a bad mount). This
        # is NOT "no remotes are approved" -- we do not know what it says.
        return ALLOWLIST_UNREADABLE, [], path, f"{type(exc).__name__}: {exc}"
    except UnicodeDecodeError as exc:
        return ALLOWLIST_UNREADABLE, [], path, f"UnicodeDecodeError: {exc}"
    entries = [l.strip() for l in lines if l.strip() and not l.startswith("#")]
    if not entries:
        return ALLOWLIST_EMPTY, [], path, f"{len(lines)} line(s), none of them a remote"
    return ALLOWLIST_OK, entries, path, ""


def load_approved_remotes(config):
    """Just the approved remotes, for callers that do not care why the list
    is empty. Anything user-facing should use read_approved_remotes()."""
    return read_approved_remotes(config)[1]


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


# A push command that names no host at all -- `git push origin main` -- can
# never match a URL-prefix allowlist, because the match is a substring test
# against the command text and the alias is resolved by git, not by us. That
# is a different mistake from pushing to a genuinely unapproved host, and the
# fix is different too, so it gets its own sentence.
_HOST_IN_COMMAND = re.compile(r"://|\bgit@|[A-Za-z0-9-]+\.[A-Za-z]{2,}[/:]")

# How many approved remotes to name in a block message before truncating.
_MAX_REMOTES_SHOWN = 5


def _allowlist_fix_note(path, filename):
    """The same two facts every not-configured case needs: where the file
    goes, and that the agent must not create it itself."""
    return (
        f"A human has to create it, at:\n    {path}\n"
        "one approved remote prefix per line ('#' comments allowed), e.g. "
        "`github.com/your-org/`.\n"
        f"Do not create it yourself: `{filename}` is a protected path, so "
        "writing it is blocked too, by design -- an agent that can edit its "
        "own allowlist does not have one. File an approval request instead."
    )


def check_git_push(text, config):
    if not re.search(r"(^|[;&|\s])git\s+push\b", text):
        return None
    filename = config["approved_remotes_file"]
    state, approved, path, detail = read_approved_remotes(config)

    if state == ALLOWLIST_OK and any(r in text for r in approved):
        return None

    if state == ALLOWLIST_MISSING:
        return (
            "GIT_PUSH_UNAPPROVED",
            "Pushing to a remote publishes work outward, so it is allowed "
            "only to remotes on your allowlist -- and that allowlist does "
            f"not exist. There is no file at {path}.\n\n"
            "This is NOT 'your remote was rejected'. There is no list to be "
            "on, so every push is blocked and will stay blocked until the "
            "file exists. If you installed this as a plugin, note that a "
            "plugin install writes no config into your project; this is "
            "expected on first run, not a bug.\n\n"
            + _allowlist_fix_note(path, filename),
        )

    if state == ALLOWLIST_EMPTY:
        return (
            "GIT_PUSH_UNAPPROVED",
            f"{path} exists but lists no remotes ({detail}), so every push "
            "is blocked. An empty allowlist is not the same as a missing "
            "one, and neither is the same as your remote being rejected -- "
            "this one means the file is there and you have not put anything "
            "in it yet.\n\n"
            + _allowlist_fix_note(path, filename),
        )

    if state == ALLOWLIST_UNREADABLE:
        return (
            "GIT_PUSH_UNAPPROVED",
            f"{path} exists but could not be read ({detail}). The guard "
            "cannot tell which remotes you approved, so it is failing "
            "closed and blocking the push. This is an unknown, not a "
            "decision: fix the file's permissions or encoding and the "
            "block goes away on its own.",
        )

    shown = ", ".join(approved[:_MAX_REMOTES_SHOWN])
    if len(approved) > _MAX_REMOTES_SHOWN:
        shown += f", +{len(approved) - _MAX_REMOTES_SHOWN} more"
    msg = (
        "Pushing to a remote publishes work outward. Only remotes listed in "
        f"{filename} are allowed, and this command names none of them.\n"
        f"Approved ({len(approved)}): {shown}"
    )
    if not _HOST_IN_COMMAND.search(text):
        msg += (
            "\n\nThe command names no host at all. The allowlist is matched "
            "as a substring of the command text, so a bare alias like "
            "`origin` can never match a URL prefix even when it resolves to "
            "an approved remote. Name the destination explicitly instead of "
            "relying on the alias -- that is not a workaround, it is how the "
            "guard is able to check where the push is going."
        )
    return ("GIT_PUSH_UNAPPROVED", msg)


# Fields a harness may put in the hook payload to say WHO is making this call.
# None of them are guaranteed to be there: a payload that omits every one is
# indistinguishable from a main-session call, and that ambiguity is exactly
# what caller_identity() is here to record rather than paper over.
IDENTITY_KEYS = (
    "agent_id", "agent_type", "subagent_type", "agent_name",
    "permission_mode", "session_id", "hook_event_name",
)

# The subset whose presence means the caller is a subagent, not the main
# session. Order matters: the first one present names the bucket.
SUBAGENT_KEYS = ("agent_type", "subagent_type", "agent_name", "agent_id")

# Cap on distinct callers tracked, so a harness that mints a fresh id per call
# cannot grow this file without bound. Overflow lands in one "other" bucket.
AGENT_BUCKET_LIMIT = 24


def clean_token(value):
    """Reduce a payload value to something safe to use as a JSON key: short,
    printable, no separators that would make the bucket name ambiguous."""
    if not isinstance(value, (str, int)):
        return None
    token = re.sub(r"[^A-Za-z0-9._:-]", "", str(value).strip())[:48]
    return token or None


def caller_identity(payload):
    """Who made this call, to the extent the harness is willing to say.

    Returns (bucket, present_keys, is_subagent).

    The honest position, and the reason this returns "unattributed" rather
    than "main": absence of an agent marker does not prove the main session
    made the call. It is equally consistent with a harness that fires the hook
    for subagents but does not label them. Only a POSITIVE marker proves
    subagent coverage; its absence proves nothing, and the heartbeat says
    "unproven" instead of guessing.
    """
    present = sorted(k for k in IDENTITY_KEYS
                     if payload.get(k) not in (None, "", {}, []))
    for key in SUBAGENT_KEYS:
        token = clean_token(payload.get(key))
        if token:
            return f"{key}={token}", present, True
    return "unattributed", present, False


def merge_seen(prior, key, values, limit=32):
    """Union of what previous invocations saw with what this one sees, sorted
    and capped. Every field here is cumulative: the question being answered is
    'has this EVER happened', not 'what happened last time'."""
    before = prior.get(key)
    before = [v for v in before if isinstance(v, str)] if isinstance(before, list) else []
    return sorted(set(before) | set(values))[:limit]


def record_identity(prior, payload, decision, now, probe):
    """Track which callers the harness has actually routed through this hook.

    This exists because "is the gate binding on subagent tool calls?" is
    currently unanswerable from the outside -- upstream reports of hooks not
    firing for subagent calls sit open with nobody able to produce evidence
    either way, because nothing records the deciding field. A guard that runs
    on every call is in the one position to record it, so it does.
    """
    bucket, present, is_subagent = caller_identity(payload)
    agents = prior.get("agents")
    agents = dict(agents) if isinstance(agents, dict) else {}

    if not probe:  # A probe proves nothing about who the harness routes here.
        if bucket not in agents and len(agents) >= AGENT_BUCKET_LIMIT:
            bucket = "other"
        row = agents.get(bucket)
        row = dict(row) if isinstance(row, dict) else {}

        def bump(field):
            value = row.get(field)
            return value + 1 if isinstance(value, int) else 1

        agents[bucket] = {
            "invocations": bump("invocations"),
            "blocks": bump("blocks") if decision == "block"
                else (row.get("blocks") if isinstance(row.get("blocks"), int) else 0),
            "subagent": is_subagent or bool(row.get("subagent")),
            "first_seen": row.get("first_seen") or now,
            "last_seen": now,
        }

    proven = any(isinstance(v, dict) and v.get("subagent")
                 for v in agents.values())
    return {
        # Every top-level key the harness has ever sent. If agent_type is not
        # in here, the harness never offered one and no amount of reading this
        # file will tell you whether a subagent was involved.
        "payload_keys_seen": merge_seen(prior, "payload_keys_seen",
                                        (k for k in payload if isinstance(k, str))),
        "identity_keys_seen": merge_seen(prior, "identity_keys_seen", present),
        # Recorded because a bypassPermissions call reaching this hook is the
        # single most load-bearing thing a user can learn about their setup.
        "permission_modes_seen": merge_seen(
            prior, "permission_modes_seen",
            [t for t in [clean_token(payload.get("permission_mode"))] if t], 8),
        "agents": agents,
        "subagent_coverage": "observed" if proven else "unproven",
    }


def record_heartbeat(config, payload, tool_name, decision, rule_id):
    """Leave proof that the harness actually invoked this hook.

    The failure mode this exists for: a PreToolUse hook that is registered in
    settings.json but silently never runs. Nothing in the transcript says so --
    the agent's tool calls just succeed, and a guard you believe is enforcing
    is inert. Wiring is not firing, and until now nothing here could tell the
    two apart from the outside.

    So every invocation rewrites one small file: when it last ran, how many
    times, which copy of this script ran, and which config it loaded. That last
    pair matters more than it looks -- a harness running a stale copy from
    another directory, or loading a config you have since edited, presents
    exactly as "my rule change did nothing".

    Probe invocations (verify.py driving the hook directly, marked with
    GATE_GUARD_PROBE) are counted separately, because a probe proves the script
    works and proves nothing at all about the harness.

    It also records WHICH caller the harness routed here -- main session or
    subagent, and under which permission mode -- because "does the gate bind
    on subagent tool calls?" is otherwise unanswerable from the outside. See
    record_identity().

    Caveats, stated rather than hidden:
      * Counters are best-effort read-modify-write. Under parallel tool calls
        an increment can be lost, so `invocations` is a lower bound, never an
        overcount.
      * Every failure here is swallowed. A guard that crashes on bookkeeping
        would turn a block into an allow, which is the one outcome worse than
        having no heartbeat at all.
    """
    rel = config.get("heartbeat_path") or ""
    if not rel:
        return
    path = os.path.join(config["_project_root"], rel)
    now = datetime.now(timezone.utc).isoformat()
    probe = bool(os.environ.get("GATE_GUARD_PROBE"))
    try:
        prior = {}
        try:
            with open(path) as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                prior = loaded
        except (FileNotFoundError, ValueError):
            pass

        def count(field):
            value = prior.get(field, 0)
            return value + 1 if isinstance(value, int) else 1

        guard_path = os.path.abspath(__file__)
        entry = {
            "schema": 1,
            "first_invocation": prior.get("first_invocation") or now,
            "invocations": prior.get("invocations", 0) if probe else count("invocations"),
            "probe_invocations": count("probe_invocations") if probe
                else prior.get("probe_invocations", 0),
            "blocks": count("blocks") if decision == "block"
                else prior.get("blocks", 0),
            "guard_path": guard_path,
            "config_path": find_config_path(),
            "python": sys.executable,
            "identity": record_identity(
                prior.get("identity") if isinstance(prior.get("identity"), dict)
                else {}, payload, decision, now, probe),
        }
        # Whether the running copy of the guard is the one on disk now: if the
        # file has been edited since it last ran, the harness is still holding
        # the old behaviour and the session needs a restart.
        try:
            entry["guard_mtime"] = datetime.fromtimestamp(
                os.path.getmtime(guard_path), timezone.utc).isoformat()
        except OSError:
            entry["guard_mtime"] = None

        # The last real (non-probe) invocation is the liveness signal, so a
        # verify.py run must never refresh it.
        last = {
            "last_invocation": now,
            "last_tool": tool_name,
            "last_decision": decision,
            "last_rule": rule_id,
            "last_pid": os.getpid(),
        }
        if probe:
            entry.update({k: prior.get(k) for k in last})
            entry["last_probe_invocation"] = now
        else:
            entry.update(last)
            entry["last_probe_invocation"] = prior.get("last_probe_invocation")

        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        # Write-then-rename: a reader mid-write sees the old file, never a
        # truncated one. Unique temp name so concurrent hooks don't collide.
        tmp = f"{path}.{os.getpid()}.tmp"
        with open(tmp, "w") as f:
            json.dump(entry, f, indent=2)
            f.write("\n")
        os.replace(tmp, path)
    except Exception:
        pass  # Never let bookkeeping failure change a decision.


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

    # Everything from here on is this guard's own logic, and a bug in it must
    # not be able to quietly wave a gated call through. Under Claude Code's
    # PreToolUse contract only 0 (allow) and 2 (block) are meaningful; every
    # other exit status -- including the 1 that an unhandled Python exception
    # produces -- is treated as a non-blocking error and THE TOOL CALL RUNS.
    # So the default here is to fail closed: a guard that cannot decide is
    # treated as a guard that said no. That is a deliberate trade against the
    # lockout risk documented in docs/hook-not-firing.md, and it is the one a
    # security control should take. Set fail_closed_on_internal_error to false
    # if you would rather a broken guard let work continue.
    try:
        config = load_config()
        hit, tool_name, text, tier = evaluate(payload, config)
        record_heartbeat(config, payload, tool_name, "block" if hit else "allow",
                         hit[0] if hit else None)
    except SystemExit:
        raise
    except BaseException as exc:
        fail_closed = True
        try:
            fail_closed = bool(load_config().get(
                "fail_closed_on_internal_error", True))
        except BaseException:
            pass
        print(
            f"gate_guard: INTERNAL ERROR in the approval gate itself: "
            f"{type(exc).__name__}: {exc}\n"
            f"This is not a policy decision -- the guard could not reach one. "
            f"{'Failing CLOSED (call blocked).' if fail_closed else 'Failing OPEN (call allowed).'}\n"
            f"Fix the guard before relying on it; a hook that cannot run is a "
            f"hook that is not protecting anything.",
            file=sys.stderr,
        )
        sys.exit(2 if fail_closed else 0)

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
