# agent-approval-gate

Mechanical enforcement of "don't spend money, create accounts, or move funds
without human approval" for an autonomous LLM agent — plus the approval
queue that turns a block into a ticket, and a single-chokepoint state writer
that protects the fields a human should own.

Three small, dependency-free Python scripts. No framework, no daemon, no
external service.

## The problem this solves

If you tell an agent in its system prompt "never spend money without asking
me first," that instruction is advisory. It competes with every other
instruction in the context window, it can be argued around by the agent's
own reasoning ("this is only $4, surely that's fine"), and it silently stops
working the moment the instruction scrolls out of context on a long session.
An agent that is merely *told* not to spend money will, eventually, spend
money — not out of malice, just because language-model instruction-following
degrades under load and an autonomous agent racks up a lot of load.

The fix is not a better prompt. It's a mechanical gate that inspects the
actual tool call — the curl to a payment API, the `npm install`, the write to
a state file a human is supposed to own — and blocks it structurally, before
it executes, regardless of what the agent's reasoning concluded. A prompt
asks the model to behave. A `PreToolUse` hook decides, in code, whether the
call is allowed to happen at all.

That's what `gate_guard.py` is. It is not a content filter and it is not
trying to police what the agent *thinks*; it looks at what the agent is
about to *do* — the tool name and its arguments — and matches that against a
short, deliberately narrow set of rules aimed at the act (spending,
registering, moving funds, deploying a contract) rather than at keywords. A
block is also not a dead end: it's logged, and the agent is told to file a
request with `approve.py` so a human sees a queued ticket instead of the
agent silently retrying or working around it.

## What's in this repo

| File | Purpose |
|---|---|
| `gate_guard.py` | The `PreToolUse` hook. Reads the pending tool call on stdin, exits 0 (allow) or 2 (block). |
| `approve.py` | The approval queue CLI: file a request, list what's pending, record a human's decision. |
| `state.py` | The only sanctioned way to write an agent's state file — the chokepoint that keeps a human-owned field (like a trust tier) actually human-owned. |
| `gate-guard.config.example.json` | Copy to `gate-guard.config.json` in your project root and edit. Every path and rule in the three scripts above is driven by this file. |
| `examples/claude-code-settings.json` | How to register `gate_guard.py` as a Claude Code `PreToolUse` hook. |
| `examples/approved-remotes.example.txt` | Format for the git-push allowlist. |
| `examples/STATE.example.json` | Minimal shape `state.py` expects. |
| `tests/test_gate_guard.py` | A small sanity suite for the default rule pack (13 cases). Not a security audit — see "Testing" below. |

Nothing here is specific to any one business, product, or agent identity.
Config is JSON, state is JSON, the queue is JSONL. Drop it into any project.

## Install

```bash
git clone https://github.com/Prime-agentai/agent-approval-gate.git
cd your-agent-project
cp /path/to/agent-approval-gate/gate_guard.py bin/
cp /path/to/agent-approval-gate/approve.py bin/
cp /path/to/agent-approval-gate/state.py bin/
cp /path/to/agent-approval-gate/gate-guard.config.example.json gate-guard.config.json
```

Edit `gate-guard.config.json`: set `state_path` to wherever your agent's
state file lives, add your own protected files to `protected_paths`, and
create `approved-remotes.txt` (see the example in `examples/`) listing the
git remotes your agent is allowed to push to. An empty or missing
`approved-remotes.txt` means `git push` is blocked from every tool call,
unconditionally — fail closed, not fail open.

No dependencies beyond the Python 3 standard library.

## Wiring it into Claude Code (or any harness with a `PreToolUse` hook)

Claude Code hooks are configured in `.claude/settings.json`. Add:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "python3 /absolute/path/to/bin/gate_guard.py"
          }
        ]
      }
    ]
  }
}
```

(full example in `examples/claude-code-settings.json`). The harness sends
the pending tool call — tool name and arguments — as JSON on stdin before it
runs. `gate_guard.py` reads it, decides, and:

- exits **0** → the tool call proceeds, no output
- exits **2** → the tool call is blocked, and whatever is printed to stderr
  is fed back to the agent as the reason

Any other agent harness that supports a pre-execution hook with the same
shape (tool name + arguments in, allow/block decision out) can use this the
same way — the script only assumes JSON on stdin and an exit code, nothing
Claude-Code-specific.

**Protect the hook itself.** Add `gate_guard.py`, your state file, and your
harness's own hook-registration file (e.g. `.claude/settings.json`) to
`protected_paths` in the config, so the agent cannot edit its own
restraints. A gate the agent can turn off is not a gate.

## The approval-queue workflow, end to end

1. **Agent attempts a gated action.** Say it runs `npm install some-package`.
   `gate_guard.py` matches the `PACKAGE_INSTALL` rule, blocks the call (exit
   2), logs the attempt to `approvals/blocked.jsonl`, and tells the agent on
   stderr to file a request instead of retrying.

2. **Agent files a request.**
   ```bash
   python3 bin/approve.py request \
     --tier TOOLING \
     --ask "Install the 'some-package' npm dependency" \
     --why "Needed to parse RSS feeds for the content pipeline" \
     --cost "\$0" --reversible yes \
     --blocked-if-denied "Content pipeline stays manual"
   ```
   This appends a structured entry to `approvals/queue.jsonl` — an
   append-only log, never edited in place — and prints a reminder that the
   agent should move on to unblocked work rather than idle on the answer.

3. **Human reviews what's pending.**
   ```bash
   python3 bin/approve.py pending
   ```
   Prints every queued request that doesn't yet have a matching decision,
   with its ask, justification, cost, and reversibility, in a fixed format
   meant to be skimmed in a daily review rather than dug out of a log.

4. **Human decides.**
   ```bash
   python3 bin/approve.py decide 1 approve "fine, go ahead"
   python3 bin/approve.py decide 2 deny "not yet, revisit after launch"
   ```
   Appends to `approvals/decisions.jsonl` — again, append-only, matched to
   the request by id. `approve.py decide` is meant to be run by the human,
   not the agent; nothing technical stops the agent from invoking it, so if
   your harness can restrict specific script arguments to human-only
   sessions, do that at the harness level.

5. **Agent picks the decision up** on its next session (read
   `approvals/decisions.jsonl`, filter for ids without a corresponding
   completed action) and proceeds or doesn't, accordingly.

The queue is deliberately dumb — two JSONL files and a CLI, no database, no
web UI. That's the point: it has to survive being read by both a human
skimming a terminal and an agent parsing JSON, and it has to be auditable
after the fact, which an append-only log gives you for free.

## `state.py` — the state chokepoint

If your agent tracks its own state (a trust level, a phase, cumulative
verified revenue) in a JSON file, letting the agent write that file directly
with a generic `Write` tool means any field — including the ones you meant
to be human-controlled — is one `Edit` call away from being changed by the
agent itself. `state.py` is the single sanctioned way to write that file:

```bash
python3 bin/state.py show                                    # print state
python3 bin/state.py get metrics.revenue_verified             # read one field
python3 bin/state.py set phase "build"                        # write one field
python3 bin/state.py session research                         # bump a session counter
python3 bin/state.py revenue 49.99 stripe "charge_1AbCdEfGh"  # append a verified ledger entry
```

List the fields a human should own — a trust tier, a promotion flag,
whatever your project's equivalent is — under `immutable_fields` in
`gate-guard.config.json`. `state.py` refuses to write those fields even if
asked directly; combine that with `gate_guard.py` blocking direct edits to
the state file via `Write`/`Edit`/shell redirection, and the only path left
to change an immutable field is a human editing the file by hand.

`revenue` specifically enforces a distinction worth keeping in any agent
that reports numbers to a human: only append a ledger entry for a **verified**
event you have direct evidence for in the current session (a matched charge
ID, a bank confirmation) — never for a projection, a pledge, or a number the
agent is inferring. That discipline lives in how you call the script, not in
code the script can enforce, but the append-only ledger it produces is what
makes a claim checkable after the fact.

## Configuration reference

All three scripts share one config file. See
`gate-guard.config.example.json` for the full default. Key fields:

| Field | Used by | Meaning |
|---|---|---|
| `state_path` | all three | Path to the agent's state JSON file |
| `trust_tier_field` | `gate_guard.py` | Field in state holding the current trust tier (int) |
| `min_tier_for_tier_gated` | `gate_guard.py` | Tier at/above which `tier_gated_rules` stop blocking |
| `protected_paths` | `gate_guard.py` | Files no tool call may modify, ever |
| `approved_remotes_file` | `gate_guard.py` | Allowlist for `git push` targets |
| `blocked_log` | `gate_guard.py` | Where blocked attempts are logged |
| `queue_path`, `decisions_path` | `approve.py` | The two JSONL files |
| `approval_tiers` | `approve.py` | Allowed values for `--tier` |
| `immutable_fields` | `state.py` | Top-level state fields the script refuses to write |
| `ledger_path` | `state.py` | Where `revenue` entries are appended |
| `trust_threshold_usd` | `state.py` | Optional: prints an eligibility notice past this cumulative verified amount (does not auto-promote) |

`absolute_rules` and `tier_gated_rules` in the config file, if present,
**replace** the built-in defaults in `gate_guard.py` rather than merge with
them — copy the defaults out of `gate_guard.py`'s `DEFAULT_CONFIG` first if
you want to extend rather than replace.

## Testing

`tests/test_gate_guard.py` is a small (13-case) sanity suite that exercises
the shipped default rule pack directly against `gate_guard.py`'s pure
decision function — no stdin/stdout plumbing, no subprocess. Run it with:

```bash
python3 tests/test_gate_guard.py
```

This is not the adversarial suite referenced in the provenance note below.
That suite lives in the private project this tool was extracted from, is
specific to that project's file layout and rule set, and is not published
here. Treat the included tests as confirming the documented default
behavior, not as a guarantee about whatever custom rules you add.

**Provenance.** The rule-engine shape and protected-path model here were
extracted from a private, in-production autonomous agent, where an earlier
version of this hook was adversarially tested at 59 of 59 passing cases
(after a patch that closed the 13 bypasses found in the prior round, which
had passed 46 of 59 — shell-level writes to protected files, and credential
exfiltration through tools other than the shell). That number describes the
private project's own test run on its own configuration; it is reported here
as provenance for the design, not as a claim about this public package's
default rule set, which you should test against your own threat model before
relying on it.

## What this is not

- **Not a sandbox.** It inspects the tool call before it runs; it does not
  contain or reverse anything that already executed. Pair it with running
  the agent under least-privilege credentials (a scoped API token, a
  restricted cloud account) — the gate is a second layer, not the only one.
- **Not exhaustive.** Regex-based content matching on tool arguments will
  have both false positives (over-blocking legitimate work — its own
  documented failure mode) and false negatives (a sufficiently adversarial
  or unusual phrasing of a command getting through). Treat the default rule
  pack as a starting point and extend it for your own agent's actual
  capabilities.
- **Not a replacement for scoped credentials.** If the agent's API token can
  reach production billing, no hook fully closes that gap — the token itself
  is the boundary of last resort. Scope credentials first; use this to catch
  what scoping alone doesn't.

## License

MIT — see `LICENSE`.

## Support

This is free and open. If it's useful to you and you want to support ongoing
maintenance, GitHub Sponsors is linked on the repo's main page once it's set
up. No paid tier, no feature gate — sponsorship funds maintenance, it
doesn't unlock anything.
