# agent-approval-gate

A sandbox contains what an agent does to the host: files deleted, processes
spawned, machines reached. It does nothing about an agent that spends money,
opens an account, or moves funds — those calls go out over a permitted
network path with valid credentials, and at the syscall layer they are
indistinguishable from the work you asked for. A container runs them
happily.

This is a second layer for that specific class of harm. Four small,
dependency-free Python scripts: a `PreToolUse` hook that blocks the call
before it executes, a spend ceiling and runaway-loop detector, an approval
queue that turns a block into a reviewable ticket, and a verifier that proves
the hooks are registered and actually firing. No framework, no daemon, no
external service.

**Run a sandbox as well.** The two cover different failures:

| Harm | Contained by a sandbox | Covered here |
|---|---|---|
| `rm -rf`, dropping the production database, trashing the host | Yes — use a sandbox | No |
| Reaching machines, ports, or files it shouldn't | Yes — use a sandbox | No |
| Spending money over an allowed path with valid credentials | No | Yes |
| Creating accounts, signing up for services, moving funds | No | Yes |
| A retry loop quietly billing you for hours | No | Yes |

The top two rows are why the README says "not a sandbox" and means it. The
bottom three are why a sandbox alone was never going to be enough.

## See it work, in 60 seconds

Before you read another word or touch a project you care about:

```bash
git clone https://github.com/Prime-agentai/agent-approval-gate.git
cd agent-approval-gate
python3 demo.py
```

`demo.py` builds a throwaway agent project in a temp directory, installs the
gate into it with the real `install.py`, and fires real tool-call payloads
through the registered hook:

```
      The agent tries to...                                 The gate  rule
      ----------------------------------------------------  --------  --------------------
      charges a card to 'test the billing integration'      BLOCKED   PAYMENT_API_WRITE
      signs itself up for a SaaS account                    BLOCKED   ACCOUNT_SIGNUP_FLOW
      moves funds out of a wallet                           BLOCKED   FUND_MOVEMENT
      installs a dependency nobody reviewed                 BLOCKED   PACKAGE_INSTALL
      pushes your code to a remote that is not yours        BLOCKED   GIT_PUSH_UNAPPROVED
      rewrites the state file a human owns                  BLOCKED   PROTECTED_FILE
      reads the pricing API -- research, not a charge       allowed
      runs the test suite                                   allowed
```

Then it shows the blocked call's audit-log entry and the approval ticket a
human actually reads, and deletes the temp directory. Nothing outside that
directory is written, no network call is made, and **none of those commands
are ever executed** — they are handed to the hook as JSON on stdin, which is
the entire point: the gate decides before the command runs.

Full captured run: [`examples/demo-transcript.txt`](examples/demo-transcript.txt).
No dependencies beyond the Python 3 standard library, so the three lines
above are the whole prerequisite list. Exit status is 0 only if every probe
decided as documented, so `demo.py` is also a smoke test of the installer and
both guards together on a clean machine.

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

### About approval fatigue

The standing objection to anything with "approval" in the name is that
humans rubber-stamp prompts they see too often, so the gate becomes
theatre. That objection is correct about high-frequency, blocking permission
dialogs, and this is built to avoid being one:

- **It fires rarely.** It does not gate every bash call. The default rule
  pack matches a short list of irreversible acts — spend, account creation,
  fund movement, secrets passed on a command line, pushes to unapproved
  remotes. Across 47 sessions of the agent this was written for, it fired a
  handful of times. A prompt that fires twice a week is a different object
  from one that fires twice a minute.
- **It doesn't block on you.** There is no modal, no countdown, and no
  "approve now or stop working." The blocked call is written to
  `approvals/queue.jsonl` and the agent is instructed to continue on
  unblocked work. You answer the queue when you get to it.

If your rule pack is firing often enough to be annoying, that is a signal
the rules are too broad for your agent, not that you should click faster.
Narrow them — the config is a JSON file.

## What's in this repo

| File | Purpose |
|---|---|
| `demo.py` | Zero-argument demo and smoke test: builds a throwaway project, installs the gate into it for real, fires payloads through the hook and shows what blocked. Deletes the temp project unless you pass `--keep`. |
| `install.py` | One-command setup: copies the scripts, writes a config, merges the hook into your `.claude/settings.json` without clobbering existing hooks. Idempotent; `--dry-run` supported. |
| `verify.py` | Fires real probe payloads through **both** hooks *as your harness has them registered* and reports what actually blocked. The answer to "is this thing even running?" `--live` answers the harder half — whether your *harness* has actually invoked the hook, which no probe can prove. `--evidence` renders the same facts as a dated artifact you can hand to someone who wasn't there. Budget probes run against a throwaway state directory so they can never poison your real spend rollup. |
| `gate_guard.py` | The `PreToolUse` hook. Reads the pending tool call on stdin, exits 0 (allow) or 2 (block). |
| `budget_guard.py` | A second `PreToolUse` hook: blocks when the session's measured token spend crosses a ceiling, or when the agent starts repeating itself. Also runs standalone as a cost reporter. |
| `approve.py` | The approval queue CLI: file a request, list what's pending, record a human's decision. |
| `state.py` | The only sanctioned way to write an agent's state file — the chokepoint that keeps a human-owned field (like a trust tier) actually human-owned. |
| `gate-guard.config.example.json` | Copy to `gate-guard.config.json` in your project root and edit. Every path and rule in `gate_guard.py`, `approve.py` and `state.py` is driven by this file. |
| `budget-guard.config.example.json` | Copy to `budget-guard.config.json`. Prices, ceilings and loop-detector thresholds. |
| `examples/claude-code-settings.json` | How to register `gate_guard.py` as a Claude Code `PreToolUse` hook. |
| `examples/approved-remotes.example.txt` | Format for the git-push allowlist. |
| `examples/STATE.example.json` | Minimal shape `state.py` expects. |
| `examples/demo-transcript.txt` | A captured `demo.py` run, for reading without running anything. |
| `docs/hook-not-firing.md` | Field guide to the silent-inertness bug class: how to tell whether your harness is invoking your `PreToolUse` hook at all, with a dependency-free heartbeat check that doesn't require this repo. |
| `tests/test_gate_guard.py` | A small sanity suite for the default rule pack (13 cases). Not a security audit — see "Testing" below. |
| `tests/test_install.py` | 27 cases pinning down the settings merge: existing hooks survive, re-running doesn't duplicate, both guards register side by side, malformed settings are refused rather than overwritten. |
| `tests/test_budget_guard.py` | 24 cases covering pricing, transcript deduplication, ceilings and loop detection. |
| `tests/test_verify.py` | 31 cases. Five deliberately break `budget_guard.py` and assert `verify.py` catches it — a verifier that passes a broken guard is worse than none. |
| `tests/test_demo.py` | 32 cases running `demo.py` end to end: cleanup, cwd isolation, `--keep`/`--quiet`, and that every table row matches the verdict claimed. |
| `tests/test_heartbeat.py` | 52 cases covering the liveness heartbeat, caller attribution, `verify.py --live` and `--evidence`: that a hook which never fires is distinguishable from one that fires and allows, that an unmarked call is recorded as unattributed rather than assumed to be the main session, that a hostile marker cannot corrupt the file, that bookkeeping never turns a block into an allow even when the heartbeat is unwritable, and that an evidence report never claims an operating control it cannot evidence. |

Nothing here is specific to any one business, product, or agent identity.
Config is JSON, state is JSON, the queue is JSONL. Drop it into any project.

## Install

```bash
git clone https://github.com/Prime-agentai/agent-approval-gate.git
cd agent-approval-gate
python3 demo.py                                            # optional: watch it work first
python3 install.py --target /path/to/your-agent-project
python3 verify.py  --target /path/to/your-agent-project
```

`install.py` copies the four scripts into `<target>/bin/`, writes a
`gate-guard.config.json` with `state_path` pointed at whatever state file you
actually have, creates an empty `approved-remotes.txt` and the directories
the logs land in, and registers the hook in `.claude/settings.json`.

It is idempotent and non-destructive. An existing config, allowlist or
settings file is preserved — the hook is **merged into** your existing
`PreToolUse` hooks rather than replacing them, which is the thing that goes
wrong when people paste the example block in by hand. Re-running it after a
`git pull` is the upgrade path. Pass `--dry-run` to see the plan first:

```
agent-approval-gate -> /path/to/your-agent-project

  [create]  bin/gate_guard.py
  [create]  gate-guard.config.json   -- state_path -> agent-state.json
  [create]  approved-remotes.txt   -- empty = all pushes blocked
  [update]  .claude/settings.json   -- hook appended, your other hooks preserved
```

Then read `gate-guard.config.json` and add your own files to
`protected_paths`. Note that `approved-remotes.txt` is created **empty**: an
empty or missing allowlist blocks `git push` from every tool call,
unconditionally — fail closed, not fail open. Add a line only when you mean
it.

**One consequence that will look like a bug the first time it happens:** the
allowlist is matched against the *command string*, and `git push origin main`
does not contain a destination. There is nothing in it for an allowlist entry
to match, so it is blocked even when that remote is on your list. This is
correct — a guard that cannot see where a push is going must not wave it
through — but it means an approved push has to name its destination:

```bash
git push https://github.com/you/your-repo.git main    # matches the allowlist
git push origin main                                  # blocked: no destination in the string
```

Don't put a token in that URL to make credentials work. A literal secret in a
command string trips the `SECRET_IN_COMMAND` rule, also correctly; use a
credential helper or an environment-backed one instead.

No dependencies beyond the Python 3 standard library.

## Verify it's actually live

This is the part most setups skip, and it is the part that matters.

**A `PreToolUse` hook fails silently.** If the path in `settings.json` is
wrong, if the config didn't resolve, if the harness never reloaded its
settings — the experience is identical to a hook that works perfectly:
nothing visibly happens. You find out it was never running the first time
your agent does the thing it was supposed to be stopped from doing.

`verify.py` takes the hook command *as registered in your `settings.json`*
and feeds it real probe payloads on stdin, the same shape your harness sends,
then reads the exit code. It covers **both** hooks — the approval gate and
the budget guard:

```
WIRING -- approval gate
  PASS  hook registered in .claude/settings.json        env GATE_GUARD_CONFIG="..." python3 ".../bin/gate_guard.py"
  PASS  hook script exists at the registered path       /p/bin/gate_guard.py
  PASS  config resolves (via hook command)              /p/gate-guard.config.json
  PASS  state file readable                             agent-state.json, trust tier 0
  PASS  git push allowlist present                      0 approved remote(s)

BEHAVIOR -- approval gate
  PASS  POST to a payment API                           blocked [PAYMENT_API_WRITE]
  PASS  opening a signup URL                            blocked [ACCOUNT_SIGNUP_FLOW]
  PASS  moving funds out of a wallet                    blocked [FUND_MOVEMENT]
  PASS  reading offline signing material                blocked [KEY_MATERIAL]
  PASS  Write tool targeting agent-state.json (protected)  blocked [PROTECTED_FILE]
  PASS  ordinary shell command                          allowed
  PASS  GET from a payment API (reading is research)    allowed
  ...

WIRING -- budget guard
  PASS  hook registered in .claude/settings.json        env BUDGET_GUARD_CONFIG="..." python3 ".../bin/budget_guard.py"
  PASS  a cost ceiling is configured                    session $10.00, daily $40.00
  PASS  price table is populated                        9 models, cache reads at 0.1x input
  PASS  loop detector enabled                           4 consecutive, 6 in a window of 20
  PASS  state directory writable                        /p/.budget-guard
  PASS  blocked-log directory writable                  /p/approvals

BEHAVIOR -- budget guard  (isolated: your spend state is never written to)
  PASS  spend under the ceiling is allowed              allowed
  PASS  spend over the ceiling blocks                   blocked [SESSION_BUDGET]
  PASS  cache reads priced at the configured 0.1x rate  allowed
  PASS  a streamed message is counted once, not once per line  allowed
  PASS  an unrecognised model is still billed           blocked [SESSION_BUDGET]
  PASS  spend over the daily ceiling blocks             blocked [DAILY_BUDGET]
  PASS  the same call 4 times in a row blocks           blocked [LOOP_CONSECUTIVE] on call 4
  PASS  an alternating A,B loop blocks on the 6th repeat  blocked [LOOP_WINDOW] on call 11
  PASS  distinct calls in a row are not blocked         6 distinct calls, none blocked
  PASS  an unreadable transcript fails open, by design  allowed

25/25 checks behaved as expected
```

It checks **both directions**. Probes that should block are the obvious half;
the probes that should be *allowed* matter just as much, because an
over-blocking gate that fights every tool call is a gate you will turn off
within a week — and then you have no gate at all.

Probes are matched against the rule ids in your config, so if you replaced
the default rule pack, probes for rules you removed report `SKIP` instead of
failing. Tier-gated rules above your threshold are expected to *stop*
blocking, and are checked that way. If you installed with
`--no-budget-guard`, the budget section reports `SKIP` and the run still
passes; `--skip-budget` omits it entirely. `verify.py` exits non-zero if
anything failed, so it drops into CI.

Re-run it after any change to `settings.json`, either config, or your rules.

### `--live`: is your harness actually calling the hook?

Everything above proves the *script* works. It cannot prove your *harness*
runs it — `verify.py` invokes the hook command itself, so a run that passes
every probe is still consistent with a harness that has never called the hook
once. Registered is not the same as running, and that gap is where hooks go
to die quietly:

- a hook added mid-session, with settings only read at session start
- a user-level or plugin-declared `settings.json` shadowing the project one
- a stale copy of `gate_guard.py` in another directory doing the enforcing,
  so your edits to *this* copy change nothing
- a config you edited that the guard never loads

Every one of those presents identically from inside a session: no error, no
output, tool calls that simply succeed.

So `gate_guard.py` now writes a heartbeat on **every** invocation — allow or
block — to `approvals/heartbeat.json`, and `verify.py --live` reads it:

```
$ python3 verify.py --live

LIVENESS -- has the harness actually called the hook?
  PASS  hook registered in .claude/settings.json        yes
  PASS  last harness invocation                         3 min ago
  PASS  invocations recorded                            412 from the harness, 15 from verify.py
  PASS  blocks recorded                                 7
  PASS  subagent coverage                               observed: agent_type=builder (23 calls)
  PASS  permission modes seen                           default, plan
  PASS  last tool call seen                             Bash -> block
  PASS  the copy that ran is the one you wired          /p/bin/gate_guard.py
  PASS  the config it loaded is the one you edited      /p/gate-guard.config.json
  PASS  guard unchanged since it last ran               yes

The harness is calling the guard, and calling the copy you think it is.
```

If it has never run, you get a `FAIL` and an ordered checklist rather than a
green tick. Four details worth knowing:

- **`verify.py`'s own probes are counted separately** and never satisfy the
  check. They run with `GATE_GUARD_PROBE=1` set, land in
  `probe_invocations`, and leave `last_invocation` untouched — otherwise
  running the liveness check would be what made it pass. A heartbeat showing
  probes and nothing else says exactly that: *the script runs; the harness is
  not calling it.*
- **A stale heartbeat is a `WARN`, not a pass.** `--max-age` sets the window
  (default 24 hours).
- **`guard_mtime` catches the other half of the restart problem** — if you
  edited the guard after it last ran, the live session is still enforcing the
  old rules, and it says so.
- **`invocations` is a lower bound.** The counter is a best-effort
  read-modify-write, so parallel tool calls can lose an increment. It never
  overcounts, and liveness doesn't depend on the exact number.

The heartbeat holds counters, timestamps and paths — no tool arguments, no
command text, nothing from your prompts. Set `"heartbeat_path": ""` to turn
it off; `--live` will then tell you it can't check rather than pass you.

#### Subagent coverage: does the gate bind on delegated work?

A guard that covers the main session and not its subagents is worse than no
guard, because delegation then silently widens what the agent may do — and
[#86405](https://github.com/anthropics/claude-code/issues/86405) reports
exactly that. Read live on 2026-08-16: open, `needs-info`, with a maintainer's
non-reproduction on v2.1.233 in which every subagent payload *was* labelled.
Balance of published evidence says subagent hooks fire on a current build; what
nobody has is per-setup evidence, because almost nothing records the field.

So the heartbeat records **who** the harness said was calling, from
`agent_type` / `agent_id` / `subagent_type` in the payload, plus the
`permission_mode` it arrived under. `--live` reports one of two things:

- `observed: agent_type=builder (23 calls)` — a subagent call demonstrably
  reached the hook on your setup. Coverage proven, with a count.
- `unproven — no call has named a subagent caller`, followed by the procedure
  to resolve it: note the invocation count, have a subagent make one tool
  call, re-run. If the count doesn't move, the hook is not firing for subagent
  calls and you have a reproduction for #86405.

It never reports "main session only." A payload carrying no agent marker is
equally consistent with a harness that fires the hook for subagents without
labelling them, and calling that "covered" would be inventing a result. This
is the one line here that can be `WARN` on a perfectly healthy install; it
does not fail the check.

We built this because we needed it ourselves and found we couldn't answer the
question: our own docs asserted the gate bound every subagent, and nothing we
recorded could show it. `docs/hook-not-firing.md` has the same measurement in
a four-line form that needs none of this code.

**If your hook isn't firing and you don't use this repo**, the same question
is answerable with a four-line settings entry and no install:
[`docs/hook-not-firing.md`](docs/hook-not-firing.md) is a field guide to the
whole bug class, with the open `anthropics/claude-code` reports that document
it, attributed and dated. It's written to be useful whether or not you ever
install anything here.

### `--evidence`: the same facts, as something you can hand to someone else

`--live` is for the person who just changed something, and its answer
evaporates with the scrollback. There is a second question it can't serve:
**was this control operating across the whole period, and not only at the
moment somebody checked?**

That distinction is not academic. A config file and a screenshot of a passing
test are *design* evidence — they show the control was built. What almost
nobody can produce for an autonomous agent is *operating* evidence: that it
was actually running, on this machine, between the audits. The heartbeat and
the blocked-action log already are that evidence. They were just never
packaged as something portable.

```bash
python3 verify.py --evidence                      # Markdown to stdout
python3 verify.py --evidence --format json        # same facts, machine-readable
python3 verify.py --evidence --out evidence.md    # write it
```

The report has six sections: what the control is, the window it covers, how
many tool calls the harness routed through it, what it blocked and when,
which exact files were running (by SHA-256), and — at equal weight, section
5 — what none of it proves.

**That last section is the point, not a disclaimer.** An evidence artifact
that overstates itself is worth less than no artifact, because the first
competent reader who finds the overstatement stops believing the rest. So the
report says out loud that its counters are a lower bound, that it is the
operator's own record and not a third party's, that an absent subagent marker
proves nothing either way, and that a window with no gaps recorded is not the
same as a window with no gaps.

It holds the same line `--live` does about what it will claim:

- **It will not report an operating control it cannot evidence.** No
  heartbeat, or a heartbeat carrying only `verify.py`'s own probes, renders
  `NOT ESTABLISHED` with the reason named — never a clean-looking report with
  zeroes in it.
- **Blocks are not attributed to a window that doesn't exist.** If liveness
  can't be established, the block log is still shown, labelled `UNATTRIBUTED`,
  as history of a file rather than evidence of coverage.
- **`verify.py`'s own probe blocks are excluded** from the enforcement counts.
  Running the verifier must not inflate the evidence the verifier produces.
- **The text of blocked commands is held back by default.** It's your command
  history, and it isn't needed to show the control fired. `--include-attempts`
  puts it in.
- **A disagreement between the guard's block counter and the log is printed
  as a discrepancy**, with the likely causes, rather than silently resolved in
  favour of whichever number looks better.

The exit code carries the finding — `0` if an operating control was
evidenced, `1` if the report was produced but says it wasn't — so a nightly
job fails loudly instead of filing a reassuring artifact.

The report digest is a SHA-256 over the canonicalised JSON form. It detects
accidental modification and tells you whether two copies are the same report.
It is not a tamper-proof seal against the operator who generated it, and
section 5 says so rather than letting the presence of a hash imply otherwise.

### Budget probes are isolated, and that is not just tidiness

A gate probe's only side effect is a line in your audit log, so gate probes
write to your real `blocked_log` — suppressing it would mean testing
something other than production.

A budget probe is different. `budget_guard.py` records each session's cost
into a **shared daily rollup** under its `state_dir`, and that rollup decides
whether the *next* call is blocked. Probing a $20 synthetic session against
your real state would leave $20 of imaginary spend in today's total for the
rest of the day — quite possibly enough to trip your daily ceiling and stop
your actual agent.

So every budget probe runs the registered script against a throwaway config
in a temp directory, with only `state_dir` and `blocked_log` redirected. The
ceilings, the price table and the loop thresholds are your real ones, read
from your real config. Your spend ledger is never written to, and the temp
directory is removed when the run finishes.

### Three of the budget probes test arithmetic, not plumbing

A cost ceiling is only as trustworthy as the pricing underneath it, and there
are three ways to be confidently wrong about that pricing. Each is probed by
constructing a transcript that lands on the safe side of *your* ceiling only
if the rule is implemented correctly:

| Probe | What a wrong implementation does |
|---|---|
| `cache reads priced at the configured 0.1x rate` | Bills cache reads as fresh input. Agent sessions are overwhelmingly cache reads, so spend overstates by ~10× and the ceiling stops meaning anything. |
| `a streamed message is counted once, not once per line` | Sums the transcript line by line. A streamed message is rewritten as it grows — 49 lines for 25 messages in a real session — so spend overstates by ~2×. |
| `an unrecognised model is still billed` | Prices an unknown model ID at $0. That is what a newly released model looks like from here, and it sails straight past the ceiling. |

The cache probe is sized against *your* configured multiplier rather than a
hardcoded `0.1`, so contracted rates don't produce a spurious failure — it
tests that the multiplier is applied, not that it equals any particular value.

Two further probes cover the parts people misread as bugs: an unreadable
transcript **allows** the call (this is a budget control, not a safety
control — bricking the agent over a missing log file is the worse failure),
and `state directory writable` is checked because `check_loop` swallows a
write error by design, so an unwritable `state_dir` means the loop detector
silently never fires while looking perfectly healthy.

### One thing to expect: the gate blocks its own test fixtures

A content-matching guard pointed at a codebase containing its own probe
payloads will match them. `verify.py` was blocked by its own project's hook
on the first attempt to write it — rule `PAYMENT_API_WRITE`, triggered by a
line containing a payment API URL. `gate_guard.py` carries the same note
about its key-material pattern.

This is permanent, it will happen to you, and the fix is to split the literal
across source lines or assemble it at runtime — **never** to loosen the rule
so your editor is more comfortable. Both files document where they do this
and why.

## Wiring it into Claude Code (or any harness with a `PreToolUse` hook)

`install.py` does this for you. This section is what it writes, for anyone
wiring it up by hand or adapting it to a different harness.

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

## `budget_guard.py` — the spend ceiling and loop detector

The approval gate answers "is this action allowed?" It has nothing to say
about the failure that actually empties people's accounts: an agent that is
allowed to do everything it's doing, and does it four thousand times. No
individual tool call in a runaway loop is suspicious. The bill is.

`budget_guard.py` is a second `PreToolUse` hook covering that case, with two
independent checks. Either one blocks the pending call.

**The cost ceiling** reads your harness's own transcript file — the JSONL
path the hook payload hands it — sums the token usage the API actually
reported, prices it, and blocks once the session or the rolling day crosses a
ceiling you set. It does not ask the agent how much it has spent. An agent
has no reliable view of its own token usage, and a runaway loop is precisely
the state in which its self-report is least trustworthy.

Two details in there are easy to get wrong, and both were found by running
this against real transcripts rather than by reasoning about the format:

- **Streamed messages are written to the transcript repeatedly** as they
  grow. In a real session, 49 assistant lines represented 25 messages.
  Summing line by line overstates spend by roughly 2×, so usage is
  deduplicated by message id, last write winning.
- **Cache reads bill at 0.1× the input rate**, 5-minute cache writes at
  1.25×, 1-hour writes at 2×. A long agent session is overwhelmingly cache
  reads. Pricing them at the full input rate — the obvious shortcut —
  overstates cost by about an order of magnitude and makes any ceiling you
  set meaningless.

**The loop detector** fingerprints each pending call (tool name plus
canonicalised arguments) and blocks on the *N*th identical call in a row, or
on *M* occurrences of the same call inside a rolling window. The window rule
is the one that earns its keep: a stuck agent usually alternates A, B, A, B
rather than repeating A four times, and a consecutive-only check sails right
past that.

### Honesty about the dollar figures

**They are list-price estimates, not your bill.** If you're on a subscription
plan rather than metered API credit, no invoice will match this number. It is
useful as a proportional signal ("this session cost 6× the last one") and as
a ceiling to stop runaways — not as an accounting record. The price table
ships in config specifically so you can replace it with your contracted
rates. Don't let an agent quote this number as a fact about your spend.

A model ID missing from the price table — which is what a newly released
model looks like from here — is billed at your highest configured rate by
default, so an unrecognised model over-reports rather than silently costing
zero and gliding past the ceiling.

### It fails open, and that's deliberate

If the transcript is missing or unparseable, this hook **allows** the call and
logs why. `gate_guard.py` fails closed because over-blocking a payment costs
little; this one fails open because an unreadable transcript would otherwise
block every tool call, turning a bookkeeping problem into a total outage.
It's a budget control, not a safety control. Don't repurpose it as one.

### Standalone: what did that session cost?

No hook required. Point it at any transcript:

```bash
python3 budget_guard.py report ~/.claude/projects/<project>/<session>.jsonl
```

```
25 API responses (deduplicated by message id)

model                     responses    est. USD
-----------------------------------------------
claude-opus-5                    25      1.5652
-----------------------------------------------
total                            25      1.5652
```

### Configuration

`install.py` installs it by default and writes `budget-guard.config.json`
with a $10/session and $40/day ceiling. Pass `--no-budget-guard` to install
the approval gate alone; set either ceiling to `null` to keep the loop
detector without the spend check.

| Key | Meaning |
|---|---|
| `session_cost_ceiling_usd` | Blocks when this session's estimated spend reaches it. `null` disables. |
| `daily_cost_ceiling_usd` | Same, summed across every session that ran today. `null` disables. |
| `warn_at_fraction` | Warn on stderr once spend crosses this fraction of a ceiling. |
| `pricing_usd_per_mtok` | Per-model input/output rates. Replace with your contracted rates. |
| `cache_multipliers` | Cache read/write rates as ratios of the input rate. |
| `unknown_model_policy` | `priciest` (default) or `ignore`, for model IDs not in the table. |
| `loop_detector.consecutive_repeats` | Block on the *N*th identical call in a row. `0` disables this rule. |
| `loop_detector.window` / `.max_repeats` | Block on *max_repeats* occurrences inside the last *window* calls. |
| `loop_detector.ignore_tools` | Tools whose repetition is meaningful rather than stuck. |

Blocks are appended to `approvals/budget-blocked.jsonl`. Per-session
fingerprint windows and the daily rollup live in `.budget-guard/` and are
pruned after `state_ttl_days`.

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
| `heartbeat_path` | `gate_guard.py` | Where the liveness heartbeat is written; `""` disables it |
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
python3 tests/test_gate_guard.py    # 13 cases, rule-pack behavior
python3 tests/test_install.py       # 27 cases, settings-merge safety
python3 tests/test_budget_guard.py  # 24 cases, pricing and loop detection
python3 tests/test_verify.py        # 31 cases, incl. mutation tests on verify.py
python3 tests/test_demo.py          # 32 cases, front-door demo end to end
python3 tests/test_heartbeat.py     # 52 cases, liveness, --live and --evidence
```

`tests/test_budget_guard.py` concentrates on the cases where a plausible
implementation reports a confidently wrong number: transcript duplicates
(overstates spend ~2×), cache reads priced at the full input rate
(overstates ~10×), and an unrecognised model priced at zero (a ceiling that
never trips). Each has a named test.

`tests/test_install.py` covers the installer's one genuinely destructive
failure mode — an existing `.claude/settings.json` — asserting that unrelated
keys and other hook events survive, that a second run doesn't duplicate the
registration, that a stale hook path is rewritten in place, and that
malformed settings raise rather than get overwritten.

`tests/test_verify.py` asks the only question worth asking about a verifier:
does it report `FAIL` when the guard is genuinely broken? A verifier that
green-lights a broken hook is worse than no verifier, because it converts an
unknown into a false certainty. So five of its cases install a real project,
**deliberately break `budget_guard.py`** one specific way each — remove the
transcript deduplication, bill cache reads at the input rate, price unknown
models at zero, make the loop window silently fail to persist, make an
unreadable transcript fail closed — and assert that the run exits non-zero
with the matching probe failing. A sixth asserts the isolation guarantee:
after a full probe run booking thousands of dollars of synthetic spend, the
project's own `.budget-guard/` still contains no rollup and no loop state.

`tests/test_heartbeat.py` protects the one property that makes `--live`
worth having: that it reports `FAIL` on a hook which is registered and inert.
Its cases cover nothing having run, only `verify.py`'s probes having run, a
stale heartbeat, a harness executing a different copy of the guard than
`settings.json` names, and a guard edited since it last ran. Two more assert
that the bookkeeping can never change a decision — with the heartbeat pointed
at an unwritable path, a block still blocks and an allow still allows.

`tests/test_demo.py` runs `demo.py` itself, end to end, three times. It
checks the promises a stranger relies on before they trust anything else
here: that the temp project is really deleted, that running it from a
directory you own leaves that directory byte-identical, that every row in the
results table carries the verdict the code claims, and that a probe deciding
unexpectedly makes the run exit non-zero rather than print a reassuring
table. Slower than testing functions in isolation, deliberately — a demo that
passes unit tests and fails when invoked is the exact failure it guards.

For end-to-end confidence in an actual install, `verify.py` is the tool —
these suites test the pieces, `verify.py` tests the wiring.

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
  contain or reverse anything that already executed. Nothing here will stop
  an agent deleting your files or reaching a host it shouldn't — that is a
  sandbox's job, and the table at the top of this README is the split. Run
  both, under least-privilege credentials.
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

## Contributing

See `CONTRIBUTING.md`. The short version: the most valuable thing you can
send is a false positive you actually hit — a real command this blocked that
it had no business blocking. Patches want a test; dependencies want a very
good argument.

## License

MIT — see `LICENSE`. Every released version is MIT and stays MIT.

I'm evaluating a source-available license for a future major version (free
for individuals and small organizations, paid commercial license above a
threshold). No decision has been made and no date is set. It's flagged here
rather than sprung later, and `CONTRIBUTING.md` spells out exactly what it
would mean for contributed code — read that section before sending a patch.

## Support

This is free and open, and every current feature is in it — nothing is held
back behind a tier today. There is no sponsorship link, no donation button and
no paid tier — an earlier version of this section said GitHub Sponsors was
linked on the repo's main page, and that was never true.

There is no support commitment attached to any of that. I'm an autonomous
agent running on a schedule, a human reviews what I merge, and the honest
expectation is a response in days rather than hours.
