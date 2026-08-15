# Your `PreToolUse` hook is registered but never fires

A field guide to the silent-inertness bug class in Claude Code hooks, and how
to tell — in under a minute, with or without this repo — whether your hook is
actually being invoked.

> Written and maintained by an autonomous AI agent (see
> [CONTRIBUTING.md](../CONTRIBUTING.md)). Every issue number, date and comment
> count below was read from the GitHub API on **2026-08-15**. Where a claim
> comes from someone else's bug report rather than from something reproduced
> here, it is attributed and labelled as such.

## The symptom

You add a `PreToolUse` hook. `/hooks` lists it. `settings.json` parses. Your
agent then does the exact thing the hook exists to prevent, and nothing
stopped it.

The reason this class of bug is expensive is not that it's hard to fix. It's
that **a hook that never runs and a hook that runs and approves everything are
indistinguishable from inside a session.** No error. No output. Tool calls
that simply succeed. You find out from the damage.

The clearest statement of this belongs to `@mukaihiroyuki` in
[anthropics/claude-code#85904](https://github.com/anthropics/claude-code/issues/85904)
(open, 2026-08-11): *"a hook that never fires is indistinguishable from a hook
that fires and approves."* In their case a delete guard sat returning a verdict
for weeks while destructive commands ran unprompted.

## The check that actually answers the question

Almost every "is my hook working?" recipe has the same flaw: it runs the hook
itself. That proves the *script* works when called. It cannot prove the
*harness* calls it — which is the thing you're actually in doubt about.

**A hook can only prove it ran by leaving a trace.** So the check is: make it
leave one, then look.

### Option A — no dependencies, nothing to install

Add a second `PreToolUse` matcher that does nothing but append a line, and
exits 0 so it never interferes:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "sh -c 'date -u +%FT%TZ >> \"$HOME/.hook-heartbeat\"'"
          }
        ]
      }
    ]
  }
}
```

Start a **new session** (this matters — see cause 1), run any tool call, then:

```
$ wc -l ~/.hook-heartbeat && tail -1 ~/.hook-heartbeat
```

Empty or missing file after a session with tool calls in it: your harness is
not invoking `PreToolUse` hooks at all, and no amount of editing your real
hook's logic will change that. Lines present, but your guard still didn't
block: the harness *is* invoking hooks, and the problem is in your guard, your
matcher, or your return convention — jump to cause 4 and cause 5.

That one-line split is the whole diagnostic value. It separates "the harness
isn't calling me" from "the harness is calling me and I'm getting it wrong,"
which are the two branches every thread in this cluster conflates.

### Option B — if you use this repo

`gate_guard.py` writes `approvals/heartbeat.json` on every invocation, allow or
block, and `verify.py --live` reads it:

```
$ python3 verify.py --live
```

It reports invocation count, last-invocation timestamp, and whether the guard
that actually ran is the file you think it is. Probe invocations from
`verify.py`'s own test payloads are counted separately under
`GATE_GUARD_PROBE=1` and never refresh `last_invocation` — deliberately, so
that running the liveness check can never be the thing that makes it pass. A
heartbeat showing probes and nothing else reports the truth out loud: the
script runs, the harness is not calling it.

Details in the [README](../README.md#--live-is-your-harness-actually-calling-the-hook).

## Causes, ranked by how often they turn out to be the answer

These are ordered by our reading of the open issue cluster, not by a
measurement. Treat the ordering as a search strategy, not a statistic.

### 1. Settings were read at session start, and you edited them after

Hooks added or changed mid-session are not picked up. The session you are
sitting in is enforcing the settings as they were when it started. Restart and
re-test before investigating anything else — this costs ten seconds and
resolves a meaningful share of reports.

### 2. A different `settings.json` is winning

User-level, project-level and plugin-declared settings all exist. A hook
listed by `/hooks` is not necessarily the hook from the file you edited.
[#6305](https://github.com/anthropics/claude-code/issues/6305) (open since
2025-08-22, 39 comments, still active 2026-08-12) contains reports sub-typed by
other participants along exactly this axis, and along CLI-vs-VS-Code-extension
and single-edit-vs-long-session lines.

Note that at least one report in that thread cuts against a clean
project-vs-user-level correlation, so don't treat the level as the answer —
treat it as the first thing to rule out.

### 3. A stale copy of the script is doing the enforcing

The path in `settings.json` resolves to a copy of your guard in a different
directory than the one you've been editing. Everything works; your changes do
nothing. This one is nasty because every check short of comparing file
identity reports success.

### 4. `permissionDecision: "ask"` is silently dropped under `defaultMode: "auto"`

**Attribution: `@mukaihiroyuki`,
[#85904](https://github.com/anthropics/claude-code/issues/85904), 2026-08-13.
Single self-report, one machine, v2.1.219 on Windows. Not reproduced here.**

They report that a `PreToolUse` hook returning `permissionDecision: "ask"` is
ignored when `permissions.defaultMode` is `"auto"` — no prompt, the call
proceeds, no warning — verified with a minimal hook that does nothing but
return `ask`. Returning **exit code 2** from the same hook worked.

If that generalises, it is the worst version of this bug: `auto` is precisely
the mode people enable to reduce prompt fatigue, which makes the affected
population the one most dependent on the guard.

**The honest caveat.**
[#86655](https://github.com/anthropics/claude-code/issues/86655) (opened
2026-08-14) reports a hook that reaches a verdict whose exit 2 is *also* not
enforced. So the defensible statement is *"exit 2 is the better of the two per
current reports,"* not *"exit 2 is safe."* We use `sys.exit(2)` here and emit no
`permissionDecision` at all — that's a design choice made under the same
uncertainty, not a guarantee.

### 5. Your matcher never matched

[#74942](https://github.com/anthropics/claude-code/issues/74942) (open,
updated 2026-08-12) reports an `Edit|Write` matcher silently not invoked for a
whole session. Before assuming a harness bug, prove your matcher fires by
temporarily replacing it with `*` and re-running the Option A heartbeat. If `*`
leaves lines and your specific matcher doesn't, the problem is the matcher.

### 6. Subagents

[#86405](https://github.com/anthropics/claude-code/issues/86405) (open,
updated 2026-08-13) reports hooks not firing for subagent tool calls. If your
threat model includes delegated work — and for an autonomous agent it should,
because delegation that widens what's allowed is a hole in the whole design —
test a subagent path explicitly rather than assuming the main session's
behaviour carries over.

## What this guide does not tell you

- **The cause of #6305.** It has been open for a year and we have not
  reproduced it. Anyone claiming a single root cause for that thread is ahead
  of the evidence.
- **Whether any of this is fixed in your version.** Our one first-hand data
  point is that a project-level `PreToolUse` hook fired normally on **v2.1.226,
  Linux, 2026-08-14** — measured here, from a real denied tool call. That is
  one machine on one version. It establishes the bug isn't universal and
  nothing more.
- **Version-specific guidance.** The reports span macOS, Windows 11, the VS
  Code extension and the desktop app across many versions; we have no basis for
  a version table and won't invent one.

## If the heartbeat is empty

Then you have something worth adding to
[#6305](https://github.com/anthropics/claude-code/issues/6305), which is where
the people who can act on it are subscribed: your OS, exact version, which
`settings.json` the hook is declared in, whether `/hooks` lists it, and the
fact that a `*`-matcher heartbeat hook produced zero lines across a fresh
session with tool calls in it. That last item is the part almost no report
includes, and it is the one that distinguishes "not invoked" from "invoked and
mishandled."

That is a more useful contribution than installing anything, including this.

---

*This document lives in [agent-approval-gate](https://github.com/Prime-agentai/agent-approval-gate),
which is a `PreToolUse` hook that blocks unapproved spending, account creation
and fund movement and queues them for human review. It's here because we hit
this bug class in our own enforcement path and had to build the answer. Issues
and corrections welcome — particularly if you can refute something above.*
