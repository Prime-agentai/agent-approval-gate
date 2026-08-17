# Security policy

## Reporting

Use **[Security → Report a vulnerability](https://github.com/Prime-agentai/agent-approval-gate/security/advisories/new)**,
not a public issue. `CONTRIBUTING.md` says the same thing; this file exists so
GitHub surfaces the route in the places people actually look for it.

## What counts as a bypass worth reporting

A bypass is a call that defeats a rule this pack plainly means to enforce — the
guard returning "allow" on something in its own forbidden set. Concretely:
reaching a protected file through a path the rules meant to cover, moving funds
through a phrasing the fund-movement rule was written to catch, or getting the
guard to fail *open* on input it should have refused.

## What is not a vulnerability

This is a regex-based `PreToolUse` hook. **It is not a sandbox, and it cannot
be one.** A sufficiently unusual phrasing getting past a pattern is a known and
documented property of the design, not a security finding — the README's "What
this is not" section is the honest boundary, and it's stated there so nobody
over-trusts the answer.

Two related things that are also working as intended:

- **It fails open.** If the guard itself errors, the call proceeds. The README
  explains why: a hook that fails closed on an unhandled exception takes the
  whole harness down with it. That trade-off is deliberate and documented.
- **It blocks its own test fixtures.** Expected, and called out in the README.

If you're unsure which side of that line your finding falls on, report it
privately anyway and I'd rather sort it out than not hear it.

## Scope

This repo only — the hook scripts, `verify.py`, `state.py`, `install.py`. It has
no server, no network calls, and no telemetry; there is nothing here that phones
home and nothing that stores a credential. If you find code in this repo doing
any of those three things, that is itself the report.

## Response expectations

The maintainer is an autonomous AI agent running on a schedule, with a human
operator reviewing anything it merges. Expect days rather than hours, and expect
a plain answer. **There is no service-level commitment here, including for
security reports** — stated plainly because a security policy that implies a
guarantee it can't keep is worse than one that admits the limit.
