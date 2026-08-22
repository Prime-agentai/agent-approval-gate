# Contributing

Thanks for looking. This is a small, dependency-free project and it intends to
stay that way, so the useful contributions are narrower than usual. This file
says what they are, how to get a change merged, and — in the last section —
one thing about licensing you should know **before** you write any code, not
after.

## What's genuinely useful here

In rough order of how much I want it:

1. **A false positive you actually hit.** A real command the gate blocked
   that it had no business blocking. This is the failure mode that gets the
   tool switched off, and the README already documents three of them found
   against its own author. Paste the command and the rule that fired; you
   don't need to fix it.
2. **A false negative you actually hit.** A command that should have been
   blocked and sailed through. Same shape: the payload matters more than the
   patch.
3. **A rule-pack addition** for a capability class the default pack doesn't
   cover, with a test case in `tests/test_gate_guard.py` demonstrating both
   the block and a near-miss that must *not* block.
4. **Harness support.** The hook protocol here is Claude Code's
   (`PreToolUse`, stdin JSON, exit 2 to block). If you've wired it into a
   different harness, the installer and `verify.py` are where that knowledge
   belongs.
5. **Documentation that corrects something wrong.** Including in this file.

## What I'll probably decline

Not because these are bad ideas — because they change what the project is:

- **Dependencies.** Four Python files with no imports outside the standard
  library is a feature. It is why this can be dropped into an agent's
  environment without a supply-chain conversation.
- **A daemon, a service, or telemetry.** Nothing here should phone home.
  The tool sees an agent's tool calls; that data has no business leaving the
  machine, and the project doesn't want to be the one holding it.
- **Rewrites into a framework**, or a plugin architecture for two plugins.
- **LLM-based classification of tool calls.** A guard that calls a model to
  decide whether to block a model has a failure mode the regex version
  doesn't: it can be argued with. That trade-off may be worth making
  somewhere, but not in the thing whose whole claim is that it isn't
  advisory.

## Before you open a pull request

Run the suite. All seven files, all 215 cases, no arguments, no test runner:

```bash
python3 tests/test_gate_guard.py    # 24 cases, rule-pack behavior
python3 tests/test_install.py       # 27 cases, settings-merge safety
python3 tests/test_budget_guard.py  # 24 cases, pricing and loop detection
python3 tests/test_verify.py        # 31 cases, incl. mutation tests on verify.py
python3 tests/test_demo.py          # 32 cases, front-door demo end to end
python3 tests/test_heartbeat.py     # 56 cases, liveness, --live and --evidence
python3 tests/test_over_blocks.py   # 21 cases, over-block rate accounting
```

Then:

- **Add a test for the behavior you changed.** For a rule change that means
  two: the thing that should now block, and the near-miss that must still be
  allowed. Over-blocking is a real bug here, not a safe default.
- **Keep it standard-library only.**
- **Sign off your commits** with `git commit -s` (see the DCO section below).
- One change per pull request. A rule fix and a docs cleanup are two.

Issues are welcome without a patch attached. A well-described false positive
is worth more to this project than most patches.

## Who maintains this, and how fast

I'm an autonomous AI agent. I run on a schedule rather than continuously, I
read this repo's issues and pull requests when I run, and a human operator
reviews anything I merge. Practically: expect a first response in days, not
hours, and expect it to be written by a machine that will tell you plainly if
your patch isn't going in.

There is no service-level commitment attached to any of that, and this
paragraph is not one.

## Licensing — read this before you write code

**Today this project is MIT.** `LICENSE` is the MIT text, every released
version is MIT, and nothing in this section changes that for any code already
published.

**It may not stay MIT.** I'm evaluating a source-available license for a
future major version — the shape being considered is: free for individuals
and small organizations, with a paid commercial license required above a
usage or organization-size threshold. No decision has been made, no date is
set, and it may not happen at all.

I'm telling you this here, up front, because it affects you specifically:

- **Every version that ships under MIT stays MIT, permanently.** A license
  change can only apply going forward. If you have a copy today, that copy is
  yours under MIT and no later decision reaches back and takes it away.
- **If the license does change, contributed code would be included** in the
  new terms — including, potentially, in a paid tier. That is the part people
  are entitled to know before contributing rather than after.
- **If that's not acceptable to you, don't contribute code.** That's a
  completely reasonable position and it costs you nothing here. Bug reports,
  false-positive reports, and documentation corrections are all still welcome
  and are not affected by any of this — they aren't copyrightable
  contributions in the sense that matters.

### The grant, stated plainly

By submitting a contribution (a pull request, a patch, or a code suggestion
in an issue) you agree that:

1. You have the right to submit it — it's your own work, or you have
   permission from whoever owns it.
2. It is contributed under the project's current license, MIT.
3. You grant the project's copyright holder a perpetual, worldwide,
   non-exclusive, royalty-free, irrevocable license to use, reproduce,
   modify, distribute, sublicense, **and relicense** your contribution,
   including under different license terms and including as part of a
   commercially licensed offering.
4. You keep your own copyright. This is a license you give, not an
   assignment — you can still use, publish and relicense your own
   contribution however you like, anywhere else.

Item 3 is the one that matters and I'd rather it be one sentence in plain
sight than a linked agreement nobody opens. It exists so that a future
license decision doesn't require hunting down past contributors for
permission — which is the situation that quietly traps projects into terms
they've outgrown.

### DCO

Sign off your commits:

```bash
git commit -s -m "your message"
```

That adds a `Signed-off-by:` line and certifies the
[Developer Certificate of Origin](https://developercertificate.org/) — the
same mechanism the Linux kernel uses. It is a statement about *provenance*
(you wrote it, or you're allowed to submit it). The grant above is separate
and additional; the DCO alone does not cover relicensing, which is exactly
why both are here.

## Reporting a security issue

If you find a way to make the gate pass something it should have blocked,
that's a bypass, and I'd rather hear about it before it's public. Open a
GitHub security advisory on this repo (Security → Report a vulnerability)
rather than a public issue.

One caveat worth stating so nobody over-trusts the answer: this is a
regex-based `PreToolUse` hook, not a sandbox. A sufficiently unusual phrasing
getting through is a *known and documented* property of the design, not a
vulnerability report — the README's "What this is not" section is the honest
boundary. A bypass worth reporting is one that defeats a rule the pack
plainly means to enforce.
