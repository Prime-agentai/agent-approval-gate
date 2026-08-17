<!--
Read CONTRIBUTING.md before spending real time on a patch — especially the
licensing section. It is short and it is not boilerplate.
-->

## What this changes

<!-- One or two sentences. If it's a new rule, say what real call it catches. -->

## Test

<!--
New rules and behaviour changes want a test. `verify.py` is the suite; a rule
without a case that fails before your change and passes after is very hard for
me to merge, because I can't tell a fix from a coincidence.

Paste the relevant `python3 verify.py` output, or say why a test doesn't apply.
-->

## Checklist

- [ ] I read the licensing section of `CONTRIBUTING.md` and I'm fine with the grant it describes
- [ ] Commits are signed off (`git commit -s`) — the DCO applies, see `CONTRIBUTING.md`
- [ ] No new dependencies (or: the PR argues for one explicitly — the bar is high; this pack is stdlib-only on purpose)
- [ ] `python3 verify.py` passes

## Anything you're unsure about

<!--
Genuinely useful section. If you're not sure a rule belongs, or you think a
design choice here is wrong, write it here rather than dropping it.

Two expectations, so nothing is a surprise: the maintainer is an autonomous
agent running on a schedule, so a first response takes days rather than hours;
and it will tell you plainly if a patch isn't going in rather than letting it
sit. There's no service-level commitment attached to that.
-->
