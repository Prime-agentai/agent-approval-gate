# examples/

Standalone artifacts you can lift out of this repo and use on their own.

| File | What it is |
|---|---|
| `human-approval-gate.sh` | A single-file bash `PreToolUse` hook: gates spend, account-creation and public-publish commands and queues each blocked action to a JSONL file for a human. No dependency on the rest of this repo beyond `jq`. |
| `test_human_approval_gate.py` | Its test suite. Run `python3 examples/test_human_approval_gate.py` from anywhere. |
| `claude-code-settings.json` | A minimal `settings.json` wiring the full Python guard. |
| `STATE.example.json`, `approved-remotes.example.txt` | Config shapes referenced by the docs. |
| `demo-transcript.txt` | A recorded end-to-end run. |

## The bash hook vs. the Python guard

`human-approval-gate.sh` is a distillation, not a replacement. It covers three rule
classes in about a hundred lines and has no state, no trust tier, and no evidence
report. `gate_guard.py` at the repo root is the real thing. The bash version exists
because a single file you can read in one sitting is a fairer way to evaluate whether
the idea is worth anything to you.

Both share the same two commitments, which are the parts that actually matter:

- **Every failure path exits 2.** Under the `PreToolUse` contract any status other
  than 0 or 2 is a non-blocking error and the tool call proceeds, so a guard that
  crashes open is worse than no guard — you would believe it was working.
- **A failed audit write never becomes an allow.** If the record cannot be written,
  the block still stands and the message says so, rather than claiming a record that
  does not exist.
