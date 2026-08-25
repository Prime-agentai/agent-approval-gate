#!/usr/bin/env python3
"""
Minimal sanity tests for gate_guard.py's decision function.

This is a small, generic suite written for the public package -- it is not
the adversarial suite referenced in the README's provenance note, which is
project-specific to the private codebase this tool was extracted from and is
not published here. Treat this as "does the shipped default rule pack behave
as documented," not as a security audit of your own configuration.

Several test fixtures below build their command/URL strings from
concatenated fragments rather than single literals. That is deliberate, for
the same reason gate_guard.py's own KEY_MATERIAL_PATTERN is assembled from
fragments: a strict content-scanning guard applied to a repository that
contains this test file will otherwise flag the test fixtures themselves.

Run: python3 tests/test_gate_guard.py
"""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import gate_guard  # noqa: E402

PASS = 0
FAIL = 0

_PAY_HOST = "api" + "." + "stripe" + "." + "com"
_SIGNUP_PATH = "sign" + "up"
_PKG_VERB = "install"
_PKG_MGR = "np" + "m"
_GIT_PUSH = "git" + " push"
_RM_VERB = "r" + "m"
_STATE_FILE = "STATE" + ".json"
_TOKEN_PREFIX = "gh" + "p_"
_W_SEED = "see" + "d"
_W_PHRASE = "phra" + "se"
_W_WORDS = "wor" + "ds"
_W_SECRET = "secr" + "et"
_W_RECOVERY = "recov" + "ery"
_W_BACKUP = "back" + "up"
# A well-known public test vector, not a credential: the all-lowest-index
# BIP-39 vector that ships in wallet test suites. It controls nothing.
_MNEMONIC = " ".join(["abandon"] * 11 + ["about"])


def check(name, condition):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"ok    {name}")
    else:
        FAIL += 1
        print(f"FAIL  {name}")


def make_config(tmpdir, **overrides):
    config = json.loads(json.dumps(gate_guard.DEFAULT_CONFIG))
    config["_project_root"] = tmpdir
    config.update(overrides)
    return config


def call(tool_name, tool_input, config):
    payload = {"tool_name": tool_name, "tool_input": tool_input}
    hit, *_ = gate_guard.evaluate(payload, config)
    return hit


def check_allowlist_states():
    """The git-push allowlist has four distinct states and they must not all
    read as 'your remote was rejected'. A missing file is an install state, an
    empty file is a config mistake, an unreadable file is an unknown, and a
    non-match is the rule working. Each gets its own tmpdir so the states
    cannot leak into each other."""
    remotes_name = "approved-remotes.txt"
    bare_push = f"{_GIT_PUSH} origin main"

    # --- missing ---------------------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        config = make_config(tmp)
        state, entries, path, _ = gate_guard.read_approved_remotes(config)
        check("a missing allowlist reports state 'missing', not empty",
              state == gate_guard.ALLOWLIST_MISSING and entries == [])
        check("load_approved_remotes() still returns a plain list of entries",
              gate_guard.load_approved_remotes(config) == [])

        hit = call("Bash", {"command": bare_push}, config)
        check("git push with no allowlist file is blocked", hit is not None)
        missing_msg = hit[1]
        check("...and the message says the allowlist does not exist",
              "does not exist" in missing_msg)
        check("...and names the absolute path the file should be at",
              path in missing_msg)
        check("...and says it is not a rejection of this remote",
              "NOT 'your remote was rejected'" in missing_msg)
        check("...and tells the agent not to create the file itself",
              "protected path" in missing_msg)
        check("...and names the plugin install as an expected way to get here",
              "plugin install writes no config" in missing_msg)

    # --- empty (present, but nothing in it) -------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        config = make_config(tmp)
        with open(os.path.join(tmp, remotes_name), "w") as f:
            f.write("# only a comment\n\n")
        state, entries, _, _ = gate_guard.read_approved_remotes(config)
        check("a comments-only allowlist reports state 'empty', not missing",
              state == gate_guard.ALLOWLIST_EMPTY and entries == [])

        hit = call("Bash", {"command": bare_push}, config)
        check("git push with an empty allowlist is blocked", hit is not None)
        empty_msg = hit[1]
        check("...and the message says the file exists but lists no remotes",
              "exists but lists no remotes" in empty_msg)
        check("...and is NOT the same message as the missing case",
              empty_msg != missing_msg and "does not exist" not in empty_msg)

    # --- unreadable -------------------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        config = make_config(tmp)
        os.mkdir(os.path.join(tmp, remotes_name))  # a directory, not a file
        state, entries, _, detail = gate_guard.read_approved_remotes(config)
        check("an unreadable allowlist reports state 'unreadable', not empty",
              state == gate_guard.ALLOWLIST_UNREADABLE and entries == [])
        check("...and carries the underlying error as detail", bool(detail))

        hit = call("Bash", {"command": bare_push}, config)
        check("git push with an unreadable allowlist is blocked (fail closed)",
              hit is not None)
        unreadable_msg = hit[1]
        check("...and the message says it could not be read",
              "could not be read" in unreadable_msg)
        check("...and calls it an unknown rather than a decision",
              "unknown, not a" in unreadable_msg)

    # --- populated: non-match, alias vs explicit host ---------------------
    with tempfile.TemporaryDirectory() as tmp:
        config = make_config(tmp)
        with open(os.path.join(tmp, remotes_name), "w") as f:
            f.write("# comment\ngithub.com/example-org/\ngithub.com/other-org/\n")
        state, entries, _, _ = gate_guard.read_approved_remotes(config)
        check("a populated allowlist reports state 'ok' with its entries",
              state == gate_guard.ALLOWLIST_OK and len(entries) == 2)

        check(
            "git push to an approved remote is still allowed",
            call("Bash", {"command": f"{_GIT_PUSH} https://github.com/example-org/repo.git main"},
                 config) is None,
        )

        hit = call("Bash", {"command": bare_push}, config)
        check("git push naming only an alias is blocked", hit is not None)
        alias_msg = hit[1]
        check("...and the message lists what IS approved",
              "github.com/example-org/" in alias_msg)
        check("...and explains that a bare alias can never match a URL prefix",
              "bare alias" in alias_msg)

        hit = call(
            "Bash",
            {"command": f"{_GIT_PUSH} https://github.com/not-approved/repo.git main"},
            config,
        )
        check("git push to an explicit unapproved host is blocked",
              hit is not None)
        check("...and does NOT get the alias explanation, which does not apply",
              "bare alias" not in hit[1])

    # --- truncation, so a long allowlist does not produce a wall of text --
    with tempfile.TemporaryDirectory() as tmp:
        config = make_config(tmp)
        with open(os.path.join(tmp, remotes_name), "w") as f:
            f.write("".join(f"github.com/org-{i}/\n" for i in range(9)))
        hit = call("Bash", {"command": bare_push}, config)
        check("a long allowlist is truncated in the block message",
              hit is not None and "+4 more" in hit[1] and "(9)" in hit[1])


def check_trust_tier_states():
    """The trust tier has five distinct states and four of them produce tier
    0. Tier 0 is the right *behaviour* in all four -- an unknown tier must
    fail closed -- so these tests do not check that the block happened
    differently. They check that the operator is told whether the 0 was read
    or assumed, because only one of the five is a decision about them.

    Each state gets its own tmpdir so they cannot leak into each other."""
    pkg = f"{_PKG_MGR} {_PKG_VERB} left-pad"

    def tier_block(config):
        hit = call("Bash", {"command": pkg}, config)
        check("a tier-gated action is blocked below the threshold",
              hit is not None)
        return hit[1] if hit else ""

    # --- state file missing ----------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        config = make_config(tmp)
        state, tier, path, _ = gate_guard.read_trust_tier(config)
        check("a missing state file reports state 'state_missing'",
              state == gate_guard.TIER_STATE_MISSING)
        check("...and still falls back to tier 0 (behaviour unchanged)",
              tier == 0)
        check("load_trust_tier() still returns a plain int",
              gate_guard.load_trust_tier(config) == 0)

        msg = tier_block(config)
        check("...and the message says the tier was assumed, not read",
              "WAS NOT READ" in msg and "ASSUMED" in msg)
        check("...and names the absolute path the state file should be at",
              path in msg)
        check("...and says the block may be an install problem, not policy",
              "may not be a policy decision" in msg)
        check("...and names the plugin install as a way to arrive here",
              "plugin install" in msg)
        check("...and says a human has to fix it, since STATE.json is protected",
              "the agent cannot" in msg)

    # --- state file present but not JSON ----------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        config = make_config(tmp)
        with open(os.path.join(tmp, "STATE.json"), "w") as f:
            f.write("{not json,")
        state, tier, _p, detail = gate_guard.read_trust_tier(config)
        check("a malformed state file reports 'state_unreadable', not missing",
              state == gate_guard.TIER_STATE_UNREADABLE and tier == 0)
        check("...and the detail names the parse failure",
              "invalid JSON" in detail)
        msg = tier_block(config)
        check("...and the message does not claim the file is absent",
              "could not be read" in msg and "there is no file" not in msg)
        check("...and does not offer the plugin-install explanation, which "
              "does not apply when the file exists",
              "plugin install" not in msg)

    # --- state file is valid JSON but not an object ------------------------
    with tempfile.TemporaryDirectory() as tmp:
        config = make_config(tmp)
        with open(os.path.join(tmp, "STATE.json"), "w") as f:
            f.write("[1, 2, 3]")
        state, tier, _p, detail = gate_guard.read_trust_tier(config)
        check("a JSON array where the state object should be is 'unreadable'",
              state == gate_guard.TIER_STATE_UNREADABLE and tier == 0)
        check("...and the detail says what was found instead of an object",
              "not an object" in detail)

    # --- state file fine, tier field absent --------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        config = make_config(tmp)
        with open(os.path.join(tmp, "STATE.json"), "w") as f:
            json.dump({"phase": "build", "notes": "no tier here"}, f)
        state, tier, _p, detail = gate_guard.read_trust_tier(config)
        check("a state file with no tier field reports 'field_missing'",
              state == gate_guard.TIER_FIELD_MISSING and tier == 0)
        check("...and the detail says how many keys it did have",
              "2 key(s)" in detail)
        msg = tier_block(config)
        check("...and the message says the field is what is absent, not the file",
              "does not contain a 'trust_tier' field" in msg)

    # --- tier field present but not an integer -----------------------------
    for value, label in (("1", "a quoted string"), (True, "a boolean"),
                         (None, "null"), (1.5, "a float")):
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(tmp)
            with open(os.path.join(tmp, "STATE.json"), "w") as f:
                json.dump({"trust_tier": value}, f)
            state, tier, _p, _d = gate_guard.read_trust_tier(config)
            check(f"tier of {label} is 'field_invalid' and does NOT grant a tier",
                  state == gate_guard.TIER_FIELD_INVALID and tier == 0)
            check(f"...and a tier-gated action stays blocked with {label}",
                  call("Bash", {"command": pkg}, config) is not None)

    # --- the one state that IS a decision ---------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        config = make_config(tmp)
        with open(os.path.join(tmp, "STATE.json"), "w") as f:
            json.dump({"trust_tier": 0}, f)
        state, tier, path, _d = gate_guard.read_trust_tier(config)
        check("a real tier 0 reports state 'ok', not one of the failures",
              state == gate_guard.TIER_OK and tier == 0)
        msg = tier_block(config)
        check("...and the message does NOT say the tier was assumed",
              "WAS NOT READ" not in msg)
        check("...and still orients the operator: tier, threshold, and source",
              "Your tier is 0" in msg and path in msg)

        # The rule's own explanation must survive the added note.
        check("...and the rule's original explanation is still in the message",
              "Installing packages changes this machine" in msg)

    # --- tier at/above the threshold still turns the rule off --------------
    with tempfile.TemporaryDirectory() as tmp:
        config = make_config(tmp)
        with open(os.path.join(tmp, "STATE.json"), "w") as f:
            json.dump({"trust_tier": 1}, f)
        check("a genuine tier 1 read from disk turns tier-gated rules off",
              call("Bash", {"command": pkg}, config) is None)

    # --- the audit log records which of the two zeros it was ---------------
    with tempfile.TemporaryDirectory() as tmp:
        config = make_config(tmp)
        gate_guard.log_block("PACKAGE_INSTALL", "Bash", pkg, 0, config,
                             gate_guard.TIER_STATE_MISSING)
        with open(os.path.join(tmp, config["blocked_log"])) as f:
            entry = json.loads(f.readline())
        check("blocked.jsonl records an assumed tier as assumed",
              entry["trust_tier_at_block"] == 0
              and entry["trust_tier_source"] == "state_missing")

    with tempfile.TemporaryDirectory() as tmp:
        config = make_config(tmp)
        gate_guard.log_block("PACKAGE_INSTALL", "Bash", pkg, 0, config,
                             gate_guard.TIER_OK)
        with open(os.path.join(tmp, config["blocked_log"])) as f:
            entry = json.loads(f.readline())
        check("...and a read tier as read", entry["trust_tier_source"] == "read")


def main():
    check_allowlist_states()
    check_trust_tier_states()

    with tempfile.TemporaryDirectory() as tmp:
        config = make_config(tmp)

        check(
            "no state file defaults to tier 0 (fail closed)",
            gate_guard.load_trust_tier(config) == 0,
        )

        check(
            "package install blocked at tier 0",
            call("Bash", {"command": f"{_PKG_MGR} {_PKG_VERB} left-pad"}, config) is not None,
        )

        check(
            "reading a pricing page is allowed",
            call("Bash", {"command": "curl https://example.com/pricing"}, config) is None,
        )

        check(
            "posting to a payment processor API is blocked",
            call("Bash", {"command": f"curl -X POST https://{_PAY_HOST}/v1/charges"}, config)
            is not None,
        )

        check(
            "getting from a payment processor API is allowed",
            call("Bash", {"command": f"curl https://{_PAY_HOST}/v1/balance"}, config) is None,
        )

        check(
            "navigating to a signup URL is blocked",
            call("Bash", {"command": f"curl https://example.com/{_SIGNUP_PATH}"}, config)
            is not None,
        )

        check(
            "a GitHub token shape is blocked in a Write call",
            call("Write", {"file_path": "notes.txt",
                            "content": "token: " + _TOKEN_PREFIX + "x" * 36}, config) is not None,
        )

        check(
            "writing to a protected path is blocked",
            call("Write", {"file_path": os.path.join(tmp, _STATE_FILE),
                            "content": "{}"}, config) is not None,
        )

        check(
            "writing to an ordinary path is allowed",
            call("Write", {"file_path": os.path.join(tmp, "notes.txt"),
                            "content": "hello"}, config) is None,
        )

        check(
            "shell removal of a protected path is blocked",
            call("Bash", {"command": f"{_RM_VERB} {_STATE_FILE}"}, config) is not None,
        )

        check(
            "git push with no approved remotes is blocked",
            call("Bash", {"command": f"{_GIT_PUSH} origin main"}, config) is not None,
        )

        with open(os.path.join(tmp, "approved-remotes.txt"), "w") as f:
            f.write("github.com/example-org/\n")
        check(
            "git push to an approved remote is allowed",
            call("Bash", {"command": f"{_GIT_PUSH} https://github.com/example-org/repo.git main"},
                 config) is None,
        )

        with open(os.path.join(tmp, _STATE_FILE), "w") as f:
            json.dump({"trust_tier": 1}, f)
        check(
            "package install allowed at trust tier >= threshold",
            call("Bash", {"command": f"{_PKG_MGR} {_PKG_VERB} left-pad"}, config) is None,
        )

        # KEY_MATERIAL matches the LABEL a wallet prints, not the material.
        # Vendors do not say "<developer word> phrase": MetaMask prints
        # "Secret Recovery Phrase", Ledger/Trezor/Coinbase print "recovery
        # phrase". Before 2026-08-19 the rule knew only the developer's
        # wording, so every vendor spelling passed. Measured, not assumed:
        # a payload labelled with the vendor wording was ALLOWED by the
        # shipped default config.
        for _label in (
            _W_RECOVERY + " " + _W_PHRASE,
            _W_SECRET + " " + _W_RECOVERY + " " + _W_PHRASE,
            _W_RECOVERY + "-" + _W_PHRASE,
            _W_SEED + " " + _W_WORDS,
            _W_BACKUP + " " + _W_PHRASE,
        ):
            check(
                f"key material caught when labelled {_label!r}",
                call("Write", {"content": f"{_label}: {_MNEMONIC}"}, config) is not None,
            )

        check(
            "the original developer wording still matches",
            call("Write", {"content": f"{_W_SEED} {_W_PHRASE}: {_MNEMONIC}"},
                 config) is not None,
        )

        # The limit, pinned so nobody reads the rule as more than it is:
        # unlabelled material is NOT detected. This is a keyword rule, not
        # an entropy detector, and README.md says so. If this assertion ever
        # starts failing, the rule grew a capability the docs deny it has.
        check(
            "UNLABELLED material is not detected (documented limit, not a bug)",
            call("Write", {"content": _MNEMONIC}, config) is None,
        )
        check(
            "ordinary prose containing neither label nor material is allowed",
            call("Write", {"content": "restore from the backup we took"},
                 config) is None,
        )

    _check_internal_error_fails_closed()

    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)


def _check_internal_error_fails_closed():
    """A crash inside the guard must not read as 'allow'.

    Injects a real fault into a real copy of the real file and runs it as the
    harness would, rather than asserting that a try/except is still present in
    the source. A static check keeps passing after a refactor removes the
    behaviour it was meant to protect; this one does not.
    """
    import subprocess

    src_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "gate_guard.py")
    with open(src_path) as f:
        src = f.read()
    marker = "def evaluate(payload, config):"
    if marker not in src:
        check("internal-error test could locate evaluate() to fault", False)
        return
    faulted = src.replace(
        marker, marker + '\n    raise RuntimeError("injected fault")', 1)
    payload = json.dumps(
        {"tool_name": "Bash", "tool_input": {"command": "echo hi"}})

    with tempfile.TemporaryDirectory() as tmp:
        mutant = os.path.join(tmp, "gate_guard.py")
        with open(mutant, "w") as f:
            f.write(faulted)

        def run(config_obj):
            if config_obj is not None:
                with open(os.path.join(tmp, "gate-guard.config.json"), "w") as f:
                    json.dump(config_obj, f)
            return subprocess.run([sys.executable, mutant], input=payload,
                                  capture_output=True, text=True, cwd=tmp)

        r = run(None)
        check("a crash inside the guard exits 2 (fails CLOSED) by default",
              r.returncode == 2)
        check("...and says on stderr that it was an internal error, not policy",
              "INTERNAL ERROR" in r.stderr)

        r = run({"fail_closed_on_internal_error": False})
        check("...and fails open only when explicitly configured to",
              r.returncode == 0)


if __name__ == "__main__":
    main()
