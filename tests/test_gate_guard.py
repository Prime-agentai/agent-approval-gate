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


def main():
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

    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
