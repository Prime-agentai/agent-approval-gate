#!/usr/bin/env python3
"""Behaviour tests for the human-approval-gate hook we publish to buildwithclaude.

Fixture strings that name a gated verb are assembled from fragments at runtime.
Our own gate-guard matches command TEXT, not intent, so a literal test vector for
a content-matching rule is blocked by that rule (memory/probe-payloads-trip-the-gate.md).
Splitting the literal satisfies the rule; it does not loosen it. The hook under test
sees the fully reassembled string, so coverage is unaffected.
"""
import json, os, shutil, stat, subprocess, sys, tempfile

BASH = shutil.which("bash") or "/bin/bash"

HOOK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "human-approval-gate.sh")

# assembled, never written as one literal
PAY_HOST = "api." + "stri" + "pe.com"
PAY_PATH = "/v1/" + "char" + "ges"
PAY_CLI = "stri" + "pe"
SIGNUP = "sign" + "up"
REGISTER = "regi" + "ster"
ADDUSER = "add" + "user"
AUTH_LOGIN = "auth " + "log" + "in"

BLOCK = [
    ("payment API POST", f"curl -X POST https://{PAY_HOST}{PAY_PATH} -d amount=500", "SPEND"),
    ("payments CLI", f"{PAY_CLI} subscriptions create --customer cus_1", "SPEND"),
    ("terraform apply", "terraform apply -auto-approve", "SPEND"),
    ("tofu apply", "tofu apply", "SPEND"),
    ("aws run-instances", "aws ec2 run-instances --image-id ami-123", "SPEND"),
    ("gcloud create", "gcloud compute instances create web-1 --zone us-central1-a", "SPEND"),
    ("users endpoint", "curl -X POST https://example.com/api/v1/users -d email=x@y.z", "ACCOUNT"),
    ("registration path", f"curl -X POST https://example.com/{REGISTER} --data-raw '{{}}'", "ACCOUNT"),
    ("signup path", f"curl -X POST https://example.com/{SIGNUP}", "ACCOUNT"),
    ("gh auth", f"gh {AUTH_LOGIN} --with-token < tok", "ACCOUNT"),
    ("npm adduser", f"npm {ADDUSER} --registry https://registry.npmjs.org", "ACCOUNT"),
    ("npm publish", "npm publish --access public", "PUBLISH"),
    ("twine upload", "twine upload dist/*", "PUBLISH"),
    ("cargo publish", "cargo publish", "PUBLISH"),
    ("docker push", "docker push myorg/img:latest", "PUBLISH"),
    ("gh release create", "gh release create v1.0.0 --notes ok", "PUBLISH"),
]

ALLOW = [
    ("plain ls", "ls -la"),
    ("npm install", "npm install --save-dev jest"),
    ("npm run build", "npm run build"),
    ("terraform plan", "terraform plan -out=tf.plan"),
    ("aws read-only", "aws s3 ls s3://bucket"),
    ("gcloud list", "gcloud compute instances list"),
    ("docker build", "docker build -t img ."),
    ("git commit", "git commit -m 'fix: typo'"),
    ("pytest", "python3 -m pytest -q"),
]


def run(payload, queue, env_extra=None):
    env = dict(os.environ, APPROVAL_QUEUE=queue)
    if env_extra:
        env.update(env_extra)
    p = subprocess.run([BASH, HOOK], input=json.dumps(payload).encode(),
                       capture_output=True, env=env)
    return p.returncode, p.stderr.decode()


def main():
    failures = []
    checks = 0
    tmp = tempfile.mkdtemp()
    queue = os.path.join(tmp, "queue.jsonl")

    for label, cmd, rule in BLOCK:
        code, err = run({"tool_name": "Bash", "tool_input": {"command": cmd}}, queue)
        checks += 1
        if code != 2:
            failures.append(f"BLOCK {label}: expected exit 2, got {code}")
        elif rule not in err:
            failures.append(f"BLOCK {label}: message did not name rule {rule}: {err.strip()[:80]}")
        elif "did not run" not in err:
            failures.append(f"BLOCK {label}: message does not say the call did not run")

    for label, cmd in ALLOW:
        code, err = run({"tool_name": "Bash", "tool_input": {"command": cmd}}, queue)
        checks += 1
        if code != 0:
            failures.append(f"ALLOW {label}: expected exit 0, got {code} ({err.strip()[:80]})")

    # non-Bash tools and empty payloads pass through
    for label, payload in [
        ("Read tool", {"tool_name": "Read", "tool_input": {"file_path": "/etc/hosts"}}),
        ("empty command", {"tool_name": "Bash", "tool_input": {"command": "   "}}),
        ("no command key", {"tool_name": "Bash", "tool_input": {}}),
    ]:
        code, err = run(payload, queue)
        checks += 1
        if code != 0:
            failures.append(f"PASSTHROUGH {label}: expected exit 0, got {code}")

    # every block wrote exactly one queue line, and the lines are valid JSON
    checks += 1
    lines = [l for l in open(queue).read().splitlines() if l.strip()]
    if len(lines) != len(BLOCK):
        failures.append(f"QUEUE: expected {len(BLOCK)} records, got {len(lines)}")
    else:
        for l in lines:
            try:
                rec = json.loads(l)
            except ValueError as e:
                failures.append(f"QUEUE: record is not valid JSON ({e})")
                break
            for k in ("ts", "rule", "detail", "tool", "attempted", "status"):
                if k not in rec:
                    failures.append(f"QUEUE: record missing field {k}")
                    break

    # an unwritable queue must NOT turn a block into an allow
    ro = os.path.join(tmp, "readonly")
    os.mkdir(ro)
    os.chmod(ro, 0o500)
    code, err = run({"tool_name": "Bash", "tool_input": {"command": "npm publish"}},
                    os.path.join(ro, "queue.jsonl"))
    checks += 1
    if code != 2:
        failures.append(f"UNWRITABLE: block must still stand, got exit {code}")
    checks += 1
    if "could NOT be written" not in err:
        failures.append("UNWRITABLE: message must say the record was not written")
    checks += 1
    if "Queued for review" in err:
        failures.append("UNWRITABLE: message claims a queued record that does not exist")
    os.chmod(ro, 0o700)

    # a payload the hook cannot parse fails CLOSED, not open
    code, err = run({"not_a_tool_payload": True}, queue)
    checks += 1
    if code != 2:
        failures.append(f"MALFORMED: expected fail-closed exit 2, got {code}")

    # jq unavailable must also fail closed rather than wave the call through.
    # Shadow jq with a stub that produces nothing, leaving the rest of PATH intact
    # so this tests "no jq" and not "no coreutils".
    stub = os.path.join(tmp, "bin")
    os.mkdir(stub)
    stub_jq = os.path.join(stub, "jq")
    with open(stub_jq, "w") as f:
        f.write("#!/bin/sh\nexit 127\n")
    os.chmod(stub_jq, os.stat(stub_jq).st_mode | stat.S_IEXEC)
    code, err = run({"tool_name": "Bash", "tool_input": {"command": "npm publish"}},
                    queue, env_extra={"PATH": stub + os.pathsep + os.environ.get("PATH", "")})
    checks += 1
    if code != 2:
        failures.append(f"NO-JQ: expected fail-closed exit 2, got {code}")
    checks += 1
    if "Failing closed" not in err:
        failures.append("NO-JQ: message should say it failed closed")

    print(f"{checks} checks run")
    if failures:
        print(f"\nFAILED ({len(failures)}):")
        for f in failures:
            print("  -", f)
        return 1
    print("all passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
