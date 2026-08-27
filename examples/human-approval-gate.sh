#!/bin/bash
# human-approval-gate.sh — queue authorized-but-consequential actions for a human
# instead of allowing them silently or blocking them into a dead end.
#
# A sandbox contains what a tool call touches on THIS machine. It does not
# contain a well-formed, authorized HTTPS request that spends money, opens an
# account, or publishes something permanent under your name — at the network
# layer those look identical to every other call the agent is allowed to make.
#
# This hook gates that specific class. On a block it writes a request record,
# so the agent has somewhere to put the action down and you have something to
# act on later.
#
# Exit 0 = allow. Exit 2 = deny (the tool call does not run).
# Any other exit status is a NON-BLOCKING error under the PreToolUse contract,
# so every failure path below ends in exit 2, never in a bare `exit 1`.

set -o pipefail

QUEUE="${APPROVAL_QUEUE:-$HOME/.claude/approval-queue.jsonl}"

INPUT=$(cat)
[ -z "$INPUT" ] && exit 0

TOOL=$(printf '%s' "$INPUT" | jq -r '.tool_name // empty' 2>/dev/null)
CMD=$(printf '%s' "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null)

# jq missing, or a payload shape we do not understand: fail closed.
# A guard that waves calls through when it is confused is worse than no guard,
# because you will believe it is working.
if [ -z "$TOOL" ]; then
    echo "human-approval-gate: could not read the hook payload (is jq installed?). Failing closed." >&2
    exit 2
fi

[ -z "${CMD//[[:space:]]/}" ] && exit 0

RULE=""
DETAIL=""

match() { printf '%s' "$CMD" | grep -qiE "$1"; }

# 1. Spend. An authorized call that costs money is indistinguishable from one
#    that does not, so no permission prompt about file access will catch it.
if match '(api\.stripe\.com|api\.paypal\.com|/v1/(charges|payment_intents|subscriptions))'; then
    RULE="SPEND"; DETAIL="payment-processor API call"
elif match '\bstripe[[:space:]]+[a-z_]*(charge|payment|subscription|invoice)'; then
    RULE="SPEND"; DETAIL="payments CLI"
elif match '\b(terraform|tofu)[[:space:]]+apply\b'; then
    RULE="SPEND"; DETAIL="infrastructure apply (provisions billable resources)"
elif match '\b(aws|gcloud|az)\b[^|;&]*\b(create|run-instances|create-cluster|deploy)\b'; then
    RULE="SPEND"; DETAIL="cloud resource provisioning"

# 2. Account creation. Not reversible by deleting a file, and it attaches your
#    real identity to a third party.
elif match '(/(signup|sign-up|register)\b|/api/v[0-9]+/(users|accounts)\b)'; then
    RULE="ACCOUNT"; DETAIL="signup or registration endpoint"
elif match '\bgh[[:space:]]+auth[[:space:]]+login\b|\bnpm[[:space:]]+adduser\b|\bdoctl[[:space:]]+auth\b'; then
    RULE="ACCOUNT"; DETAIL="account or credential registration"

# 3. Irreversible public publish. A registry does not take it back on request,
#    and the artifact carries your name from the moment it lands.
elif match '\bnpm[[:space:]]+publish\b|\btwine[[:space:]]+upload\b|\bcargo[[:space:]]+publish\b'; then
    RULE="PUBLISH"; DETAIL="package registry publish"
elif match '\bdocker[[:space:]]+push\b|\bgh[[:space:]]+release[[:space:]]+create\b'; then
    RULE="PUBLISH"; DETAIL="public artifact publish"
fi

[ -z "$RULE" ] && exit 0

# --- Record the request. ---
# This must never be able to turn a block into an allow. If the queue cannot be
# written, the block still stands and we say so, rather than telling you a
# request exists when it does not.
RECORDED="no"
if [ -n "$QUEUE" ]; then
    mkdir -p "$(dirname "$QUEUE")" 2>/dev/null || true
    LINE=$(jq -nc \
        --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --arg rule "$RULE" --arg detail "$DETAIL" \
        --arg tool "$TOOL" \
        --arg attempted "$(printf '%s' "$CMD" | head -c 400)" \
        '{ts:$ts, rule:$rule, detail:$detail, tool:$tool, attempted:$attempted, status:"pending"}' \
        2>/dev/null) || LINE=""
    if [ -n "$LINE" ] && printf '%s\n' "$LINE" >> "$QUEUE" 2>/dev/null; then
        RECORDED="yes"
    fi
fi

{
    echo "BLOCKED by human-approval-gate — $RULE ($DETAIL)."
    echo "This call did not run. It needs a human decision, not a retry and not a rephrasing."
    if [ "$RECORDED" = "yes" ]; then
        echo "Queued for review in $QUEUE — work on something else, do not wait on it."
    else
        echo "WARNING: the block stands, but it could NOT be written to $QUEUE"
        echo "(directory missing or not writable), so no request was recorded for you to see."
    fi
} >&2

exit 2
