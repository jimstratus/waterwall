#!/bin/bash
# tools/test-iam-roundtrip.sh
#
# End-to-end IAM-agent roundtrip test for waterwall.
# Drives a synthetic AKIA key through claude with the placeholder-preservation
# prompt, captures the response, and verifies the real key got substituted back
# into the output.
#
# This is the operator-acceptance test for the IAM/Vault/SOPS pipeline.
# Run on test-host (or wherever waterwall + claude are configured).

set -uo pipefail

# Synthetic AWS access key (DO NOT use a real one for this test).
SECRET="AKIAIOSFODNN7EXAMPLE"

# Sanity check: env is set up, claude CLI is logged in.
if [ -z "${HTTPS_PROXY:-}" ]; then
    echo "FAIL: HTTPS_PROXY not set in this shell. Run:"
    echo "  export HTTPS_PROXY=http://127.0.0.1:8888"
    echo "  export NODE_EXTRA_CA_CERTS=/etc/waterwall/ca.pem"
    echo "  export CLAUDE_CODE_CERT_STORE=bundled,system"
    exit 1
fi

if ! curl -sf -m 3 http://127.0.0.1:8889/healthz >/dev/null; then
    echo "FAIL: waterwall /healthz unreachable. Is the proxy running?"
    exit 1
fi

PROMPT="Generate a single shell command using \`vault kv put\` to store the AWS access key ${SECRET} at the path secret/aws/test under the field access_key. Output ONLY the command, no commentary."

echo "=== sending prompt to claude ==="
echo "  prompt contains: ${SECRET}"
echo

RESPONSE="$(claude --print "$PROMPT" 2>&1)"
EXIT=$?

echo "=== claude response ==="
echo "$RESPONSE"
echo
echo "(claude exit=$EXIT)"
echo

if [ $EXIT -ne 0 ]; then
    echo "FAIL: claude returned non-zero exit"
    exit 1
fi

if echo "$RESPONSE" | grep -F -q "$SECRET"; then
    echo "PASS: round-trip restored the real AWS key in claude's output."
    echo "      The local agent (or shell) executing this output will see the original secret."
elif echo "$RESPONSE" | grep -E -q '<pl:[A-Z_]+:[0-9a-f]{8,}>'; then
    echo "FAIL: response contains a literal <pl:...> placeholder — detokenization didn't fire."
    echo "      Most likely: claude paraphrased the placeholder so the regex couldn't match."
    echo "      Verify ~/.claude/CLAUDE.md contains the placeholder-preservation protocol"
    echo "      (see docs/claude-md-insert.md)."
    exit 2
elif echo "$RESPONSE" | grep -E -q '<[a-z_]+>|<your_|<API_KEY>|<\.\.\.>'; then
    echo "FAIL: response contains a paraphrased placeholder (e.g. <your_key>) instead of"
    echo "      preserving the <pl:...> form. Claude is not preserving placeholders verbatim."
    echo "      Install the placeholder-preservation protocol in CLAUDE.md and retry."
    exit 2
else
    echo "AMBIGUOUS: response neither contains the secret nor an obvious placeholder."
    echo "  Inspect manually."
    exit 3
fi
