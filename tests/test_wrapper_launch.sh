#!/usr/bin/env bash
# tests/test_wrapper_launch.sh
# Test that deploy/wrappers/waterwall-launch:
#   1. invokes `waterwall pre-launch-hook` first
#   2. on hook exit != 0, exits 1 without exec'ing the target binary
#      (issue #17: the exit code — not a "decision" JSON field — is the
#      enforcement contract; the JSON only carries additionalContext)
#   3. on hook exit 0, exec's the target binary with all original args
set -euo pipefail

WRAPPER="deploy/wrappers/waterwall-launch"
TMPDIR=$(mktemp -d)
export TMPDIR
trap 'rm -rf "$TMPDIR"' EXIT

# Stand up a fake `waterwall` binary with configurable exit code + stdout
cat > "$TMPDIR/waterwall" <<'EOF'
#!/usr/bin/env bash
if [ "$1" = "pre-launch-hook" ]; then
    printf '%s\n' "${WW_TEST_OUTPUT:-}"
    exit "${WW_TEST_EXIT:-0}"
fi
EOF
chmod +x "$TMPDIR/waterwall"

# Stand up a fake target binary that records its args
cat > "$TMPDIR/fake-agent" <<'EOF'
#!/usr/bin/env bash
echo "fake-agent invoked with: $*" > "$TMPDIR/fake-agent.out"
EOF
chmod +x "$TMPDIR/fake-agent"

export PATH="$TMPDIR:$PATH"

# Test 1: hook exit 0 exec's the target
WW_TEST_EXIT=0 "$WRAPPER" fake-agent --foo bar
[ -f "$TMPDIR/fake-agent.out" ] || { echo "FAIL: target not invoked on hook exit 0"; exit 1; }
grep -q -- "--foo bar" "$TMPDIR/fake-agent.out" || { echo "FAIL: args not forwarded"; exit 1; }
rm -f "$TMPDIR/fake-agent.out"

# Test 2: hook exit 1 exits non-zero, target not invoked, and the
# additionalContext message is surfaced on stderr
BLOCK_JSON='{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"WATERWALL BLOCK: proxy unhealthy"}}'
set +e
STDERR=$(WW_TEST_EXIT=1 WW_TEST_OUTPUT="$BLOCK_JSON" "$WRAPPER" fake-agent --foo bar 2>&1 >/dev/null)
rc=$?
set -e
[ $rc -ne 0 ] || { echo "FAIL: wrapper returned 0 on hook exit 1"; exit 1; }
[ ! -f "$TMPDIR/fake-agent.out" ] || { echo "FAIL: target invoked despite block"; exit 1; }
echo "$STDERR" | grep -q "proxy unhealthy" || { echo "FAIL: additionalContext reason not surfaced: $STDERR"; exit 1; }

# Test 3: hook exit 1 with NO JSON (and no jq fallback match) still refuses —
# the errexit-guarded grep must not abort the wrapper before the refusal
set +e
WW_TEST_EXIT=1 WW_TEST_OUTPUT='' "$WRAPPER" fake-agent --foo bar 2>/dev/null
rc=$?
set -e
[ $rc -ne 0 ] || { echo "FAIL: wrapper returned 0 on empty-output block"; exit 1; }
[ ! -f "$TMPDIR/fake-agent.out" ] || { echo "FAIL: target invoked despite empty-output block"; exit 1; }

echo "PASS: wrapper test"
