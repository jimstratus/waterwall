#!/bin/bash
# tools/verify-deploy.sh
#
# Automated post-install gate runner. Walks every acceptance criterion
# end-to-end and prints PASS / FAIL per gate. Run after every deploy or
# major upgrade — see docs/deploy.md §8.
#
# Exit code: 0 on full PASS, 1 on first FAIL.
#
# This script does NOT mutate persistent state — it tests against a running
# proxy and uses synthetic-only secrets (AKIAIOSFODNN7EXAMPLE, the public
# AWS test example).

set -uo pipefail

ADMIN=http://127.0.0.1:8889
PROXY=http://127.0.0.1:8888
SECRET="AKIAIOSFODNN7EXAMPLE"
PASS=0
FAIL=0

ok()    { printf "  \033[32m✓ PASS\033[0m  %s\n" "$1"; PASS=$((PASS + 1)); }
fail()  { printf "  \033[31m✗ FAIL\033[0m  %s\n" "$1"; FAIL=$((FAIL + 1)); }
hdr()   { printf "\n=== %s ===\n" "$1"; }

# ---------------------------------------------------------------------
hdr "Gate 1: /healthz reports status=ok"
HEALTH=$(curl -sf -m 3 "${ADMIN}/healthz" || echo '{"status":"unreachable"}')
STATUS=$(echo "$HEALTH" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("status","?"))' 2>/dev/null || echo "parse-error")
if [ "$STATUS" = "ok" ]; then ok "status=ok"; else fail "status=$STATUS — $HEALTH"; fi

# ---------------------------------------------------------------------
hdr "Gate 2: signer key readable + patterns loaded"
SIGNER=$(echo "$HEALTH" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("signer_key_readable"))' 2>/dev/null || echo "?")
PATTERNS=$(echo "$HEALTH" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("patterns_loaded",0))' 2>/dev/null || echo 0)
if [ "$SIGNER" = "True" ]; then ok "signer key readable"; else fail "signer_key_readable=$SIGNER"; fi
if [ "$PATTERNS" -ge 16 ]; then ok "$PATTERNS patterns loaded (>= 16 required)"; else fail "only $PATTERNS patterns"; fi

# ---------------------------------------------------------------------
hdr "Gate 3: verify-install --runtime returns 10/10"
VI_OUTPUT=$(/opt/waterwall/.venv/bin/waterwall verify-install --runtime 2>&1)
VI_OK=$(echo "$VI_OUTPUT" | python3 -c 'import sys,json;d=json.load(sys.stdin);print("yes" if d.get("ok") else "no")' 2>/dev/null || echo "parse-error")
if [ "$VI_OK" = "yes" ]; then ok "10/10 runtime checks"; else fail "verify-install runtime: $VI_OUTPUT"; fi

# ---------------------------------------------------------------------
hdr "Gate 4: redaction roundtrip via curl through proxy"
# Sanity test — sends a request with a synthetic secret. The chain log
# should record a redaction; we verify the redaction count climbed.
CHAIN_BEFORE=$(echo "$HEALTH" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("map_size",0))' 2>/dev/null || echo 0)

curl -s -x "$PROXY" -X POST https://api.anthropic.com/v1/messages \
  -H "x-api-key: test" -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d "{\"model\":\"claude-3-5-haiku\",\"max_tokens\":1,\"messages\":[{\"role\":\"user\",\"content\":\"$SECRET\"}]}" \
  --cacert /etc/waterwall/ca.pem >/dev/null 2>&1
sleep 1

HEALTH2=$(curl -sf -m 3 "${ADMIN}/healthz" || echo '{}')
CHAIN_AFTER=$(echo "$HEALTH2" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("map_size",0))' 2>/dev/null || echo 0)
if [ "$CHAIN_AFTER" -gt "$CHAIN_BEFORE" ]; then
  ok "map_size advanced ($CHAIN_BEFORE → $CHAIN_AFTER) — redaction recorded"
else
  fail "map_size unchanged ($CHAIN_BEFORE) — redaction did not fire"
fi

# ---------------------------------------------------------------------
hdr "Gate 5: kill switch arm → curl 502 → disarm"
ARM_RESP=$(curl -s -m 3 -X POST "${ADMIN}/admin/killswitch" \
  -H "content-type: application/json" \
  -d '{"action":"arm","reason":"verify-deploy"}')
sleep 1
KS=$(curl -sf -m 3 "${ADMIN}/admin/state" | python3 -c 'import sys,json;print(json.load(sys.stdin)["killswitch"]["active"])' 2>/dev/null || echo "?")
if [ "$KS" = "True" ]; then ok "killswitch armed via /admin/killswitch"; else fail "killswitch did not arm: $ARM_RESP"; fi

# Now curl through the proxy — must 502
ARMED_CODE=$(curl -s -o /dev/null -w "%{http_code}" -x "$PROXY" -X POST https://api.anthropic.com/v1/messages \
  -H "x-api-key: test" -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{"model":"claude-3-5-haiku","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}' \
  --cacert /etc/waterwall/ca.pem)
if [ "$ARMED_CODE" = "502" ]; then ok "armed proxy returned 502"; else fail "expected 502, got $ARMED_CODE"; fi

# Disarm
curl -s -m 3 -X POST "${ADMIN}/admin/killswitch" \
  -H "content-type: application/json" -d '{"action":"disarm"}' >/dev/null
sleep 1
KS2=$(curl -sf -m 3 "${ADMIN}/admin/state" | python3 -c 'import sys,json;print(json.load(sys.stdin)["killswitch"]["active"])' 2>/dev/null || echo "?")
if [ "$KS2" = "False" ]; then ok "disarm cleared all sources"; else fail "disarm did not clear: killswitch.active=$KS2"; fi

# ---------------------------------------------------------------------
hdr "Gate 6: verify-chain on the audit log"
VC=$(/opt/waterwall/.venv/bin/waterwall verify-chain \
  /var/log/waterwall/proxy.jsonl \
  --pubkey /etc/waterwall/signing.pub 2>&1 || true)
if echo "$VC" | grep -q "^OK:"; then
  ok "verify-chain reports clean — $(echo "$VC" | head -1)"
else
  fail "verify-chain failure: $VC"
fi

# ---------------------------------------------------------------------
# Optional gate: IAM-agent roundtrip — runs only if claude CLI auth + env
# are set up. We skip rather than fail if not applicable.
hdr "Gate 7 (optional): IAM-agent roundtrip via claude"
if [ -z "${HTTPS_PROXY:-}" ] || ! command -v claude >/dev/null; then
  printf "  \033[33m… SKIP\033[0m  HTTPS_PROXY not set or claude CLI missing\n"
else
  IAM_OUT=$(bash /opt/waterwall/tools/test-iam-roundtrip.sh 2>&1 || true)
  if echo "$IAM_OUT" | grep -q "^PASS:"; then
    ok "claude preserved placeholder, secret restored end-to-end"
  else
    fail "IAM roundtrip failed; full output:"
    echo "$IAM_OUT" | sed 's/^/    /'
  fi
fi

# ---------------------------------------------------------------------
hdr "Summary"
printf "  PASS: %d   FAIL: %d\n" "$PASS" "$FAIL"
if [ "$FAIL" -eq 0 ]; then
  printf "\n\033[32mDeploy verified — production-ready.\033[0m\n"
  exit 0
else
  printf "\n\033[31mDeploy has %d failing gate(s) — fix before going live.\033[0m\n" "$FAIL"
  exit 1
fi
