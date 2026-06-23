#!/usr/bin/env bash
# Generate a Name-Constrained CA permitting only api.anthropic.com.
# Spec §3 / Plan 1 Phase 1 / Plan 1 Task 1.1.

set -euo pipefail

OUT_DIR="${1:-/etc/waterwall}"
DAYS="${2:-3650}"

mkdir -p "$OUT_DIR"

cat > "$OUT_DIR/ca.cnf" <<'EOF'
[ req ]
distinguished_name = req_dn
prompt             = no
x509_extensions    = v3_ca

[ req_dn ]
CN = Waterwall Local CA

[ v3_ca ]
basicConstraints       = critical, CA:TRUE
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
nameConstraints        = critical, permitted;DNS:api.anthropic.com
EOF

openssl req -x509 -newkey rsa:4096 -nodes \
  -days "$DAYS" \
  -keyout "$OUT_DIR/ca.key" \
  -out    "$OUT_DIR/ca.pem" \
  -config "$OUT_DIR/ca.cnf"

chmod 0400 "$OUT_DIR/ca.key"
chmod 0644 "$OUT_DIR/ca.pem"

# mitmproxy 12.2.2 expects a combined key+cert PEM at <confdir>/mitmproxy-ca.pem
# (verified in Phase 1 lab notes — `--set ca_file=...` does NOT exist in this version).
cat "$OUT_DIR/ca.key" "$OUT_DIR/ca.pem" > "$OUT_DIR/mitmproxy-ca.pem"
chmod 0400 "$OUT_DIR/mitmproxy-ca.pem"

echo "CA written to $OUT_DIR/ca.pem"
echo "Private key at $OUT_DIR/ca.key (mode 0400)"
echo "mitmproxy-ca.pem (combined) at $OUT_DIR/mitmproxy-ca.pem (mode 0400)"
