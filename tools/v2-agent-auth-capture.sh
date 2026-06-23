#!/usr/bin/env bash
# tools/v2-agent-auth-capture.sh
# Capture a representative request from each v2 target agent through
# mitmdump (no waterwall addon — pass-through capture only) to verify
# whether credentials appear in headers vs body.
set -euo pipefail

CAP_DIR="${1:-/tmp/v2-auth-capture}"
mkdir -p "$CAP_DIR"

cat <<'EOF'
This script starts a transparent mitmdump on 127.0.0.1:9999 (CAPTURE-ONLY,
NO waterwall addon) and writes per-flow JSON dumps to $CAP_DIR.

Then for each target agent:
  1. Set HTTPS_PROXY=http://127.0.0.1:9999
  2. Set NODE_EXTRA_CA_CERTS=/etc/waterwall/ca.pem (use whichever CA mitmdump
     is using — e.g. mitmproxy's own ~/.mitmproxy/mitmproxy-ca.pem)
  3. Send ONE harmless test prompt
  4. Stop the agent

Then run `python tools/v2-classify-auth.py $CAP_DIR` to classify whether
credentials live in headers or body, per agent.
EOF

mitmdump --listen-host 127.0.0.1 -p 9999 \
  --set save_stream_file="$CAP_DIR/flows.mitm" \
  --set flow_detail=2
