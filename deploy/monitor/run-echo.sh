#!/usr/bin/env bash
# Serve the canary echo over TLS as the canary upstream (provider stand-in).
# The cert must be for the canary host (e.g. canary.waterwall.local) and signed
# by a CA the bypassing client trusts (NODE_EXTRA_CA_CERTS) AND, for the
# in-path test, by a CA the proxy trusts as an upstream.
#
# Usage:  bash deploy/monitor/run-echo.sh <cert.pem> <key.pem> [port]
set -euo pipefail
CERT="${1:?cert.pem}"; KEY="${2:?key.pem}"; PORT="${3:-9443}"
SECRET="${WATERWALL_CANARY_SECRET:-AKIAIOSFODNN7EXAMPLE}"
# Use the waterwall venv interpreter (the systemd unit runs as the waterwall
# user with no `python` on PATH); override with WATERWALL_PYTHON if installed
# elsewhere. argus #run-echo: bare `python` is often absent under systemd.
PYTHON="${WATERWALL_PYTHON:-/opt/waterwall/.venv/bin/python}"
[ -x "$PYTHON" ] || PYTHON="$(command -v python3 || echo python3)"
exec "$PYTHON" - "$CERT" "$KEY" "$PORT" "$SECRET" <<'PY'
import sys, uvicorn
from waterwall.monitor.echo import build_echo_app
cert, key, port, secret = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
uvicorn.run(build_echo_app(secret), host="127.0.0.1", port=port,
            ssl_certfile=cert, ssl_keyfile=key, log_level="warning")
PY
