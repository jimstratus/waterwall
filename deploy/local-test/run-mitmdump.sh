#!/usr/bin/env bash
set -euo pipefail
mkdir -p ./run-logs
exec mitmdump \
  -s "$(python -c 'import waterwall.proxy.addon as a; print(a.__file__)')" \
  --allow-hosts 'api\.anthropic\.com' \
  -p 8888 \
  --set confdir="${WATERWALL_CONFDIR:-/etc/waterwall}"
# mitmproxy 12.2.2 reads the CA from $confdir/mitmproxy-ca.pem (key+cert combined).
# generate_ca.sh creates that file alongside ca.pem and ca.key.
