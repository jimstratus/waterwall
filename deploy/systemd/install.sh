#!/bin/bash
set -euo pipefail

# Waterwall install script
# Assumes source is checked out at /opt/waterwall with .venv/ already prepared:
#   git clone ... /opt/waterwall
#   python3 -m venv /opt/waterwall/.venv
#   /opt/waterwall/.venv/bin/pip install -e /opt/waterwall

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# 1. Create waterwall system user/group (idempotent)
if ! getent passwd waterwall > /dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin waterwall
    echo "Created system user: waterwall"
else
    echo "User waterwall already exists, skipping"
fi

# 2. Create required directories with appropriate ownership and modes
mkdir -p /etc/waterwall
mkdir -p /var/log/waterwall
mkdir -p /run/waterwall
mkdir -p /opt/waterwall

chmod 0755 /etc/waterwall
chmod 0750 /var/log/waterwall
chmod 0755 /run/waterwall
chmod 0755 /opt/waterwall

# 3. CA generation happens AFTER permitted_hosts.yaml is seeded (step 5c) —
# `waterwall regen-ca` derives the CA's permittedSubtrees from that file, so
# the install-default CA covers all 4 permitted hosts (issue #11, gemini
# finding: generate_ca.sh produced a single-host CA).

# 4a. Pre-create mitmproxy-dhparam.pem if not present.
# mitmproxy lazily writes this file on first run; under our hardened systemd
# unit /etc/waterwall is mounted read-only, so the lazy create fails with
# "Read-only file system". Materializing it here avoids that.
if [ ! -f /etc/waterwall/mitmproxy-dhparam.pem ]; then
    echo "Pre-generating mitmproxy-dhparam.pem..."
    /opt/waterwall/.venv/bin/python -c "
from pathlib import Path
from mitmproxy.certs import DEFAULT_DHPARAM
Path('/etc/waterwall/mitmproxy-dhparam.pem').write_bytes(DEFAULT_DHPARAM)
"
    echo "Wrote /etc/waterwall/mitmproxy-dhparam.pem"
fi

# 4b. Generate signing keypair if not present
if [ ! -f /etc/waterwall/signing.key ]; then
    echo "Generating Ed25519 signing keypair..."
    /opt/waterwall/.venv/bin/python -c "
from pathlib import Path
from waterwall.audit.signer import generate_keypair
generate_keypair(Path('/etc/waterwall/signing.key'), Path('/etc/waterwall/signing.pub'))
"
    chmod 0400 /etc/waterwall/signing.key
    chmod 0644 /etc/waterwall/signing.pub
    echo "Signing keypair written to /etc/waterwall/signing.key and /etc/waterwall/signing.pub"
else
    echo "Signing key already exists at /etc/waterwall/signing.key, skipping"
fi

# 5. Write default patterns.py if not present
if [ ! -f /etc/waterwall/patterns.py ]; then
    cat > /etc/waterwall/patterns.py <<'EOF'
# Waterwall pattern EXTENSIONS — entries here are ADDED to the 30 built-in
# patterns (src/waterwall/proxy/patterns.py); do NOT repeat a built-in.
# A duplicate produces overlapping scan spans for the same secret (issue #21).
# Each entry is a (TYPE, regex) tuple, e.g.:
#     ("MY_INTERNAL_TOKEN", r"\bmytok_[A-Za-z0-9]{32}\b"),
PATTERNS = [
]
EOF
    echo "Wrote default /etc/waterwall/patterns.py"
else
    echo "patterns.py already exists, skipping"
fi

# 5b. Write default permitted_hosts.yaml if not present (v2)
if [ ! -f /etc/waterwall/permitted_hosts.yaml ]; then
    cat > /etc/waterwall/permitted_hosts.yaml <<'EOF'
# Operator-extensible host list. Edit, then run `waterwall regen-ca`
# and restart the proxy. Each entry:
#   host:        DNS name (must be RFC-1123 valid)
#   sse_handler: anthropic | openai | none
hosts:
  - host: api.anthropic.com
    sse_handler: anthropic
  - host: api.deepseek.com
    sse_handler: openai
  - host: api.openai.com
    sse_handler: openai
  - host: openrouter.ai
    sse_handler: openai
EOF
    echo "Wrote default /etc/waterwall/permitted_hosts.yaml"
else
    echo "permitted_hosts.yaml already exists, skipping"
fi

# 5c. Generate CA if not present — via `waterwall regen-ca` so the CA's
# permittedSubtrees match the seeded permitted_hosts.yaml (all 4 hosts),
# not a single-host CA (issue #11). Must run AFTER step 5b.
if [ ! -f /etc/waterwall/ca.pem ]; then
    echo "Generating CA (multi-host, from permitted_hosts.yaml)..."
    /opt/waterwall/.venv/bin/waterwall regen-ca \
        --hosts-file /etc/waterwall/permitted_hosts.yaml \
        --out-dir /etc/waterwall
else
    echo "CA already exists at /etc/waterwall/ca.pem, skipping"
fi

# Write default config.yaml if not present
if [ ! -f /etc/waterwall/config.yaml ]; then
    cat > /etc/waterwall/config.yaml <<'EOF'
kill_switch: false
EOF
    echo "Wrote default /etc/waterwall/config.yaml"
else
    echo "config.yaml already exists, skipping"
fi

# 6. Set ownership + perms so the runtime `waterwall` user can read what it needs.
# The systemd unit drops privileges; without group-readability the addon's
# pre-start verify-install fails with "[Errno 13] Permission denied" on
# signing.key + mitmproxy-ca.pem (BACKLOG-tracked Phase 7 finding).
chown -R waterwall:waterwall /var/log/waterwall /run/waterwall
chown root:waterwall /etc/waterwall
chmod 0750 /etc/waterwall

# Sensitive files: root-owned, waterwall-group-readable, no world access.
for f in /etc/waterwall/signing.key /etc/waterwall/mitmproxy-ca.pem /etc/waterwall/ca.key; do
    if [ -f "$f" ]; then
        chown root:waterwall "$f"
        chmod 0440 "$f"
    fi
done

# Public/non-sensitive files: world-readable is fine, but keep group consistent.
for f in /etc/waterwall/ca.pem /etc/waterwall/signing.pub /etc/waterwall/patterns.py /etc/waterwall/config.yaml; do
    if [ -f "$f" ]; then
        chown root:waterwall "$f"
        chmod 0644 "$f"
    fi
done

# 7. Copy systemd units
cp "$SOURCE_ROOT/deploy/systemd/waterwall-proxy.service" /etc/systemd/system/
cp "$SOURCE_ROOT/deploy/systemd/waterwall-proxy-restart.timer" /etc/systemd/system/
cp "$SOURCE_ROOT/deploy/systemd/waterwall-proxy-restart.service" /etc/systemd/system/

# 8. Create /opt/waterwall/bin/ shim so ExecStartPre path resolves
mkdir -p /opt/waterwall/bin
ln -sf /opt/waterwall/.venv/bin/waterwall /opt/waterwall/bin/waterwall

# 9. Reload systemd
systemctl daemon-reload

# 10. Enable units (do NOT start)
systemctl enable waterwall-proxy.service waterwall-proxy-restart.timer

echo ""
echo "install complete. start with: systemctl start waterwall-proxy.service"
