#!/usr/bin/env bash
# wire-canary.sh — Step 1 of the monitor fleet rollout: stand up the in-path
# redaction canary on THIS host (the designated first gate host) and enable the
# Phase-4 launch hard-gate.
#
# Proven mechanism: docs/superpowers/lab-notes/monitor-phase1-acceptance.md
# (live scratch-proxy validation, 2026-06-26). Spec/docs: docs/monitor.md.
#
# What it does (idempotent, every step):
#   1. preflight (waterwall installed; proxy unit + config present)
#   2. add the canary host to permitted_hosts.yaml
#   3. add it to the proxy unit's --allow-hosts regex (source + deployed)
#   4. regen-ca (so the name-constrained CA permits the canary host)
#   5. issue a canary leaf cert signed by the waterwall CA -> /etc/waterwall/canary.{pem,key}
#   6. install + enable the canary-echo systemd unit
#   7. add 127.0.0.1 canary.waterwall.local to /etc/hosts (proxy intercepts by host)
#   8. seed /etc/waterwall/client.env from the template if missing
#   9. enable the launch gate in config.yaml (monitor.gate.enabled=true, on_error=warn)
#  10. restart the proxy; start the canary echo
#
# Upstream trust: mitmproxy defaults to NOT verifying upstream certs, so the proxy
# forwards to the loopback echo without needing ssl_verify_upstream_trusted_ca. Do
# NOT add a global ssl_verify_upstream_trusted_ca=/etc/waterwall/ca.pem — real
# providers (anthropic/openai/…) are not signed by the waterwall CA and would break.
#
# Usage:  sudo bash deploy/fleet/wire-canary.sh              # dry-run (plan only)
#         sudo bash deploy/fleet/wire-canary.sh --apply      # execute
#         sudo bash deploy/fleet/wire-canary.sh --apply --canary-host canary.waterwall.local
set -euo pipefail

APPLY=0
CANARY_HOST="canary.waterwall.local"
while [ $# -gt 0 ]; do
    case "$1" in
        --apply) APPLY=1 ;;
        --canary-host) CANARY_HOST="${2:?}"; shift ;;
        -h|--help)
            sed -n '2,26p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
    shift
done

SRC=/opt/waterwall
VENV="$SRC/.venv"
WW="$VENV/bin/waterwall"
PY="$VENV/bin/python"
ETC=/etc/waterwall
PROXY_UNIT_SRC="$SRC/deploy/systemd/waterwall-proxy.service"
PROXY_UNIT="/etc/systemd/system/waterwall-proxy.service"
ECHO_UNIT_SRC="$SRC/deploy/monitor/waterwall-canary-echo.service"
ECHO_UNIT="/etc/systemd/system/waterwall-canary-echo.service"
# Derive the (regex-escaped) allow-host token from --canary-host so a custom
# host is actually admitted by the proxy, not just by permitted_hosts/cert/hosts.
ALLOW_RE="$(printf '%s' "$CANARY_HOST" | sed 's/\./\\./g')"

note() { [ "$APPLY" -eq 1 ] && echo "  >> $*" || echo "  (dry-run) $*"; }

# ---- 1. preflight -------------------------------------------------------------
echo "== preflight =="
for f in "$SRC" "$VENV/bin/waterwall" "$WW" "$ETC/config.yaml" "$ETC/permitted_hosts.yaml" "$PROXY_UNIT_SRC"; do
    [ -e "$f" ] || { echo "missing: $f — run systemd/install.sh first" >&2; exit 1; }
done
[ -e "$PROXY_UNIT" ] || { echo "missing: $PROXY_UNIT — run systemd/install.sh first" >&2; exit 1; }
getent passwd waterwall >/dev/null || { echo "missing user: waterwall" >&2; exit 1; }
echo "  ok: /opt/waterwall, venv, proxy unit, config present"

# ---- 2. permitted_hosts.yaml --------------------------------------------------
echo "== add $CANARY_HOST to permitted_hosts.yaml =="
if "$PY" - "$ETC/permitted_hosts.yaml" "$CANARY_HOST" <<'PY'
import sys, yaml
from pathlib import Path
p, host = Path(sys.argv[1]), sys.argv[2]
data = yaml.safe_load(p.read_text()) or {}
hosts = data.get("hosts") or []
if any(h.get("host") == host for h in hosts):
    print(f"  already present: {host}")
    sys.exit(42)  # signal: no change needed
sys.exit(0)  # signal: change needed
PY
then
    note "append {- host: $CANARY_HOST, sse_handler: none}"
    if [ "$APPLY" -eq 1 ]; then
        "$PY" - "$ETC/permitted_hosts.yaml" "$CANARY_HOST" <<'PY'
import sys, yaml
from pathlib import Path
p, host = Path(sys.argv[1]), sys.argv[2]
data = yaml.safe_load(p.read_text()) or {}
data.setdefault("hosts", [])
data["hosts"] = [h for h in data["hosts"] if h.get("host") != host]
data["hosts"].append({"host": host, "sse_handler": "none"})
p.write_text(yaml.safe_dump(data, sort_keys=False, default_flow_style=False))
print(f"  appended {host} (sse_handler=none)")
PY
        chown root:waterwall "$ETC/permitted_hosts.yaml"; chmod 0644 "$ETC/permitted_hosts.yaml"
    fi
else
    echo "  already present"
fi

# ---- 3. --allow-hosts regex (source + deployed) ------------------------------
echo "== add $CANARY_HOST to proxy unit --allow-hosts =="
edit_allow_hosts() {
    local unit="$1"
    if "$PY" - "$unit" "$ALLOW_RE" <<'PY'
import sys, re
from pathlib import Path
p, token = Path(sys.argv[1]), sys.argv[2]
t = p.read_text()
m = re.search(r"--allow-hosts\s+'([^']*)'", t)
if not m:
    print("  no --allow-hosts line found", file=sys.stderr); sys.exit(2)
if token in m.group(1):
    print("  already present"); sys.exit(42)
sys.exit(0)
PY
    then
        note "append |$ALLOW_RE to --allow-hosts in $unit"
        [ "$APPLY" -eq 1 ] || return 0
        "$PY" - "$unit" "$ALLOW_RE" <<'PY'
import sys, re
from pathlib import Path
p, token = Path(sys.argv[1]), sys.argv[2]
t = p.read_text()
def repl(m):
    inner = m.group(1)
    if token in inner: return m.group(0)
    return f"--allow-hosts '{inner}|{token}'"
p.write_text(re.sub(r"--allow-hosts\s+'([^']*)'", repl, t))
print("  updated --allow-hosts")
PY
    else
        echo "  already present in $unit"
    fi
}
edit_allow_hosts "$PROXY_UNIT_SRC"
edit_allow_hosts "$PROXY_UNIT"

# ---- 4. regen-ca --------------------------------------------------------------
echo "== regen-ca (name-constrained CA now permits $CANARY_HOST) =="
note "waterwall regen-ca --hosts-file $ETC/permitted_hosts.yaml --out-dir $ETC"
if [ "$APPLY" -eq 1 ]; then
    "$WW" regen-ca --hosts-file "$ETC/permitted_hosts.yaml" --out-dir "$ETC"
fi

# ---- 5. issue canary leaf cert ------------------------------------------------
echo "== issue canary leaf cert signed by the waterwall CA =="
if [ -e "$ETC/canary.pem" ] && [ -e "$ETC/canary.key" ]; then
    echo "  already present: $ETC/canary.{pem,key}"
else
    note "generate $ETC/canary.pem + canary.key (RSA leaf, SAN=$CANARY_HOST)"
    if [ "$APPLY" -eq 1 ]; then
        "$PY" - "$ETC/ca.pem" "$ETC/ca.key" "$ETC/canary.pem" "$ETC/canary.key" "$CANARY_HOST" <<'PY'
import sys, datetime as dt
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
ca_cert = x509.load_pem_x509_certificate(Path(sys.argv[1]).read_bytes())
ca_key = serialization.load_pem_private_key(Path(sys.argv[2]).read_bytes(), password=None)
host = sys.argv[5]
leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
now = dt.datetime.now(dt.timezone.utc)
cert = (
    x509.CertificateBuilder()
    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
    .issuer_name(ca_cert.subject)
    .public_key(leaf_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - dt.timedelta(minutes=5))
    .not_valid_after(now + dt.timedelta(days=365 * 5))
    .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .sign(ca_key, hashes.SHA256())
)
Path(sys.argv[3]).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
Path(sys.argv[4]).write_bytes(leaf_key.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
    serialization.NoEncryption()))
print(f"  wrote canary leaf for {host}")
PY
        chown root:waterwall "$ETC/canary.pem" "$ETC/canary.key"
        chmod 0644 "$ETC/canary.pem"; chmod 0440 "$ETC/canary.key"
    fi
fi

# ---- 6. canary-echo unit ------------------------------------------------------
echo "== install + enable canary-echo unit =="
note "cp $ECHO_UNIT_SRC -> $ECHO_UNIT; daemon-reload; enable"
if [ "$APPLY" -eq 1 ]; then
    cp "$ECHO_UNIT_SRC" "$ECHO_UNIT"
    systemctl daemon-reload
    systemctl enable waterwall-canary-echo.service >/dev/null
fi

# ---- 7. /etc/hosts loopback entry --------------------------------------------
echo "== add 127.0.0.1 $CANARY_HOST to /etc/hosts =="
if grep -qE "[[:space:]]$CANARY_HOST([[:space:]]|$)" /etc/hosts; then
    echo "  already present"
else
    note "append '127.0.0.1 $CANARY_HOST' to /etc/hosts"
    [ "$APPLY" -eq 1 ] && printf '\n127.0.0.1 %s\n' "$CANARY_HOST" >> /etc/hosts
fi

# ---- 8. client.env ------------------------------------------------------------
echo "== seed $ETC/client.env =="
if [ -e "$ETC/client.env" ]; then
    echo "  already present"
else
    note "cp $SRC/deploy/monitor/client.env.template -> $ETC/client.env"
    if [ "$APPLY" -eq 1 ]; then
        cp "$SRC/deploy/monitor/client.env.template" "$ETC/client.env"
        chown root:waterwall "$ETC/client.env"; chmod 0644 "$ETC/client.env"
    fi
fi

# ---- 9. enable the launch gate in config.yaml --------------------------------
echo "== enable monitor.gate in config.yaml (on_error=warn, fail-open) =="
snippet="monitor:
  gate:
    enabled: true
    on_error: warn
  canary_url: \"https://$CANARY_HOST/canary\"
  synthetic: AKIAIOSFODNN7EXAMPLE
  client_env: /etc/waterwall/client.env"
note "merge monitor.gate.* into $ETC/config.yaml"
if [ "$APPLY" -eq 1 ]; then
    printf '%s\n' "$snippet" | "$SRC/deploy/fleet/_config-merge.py" --config "$ETC/config.yaml"
fi

# ---- 10. restart proxy + start canary echo ------------------------------------
echo "== restart proxy; start canary echo =="
note "systemctl restart waterwall-proxy; systemctl start waterwall-canary-echo"
if [ "$APPLY" -eq 1 ]; then
    systemctl restart waterwall-proxy.service
    systemctl start waterwall-canary-echo.service
fi

echo ""
if [ "$APPLY" -eq 1 ]; then
    echo "== apply complete. Next: =="
    echo "  - enable + start the reporter: sudo systemctl enable --now waterwall-reporter.service"
    echo "    (set monitor.enabled + gateway_url/token in $ETC/config.yaml first)"
    echo "  - verify: bash $SRC/deploy/fleet/verify-monitor.sh"
else
    echo "== dry-run complete (no changes). Re-run with --apply to execute. =="
fi