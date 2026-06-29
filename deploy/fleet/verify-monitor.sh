#!/usr/bin/env bash
# verify-monitor.sh — read-only drift + health check for the monitor fleet on
# THIS host. No state changes; safe to run any time. Exits 1 if any check fails.
#
# Checks:
#   1. proxy systemd unit active/healthy
#   2. permitted_hosts.yaml vs the deployed unit's --allow-hosts regex (drift)
#   3. CA permittedSubtrees vs permitted_hosts (regen-ca needed?)
#   4. canary-echo unit enabled + leaf cert present + cert valid + matches host
#   5. launch-gate config (monitor.gate.enabled + canary_url + client_env)
#   6. reporter unit enabled + config present (monitor.enabled/gateway_url/token)
#   7. backup notifier config (enabled + webhook + log_path writable)
#   8. /etc/hosts loopback entry for the canary host
#
# Usage:  sudo bash /opt/waterwall/deploy/fleet/verify-monitor.sh
set -euo pipefail

SRC=/opt/waterwall
VENV="$SRC/.venv"
PY="$VENV/bin/python"
ETC=/etc/waterwall
PROXY_UNIT="/etc/systemd/system/waterwall-proxy.service"
PASS=0; FAIL=0
ok()   { printf '  \xe2\x9c\x93 %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '  \xe2\x9c\x97 %s\n' "$*"; FAIL=$((FAIL+1)); }
warn() { printf '  \xe2\x9a\xa0 %s\n' "$*"; }

load_cfg() { "$PY" - "$ETC/config.yaml" "$1" <<'PY'
import sys, yaml
from pathlib import Path
cfg = yaml.safe_load(Path(sys.argv[1]).read_text()) or {}
mon = (cfg or {}).get("monitor") or {}
keys = sys.argv[2].split(".")
v = mon
for k in keys:
    v = v.get(k) if isinstance(v, dict) else None
print(v if v is not None else "")
PY
}

echo "== 1. proxy unit =="
if systemctl is-active --quiet waterwall-proxy.service 2>/dev/null; then
    ok "waterwall-proxy.service active"
else
    bad "waterwall-proxy.service not active"
fi

echo "== 2. permitted_hosts vs --allow-hosts (drift) =="
if [ -f "$ETC/permitted_hosts.yaml" ] && [ -f "$PROXY_UNIT" ]; then
    drift="$("$PY" - "$ETC/permitted_hosts.yaml" "$PROXY_UNIT" <<'PY'
import re, sys, yaml
from pathlib import Path
hosts = [h["host"] for h in (yaml.safe_load(Path(sys.argv[1]).read_text()) or {}).get("hosts") or []]
m = re.search(r"--allow-hosts\s+'([^']*)'", Path(sys.argv[2]).read_text())
seg = (m.group(1).split("|") if m else [])
# the unit regex-escapes dots; compare re.escape(host) to the segments
print("\n".join(h for h in hosts if re.escape(h) not in seg))
PY
)"
    if [ -z "$drift" ]; then ok "all permitted_hosts are in --allow-hosts"; else bad "drift — hosts in permitted_hosts missing from --allow-hosts: $drift"; fi
else
    warn "permitted_hosts.yaml or proxy unit absent — skipping"
fi

echo "== 3. CA permittedSubtrees vs permitted_hosts =="
if [ -f "$ETC/ca.pem" ] && [ -x "$PY" ]; then
    res="$("$PY" - "$ETC/ca.pem" "$ETC/permitted_hosts.yaml" <<'PY'
import sys, yaml
from pathlib import Path
from cryptography import x509
ca = x509.load_pem_x509_certificate(Path(sys.argv[1]).read_bytes())
nc = next((e.value for e in ca.extensions if isinstance(e.value, x509.NameConstraints)), None)
hosts = [h["host"] for h in (yaml.safe_load(Path(sys.argv[2]).read_text()) or {}).get("hosts") or []]
permitted = [s.value for s in (nc.permitted_subtrees or [])] if nc else []
missing = [h for h in hosts if h not in permitted]
print("DRIFT:" + ",".join(missing) if missing else "OK")
PY
)"
    if [ "$res" = "OK" ]; then ok "CA permittedSubtrees match permitted_hosts"; else bad "regen-ca needed — missing: ${res#DRIFT:}"; fi
else
    warn "ca.pem/venv absent — skipping"
fi

echo "== 4. canary-echo unit + leaf cert =="
CANARY_HOST="$(load_cfg canary_url | sed -E 's#^https?://([^/]+)/.*#\1#')"
[ -z "$CANARY_HOST" ] && CANARY_HOST="canary.waterwall.local"
if systemctl is-enabled --quiet waterwall-canary-echo.service 2>/dev/null; then
    ok "canary-echo unit enabled"
else
    bad "canary-echo unit not enabled (run wire-canary.sh)"
fi
if [ -f "$ETC/canary.pem" ] && [ -f "$ETC/canary.key" ]; then
    exp="$("$PY" - "$ETC/canary.pem" "$CANARY_HOST" <<'PY'
import sys
from pathlib import Path
from datetime import datetime, timezone
from cryptography import x509
c = x509.load_pem_x509_certificate(Path(sys.argv[1]).read_bytes())
host = sys.argv[2]
sans = []
for e in c.extensions:
    if isinstance(e.value, x509.SubjectAlternativeName):
        sans = e.value.get_values_for_type(x509.DNSName)
exp = c.not_valid_after_utc
now = datetime.now(timezone.utc)
if host not in sans: print("SAN_MISMATCH")
elif exp < now: print("EXPIRED:" + exp.isoformat())
else: print("OK:" + exp.date().isoformat())
PY
)"
    case "$exp" in
        OK:*) ok "canary leaf cert valid (SAN=$CANARY_HOST, expires ${exp#OK:})" ;;
        SAN_MISMATCH) bad "canary leaf SAN != $CANARY_HOST — re-run wire-canary.sh" ;;
        EXPIRED:*) bad "canary leaf cert expired (${exp#EXPIRED:})" ;;
        *) warn "could not inspect canary leaf cert" ;;
    esac
else
    bad "canary leaf cert missing ($ETC/canary.{pem,key})"
fi

echo "== 5. launch gate config =="
gate="$(load_cfg gate.enabled)"
if [ "$gate" = "True" ]; then
    ok "monitor.gate.enabled=true"; onerr="$(load_cfg gate.on_error)"; ok "gate.on_error=${onerr:-warn}"
else
    warn "monitor.gate.enabled not true (gate off) — run wire-canary.sh to enable on a gate host"
fi

echo "== 6. reporter unit + config =="
if systemctl is-enabled --quiet waterwall-reporter.service 2>/dev/null; then
    ok "reporter unit enabled"
else
    warn "reporter unit not enabled"
fi
men="$(load_cfg enabled)"; gw="$(load_cfg gateway_url)"; tok="$(load_cfg token)"
if [ "$men" = "True" ]; then ok "monitor.enabled=true"; else warn "monitor.enabled not true (reporter idle)"; fi
if [ -n "$gw" ]; then ok "monitor.gateway_url set"; else warn "monitor.gateway_url missing"; fi
if [ -n "$tok" ]; then ok "monitor.token set"; else warn "monitor.token missing"; fi

echo "== 7. backup notifier config =="
ben="$(load_cfg backup.enabled)"
if [ "$ben" = "True" ]; then
    ok "backup.enabled=true"
    lp="$(load_cfg backup.log_path)"
    if [ -n "$lp" ]; then
        # test as the waterwall service account, not root (argus #5): the reporter
        # runs as waterwall, so a root-writable log owned by root would false-ok.
        if sudo -u waterwall test -w "$lp"; then ok "backup log_path writable (as waterwall): $lp"; else bad "backup log_path not writable by waterwall: $lp"; fi
    else
        bad "backup log_path unset"
    fi
    wh="$(load_cfg backup.webhook)"
    if [ -n "$wh" ]; then ok "backup.webhook set"; else bad "backup.webhook missing"; fi
else
    warn "backup notifier not enabled (run enable-backup-notifier.sh)"
fi

echo "== 8. /etc/hosts canary loopback =="
if grep -qE "[[:space:]]$CANARY_HOST([[:space:]]|$)" /etc/hosts; then
    ok "$CANARY_HOST in /etc/hosts"
else
    bad "$CANARY_HOST missing from /etc/hosts (wire-canary.sh step 7)"
fi

echo ""
echo "== verify-monitor: $PASS ok, $FAIL fail =="
[ "$FAIL" -eq 0 ]