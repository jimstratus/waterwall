#!/usr/bin/env bash
# bootstrap-host.sh — idempotent per-host install of Waterwall + the monitor
# reporter. Run ON each fleet target (e.g. a WSL host) as part of Step 2, either
# directly or via deploy-fleet.sh from a connectivity host.
#
# Assumes the repo is checked out at /opt/waterwall (the operator clones it on
# each host; this script does NOT clone). Builds the venv, runs systemd/install.sh
# (proxy + CA + units), installs the monitor units, then leaves everything
# enabled-but-not-started so the operator can wire config before going live.
#
# Usage:  sudo bash /opt/waterwall/deploy/fleet/bootstrap-host.sh
set -euo pipefail

SRC=/opt/waterwall
VENV="$SRC/.venv"

[ -d "$SRC" ] || { echo "error: $SRC not checked out — clone the repo there first" >&2; exit 1; }

# 1. venv + editable install (idempotent)
if [ ! -x "$VENV/bin/waterwall" ]; then
    echo "== creating venv + installing waterwall =="
    python3 -m venv "$VENV"
    "$VENV/bin/pip" install --upgrade pip >/dev/null
    "$VENV/bin/pip" install -e "$SRC" >/dev/null
else
    echo "== venv already installed =="
    # Pull in new/changed deps on re-runs (e.g. after a git pull). Do NOT swallow
    # a failure (argus #3): a silent pip error would leave the host on new code
    # with a stale env, failing later while bootstrap reports success. set -e
    # surfaces a real pip failure.
    "$VENV/bin/pip" install -e "$SRC"
fi

# 2. base proxy install (systemd/install.sh is idempotent): user, dirs, CA, units.
echo "== running systemd/install.sh =="
bash "$SRC/deploy/systemd/install.sh"

# 3. monitor units (canary echo, reporter, gateway). The gateway runs ONLY on the
#    edge/gateway host; copying its unit elsewhere is harmless because it stays
#    disabled unless explicitly enabled.
echo "== installing monitor systemd units =="
for u in waterwall-canary-echo waterwall-reporter waterwall-monitor-gateway; do
    if [ -f "$SRC/deploy/monitor/$u.service" ]; then
        cp "$SRC/deploy/monitor/$u.service" "/etc/systemd/system/$u.service"
    fi
done
systemctl daemon-reload

# 4. seed client.env from the template if missing (the reporter + agent both need it)
if [ ! -f /etc/waterwall/client.env ] && [ -f "$SRC/deploy/monitor/client.env.template" ]; then
    cp "$SRC/deploy/monitor/client.env.template" /etc/waterwall/client.env
    chown root:waterwall /etc/waterwall/client.env; chmod 0644 /etc/waterwall/client.env
    echo "== seeded /etc/waterwall/client.env =="
fi

# 5. enable proxy + restart timer (NOT start) — operator starts in a window.
systemctl enable waterwall-proxy.service waterwall-proxy-restart.timer >/dev/null

cat <<EOF

== bootstrap complete on $(hostname). Enabled (not started):
   - waterwall-proxy.service            (start: systemctl start waterwall-proxy)
   - waterwall-reporter.service         (configure monitor.* in /etc/waterwall/config.yaml first)
   - waterwall-canary-echo.service      (requires wire-canary.sh on this host)
Next:
   - Set monitor.enabled/gateway_url/token in /etc/waterwall/config.yaml
   - Run wire-canary.sh on this host if it is a gate host
   - Run enable-backup-notifier.sh to turn on the Phase-2 local notifier
EOF