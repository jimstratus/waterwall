#!/usr/bin/env bash
# deploy-fleet.sh — Step 2 orchestrator. Runs on a CONNECTIVITY HOST that has
# SSH access to the fleet targets (NOT the edge/gateway host — that host has no
# outbound fleet connectivity). For each target it SSHes in, pulls /opt/waterwall
# to REF, and runs bootstrap-host.sh remotely.
#
# Host/user mapping is operator-specific, so this is a thin, parameterized loop.
# Targets are passed as user@host (or bare host, then --user applies). Examples
# below use the generic names from deploy/fleet/README.md.
#
# Usage:
#   bash deploy/fleet/deploy-fleet.sh --ref master canary-host fleet-host-1 fleet-host-2
#   bash deploy/fleet/deploy-fleet.sh --user operator --ref master canary-host
#
# NOTE: a WSL target needs WSL2 with /etc/wsl.conf [boot] systemd=true plus a
# reachable SSH server before this will work there.
set -euo pipefail

REF=master
SSH_USER=""
REFRESH=0
TARGETS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --ref) REF="${2:?}"; shift ;;
        --user) SSH_USER="${2:?}"; shift ;;
        --refresh) REFRESH=1 ;;   # git fetch + hard reset to origin/REF on each host
        -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
        -*) echo "unknown flag: $1" >&2; exit 2 ;;
        *) TARGETS+=("$1") ;;
    esac
    shift
done
[ "${#TARGETS[@]}" -gt 0 ] || { echo "no targets given" >&2; exit 2; }

BOOTS=/opt/waterwall/deploy/fleet/bootstrap-host.sh

for t in "${TARGETS[@]}"; do
    # support: host | user@host | host:port | user@host:port
    after_at="${t##*@}"          # the host[:port] part (or whole token if no @)
    user="${SSH_USER:-${t%@*}}"  # the user@ part (or whole token if no @); -user overrides
    [ "$user" = "$t" ] && user=""            # no @ and no --user -> no user
    port="${after_at##*:}"                    # port after a ':' (or whole if no ':')
    host="${after_at%%:*}"
    [ "$port" = "$after_at" ] && port=""      # no ':' -> no port
    ssh_target="${user:+$user@}$host"
    ssh_opts=()
    [ -n "$port" ] && ssh_opts=(-p "$port")
    echo "==== target $ssh_target${port:+:$port} (ref $REF) ===="
    ssh "${ssh_opts[@]}" "$ssh_target" bash -s "$REF" "$REFRESH" "$BOOTS" <<'REMOTE'
set -euo pipefail
ref="$1"; refresh="$2"; boots="$3"
cd /opt/waterwall
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "error: /opt/waterwall is not a git checkout on $(hostname)" >&2; exit 1
fi
if [ "$refresh" = "1" ]; then
    git fetch --quiet origin
    git reset --hard "origin/$ref"
else
    git fetch --quiet origin
    git checkout "$ref" 2>/dev/null || git checkout "origin/$ref"
fi
git submodule update --init --recursive --quiet 2>/dev/null || true
echo "== /opt/waterwall at $(git rev-parse --short HEAD)"
sudo bash "$boots"
REMOTE
done