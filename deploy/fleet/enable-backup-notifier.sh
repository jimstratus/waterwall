#!/usr/bin/env bash
# enable-backup-notifier.sh — Step 3: turn on the Phase-2 per-host backup local
# notifier in /etc/waterwall/config.yaml. Independent of the central gateway, so
# a single host can still warn you when the gateway/Discord path is down.
#
# The Discord webhook is a SECRET. Read it from a 0400 root file (or stdin/prompt)
# — never pass it on the command line (shell history / ps). E.g.:
#   echo "https://discord.com/api/webhooks/…" | sudo bash deploy/fleet/enable-backup-notifier.sh
# or write it to /etc/waterwall/backup-webhook (chmod 0400) and run with --from-file.
#
# Idempotent: merging the same config twice returns "no changes".
#
# Usage:
#   echo "$WEBHOOK" | sudo bash deploy/fleet/enable-backup-notifier.sh
#   sudo bash deploy/fleet/enable-backup-notifier.sh --from-file /etc/waterwall/backup-webhook \
#       --log-path /var/log/waterwall/backup-alerts.log --miss-threshold 2
set -euo pipefail

FROM_FILE=""
LOG_PATH="/var/log/waterwall/backup-alerts.log"
MISS=2
while [ $# -gt 0 ]; do
    case "$1" in
        --from-file) FROM_FILE="${2:?}"; shift ;;
        --log-path) LOG_PATH="${2:?}"; shift ;;
        --miss-threshold) MISS="${2:?}"; shift ;;
        -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
    shift
done

ETC=/etc/waterwall
SRC=/opt/waterwall
PY="$SRC/.venv/bin/python"
WEBHOOK="${WATERWALL_BACKUP_WEBHOOK:-}"

if [ -n "$FROM_FILE" ]; then
    [ -r "$FROM_FILE" ] || { echo "error: cannot read $FROM_FILE" >&2; exit 1; }
    WEBHOOK="$(cat "$FROM_FILE")"
elif [ -z "$WEBHOOK" ] && [ -t 0 ]; then
    # interactive: prompt without echoing to the terminal
    printf "Discord webhook URL (input hidden): "; read -rs WEBHOOK; echo
elif [ -z "$WEBHOOK" ]; then
    WEBHOOK="$(cat)"
fi
[ -n "$WEBHOOK" ] || { echo "error: empty webhook" >&2; exit 1; }
case "$WEBHOOK" in
    https://discord.com/api/webhooks/*) : ;;
    *) echo "error: webhook must start with https://discord.com/api/webhooks/" >&2; exit 2 ;;
esac

# Prepare the log dir + file (the reporter runs as the waterwall user and writes here).
mkdir -p "$(dirname "$LOG_PATH")"
touch "$LOG_PATH"
chown waterwall:waterwall "$LOG_PATH" 2>/dev/null || chown waterwall "$LOG_PATH"
chmod 0640 "$LOG_PATH"

mkdir -p "$ETC"

snippet=$(printf 'monitor:\n  backup:\n    enabled: true\n    webhook: "%s"\n    log_path: "%s"\n    gateway_miss_threshold: %s\n' "$WEBHOOK" "$LOG_PATH" "$MISS")
printf '%s\n' "$snippet" | "$PY" "$SRC/deploy/fleet/_config-merge.py" --config "$ETC/config.yaml"

# Restart the reporter so it picks up the new config (no-op if it wasn't running).
if systemctl list-unit-files 2>/dev/null | grep -q waterwall-reporter.service; then
    systemctl restart waterwall-reporter.service 2>/dev/null && echo "restarted waterwall-reporter" || \
        echo "note: waterwall-reporter not started (enable it once monitor.enabled is set)"
fi

echo ""
echo "== backup notifier enabled =="
echo "  log_path: $LOG_PATH   (tail with: sudo tail -f \"$LOG_PATH\"; journalctl -u waterwall-reporter)"
echo "  webhook + miss_threshold stored in $ETC/config.yaml — REMINDER: keep $ETC/config.yaml 0640 root:waterwall"
[ -n "$FROM_FILE" ] || echo "  (webhook was read from stdin/prompt; not stored to disk anywhere except config.yaml)"