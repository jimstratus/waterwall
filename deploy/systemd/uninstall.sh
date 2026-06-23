#!/bin/bash
# Waterwall uninstall script — exact inverse of install.sh.
#
# Default behavior (safe): stop the service, disable units, remove unit files,
# remove the /opt/waterwall/bin/waterwall symlink, and remove the `waterwall`
# system user. Persistent state (/etc/waterwall, /var/log/waterwall, /run/waterwall)
# is PRESERVED so a future install.sh re-uses the existing CA + signing key +
# audit logs.
#
# Pass --purge to also delete /etc/waterwall, /var/log/waterwall, /run/waterwall,
# and /opt/waterwall. This is irreversible — back up the signing key first if
# you ever want to verify historical evidence.
#
# Pass --keep-source to leave /opt/waterwall in place under --purge (useful when
# you cloned waterwall as a non-root user and just want to remove the system
# install bits).
#
# Run as root.

set -uo pipefail

PURGE=0
KEEP_SOURCE=0
for arg in "$@"; do
    case "$arg" in
        --purge)       PURGE=1 ;;
        --keep-source) KEEP_SOURCE=1 ;;
        --help|-h)
            sed -n 's/^# //p' "$0" | head -25
            exit 0
            ;;
        *)
            echo "Unknown arg: $arg"
            echo "Run with --help for usage"
            exit 1
            ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: must run as root"
    exit 1
fi

echo "=== Waterwall uninstall ==="
[ $PURGE -eq 1 ] && echo "MODE: --purge (will delete config + audit logs + source)"

# 1. Stop and disable units (idempotent — silently OK if already stopped/missing)
echo "--- stopping + disabling systemd units ---"
systemctl stop waterwall-proxy.service 2>/dev/null || true
systemctl stop waterwall-proxy-restart.timer 2>/dev/null || true
systemctl disable waterwall-proxy.service 2>/dev/null || true
systemctl disable waterwall-proxy-restart.timer 2>/dev/null || true

# 2. Remove unit files
echo "--- removing unit files ---"
rm -f /etc/systemd/system/waterwall-proxy.service
rm -f /etc/systemd/system/waterwall-proxy-restart.timer
rm -f /etc/systemd/system/waterwall-proxy-restart.service
systemctl daemon-reload

# 3. Remove /opt/waterwall/bin shim
echo "--- removing /opt/waterwall/bin shim ---"
rm -f /opt/waterwall/bin/waterwall
rmdir /opt/waterwall/bin 2>/dev/null || true

# 4. Remove the system user
echo "--- removing waterwall system user ---"
if getent passwd waterwall > /dev/null 2>&1; then
    userdel waterwall || echo "WARN: userdel failed (user may have running processes)"
else
    echo "(no waterwall user to remove)"
fi

# 5. Purge persistent state if requested
if [ $PURGE -eq 1 ]; then
    echo "--- PURGE: removing /etc/waterwall ---"
    rm -rf /etc/waterwall
    echo "--- PURGE: removing /var/log/waterwall ---"
    rm -rf /var/log/waterwall
    echo "--- PURGE: removing /run/waterwall ---"
    rm -rf /run/waterwall
    if [ $KEEP_SOURCE -eq 0 ]; then
        echo "--- PURGE: removing /opt/waterwall ---"
        rm -rf /opt/waterwall
    else
        echo "--- KEEP_SOURCE: leaving /opt/waterwall in place ---"
    fi
else
    echo "--- preserving /etc/waterwall, /var/log/waterwall, /run/waterwall, /opt/waterwall ---"
    echo "    (re-run install.sh to restore service; pass --purge to fully delete)"
fi

echo ""
echo "=== uninstall complete ==="
if [ $PURGE -eq 0 ]; then
    echo "State retained for possible re-install."
    echo "To fully delete: $0 --purge"
fi
