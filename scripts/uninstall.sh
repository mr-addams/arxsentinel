#!/usr/bin/env bash
# uninstall.sh — removes nginx-sentinel from the system.
# Logs are NOT deleted: /var/log/nginx-sentinel/ is preserved for audit.
# Requires: root.
set -euo pipefail

# ── 1. Stop service ───────────────────────────────────────────────────────────────────
echo "[1/6] Stopping service..."
systemctl stop    nginx-sentinel 2>/dev/null || true
systemctl disable nginx-sentinel 2>/dev/null || true

# ── 2. systemd unit ───────────────────────────────────────────────────────────────────
echo "[2/6] systemd..."
rm -f /etc/systemd/system/nginx-sentinel.service
systemctl daemon-reload

# ── 3. Fail2Ban ───────────────────────────────────────────────────────────────────────
echo "[3/6] Fail2Ban..."
rm -f /etc/fail2ban/filter.d/nginx-sentinel.conf
rm -f /etc/fail2ban/jail.d/nginx-sentinel.conf
systemctl reload fail2ban 2>/dev/null || true

# ── 4. Logrotate ──────────────────────────────────────────────────────────────────────
echo "[4/6] Logrotate..."
rm -f /etc/logrotate.d/nginx-sentinel

# ── 5. Config ─────────────────────────────────────────────────────────────────────────
echo "[5/6] Config..."
rm -rf /etc/nginx-sentinel

# ── 6. Binary and user ────────────────────────────────────────────────────────────────
echo "[6/6] Binary and user..."
rm -f /usr/local/bin/nginx-sentinel
# || true: user may have already been deleted.
userdel nginx-sentinel 2>/dev/null || true

echo ""
echo "Uninstall complete. Logs preserved at /var/log/nginx-sentinel/"
