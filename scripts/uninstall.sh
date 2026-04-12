#!/usr/bin/env bash
# uninstall.sh — удаление nginx-sentinel с системы.
# Логи НЕ удаляются: /var/log/nginx-sentinel/ сохраняется для аудита.
# Требует: root.
set -euo pipefail

# ── 1. Остановка сервиса ──────────────────────────────────────────────────────────────
echo "[1/6] Остановка сервиса..."
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

# ── 5. Конфиг ─────────────────────────────────────────────────────────────────────────
echo "[5/6] Конфиг..."
rm -rf /etc/nginx-sentinel

# ── 6. Бинарник и пользователь ───────────────────────────────────────────────────────
echo "[6/6] Бинарник и пользователь..."
rm -f /usr/local/bin/nginx-sentinel
# || true: пользователь может уже быть удалён.
userdel nginx-sentinel 2>/dev/null || true

echo ""
echo "Удаление завершено. Логи сохранены в /var/log/nginx-sentinel/"
