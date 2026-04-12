#!/usr/bin/env bash
# install.sh — установка nginx-sentinel на системе.
# Идемпотентный: безопасен для повторного запуска — существующие файлы не перезаписываются.
# Требует: root, go (для сборки), systemd, fail2ban.
set -euo pipefail

BINARY=/usr/local/bin/nginx-sentinel
CONFIG=/etc/nginx-sentinel/config.yaml
LOG_DIR=/var/log/nginx-sentinel

# ── 1. Сборка бинарника ───────────────────────────────────────────────────────────────
echo "[1/6] Сборка..."
go build -o "$BINARY" .

# ── 2. Системный пользователь ─────────────────────────────────────────────────────────
# || true: пользователь может уже существовать при повторном запуске — не прерывать скрипт.
echo "[2/6] Пользователь nginx-sentinel..."
useradd --system --no-create-home --shell /usr/sbin/nologin nginx-sentinel 2>/dev/null || true

# ── 3. Директории и конфиг ────────────────────────────────────────────────────────────
echo "[3/6] Директории и конфиг..."
install -d -o nginx-sentinel -g nginx-sentinel "$LOG_DIR"
install -d /etc/nginx-sentinel
# Конфиг копируется только если его ещё нет — не перезаписываем production-настройки.
[ -f "$CONFIG" ] || install -m 644 config.yaml "$CONFIG"

# ── 4. systemd unit ───────────────────────────────────────────────────────────────────
echo "[4/6] systemd..."
install -m 644 deploy/nginx-sentinel.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable nginx-sentinel

# ── 5. Fail2Ban ───────────────────────────────────────────────────────────────────────
echo "[5/6] Fail2Ban..."
install -m 644 deploy/fail2ban/filter.d/nginx-sentinel.conf /etc/fail2ban/filter.d/
install -m 644 deploy/fail2ban/jail.d/nginx-sentinel.conf   /etc/fail2ban/jail.d/
# || true: fail2ban может быть не запущен в момент установки — не прерывать скрипт.
systemctl reload fail2ban 2>/dev/null || true

# ── 6. Logrotate ──────────────────────────────────────────────────────────────────────
echo "[6/6] Logrotate..."
install -m 644 deploy/logrotate/nginx-sentinel /etc/logrotate.d/

echo ""
echo "Установка завершена. Запустить: systemctl start nginx-sentinel"
echo "Статус:                         systemctl status nginx-sentinel"
