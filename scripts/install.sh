#!/usr/bin/env bash
# install.sh — установка nginx-sentinel на системе.
# Идемпотентный: безопасен для повторного запуска.
#   Обновляется при каждом запуске: бинарник, systemd unit, fail2ban конфиги, logrotate.
#   Не перезаписывается: config.yaml (чтобы не затирать production-настройки).
# Требует: root, go (для сборки), systemd. fail2ban опционален — шаг 5 пропускается если не установлен.
# Запуск: sudo ./scripts/install.sh  (из любой директории)
set -euo pipefail

# ── Корень репозитория — скрипт всегда работает из него ──────────────────────────────
# readlink -f раскрывает symlinks; dirname + cd гарантируют абсолютный путь.
REPO_ROOT="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
cd "$REPO_ROOT"

# ── Проверка прав ─────────────────────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] запустите скрипт от root (sudo ./scripts/install.sh)"
    exit 1
fi

# ── Проверка зависимостей ─────────────────────────────────────────────────────────────
command -v go        >/dev/null 2>&1 || { echo "[ERROR] go не найден: установите Go 1.19+"; exit 1; }
command -v systemctl >/dev/null 2>&1 || { echo "[ERROR] systemctl не найден: требуется systemd"; exit 1; }

HAS_FAIL2BAN=false
if command -v fail2ban-client >/dev/null 2>&1; then
    HAS_FAIL2BAN=true
else
    echo "[WARN] fail2ban не найден — шаг 5 (Fail2Ban) будет пропущен"
fi

# ── Проверка наличия deploy-файлов и конфига ─────────────────────────────────────────
for f in config.yaml \
          deploy/nginx-sentinel.service deploy/logrotate/nginx-sentinel \
          deploy/fail2ban/filter.d/nginx-sentinel.conf \
          deploy/fail2ban/jail.d/nginx-sentinel.conf; do
    [ -f "$f" ] || { echo "[ERROR] отсутствует файл: $f"; exit 1; }
done

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
if $HAS_FAIL2BAN; then
    echo "[5/6] Fail2Ban..."
    install -m 644 deploy/fail2ban/filter.d/nginx-sentinel.conf /etc/fail2ban/filter.d/
    install -m 644 deploy/fail2ban/jail.d/nginx-sentinel.conf   /etc/fail2ban/jail.d/
    # || true: fail2ban может быть не запущен в момент установки — не прерывать скрипт.
    systemctl reload fail2ban 2>/dev/null || true
else
    echo "[5/6] Fail2Ban — пропущен"
fi

# ── 6. Logrotate ──────────────────────────────────────────────────────────────────────
echo "[6/6] Logrotate..."
install -m 644 deploy/logrotate/nginx-sentinel /etc/logrotate.d/

echo ""
echo "Установка завершена. Запустить: systemctl start nginx-sentinel"
echo "Статус:                         systemctl status nginx-sentinel"
