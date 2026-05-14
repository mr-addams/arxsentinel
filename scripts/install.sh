#!/usr/bin/env bash
# install.sh — installs nginx-sentinel on the system.
# Idempotent: safe to run multiple times.
#   Updated on every run: binary, systemd unit, fail2ban configs, logrotate.
#   Not overwritten: config.yaml (to preserve production settings).
# Requires: root, go (for build), systemd. fail2ban is optional — step 5 is skipped if not installed.
# Usage: sudo ./scripts/install.sh  (from any directory)
set -euo pipefail

# ── Repository root — the script always runs from it ─────────────────────────────────
# readlink -f resolves symlinks; dirname + cd ensures an absolute path.
REPO_ROOT="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
cd "$REPO_ROOT"

# ── Privilege check ───────────────────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] run the script as root (sudo ./scripts/install.sh)"
    exit 1
fi

# ── Dependency check ──────────────────────────────────────────────────────────────────
command -v go        >/dev/null 2>&1 || { echo "[ERROR] go not found: install Go 1.19+"; exit 1; }
command -v systemctl >/dev/null 2>&1 || { echo "[ERROR] systemctl not found: systemd is required"; exit 1; }

HAS_FAIL2BAN=false
if command -v fail2ban-client >/dev/null 2>&1; then
    HAS_FAIL2BAN=true
else
    echo "[WARN] fail2ban not found — step 5 (Fail2Ban) will be skipped"
fi

# ── Check for deploy files and config ────────────────────────────────────────────────
for f in config.yaml \
          deploy/nginx-sentinel.service deploy/logrotate/nginx-sentinel \
          deploy/fail2ban/filter.d/nginx-sentinel.conf \
          deploy/fail2ban/jail.d/nginx-sentinel.conf; do
    [ -f "$f" ] || { echo "[ERROR] missing file: $f"; exit 1; }
done

BINARY=/usr/local/bin/nginx-sentinel
CONFIG=/etc/nginx-sentinel/config.yaml
LOG_DIR=/var/log/nginx-sentinel

# ── 1. Build binary ───────────────────────────────────────────────────────────────────
echo "[1/6] Building..."
go build -o "$BINARY" .

# ── 2. System user ────────────────────────────────────────────────────────────────────
# || true: user may already exist on repeated runs — do not abort the script.
echo "[2/6] User nginx-sentinel..."
useradd --system --no-create-home --shell /usr/sbin/nologin nginx-sentinel 2>/dev/null || true

# ── 3. Directories and config ─────────────────────────────────────────────────────────
echo "[3/6] Directories and config..."
install -d -o nginx-sentinel -g nginx-sentinel "$LOG_DIR"
install -d /etc/nginx-sentinel
# Config is copied only if it does not yet exist — do not overwrite production settings.
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
    # || true: fail2ban may not be running at install time — do not abort the script.
    systemctl reload fail2ban 2>/dev/null || true
else
    echo "[5/6] Fail2Ban — skipped"
fi

# ── 6. Logrotate ──────────────────────────────────────────────────────────────────────
echo "[6/6] Logrotate..."
install -m 644 deploy/logrotate/nginx-sentinel /etc/logrotate.d/

echo ""
echo "Installation complete. Start with: systemctl start nginx-sentinel"
echo "Status:                            systemctl status nginx-sentinel"
