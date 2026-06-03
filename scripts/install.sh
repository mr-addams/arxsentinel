#!/usr/bin/env bash
# install.sh — installs arxsentinel on the system.
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
for f in deploy/arxsentinel.service deploy/logrotate/arxsentinel \
          deploy/fail2ban/filter.d/arxsentinel.conf \
          deploy/fail2ban/jail.d/arxsentinel.conf; do
    [ -f "$f" ] || { echo "[ERROR] missing file: $f"; exit 1; }
done

# Resolve source config: prefer real config.yaml, fall back to examples.
if [ -f config.yaml ]; then
    SRC_CONFIG=config.yaml
elif [ -f cookbook/fail2ban/nginx-basic.yaml ]; then
    SRC_CONFIG=cookbook/fail2ban/nginx-basic.yaml
    echo "[INFO] using cookbook/fail2ban/nginx-basic.yaml as source config"
elif [ -f config.reference.yaml ]; then
    SRC_CONFIG=config.reference.yaml
    echo "[INFO] using config.reference.yaml as source config"
else
    echo "[ERROR] no config.yaml or example config found"
    exit 1
fi

BINARY=/usr/local/bin/arxsentinel
CONFIG=/etc/arxsentinel/config.yaml
LOG_DIR=/var/log/arxsentinel
CFG_EXAMPLE="${CONFIG}.example"

# ── Check if service is currently running ──────────────────────────────────────────────
WAS_RUNNING=false
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet arxsentinel 2>/dev/null; then
    WAS_RUNNING=true
    echo "[*] Stopping running service..."
    systemctl stop arxsentinel || true
fi

# ── 1. Build binary ───────────────────────────────────────────────────────────────────
echo "[1/6] Building..."
go build -o "$BINARY" ./cmd/arxsentinel

# ── 2. System user ────────────────────────────────────────────────────────────────────
# || true: user may already exist on repeated runs — do not abort the script.
echo "[2/6] User arxsentinel..."
useradd --system --no-create-home --shell /usr/sbin/nologin arxsentinel 2>/dev/null || true

# ── 3. Directories and config ─────────────────────────────────────────────────────────
echo "[3/6] Directories and config..."
install -d -o arxsentinel -g arxsentinel "$LOG_DIR"
install -d /etc/arxsentinel
# Config is copied only if it does not yet exist — do not overwrite production settings.
[ -f "$CONFIG" ] || install -m 644 "$SRC_CONFIG" "$CONFIG"

# ── 4. systemd unit ───────────────────────────────────────────────────────────────────
echo "[4/6] systemd..."
install -m 644 deploy/arxsentinel.service /etc/systemd/system/arxsentinel.service
systemctl daemon-reload
systemctl enable arxsentinel

# ── 5. Fail2Ban ───────────────────────────────────────────────────────────────────────
if $HAS_FAIL2BAN; then
    echo "[5/6] Fail2Ban..."
    install -m 644 deploy/fail2ban/filter.d/arxsentinel.conf /etc/fail2ban/filter.d/
    install -m 644 deploy/fail2ban/jail.d/arxsentinel.conf   /etc/fail2ban/jail.d/
    # || true: fail2ban may not be running at install time — do not abort the script.
    systemctl reload fail2ban 2>/dev/null || true
else
    echo "[5/6] Fail2Ban — skipped"
fi

# ── 6. Logrotate ──────────────────────────────────────────────────────────────────────
echo "[6/6] Logrotate..."
install -m 644 deploy/logrotate/arxsentinel /etc/logrotate.d/

# ── 7. Config validation (show any missing top-level sections) ──────────────────────────
# Only run if config exists and example is available (post-install).
if [ -f "$CONFIG" ] && [ -f "$CFG_EXAMPLE" ]; then
    missing=""
    while IFS= read -r key; do
        # Match only top-level keys (no leading whitespace, ends with colon)
        if ! grep -qE "^${key}[[:space:]]*:" "$CONFIG"; then
            missing="${missing}  - ${key}\n"
        fi
    done < <(grep -E '^[a-z_]+:' "$CFG_EXAMPLE" | sed 's/:.*//' | sort -u)

    if [ -n "${missing}" ]; then
        echo ""
        echo "┌─────────────────────────────────────────────────────────────────┐"
        echo "│  arxsentinel: config.yaml update recommended                    │"
        echo "└─────────────────────────────────────────────────────────────────┘"
        echo ""
        echo "  Your existing config is missing the following sections:"
        echo ""
        printf "%b" "${missing}"
        echo ""
        echo "  New features in these sections will not be active until you add"
        echo "  them. See the example config for reference:"
        echo "    ${CFG_EXAMPLE}"
        echo ""
    fi
fi

# ── 8. Restart service if it was running before ────────────────────────────────────────
if $WAS_RUNNING; then
    echo "[*] Restarting service..."
    systemctl start arxsentinel
else
    echo ""
    echo "Installation complete. Start with: systemctl start arxsentinel"
    echo "Status:                            systemctl status arxsentinel"
fi
