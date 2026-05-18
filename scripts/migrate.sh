#!/usr/bin/env bash
# migrate.sh — migrates an existing nginx-sentinel installation to arxsentinel.
#
# What it does:
#   1. Detects whether nginx-sentinel is installed (service or config dir).
#   2. Backs up /etc/nginx-sentinel/config.yaml before touching anything.
#   3. Copies /etc/nginx-sentinel/ → /etc/arxsentinel/ (skips existing files by default).
#   4. Stops and disables nginx-sentinel.service (if present).
#   5. Enables and starts arxsentinel.service.
#   6. Updates Fail2Ban jail paths in /etc/fail2ban/jail.d/ to point at new log dir.
#   7. Verifies the new service is up by checking /metrics for arx_sentinel_* names.
#
# Idempotent: running it a second time is safe — each step checks state before acting.
# Dry-run:    --dry-run prints every action without executing it.
#
# Usage: sudo ./scripts/migrate.sh [--dry-run]
#        sudo ./scripts/migrate.sh --help

set -euo pipefail

# ── Constants ─────────────────────────────────────────────────────────────────────────

OLD_SERVICE="nginx-sentinel.service"
NEW_SERVICE="arxsentinel.service"

OLD_CONFIG_DIR="/etc/nginx-sentinel"
NEW_CONFIG_DIR="/etc/arxsentinel"

OLD_LOG_DIR="/var/log/nginx-sentinel"
NEW_LOG_DIR="/var/log/arxsentinel"

FAIL2BAN_JAIL_DIR="/etc/fail2ban/jail.d"
METRICS_URL="http://localhost:9117/metrics"

# ── Flags ─────────────────────────────────────────────────────────────────────────────

DRY_RUN=false

# ── Helpers ───────────────────────────────────────────────────────────────────────────

usage() {
    echo "Usage: sudo $0 [--dry-run]"
    echo ""
    echo "Migrates nginx-sentinel installation to arxsentinel."
    echo ""
    echo "Options:"
    echo "  --dry-run   Show what would be done without making any changes."
    echo "  --help      Show this help and exit."
    exit 0
}

log() {
    echo "[migrate] $*"
}

log_dry() {
    # Prefix dry-run lines so the operator can distinguish them at a glance.
    echo "[DRY-RUN] $*"
}

# run <cmd> [args...] — executes or prints depending on dry-run mode.
run() {
    if $DRY_RUN; then
        log_dry "$*"
    else
        "$@"
    fi
}

# run_if_dry <cmd> [args...] — executes even in dry-run (read-only commands for detection).
run_if_dry() {
    "$@"
}

die() {
    echo "[ERROR] $*" >&2
    exit 1
}

# ── Argument parsing ──────────────────────────────────────────────────────────────────

for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=true ;;
        --help)    usage ;;
        *) die "Unknown option: $arg. Run with --help for usage." ;;
    esac
done

# ── Privilege check ───────────────────────────────────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
    die "Run as root: sudo $0"
fi

# ── Step 0: Detect whether nginx-sentinel is present ──────────────────────────────────

log "Step 0: Detecting nginx-sentinel installation..."

OLD_SERVICE_PRESENT=false
OLD_CONFIG_PRESENT=false

if systemctl list-unit-files --no-legend 2>/dev/null | grep -q "^${OLD_SERVICE}"; then
    OLD_SERVICE_PRESENT=true
    log "  Found service: ${OLD_SERVICE}"
fi

if [ -d "$OLD_CONFIG_DIR" ]; then
    OLD_CONFIG_PRESENT=true
    log "  Found config directory: ${OLD_CONFIG_DIR}"
fi

if ! $OLD_SERVICE_PRESENT && ! $OLD_CONFIG_PRESENT; then
    log "  Nothing to migrate — nginx-sentinel installation not detected."
    log "  Skipping to step 5 (ensure arxsentinel is enabled)."
fi

# ── Step 1: Backup old config ─────────────────────────────────────────────────────────

log "Step 1: Backing up old config..."

if $OLD_CONFIG_PRESENT && [ -f "${OLD_CONFIG_DIR}/config.yaml" ]; then
    BACKUP="${OLD_CONFIG_DIR}/config.yaml.backup"
    if $DRY_RUN; then
        log_dry "cp ${OLD_CONFIG_DIR}/config.yaml ${BACKUP}"
    else
        # Skip backup if it already exists — idempotent: do not overwrite a previous backup.
        if [ -f "$BACKUP" ]; then
            log "  Backup already exists at ${BACKUP} — skipping."
        else
            cp "${OLD_CONFIG_DIR}/config.yaml" "$BACKUP"
            log "  Backed up to ${BACKUP}"
        fi
    fi
else
    log "  No config.yaml found in ${OLD_CONFIG_DIR} — skipping backup."
fi

# ── Step 2: Copy config directory ─────────────────────────────────────────────────────

log "Step 2: Copying ${OLD_CONFIG_DIR} → ${NEW_CONFIG_DIR}..."

if $OLD_CONFIG_PRESENT; then
    run mkdir -p "$NEW_CONFIG_DIR"
    # -n: do not overwrite existing files — idempotent, preserves manual edits in new dir.
    run cp -rn "${OLD_CONFIG_DIR}/." "${NEW_CONFIG_DIR}/"
    log "  Config copied (existing files in ${NEW_CONFIG_DIR} were not overwritten)."
else
    log "  ${OLD_CONFIG_DIR} not found — skipping copy."
fi

# ── Step 3: Stop and disable old service ──────────────────────────────────────────────

log "Step 3: Stopping ${OLD_SERVICE}..."

if $OLD_SERVICE_PRESENT; then
    # is-active exits non-zero if service is not running — ignore to stay idempotent.
    if run_if_dry systemctl is-active --quiet "$OLD_SERVICE" 2>/dev/null; then
        run systemctl stop "$OLD_SERVICE"
        log "  Service stopped."
    else
        log "  Service is already stopped."
    fi

    # is-enabled exits non-zero if already disabled — ignore to stay idempotent.
    if run_if_dry systemctl is-enabled --quiet "$OLD_SERVICE" 2>/dev/null; then
        run systemctl disable "$OLD_SERVICE"
        log "  Service disabled."
    else
        log "  Service is already disabled."
    fi
else
    log "  ${OLD_SERVICE} not found — skipping."
fi

# ── Step 4: Enable and start new service ──────────────────────────────────────────────

log "Step 4: Enabling and starting ${NEW_SERVICE}..."

if ! run_if_dry systemctl list-unit-files --no-legend 2>/dev/null | grep -q "^${NEW_SERVICE}"; then
    die "${NEW_SERVICE} is not installed. Run scripts/install.sh first."
fi

if $DRY_RUN; then
    log_dry "systemctl enable ${NEW_SERVICE}"
    log_dry "systemctl start ${NEW_SERVICE}"
else
    systemctl enable "$NEW_SERVICE"
    # is-active exits non-zero if not running — start only when needed.
    if systemctl is-active --quiet "$NEW_SERVICE" 2>/dev/null; then
        log "  Service is already running — reloading to pick up any config changes."
        systemctl reload-or-restart "$NEW_SERVICE"
    else
        systemctl start "$NEW_SERVICE"
    fi
    log "  ${NEW_SERVICE} is enabled and running."
fi

# ── Step 5: Update Fail2Ban jail paths ────────────────────────────────────────────────

log "Step 5: Updating Fail2Ban jail paths in ${FAIL2BAN_JAIL_DIR}..."

if ! command -v fail2ban-client >/dev/null 2>&1; then
    log "  fail2ban not installed — skipping."
else
    # Replace every occurrence of the old log path in all jail configs.
    # sed -i is atomic on Linux (GNU sed uses a tmp file internally).
    JAILS_UPDATED=0
    for jail_file in "${FAIL2BAN_JAIL_DIR}"/*.conf; do
        [ -f "$jail_file" ] || continue
        if grep -q "$OLD_LOG_DIR" "$jail_file" 2>/dev/null; then
            if $DRY_RUN; then
                log_dry "sed -i 's|${OLD_LOG_DIR}|${NEW_LOG_DIR}|g' ${jail_file}"
            else
                sed -i "s|${OLD_LOG_DIR}|${NEW_LOG_DIR}|g" "$jail_file"
                log "  Updated: ${jail_file}"
            fi
            JAILS_UPDATED=$((JAILS_UPDATED + 1))
        fi
    done

    if [ "$JAILS_UPDATED" -eq 0 ]; then
        log "  No jail files reference ${OLD_LOG_DIR} — nothing to update."
    fi

    # Reload fail2ban only when we actually changed something and not in dry-run.
    if [ "$JAILS_UPDATED" -gt 0 ] && ! $DRY_RUN; then
        # || true: fail2ban may not be running — do not abort the migration.
        systemctl reload fail2ban 2>/dev/null || true
        log "  fail2ban reloaded."
    fi
fi

# ── Step 6: Verify new service is up ──────────────────────────────────────────────────

log "Step 6: Verifying ${NEW_SERVICE} metrics..."

if $DRY_RUN; then
    log_dry "curl -s ${METRICS_URL} | grep arx_sentinel_"
else
    # Give systemd a moment to bring the service fully up before querying metrics.
    sleep 2

    if ! command -v curl >/dev/null 2>&1; then
        log "  curl not installed — skipping metrics verification."
    else
        METRICS_OUTPUT=""
        if METRICS_OUTPUT="$(curl -sf --max-time 5 "$METRICS_URL" 2>/dev/null)"; then
            METRIC_COUNT="$(echo "$METRICS_OUTPUT" | grep -c '^arx_sentinel_' || true)"
            log "  arx_sentinel_* metrics found: ${METRIC_COUNT}"
            if [ "$METRIC_COUNT" -gt 0 ]; then
                log "  Verification passed."
            else
                log "  [WARN] No arx_sentinel_* metrics returned — check service logs."
            fi
        else
            log "  [WARN] Could not reach ${METRICS_URL} — service may still be starting."
            log "         Check manually: curl ${METRICS_URL} | grep arx_sentinel_"
        fi
    fi
fi

# ── Done ─────────────────────────────────────────────────────────────────────────────

echo ""
if $DRY_RUN; then
    log "Dry run complete. Re-run without --dry-run to apply."
else
    log "Migration complete."
    log "Old config backed up at: ${OLD_CONFIG_DIR}/config.yaml.backup"
    log "New config is at:        ${NEW_CONFIG_DIR}/config.yaml"
    log "Status: systemctl status ${NEW_SERVICE}"
fi
