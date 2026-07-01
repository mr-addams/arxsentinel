#!/bin/sh
#
# ArxSentinel — FreeBSD installer.
#
# Purpose: install the arxsentinel binary + rc.d script + cookbook snapshot
# extracted from a Flow 090 freebsd-archive tarball, with correct FreeBSD
# filesystem paths and a dedicated arxsentinel system user.
#
# FreeBSD path conventions in use (DECISIONS.md Decision 4):
#   - /usr/local/bin/arxsentinel             — daemon binary
#   - /usr/local/etc/rc.d/arxsentinel        — rc.d start script
#   - /usr/local/etc/arxsentinel/            — config dir (NOT /etc)
#   - /var/db/arxsentinel/                   — state dir (used as $HOME)
#   - /var/log/arxsentinel/                  — log dir
#   - /var/run/arxsentinel/                  — pidfile dir (created at start_pre)
#
# This script is intentionally POSIX /bin/sh (NOT bash). FreeBSD /bin/sh is
# ash-like and does not support `[[ ]]`, arrays, `local`, `echo -e`, etc.
# Re-validated by `sh -n` and `dash -n` in the Flow 090 local snapshot gate.
# Reference: DECISIONS.md Decision 4 + Q1 (Revised note on Decision 4).

set -eu

# ── Constants — paths and identifiers used throughout ──────────────────────────
SENTINEL_USER="arxsentinel"
SENTINEL_GROUP="arxsentinel"
SENTINEL_COMMENT="arxsentinel daemon"
SENTINEL_SHELL="/usr/sbin/nologin"
SENTINEL_HOME="/var/db/arxsentinel"

LOG_DIR="/var/log/arxsentinel"
CFG_DIR="/usr/local/etc/arxsentinel"
RC_DIR="/usr/local/etc/rc.d"
BIN_DIR="/usr/local/bin"
BIN_PATH="${BIN_DIR}/arxsentinel"
RC_PATH="${RC_DIR}/arxsentinel"
CFG_EXAMPLE="${CFG_DIR}/config.yaml.example"
CFG_REFERENCE="${CFG_DIR}/config.reference.yaml"
CFG_FILE="${CFG_DIR}/config.yaml"

# Sources live in the current working directory (the archive root the user
# extracted). Relative paths make the script portable across invocation
# styles: `sh install.sh`, `./install.sh`, `cd arxsentinel-* && sh install.sh`.
# The goreleaser archives: block flattens the cookbook tree one level — only
# the nginx-basic example is bundled at cookbook/nginx-basic.yaml (not the
# full cookbook/ tree), and config.reference.yaml is at the archive root.
SRC_BIN="./arxsentinel"
SRC_RC="./arxsentinel.rc"
SRC_COOKBOOK_EXAMPLE="./cookbook/nginx-basic.yaml"
SRC_COOKBOOK_REFERENCE="./config.reference.yaml"

# ── Pre-flight: must run as root ──────────────────────────────────────────────
# POSIX: `[` is the only portable test command (no `[[`).
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: install.sh must be run as root (e.g. 'sudo sh install.sh')." >&2
    exit 1
fi

# ── Pre-flight: required source files must be present ─────────────────────────
# Hard fail early if the archive is incomplete — clearer than failing mid-step.
for f in "${SRC_BIN}" "${SRC_RC}" "${SRC_COOKBOOK_EXAMPLE}" "${SRC_COOKBOOK_REFERENCE}"; do
    if [ ! -f "${f}" ]; then
        echo "ERROR: required source file missing in current directory: ${f}" >&2
        echo "       Run install.sh from the root of the extracted archive." >&2
        exit 1
    fi
done

# ── Header ────────────────────────────────────────────────────────────────────
echo ""
echo "================================================================="
echo "  ArxSentinel — FreeBSD installer"
echo "================================================================="
echo ""

# ── Step 1: create the system group + user (idempotent) ───────────────────────
# `pw groupadd` / `pw useradd` return non-zero if the entry already exists.
# Guard with `|| true` so re-running install.sh does not abort on `set -e`.
echo "[1/9] Creating system group + user '${SENTINEL_USER}'..."
if ! pw groupshow "${SENTINEL_GROUP}" >/dev/null 2>&1; then
    pw groupadd "${SENTINEL_GROUP}" || true
fi
if ! pw usershow "${SENTINEL_USER}" >/dev/null 2>&1; then
    # -M creates $HOME (-d path) — FreeBSD idiom for system user.
    pw useradd "${SENTINEL_USER}" \
        -g "${SENTINEL_GROUP}" \
        -c "${SENTINEL_COMMENT}" \
        -s "${SENTINEL_SHELL}" \
        -d "${SENTINEL_HOME}" \
        -M
fi

# ── Step 2: log directory ─────────────────────────────────────────────────────
# The daemon writes to LOG_DIR; restrict to user:group, mode 750 (rwx for
# owner, rx for group, none for others).
echo "[2/9] Preparing log directory ${LOG_DIR}..."
mkdir -p "${LOG_DIR}"
chown "${SENTINEL_USER}:${SENTINEL_GROUP}" "${LOG_DIR}"
chmod 750 "${LOG_DIR}"

# ── Step 3: config directory ──────────────────────────────────────────────────
echo "[3/9] Preparing config directory ${CFG_DIR}..."
mkdir -p "${CFG_DIR}"

# ── Step 4: install binary ────────────────────────────────────────────────────
# Mode 0555 = read+execute for everyone, no write. The daemon does not
# self-write its own binary, and a non-writable binary is a defence-in-depth
# measure against post-install tampering.
echo "[4/9] Installing binary to ${BIN_PATH}..."
install -m 0555 -o root -g "${SENTINEL_GROUP}" "${SRC_BIN}" "${BIN_PATH}"

# ── Step 5: install rc.d script ───────────────────────────────────────────────
# Mode 0555 same as binary — read+execute for everyone.
# /usr/local/etc/rc.d is the FreeBSD convention for third-party rc.d scripts
# (system-shipped ones live in /etc/rc.d).
echo "[5/9] Installing rc.d script to ${RC_PATH}..."
install -m 0555 -o root -g wheel "${SRC_RC}" "${RC_PATH}"

# ── Step 6: copy quick-start cookbook to config.yaml.example ──────────────────
# This is the FreeBSD path analogue of /etc/arxsentinel/config.yaml.example on
# Linux. `install` preserves the source mtime; use `cp -p` for clarity here
# because we are copying a config file, not an executable.
echo "[6/9] Copying example config to ${CFG_EXAMPLE}..."
cp -p "${SRC_COOKBOOK_EXAMPLE}" "${CFG_EXAMPLE}"
chown root:${SENTINEL_GROUP} "${CFG_EXAMPLE}"
chmod 640 "${CFG_EXAMPLE}"

# ── Step 7: copy full reference config ───────────────────────────────────────
echo "[7/9] Copying reference config to ${CFG_REFERENCE}..."
cp -p "${SRC_COOKBOOK_REFERENCE}" "${CFG_REFERENCE}"
chown root:${SENTINEL_GROUP} "${CFG_REFERENCE}"
chmod 640 "${CFG_REFERENCE}"

# ── Step 8: seed config.yaml on first install (do not clobber existing) ───────
# The user's local config.yaml must NEVER be overwritten by re-running the
# installer — that would destroy their tuning. Guard with `if [ ! -f ... ]`.
echo "[8/9] Seeding ${CFG_FILE} from example (if absent)..."
if [ ! -f "${CFG_FILE}" ]; then
    cp -p "${CFG_EXAMPLE}" "${CFG_FILE}"
    chown root:${SENTINEL_GROUP} "${CFG_FILE}"
    chmod 640 "${CFG_FILE}"
    echo "      Created ${CFG_FILE} from example."
else
    echo "      ${CFG_FILE} already exists — left untouched."
fi

# ── Step 9: final instructions ────────────────────────────────────────────────
# We deliberately do NOT call `service arxsentinel start` here — starting
# before the user has reviewed config.yaml is reckless (the daemon could
# hit real WAF/CF backends on first launch). We only print the instructions.
echo ""
echo "[9/9] Installation complete."
echo ""
echo "================================================================="
echo "  Next steps"
echo "================================================================="
echo ""
echo "  1. Review and edit the config if needed:"
echo "       ${CFG_FILE}"
echo ""
echo "  2. Enable the service (persists across reboots via /etc/rc.conf):"
echo "       sysrc arxsentinel_enable=YES"
echo ""
echo "  3. Start the service:"
echo "       service arxsentinel start"
echo ""
echo "  Cookbook: the archive's 'cookbook/' directory contains ready-to-use"
echo "  recipes (currently: the fail2ban/nginx-basic example). Copy any"
echo "  recipe manually to ${CFG_DIR}/ if you want a non-default setup."
echo ""
echo "  Uninstall (manual):"
echo "       service arxsentinel stop"
echo "       sysrc arxsentinel_enable=NO"
echo "       rm ${BIN_PATH} ${RC_PATH}"
echo "       rm -rf ${CFG_DIR} ${LOG_DIR}"
echo "       pw userdel ${SENTINEL_USER}"
echo ""
