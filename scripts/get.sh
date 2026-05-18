#!/usr/bin/env bash
# get.sh — universal ArxSentinel installer.
# Detects OS and architecture, downloads the correct package from GitHub
# Releases, installs it, and starts the service.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/mr-addams/arxsentinel/main/scripts/get.sh | sudo bash
#   sudo bash get.sh
set -euo pipefail

# ── Colour palette ────────────────────────────────────────────────────────────
if [ -t 1 ] && [ "${NO_COLOR:-}" = "" ]; then
  R='\033[0;31m'   # red
  G='\033[0;32m'   # green
  Y='\033[1;33m'   # yellow
  B='\033[0;34m'   # blue
  C='\033[0;36m'   # cyan
  M='\033[0;35m'   # magenta
  W='\033[1;37m'   # bold white
  DIM='\033[2m'
  RESET='\033[0m'
else
  R='' G='' Y='' B='' C='' M='' W='' DIM='' RESET=''
fi

REPO="mr-addams/arxsentinel"
API="https://api.github.com/repos/${REPO}/releases/latest"

# ── Helpers ───────────────────────────────────────────────────────────────────

banner() {
  echo
  echo -e "${C}┌─────────────────────────────────────────────┐${RESET}"
  echo -e "${C}│${W}           ArxSentinel  installer             ${C}│${RESET}"
  echo -e "${C}│${DIM}    Universal HTTP threat detection daemon    ${C}│${RESET}"
  echo -e "${C}└─────────────────────────────────────────────┘${RESET}"
  echo
}

step() { echo -e "  ${B}→${RESET}  $*"; }
ok()   { echo -e "  ${G}✓${RESET}  $*"; }
warn() { echo -e "  ${Y}!${RESET}  $*"; }
fail() { echo -e "\n  ${R}✗${RESET}  ${W}$*${RESET}\n" >&2; exit 1; }

section() {
  echo
  echo -e "${W}$*${RESET}"
  echo -e "${DIM}$(printf '─%.0s' $(seq 1 50))${RESET}"
}

spinner() {
  local pid=$1 msg=$2
  local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
  local i=0
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r  ${C}%s${RESET}  %s " "${frames[$((i % 10))]}" "$msg"
    i=$((i + 1))
    sleep 0.1
  done
  printf "\r%-60s\r" " "   # clear spinner line
}

need_cmd() { command -v "$1" &>/dev/null || fail "Required command not found: $1"; }

# ── Root check ────────────────────────────────────────────────────────────────

check_root() {
  section "Checking permissions"
  if [ "$EUID" -ne 0 ]; then
    fail "This installer must be run as root (use: sudo bash get.sh)"
  fi
  ok "Running as root"
}

# ── OS detection ──────────────────────────────────────────────────────────────

detect_os() {
  section "Detecting operating system"

  [ -f /etc/os-release ] || fail "Cannot detect OS: /etc/os-release not found"
  # shellcheck source=/dev/null
  . /etc/os-release

  OS_ID="${ID:-unknown}"
  OS_LIKE="${ID_LIKE:-}"
  OS_NAME="${PRETTY_NAME:-$OS_ID}"

  case "$OS_ID $OS_LIKE" in
    *ubuntu*|*debian*|*linuxmint*|*raspbian*|*pop*)
      PKG_MGR="apt"; EXT="deb"
      ;;
    *fedora*|*rhel*|*centos*|*rocky*|*alma*|*ol*|*amzn*)
      PKG_MGR="dnf"; EXT="rpm"
      # Fallback to yum on older RHEL/CentOS 7
      command -v dnf &>/dev/null || PKG_MGR="yum"
      ;;
    *arch*|*manjaro*|*artix*|*endeavouros*)
      PKG_MGR="pacman"; EXT="pkg.tar.zst"
      ;;
    *)
      fail "Unsupported OS: ${OS_NAME}. Supported: Debian/Ubuntu, Fedora/RHEL, Arch Linux."
      ;;
  esac

  ok "OS: ${W}${OS_NAME}${RESET}"
  ok "Package manager: ${W}${PKG_MGR}${RESET}"
}

# ── Architecture detection ────────────────────────────────────────────────────

detect_arch() {
  section "Detecting architecture"

  RAW_ARCH=$(uname -m)
  case "$RAW_ARCH" in
    x86_64)          ARCH="amd64" ;;
    aarch64|arm64)   ARCH="arm64" ;;
    *)               fail "Unsupported architecture: ${RAW_ARCH}. Supported: x86_64, aarch64." ;;
  esac

  ok "Architecture: ${W}${ARCH}${RESET} (${DIM}${RAW_ARCH}${RESET})"
}

# ── Fetch latest release ──────────────────────────────────────────────────────

fetch_release() {
  section "Fetching latest release"

  need_cmd curl
  need_cmd grep
  need_cmd cut

  step "Querying GitHub API..."
  RELEASE_JSON=$(curl -fsSL "$API" 2>/dev/null) \
    || fail "Failed to reach GitHub API. Check your internet connection."

  VERSION=$(echo "$RELEASE_JSON" | grep '"tag_name"' | cut -d'"' -f4)
  [ -n "$VERSION" ] || fail "Could not determine latest release version."

  # Find the download URL matching our arch and package format
  DOWNLOAD_URL=$(echo "$RELEASE_JSON" \
    | grep browser_download_url \
    | grep "${ARCH}\.${EXT}" \
    | cut -d'"' -f4 \
    | head -1)

  [ -n "$DOWNLOAD_URL" ] \
    || fail "No ${EXT} package found for ${ARCH} in release ${VERSION}."

  FILENAME=$(basename "$DOWNLOAD_URL")

  ok "Latest version: ${W}${VERSION}${RESET}"
  ok "Package: ${W}${FILENAME}${RESET}"
}

# ── Download ──────────────────────────────────────────────────────────────────

download_package() {
  section "Downloading package"

  TMPDIR=$(mktemp -d)
  # shellcheck disable=SC2064
  trap "rm -rf '${TMPDIR}'" EXIT

  DEST="${TMPDIR}/${FILENAME}"

  step "Downloading from: ${DIM}${DOWNLOAD_URL}${RESET}"

  curl -fsSL --progress-bar -o "$DEST" "$DOWNLOAD_URL" \
    || fail "Download failed."

  ok "Saved to: ${DIM}${DEST}${RESET}"
}

# ── Install dependencies ──────────────────────────────────────────────────────

install_deps() {
  section "Checking dependencies"

  case "$PKG_MGR" in
    apt)
      if ! dpkg -s fail2ban &>/dev/null 2>&1; then
        step "Installing fail2ban via apt..."
        (apt-get update -qq && apt-get install -y -q fail2ban) &
        spinner $! "Installing fail2ban"
        ok "fail2ban installed"
      else
        ok "fail2ban already installed"
      fi
      ;;
    dnf|yum)
      if ! rpm -q fail2ban &>/dev/null 2>&1; then
        step "Installing fail2ban via ${PKG_MGR}..."
        ("$PKG_MGR" install -y -q fail2ban) &
        spinner $! "Installing fail2ban"
        ok "fail2ban installed"
      else
        ok "fail2ban already installed"
      fi
      ;;
    pacman)
      if ! pacman -Qi fail2ban &>/dev/null 2>&1; then
        step "Installing fail2ban via pacman..."
        (pacman -S --noconfirm --quiet fail2ban) &
        spinner $! "Installing fail2ban"
        ok "fail2ban installed"
      else
        ok "fail2ban already installed"
      fi
      ;;
  esac
}

# ── Install package ───────────────────────────────────────────────────────────

install_package() {
  section "Installing ArxSentinel ${VERSION}"

  case "$PKG_MGR" in
    apt)
      step "Running apt install..."
      (apt-get install -y -q "$DEST") &
      spinner $! "Installing package"
      ;;
    dnf|yum)
      step "Running ${PKG_MGR} install..."
      ("$PKG_MGR" install -y -q "$DEST") &
      spinner $! "Installing package"
      ;;
    pacman)
      step "Running pacman -U..."
      (pacman -U --noconfirm "$DEST") &
      spinner $! "Installing package"
      ;;
  esac

  ok "ArxSentinel ${VERSION} installed"
}

# ── Post-install config ───────────────────────────────────────────────────────

configure() {
  section "Configuration"

  CFG="/etc/arxsentinel/config.yaml"

  # Try to detect nginx access.log path automatically
  NGINX_LOG=""
  for candidate in \
      /var/log/nginx/access.log \
      /var/log/nginx/combined.log \
      /usr/local/nginx/logs/access.log; do
    if [ -f "$candidate" ]; then
      NGINX_LOG="$candidate"
      break
    fi
  done

  if [ -n "$NGINX_LOG" ]; then
    # Patch log_file in the config if it still points to the default
    if grep -q "log_file:" "$CFG" 2>/dev/null; then
      sed -i "s|log_file:.*|log_file: ${NGINX_LOG}|" "$CFG"
      ok "log_file auto-configured: ${W}${NGINX_LOG}${RESET}"
    fi
  else
    warn "nginx access.log not found at standard paths."
    warn "Edit ${W}${CFG}${RESET} and set ${W}general.log_file${RESET} manually."
  fi
}

# ── Start service ─────────────────────────────────────────────────────────────

start_service() {
  section "Starting service"

  if ! command -v systemctl &>/dev/null; then
    warn "systemd not found — start the service manually."
    return
  fi

  systemctl daemon-reload
  systemctl enable arxsentinel
  systemctl restart arxsentinel

  sleep 1

  if systemctl is-active --quiet arxsentinel; then
    ok "${G}ArxSentinel is running${RESET}"
  else
    warn "Service did not start. Check: ${W}journalctl -u arxsentinel -n 30${RESET}"
  fi
}

# ── Summary ───────────────────────────────────────────────────────────────────

summary() {
  echo
  echo -e "${G}┌─────────────────────────────────────────────┐${RESET}"
  echo -e "${G}│${W}          Installation complete!              ${G}│${RESET}"
  echo -e "${G}└─────────────────────────────────────────────┘${RESET}"
  echo
  echo -e "  ${W}Version   ${RESET}${VERSION}"
  echo -e "  ${W}Config    ${RESET}/etc/arxsentinel/config.yaml"
  echo -e "  ${W}Logs      ${RESET}/var/log/arxsentinel/sentinel.log"
  echo -e "  ${W}Threats   ${RESET}/var/log/arxsentinel/threats.log"
  echo
  echo -e "  ${DIM}Next steps:${RESET}"
  echo -e "  ${B}→${RESET}  Review config:   ${C}sudo nano /etc/arxsentinel/config.yaml${RESET}"
  echo -e "  ${B}→${RESET}  Watch live logs: ${C}sudo journalctl -u arxsentinel -f${RESET}"
  echo -e "  ${B}→${RESET}  Reload config:   ${C}sudo systemctl kill -s HUP arxsentinel${RESET}"
  echo -e "  ${B}→${RESET}  Docs:            ${C}https://mr-addams.github.io/arxsentinel/${RESET}"
  echo
}

# ── Main ──────────────────────────────────────────────────────────────────────

main() {
  banner
  check_root
  detect_os
  detect_arch
  fetch_release
  download_package
  install_deps
  install_package
  configure
  start_service
  summary
}

main "$@"
