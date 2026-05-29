#!/usr/bin/env bash
# ========================== check-config-sync.sh =====================================
#
#   Config consistency checker.
#   Ensures that every change to the config chain is propagated everywhere.
#
#   THE CONFIG CHAIN (all must stay in sync):
#     1. internal/sys/config/config.go  — Go structs + applyEnvOverrides()  ← source of truth
#     2. config.yaml                    — packaged as /etc/arxsentinel/config.yaml.example
#     3. deploy/container/docker/config.docker.yaml  — full Docker config
#     4. deploy/container/docker/.env.example        — env var reference for operators
#     5. deploy/container/docker/README.md           — env var table (Docker docs)
#     6. deploy/container/k8s/arxsentinel/README.md  — env var table (K8s docs)
#
#   WHAT IS CHECKED:
#     A. Env vars: every "ARXSENTINEL_*" passed to envXxx() in applyEnvOverrides()
#        must appear in files 4, 5, 6.
#     B. Sections: every top-level section in config.yaml (except intentionally
#        advanced/migration-only ones) must appear in config.docker.yaml (file 3).
#     C. Default values: TestEnvExampleDefaults verifies that documented defaults in
#        .env.example match actual Go defaults from defaultConfig() + applyEnvOverrides().
#
#   WHAT IS NOT CHECKED (intentionally YAML-only, env vars make no sense):
#     streams, inputs, outputs, executors — multi-pipeline / exec plugin syntax;
#     these are complex nested structures that cannot be expressed as env vars.
#     Detector arrays (probe.paths, overflow.suspicious_params, extra_*_patterns)
#     are also YAML-only — no env var equivalents exist.
#   Reference: full examples with all YAML-only sections are in config.example.yaml.
#   Run manually:  bash scripts/check-config-sync.sh
#   Pre-commit:    called automatically by scripts/hooks/pre-commit
#
#   Exit: 0 = consistent, 1 = gaps found (commit is blocked)
#
# ======================================================================================
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

FAIL=0

# ── Colour palette (suppressed when not a terminal or NO_COLOR is set) ─────────
if [ -t 1 ] && [ "${NO_COLOR:-}" = "" ]; then
  R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' W='\033[1;37m' DIM='\033[2m' RESET='\033[0m'
else
  R='' G='' Y='' W='' DIM='' RESET=''
fi

ok()   { echo -e "  ${G}✓${RESET}  $*"; }
fail() { echo -e "  ${R}✗${RESET}  $*"; FAIL=1; }
skip() { echo -e "  ${DIM}–${RESET}  $*"; }
info() { echo -e "\n${W}$*${RESET}"; echo -e "${DIM}$(printf '─%.0s' $(seq 1 60))${RESET}"; }

echo
echo -e "${W}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${W}║         Config chain consistency check           ║${RESET}"
echo -e "${W}╚══════════════════════════════════════════════════╝${RESET}"

CONFIG_GO="internal/sys/config/config.go"
ENV_EXAMPLE="deploy/container/docker/.env.example"
DOCKER_README="deploy/container/docker/README.md"
K8S_README="deploy/container/k8s/arxsentinel/README.md"
DOCKER_CONFIG="deploy/container/docker/config.docker.yaml"
MAIN_CONFIG="config.yaml"

# Sanity: all reference files must exist.
for f in "$CONFIG_GO" "$ENV_EXAMPLE" "$DOCKER_README" "$K8S_README" "$DOCKER_CONFIG" "$MAIN_CONFIG"; do
  [ -f "$f" ] || { echo -e "${R}ERROR: required file not found: $f${RESET}"; exit 1; }
done

# ── A. Env var coverage ────────────────────────────────────────────────────────
#
# Extract every "ARXSENTINEL_..." string literal that appears as the first argument
# to an env* helper call in applyEnvOverrides().
# Grep for double-quoted ARXSENTINEL_ strings in the config file — these are
# exclusively the env var names passed to envBool/envStr/envInt/envDur/etc.
# Comments also use this pattern (ENV: ARXSENTINEL_...) — both are intentional:
# they document the contract and the implementation in one place.

info "A. Env vars: applyEnvOverrides() → .env.example + README tables"

DECLARED_VARS=$(grep -oE '"ARXSENTINEL_[A-Z_]+"' "$CONFIG_GO" | tr -d '"' | sort -u)
VAR_COUNT=0
VAR_MISSING=0

while IFS= read -r var; do
  VAR_COUNT=$((VAR_COUNT + 1))
  missing=()
  grep -qF "$var" "$ENV_EXAMPLE"    || missing+=(".env.example")
  grep -qF "$var" "$DOCKER_README"  || missing+=("docker/README.md")
  grep -qF "$var" "$K8S_README"     || missing+=("k8s/README.md")

  if [ ${#missing[@]} -gt 0 ]; then
    fail "$var  →  missing from: ${missing[*]}"
    VAR_MISSING=$((VAR_MISSING + 1))
  else
    ok "$var"
  fi
done <<< "$DECLARED_VARS"

echo
if [ $VAR_MISSING -eq 0 ]; then
  echo -e "  ${G}$VAR_COUNT vars — all covered${RESET}"
else
  echo -e "  ${R}$VAR_MISSING of $VAR_COUNT vars not fully documented${RESET}"
fi

# ── B. config.yaml sections → config.docker.yaml ──────────────────────────────
#
# Every top-level section in config.yaml must also appear in config.docker.yaml.
# Exceptions: intentionally advanced / migration-only sections that have no
# place in a single-stream Docker deployment and are documented separately.

info "B. config.yaml sections → config.docker.yaml"

# Sections intentionally absent from config.docker.yaml (one per line for clarity):
#   streams   — multi-stream mode; advanced, not needed for standard Docker deploy
#   inputs    — universal I/O migration syntax; handled by general.log_file in Docker
#   outputs   — same; handled by output.threat_log
#   executors — exec plugin / action executor; optional advanced feature
SKIP_SECTIONS="streams inputs outputs executors"

SEC_COUNT=0
SEC_MISSING=0

while IFS= read -r section; do
  SEC_COUNT=$((SEC_COUNT + 1))

  if echo "$SKIP_SECTIONS" | grep -qw "$section"; then
    skip "$section  (intentionally advanced — YAML-only, skip)"
    continue
  fi

  if grep -qE "^${section}:" "$DOCKER_CONFIG"; then
    ok "$section"
  else
    fail "$section  →  missing from $DOCKER_CONFIG"
    SEC_MISSING=$((SEC_MISSING + 1))
  fi
done < <(grep -E '^[a-z_]+:' "$MAIN_CONFIG" | cut -d: -f1)

echo
if [ $SEC_MISSING -eq 0 ]; then
  echo -e "  ${G}$SEC_COUNT sections checked — all covered${RESET}"
else
  echo -e "  ${R}$SEC_MISSING of $SEC_COUNT sections missing from config.docker.yaml${RESET}"
fi

# ── C. Default values in .env.example match Go defaults ──────────────────────────────
#
# Runs TestEnvExampleDefaults — verifies that every documented default value in
# .env.example matches the actual Go default from defaultConfig() + applyEnvOverrides().
# If a default changes in config.go without updating .env.example, this test fails.

info "C. .env.example default values → Go defaults (TestEnvExampleDefaults)"

if go test ./internal/sys/config -run TestEnvExampleDefaults -count=1 -timeout 30s >/dev/null 2>&1; then
  ok "TestEnvExampleDefaults passed"
else
  fail "TestEnvExampleDefaults FAILED — a default value in .env.example does not match config.go"
  echo "    Run: go test ./internal/sys/config -run TestEnvExampleDefaults -v to see details"
  FAIL=1
fi

# ── Result ─────────────────────────────────────────────────────────────────────

echo
if [ $FAIL -ne 0 ]; then
  echo -e "${R}╔══════════════════════════════════════════════════╗${RESET}"
  echo -e "${R}║  Config sync check FAILED — fix gaps before      ║${RESET}"
  echo -e "${R}║  committing. See output above for details.        ║${RESET}"
  echo -e "${R}╚══════════════════════════════════════════════════╝${RESET}"
  echo
  echo -e "${Y}HOW TO FIX:${RESET}"
  echo -e "  • Missing env var in .env.example → add commented line"
  echo -e "  • Missing env var in README → add row to the env var table"
  echo -e "  • Missing section in config.docker.yaml → add with defaults"
  echo
  exit 1
fi

echo -e "${G}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${G}║          Config sync check passed ✓              ║${RESET}"
echo -e "${G}╚══════════════════════════════════════════════════╝${RESET}"
echo
