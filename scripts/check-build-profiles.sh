#!/usr/bin/env bash
# ========================== check-build-profiles.sh ====================================
#
#   Build profile consistency verifier (Flow 075, Phase 1.5; extended for
#   detectors in Flow 076, Task 6.1).
#   Three static invariants over profiles/*.yaml, cmd/arxsentinel/plugins_*.go,
#   pkg/{source,sink,executor,processor,detector}/, and cookbook/profiles/*.yaml:
#
#     (a) Declaration ↔ generated drift
#         For each profiles/<name>.yaml, plugin names (sources/sinks/executors/
#         processors/detectors) are matched against blank-imports in
#         cmd/arxsentinel/plugins_<name>.go (for `full` — plugins_full.go,
#         hand-maintained). Extra/missing → fail.
#
#   Маппинг profile-name → blank-import path: 1:1, с единственным исключением
#   `ua` → `pkg/detector/useragent` (hardcoded в verifier; регистровое имя остаётся
#   "ua").
#
#     (b) Plugin name → Register existence
#         Each declared source/sink/executor/detector name must have a matching
#         `Register("<name>"` call in pkg/<kind>/<name-or-exception>/*.go
#         (non-test). Processors are checked only for package existence
#         (registry package; Decision 15) — no Register call required.
#
#     (c) Reference config ↔ profile membership
#         For each cookbook/profiles/<name>.yaml, every `type:` field in
#         streams/inputs/outputs/executors must correspond to a plugin declared
#         in profiles/<name>.yaml. Detects cookbook drift after a profile change.
#         Detectors are not individually declared as `type:` in cookbook configs,
#         so they participate in the declared set but are not expected to appear
#         as stream/executor types.
#
# The single path exception for detectors is also hardcoded because the package
# directory is 'useragent' while the profile/registry name remains 'ua'.
#
#   Run manually:  bash scripts/check-build-profiles.sh
#   Pre-commit:    called by scripts/hooks/pre-commit when profile/plugin files
#                  are staged.
#
#   Exit: 0 = all invariants hold, 1 = at least one violation found.
#          All violations are collected and reported in a single run.
#
# ======================================================================================
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

FAIL=0
VIOLATIONS=0

# ── Colour palette (suppressed when not a terminal or NO_COLOR is set) ─────────
if [ -t 1 ] && [ "${NO_COLOR:-}" = "" ]; then
  R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' W='\033[1;37m' DIM='\033[2m' RESET='\033[0m'
else
  R='' G='' Y='' W='' DIM='' RESET=''
fi

ok()   { echo -e "  ${G}✓${RESET}  $*"; }
fail() { echo -e "  ${R}✗${RESET}  $*"; FAIL=1; VIOLATIONS=$((VIOLATIONS+1)); }
skip() { echo -e "  ${DIM}–${RESET}  $*"; }
info() { echo -e "\n${W}$*${RESET}"; echo -e "${DIM}$(printf '─%.0s' $(seq 1 60))${RESET}"; }

echo
echo -e "${W}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${W}║       Build profile consistency check            ║${RESET}"
echo -e "${W}╚══════════════════════════════════════════════════╝${RESET}"

PROFILES_DIR="profiles"
PLUGINS_DIR="cmd/arxsentinel"
PKG_ROOT="pkg"
COOKBOOK_PROFILES_DIR="cookbook/profiles"

# Sanity: required directories must exist.
for d in "$PROFILES_DIR" "$PLUGINS_DIR" "$PKG_ROOT"; do
  [ -d "$d" ] || { echo -e "${R}ERROR: required directory not found: $d${RESET}"; exit 1; }
done

# ── Helpers ────────────────────────────────────────────────────────────────────
#
# pkg_suffix_for <kind> <name>
#   Resolves the package-directory suffix for a plugin (kind, name) pair.
#   Override cases:
#     - Register name "sentinel-threat" lives in pkg/sink/sentinel
#       (Decision 15 / Decision 16, Flow 075).
#     - Detector "ua" lives in pkg/detector/useragent (Flow 076, Task 6.1);
#       the Register name stays "ua" regardless of the directory name.
#   In every exception the Register name stays verbatim in profile YAML; only the
#   derived package/import path is redirected.
pkg_suffix_for() {
  local kind="$1" name="$2"
  case "$kind/$name" in
    sinks/sentinel-threat) echo "sentinel" ;;
    detectors/ua)          echo "useragent" ;;
    *) echo "$name" ;;
  esac
}

# expected_import_path <kind> <name>
#   Returns the canonical import path (relative to repo root, as it appears in
#   blank-import lines: github.com/mr-addams/arxsentinel/pkg/...).
expected_import_path() {
  local kind="$1" name="$2"
  local suffix; suffix="$(pkg_suffix_for "$kind" "$name")"
  case "$kind" in
    sources)    echo "github.com/mr-addams/arxsentinel/pkg/source/$suffix" ;;
    sinks)      echo "github.com/mr-addams/arxsentinel/pkg/sink/$suffix" ;;
    executors)  echo "github.com/mr-addams/arxsentinel/pkg/executor/$suffix" ;;
    processors)
      if [ "$name" = "processor" ]; then
        echo "github.com/mr-addams/arxsentinel/pkg/processor"
      else
        echo "github.com/mr-addams/arxsentinel/pkg/processor/$suffix"
      fi
      ;;
    detectors) echo "github.com/mr-addams/arxsentinel/pkg/detector/$suffix" ;;
    *) echo "" ;;
  esac
}

# pkg_relative_dir <kind> <name>
#   Filesystem path under pkg/ for os.path checks (invariant b / processor check).
pkg_relative_dir() {
  local kind="$1" name="$2"
  local suffix; suffix="$(pkg_suffix_for "$kind" "$name")"
  case "$kind" in
    sources)    echo "pkg/source/$suffix" ;;
    sinks)      echo "pkg/sink/$suffix" ;;
    executors)  echo "pkg/executor/$suffix" ;;
    processors)
      if [ "$name" = "processor" ]; then
        echo "pkg/processor"
      else
        echo "pkg/processor/$suffix"
      fi
      ;;
    detectors) echo "pkg/detector/$suffix" ;;
    *) echo "" ;;
  esac
}

# Extract declared plugin names for a given kind from a profile YAML.
# Empty/absent kind yields no lines. Detectors handled like other plugin kinds since
# Flow 076 (Task 6.1).
declared_names() {
  local profile="$1" kind="$2"
  # Match `  - name: foo` lines that appear under the `<kind>:` block.
  # awk walks the file, tracks current top-level block under `plugins:`, and
  # prints `name:` values belonging to the requested kind.
  awk -v want="$kind" '
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*[a-z_]+:[[:space:]]*$/ {
      sub(/[[:space:]]*:.*$/, "", $0); gsub(/^[[:space:]]+/, "", $0)
      current = $0
      next
    }
    /^[[:space:]]*-[[:space:]]*name:[[:space:]]*/ && current == want {
      line = $0
      sub(/.*name:[[:space:]]*/, "", line)
      gsub(/[[:space:]]*#.*/, "", line)
      gsub(/["'"'"']/, "", line)
      gsub(/[[:space:]]+$/, "", line)
      if (line != "") print line
    }
  ' "$profile"
}

profiles_list() {
  ls -1 "$PROFILES_DIR"/*.yaml 2>/dev/null | sort
}

profile_name_from_path() {
  local p="$1"
  b="$(basename "$p")"
  echo "${b%.yaml}"
}

# ── (a) Declaration ↔ generated drift ──────────────────────────────────────────
#
#   For each profile, build the expected set of import paths from declarations
#   (sources/sinks/executors/processors/detectors) and compare against
#   the blank-import lines actually present in plugins_<name>.go.
#   For `full` → plugins_full.go (hand-maintained, //go:build !arx_tag).
#   For other profiles → plugins_<name>.go (generated).

info "A. Declaration ↔ generated drift"

while IFS= read -r profile_path; do
  pname="$(profile_name_from_path "$profile_path")"

  if [ "$pname" = "full" ]; then
    go_file="$PLUGINS_DIR/plugins_full.go"
  else
    go_file="$PLUGINS_DIR/plugins_${pname}.go"
  fi

  if [ ! -f "$go_file" ]; then
    fail "profile '$pname': expected file $go_file not found"
    continue
  fi

  # Build expected imports (sorted, unique) — one import path per line.
  expected_file="$(mktemp)"
  for kind in sources sinks executors processors detectors; do
    while IFS= read -r n; do
      [ -z "$n" ] && continue
      expected_import_path "$kind" "$n"
    done < <(declared_names "$profile_path" "$kind")
  done | sort -u > "$expected_file"

  # Build actual blank-imports from the .go file.
  # Pattern: lines starting with whitespace, ` _ "github.com/..."`
  actual_file="$(mktemp)"
  grep -E '^[[:space:]]*_[[:space:]]*"github\.com/mr-addams/arxsentinel/pkg/' "$go_file" \
    | sed -E 's|^[[:space:]]*_[[:space:]]*"([^"]+)".*|\1|' \
    | sort -u > "$actual_file"

  missing_file="$(mktemp)"
  extra_file="$(mktemp)"
  comm -23 "$expected_file" "$actual_file" > "$missing_file"
  comm -13 "$expected_file" "$actual_file" > "$extra_file"

  if [ -s "$missing_file" ] || [ -s "$extra_file" ]; then
    while IFS= read -r imp; do
      [ -z "$imp" ] && continue
      fail "profile '$pname': missing from $go_file — $imp"
    done < "$missing_file"
    while IFS= read -r imp; do
      [ -z "$imp" ] && continue
      fail "profile '$pname': extra in $go_file (not in declaration) — $imp"
    done < "$extra_file"
  else
    ok "profile '$pname': declaration matches $(wc -l < "$expected_file") blank-imports"
  fi

  rm -f "$expected_file" "$actual_file" "$missing_file" "$extra_file"
done < <(profiles_list)

# ── (b) Plugin name → Register existence ───────────────────────────────────────
#
# For source/sink/executor/detector entries: require a `Register("<name>"` literal
#   (regardless of the receiver — detector / pkgsink / pkgsource / executor) to
#   exist in a non-test .go file under pkg/<kind>/<name-or-exception>/. Catches
#   typos and renamed-but-not-profile-updated plugins (Decision 4 / Decision 15).
#
#   For detector entries: the only path exception is `ua` → pkg/detector/useragent;
#   the Register-name lookup still uses the literal profile name "ua".
#
#   For processor entries: only require the package directory to exist on disk
#   (registry package has no Register call by plugin name — Decision 15).

info "B. Plugin name → Register existence"

while IFS= read -r profile_path; do
  pname="$(profile_name_from_path "$profile_path")"

  for kind in sources sinks executors processors detectors; do
    while IFS= read -r n; do
      [ -z "$n" ] && continue

      pkg_dir="$(pkg_relative_dir "$kind" "$n")"
      if [ ! -d "$pkg_dir" ]; then
        fail "profile '$pname': package directory not found for $kind/$n — $pkg_dir"
        continue
      fi

      if [ "$kind" = "processors" ]; then
        # Registry package: existence is sufficient. Require at least one
        # non-test .go file declaring `package <basename>`.
        base="$(basename "$pkg_dir")"
        if ! grep -lE "^package ${base}\b" "$pkg_dir"/*.go 2>/dev/null | grep -v _test.go | grep -q .; then
          fail "profile '$pname': no non-test Go file in $pkg_dir declaring 'package $base'"
        else
          ok "profile '$pname': processor package exists — $pkg_dir"
        fi
        continue
      fi

      # source/sink/executor/detector: look for Register("<name>" in non-test .go files.
      # The receiver (detector / pkgsink / pkgsource / executor) is intentionally not
      # anchored — the universal pattern is `Register\(\s*"<name>"\s*,`.
      if grep -rnE "Register\(\s*\"${n}\"\s*," "$pkg_dir"/*.go 2>/dev/null \
           | grep -v _test.go | grep -q .; then
        ok "profile '$pname': $kind/$n registered"
      else
        fail "profile '$pname': Register(\"$n\") not found in $pkg_dir/*.go"
      fi
    done < <(declared_names "$profile_path" "$kind")
  done
done < <(profiles_list)

# ── (c) Reference config ↔ profile membership ──────────────────────────────────
#
# For each cookbook/profiles/<name>.yaml that exists, collect every `type:`
# value under streams/inputs/outputs/executors blocks and verify that value is
# a plugin declared in profiles/<name>.yaml.
#
# Mapping of config block to plugin kind:
#   streams[].inputs[].type   → source
#   streams[].outputs[].type  → sink
#   top-level inputs[].type   → source
#   top-level outputs[].type  → sink
#   executors[].type          → executor
#
# The verifier does not enforce the kind — only that `type: X` is a member of
# the union of all declared plugin names for that profile. This keeps the
# verifier schema-agnostic (cookbook configs may add sections over time).

info "C. Reference config ↔ profile membership"

while IFS= read -r profile_path; do
  pname="$(profile_name_from_path "$profile_path")"
  cookbook_cfg="$COOKBOOK_PROFILES_DIR/${pname}.yaml"

  if [ ! -f "$cookbook_cfg" ]; then
    skip "profile '$pname': no cookbook/profiles/${pname}.yaml — invariant (c) not applicable"
    continue
  fi

  # Build union of all declared plugin names (Register names) for this profile.
  declared_set_file="$(mktemp)"
  for kind in sources sinks executors processors detectors; do
    declared_names "$profile_path" "$kind"
  done | sort -u > "$declared_set_file"

  # Build union of declared import-path tails (e.g. "sentinel" for source/sentinel
  # AND sink/sentinel), so cookbook `type:` can also match by directory name when
  # Register name differs (e.g. sink/sentinel → Register "sentinel-threat").
  # For invariant (c) the contract is Register name (Decision 15 / Decision 6),
  # but we additionally accept the package tail to avoid false positives for
  # cases like `type: sentinel-threat` (Register name) vs `type: sentinel`
  # (directory name). The canonical contract is the Register name.
  declared_tails_file="$(mktemp)"
  for kind in sources sinks executors processors detectors; do
    while IFS= read -r n; do
      [ -z "$n" ] && continue
      pkg_dir="$(pkg_relative_dir "$kind" "$n")"
      basename "$pkg_dir"
    done < <(declared_names "$profile_path" "$kind")
  done | sort -u > "$declared_tails_file"

  # Extract every `type:` value from the cookbook config. Strip comments and
  # quotes. Exclude lines under `detectors:` (those are detector section types,
  # not plugin types — out of profile scope).
  cfg_types_file="$(mktemp)"
  awk '
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*[a-z_]+:[[:space:]]*$/ {
      sub(/[[:space:]]*:.*$/, "", $0); gsub(/^[[:space:]]+/, "", $0)
      block = $0
      next
    }
    /^[[:space:]]*-[[:space:]]*type:[[:space:]]*/ || /^[[:space:]]+type:[[:space:]]*/ {
      if (block == "detectors") next
      line = $0
      sub(/.*type:[[:space:]]*/, "", line)
      gsub(/[[:space:]]*#.*/, "", line)
      gsub(/["'"'"']/, "", line)
      gsub(/[[:space:]]+$/, "", line)
      if (line != "") print line
    }
  ' "$cookbook_cfg" | sort -u > "$cfg_types_file"

  # Compare. A cookbook type is valid if it matches either a declared Register
  # name OR a declared package tail.
  bad_file="$(mktemp)"
  while IFS= read -r t; do
    [ -z "$t" ] && continue
    if ! grep -qxF "$t" "$declared_set_file" && ! grep -qxF "$t" "$declared_tails_file"; then
      echo "$t" >> "$bad_file"
    fi
  done < "$cfg_types_file"

  if [ -s "$bad_file" ]; then
    while IFS= read -r t; do
      [ -z "$t" ] && continue
      fail "profile '$pname': cookbook type '$t' not declared in $profile_path"
    done < "$bad_file"
  else
    ok "profile '$pname': cookbook types match declaration ($(wc -l < "$cfg_types_file") type(s))"
  fi

  rm -f "$declared_set_file" "$declared_tails_file" "$cfg_types_file" "$bad_file"
done < <(profiles_list)

# ── Summary ────────────────────────────────────────────────────────────────────
echo
if [ "$FAIL" = 0 ]; then
  echo -e "${G}All build-profile invariants hold.${RESET}"
else
  echo -e "${R}Build-profile check failed: $VIOLATIONS violation(s) found.${RESET}"
fi
exit "$FAIL"