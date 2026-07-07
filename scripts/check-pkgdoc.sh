#!/usr/bin/env bash
# check-pkgdoc.sh — verifies every Go package touched by the staged changes
# has a package-doc comment that `go doc` will actually surface.
#
# WHY THIS EXISTS (bug found in arx-core, fixed here 2026-07-07):
#   Go's doc extraction only recognizes a comment as the package doc when it
#   sits DIRECTLY above the `package X` clause — zero blank lines in
#   between. A repo-wide sweep found the same one-blank-line gap across 90
#   files in this repo, which silently dropped the comment from `go doc
#   ./<pkg>` output. `go build`/`go vet`/gofmt do not catch this — the code
#   is perfectly valid Go, just undocumented from a tooling standpoint.
#   This check closes that gap so the mistake cannot silently reappear in
#   a new package.
#
# SCOPE: only packages with at least one staged, non-test .go file are
# checked — same "only when touched" pattern as check-build-profiles.sh /
# check-config-sync.sh in this repo. A full-repo sweep is deliberately NOT
# run here on every commit: some small internal packages may not need a
# doc comment, and retrofitting every existing package is a separate,
# one-time cleanup, not a per-commit gate.
#
# WHAT "found" MEANS: at least one non-test .go file in the package
# directory has a `//`-comment on the line immediately preceding
# `package <name>` (no blank line separating them). This mirrors exactly
# what go/doc requires — see https://pkg.go.dev/go/doc for the rule.

set -euo pipefail

fail=0
declare -a checked_dirs=()

is_checked() {
  local needle="$1"
  local d
  for d in "${checked_dirs[@]:-}"; do
    [[ "$d" == "$needle" ]] && return 0
  done
  return 1
}

while IFS= read -r file; do
  [[ "$file" == *.go ]] || continue
  [[ "$file" == *_test.go ]] && continue
  [[ -f "$file" ]] || continue # skip deleted files (diff-filter already excludes D, but be defensive)

  dir=$(dirname "$file")
  is_checked "$dir" && continue
  checked_dirs+=("$dir")

  found_doc=0
  for f in "$dir"/*.go; do
    [[ -f "$f" ]] || continue
    [[ "$f" == *_test.go ]] && continue

    match=$(grep -n -m1 '^package ' "$f" || true)
    [[ -z "$match" ]] && continue
    pkgline="${match%%:*}"
    prevline=$((pkgline - 1))
    [[ "$prevline" -lt 1 ]] && continue

    prevcontent=$(sed -n "${prevline}p" "$f")
    if [[ "$prevcontent" == //* ]]; then
      found_doc=1
      break
    fi
  done

  if [[ "$found_doc" -eq 0 ]]; then
    echo "[check-pkgdoc] WARNING: $dir has no file with a comment directly above 'package' — 'go doc ./$dir' will show nothing useful. See scripts/check-pkgdoc.sh header for the exact rule (no blank line before the package clause)."
    fail=1
  fi
done < <(git diff --cached --name-only --diff-filter=ACMR)

if [[ "$fail" -ne 0 ]]; then
  echo "[check-pkgdoc] one or more touched packages lack a go-doc-visible package comment"
  exit 1
fi

echo "[check-pkgdoc] OK"
