#!/usr/bin/env bash
# install-hooks.sh — install the arxsentinel git hooks (pre-commit + pre-push) into
# .git/hooks/ of the current repo via relative symlinks.
#
# Usage:
#   bash scripts/install-hooks.sh
#
# Idempotent: re-running recreates the symlinks via 'ln -sf', so it is safe to call
# after pulling changes that touched scripts/hooks/*. The script exits non-zero if
# .git/ is missing (not a git repository) or if the hook sources are absent.

set -euo pipefail

# Resolve the repo root via git so the script is callable from any cwd.
REPO_ROOT="$(git rev-parse --show-toplevel)"

# Target directory: the per-clone .git/hooks managed by git itself.
HOOKS_DIR="$REPO_ROOT/.git/hooks"

# Helper: (re)create a relative symlink .git/hooks/<name> → ../../scripts/hooks/<name>.
# Relative links survive 'git mv' of the clone and don't embed a host-specific path.
install_hook() {
  local name="$1"
  local target="../../scripts/hooks/$name"
  local link="$HOOKS_DIR/$name"

  # Ensure the .git/hooks directory exists (git creates it, but be defensive in a
  # fresh clone or a worktree where the directory may be absent).
  mkdir -p "$HOOKS_DIR"

  # 'ln -sf' overwrites an existing link (or file), making the script idempotent.
  ln -sfn "$target" "$link"
  chmod +x "$link"

  echo "[install-hooks] linked $link -> $target"
}

# Source files must exist; fail loudly instead of producing a dangling symlink.
for hook in pre-commit pre-push; do
  src="$REPO_ROOT/scripts/hooks/$hook"
  if [[ ! -f "$src" ]]; then
    echo "[install-hooks] ERROR: missing hook source: $src" >&2
    exit 1
  fi
done

install_hook pre-commit
install_hook pre-push

echo "[install-hooks] OK (pre-commit + pre-push installed)"
