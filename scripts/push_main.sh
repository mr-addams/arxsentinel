#!/usr/bin/env bash
# Publishes a stable release by creating and merging a PR from dev into main.
# Use instead of: git push origin main
set -euo pipefail

BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ "$BRANCH" != "dev" ]; then
  echo "push_main: must be on dev branch, currently on $BRANCH" >&2
  exit 1
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "push_main: uncommitted changes present, commit first" >&2
  exit 1
fi

if [ ! -f VERSION ]; then
  echo "push_main: VERSION file not found" >&2
  exit 1
fi

VERSION=$(< VERSION)
TITLE="Release v${VERSION}"

git push origin dev

PR_NUMBER=$(gh pr list --base main --head dev --json number -q '.[0].number' 2>/dev/null || true)
if [ -z "$PR_NUMBER" ]; then
  PR_NUMBER=$(gh pr create \
    --base main \
    --head dev \
    --title "$TITLE" \
    --body "Stable release v${VERSION} — merged from dev." \
    --json number -q '.number')
fi

gh pr merge "$PR_NUMBER" --merge --delete-branch=false
