#!/usr/bin/env sh
# tests/integration-freebsd/run-smoke.sh — FreeBSD/podman analogue of
# tests/container/container_test.go::TestContainerDetectsThreat.
#
# Port from testcontainers (Linux, Go) to native podman CLI (FreeBSD, sh).
# Reuses the existing arxsentinel:freebsd-local image (built in-job, see
# DECISIONS §"Group G" Decision G.1c) and the existing
# testdata/synthetic.access.log fixture (10 lines, attacker 10.0.0.1 +
# legit 10.0.0.2 — NO new fixtures).
#
# Why POSIX sh (NOT bash):
#   vmactions/freebsd-vm@v1.5.0 with `usesh: true` runs /bin/sh, which on
#   FreeBSD 14.3 is ash-like — NOT bash. Avoid bashisms: no `[[ ]]`, no
#   arrays, no `<(...)`, no `local` outside functions, no `echo -e`. Use
#   `[ ]`, `set --` for arg lists, and explicit `\n` via printf.
#
# Why set -eu (not set -e alone):
#   This smoke is NOT research-grade (unlike podman-spike B.3). A red
#   smoke is a real finding to triage, but the script itself should fail
#   fast on any error or unset variable — silently continuing past a
#   bind-mount typo would produce a meaningless "all 3 assertions green"
#   on an empty threat log.
#
# Why chmod 0755 (NOT 0777 like the Linux test):
#   FreeBSD Containerfile.freebsd (Decision E.2) has no USER directive;
#   freebsd-static:14.3 runs as root (uid 0). Root writes regardless of
#   mode bits. The Linux test's chmod 0777 is a workaround for the
#   distroless:nonroot uid 65532; copying that here would be dead weight
#   AND would misrepresent the FreeBSD image's actual posture. See
#   DECISIONS §"Group G" Decision G.1d.

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
INT_DIR="$REPO_ROOT/tests/integration-freebsd"
WORK_DIR="${TMPDIR:-/tmp}/arx-smoke-$$"
mkdir -p "$WORK_DIR/input" "$WORK_DIR/output"
# 0755 is enough: container runs as root (Decision G.1d).
chmod 0755 "$WORK_DIR/output"

CFG="$INT_DIR/smoke.yaml"
INPUT_LOG="$WORK_DIR/input/access.log"
OUTPUT_DIR="$WORK_DIR/output"
THREAT_LOG="$OUTPUT_DIR/threats.log"
SYNTHETIC_LOG="$REPO_ROOT/testdata/synthetic.access.log"

CID=""

# Trap fires on normal exit, INT (Ctrl-C), and TERM. Removes the
# container (idempotent: empty $CID is a no-op) and the work dir.
# Do NOT call cleanup() manually at the end of the script — the trap is
# the single source of truth for teardown.
cleanup() {
    if [ -n "$CID" ]; then
        podman rm -f "$CID" >/dev/null 2>&1 || true
    fi
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT INT TERM

# Sanity: synthetic log must exist (committed fixture, not created here).
# Without this, an empty bind-mount would silently produce an empty
# threat log and the assertions would falsely PASS.
if [ ! -s "$SYNTHETIC_LOG" ]; then
    echo "[smoke] FAIL: synthetic.access.log missing or empty at $SYNTHETIC_LOG" >&2
    exit 1
fi

# Step 1: create empty input log. TailReader opens with O_RDWR and seeks
# to EOF on start; an empty file is EOF at pos 0, so the watcher fires
# on the first WRITE event after we append.
: > "$INPUT_LOG"

# Step 2: start arxsentinel detached. Image built in the same VM-job by
# the workflow (Decision G.1c — images do not persist across VM-action
# jobs). Config is :ro, input log RW (host appends), output dir RW
# (container writes threats.log). No --user: freebsd-static runs as root.
echo "[smoke] starting arxsentinel container..."
CID=$(podman run -d \
    --name "arx-smoke-$$" \
    -v "$CFG:/etc/arxsentinel/config.yaml:ro" \
    -v "$INPUT_LOG:/input/access.log" \
    -v "$OUTPUT_DIR:/output" \
    arxsentinel:freebsd-local)
echo "[smoke] container $CID started"

# Step 3: wait for TailReader "watching started" (sync, ~30s timeout).
# This mirrors testcontainers wait.ForLog("watching started") in
# TestContainerDetectsThreat. Without this sync, the host append in
# step 4 may race TailReader's open+seek(EOF) — the WRITE inotify event
# would fire BEFORE the container has the FD open, and sentinel would
# seek past the appended content to the new EOF and miss all lines.
# The `2>&1` is because sentinel writes operational logs to stderr by
# default (console_color: false in smoke.yaml).
echo "[smoke] waiting for TailReader 'watching started' (timeout 30s)..."
DEADLINE=$(($(date +%s) + 30))
READY=0
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    if podman logs "$CID" 2>&1 | grep -q "watching started"; then
        READY=1
        break
    fi
    sleep 1
done
if [ "$READY" -ne 1 ]; then
    echo "[smoke] FAIL: 'watching started' not seen within 30s" >&2
    echo "[smoke] container logs (last 50 lines):" >&2
    podman logs --tail 50 "$CID" >&2 || true
    exit 1
fi
echo "[smoke] TailReader ready"

# Step 4: append synthetic log content to the mounted input log. Same
# pattern as the Linux test (os.OpenFile(..., O_WRONLY|O_APPEND, 0o644)
# + Write). In sh: `cat >> file` opens O_WRONLY|O_APPEND.
echo "[smoke] appending synthetic log content..."
cat "$SYNTHETIC_LOG" >> "$INPUT_LOG"

# Step 5: poll threats.log for non-empty content (~20s timeout, same as
# the Linux test). Sentinel has 10 lines to parse and at least 5 THREAT
# matches to score/write — 20s is generous.
echo "[smoke] polling threats.log (timeout 20s)..."
DEADLINE=$(($(date +%s) + 20))
WRITTEN=0
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    if [ -s "$THREAT_LOG" ]; then
        WRITTEN=1
        break
    fi
    sleep 1
done
if [ "$WRITTEN" -ne 1 ]; then
    echo "[smoke] FAIL: threats.log not written within 20s" >&2
    echo "[smoke] container logs (last 80 lines):" >&2
    podman logs --tail 80 "$CID" >&2 || true
    exit 1
fi

# Persist threats.log to a stable path for the workflow artifact. The
# cleanup() trap on EXIT will remove $WORK_DIR; this copy is in
# $TMPDIR (NOT under $WORK_DIR) so it survives the trap. The workflow
# sets TMPDIR=$GITHUB_WORKSPACE so the file lands in the synced workspace
# and copyback returns it to the host.
if [ -s "$THREAT_LOG" ]; then
    cp "$THREAT_LOG" "${TMPDIR:-/tmp}/threats.log.smoke"
fi

# Step 6: three assertions matching TestContainerDetectsThreat exactly.
# Read the whole file into $LINES (sentinel writes a small number of
# lines, this is fine for an integration smoke).
LINES=$(cat "$THREAT_LOG")
echo "[smoke] threat log content:"
printf '%s\n' "$LINES" | sed 's/^/  /'

FAIL=0

# Assertion 1: attacker 10.0.0.1 must be caught with a THREAT entry.
# Matches the Go test: strings.Contains(lines, " THREAT ") AND
# strings.Contains(lines, " 10.0.0.1 ").
ATTACKER="10.0.0.1"
if ! printf '%s\n' "$LINES" | grep -q " THREAT " \
   || ! printf '%s\n' "$LINES" | grep -q " $ATTACKER "; then
    echo "[smoke] FAIL: assertion 1 - expected THREAT for attacker $ATTACKER not found" >&2
    FAIL=1
fi

# Assertion 2: legitimate 10.0.0.2 must NOT appear in the threat log
# (no false positive). Matches the Go test's per-line scan.
LEGIT="10.0.0.2"
if printf '%s\n' "$LINES" | grep -q " $LEGIT "; then
    echo "[smoke] FAIL: assertion 2 - false positive: legitimate IP $LEGIT appeared in threat log" >&2
    FAIL=1
fi

# Assertion 3: every non-empty threat line has score= AND reason=
# (Fail2Ban-like format). The Go test uses bufio.Scanner + per-line
# strings.Contains. The POSIX sh equivalent is `grep -cv` over a pattern
# that requires BOTH `score=` AND `reason=` on the same line:
# non-empty lines WITHOUT both markers → BAD_COUNT > 0 → fail.
# Note: `|| true` on the grep -cv because an all-matching input exits 1
# (no matches for the negative pattern) which would short-circuit set -e.
BAD_COUNT=$(printf '%s\n' "$LINES" | grep -v '^$' | grep -cv 'score=.*reason=' || true)
if [ "$BAD_COUNT" -gt 0 ]; then
    echo "[smoke] FAIL: assertion 3 - $BAD_COUNT threat line(s) missing score=/reason=" >&2
    FAIL=1
fi

# Step 7: report + exit. Cleanup happens via the trap on EXIT (set in
# the preamble); do not call cleanup() manually.
if [ "$FAIL" -ne 0 ]; then
    echo "[smoke] FAIL: one or more assertions failed (see above)"
    exit 1
fi
echo "[smoke] PASS: all 3 assertions green - FreeBSD/podman end-to-end works"
exit 0
