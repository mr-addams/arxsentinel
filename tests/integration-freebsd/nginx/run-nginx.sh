#!/usr/bin/env sh
# tests/integration-freebsd/nginx/run-nginx.sh — Flow 089 integration
# smoke for the nginx backend under FreeBSD/podman.
#
# Architecture (per Flow 089 DECISIONS §2 + §3):
# - nginx runs in a Linux-emulated nginx:alpine container under
#   podman (FreeBSD Linux compat — see Flow 088 DECISIONS §"A.2").
# - arxsentinel runs NATIVE on the VM host (NOT in a container —
#   DECISIONS §2), with its CWD = $WORK_DIR so the relative paths in
#   sentinel-nginx.yaml resolve correctly.
# - The attacker runs in a SECOND podman container (curlimages/curl)
#   on the same CNI network. Both attacker requests share the curl
#   container's CNI IP (DECISIONS §3).
#
# Mirrors tests/integration-freebsd/run-smoke.sh (Flow 088 G.1) for
# scaffolding, but the threat-log grader is adapted per Flow 089
# DECISIONS §5 (UA-based, not IP-based).
#
# Why POSIX sh (NOT bash):
#   vmactions/freebsd-vm@v1.5.0 with `usesh: true` runs /bin/sh, which
#   on FreeBSD 14.3 is ash-like — NOT bash. No `[[ ]]`, no arrays,
#   no `<(...)`, no `local` outside functions, no `echo -e`. Use
#   `[ ]`, `set --` for arg lists, `printf` for `\n`.
#
# Why set -eu (not just -e):
#   Fail fast on any error or unset variable. A red run is a finding
#   (DECISIONS §6), but the script itself must not silently continue
#   past a bind-mount typo and then produce a meaningless "all 3
#   assertions green" on an empty threat log.
#
# Phase 3 step mapping:
#   - Task 3.2: this file's skeleton + CNI network + nginx container
#     startup (steps 0-3 below).
#   - Task 3.3: sentinel host-process launch + "watching started" sync
#     (steps 4-5 below).
#   - Task 3.4: curl attacker with sqlmap + Mozilla UAs (step 6 below).
#   - Task 3.5: three assertions adapted per DECISIONS §5 (step 7).
#   - Task 3.6: artifact persistence copy (step 8).

set -eu

# ---------------------------------------------------------------------
# Step 0: locate inputs. REPO_ROOT is the workspace root ($GITHUB_WORKSPACE
# at workflow runtime). All three inputs are committed in this directory.
# ---------------------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
NGINX_DIR="$REPO_ROOT/tests/integration-freebsd/nginx"
NGINX_CONF="$NGINX_DIR/nginx.conf"
SENTINEL_BIN="$REPO_ROOT/arxsentinel"
SENTINEL_CFG_SRC="$NGINX_DIR/sentinel-nginx.yaml"

# Sanity: all three inputs must exist. A typo or missing build would
# silently produce an empty access log and the assertions would
# falsely PASS.
if [ ! -s "$NGINX_CONF" ]; then
    echo "[nginx] FAIL: nginx.conf missing or empty at $NGINX_CONF" >&2
    exit 1
fi
if [ ! -x "$SENTINEL_BIN" ]; then
    echo "[nginx] FAIL: arxsentinel binary not found or not executable at $SENTINEL_BIN" >&2
    exit 1
fi
if [ ! -s "$SENTINEL_CFG_SRC" ]; then
    echo "[nginx] FAIL: sentinel-nginx.yaml missing or empty at $SENTINEL_CFG_SRC" >&2
    exit 1
fi

# ---------------------------------------------------------------------
# Step 1: create $WORK_DIR + the bind-mounted subdirs. $WORK_DIR lives
# under $TMPDIR (set by the workflow as scoped TMPDIR — Task 4.2) so
# the cleanup trap's rm -rf lands in a tmpfs / workspace sync area, not
# under /var/db or /usr/local. The relative paths in sentinel-nginx.yaml
# (nginx/access.log, output/threats-nginx.log) resolve against
# $WORK_DIR when the sentinel CWDs there in step 4.
# ---------------------------------------------------------------------
WORK_DIR="${TMPDIR:-/tmp}/arx-nginx-$$"
mkdir -p "$WORK_DIR/nginx" "$WORK_DIR/output"
# 0755 is enough: sentinel runs as root on the FreeBSD host (no
# nonroot hardening yet — see Flow 089 Deferred 089.9 + 088 TD-8).
chmod 0755 "$WORK_DIR/output"

# Stage inputs into $WORK_DIR so the nginx container bind-mount and
# the sentinel CWD see them in a predictable layout.
cp "$NGINX_CONF" "$WORK_DIR/nginx.conf"
cp "$SENTINEL_CFG_SRC" "$WORK_DIR/sentinel-nginx.yaml"

# podman-network and container-name markers — used in cleanup() and
# step 3 (wait-for-nginx). Set as empty strings so the trap is
# idempotent on early exit (e.g. if podman network create fails).
NETWORK="arx-net"
NGINX_CID=""

cleanup() {
    if [ -n "$NGINX_CID" ]; then
        podman rm -f "$NGINX_CID" >/dev/null 2>&1 || true
    fi
    # CNI networks do not auto-GC on job exit (DECISIONS §3 consequences):
    # remove the network explicitly.
    podman network rm "$NETWORK" >/dev/null 2>&1 || true
    # Remove the sentinel process if it's still running. The pid file
    # is the canonical handle (sentinel writes it on start).
    if [ -f /tmp/arxsentinel.pid ]; then
        SPID=$(cat /tmp/arxsentinel.pid 2>/dev/null || true)
        if [ -n "$SPID" ]; then
            kill "$SPID" >/dev/null 2>&1 || true
        fi
        rm -f /tmp/arxsentinel.pid
    fi
    # Keep $WORK_DIR on exit if TMPDIR=$GITHUB_WORKSPACE (workflow
    # artifact path — Task 3.6 / 4.3). The workflow's
    # actions/upload-artifact picks it up before the VM is destroyed.
    # If TMPDIR is NOT $GITHUB_WORKSPACE (local-debug use), the user
    # is responsible for cleanup; rm -rf is intentionally omitted.
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------
# Step 2: create the CNI network. DECISIONS §3 — native `podman network
# create`, NOT podman-compose (which is not in FreeBSD pkg; pip install
# adds a non-FreeBSD-pkg dependency). The default CNI subnet (typically
# 10.88.0.0/16 on FreeBSD) is fine for the direct-nginx test.
# ---------------------------------------------------------------------
echo "[nginx] creating CNI network $NETWORK..."
podman network create "$NETWORK"

# ---------------------------------------------------------------------
# Step 3: start the nginx container detached. bind-mount the staged
# nginx.conf over /etc/nginx/nginx.conf (so nginx reads our config,
# not the image's default) and bind-mount $WORK_DIR/nginx over
# /var/log/nginx (so the access log lands at $WORK_DIR/nginx/access.log
# on the host — the path the host-native sentinel reads in step 4).
# --name nginx gives the attacker container a DNS name to reach
# ("curl http://nginx/" — DECISIONS §3 consequences).
# ---------------------------------------------------------------------
echo "[nginx] starting nginx container..."
NGINX_CID=$(podman run -d \
    --name nginx \
    --network "$NETWORK" \
    -v "$WORK_DIR/nginx.conf:/etc/nginx/nginx.conf:ro" \
    -v "$WORK_DIR/nginx:/var/log/nginx" \
    nginx:alpine)
echo "[nginx] container $NGINX_CID started"

# Wait for nginx to be ready: `podman exec nginx nginx -t` validates
# the config (catches the bind-mount typo case); the `podman logs`
# line for "start worker processes" signals that nginx has fully
# started. ~15s timeout is generous for first-pull + boot.
echo "[nginx] waiting for nginx ready (timeout 30s)..."
DEADLINE=$(($(date +%s) + 30))
READY=0
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    if podman exec nginx nginx -t >/dev/null 2>&1 \
       && podman logs nginx 2>&1 | grep -q "start worker processes"; then
        READY=1
        break
    fi
    sleep 1
done
if [ "$READY" -ne 1 ]; then
    echo "[nginx] FAIL: nginx not ready within 30s" >&2
    echo "[nginx] nginx logs (last 30 lines):" >&2
    podman logs --tail 30 nginx >&2 || true
    exit 1
fi
echo "[nginx] nginx ready"

# ---------------------------------------------------------------------
# Step 4: start the native sentinel. DECISIONS §2 — sentinel on host,
# NOT in a container. CWD = $WORK_DIR so the relative paths in
# sentinel-nginx.yaml resolve. The sentinel writes its pid to
# /tmp/arxsentinel.pid (per the yaml) and its operational log to
# sentinel-nginx.log under $WORK_DIR.
# ---------------------------------------------------------------------
echo "[nginx] starting native sentinel (CWD=$WORK_DIR)..."
cd "$WORK_DIR"
"$SENTINEL_BIN" \
    --config "$WORK_DIR/sentinel-nginx.yaml" \
    > "$WORK_DIR/sentinel-nginx.log" 2>&1 &
SENTINEL_PID=$!
echo "[nginx] sentinel started with PID $SENTINEL_PID"

# Step 5: wait for "watching started" in sentinel-nginx.log. This
# sync prevents the host append in step 6 from racing the TailReader
# open+seek(EOF) (mirrors 088 run-smoke.sh step 3). The yaml's
# logging.debug: true is REQUIRED for the "TAIL watching started"
# line to be emitted (see sentinel-nginx.yaml header).
echo "[nginx] waiting for 'watching started' (timeout 30s)..."
DEADLINE=$(($(date +%s) + 30))
WATCHING=0
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    if grep -q "watching started" "$WORK_DIR/sentinel-nginx.log" 2>/dev/null; then
        WATCHING=1
        break
    fi
    sleep 1
done
if [ "$WATCHING" -ne 1 ]; then
    echo "[nginx] FAIL: 'watching started' not seen within 30s" >&2
    echo "[nginx] sentinel log (last 50 lines):" >&2
    tail -50 "$WORK_DIR/sentinel-nginx.log" >&2 || true
    kill "$SENTINEL_PID" 2>/dev/null || true
    exit 1
fi
echo "[nginx] TailReader ready"

