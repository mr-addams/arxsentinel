#!/usr/bin/env bash
# Integration test runner.
# Builds arxsentinel, spins up 5 server containers, fires attack scenarios,
# and verifies each server's threat log.
#
# Usage:
#   bash tests/integration/run.sh            # run from repo root
#   bash tests/integration/run.sh --skip-build  # reuse existing binary

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INT_DIR="$REPO_ROOT/tests/integration"
LOGS_DIR="$INT_DIR/logs"
BIN="$REPO_ROOT/bin/arxsentinel"

SKIP_BUILD=false
for arg in "$@"; do
    [[ "$arg" == "--skip-build" ]] && SKIP_BUILD=true
done

# ── Cleanup on exit ───────────────────────────────────────────────────────────────────

cleanup() {
    echo "[run] cleaning up..."

    # Stop sentinel instances by tracked PIDs.
    for pid in "${SENTINEL_PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    rm -f /tmp/arxsentinel-{nginx,apache,traefik,caddy,haproxy}.pid
    rm -f /tmp/arxsentinel-{nginx-proxy,apache-proxy,traefik-proxy,caddy-proxy,haproxy-proxy}.pid

    # Stop HAProxy log capture (proxy and backend).
    kill "$HAPROXY_LOG_PID" 2>/dev/null || true
    kill "$HAPROXY_BACKEND_LOG_PID" 2>/dev/null || true

    # Stop containers.
    docker compose -f "$INT_DIR/docker-compose.yml" down --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

# ── Step 1: build ─────────────────────────────────────────────────────────────────────

if [ "$SKIP_BUILD" = false ]; then
    echo "[run] building arxsentinel..."
    mkdir -p "$REPO_ROOT/bin"
    (cd "$REPO_ROOT" && go build -o "$BIN" .)
    echo "[run] build done"
fi

# ── Step 2: prepare log directories ──────────────────────────────────────────────────

mkdir -p \
    "$LOGS_DIR/nginx" \
    "$LOGS_DIR/apache" \
    "$LOGS_DIR/traefik" \
    "$LOGS_DIR/caddy" \
    "$LOGS_DIR/haproxy" \
    "$LOGS_DIR/apache-proxy" \
    "$LOGS_DIR/traefik-proxy" \
    "$LOGS_DIR/caddy-proxy" \
    "$LOGS_DIR/haproxy-proxy" \
    "$LOGS_DIR/threats"

# Touch log files so tail can start before the first request arrives.
for f in nginx apache traefik caddy haproxy; do
    touch "$LOGS_DIR/$f/access.log"
done
# Proxy-chain backend log files.
touch "$LOGS_DIR/nginx/access-proxy.log"
touch "$LOGS_DIR/apache-proxy/access.log"
touch "$LOGS_DIR/traefik-proxy/access-proxy.log"
touch "$LOGS_DIR/caddy-proxy/access-proxy.log"
touch "$LOGS_DIR/haproxy-proxy/access.log"

# Truncate threat logs from previous runs — verify.sh reads cumulative content, so
# stale entries with proxy IPs from earlier runs would cause false "IP leaked" failures.
rm -f "$LOGS_DIR/threats"/*.log

# ── Step 3: start containers ──────────────────────────────────────────────────────────

echo "[run] starting server containers..."
# --force-recreate: restart containers even if nothing changed — ensures fresh file descriptors
# for log files. Without this, log files deleted between runs cause servers to write to the
# old unlinked inode, leaving new files empty.
docker compose -f "$INT_DIR/docker-compose.yml" up -d --build --force-recreate

# Give containers time to initialise and start serving.
sleep 5

# ── Step 4: capture HAProxy stdout → log file ─────────────────────────────────────────
#
# HAProxy logs to stdout (format raw — no syslog prefix).
# docker compose logs captures the stream and appends to access.log.

docker compose -f "$INT_DIR/docker-compose.yml" logs -f --no-log-prefix haproxy \
    >> "$LOGS_DIR/haproxy/access.log" 2>/dev/null &
HAPROXY_LOG_PID=$!

# Capture haproxy-backend stdout → log file for proxy-chain tests.
docker compose -f "$INT_DIR/docker-compose.yml" logs -f --no-log-prefix haproxy-backend \
    >> "$LOGS_DIR/haproxy-proxy/access.log" 2>/dev/null &
HAPROXY_BACKEND_LOG_PID=$!

# ── Step 5: start 5 arxsentinel instances ────────────────────────────────────────────

echo "[run] starting arxsentinel instances..."

SERVERS=(nginx apache traefik caddy haproxy)

SENTINEL_PIDS=()
for server in "${SERVERS[@]}"; do
    # exec replaces the subshell so $! captures the arxsentinel PID directly.
    # stdout/stderr discarded: the binary already writes operational output to
    # output.operational_log (sentinel-${server}.log); redirecting here would duplicate it.
    (cd "$INT_DIR" && exec env ARXSENTINEL_CONFIG="$INT_DIR/arxsentinel/${server}.yaml" \
        "$BIN" > /dev/null 2>&1) &
    SENTINEL_PIDS+=($!)
done

# Start 5 additional sentinel instances for proxy-chain backends.
PROXY_SERVERS=(nginx-proxy apache-proxy traefik-proxy caddy-proxy haproxy-proxy)
for server in "${PROXY_SERVERS[@]}"; do
    (cd "$INT_DIR" && exec env ARXSENTINEL_CONFIG="$INT_DIR/arxsentinel/${server}.yaml" \
        "$BIN" > /dev/null 2>&1) &
    SENTINEL_PIDS+=($!)
done

# Give sentinels time to open and begin tailing log files.
sleep 3

# ── Step 6: run attack scenarios ─────────────────────────────────────────────────────

echo "[run] running attack scenarios..."
bash "$INT_DIR/scenarios.sh"

# Give sentinels time to process the last log lines.
sleep 5

# ── Step 7: verify ────────────────────────────────────────────────────────────────────
# tee preserves the original exit code via pipefail while saving output for CI analysis.

bash "$INT_DIR/verify.sh" "$LOGS_DIR" | tee "$LOGS_DIR/verify-output.txt"
