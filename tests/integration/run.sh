#!/usr/bin/env bash
# Integration test runner.
# Builds arxsentinel, spins up 6 direct-test server containers + nginx-rp as proxy,
# fires attack scenarios, and verifies each server's threat log.
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
# Initialize PID variables before trap so cleanup() never sees unbound variables
# even if the script exits early (e.g. build failure before docker compose up).
HAPROXY_LOG_PID=""
HAPROXY_BACKEND_LOG_PID=""

cleanup() {
    echo "[run] cleaning up..."

    # Stop sentinel instances by tracked PIDs.
    for pid in "${SENTINEL_PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    rm -f /tmp/arxsentinel-{nginx,apache,traefik,caddy,haproxy,litespeed}.pid
    rm -f /tmp/arxsentinel-{nginx-proxy,apache-proxy,traefik-proxy,caddy-proxy,haproxy-proxy,litespeed-proxy}.pid
    rm -f /tmp/arxsentinel-{cf-broken,bogon-victim}.pid

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
    (cd "$REPO_ROOT" && go build -o "$BIN" ./cmd/arxsentinel)
    echo "[run] build done"
fi

# ── Step 2: fetch blocklist patterns for the badbot integration test ─────────────────
# Downloads 20 real patterns from upstream sources and saves them for:
#   a) the lighttpd Dockerfile (COPY at docker build time)
#   b) scenarios.sh — to pick a test UA that is guaranteed to be in the loaded list
#
# Fails fast on network error — testing "patterns load and apply" requires real data.

BLOCKLIST_DIR="$INT_DIR/blocklist"
mkdir -p "$BLOCKLIST_DIR"

UA_URL="https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-user-agents.list"
REF_URL="https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-referrers.list"

echo "[run] fetching blocklist patterns from upstream..."
# pipefail disabled per-pipeline: head -20 closes stdin before grep/curl finish reading
# all ~685/7108 lines — SIGPIPE on grep is expected and benign.
# Content is verified by checking the output file size afterward.
# The same pattern is used in scenarios.sh for the LONG_PATH variable.
(set +o pipefail; curl -fsSL --max-time 30 "$UA_URL" \
    | grep -v '^[[:space:]]*#' | grep -v '^[[:space:]]*$' \
    | head -20) > "$BLOCKLIST_DIR/badbot-ua.list" 2>/dev/null || true
if [ ! -s "$BLOCKLIST_DIR/badbot-ua.list" ]; then
    echo "[run] ERROR: failed to fetch UA patterns from $UA_URL" >&2
    exit 1
fi

(set +o pipefail; curl -fsSL --max-time 30 "$REF_URL" \
    | grep -v '^[[:space:]]*#' | grep -v '^[[:space:]]*$' \
    | head -20) > "$BLOCKLIST_DIR/badbot-ref.list" 2>/dev/null || true
if [ ! -s "$BLOCKLIST_DIR/badbot-ref.list" ]; then
    echo "[run] ERROR: failed to fetch referrer patterns from $REF_URL" >&2
    exit 1
fi

# Save the first UA pattern so scenarios.sh can send a request we know will match.
BADBOT_TEST_UA=$(head -1 "$BLOCKLIST_DIR/badbot-ua.list")
if [ -z "$BADBOT_TEST_UA" ]; then
    echo "[run] ERROR: badbot-ua.list is empty after fetch" >&2
    exit 1
fi
echo "$BADBOT_TEST_UA" > "$BLOCKLIST_DIR/test-ua.txt"

UA_COUNT=$(wc -l < "$BLOCKLIST_DIR/badbot-ua.list")
REF_COUNT=$(wc -l < "$BLOCKLIST_DIR/badbot-ref.list")
echo "[run] blocklist fetched: ${UA_COUNT} UA patterns, ${REF_COUNT} referrer patterns"
echo "[run] test UA for badbot scenario: ${BADBOT_TEST_UA}"

# Create test Cloudflare CIDR file for chain_guard integration test.
# Includes Docker bridge subnet (172.16.0.0/12) so cloudflare-sim's container IP
# is treated as "Cloudflare" by the cf-broken sentinel.
# In production, real Cloudflare CIDRs are fetched from cloudflare.com/ips-*.
cat > "$BLOCKLIST_DIR/test-cloudflare-cidrs.txt" <<'EOF'
# Integration test Cloudflare CIDR list — not for production use.
# Docker bridge net: covers cloudflare-sim container IP for broken-chain test.
172.16.0.0/12
# Real Cloudflare ranges (May 2026):
173.245.48.0/20
103.21.244.0/22
104.16.0.0/13
172.64.0.0/13
EOF
echo "[run] test Cloudflare CIDR file created: $BLOCKLIST_DIR/test-cloudflare-cidrs.txt"

# ── Step 3: prepare log directories ──────────────────────────────────────────────────

mkdir -p \
    "$LOGS_DIR/nginx" \
    "$LOGS_DIR/apache" \
    "$LOGS_DIR/traefik" \
    "$LOGS_DIR/caddy" \
    "$LOGS_DIR/haproxy" \
    "$LOGS_DIR/litespeed" \
    "$LOGS_DIR/apache-proxy" \
    "$LOGS_DIR/traefik-proxy" \
    "$LOGS_DIR/caddy-proxy" \
    "$LOGS_DIR/haproxy-proxy" \
    "$LOGS_DIR/litespeed-proxy" \
    "$LOGS_DIR/nginx-bare" \
    "$LOGS_DIR/nginx-bogon-victim" \
    "$LOGS_DIR/threats" \
    "$LOGS_DIR/warnings"

# Truncate all server access logs from previous runs.
# --force-recreate below restarts containers with fresh file descriptors, so
# truncate-in-place (>) is safe — the running process is being replaced anyway.
# OLS log files may be owned by nobody:nogroup after a prior run; sudo-remove
# them so the recreated container starts with a fresh file at the correct path.
for f in nginx apache traefik caddy haproxy; do
    > "$LOGS_DIR/$f/access.log"
done
sudo rm -f "$LOGS_DIR/litespeed/localhost.access.log"
touch       "$LOGS_DIR/litespeed/localhost.access.log"
# Proxy-chain backend log files.
> "$LOGS_DIR/nginx/access-proxy.log"
> "$LOGS_DIR/apache-proxy/access.log"
> "$LOGS_DIR/traefik-proxy/access-proxy.log"
> "$LOGS_DIR/caddy-proxy/access-proxy.log"
> "$LOGS_DIR/haproxy-proxy/access.log"
sudo rm -f "$LOGS_DIR/litespeed-proxy/localhost.access.log"
touch       "$LOGS_DIR/litespeed-proxy/localhost.access.log"

# Chain guard test server log files.
> "$LOGS_DIR/nginx-bare/access.log"
> "$LOGS_DIR/nginx-bogon-victim/access.log"

# Truncate threat and warning logs from previous runs — verify.sh reads cumulative content, so
# stale entries from earlier runs would cause false positives or false negatives.
rm -f "$LOGS_DIR/threats"/*.log
rm -f "$LOGS_DIR/warnings"/*.log

# ── Step 4: start containers ──────────────────────────────────────────────────────────

echo "[run] starting server containers..."
# --force-recreate: restart containers even if nothing changed — ensures fresh file descriptors
# for log files. Without this, log files deleted between runs cause servers to write to the
# old unlinked inode, leaving new files empty.
docker compose -f "$INT_DIR/docker-compose.yml" up -d --build --force-recreate

# Give containers time to initialise and start serving.
sleep 5

# ── Step 5: capture HAProxy stdout → log file ─────────────────────────────────────────
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

# ── Step 6: start 6 arxsentinel instances ────────────────────────────────────────────

echo "[run] starting arxsentinel instances..."

SERVERS=(nginx apache traefik caddy haproxy litespeed)

SENTINEL_PIDS=()
for server in "${SERVERS[@]}"; do
    # exec replaces the subshell so $! captures the arxsentinel PID directly.
    # stdout/stderr discarded: the binary already writes operational output to
    # output.operational_log (sentinel-${server}.log); redirecting here would duplicate it.
    (cd "$INT_DIR" && exec env ARXSENTINEL_CONFIG="$INT_DIR/arxsentinel/${server}.yaml" \
        "$BIN" > /dev/null 2>&1) &
    SENTINEL_PIDS+=($!)
done

# Start 6 additional sentinel instances for proxy-chain backends.
PROXY_SERVERS=(nginx-proxy apache-proxy traefik-proxy caddy-proxy haproxy-proxy litespeed-proxy)
for server in "${PROXY_SERVERS[@]}"; do
    (cd "$INT_DIR" && exec env ARXSENTINEL_CONFIG="$INT_DIR/arxsentinel/${server}.yaml" \
        "$BIN" > /dev/null 2>&1) &
    SENTINEL_PIDS+=($!)
done

# Start 2 chain_guard sentinel instances (cf-broken + bogon-victim).
# cf-broken watches nginx-bare access log and detects cloudflare-sim IP as client.
# bogon-victim watches nginx-bogon-victim access log and detects 10.0.0.1 as client.
CHAIN_GUARD_SENTINELS=(cf-broken bogon-victim)
for server in "${CHAIN_GUARD_SENTINELS[@]}"; do
    (cd "$INT_DIR" && exec env ARXSENTINEL_CONFIG="$INT_DIR/arxsentinel/${server}.yaml" \
        "$BIN" > /dev/null 2>&1) &
    SENTINEL_PIDS+=($!)
done

# Give sentinels time to open and begin tailing log files.
sleep 3

# ── Step 7: run attack scenarios ─────────────────────────────────────────────────────

echo "[run] running attack scenarios..."
# Export BIN so scenarios.sh can locate the binary we just built.
# scenarios.sh uses ARX_BIN with a fallback to its legacy path for standalone runs.
ARX_BIN="$BIN" bash "$INT_DIR/scenarios.sh"

# Give sentinels time to process the last log lines.
sleep 5

# ── Step 8: verify ────────────────────────────────────────────────────────────────────
# tee preserves the original exit code via pipefail while saving output for CI analysis.

bash "$INT_DIR/verify.sh" "$LOGS_DIR" | tee "$LOGS_DIR/verify-output.txt"
