#!/usr/bin/env bash
# Distributed NCS container integration tests.
#
# Two fully-containerized multi-node scenarios, each node running the SAME
# production image (deploy/container/docker/Dockerfile) on its own Docker
# network — the "practical" counterpart to the fast Go subprocess tests in
# cmd/arxsentinel/distributed_ncs_*_test.go (-tags integration). Those prove
# the wiring quickly on every change; this proves the actual container image
# behaves the same way when nodes are genuinely isolated processes on a
# Docker-managed network, resolving each other by service name — the closest
# this test suite gets to a real multi-host deployment without provisioning
# real hosts.
#
#   Scenario 1 (aggregation):    3 collectors → 1 detector → 1 executor
#   Scenario 2 (mixed-routing):  2 collectors → 1 detector (2 pipelines) →
#                                 2 different executor types on 2 nodes
#
# Usage:
#   bash tests/integration/distributed-ncs/run.sh

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

PASS=0
FAIL=0

cleanup() {
    echo "[distributed-ncs] cleaning up..."
    docker compose -f docker-compose.aggregation.yml down -v --remove-orphans 2>/dev/null || true
    docker compose -f docker-compose.mixed-routing.yml down -v --remove-orphans 2>/dev/null || true
    rm -rf "$DIR/data"
}
trap cleanup EXIT

# check: records a PASS/FAIL line and updates the running counters. $2 is the
# actual content to search, $3 is the substring expected somewhere in it —
# mirrors the PASS/FAIL line convention the main verify.sh uses so CI log
# output stays scannable the same way across both test suites.
check() {
    local name="$1" content="$2" want="$3"
    if [[ "$content" == *"$want"* ]]; then
        echo "PASS [$name]  found '$want'"
        PASS=$((PASS + 1))
    else
        echo "FAIL [$name]  expected to find '$want', got: $content"
        FAIL=$((FAIL + 1))
    fi
}

# check_absent: the negative-control counterpart of check — passes when want
# is NOT present (proves mixed-routing does not leak across pipelines).
check_absent() {
    local name="$1" content="$2" unwanted="$3"
    if [[ "$content" == *"$unwanted"* ]]; then
        echo "FAIL [$name]  unexpectedly found '$unwanted', got: $content"
        FAIL=$((FAIL + 1))
    else
        echo "PASS [$name]  '$unwanted' correctly absent"
        PASS=$((PASS + 1))
    fi
}

# wait_for_file_content: polls a bind-mounted file every 500ms until it
# contains substr or timeout_s elapses. A missing file is "not yet", not an
# error — the executor creates its output lazily on first write.
wait_for_file_content() {
    local file="$1" substr="$2" timeout_s="${3:-15}"
    local waited=0
    while (( waited < timeout_s * 2 )); do
        if [ -f "$file" ] && grep -qF "$substr" "$file" 2>/dev/null; then
            return 0
        fi
        sleep 0.5
        waited=$((waited + 1))
    done
    return 1
}

# probe_line: renders a combined-format access-log line for the given IP.
# The same wp-login.php probe used by the Go integration tests — the
# bruteforce/probe/ua detectors combine to cross the default
# AlertThreshold=50 within 3 hits (proven empirically, see
# cmd/arxsentinel/distributed_ncs_integration_test.go's comment on the same
# finding: a single hit only scores 25, well under threshold).
probe_line() {
    local ip="$1"
    echo "${ip} - - [04/Jul/2026:10:00:00 +0000] \"GET /wp-login.php HTTP/1.1\" 200 512 \"-\" \"curl/7.88\" \"${ip}\""
}

# ════════════════════════════════════════════════════════════════════════════
# Scenario 1: aggregation — 3 collectors → 1 detector → 1 executor
# ════════════════════════════════════════════════════════════════════════════
echo "[distributed-ncs] === Scenario 1: aggregation ==="

mkdir -p data/agg/collector-nginx-edge data/agg/collector-api-gateway data/agg/collector-auth-service data/agg/executor
touch data/agg/collector-nginx-edge/access.log data/agg/collector-api-gateway/access.log data/agg/collector-auth-service/access.log
touch data/agg/executor/idle.log
# 777: the distroless nonroot (UID 65532) container writes blocklist.conf/idle-out.log
# here; the host-side collector append below needs write access to the same dirs too.
chmod -R 777 data/agg

docker compose -f docker-compose.aggregation.yml up -d --build
echo "[distributed-ncs] waiting for aggregation nodes to start..."
sleep 3

BLOCKLIST="data/agg/executor/blocklist.conf"
declare -A AGG_IPS=(
    [collector-nginx-edge]=203.0.113.11
    [collector-api-gateway]=203.0.113.12
    [collector-auth-service]=203.0.113.13
)
for collector in "${!AGG_IPS[@]}"; do
    ip="${AGG_IPS[$collector]}"
    line="$(probe_line "$ip")"
    ok=false
    for _ in $(seq 1 20); do
        echo "$line" >> "data/agg/${collector}/access.log"
        if wait_for_file_content "$BLOCKLIST" "$ip" 1; then
            ok=true
            break
        fi
    done
    if $ok; then
        check "distributed-ncs/agg/${collector}" "$(cat "$BLOCKLIST" 2>/dev/null || true)" "$ip"
    else
        check "distributed-ncs/agg/${collector}" "$(cat "$BLOCKLIST" 2>/dev/null || true)" "$ip"
        echo "  --- detector logs ---"
        docker compose -f docker-compose.aggregation.yml logs detector 2>&1 | tail -20
        echo "  --- executor logs ---"
        docker compose -f docker-compose.aggregation.yml logs executor 2>&1 | tail -20
    fi
done

docker compose -f docker-compose.aggregation.yml down -v --remove-orphans
rm -rf data/agg

# ════════════════════════════════════════════════════════════════════════════
# Scenario 2: mixed-routing — 2 collectors → 1 detector (2 pipelines) → 2 executors
# ════════════════════════════════════════════════════════════════════════════
echo "[distributed-ncs] === Scenario 2: mixed-routing ==="

mkdir -p data/mixed/collector-web data/mixed/collector-auth data/mixed/nginx-executor data/mixed/mikrotik-executor
touch data/mixed/collector-web/access.log data/mixed/collector-auth/access.log
touch data/mixed/nginx-executor/idle.log data/mixed/mikrotik-executor/idle.log
chmod -R 777 data/mixed

docker compose -f docker-compose.mixed-routing.yml up -d --build
echo "[distributed-ncs] waiting for mixed-routing nodes to start..."
sleep 3

WEB_IP="203.0.113.21"
AUTH_IP="203.0.113.22"
NGINX_BLOCKLIST="data/mixed/nginx-executor/blocklist.conf"
web_line="$(probe_line "$WEB_IP")"
auth_line="$(probe_line "$AUTH_IP")"

web_ok=false
for _ in $(seq 1 20); do
    echo "$web_line" >> data/mixed/collector-web/access.log
    if wait_for_file_content "$NGINX_BLOCKLIST" "$WEB_IP" 1; then
        web_ok=true
        break
    fi
done
if ! $web_ok; then
    echo "  --- detector logs ---"
    docker compose -f docker-compose.mixed-routing.yml logs detector 2>&1 | tail -20
    echo "  --- nginx-executor logs ---"
    docker compose -f docker-compose.mixed-routing.yml logs nginx-executor 2>&1 | tail -20
fi
check "distributed-ncs/mixed/web-to-nginx" "$(cat "$NGINX_BLOCKLIST" 2>/dev/null || true)" "$WEB_IP"

auth_ok=false
ros_result=""
for _ in $(seq 1 20); do
    echo "$auth_line" >> data/mixed/collector-auth/access.log
    ros_result="$(curl -sf http://localhost:8095/recorded-items 2>/dev/null || true)"
    if [[ "$ros_result" == *"$AUTH_IP"* ]]; then
        auth_ok=true
        break
    fi
    sleep 1
done
if ! $auth_ok; then
    echo "  --- detector logs ---"
    docker compose -f docker-compose.mixed-routing.yml logs detector 2>&1 | tail -20
    echo "  --- mikrotik-executor logs ---"
    docker compose -f docker-compose.mixed-routing.yml logs mikrotik-executor 2>&1 | tail -20
fi
check "distributed-ncs/mixed/auth-to-mikrotik" "$ros_result" "$AUTH_IP"

# Cross-checks: mixed routing must not leak between pipelines.
check_absent "distributed-ncs/mixed/no-leak-auth-in-nginx" "$(cat "$NGINX_BLOCKLIST" 2>/dev/null || true)" "$AUTH_IP"
check_absent "distributed-ncs/mixed/no-leak-web-in-mikrotik" "$ros_result" "$WEB_IP"

docker compose -f docker-compose.mixed-routing.yml down -v --remove-orphans
rm -rf data/mixed

# ── Summary ────────────────────────────────────────────────────────────────
echo ""
echo "[distributed-ncs] $PASS passed, $FAIL failed"
if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
