#!/usr/bin/env bash
# Verify that each server's threat log contains THREAT entries from all 7 detectors.
#
# Format: "... modules=probe,ua,noasset ..."
# Checks presence of each module name as a whole word in any log line.

set -euo pipefail

LOGS_DIR="${1:-logs}"
PASS=0
FAIL=0

SERVERS=(nginx apache traefik caddy haproxy)
MODULES=(probe ua bruteforce crawler noasset rate overflow)

# assert_module SERVER MODULE
#   Checks that MODULE appears in the threat log for SERVER.
assert_module() {
    local server=$1
    local module=$2
    local logfile="$LOGS_DIR/threats/${server}.log"

    if [ ! -f "$logfile" ]; then
        echo "FAIL [$server/$module] log not found: $logfile"
        FAIL=$((FAIL + 1))
        return
    fi

    # grep -w matches whole words — commas act as word boundaries in CLF lines.
    if grep -qw "$module" "$logfile"; then
        echo "PASS [$server/$module]"
        PASS=$((PASS + 1))
    else
        echo "FAIL [$server/$module] not found in $logfile"
        FAIL=$((FAIL + 1))
    fi
}

# assert_chain PROXY BACKEND
#   Checks that the backend's proxy-chain threat log:
#     1. Contains at least one THREAT entry (detection happened).
#     2. Does NOT contain the proxy container's IP in any THREAT line.
#        IP leakage means the backend logged the proxy address instead of the attacker.
assert_chain() {
    local proxy=$1
    local backend=$2
    local logfile="$LOGS_DIR/threats/${backend}-proxy.log"

    if [ ! -f "$logfile" ]; then
        echo "FAIL [chain/$proxy→$backend] log not found: $logfile"
        FAIL=$((FAIL + 1))
        return
    fi

    # Resolve the proxy container IP from Docker inspect.
    # Container name: "integration-<service>-1" (project = integration/ directory).
    local container="integration-${proxy}-1"
    local proxy_ip
    proxy_ip=$(docker inspect "$container" \
        --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null | head -1)

    if [ -z "$proxy_ip" ]; then
        echo "WARN [chain/$proxy→$backend] could not resolve proxy container IP, skipping IP check"
        # Still check that THREAT exists.
        if grep -q "THREAT" "$logfile"; then
            echo "PASS [chain/$proxy→$backend] threat detected (IP check skipped)"
            PASS=$((PASS + 1))
        else
            echo "FAIL [chain/$proxy→$backend] no THREAT in $logfile"
            FAIL=$((FAIL + 1))
        fi
        return
    fi

    local has_threat=false
    local ip_leaked=false
    grep -q "THREAT" "$logfile" && has_threat=true
    grep -q "THREAT" "$logfile" && grep -qw "$proxy_ip" "$logfile" && ip_leaked=true

    if $has_threat && ! $ip_leaked; then
        echo "PASS [chain/$proxy→$backend] real IP ≠ proxy IP ($proxy_ip)"
        PASS=$((PASS + 1))
    elif ! $has_threat; then
        echo "FAIL [chain/$proxy→$backend] no THREAT detected in $logfile"
        FAIL=$((FAIL + 1))
    else
        echo "FAIL [chain/$proxy→$backend] proxy IP leaked: $proxy_ip appears in threat log"
        FAIL=$((FAIL + 1))
    fi
}

CHAIN_PROXIES=(traefik caddy haproxy nginx-rp)
CHAIN_BACKENDS=(nginx apache traefik caddy haproxy)

echo ""
echo "=== Integration test results ==="
echo ""

for srv in "${SERVERS[@]}"; do
    for mod in "${MODULES[@]}"; do
        assert_module "$srv" "$mod"
    done
    echo ""
done

echo "--- Proxy-chain results ---"
echo ""

for proxy in "${CHAIN_PROXIES[@]}"; do
    for backend in "${CHAIN_BACKENDS[@]}"; do
        assert_chain "$proxy" "$backend"
    done
    echo ""
done

DIRECT_TOTAL=$((${#SERVERS[@]} * ${#MODULES[@]}))
CHAIN_TOTAL=$((${#CHAIN_PROXIES[@]} * ${#CHAIN_BACKENDS[@]}))
TOTAL=$((DIRECT_TOTAL + CHAIN_TOTAL))

echo "================================"
echo "Results: $PASS passed, $FAIL failed"
echo "(${#SERVERS[@]} servers × ${#MODULES[@]} detectors = ${DIRECT_TOTAL} direct checks)"
echo "(${#CHAIN_PROXIES[@]} proxies × ${#CHAIN_BACKENDS[@]} backends = ${CHAIN_TOTAL} proxy-chain checks)"
echo "(total: ${TOTAL} checks)"
echo ""

[ "$FAIL" -eq 0 ] || exit 1
