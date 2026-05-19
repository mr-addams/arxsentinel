#!/usr/bin/env bash
# Verify that each server's threat log contains THREAT entries from all 7 detectors,
# and that proxy-chain tests record the attacker IP rather than the proxy IP.
#
# On failure each check emits a structured diagnostic block:
#   class=          root-cause category (server-silent | parser-miss | detector-miss |
#                   backend-silent | chain-parser-miss | ip-leak)
#   access-log:     line count + sample — helps distinguish log-path vs parser issues
#   threat-log:     entry count or leaked line
#   hint:           plain-English next step
#   image:          Docker image + sha256 digest — pins the exact upstream version tested

set -euo pipefail

LOGS_DIR="${1:-logs}"
PASS=0
FAIL=0

SERVERS=(nginx apache traefik caddy haproxy)
MODULES=(probe ua bruteforce crawler noasset rate overflow)

# ── Helpers ───────────────────────────────────────────────────────────────────

# image_for_server: maps service name to its Docker image reference.
image_for_server() {
    case "${1:-}" in
        nginx|nginx-rp)                        echo "nginx:latest"   ;;
        apache|apache-proxy)                   echo "httpd:latest"   ;;
        traefik|traefik-proxy|traefik-backend) echo "traefik:latest" ;;
        caddy|caddy-proxy|caddy-backend)       echo "caddy:latest"   ;;
        haproxy|haproxy-proxy|haproxy-backend) echo "haproxy:latest" ;;
        *)                                     echo "unknown"        ;;
    esac
}

# digest_for_image: returns the sha256 hash from the local Docker daemon.
# Images remain in the daemon after 'docker compose down', so this is safe to call
# at any point during or after the test run.
digest_for_image() {
    local img=$1
    local d
    d=$(docker inspect "$img" \
        --format '{{if .RepoDigests}}{{index .RepoDigests 0}}{{end}}' \
        2>/dev/null || true)
    echo "${d##*@}"   # strip "image@" prefix, leave "sha256:..."
}

# img_line SERVER — emits "  image: <img> (<digest>)" for embedding in FAIL blocks.
img_line() {
    local img; img=$(image_for_server "$1")
    local hash; hash=$(digest_for_image "$img")
    echo "  image: $img (${hash:-no-digest})"
}

# backend_access_log BACKEND — returns the proxy-chain access log path for a backend.
# Each backend writes to a different path depending on its log configuration.
backend_access_log() {
    case "$1" in
        nginx)   echo "$LOGS_DIR/nginx/access-proxy.log"          ;;
        apache)  echo "$LOGS_DIR/apache-proxy/access.log"         ;;
        traefik) echo "$LOGS_DIR/traefik-proxy/access-proxy.log"  ;;
        caddy)   echo "$LOGS_DIR/caddy-proxy/access-proxy.log"    ;;
        haproxy) echo "$LOGS_DIR/haproxy-proxy/access.log"        ;;
        *)       echo ""                                           ;;
    esac
}

# log_sample FILE [N] — prints the last N lines of FILE, indented by 4 spaces.
# Prints "(empty)" if the file is absent or contains nothing.
log_sample() {
    local file=$1
    local n="${2:-2}"
    if [ ! -f "$file" ] || [ ! -s "$file" ]; then
        echo "    (empty)"
        return
    fi
    tail -n "$n" "$file" | sed 's/^/    /'
}

# ── assert_module ─────────────────────────────────────────────────────────────
# assert_module SERVER MODULE
#   Checks that MODULE appears as a whole word in the threat log for SERVER.
#   On failure emits a multi-line diagnostic block with root-cause class.

assert_module() {
    local server=$1
    local module=$2
    local threat_log="$LOGS_DIR/threats/${server}.log"
    local access_log="$LOGS_DIR/${server}/access.log"

    # grep -w matches whole words — commas act as word boundaries in CLF lines.
    if grep -qw "$module" "$threat_log" 2>/dev/null; then
        echo "PASS [$server/$module]"
        PASS=$((PASS + 1))
        return
    fi

    FAIL=$((FAIL + 1))

    local access_lines=0
    [ -f "$access_log" ] && access_lines=$(wc -l < "$access_log")

    local threat_entries=0
    [ -f "$threat_log" ] && threat_entries=$(grep -c "THREAT" "$threat_log" 2>/dev/null || true)

    if [ "$access_lines" -eq 0 ]; then
        # Server never wrote anything to the access log — startup failure or log path changed.
        echo "FAIL [$server/$module]  class=server-silent"
        echo "  access-log: $access_log (0 lines — never written)"
        echo "  threat-log: $threat_log (not written)"
        echo "  hint: server container failed to start, log path changed, or wrong log volume mount"
        img_line "$server"

    elif [ "$threat_entries" -eq 0 ]; then
        # Access log has lines but sentinel produced zero THREAT entries — parser mismatch.
        echo "FAIL [$server/$module]  class=parser-miss"
        echo "  access-log: $access_log ($access_lines lines)"
        echo "  log-sample (last 2 lines):"
        log_sample "$access_log"
        echo "  threat-log: $threat_log (0 THREAT entries)"
        echo "  hint: sentinel parser regex does not match current log format, or sentinel is watching the wrong file"
        img_line "$server"

    else
        # Sentinel is working (other threats found) but this specific detector is absent.
        echo "FAIL [$server/$module]  class=detector-miss"
        echo "  access-log: $access_log ($access_lines lines)"
        echo "  threat-log: $threat_log ($threat_entries THREAT entries, '$module' absent)"
        echo "  threat-sample (last entry):"
        tail -1 "$threat_log" 2>/dev/null | sed 's/^/    /' || true
        echo "  hint: '$module' detector logic or threshold misconfiguration; parser is working"
        img_line "$server"
    fi
}

# ── assert_chain ──────────────────────────────────────────────────────────────
# assert_chain PROXY BACKEND
#   Checks that the backend's proxy-chain threat log:
#     1. Contains at least one THREAT entry (detection happened).
#     2. Does NOT contain the proxy container's IP — IP leakage means the backend
#        logged the proxy address instead of the real attacker IP.

assert_chain() {
    local proxy=$1
    local backend=$2
    local threat_log="$LOGS_DIR/threats/${backend}-proxy.log"
    local access_log; access_log=$(backend_access_log "$backend")

    # Resolve proxy container IP from Docker inspect.
    # Container name follows Compose convention: "integration-<service>-1".
    local container="integration-${proxy}-1"
    local proxy_ip
    proxy_ip=$(docker inspect "$container" \
        --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
        2>/dev/null | head -1 || true)

    # ── Case 1: no THREAT in threat log ──────────────────────────────────────

    if ! grep -q "THREAT" "$threat_log" 2>/dev/null; then
        FAIL=$((FAIL + 1))

        local access_lines=0
        [ -n "$access_log" ] && [ -f "$access_log" ] && access_lines=$(wc -l < "$access_log")

        if [ "$access_lines" -eq 0 ]; then
            # Proxy did not deliver the request to the backend, or backend did not log.
            echo "FAIL [chain/$proxy→$backend]  class=backend-silent"
            echo "  access-log: ${access_log:-(unknown)} (0 lines — backend did not log)"
            echo "  hint: proxy routing for /backend-${backend}/ is broken, or backend log path changed"
        else
            # Backend received and logged the request, but sentinel did not detect it.
            echo "FAIL [chain/$proxy→$backend]  class=chain-parser-miss"
            echo "  access-log: $access_log ($access_lines lines)"
            echo "  log-sample (last 2 lines):"
            log_sample "$access_log"
            echo "  threat-log: $threat_log (0 THREAT entries)"
            echo "  hint: sentinel parser does not match the proxy-chain backend log format"
        fi

        local proxy_img; proxy_img=$(image_for_server "$proxy")
        local backend_img; backend_img=$(image_for_server "$backend")
        echo "  proxy-image:   $proxy_img ($(digest_for_image "$proxy_img"))"
        echo "  backend-image: $backend_img ($(digest_for_image "$backend_img"))"
        return
    fi

    # ── Case 2: THREAT exists — check for IP leakage ─────────────────────────

    local ip_leaked=false
    if [ -n "$proxy_ip" ] && grep -qF "$proxy_ip" "$threat_log" 2>/dev/null; then
        # Check that the leaked IP actually appears on a THREAT line (not just any line).
        grep "THREAT" "$threat_log" | grep -qF "$proxy_ip" && ip_leaked=true
    fi

    if $ip_leaked; then
        FAIL=$((FAIL + 1))
        local leaked_line
        leaked_line=$(grep "THREAT" "$threat_log" | grep -F "$proxy_ip" | tail -1)
        local proxy_img; proxy_img=$(image_for_server "$proxy")
        local backend_img; backend_img=$(image_for_server "$backend")

        echo "FAIL [chain/$proxy→$backend]  class=ip-leak  proxy-ip=$proxy_ip"
        echo "  leaked-line: $leaked_line"
        echo "  hint: $backend-backend not resolving real IP from X-Forwarded-For; check trusted_proxies/RemoteIPInternalProxy config"
        echo "  proxy-image:   $proxy_img ($(digest_for_image "$proxy_img"))"
        echo "  backend-image: $backend_img ($(digest_for_image "$backend_img"))"
        return
    fi

    # ── PASS ─────────────────────────────────────────────────────────────────

    echo "PASS [chain/$proxy→$backend] real IP ≠ proxy IP (${proxy_ip:-unknown})"
    PASS=$((PASS + 1))
}

# ── Main ──────────────────────────────────────────────────────────────────────

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
