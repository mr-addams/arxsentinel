#!/usr/bin/env bash
# Integration test scenarios — one Docker container per detector.
#
# Each container gets a unique IP in the Docker network → clean state isolation
# in arxsentinel's IP tracker. No cross-contamination between detector tests.
#
# Detectors under test:
#   probe      — sensitive path access (/.env, /wp-login.php, ...)
#   ua         — scanner User-Agent (sqlmap)
#   bruteforce — 404 ratio > 60% over 10+ requests
#   crawler    — sequential numeric URLs (/items/1..6, min_sequential=5)
#   noasset    — page requests without loading CSS/JS assets
#   rate       — > 100 req/60s from one IP (requests span multiple log seconds)
#   overflow   — URL length > 2048 bytes
#   badbot     — community blocklist UA (mitchellkrogza real pattern, fetched by run.sh)

set -euo pipefail

INT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETWORK="integration_default"
IMAGE="curlimages/curl"   # Alpine-based, tiny, has /bin/sh

# Internal hostnames of the 6 servers (from inside the Docker network).
SERVERS=(nginx apache traefik caddy haproxy litespeed)

# Pull the attacker image once before the scenarios start.
docker pull -q "$IMAGE"

# run_scenario NAME SCRIPT
#   Runs SCRIPT inside a fresh container on the integration network.
#   Each call = new container = unique Docker IP = isolated tracker state.
run_scenario() {
    local name=$1
    local script=$2
    echo "[scenarios] running: $name"
    docker run --rm \
        --network "$NETWORK" \
        --entrypoint /bin/sh \
        --name "attacker-${name}-$$" \
        "$IMAGE" -c "$script"
}

# ── attack_all SERVER_LIST SCRIPT ────────────────────────────────────────────────────────
# Generates a script block that runs SCRIPT against every server in the list.
attack_all() {
    local inner=$1
    local script=""
    for srv in "${SERVERS[@]}"; do
        # Replace placeholder __SRV__ with the actual server hostname.
        script+="${inner//__SRV__/$srv}"$'\n'
    done
    echo "$script"
}

# ── 1. probe ─────────────────────────────────────────────────────────────────────────────
# Requests to well-known sensitive paths — each hit fires probe detector immediately.
run_scenario "probe" "$(attack_all '
    curl -sf -o /dev/null http://__SRV__/wp-login.php      || true
    curl -sf -o /dev/null http://__SRV__/.env              || true
    curl -sf -o /dev/null http://__SRV__/.git/config       || true
    curl -sf -o /dev/null http://__SRV__/admin/config.php  || true
    curl -sf -o /dev/null http://__SRV__/etc/passwd        || true
    curl -sf -o /dev/null http://__SRV__/.aws/credentials  || true
    curl -sf -o /dev/null http://__SRV__/xmlrpc.php        || true
')"

# ── 2. ua (useragent) ─────────────────────────────────────────────────────────────────────
# Scanner User-Agent to normal pages — ua detector fires on first request.
run_scenario "ua" "$(attack_all '
    curl -sf -o /dev/null -A "sqlmap/1.7.11"   http://__SRV__/     || true
    curl -sf -o /dev/null -A "sqlmap/1.7.11"   http://__SRV__/     || true
    curl -sf -o /dev/null -A "Nuclei/3.0"      http://__SRV__/     || true
    curl -sf -o /dev/null -A "masscan/1.3"     http://__SRV__/     || true
    curl -sf -o /dev/null -A "zgrab/0.x"       http://__SRV__/     || true
')"

# ── 3. bruteforce ─────────────────────────────────────────────────────────────────────────
# 15 requests, 12 to nonexistent paths (80% 404) — fires after min_requests=10 threshold.
run_scenario "bruteforce" "$(attack_all '
    curl -sf -o /dev/null http://__SRV__/                      || true
    curl -sf -o /dev/null http://__SRV__/                      || true
    curl -sf -o /dev/null http://__SRV__/                      || true
    curl -sf -o /dev/null http://__SRV__/missing-page-1        || true
    curl -sf -o /dev/null http://__SRV__/missing-page-2        || true
    curl -sf -o /dev/null http://__SRV__/missing-page-3        || true
    curl -sf -o /dev/null http://__SRV__/missing-page-4        || true
    curl -sf -o /dev/null http://__SRV__/missing-page-5        || true
    curl -sf -o /dev/null http://__SRV__/missing-page-6        || true
    curl -sf -o /dev/null http://__SRV__/missing-page-7        || true
    curl -sf -o /dev/null http://__SRV__/missing-page-8        || true
    curl -sf -o /dev/null http://__SRV__/missing-page-9        || true
    curl -sf -o /dev/null http://__SRV__/missing-page-10       || true
    curl -sf -o /dev/null http://__SRV__/missing-page-11       || true
    curl -sf -o /dev/null http://__SRV__/missing-page-12       || true
')"

# ── 4. crawler ────────────────────────────────────────────────────────────────────────────
# 6 consecutive numeric paths under the same prefix — fires at min_sequential=5.
# Paths return 404 (no /items/ in webapp) — crawler doesn't check status codes.
run_scenario "crawler" "$(attack_all '
    curl -sf -o /dev/null http://__SRV__/items/1  || true
    curl -sf -o /dev/null http://__SRV__/items/2  || true
    curl -sf -o /dev/null http://__SRV__/items/3  || true
    curl -sf -o /dev/null http://__SRV__/items/4  || true
    curl -sf -o /dev/null http://__SRV__/items/5  || true
    curl -sf -o /dev/null http://__SRV__/items/6  || true
')"

# ── 5. noasset ────────────────────────────────────────────────────────────────────────────
# 8 HTML page requests, zero asset requests.
# assetRatio = 0% < threshold 10% → fires after min_page_requests=3.
run_scenario "noasset" "$(attack_all '
    curl -sf -o /dev/null http://__SRV__/           || true
    curl -sf -o /dev/null http://__SRV__/           || true
    curl -sf -o /dev/null http://__SRV__/           || true
    curl -sf -o /dev/null http://__SRV__/info.php   || true
    curl -sf -o /dev/null http://__SRV__/           || true
    curl -sf -o /dev/null http://__SRV__/           || true
    curl -sf -o /dev/null http://__SRV__/info.php   || true
    curl -sf -o /dev/null http://__SRV__/           || true
')"

# ── 6. rate ───────────────────────────────────────────────────────────────────────────────
# 60 requests in two bursts with a 1s gap → log timestamps span 2+ seconds.
# ApproxRate = ~30 req/s >> threshold (100/60 = 1.67 req/s).
run_scenario "rate" "$(attack_all '
    i=0; while [ $i -lt 30 ]; do
        curl -sf -o /dev/null http://__SRV__/ || true
        i=$((i+1))
    done
    sleep 1
    i=0; while [ $i -lt 30 ]; do
        curl -sf -o /dev/null http://__SRV__/ || true
        i=$((i+1))
    done
')"

# ── 7. overflow ───────────────────────────────────────────────────────────────────────────
# Single request with URL path > 2048 bytes — fires immediately.
# Generate a 2200-char alphanumeric path.
# /dev/urandom is ~24% alphanumeric, so we read 20000 bytes to guarantee 2200 clean chars.
# pipefail is disabled inside $() because head -c 2200 closes stdin before tr finishes
# reading — SIGPIPE on tr is expected and benign. 2>/dev/null suppresses the stderr message.
LONG_PATH="/$(set +o pipefail; head -c 20000 /dev/urandom | tr -dc 'a-zA-Z0-9' 2>/dev/null | head -c 2200)"
run_scenario "overflow" "$(attack_all "
    curl -sf -o /dev/null 'http://__SRV__${LONG_PATH}' || true
")"

# ── 8. badbot ────────────────────────────────────────────────────────────────────────
# Request with a real bad-bot User-Agent fetched from upstream by run.sh.
# The blocklist automaton is built from the same file, so the match is guaranteed.
# Placed last among direct-server scenarios to give sentinels time to load patterns
# from the local blocklist-server container before the request arrives.
BADBOT_UA=$(cat "$INT_DIR/blocklist/test-ua.txt" 2>/dev/null || echo "AhrefsBot")
run_scenario "badbot" "$(attack_all "
    curl -sf -o /dev/null -A '${BADBOT_UA}/1.0' http://__SRV__/ || true
    curl -sf -o /dev/null -A '${BADBOT_UA}/1.0' http://__SRV__/ || true
")"

# ── 9. proxy-chain ───────────────────────────────────────────────────────────────────────
# For each proxy × backend combination: send probe requests through the proxy.
# Each run_scenario call = new Docker container = unique attacker IP.
# Verifies that sentinel's threat log shows the attacker IP, not the proxy IP.
#
# Proxies route /backend-<name>/ to the corresponding backend (prefix is stripped).
# The real attacker IP is forwarded via X-Forwarded-For.
CHAIN_PROXIES=(
    "traefik:80"
    "caddy:80"
    "haproxy:80"
    "nginx-rp:80"
)
CHAIN_BACKENDS=(nginx apache traefik caddy haproxy litespeed)

for proxy_spec in "${CHAIN_PROXIES[@]}"; do
    proxy_name="${proxy_spec%%:*}"
    proxy_port="${proxy_spec##*:}"
    for backend in "${CHAIN_BACKENDS[@]}"; do
        # Build the probe script for this (proxy, backend) pair.
        # All requests go to the same proxy host on the same port — no __SRV__ loop needed.
        chain_script="
curl -sf -o /dev/null 'http://${proxy_name}:${proxy_port}/backend-${backend}/wp-login.php'    || true
curl -sf -o /dev/null 'http://${proxy_name}:${proxy_port}/backend-${backend}/.env'            || true
curl -sf -o /dev/null 'http://${proxy_name}:${proxy_port}/backend-${backend}/.git/config'     || true
curl -sf -o /dev/null 'http://${proxy_name}:${proxy_port}/backend-${backend}/admin/login.php' || true
curl -sf -o /dev/null 'http://${proxy_name}:${proxy_port}/backend-${backend}/xmlrpc.php'      || true
"
        run_scenario "chain-${proxy_name}-${backend}" "$chain_script"
    done
done

# ── 10. Cloudflare Case 1: CF → product directly ─────────────────────────────────────────
# cloudflare-sim acts as Cloudflare edge: replaces X-Forwarded-For with $remote_addr and
# adds CF-Connecting-IP. Each backend must extract the real IP from these headers.
# Uses the same *-backend services as proxy-chain tests (nginx:8080, apache-proxy:80, etc.)
# so the proxy-chain sentinels capture the entries — no new sentinels needed.
CF_BACKENDS=(nginx apache traefik caddy haproxy litespeed)

for backend in "${CF_BACKENDS[@]}"; do
    run_scenario "cf-direct-${backend}" "
        curl -sf -o /dev/null 'http://cloudflare-sim:80/cf-${backend}/wp-login.php'    || true
        curl -sf -o /dev/null 'http://cloudflare-sim:80/cf-${backend}/.env'            || true
        curl -sf -o /dev/null 'http://cloudflare-sim:80/cf-${backend}/.git/config'     || true
        curl -sf -o /dev/null 'http://cloudflare-sim:80/cf-${backend}/admin/login.php' || true
        curl -sf -o /dev/null 'http://cloudflare-sim:80/cf-${backend}/xmlrpc.php'      || true
    "
done

# ── 11. Cloudflare Case 2: CF → our proxy → product ─────────────────────────────────────
# Two-hop chain: cloudflare-sim sets CF headers, then one of our configured proxies
# forwards the request to the backend. The backend must survive both hops and log the
# original attacker IP rather than the cloudflare-sim or proxy IP.
CF_CHAIN_PROXIES=(traefik caddy haproxy nginx-rp)
CF_CHAIN_BACKENDS=(nginx apache traefik caddy haproxy litespeed)

for proxy in "${CF_CHAIN_PROXIES[@]}"; do
    for backend in "${CF_CHAIN_BACKENDS[@]}"; do
        run_scenario "cf-chain-${proxy}-${backend}" "
            curl -sf -o /dev/null 'http://cloudflare-sim:80/cf-chain-${proxy}/backend-${backend}/wp-login.php' || true
            curl -sf -o /dev/null 'http://cloudflare-sim:80/cf-chain-${proxy}/backend-${backend}/.env'        || true
            curl -sf -o /dev/null 'http://cloudflare-sim:80/cf-chain-${proxy}/backend-${backend}/xmlrpc.php'  || true
        "
    done
done

# ── 12. Chain guard: broken chain + bogon injection (Case 3) ─────────────────────────────
# 3A: cloudflare-sim → nginx-bare (nginx-bare has no real_ip_header — logs cloudflare-sim
#     container IP). The cf-broken sentinel must detect that IP as Cloudflare range and
#     write cloudflare-ip-as-client to warnings/cf-broken.log.
run_scenario "cf-broken" "
    curl -sf -o /dev/null 'http://cloudflare-sim:80/cf-bare/wp-login.php' || true
    curl -sf -o /dev/null 'http://cloudflare-sim:80/cf-bare/.env'         || true
"

# 3B: bogon-injector sets X-Forwarded-For: 10.0.0.1 before forwarding to nginx-bogon-victim.
#     nginx-bogon-victim trusts XFF from the Docker subnet and logs 10.0.0.1 as client IP.
#     The bogon-victim sentinel must detect 10.0.0.1 as RFC 1918 bogon and write
#     bogon-ip-as-client to warnings/bogon-victim.log.
run_scenario "bogon-injection" "
    curl -sf -o /dev/null 'http://bogon-injector:80/wp-login.php' || true
    curl -sf -o /dev/null 'http://bogon-injector:80/.env'         || true
"

echo "[scenarios] all scenarios done"
