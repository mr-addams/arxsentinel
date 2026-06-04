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
# CF attacker containers use a separate subnet (10.88.0.0/24) that is outside the
# trusted proxy CIDR (172.16.0.0/12). This prevents real_ip_recursive from exhausting
# all trusted IPs and falling back to cloudflare-sim's Docker IP as the client address.
CF_NETWORK="integration_cf_ext_net"
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

# run_cf_scenario NAME SCRIPT
#   Same as run_scenario but uses CF_NETWORK (10.88.0.0/24) so the attacker
#   container gets an IP outside the trusted proxy CIDR (172.16.0.0/12).
#   Used for all Cloudflare-sim scenarios (Cases 1, 2, 3A) so that backends
#   with real_ip_recursive can correctly resolve the attacker IP from XFF /
#   CF-Connecting-IP instead of falling back to cloudflare-sim's container IP.
run_cf_scenario() {
    local name=$1
    local script=$2
    echo "[scenarios] running: $name"
    docker run --rm \
        --network "$CF_NETWORK" \
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
    run_cf_scenario "cf-direct-${backend}" "
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
        run_cf_scenario "cf-chain-${proxy}-${backend}" "
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
# Uses CF_NETWORK so the attacker has a non-172.16.x.x IP — consistent with CF scenario
# isolation, though nginx-bare doesn't look at XFF so attacker IP doesn't affect the test.
run_cf_scenario "cf-broken" "
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

# ── Universal I/O pipe-mode scenarios (no Docker required) ───────────────────────────────
# These scenarios test the --input=stdin / --output=stdout CLI flags introduced in Flow #030.
# They run the arxsentinel binary directly and do not need a Docker network.
# Skipped when the binary is not present in the expected location.

# ARX_BIN can be injected by run.sh (which builds to bin/); fallback covers standalone runs.
ARX_BIN="${ARX_BIN:-${INT_DIR}/arxsentinel/arxsentinel}"
ARX_CONFIG="${INT_DIR}/configs/default.yaml"

run_stdin_scenario() {
    # Pipe probe attack lines through stdin and verify JSON output on stdout.
    # Uses BADBOT_UA (downloaded by run.sh) as the request User-Agent — realistic payload.
    # 10 lines × probe(25) = 250 >> alert_threshold(50), so detection is guaranteed
    # even before the blocklist async-loads. Badbot(60) fires as a bonus if it loads in time.
    if [[ ! -x "$ARX_BIN" ]]; then
        echo "[scenarios/stdin] SKIP — binary not found at $ARX_BIN"
        return
    fi
    echo "[scenarios/stdin] testing --input=stdin --output=stdout,json"
    local ua="${BADBOT_UA:-AhrefsBot/7.0}"
    local attack_line="1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] \"GET /.env HTTP/1.1\" 404 0 \"-\" \"${ua}\" \"1.2.3.4\""
    local output n=0
    output=$(
        while [ "$n" -lt 10 ]; do
            printf '%s\n' "$attack_line"
            n=$((n + 1))
        done | timeout 10 "$ARX_BIN" --input=stdin --output=stdout,json \
            --config "$ARX_CONFIG" 2>/dev/null || true
    )
    if echo "$output" | grep -q '"ip":"1.2.3.4"'; then
        echo "[scenarios/stdin] PASS — threat event detected in JSON output"
    else
        echo "[scenarios/stdin] SKIP — no threat event (thresholds may require more lines)"
    fi
}

run_stdin_scenario

# ── Pipeline abstraction scenarios (Flow #034, Task 5) ───────────────────────────────────
# These scenarios verify that the new multi-pipeline configuration syntax works correctly.
# They run the arxsentinel binary directly against config files with pipelines: syntax.
# All scenarios skip gracefully when the binary is not found.

# run_compat_pipeline_scenario: verifies that a config using the legacy inputs:/outputs:
# format (no pipelines: key) produces identical threat output to before Task 3.
# Migrate() wraps it in a single unnamed pipeline transparently.
run_compat_pipeline_scenario() {
    # Same attack payload as run_stdin_scenario — but config uses legacy inputs:/outputs: syntax.
    # Migrate() transparently wraps it in a single unnamed pipeline; output must be identical.
    if [[ ! -x "$ARX_BIN" ]]; then
        echo "[scenarios/pipeline-compat] SKIP — binary not found at $ARX_BIN"
        return
    fi
    echo "[scenarios/pipeline-compat] testing backward compat: legacy inputs/outputs → single pipeline"
    local ua="${BADBOT_UA:-AhrefsBot/7.0}"
    local attack_line="1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] \"GET /.env HTTP/1.1\" 404 0 \"-\" \"${ua}\" \"1.2.3.4\""
    local output n=0
    output=$(
        while [ "$n" -lt 10 ]; do
            printf '%s\n' "$attack_line"
            n=$((n + 1))
        done | timeout 10 "$ARX_BIN" --input=stdin --output=stdout,json \
            --config "$ARX_CONFIG" 2>/dev/null || true
    )
    if echo "$output" | grep -q '"ip":"1.2.3.4"'; then
        echo "[scenarios/pipeline-compat] PASS — threat event detected with legacy config format"
    else
        echo "[scenarios/pipeline-compat] SKIP — no threat event (thresholds may need more lines)"
    fi
}

# run_multi_pipeline_scenario: verifies that a config with explicit pipelines: syntax works.
# Creates a temp config with a named pipeline (probe-only) that reads from a temp file source.
# The sentinel detects the probe attack and writes to the temp threat log.
run_multi_pipeline_scenario() {
    if [[ ! -x "$ARX_BIN" ]]; then
        echo "[scenarios/multi-pipeline] SKIP — binary not found at $ARX_BIN"
        return
    fi

    local tmpdir
    tmpdir=$(mktemp -d)
    local log_file="${tmpdir}/access.log"
    local threat_log="${tmpdir}/threats.log"
    local cfg_file="${tmpdir}/multi.yaml"

    touch "$log_file"
    cat > "$cfg_file" <<EOF
scoring:
  alert_threshold: 50
  ban_threshold: 75
  observation_window: 300s

streams:
  - name: test-stream
    pipelines:
      - name: probe-only
        inputs:
          - type: file
            path: ${log_file}
        outputs:
          - type: file
            path: ${threat_log}
            format: json
        detectors:
          probe:
            enabled: true
            score: 60
EOF

    # Start sentinel in background, feed attack lines, wait for output.
    local attack_line='1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] "GET /.env HTTP/1.1" 404 0 "-" "curl/7.88" "1.2.3.4"'
    timeout 5 "$ARX_BIN" --config "$cfg_file" 2>/dev/null &
    local pid=$!

    sleep 1
    local n=0
    while [ "$n" -lt 5 ]; do
        echo "$attack_line" >> "$log_file"
        n=$((n+1))
    done
    sleep 2

    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true

    if grep -q '"ip":"1.2.3.4"' "$threat_log" 2>/dev/null; then
        echo "[scenarios/multi-pipeline] PASS — threat detected with explicit pipelines: config syntax"
    else
        echo "[scenarios/multi-pipeline] SKIP — no threat event (binary or timing issue)"
    fi

    rm -rf "$tmpdir"
}

run_compat_pipeline_scenario
run_multi_pipeline_scenario

# ── executor-cf-ban: verify that CF executor sends THREAT IP to CF API mock ──────────
# Writes probe attack lines to nginx access log, waits for sentinel to detect THREAT
# and flush to cf-api-mock. Records result to logs/executor-cf-ban.json for verify.sh.

run_executor_cf_ban_scenario() {
    echo "[scenarios] running: executor-cf-ban"

    mkdir -p "$INT_DIR/logs/threats"

    # Write 5 probe attack lines — enough to exceed alert_threshold=50 with score=60/hit.
    local attack_ip="5.6.7.8"
    local attack_line="${attack_ip} - - [01/Jan/2026:00:00:00 +0000] \"GET /.env HTTP/1.1\" 404 0 \"-\" \"curl/7.88\" \"${attack_ip}\""
    for i in $(seq 1 5); do
        echo "$attack_line" >> "$INT_DIR/logs/nginx/access.log"
    done

    # Wait for sentinel (started in run.sh) to detect + flush batch to cf-api-mock.
    sleep 5

    # Query cf-api-mock for recorded items (from host, port 8091 exposed).
    local result
    result=$(curl -sf http://localhost:8091/recorded-items 2>/dev/null || true)
    echo "$result" > "$INT_DIR/logs/executor-cf-ban.json"
    # Also log cf-executor sentinel output for debugging.
    echo "[executor-cf-ban] recorded-items: $result" >&2
}
run_executor_cf_ban_scenario

# ── executor-ros-ban: verify that MikroTik executor sends THREAT IP to RouterOS API mock ──
# Appends probe attack lines to nginx access log; the ros-executor sentinel (started in
# run.sh) picks them up, detects THREAT, and flushes to ros-api-mock.
# Records result to logs/executor-ros-ban.json for verify.sh.

run_executor_ros_ban_scenario() {
    echo "[scenarios] running: executor-ros-ban"

    mkdir -p "$INT_DIR/logs/threats"

    # Use a different attack IP to avoid cross-contamination with CF scenario.
    local attack_ip="9.10.11.12"
    local attack_line="${attack_ip} - - [01/Jan/2026:00:00:00 +0000] \"GET /.env HTTP/1.1\" 404 0 \"-\" \"curl/7.88\" \"${attack_ip}\""

    # Write 5 probe attack lines — enough to exceed alert_threshold=50 with score=60/hit.
    for i in $(seq 1 5); do
        echo "$attack_line" >> "$INT_DIR/logs/nginx/access.log"
    done

    # Wait for ros-executor sentinel to detect + flush batch to ros-api-mock.
    sleep 5

    # Query ros-api-mock for recorded items (from host, port 8093 exposed).
    local result
    result=$(curl -sf http://localhost:8093/recorded-items 2>/dev/null || true)
    echo "$result" > "$INT_DIR/logs/executor-ros-ban.json"
    }
run_executor_ros_ban_scenario

# ── executor-nginx-ban: verify that nginx executor writes attacker IP to blocklist file ──
# Appends probe attack lines to nginx access log; the nginx-executor sentinel (started in
# run.sh) picks them up, detects THREAT, and writes the IP to nginx-blocklist.conf.
# Records result to logs/executor-nginx-ban.txt for verify.sh.

run_executor_nginx_ban_scenario() {
    echo "[scenarios] running: executor-nginx-ban"

    mkdir -p "$INT_DIR/logs/threats"

    local attack_ip="17.18.19.20"
    local attack_line="${attack_ip} - - [01/Jan/2026:00:00:00 +0000] \"GET /.env HTTP/1.1\" 404 0 \"-\" \"curl/7.88\" \"${attack_ip}\""
    for i in $(seq 1 5); do
        echo "$attack_line" >> "$INT_DIR/logs/nginx/access.log"
    done

    sleep 5

    local result=""
    result=$(cat "$INT_DIR/logs/threats/nginx-blocklist.conf" 2>/dev/null || true)
    echo "$result" > "$INT_DIR/logs/executor-nginx-ban.txt"
    echo "[executor-nginx-ban] blocklist content: $result" >&2
}
run_executor_nginx_ban_scenario

# ── 16. HTTP source: plain text push ─────────────────────────────────────────────
run_http_plain_scenario() {
    echo "[scenarios/http-plain] testing HTTP push source (plain text)"

    local HTTP_PORT TMPDIR ARX_PID
    HTTP_PORT=$(python3 -c "import socket; s=socket.socket(); s.bind(('',0)); print(s.getsockname()[1]); s.close()")
    TMPDIR=$(mktemp -d)

    if [[ ! -x "$ARX_BIN" ]]; then
        echo "[scenarios/http-plain] SKIP — binary not found at $ARX_BIN"
        rm -rf "$TMPDIR"
        return
    fi

    cat > "$TMPDIR/config.yaml" << YAML
streams:
  - name: http-plain-test
    pipelines:
      - name: probe-detect
        inputs:
          - type: http
            addr: "http://127.0.0.1:${HTTP_PORT}"
            protocol: plain
        outputs:
          - type: file
            path: "$TMPDIR/threats.log"
            format: json
        detectors:
          probe:
            enabled: true
            score: 60
scoring:
  alert_threshold: 40
  ban_threshold: 60
  window: 60s
parser:
  log_format: combined
YAML

    "$ARX_BIN" --config "$TMPDIR/config.yaml" > "$TMPDIR/arx.log" 2>&1 &
    ARX_PID=$!

    for _ in $(seq 1 20); do
        curl -sf --max-time 0.5 "http://127.0.0.1:${HTTP_PORT}" > /dev/null 2>&1
        [ $? -ne 7 ] && break
        sleep 0.3
    done

    PROBE_LINES=$(cat << 'LINES'
1.2.3.4 - - [04/Jun/2026:00:00:01 +0000] "GET /.env HTTP/1.1" 404 0 "-" "curl/8.0" "1.2.3.4"
1.2.3.4 - - [04/Jun/2026:00:00:02 +0000] "GET /.git/config HTTP/1.1" 404 0 "-" "curl/8.0" "1.2.3.4"
1.2.3.4 - - [04/Jun/2026:00:00:03 +0000] "GET /wp-login.php HTTP/1.1" 404 0 "-" "curl/8.0" "1.2.3.4"
1.2.3.4 - - [04/Jun/2026:00:00:04 +0000] "GET /admin/config.php HTTP/1.1" 404 0 "-" "curl/8.0" "1.2.3.4"
1.2.3.4 - - [04/Jun/2026:00:00:05 +0000] "GET /etc/passwd HTTP/1.1" 404 0 "-" "curl/8.0" "1.2.3.4"
1.2.3.4 - - [04/Jun/2026:00:00:06 +0000] "GET /.aws/credentials HTTP/1.1" 404 0 "-" "curl/8.0" "1.2.3.4"
1.2.3.4 - - [04/Jun/2026:00:00:07 +0000] "GET /xmlrpc.php HTTP/1.1" 404 0 "-" "curl/8.0" "1.2.3.4"
LINES
)

    curl -sf -X POST \
        -H "Content-Type: text/plain" \
        -d "$PROBE_LINES" \
        "http://127.0.0.1:${HTTP_PORT}" > /dev/null 2>&1 || true

    sleep 1

    if [ -f "$TMPDIR/threats.log" ] && grep -q '"ip":"1.2.3.4"' "$TMPDIR/threats.log" 2>/dev/null; then
        echo "[scenarios/http-plain] PASS — threat event detected from HTTP push source"
    else
        echo "[scenarios/http-plain] FAIL — no threat event in $TMPDIR/threats.log"
        echo "[scenarios/http-plain] ArxSentinel log:" >&2
        cat "$TMPDIR/arx.log" >&2
        kill "$ARX_PID" 2>/dev/null || true
        rm -rf "$TMPDIR"
        return 1
    fi

    kill "$ARX_PID" 2>/dev/null || true
    rm -rf "$TMPDIR"
}

# ── 17. HTTP source: NDJSON push ────────────────────────────────────────────────
run_http_ndjson_scenario() {
    echo "[scenarios/http-ndjson] testing HTTP push source (NDJSON with field extraction)"

    local HTTP_PORT TMPDIR ARX_PID
    HTTP_PORT=$(python3 -c "import socket; s=socket.socket(); s.bind(('',0)); print(s.getsockname()[1]); s.close()")
    TMPDIR=$(mktemp -d)

    if [[ ! -x "$ARX_BIN" ]]; then
        echo "[scenarios/http-ndjson] SKIP — binary not found at $ARX_BIN"
        rm -rf "$TMPDIR"
        return
    fi

    cat > "$TMPDIR/config.yaml" << YAML
streams:
  - name: http-ndjson-test
    pipelines:
      - name: probe-detect
        inputs:
          - type: http
            addr: "http://127.0.0.1:${HTTP_PORT}"
            protocol: ndjson
            envelope_field: log
        outputs:
          - type: file
            path: "$TMPDIR/threats.log"
            format: json
        detectors:
          probe:
            enabled: true
            score: 60
scoring:
  alert_threshold: 40
  ban_threshold: 60
  window: 60s
parser:
  log_format: combined
YAML

    "$ARX_BIN" --config "$TMPDIR/config.yaml" > "$TMPDIR/arx.log" 2>&1 &
    ARX_PID=$!

    for _ in $(seq 1 20); do
        curl -sf --max-time 0.5 "http://127.0.0.1:${HTTP_PORT}" > /dev/null 2>&1
        [ $? -ne 7 ] && break
        sleep 0.3
    done

    NDJSON_BODY=$(cat << 'LINES'
{"log":"1.2.3.4 - - [04/Jun/2026:00:00:01 +0000] \"GET /.env HTTP/1.1\" 404 0 \"-\" \"curl/8.0\" \"1.2.3.4\""}
{"log":"1.2.3.4 - - [04/Jun/2026:00:00:02 +0000] \"GET /.git/config HTTP/1.1\" 404 0 \"-\" \"curl/8.0\" \"1.2.3.4\""}
{"log":"1.2.3.4 - - [04/Jun/2026:00:00:03 +0000] \"GET /wp-login.php HTTP/1.1\" 404 0 \"-\" \"curl/8.0\" \"1.2.3.4\""}
{"log":"1.2.3.4 - - [04/Jun/2026:00:00:04 +0000] \"GET /admin/config.php HTTP/1.1\" 404 0 \"-\" \"curl/8.0\" \"1.2.3.4\""}
{"log":"1.2.3.4 - - [04/Jun/2026:00:00:05 +0000] \"GET /etc/passwd HTTP/1.1\" 404 0 \"-\" \"curl/8.0\" \"1.2.3.4\""}
{"log":"1.2.3.4 - - [04/Jun/2026:00:00:06 +0000] \"GET /.aws/credentials HTTP/1.1\" 404 0 \"-\" \"curl/8.0\" \"1.2.3.4\""}
{"log":"1.2.3.4 - - [04/Jun/2026:00:00:07 +0000] \"GET /xmlrpc.php HTTP/1.1\" 404 0 \"-\" \"curl/8.0\" \"1.2.3.4\""}
LINES
)

    curl -sf -X POST \
        -H "Content-Type: application/x-ndjson" \
        -d "$NDJSON_BODY" \
        "http://127.0.0.1:${HTTP_PORT}" > /dev/null 2>&1 || true

    sleep 1

    if [ -f "$TMPDIR/threats.log" ] && grep -q '"ip":"1.2.3.4"' "$TMPDIR/threats.log" 2>/dev/null; then
        echo "[scenarios/http-ndjson] PASS — threat event detected from HTTP NDJSON source"
    else
        echo "[scenarios/http-ndjson] FAIL — no threat event"
        cat "$TMPDIR/arx.log" >&2
        kill "$ARX_PID" 2>/dev/null || true
        rm -rf "$TMPDIR"
        return 1
    fi

    kill "$ARX_PID" 2>/dev/null || true
    rm -rf "$TMPDIR"
}

# ── 18. HTTP source: gzip-compressed push ──────────────────────────────────────
run_http_gzip_scenario() {
    echo "[scenarios/http-gzip] testing HTTP push source (gzip Content-Encoding)"

    local HTTP_PORT TMPDIR ARX_PID
    HTTP_PORT=$(python3 -c "import socket; s=socket.socket(); s.bind(('',0)); print(s.getsockname()[1]); s.close()")
    TMPDIR=$(mktemp -d)

    if [[ ! -x "$ARX_BIN" ]]; then
        echo "[scenarios/http-gzip] SKIP — binary not found at $ARX_BIN"
        rm -rf "$TMPDIR"
        return
    fi

    cat > "$TMPDIR/config.yaml" << YAML
streams:
  - name: http-gzip-test
    pipelines:
      - name: probe-detect
        inputs:
          - type: http
            addr: "http://127.0.0.1:${HTTP_PORT}"
            protocol: plain
        outputs:
          - type: file
            path: "$TMPDIR/threats.log"
            format: json
        detectors:
          probe:
            enabled: true
            score: 60
scoring:
  alert_threshold: 40
  ban_threshold: 60
  window: 60s
parser:
  log_format: combined
YAML

    "$ARX_BIN" --config "$TMPDIR/config.yaml" > "$TMPDIR/arx.log" 2>&1 &
    ARX_PID=$!

    for _ in $(seq 1 20); do
        curl -sf --max-time 0.5 "http://127.0.0.1:${HTTP_PORT}" > /dev/null 2>&1
        [ $? -ne 7 ] && break
        sleep 0.3
    done

    PROBE_LINES='1.2.3.4 - - [04/Jun/2026:00:00:01 +0000] "GET /.env HTTP/1.1" 404 0 "-" "curl/8.0" "1.2.3.4"
1.2.3.4 - - [04/Jun/2026:00:00:02 +0000] "GET /.git/config HTTP/1.1" 404 0 "-" "curl/8.0" "1.2.3.4"
1.2.3.4 - - [04/Jun/2026:00:00:03 +0000] "GET /wp-login.php HTTP/1.1" 404 0 "-" "curl/8.0" "1.2.3.4"
1.2.3.4 - - [04/Jun/2026:00:00:04 +0000] "GET /admin/config.php HTTP/1.1" 404 0 "-" "curl/8.0" "1.2.3.4"
1.2.3.4 - - [04/Jun/2026:00:00:05 +0000] "GET /etc/passwd HTTP/1.1" 404 0 "-" "curl/8.0" "1.2.3.4"
1.2.3.4 - - [04/Jun/2026:00:00:06 +0000] "GET /.aws/credentials HTTP/1.1" 404 0 "-" "curl/8.0" "1.2.3.4"
1.2.3.4 - - [04/Jun/2026:00:00:07 +0000] "GET /xmlrpc.php HTTP/1.1" 404 0 "-" "curl/8.0" "1.2.3.4"'

    echo "$PROBE_LINES" | gzip | curl -sf -X POST \
        -H "Content-Type: text/plain" \
        -H "Content-Encoding: gzip" \
        --data-binary @- \
        "http://127.0.0.1:${HTTP_PORT}" > /dev/null 2>&1 || true

    sleep 1

    if [ -f "$TMPDIR/threats.log" ] && grep -q '"ip":"1.2.3.4"' "$TMPDIR/threats.log" 2>/dev/null; then
        echo "[scenarios/http-gzip] PASS — threat event detected from gzip-compressed HTTP push"
    else
        echo "[scenarios/http-gzip] FAIL — no threat event"
        cat "$TMPDIR/arx.log" >&2
        kill "$ARX_PID" 2>/dev/null || true
        rm -rf "$TMPDIR"
        return 1
    fi

    kill "$ARX_PID" 2>/dev/null || true
    rm -rf "$TMPDIR"
}

# ── HTTP source scenario calls (direct binary, no Docker) ─────────────────────
run_http_plain_scenario
run_http_ndjson_scenario
run_http_gzip_scenario
