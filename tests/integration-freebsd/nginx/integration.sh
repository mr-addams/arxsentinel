#!/usr/bin/env sh
# tests/integration-freebsd/nginx/integration.sh — Flow 089 integration
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
#
# This script lives at tests/integration-freebsd/nginx/integration.sh — three
# path segments below the repo root, so dirname($0) needs three "../" to
# reach it (NOT two, which is what 088's tests/integration-freebsd/
# run-smoke.sh used, since that script is only two segments deep).
# ---------------------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
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
# Chain-scenario markers (Steps 10-15). Separate from the direct-scenario
# vars above so a failure in Step 3 cleanup() still leaves the chain
# cleanup code paths exercised (and vice versa). Empty defaults keep the
# trap idempotent if the chain section is never reached.
CHAIN_NETWORK="arx-chain-net"
NGINX_CHAIN_CID=""
NGINX_RP_CID=""

cleanup() {
    if [ -n "$NGINX_CID" ]; then
        podman rm -f "$NGINX_CID" >/dev/null 2>&1 || true
    fi
    if [ -n "$NGINX_CHAIN_CID" ]; then
        podman rm -f "$NGINX_CHAIN_CID" >/dev/null 2>&1 || true
    fi
    if [ -n "$NGINX_RP_CID" ]; then
        podman rm -f "$NGINX_RP_CID" >/dev/null 2>&1 || true
    fi
    # CNI networks do not auto-GC on job exit (DECISIONS §3 consequences):
    # remove the networks explicitly. Both direct and chain networks
    # are unconditionally attempted — podman network rm on a missing
    # network exits non-zero, hence the || true (matches the original
    # direct-scenario pattern).
    podman network rm "$NETWORK" >/dev/null 2>&1 || true
    podman network rm "$CHAIN_NETWORK" >/dev/null 2>&1 || true
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
# --name nginx is kept for operator convenience (`podman logs nginx`,
# `podman exec nginx ...` below) but is NOT used as a DNS name by the
# curl attacker — step 6 resolves the container's CNI IP via `podman
# inspect` instead, since the FreeBSD CNI bridge plugin has no
# dnsname resolver (see step 6's comment for the live-run finding).
#
# Fully-qualified docker.io/library/nginx:alpine (NOT bare nginx:alpine):
# the FreeBSD podman default /usr/local/share/containers/registries.conf
# has no unqualified-search-registries entry, so a short name fails with
# "did not resolve to an alias and no unqualified-search registries are
# defined" (same class of bug as Flow 088 Decision F.4 — alpine short-name
# fix in podman-spike step 5).
#
# --os=linux is REQUIRED: nginx:alpine's OCI image index has no
# "freebsd" OS variant, only linux/*. Without --os=linux, podman on
# FreeBSD defaults to looking for a freebsd-OS manifest and fails with
# "no image found in image index for architecture amd64 ... OS freebsd"
# (same flag Flow 088 podman-spike step 5 used for docker.io/alpine).
# ---------------------------------------------------------------------
echo "[nginx] starting nginx container..."
NGINX_CID=$(podman run -d \
    --os=linux \
    --name nginx \
    --network "$NETWORK" \
    -v "$WORK_DIR/nginx.conf:/etc/nginx/nginx.conf:ro" \
    -v "$WORK_DIR/nginx:/var/log/nginx" \
    docker.io/library/nginx:alpine)
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

# ---------------------------------------------------------------------
# Step 6: drive attacks from a curl container. DECISIONS §3 said the
# curl container could resolve "nginx" via container DNS — live run
# 28476909225 disproved that: nginx started fine and TailReader was
# watching, but access.log stayed empty and curl exited non-zero. The
# FreeBSD `containernetworking-plugins` port ships the basic CNI
# bridge plugin only, NOT a dnsname plugin (that is what provides
# container-name DNS resolution on a CNI bridge network; podman on
# Linux gets this for free from netavark+aardvark-dns, which FreeBSD
# podman does not use). Resolve the nginx container's CNI IP via
# `podman inspect` instead of relying on DNS, and use the IP directly
# in the curl URL — this departs from DECISIONS §3's stated mechanism
# but keeps its consequence (same-IP-for-both-requests, UA-selective
# grader) intact.
# ---------------------------------------------------------------------
SQLMAP_UA='sqlmap/1.7.11'
MOZILLA_UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'

# `index` (not dot-notation) is REQUIRED: $NETWORK contains a hyphen
# ("arx-net"), and a Go template map-key access via dot-notation
# (.Networks.arx-net.IPAddress) parses the hyphen as a subtraction
# operator and fails with "bad character U+002D '-'" (live run
# 28477133986 hit this exact error). `index` takes the key as a
# string argument, sidestepping Go template identifier syntax rules.
NGINX_IP=$(podman inspect nginx --format "{{(index .NetworkSettings.Networks \"${NETWORK}\").IPAddress}}")
if [ -z "$NGINX_IP" ]; then
    echo "[nginx] FAIL: could not resolve nginx container's CNI IP via podman inspect" >&2
    exit 1
fi
echo "[nginx] nginx container IP: $NGINX_IP"

# Generate the long URL path for the overflow scenario (block 7) on
# the HOST (not inside the curl container) so the value can be
# embedded as a literal in the -c "..." script string below.
#
# NOT scenarios.sh:169's `/dev/urandom | tr -dc 'a-zA-Z0-9'` recipe:
# live run 28587170404 found it produces EMPTY output on this FreeBSD
# VM's native sh — LONG_PATH came out as "/" (1 byte), so the overflow
# detector (which only checks byte length, not content — see
# pkg/detectorplugins/overflow/overflow.go's ALGORITHM comment) never
# fired. Root cause not pinned down further (FreeBSD's tr(1) vs GNU
# tr, or /dev/urandom access under the vmactions SSH session — either
# way, not worth chasing since the detector doesn't need randomness).
# `awk` generates a deterministic 2200-char string in one process,
# POSIX-standard and present on every FreeBSD base install — no
# /dev/urandom or tr(1) portability surface at all.
LONG_PATH="/$(awk 'BEGIN { s = ""; for (i = 0; i < 2200; i++) s = s "a"; print s }')"
# Diagnostic (live run 28585617384 found the overflow assertion failing
# with no obvious quoting bug on static read) — print the byte length so
# a re-dispatch can confirm/rule out FreeBSD's tr(1) behaving differently
# from scenarios.sh's Linux/GNU-tr assumption for `-dc 'a-zA-Z0-9'`.
echo "[nginx] LONG_PATH length: $(printf '%s' "$LONG_PATH" | wc -c) bytes"

# Pick the badbot UA the same way scenarios.sh:179 does: prefer the
# committed test fixture ($REPO_ROOT/tests/integration/blocklist/
# test-ua.txt) because it is the same file run.sh:122 produces from
# the FIRST literal pattern in the upstream mitchellkrogza list — a
# pattern the FreeBSD sentinel's blocklist automaton will also load
# (same upstream URL, see sentinel-nginx.yaml blocklist.lists[0].
# sources[0].url). Fallback "AhrefsBot/1.0" matches scenarios.sh:179
# — a UA guaranteed to be in the upstream list as a regex literal
# (AhrefsBot appears unescaped near the top of bad-user-agents.list).
if [ -s "$REPO_ROOT/tests/integration/blocklist/test-ua.txt" ]; then
    BADBOT_UA=$(head -1 "$REPO_ROOT/tests/integration/blocklist/test-ua.txt")
else
    BADBOT_UA="AhrefsBot"
fi
echo "[nginx] using badbot UA for block 8: ${BADBOT_UA}/1.0"

echo "[nginx] driving 8 attack blocks from a single curl container..."
# Fully-qualified docker.io/curlimages/curl (NOT bare curlimages/curl) —
# same short-name resolution issue as the nginx image above. --os=linux —
# same image-index reasoning as the nginx container above (curlimages/curl
# has no freebsd OS variant either).
#
# ONE curl container for ALL 8 blocks (NOT one per block) — the
# detectors under test (bruteforce, crawler, noasset, rate) are
# per-IP trackers. Multiple containers would mean multiple attacker
# IPs, and each detector would see only a fraction of the required
# request count → no fire → no threat log entry → false-negative
# assertion. This is the same collapse battle-suite's attack_all
# does: scenarios.sh:80-183 wraps each block in a SERVERS[] loop
# (one container per server, but all blocks within a single server
# run from the same container). We have one server, so the SERVERS[]
# loop collapses to a single container. The Mozilla UA legit request
# is folded into block 2 (ua) as the last request of that block —
# it must share the attacker's IP (it does, single container) and
# must come AFTER the scanner-UA hits so the scorer's per-IP state
# for that client already has the ua module in its reason list
# (Mozilla then either drops the score below threshold or simply
# doesn't add a new module — the assertion is that the Mozilla UA
# string itself is absent from the threat log, not that the IP
# isn't there).
#
# The 8 blocks are verbatim ports from tests/integration/
# scenarios.sh:80-183 (per Flow 092 Decision 7 — close the Flow
# 091 Decision 9 gap). Each block's source line is annotated below
# in the same WHY comment style as the rest of this file.
ATTACK_SCRIPT="
# ── block 1: probe (scenarios.sh:82-90) ──
curl -sf -o /dev/null http://${NGINX_IP}/wp-login.php      || true
curl -sf -o /dev/null http://${NGINX_IP}/.env              || true
curl -sf -o /dev/null http://${NGINX_IP}/.git/config       || true
curl -sf -o /dev/null http://${NGINX_IP}/admin/config.php  || true
curl -sf -o /dev/null http://${NGINX_IP}/etc/passwd        || true
curl -sf -o /dev/null http://${NGINX_IP}/.aws/credentials  || true
curl -sf -o /dev/null http://${NGINX_IP}/xmlrpc.php        || true
# ── block 2: ua (scenarios.sh:94-100) + the legit Mozilla request ──
curl -sf -o /dev/null -A '${SQLMAP_UA}'     http://${NGINX_IP}/ || true
curl -sf -o /dev/null -A '${SQLMAP_UA}'     http://${NGINX_IP}/ || true
curl -sf -o /dev/null -A 'Nuclei/3.0'       http://${NGINX_IP}/ || true
curl -sf -o /dev/null -A 'masscan/1.3'      http://${NGINX_IP}/ || true
curl -sf -o /dev/null -A 'zgrab/0.x'        http://${NGINX_IP}/ || true
# Legit Mozilla request — kept in block 2 (NOT a separate block)
# because Assertion 2 (Mozilla UA absent from threat log) only
# makes sense in the context of the scanner-UA attack on the same
# IP. If Mozilla were in its own block AFTER all scanners, the
# scorer's per-IP state for this client would have already been
# written to the threat log with the sqlmap IP; sending a Mozilla
# request on a fresh connection (or with a different effective
# source) would muddle the test.
curl -sf -o /dev/null -A '${MOZILLA_UA}'   http://${NGINX_IP}/ || true
# ── block 3: bruteforce (scenarios.sh:104-120) ──
curl -sf -o /dev/null http://${NGINX_IP}/                      || true
curl -sf -o /dev/null http://${NGINX_IP}/                      || true
curl -sf -o /dev/null http://${NGINX_IP}/                      || true
curl -sf -o /dev/null http://${NGINX_IP}/missing-page-1        || true
curl -sf -o /dev/null http://${NGINX_IP}/missing-page-2        || true
curl -sf -o /dev/null http://${NGINX_IP}/missing-page-3        || true
curl -sf -o /dev/null http://${NGINX_IP}/missing-page-4        || true
curl -sf -o /dev/null http://${NGINX_IP}/missing-page-5        || true
curl -sf -o /dev/null http://${NGINX_IP}/missing-page-6        || true
curl -sf -o /dev/null http://${NGINX_IP}/missing-page-7        || true
curl -sf -o /dev/null http://${NGINX_IP}/missing-page-8        || true
curl -sf -o /dev/null http://${NGINX_IP}/missing-page-9        || true
curl -sf -o /dev/null http://${NGINX_IP}/missing-page-10       || true
curl -sf -o /dev/null http://${NGINX_IP}/missing-page-11       || true
curl -sf -o /dev/null http://${NGINX_IP}/missing-page-12       || true
# ── block 4: crawler (scenarios.sh:126-132) ──
curl -sf -o /dev/null http://${NGINX_IP}/items/1  || true
curl -sf -o /dev/null http://${NGINX_IP}/items/2  || true
curl -sf -o /dev/null http://${NGINX_IP}/items/3  || true
curl -sf -o /dev/null http://${NGINX_IP}/items/4  || true
curl -sf -o /dev/null http://${NGINX_IP}/items/5  || true
curl -sf -o /dev/null http://${NGINX_IP}/items/6  || true
# ── block 5: noasset (scenarios.sh:138-146) ──
curl -sf -o /dev/null http://${NGINX_IP}/           || true
curl -sf -o /dev/null http://${NGINX_IP}/           || true
curl -sf -o /dev/null http://${NGINX_IP}/           || true
curl -sf -o /dev/null http://${NGINX_IP}/info.php   || true
curl -sf -o /dev/null http://${NGINX_IP}/           || true
curl -sf -o /dev/null http://${NGINX_IP}/           || true
curl -sf -o /dev/null http://${NGINX_IP}/info.php   || true
curl -sf -o /dev/null http://${NGINX_IP}/           || true
# ── block 6: rate (scenarios.sh:151-161) — 60 requests in 2 waves with 1s gap ──
i=0; while [ \$i -lt 30 ]; do
    curl -sf -o /dev/null http://${NGINX_IP}/ || true
    i=\$((i+1))
done
sleep 1
i=0; while [ \$i -lt 30 ]; do
    curl -sf -o /dev/null http://${NGINX_IP}/ || true
    i=\$((i+1))
done
# ── block 7: overflow (scenarios.sh:169-172) — single URL with path > 2048 bytes ──
curl -sf -o /dev/null 'http://${NGINX_IP}${LONG_PATH}' || true
# ── block 8: badbot (scenarios.sh:180-183) — LAST on purpose ──
# scenarios.sh:177-178: 'Placed last among direct-server scenarios to
# give sentinels time to load patterns from the local blocklist-server
# container before the request arrives.' The same reasoning applies
# here even though we fetch directly from upstream (the fetch is async
# from start, and the automaton rebuild happens on the first successful
# fetch — putting badbot last gives the blocklist manager the most
# wall-clock time to complete that fetch + rebuild cycle before the
# first matching request hits). Two requests, not one, for the same
# threshold-crossing reason as the sqlmap pair in block 2 (the badbot
# detector's first hit may not cross the alert threshold on its own).
curl -sf -o /dev/null -A '${BADBOT_UA}/1.0' http://${NGINX_IP}/ || true
curl -sf -o /dev/null -A '${BADBOT_UA}/1.0' http://${NGINX_IP}/ || true
"

podman run --rm --os=linux --network "$NETWORK" \
    --entrypoint /bin/sh \
    docker.io/curlimages/curl \
    -c "$ATTACK_SCRIPT" \
    >/dev/null 2>&1 \
    || echo "[nginx] curl attacker exited non-zero (still check the access log)"
echo "[nginx] attacks sent"

# ---------------------------------------------------------------------
# Step 7: poll the threat log for non-empty content.
# Timeout RAISED from 20s → 40s as part of Task A1 (Flow 092
# Decision 7): the previous 3-request Step 6 finished in <1s of
# attack traffic; the new 8-block Step 6 sends ~7 + 6 + 15 + 6 + 8
# + 60 + 1 + 2 = 105 attack requests, with the rate block's 1s
# sleep and the sentinel's per-request scoring adding wall-clock
# cost on top. 40s is a conservative budget for the polling loop
# (the actual elapsed time in CI is typically 3-5s, the rest is
# margin for first-podman-pull + cold blocklist-fetch). Mirrors
# 088 run-smoke.sh step 5 (which uses 20s for its much smaller
# request set).
# ---------------------------------------------------------------------
THREAT_LOG="$WORK_DIR/output/threats-nginx.log"
echo "[nginx] polling $THREAT_LOG (timeout 40s)..."
DEADLINE=$(($(date +%s) + 40))
WRITTEN=0
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    if [ -s "$THREAT_LOG" ]; then
        WRITTEN=1
        break
    fi
    sleep 1
done
if [ "$WRITTEN" -ne 1 ]; then
    echo "[nginx] FAIL: $THREAT_LOG not written within 40s" >&2
    echo "[nginx] access log content (if any):" >&2
    cat "$WORK_DIR/nginx/access.log" >&2 || true
    echo "[nginx] sentinel log (last 80 lines):" >&2
    tail -80 "$WORK_DIR/sentinel-nginx.log" >&2 || true
    exit 1
fi

# Dump the threat log for inline visibility.
LINES=$(cat "$THREAT_LOG")
echo "[nginx] threat log content:"
printf '%s\n' "$LINES" | sed 's/^/  /'

# ---------------------------------------------------------------------
# Step 7a: extract the sqlmap-request source IP from the access log.
# DECISIONS §5 — the attacker's source IP is the curl container's
# CNI-assigned IP, which appears in access.log as the first field
# of the line containing the sqlmap UA. We extract that IP here
# (once) so assertions 1 and 2 below can use it.
# ---------------------------------------------------------------------
ACCESS_LOG="$WORK_DIR/nginx/access.log"
if [ ! -s "$ACCESS_LOG" ]; then
    echo "[nginx] FAIL: access log empty or missing at $ACCESS_LOG" >&2
    exit 1
fi
# grep the sqlmap UA (literal, no regex specials) then awk the first
# field. Safe even if the UA contains regex chars — grep treats it
# as a fixed string in this case (no -E flag).
SQLMAP_IP=$(grep "${SQLMAP_UA}" "$ACCESS_LOG" | awk '{print $1}' | head -1)
if [ -z "$SQLMAP_IP" ]; then
    echo "[nginx] FAIL: could not extract sqlmap request IP from access log" >&2
    echo "[nginx] access log content:" >&2
    cat "$ACCESS_LOG" >&2 || true
    exit 1
fi
echo "[nginx] sqlmap request source IP: $SQLMAP_IP"

# Diagnostic (live run 28585617384 — overflow assertion failing, LONG_PATH
# byte-length echoed near generation to compare against this): print the
# access-log line matching the long-path request, and its request-field
# byte length, to see what nginx actually logged for it (full URI vs
# truncated vs never received).
OVERFLOW_LOG_LINE=$(grep -E '"GET /[a-zA-Z0-9]{100,}' "$ACCESS_LOG" | head -1)
if [ -n "$OVERFLOW_LOG_LINE" ]; then
    echo "[nginx] overflow request access-log line length: $(printf '%s' "$OVERFLOW_LOG_LINE" | wc -c) bytes"
else
    echo "[nginx] overflow request NOT FOUND in access log (long-path GET never logged)"
fi

# ---------------------------------------------------------------------
# Step 7b: assertions. Originally 3 per DECISIONS §5 (adapted from
# 088 run-smoke.sh — UA-based, not IP-based). EXTENDED to 12 per
# Flow 092 Task A1 / Decision 7: 1-3 retained, 4-10 are one
# `grep -qw "reason=<module>"` per attack scenario (mirrors
# tests/integration/verify.sh:144 assert_module's exact grep
# pattern), 11 is badbot UA presence, 12 is the blocklist
# automaton-loaded check (mirrors verify.sh:109
# assert_blocklist_loaded's exact regex). A single FAIL on any
# assertion sets FAIL=1; the script reports all at the end
# (does not short-circuit, so the grader can see the full failure
# shape).
# ---------------------------------------------------------------------
FAIL=0

# Assertion 1: ` THREAT ` substring AND sqlmap-attack source IP
# appear in the threat log. (088 run-smoke.sh assertion 1 with the
# IP extracted from access.log, NOT a fixed literal.) The sqlmap
# request from block 2 of Step 6 still appears in the access log
# (the curl container shares one IP across all 8 blocks), so the
# IP extracted in Step 7a is the curl container's CNI IP, which is
# the same IP attributed to the threat log entry that fired the ua
# module — the assertion remains meaningful.
if ! printf '%s\n' "$LINES" | grep -q " THREAT " \
   || ! printf '%s\n' "$LINES" | grep -q " $SQLMAP_IP "; then
    echo "[nginx] FAIL: assertion 1 - expected ' THREAT ' and IP '$SQLMAP_IP' in threat log" >&2
    FAIL=1
fi

# Assertion 2: Mozilla UA does NOT appear in the threat log.
# DEPARTURE FROM 088 run-smoke.sh assertion 2 (which used a legit
# IP-absent check): all curl requests share the curl container's
# CNI IP (single container for all 8 blocks — see Step 6), so
# IP-based legit-vs-attacker discrimination does not work. Instead
# we assert the Mozilla UA itself is absent — a stricter test of
# UA-selectivity (the detector must score on UA, not just on the
# request itself). The Mozilla request is folded into block 2 of
# Step 6, AFTER the scanner-UA hits on the same IP, so if the
# scorer were naively tagging every request from that IP, the
# Mozilla request would inherit the threat-log entry; absence
# proves the scorer actually discriminates on UA.
if printf '%s\n' "$LINES" | grep -q "${MOZILLA_UA}"; then
    echo "[nginx] FAIL: assertion 2 - false positive: Mozilla UA appeared in threat log" >&2
    FAIL=1
fi

# Assertion 3: every non-empty threat line has score= AND reason=
# (Fail2Ban-like format). Identical to 088 run-smoke.sh assertion 3.
# non-empty lines WITHOUT both markers → BAD_COUNT > 0 → fail.
# `|| true` on the grep -cv because an all-matching input exits 1
# (no matches for the negative pattern) which would short-circuit
# set -e.
BAD_COUNT=$(printf '%s\n' "$LINES" | grep -v '^$' | grep -cv 'score=.*reason=' || true)
if [ "$BAD_COUNT" -gt 0 ]; then
    echo "[nginx] FAIL: assertion 3 - $BAD_COUNT threat line(s) missing score=/reason=" >&2
    FAIL=1
fi

# Assertions 4-10: one `grep -qw "reason=<module>"` per attack
# scenario, mirroring tests/integration/verify.sh:144 assert_module's
# exact pattern (`grep -qw "$module" "$threat_log"`). The format in
# the threat log is `reason="<module>:<detail>:<count>,..."` (per
# internal/threat/format/format.go:110 — `<timestamp> THREAT <ip>
# score=<N> modules=<list> reason="%s"`; example line from
# format_test.go:43: `... reason="probe:env:3,bad_bot:known"`).
# `grep -qw "probe"` matches the `probe` token at the start of
# `reason="probe:env:3"` because both `"` and `:` are non-word
# characters and therefore act as word boundaries for `-w`. The
# same pattern assert_module uses, same word-boundary semantics,
# same fail-on-miss behaviour. If a module fires but its name does
# not appear in the threat log (e.g. scorer dropped it under the
# alert threshold), this assertion catches that case explicitly,
# block by block.
for module in probe ua bruteforce crawler noasset rate overflow; do
    if ! printf '%s\n' "$LINES" | grep -qw "$module"; then
        echo "[nginx] FAIL: assertion - expected module '$module' in threat log (reason=)" >&2
        FAIL=1
    fi
done

# Assertion 11: the badbot MODULE fired. Checked on the module name
# (`badbot`), NOT on the upstream pattern string (`$BADBOT_UA`)
# — the badbot detector's matching path is case-insensitive
# (`strings.ToLower` in pkg/detectorplugins/badbot/badbot.go and in
# internal/core/blocklist/parser.go), so the pattern it writes to
# the threat log's `reason=` field is always lowercase
# (e.g. `360spider`, not `360Spider`); grep'ing for the original
# `BADBOT_UA` value as-shipped would case-miss every time. The
# module name `badbot` is the contract, mirrors the
# `assert_module "$srv" "badbot"` call at tests/integration/
# verify.sh:444 (battle-suite parity), and is consistent with
# Assertions 4-10 above (also `grep -qw "<module>"`).
if ! printf '%s\n' "$LINES" | grep -qw "badbot"; then
    echo "[nginx] FAIL: assertion 11 - badbot module not in threat log (expected reason=badbot:...)" >&2
    FAIL=1
fi

# Assertion 12: blocklist automaton actually loaded patterns (N > 0).
# Greps the SENTINEL'S OPERATIONAL LOG (not the threat log) for the
# line emitted by internal/core/blocklist/manager.go:393
# (`utils.Log("BLOCKLIST", fmt.Sprintf("list %q: automaton
# rebuilt (%d patterns)", cfg.Name, len(all)), "info")`). The exact
# regex `automaton rebuilt \([1-9][0-9]* patterns\)` is copied
# verbatim from tests/integration/verify.sh:109 (assert_blocklist_
# loaded) — same match pattern, same non-zero-count requirement
# (the `[1-9]` leading digit excludes a 0-patterns match, which
# would mean the fetch succeeded but the upstream list was empty).
# This proves the end-to-end path: blocklist.lists[0].sources[0].url
# in sentinel-nginx.yaml → upstream fetch → automaton rebuild → UA
# matching in block 8's requests.
SENTINEL_OP_LOG="$WORK_DIR/sentinel-nginx.log"
if [ ! -s "$SENTINEL_OP_LOG" ] \
   || ! grep -qE 'automaton rebuilt \([1-9][0-9]* patterns\)' "$SENTINEL_OP_LOG"; then
    echo "[nginx] FAIL: assertion 12 - blocklist automaton not loaded (no 'automaton rebuilt (N patterns)' with N>0 in $SENTINEL_OP_LOG)" >&2
    FAIL=1
fi

# ---------------------------------------------------------------------
# Step 8: persist artifacts for the workflow. The cleanup trap on
# EXIT (set in step 1) does NOT remove $WORK_DIR when TMPDIR is
# $GITHUB_WORKSPACE — the workflow's actions/upload-artifact picks
# up these files BEFORE the VM is destroyed (Task 3.6). The copies
# here land at the top of $TMPDIR (= $GITHUB_WORKSPACE in CI)
# so the workflow's `cat $GITHUB_WORKSPACE/...` + `upload-artifact`
# at Task 4.3 can find them by name.
# ---------------------------------------------------------------------
if [ -s "$THREAT_LOG" ]; then
    cp "$THREAT_LOG" "${TMPDIR:-/tmp}/threats-nginx.log.smoke"
fi
if [ -s "$ACCESS_LOG" ]; then
    cp "$ACCESS_LOG" "${TMPDIR:-/tmp}/nginx-access.log"
fi

# ---------------------------------------------------------------------
# Steps 10-15: proxy-chain scenario. Flow 092 (DECISIONS §2/§3/§5).
# The direct-scenario above is DONE and green-or-fail-independent of
# this section — it has already written its threat log, already
# captured its artifacts, and is only consulted in the final FAIL
# tally below (FAIL accumulator carries from Step 7b unchanged). All
# new assertions here accumulate into the SAME FAIL=1 flag so a
# chain-scenario failure still surfaces in a single exit-code-1
# summary at the end.
#
# Static-IP design (DECISIONS §2): the chain network's two endpoints
# have fixed, known addresses from creation time (.10 for the chain
# backend, .20 for the proxy). This sidesteps the inspect-after-start
# chicken-and-egg problem (the backend's config has to declare
# "trust XFF from proxy IP X" BEFORE the proxy starts — known-upfront
# IPs make both configs static, no rewrite-on-startup dance). It
# also makes this script's inline log readable: a fixed address in
# the proxy URL is easier to grep-and-know than a $NGINX_RP_IP capture.
# ---------------------------------------------------------------------

# ---------------------------------------------------------------------
# Step 10: create the chain network with a dedicated subnet
# (10.89.1.0/24 for nginx — per-backend offset, see Flow 092
# DECISIONS §2). A separate network from the direct-scenario's
# $NETWORK ("arx-net") keeps the two scenarios' CNI bridges
# independent — a podman network create with the same name as a
# pre-existing network exits non-zero, so re-use would need
# an "if exists" dance. A fresh network is the simpler path.
# ---------------------------------------------------------------------
echo "[nginx] creating chain CNI network $CHAIN_NETWORK (subnet 10.89.1.0/24)..."
podman network create --subnet 10.89.1.0/24 "$CHAIN_NETWORK"

# Static IP assignment for the chain backend (DECISIONS §2/§3).
# .10 within 10.89.1.0/24 — chosen by convention (smallest non-zero
# suffix for the "primary" service in the network, .20 for the
# upstream proxy). Hard-coded, not derived, on purpose: see
# DECISIONS §2 "static IPs also make the chain-scenario shell
# script easier to read and debug from an inline log".
CHAIN_BACKEND_IP="10.89.1.10"
CHAIN_PROXY_IP="10.89.1.20"

# ---------------------------------------------------------------------
# Step 11: start the chain-scenario backend. SAME image as Step 3
# (docker.io/library/nginx:alpine) on the chain network at the static
# $CHAIN_BACKEND_IP, with a CONFIG EXTENDED by three realip directives
# (DECISIONS §5/§3) — copied from $NGINX_CONF (Step 1's staged
# direct-scenario config) with the directives injected inside the
# server { } block. WHY a separate config file: the direct-scenario
# backend does NOT need the realip module (it never receives an XFF
# header in that scenario — the attacker connects directly, no proxy
# in front). Sharing one config would either require removing the
# realip directives for the direct run (loses the chain scenario) or
# keeping them for both (harmless for direct, but confuses the
# grader: a request with no XFF would have $remote_addr replaced by
# an empty realip-resolved value — sentinel's parser would then log
# an empty field, polluting the threat log). Two files, two
# containers, two log dirs — clean separation, same image.
#
# WHY /32 trust, not a subnet (DECISIONS §3): the chain network has
# exactly one proxy container, so its single static IP is the only
# IP that will ever present an XFF header. Trusting a /32 is
# narrower than trusting a subnet (which is what the Docker battle
# suite does at tests/integration/configs/nginx.conf:48 — `set_real_ip_from
# 172.16.0.0/12;` — there because the Docker compose network
# contains multiple proxies). Narrower trust means a real attacker
# who somehow gets on the chain network cannot spoof XFF headers
# and have them trusted.
# ---------------------------------------------------------------------
echo "[nginx] preparing chain-scenario nginx config (with realip trust for $CHAIN_PROXY_IP/32)..."
mkdir -p "$WORK_DIR/nginx-chain"

# Top-of-block placement matches the battle suite's convention at
# tests/integration/configs/nginx.conf:43-50 — readability consistency
# across the project, and a one-grep diff against the battle suite if
# anyone needs to compare (placing the directives anywhere in the
# server scope is equally valid for the realip module — this is a
# style choice, not a functional requirement). Build nginx-chain.conf:
# copy of the direct-scenario config (Step 1 staged
# $WORK_DIR/nginx.conf) with the three realip directives inserted
# inside the server { } block. The awk trick: the first action
# pattern matches the `server {` line, prints it, then sets a flag —
# the next two patterns are gated on that flag, so the three realip
# directives land on the THREE LINES IMMEDIATELY AFTER the `server {`
# opener, inside the server block.
awk '
    /server \{/ {
        print
        just_opened=1
        next
    }
    just_opened {
        print "        set_real_ip_from  '"$CHAIN_PROXY_IP"'/32;"
        print "        real_ip_header    X-Forwarded-For;"
        print "        real_ip_recursive on;"
        just_opened=0
    }
    { print }
' "$NGINX_CONF" > "$WORK_DIR/nginx-chain.conf"

echo "[nginx] starting chain-scenario nginx container on $CHAIN_BACKEND_IP..."
NGINX_CHAIN_CID=$(podman run -d \
    --os=linux \
    --name nginx-chain \
    --network "$CHAIN_NETWORK" \
    --ip "$CHAIN_BACKEND_IP" \
    -v "$WORK_DIR/nginx-chain.conf:/etc/nginx/nginx.conf:ro" \
    -v "$WORK_DIR/nginx-chain:/var/log/nginx" \
    docker.io/library/nginx:alpine)
echo "[nginx] chain backend $NGINX_CHAIN_CID started"

# Wait-for-ready pattern identical to Step 3: nginx -t validates the
# config (catches a typo in the realip insertion), "start worker
# processes" in podman logs signals full start. 30s is generous
# (container start is faster than first-pull, but we share the
# limit with Step 3 for consistency).
echo "[nginx] waiting for chain backend ready (timeout 30s)..."
DEADLINE=$(($(date +%s) + 30))
READY=0
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    if podman exec nginx-chain nginx -t >/dev/null 2>&1 \
       && podman logs nginx-chain 2>&1 | grep -q "start worker processes"; then
        READY=1
        break
    fi
    sleep 1
done
if [ "$READY" -ne 1 ]; then
    echo "[nginx] FAIL: chain backend not ready within 30s" >&2
    echo "[nginx] chain backend logs (last 30 lines):" >&2
    podman logs --tail 30 nginx-chain >&2 || true
    exit 1
fi
echo "[nginx] chain backend ready"

# ---------------------------------------------------------------------
# Step 12: start the proxy container. Adapted from
# tests/integration/configs/nginx-rp.conf (battle suite) but with a
# SINGLE location "/" — the battle suite's config path-routes to 6
# backends (nginx, apache, traefik, caddy, haproxy, litespeed) under
# /backend-<name>/ prefixes; we have ONE backend (nginx-chain on
# $CHAIN_BACKEND_IP:80), no need for the routing tree. The proxy
# itself runs the same image (nginx:alpine) — proven on FreeBSD by
# Step 3, and the config is trivial (events + http + one server).
#
# WHY the full $NGINX_CONF directive set (error_log, mime.types,
# open_log_file_cache), not a from-scratch minimal config: live runs
# 28583294976/28584079469 found nginx-rp failing to start — first
# with a visible "io_setup() failed (38: Function not implemented)"
# crash, then (after a bind-mount-only fix attempt) the SAME failure
# but silent, because the bind-mount replaced the image's
# /var/log/nginx/error.log -> /dev/stderr symlink without restoring
# it (exactly the gotcha $NGINX_CONF's own header already documents
# and fixes with `error_log /dev/stderr notice;`). Rather than
# re-derive a minimal proxy config and re-discover each of
# $NGINX_CONF's already-proven directives one crash at a time, this
# config is the SAME proven template (mime.types, named log_format,
# error_log, open_log_file_cache off) with ONLY the location block's
# content swapped from `return 404` to `proxy_pass` + the XFF
# headers. If io_setup() was actually about a missing directive in
# the minimal config (not a container-count or bind-mount issue —
# per DECISIONS Decision 2 discussion, unproven either way), this
# rules it out empirically by removing every config difference except
# the one that matters for the chain scenario.
#
# proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for: the
# same directive the battle suite uses, which APPENDS to any
# incoming XFF chain (rather than overwriting) — irrelevant for this
# single-hop test (curl sets no XFF, so $proxy_add_x_forwarded_for
# evaluates to the connecting IP, which is the curl container's CNI
# IP). real_ip_recursive on the backend will then walk the chain
# and pick that leftmost IP. Host header is passed through; X-Real-IP
# is explicitly cleared (battle-suite convention — standardise on
# XFF only, avoid the two-header ambiguity that some backends
# resolve differently).
# ---------------------------------------------------------------------
cat > "$WORK_DIR/nginx-rp.conf" <<NGINX_RP_EOF
error_log /dev/stderr notice;

events {}

http {
    include      /etc/nginx/mime.types;
    default_type application/octet-stream;

    server {
        listen 80 default_server;
        server_name _;

        open_log_file_cache off;

        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Host             \$host;
        proxy_set_header X-Real-IP        "";

        location / {
            proxy_pass http://${CHAIN_BACKEND_IP}:80/;
        }
    }
}
NGINX_RP_EOF

# Bind-mount /var/log/nginx for consistency with the proven $NGINX_CONF
# template (Step 3, Step 11 both do this) — this script never reads
# nginx-rp's own log, but matching the proven container-start shape
# exactly (bind-mount + error_log /dev/stderr, see the config comment
# above) removes it as a variable while root-causing the earlier
# "io_setup() failed" startup crash (live runs 28583294976,
# 28584079469).
mkdir -p "$WORK_DIR/nginx-rp"
echo "[nginx] starting proxy container on $CHAIN_PROXY_IP..."
NGINX_RP_CID=$(podman run -d \
    --os=linux \
    --name nginx-rp \
    --network "$CHAIN_NETWORK" \
    --ip "$CHAIN_PROXY_IP" \
    -v "$WORK_DIR/nginx-rp.conf:/etc/nginx/nginx.conf:ro" \
    -v "$WORK_DIR/nginx-rp:/var/log/nginx" \
    docker.io/library/nginx:alpine)
echo "[nginx] proxy $NGINX_RP_CID started"

# Same wait-for-ready pattern. nginx -t catches the heredoc-substituted
# config typo case; "start worker processes" in podman logs is the
# full-start signal.
echo "[nginx] waiting for proxy ready (timeout 30s)..."
DEADLINE=$(($(date +%s) + 30))
READY=0
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    if podman exec nginx-rp nginx -t >/dev/null 2>&1 \
       && podman logs nginx-rp 2>&1 | grep -q "start worker processes"; then
        READY=1
        break
    fi
    sleep 1
done
if [ "$READY" -ne 1 ]; then
    echo "[nginx] FAIL: proxy not ready within 30s" >&2
    echo "[nginx] proxy logs (last 30 lines):" >&2
    podman logs --tail 30 nginx-rp >&2 || true
    exit 1
fi
echo "[nginx] proxy ready"

# ---------------------------------------------------------------------
# Step 13: drive attacks THROUGH the proxy. Same UA mix as Step 6
# (sqlmap x2 + Mozilla x1) but the URL is the proxy's static IP
# (http://10.89.1.20/), NOT the backend's IP. The proxy adds
# X-Forwarded-For with the curl container's CNI IP, the backend's
# realip module resolves that as the real client IP, and the
# "sentinel" log format logs the real client IP in $remote_addr
# (which is what the parser and grader use to attribute the
# attack). Mirror of the direct-scenario attack — same curl image,
# same attacker behavior, only the URL changes.
#
# --network $NETWORK: the curl container runs on the DIRECT-scenario
# network (arx-net), not the chain network. The two networks are
# isolated — a packet from arx-net cannot reach 10.89.1.20 by
# Layer-2 routing. This is the intended topology: the attacker
# sits on the same "outside" network as in Step 6, the proxy is
# the bridge. The curl container's CNI IP will therefore be on
# arx-net (different from the IP it would have if it were on
# arx-chain-net) — Step 14's assertion extracts the IP from the
# chain-backend's access log, so it doesn't matter that this IP
# is on a different network than the direct scenario's attacker IP.
# ---------------------------------------------------------------------
echo "[nginx] driving proxy-chain attacks from curl container (sqlmap + Mozilla UAs)..."
podman run --rm --os=linux --network "$NETWORK" \
    --entrypoint /bin/sh \
    docker.io/curlimages/curl \
    -c "curl -sS -A '${SQLMAP_UA}' http://${CHAIN_PROXY_IP}/ ; curl -sS -A '${SQLMAP_UA}' http://${CHAIN_PROXY_IP}/ ; curl -sS -A '${MOZILLA_UA}' http://${CHAIN_PROXY_IP}/" \
    >/dev/null 2>&1 \
    || echo "[nginx] chain curl attacker exited non-zero (still check the access log)"
echo "[nginx] chain attacks sent"

# ---------------------------------------------------------------------
# Step 14: chain-specific assertion (4th). Wait for the chain-backend's
# access log to be written, extract the sqlmap-request source IP from
# IT (NOT from the direct-scenario access log), and verify that the
# extracted IP is the REAL client (curl container's CNI IP) — NOT
# the proxy's IP ($CHAIN_PROXY_IP). If the realip module did NOT
# resolve the XFF chain, the logged IP would be the proxy's
# connecting address ($CHAIN_PROXY_IP) — that is the "ip-leak" class
# of failure the battle suite's assert_chain (verify.sh:188) calls
# out (class=ip-leak in its report). Mirrored here in this script's
# existing grep-based assertion style (Step 7b) — same FAIL=1
# accumulator, same non-short-circuit report-at-end discipline.
#
# A note on UA-vs-NA-detection here: the chain scenario's detection
# fires off the SAME UA (sqlmap), so the threat log may contain
# entries from BOTH scenarios (direct Step 7's three requests and
# chain Step 13's three requests, all with the same UA, all from
# attackers the sentinel sees as the same kind of source). The
# check below is intentionally scoped to the chain-backend's OWN
# access log — that log only contains the chain scenario's three
# requests, and $remote_addr in that log is whatever realip
# resolved (which we want to be the real client, not the proxy).
# ---------------------------------------------------------------------
CHAIN_ACCESS_LOG="$WORK_DIR/nginx-chain/access.log"
echo "[nginx] polling $CHAIN_ACCESS_LOG (timeout 20s)..."
DEADLINE=$(($(date +%s) + 20))
WRITTEN=0
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    if [ -s "$CHAIN_ACCESS_LOG" ]; then
        WRITTEN=1
        break
    fi
    sleep 1
done
if [ "$WRITTEN" -ne 1 ]; then
    echo "[nginx] FAIL: $CHAIN_ACCESS_LOG not written within 20s" >&2
    echo "[nginx] proxy logs (last 30 lines):" >&2
    podman logs --tail 30 nginx-rp >&2 || true
    exit 1
fi

# Extract the sqlmap-request source IP from the chain backend's
# access log. awk the first field (which is $remote_addr in the
# "sentinel" log format, populated by the realip module with the
# XFF-resolved IP). head -1 to pick the first match — same
# convention as Step 7a (deterministic, survives multiple hits).
CHAIN_SQLMAP_IP=$(grep "${SQLMAP_UA}" "$CHAIN_ACCESS_LOG" | awk '{print $1}' | head -1)
if [ -z "$CHAIN_SQLMAP_IP" ]; then
    echo "[nginx] FAIL: could not extract sqlmap request IP from chain access log" >&2
    echo "[nginx] chain access log content:" >&2
    cat "$CHAIN_ACCESS_LOG" >&2 || true
    exit 1
fi
echo "[nginx] chain sqlmap request source IP (as logged by chain backend): $CHAIN_SQLMAP_IP"

# Assertion 4: the IP logged by the chain backend must NOT be the
# proxy's IP. If it IS the proxy's IP, the realip module failed to
# resolve XFF and we are logging the proxy's connecting address
# instead of the real client — the exact failure mode assert_chain
# in tests/integration/verify.sh:188 calls "ip-leak". Conversely,
# any non-proxy IP is treated as a PASS for this assertion (the
# detailed IP-correctness of the curl container's CNI assignment
# is not what we are asserting here; what matters is "not the
# proxy's IP").
if [ "$CHAIN_SQLMAP_IP" = "$CHAIN_PROXY_IP" ]; then
    echo "[nginx] FAIL: assertion 4 - real_ip module did not resolve proxy chain - logged proxy IP instead of real client IP (ip-leak)" >&2
    FAIL=1
fi

# ---------------------------------------------------------------------
# Step 15: persist the chain-scenario access log for the workflow's
# upload-artifact step. Same pattern as Step 8 — copy to
# ${TMPDIR:-/tmp}/ (which the workflow's freebsd-integration.yml
# already syncs as $GITHUB_WORKSPACE in CI). Whether the workflow
# picks up this NEW file under the existing upload pattern is a
# separate task (Task 7's workflow-YAML wiring); this script's job
# is to put the artifact in the expected location. If the workflow
# does not auto-include it, the file still lands next to the
# direct-scenario nginx-access.log for an operator to grab.
# ---------------------------------------------------------------------
if [ -s "$CHAIN_ACCESS_LOG" ]; then
    cp "$CHAIN_ACCESS_LOG" "${TMPDIR:-/tmp}/nginx-chain-access.log"
fi

# Step 16 (was Step 9): final report. Cleanup happens via the EXIT
# trap. FAIL=1 may have been set by either Step 7b's direct-scenario
# assertions OR Step 14's chain-scenario assertion — both
# accumulate into the same flag, both are reported by this single
# exit-code decision.
if [ "$FAIL" -ne 0 ]; then
    echo "[nginx] FAIL: one or more assertions failed (see above)"
    exit 1
fi
echo "[nginx] PASS: all assertions green - direct + proxy-chain FreeBSD/podman nginx integration end-to-end works"
exit 0
