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

echo "[nginx] driving attacks from curl container (sqlmap + Mozilla UAs)..."
# Fully-qualified docker.io/curlimages/curl (NOT bare curlimages/curl) —
# same short-name resolution issue as the nginx image above. --os=linux —
# same image-index reasoning as the nginx container above (curlimages/curl
# has no freebsd OS variant either).
#
# TWO sqlmap requests (not one): live run 28478337664 proved detection
# fires correctly on a single hit ([DETECTOR] [UA] ... +40 ...) but the
# config's default alert threshold is 50 — one hit (score=40) never
# crosses it, so nothing is written to the threat log. The scorer is
# additive within the decay window ("decay 0→0 + delta=40" in that run's
# log), so a second identical-UA hit lands at score=80, comfortably over
# the threshold. Matches 088's testdata/synthetic.access.log fixture,
# which also sends multiple sqlmap-UA requests from the same attacker
# (5, in that case) rather than relying on a single hit.
podman run --rm --os=linux --network "$NETWORK" \
    --entrypoint /bin/sh \
    docker.io/curlimages/curl \
    -c "curl -sS -A '${SQLMAP_UA}' http://${NGINX_IP}/ ; curl -sS -A '${SQLMAP_UA}' http://${NGINX_IP}/ ; curl -sS -A '${MOZILLA_UA}' http://${NGINX_IP}/" \
    >/dev/null 2>&1 \
    || echo "[nginx] curl attacker exited non-zero (still check the access log)"
echo "[nginx] attacks sent"

# ---------------------------------------------------------------------
# Step 7: poll the threat log for non-empty content (~20s timeout).
# Mirrors 088 run-smoke.sh step 5.
# ---------------------------------------------------------------------
THREAT_LOG="$WORK_DIR/output/threats-nginx.log"
echo "[nginx] polling $THREAT_LOG (timeout 20s)..."
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
    echo "[nginx] FAIL: $THREAT_LOG not written within 20s" >&2
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

# ---------------------------------------------------------------------
# Step 7b: three assertions per DECISIONS §5 (adapted from 088
# run-smoke.sh — UA-based, not IP-based). A single FAIL on any
# assertion sets FAIL=1; the script reports all three at the end
# (does not short-circuit, so the grader can see the full failure
# shape).
# ---------------------------------------------------------------------
FAIL=0

# Assertion 1: ` THREAT ` substring AND sqlmap-attack source IP
# appear in the threat log. (088 run-smoke.sh assertion 1 with the
# IP extracted from access.log, NOT a fixed literal.)
if ! printf '%s\n' "$LINES" | grep -q " THREAT " \
   || ! printf '%s\n' "$LINES" | grep -q " $SQLMAP_IP "; then
    echo "[nginx] FAIL: assertion 1 - expected ' THREAT ' and IP '$SQLMAP_IP' in threat log" >&2
    FAIL=1
fi

# Assertion 2: Mozilla UA does NOT appear in the threat log.
# DEPARTURE FROM 088 run-smoke.sh assertion 2 (which used a legit
# IP-absent check): both curl requests share the curl container's
# CNI IP (DECISIONS §3 + §5), so IP-based legit-vs-attacker
# discrimination does not work. Instead we assert the Mozilla UA
# itself is absent — a stricter test of UA-selectivity (the
# detector must score on UA, not just on the request itself).
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
events {}
http {
    server {
        listen 80;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Host             \$host;
        proxy_set_header X-Real-IP        "";
        location / {
            proxy_pass http://${CHAIN_BACKEND_IP}:80/;
        }
    }
}
NGINX_RP_EOF

# Live run 28583294976 found nginx-rp failing to start entirely:
# "io_setup() failed (38: Function not implemented)" from nginx's
# master process. Every OTHER nginx container in this project (Step 3,
# Step 11) bind-mounts its /var/log/nginx to a host path; nginx-rp was
# the only one left writing to the container's own overlay layer.
# Bind-mounting its log dir (even though this script never reads it)
# routes those log writes through the same host-filesystem path the
# working containers use instead of ocijail's emulated overlay I/O —
# which is the concrete difference between the two outcomes.
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
