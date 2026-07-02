#!/usr/bin/env sh
# tests/integration-freebsd/caddy/integration.sh — Flow 091 integration
# smoke for the caddy backend under FreeBSD/podman.
#
# Adapted from integration.sh — Flow 089 paid 9 iterations to make this
#  structure green; do NOT restructure without re-verifying all assertions.
#
# Architecture (per Flow 089 DECISIONS §2 + §3, carried over verbatim):
# - caddy runs in a Linux-emulated caddy-arxsentinel:local container
#   under podman (a custom caddy binary built in the workflow's
#   unblock chain from tests/integration/dockerfiles/Caddy.Dockerfile
#   with the caddyserver/transform-encoder plugin pre-compiled, so it
#   emits Apache CLF instead of nested JSON -- see Caddyfile header
#   and the bind-mount WHY-comment at step 3 for the full rationale).
#   podman (FreeBSD Linux compat — see Flow 088 DECISIONS §"A.2").
# - arxsentinel runs NATIVE on the VM host (NOT in a container —
#   DECISIONS §2), with its CWD = $WORK_DIR so the relative paths in
#   sentinel-caddy.yaml resolve correctly.
# - The attacker runs in a SECOND podman container (curlimages/curl)
#   on the same CNI network. Both attacker requests share the curl
#   container's CNI IP (DECISIONS §3).
#
# Per Flow 091 DECISIONS §2 (copy-then-adapt, no premature library
# extraction) the script structure is verbatim from integration.sh;
# backend-specific divergences are documented inline as WHY-comments
# at the point of divergence.
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
# Phase P2 step mapping (P2.2 Caddyfile + sentinel-caddy.yaml; P2.3
# this script; P2.4 job wiring):
#   - P2.2: Caddyfile (log path /var/log/caddy/access.log via
#     transform-encoder plugin) + sentinel-caddy.yaml
#     (general.log_file: log/access.log, parser.profile: caddy,
#     output.threat_log: output/threats-caddy.log).
#     sentinel-caddy.yaml (general.log_file: log/access.log,
#     output.threat_log: output/threats-caddy.log).
#   - P2.3: this file's skeleton + CNI network + caddy container
#     startup (steps 0-3 below).
#   - P2.3: sentinel host-process launch + "watching started" sync
#     (steps 4-5 below).
#   - P2.3: 8 attack blocks (probe/ua/bruteforce/crawler/noasset/
#     rate/overflow/badbot) from a single curl container (step 6).
#   - P2.3: 12 assertions (1-3 base + 4-10 per-module + 11 badbot
#     + 12 blocklist-loaded) adapted per DECISIONS §5 (step 7).
#   - P2.3: artifact persistence copy (step 8).
#   - P2.3: chain-scenario steps 10-16 added per Flow 092
#     (DECISIONS §1-6) — backend on arx-chain-net with trusted_proxies
#     static + nginx-rp proxy on 10.89.2.0/24 (caddy = N=2 offset
#     from nginx's N=1).

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
CADDY_DIR="$REPO_ROOT/tests/integration-freebsd/caddy"
CADDY_CONF="$CADDY_DIR/Caddyfile"
SENTINEL_BIN="$REPO_ROOT/arxsentinel"
SENTINEL_CFG_SRC="$CADDY_DIR/sentinel-caddy.yaml"

# Sanity: all three inputs must exist. A typo or missing build would
# silently produce an empty access log and the assertions would
# falsely PASS.
if [ ! -s "$CADDY_CONF" ]; then
    echo "[caddy] FAIL: Caddyfile missing or empty at $CADDY_CONF" >&2
    exit 1
fi
if [ ! -x "$SENTINEL_BIN" ]; then
    echo "[caddy] FAIL: arxsentinel binary not found or not executable at $SENTINEL_BIN" >&2
    exit 1
fi
if [ ! -s "$SENTINEL_CFG_SRC" ]; then
    echo "[caddy] FAIL: sentinel-caddy.yaml missing or empty at $SENTINEL_CFG_SRC" >&2
    exit 1
fi

# ---------------------------------------------------------------------
# Step 1: create $WORK_DIR + the bind-mounted subdirs. $WORK_DIR lives
# under $TMPDIR (set by the workflow as scoped TMPDIR — Task 4.2) so
# the cleanup trap's rm -rf lands in a tmpfs / workspace sync area, not
# under /var/db or /usr/local. The relative paths in sentinel-caddy.yaml
# (log/access.log, output/threats-caddy.log) resolve against
# $WORK_DIR when the sentinel CWDs there in step 4.
# ---------------------------------------------------------------------
WORK_DIR="${TMPDIR:-/tmp}/arx-caddy-$$"
mkdir -p "$WORK_DIR/log" "$WORK_DIR/output"
# 0755 is enough: sentinel runs as root on the FreeBSD host (no
# nonroot hardening yet — see Flow 089 Deferred 089.9 + 088 TD-8).
chmod 0755 "$WORK_DIR/output"

# Stage inputs into $WORK_DIR so the nginx container bind-mount and
# the sentinel CWD see them in a predictable layout.
cp "$CADDY_CONF" "$WORK_DIR/Caddyfile"
cp "$SENTINEL_CFG_SRC" "$WORK_DIR/sentinel-caddy.yaml"

# podman-network and container-name markers — used in cleanup() and
# step 3 (wait-for-nginx). Set as empty strings so the trap is
# idempotent on early exit (e.g. if podman network create fails).
NETWORK="arx-net"
CADDY_CID=""

# Chain-scenario markers (Steps 10-16). Separate from the direct-scenario
# vars above so a failure in Step 3 cleanup() still leaves the chain
# cleanup code paths exercised (and vice versa). Empty defaults keep the
# trap idempotent if the chain section is never reached.
CHAIN_NETWORK="arx-chain-net"
CADDY_CHAIN_CID=""
CADDY_RP_CID=""

cleanup() {
    if [ -n "$CADDY_CID" ]; then
        podman rm -f "$CADDY_CID" >/dev/null 2>&1 || true
    fi
    if [ -n "$CADDY_CHAIN_CID" ]; then
        podman rm -f "$CADDY_CHAIN_CID" >/dev/null 2>&1 || true
    fi
    if [ -n "$CADDY_RP_CID" ]; then
        podman rm -f "$CADDY_RP_CID" >/dev/null 2>&1 || true
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
echo "[caddy] creating CNI network $NETWORK..."
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
echo "[caddy] starting caddy container..."
# caddy-arxsentinel:local is the custom drop-in caddy
# binary built in the workflow unblock chain (P2.4)
# from tests/integration/dockerfiles/Caddy.Dockerfile
# -- same Dockerfile the battle suite uses for its
# caddy + caddy-backend services (tests/integration/
# docker-compose.yml:58). The Dockerfile adds
# github.com/caddyserver/transform-encoder to the caddy
# binary via xcaddy; the resulting caddy emits Apache
# CLF (text, 9-field) instead of nested JSON, which is
# what the arx-core caddy parser profile
# (parser/profiles.go caddyProfile) expects via
# NewRegexParser(apacheCLFPattern). Plain caddy:2-alpine
# would emit JSON and the sentinel would silently produce
# an empty threat log.
# CRITICAL: the WHY-comment block above MUST stay OUTSIDE the
# $(...) command substitution. If a comment line is inserted
# between the -v flag backslash-continuation and the image
# name, the comment (which has no trailing backslash) breaks
# the continuation chain -- the $(...) closes early and the
# image name becomes a separate broken command. sh -n and
# (Note: `shellcheck` does NOT catch this class of bug; it is a runtime
# bug, not a syntax bug). Empirical proof: the previous draft
# produced CADDY_CID="PODMAN-CALLED: <run> <-d> <--os=linux> ..."
# (missing caddy-arxsentinel:local) on a stub-podman runtime
# test, and `sh: 24: caddy-arxsentinel:local: not found` on
# sh. See .tmp/coder-brief-091-p2-fix2.md for the full
# post-mortem. (Same caveat applies to every other multi-line
# command substitution in this script -- see step 3 grep
# check in the brief.)
CADDY_CID=$(podman run -d \
    --os=linux \
    --name caddy \
    --network "$NETWORK" \
    -v "$WORK_DIR/Caddyfile:/etc/caddy/Caddyfile:ro" \
    -v "$WORK_DIR/log:/var/log/caddy" \
    caddy-arxsentinel:local)
echo "[caddy] container $CADDY_CID started"

# Wait for caddy to be ready: `podman exec caddy caddy version` validates
# the binary is executable; the `podman logs` line for "server running"
# (caddy's JSON startup log, confirmed via live dispatch 28550879869)
# signals caddy has fully started serving.
#
# NOT wget-based (unlike integration.sh's original check): live dispatch
# 28550879869 found `caddy:latest` (Debian-based upstream, unlike
# alpine/busybox images) does NOT ship wget — `podman exec caddy wget
# ...` silently failed on every poll for the full 30s timeout even
# though caddy's own log showed "server running" within ~1s of start.
# See Decision 4 Revised addendum / triage-caddy-1.md for the full
# finding.
echo "[caddy] waiting for caddy ready (timeout 30s)..."
DEADLINE=$(($(date +%s) + 30))
READY=0
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    if podman exec caddy caddy version >/dev/null 2>&1 \
       && podman logs caddy 2>&1 | grep -q '"msg":"server running"'; then
        READY=1
        break
    fi
    sleep 1
done
if [ "$READY" -ne 1 ]; then
    echo "[caddy] FAIL: caddy not ready within 30s" >&2
    echo "[caddy] caddy logs (last 30 lines):" >&2
    podman logs --tail 30 caddy >&2 || true
    exit 1
fi
echo "[caddy] caddy ready"

# ---------------------------------------------------------------------
# Step 4: start the native sentinel. DECISIONS §2 — sentinel on host,
# NOT in a container. CWD = $WORK_DIR so the relative paths in
# sentinel-caddy.yaml resolve. The sentinel writes its pid to
# /tmp/arxsentinel.pid (per the yaml) and its operational log to
# sentinel-caddy.log under $WORK_DIR.
# ---------------------------------------------------------------------
echo "[caddy] starting native sentinel (CWD=$WORK_DIR)..."
cd "$WORK_DIR"
"$SENTINEL_BIN" \
    --config "$WORK_DIR/sentinel-caddy.yaml" \
    > "$WORK_DIR/sentinel-caddy.log" 2>&1 &
SENTINEL_PID=$!
echo "[caddy] sentinel started with PID $SENTINEL_PID"

# Step 5: wait for "watching started" in sentinel-caddy.log. This
# sync prevents the host append in step 6 from racing the TailReader
# open+seek(EOF) (mirrors 088 run-smoke.sh step 3). The yaml's
# logging.debug: true is REQUIRED for the "TAIL watching started"
# line to be emitted (see sentinel-caddy.yaml header).
echo "[caddy] waiting for 'watching started' (timeout 30s)..."
DEADLINE=$(($(date +%s) + 30))
WATCHING=0
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    if grep -q "watching started" "$WORK_DIR/sentinel-caddy.log" 2>/dev/null; then
        WATCHING=1
        break
    fi
    sleep 1
done
if [ "$WATCHING" -ne 1 ]; then
    echo "[caddy] FAIL: 'watching started' not seen within 30s" >&2
    echo "[caddy] sentinel log (last 50 lines):" >&2
    tail -50 "$WORK_DIR/sentinel-caddy.log" >&2 || true
    kill "$SENTINEL_PID" 2>/dev/null || true
    exit 1
fi
echo "[caddy] TailReader ready"

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
CADDY_IP=$(podman inspect caddy --format "{{(index .NetworkSettings.Networks \"${NETWORK}\").IPAddress}}")
if [ -z "$CADDY_IP" ]; then
    echo "[caddy] FAIL: could not resolve caddy container's CNI IP via podman inspect" >&2
    exit 1
fi
echo "[caddy] caddy container IP: $CADDY_IP"

# Generate the long URL path for the overflow scenario (block 7) on
# the HOST (not inside the curl container) so the value can be
# embedded as a literal in the -c "..." script string below.
#
# NOT scenarios.sh:169's `/dev/urandom | tr -dc 'a-zA-Z0-9'` recipe:
# live run 28587170404 (nginx Task A1) found it produces EMPTY output
# on this FreeBSD VM's native sh — LONG_PATH came out as "/" (1 byte),
# so the overflow detector (which only checks byte length, not
# content — see pkg/detectorplugins/overflow/overflow.go's ALGORITHM
# comment) never fired. Root cause not pinned down further (FreeBSD's
# tr(1) vs GNU tr, or /dev/urandom access under the vmactions SSH
# session — either way, not worth chasing since the detector doesn't
# need randomness). `awk` generates a deterministic 2200-char string
# in one process, POSIX-standard and present on every FreeBSD base
# install — no /dev/urandom or tr(1) portability surface at all.
LONG_PATH="/$(awk 'BEGIN { s = ""; for (i = 0; i < 2200; i++) s = s "a"; print s }')"
# Diagnostic (live run 28585617384 found the overflow assertion failing
# with no obvious quoting bug on static read) — print the byte length so
# a re-dispatch can confirm/rule out FreeBSD's tr(1) behaving differently
# from scenarios.sh's Linux/GNU-tr assumption for `-dc 'a-zA-Z0-9'`.
echo "[caddy] LONG_PATH length: $(printf '%s' "$LONG_PATH" | wc -c) bytes"

# Pick the badbot UA the same way scenarios.sh:179 does: prefer the
# committed test fixture ($REPO_ROOT/tests/integration/blocklist/
# test-ua.txt) because it is the same file run.sh:122 produces from
# the FIRST literal pattern in the upstream mitchellkrogza list — a
# pattern the FreeBSD sentinel's blocklist automaton will also load
# (same upstream URL, see sentinel-caddy.yaml blocklist.lists[0].
# sources[0].url). Fallback "AhrefsBot" matches scenarios.sh:179 —
# a UA guaranteed to be in the upstream list as a regex literal
# (AhrefsBot appears unescaped near the top of bad-user-agents.list).
if [ -s "$REPO_ROOT/tests/integration/blocklist/test-ua.txt" ]; then
    BADBOT_UA=$(head -1 "$REPO_ROOT/tests/integration/blocklist/test-ua.txt")
else
    BADBOT_UA="AhrefsBot"
fi
echo "[caddy] using badbot UA for block 8: ${BADBOT_UA}/1.0"

echo "[caddy] driving 8 attack blocks from a single curl container..."
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
curl -sf -o /dev/null http://${CADDY_IP}/wp-login.php      || true
curl -sf -o /dev/null http://${CADDY_IP}/.env              || true
curl -sf -o /dev/null http://${CADDY_IP}/.git/config       || true
curl -sf -o /dev/null http://${CADDY_IP}/admin/config.php  || true
curl -sf -o /dev/null http://${CADDY_IP}/etc/passwd        || true
curl -sf -o /dev/null http://${CADDY_IP}/.aws/credentials  || true
curl -sf -o /dev/null http://${CADDY_IP}/xmlrpc.php        || true
# ── block 2: ua (scenarios.sh:94-100) + the legit Mozilla request ──
curl -sf -o /dev/null -A '${SQLMAP_UA}'     http://${CADDY_IP}/ || true
curl -sf -o /dev/null -A '${SQLMAP_UA}'     http://${CADDY_IP}/ || true
curl -sf -o /dev/null -A 'Nuclei/3.0'       http://${CADDY_IP}/ || true
curl -sf -o /dev/null -A 'masscan/1.3'      http://${CADDY_IP}/ || true
curl -sf -o /dev/null -A 'zgrab/0.x'        http://${CADDY_IP}/ || true
# Legit Mozilla request — kept in block 2 (NOT a separate block)
# because Assertion 2 (Mozilla UA absent from threat log) only
# makes sense in the context of the scanner-UA attack on the same
# IP. If Mozilla were in its own block AFTER all scanners, the
# scorer's per-IP state for this client would have already been
# written to the threat log with the sqlmap IP; sending a Mozilla
# request on a fresh connection (or with a different effective
# source) would muddle the test.
curl -sf -o /dev/null -A '${MOZILLA_UA}'   http://${CADDY_IP}/ || true
# ── block 3: bruteforce (scenarios.sh:104-120) ──
curl -sf -o /dev/null http://${CADDY_IP}/                      || true
curl -sf -o /dev/null http://${CADDY_IP}/                      || true
curl -sf -o /dev/null http://${CADDY_IP}/                      || true
curl -sf -o /dev/null http://${CADDY_IP}/missing-page-1        || true
curl -sf -o /dev/null http://${CADDY_IP}/missing-page-2        || true
curl -sf -o /dev/null http://${CADDY_IP}/missing-page-3        || true
curl -sf -o /dev/null http://${CADDY_IP}/missing-page-4        || true
curl -sf -o /dev/null http://${CADDY_IP}/missing-page-5        || true
curl -sf -o /dev/null http://${CADDY_IP}/missing-page-6        || true
curl -sf -o /dev/null http://${CADDY_IP}/missing-page-7        || true
curl -sf -o /dev/null http://${CADDY_IP}/missing-page-8        || true
curl -sf -o /dev/null http://${CADDY_IP}/missing-page-9        || true
curl -sf -o /dev/null http://${CADDY_IP}/missing-page-10       || true
curl -sf -o /dev/null http://${CADDY_IP}/missing-page-11       || true
curl -sf -o /dev/null http://${CADDY_IP}/missing-page-12       || true
# ── block 4: crawler (scenarios.sh:126-132) ──
curl -sf -o /dev/null http://${CADDY_IP}/items/1  || true
curl -sf -o /dev/null http://${CADDY_IP}/items/2  || true
curl -sf -o /dev/null http://${CADDY_IP}/items/3  || true
curl -sf -o /dev/null http://${CADDY_IP}/items/4  || true
curl -sf -o /dev/null http://${CADDY_IP}/items/5  || true
curl -sf -o /dev/null http://${CADDY_IP}/items/6  || true
# ── block 5: noasset (scenarios.sh:138-146) ──
curl -sf -o /dev/null http://${CADDY_IP}/           || true
curl -sf -o /dev/null http://${CADDY_IP}/           || true
curl -sf -o /dev/null http://${CADDY_IP}/           || true
curl -sf -o /dev/null http://${CADDY_IP}/info.php   || true
curl -sf -o /dev/null http://${CADDY_IP}/           || true
curl -sf -o /dev/null http://${CADDY_IP}/           || true
curl -sf -o /dev/null http://${CADDY_IP}/info.php   || true
curl -sf -o /dev/null http://${CADDY_IP}/           || true
# ── block 6: rate (scenarios.sh:151-161) — 60 requests in 2 waves with 1s gap ──
i=0; while [ \$i -lt 30 ]; do
    curl -sf -o /dev/null http://${CADDY_IP}/ || true
    i=\$((i+1))
done
sleep 1
i=0; while [ \$i -lt 30 ]; do
    curl -sf -o /dev/null http://${CADDY_IP}/ || true
    i=\$((i+1))
done
# ── block 7: overflow (scenarios.sh:169-172) — single URL with path > 2048 bytes ──
curl -sf -o /dev/null 'http://${CADDY_IP}${LONG_PATH}' || true
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
curl -sf -o /dev/null -A '${BADBOT_UA}/1.0' http://${CADDY_IP}/ || true
curl -sf -o /dev/null -A '${BADBOT_UA}/1.0' http://${CADDY_IP}/ || true
"

podman run --rm --os=linux --network "$NETWORK" \
    --entrypoint /bin/sh \
    docker.io/curlimages/curl \
    -c "$ATTACK_SCRIPT" \
    >/dev/null 2>&1 \
    || echo "[caddy] curl attacker exited non-zero (still check the access log)"
echo "[caddy] attacks sent"

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
THREAT_LOG="$WORK_DIR/output/threats-caddy.log"
echo "[caddy] polling $THREAT_LOG (timeout 40s)..."
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
    echo "[caddy] FAIL: $THREAT_LOG not written within 40s" >&2
    echo "[caddy] access log content (if any):" >&2
    cat "$WORK_DIR/log/access.log" >&2 || true
    echo "[caddy] sentinel log (last 80 lines):" >&2
    tail -80 "$WORK_DIR/sentinel-caddy.log" >&2 || true
    exit 1
fi

# Dump the threat log for inline visibility.
LINES=$(cat "$THREAT_LOG")
echo "[caddy] threat log content:"
printf '%s\n' "$LINES" | sed 's/^/  /'

# ---------------------------------------------------------------------
# Step 7a: extract the sqlmap-request source IP from the access log.
# DECISIONS §5 — the attacker's source IP is the curl container's
# CNI-assigned IP, which appears in access.log as the first field
# of the line containing the sqlmap UA. We extract that IP here
# (once) so assertions 1 and 2 below can use it.
# ---------------------------------------------------------------------
ACCESS_LOG="$WORK_DIR/log/access.log"
if [ ! -s "$ACCESS_LOG" ]; then
    echo "[caddy] FAIL: access log empty or missing at $ACCESS_LOG" >&2
    exit 1
fi
# grep the sqlmap UA (literal, no regex specials) then awk the first
# field. Safe even if the UA contains regex chars — grep treats it
# as a fixed string in this case (no -E flag).
SQLMAP_IP=$(grep "${SQLMAP_UA}" "$ACCESS_LOG" | awk '{print $1}' | head -1)
if [ -z "$SQLMAP_IP" ]; then
    echo "[caddy] FAIL: could not extract sqlmap request IP from access log" >&2
    echo "[caddy] access log content:" >&2
    cat "$ACCESS_LOG" >&2 || true
    exit 1
fi
echo "[caddy] sqlmap request source IP: $SQLMAP_IP"

# Diagnostic (live run 28585617384 — overflow assertion failing, LONG_PATH
# byte-length echoed near generation to compare against this): print the
# access-log line matching the long-path request, and its request-field
# byte length, to see what caddy actually logged for it (full URI vs
# truncated vs never received). Same probe as nginx Task A1 — caddy's
# transform-encoder pattern has a fixed 9-field form, so a > 2048-byte
# path in the request field still produces a parsable line; this
# diagnostic confirms the long path made it through caddy (not rejected
# at the HTTP layer) and into the access log.
OVERFLOW_LOG_LINE=$(grep -E '"GET /[a-zA-Z0-9]{100,}' "$ACCESS_LOG" | head -1)
if [ -n "$OVERFLOW_LOG_LINE" ]; then
    echo "[caddy] overflow request access-log line length: $(printf '%s' "$OVERFLOW_LOG_LINE" | wc -c) bytes"
else
    echo "[caddy] overflow request NOT FOUND in access log (long-path GET never logged)"
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
    echo "[caddy] FAIL: assertion 1 - expected ' THREAT ' and IP '$SQLMAP_IP' in threat log" >&2
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
    echo "[caddy] FAIL: assertion 2 - false positive: Mozilla UA appeared in threat log" >&2
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
    echo "[caddy] FAIL: assertion 3 - $BAD_COUNT threat line(s) missing score=/reason=" >&2
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
        echo "[caddy] FAIL: assertion - expected module '$module' in threat log (reason=)" >&2
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
    echo "[caddy] FAIL: assertion 11 - badbot module not in threat log (expected reason=badbot:...)" >&2
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
# in sentinel-caddy.yaml → upstream fetch → automaton rebuild → UA
# matching in block 8's requests.
SENTINEL_OP_LOG="$WORK_DIR/sentinel-caddy.log"
if [ ! -s "$SENTINEL_OP_LOG" ] \
   || ! grep -qE 'automaton rebuilt \([1-9][0-9]* patterns\)' "$SENTINEL_OP_LOG"; then
    echo "[caddy] FAIL: assertion 12 - blocklist automaton not loaded (no 'automaton rebuilt (N patterns)' with N>0 in $SENTINEL_OP_LOG)" >&2
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
    cp "$THREAT_LOG" "${TMPDIR:-/tmp}/threats-caddy.log.smoke"
fi
if [ -s "$ACCESS_LOG" ]; then
    cp "$ACCESS_LOG" "${TMPDIR:-/tmp}/caddy-access.log"
fi

# Step 9: final report. Cleanup happens via the EXIT trap.
if [ "$FAIL" -ne 0 ]; then
    echo "[caddy] FAIL: one or more assertions failed (see above)"
    exit 1
fi
echo "[caddy] PASS: all 12 assertions green - FreeBSD/podman caddy integration end-to-end works"
exit 0
