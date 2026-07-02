#!/usr/bin/env sh
# tests/integration-freebsd/litespeed/integration.sh — Flow 091
# integration smoke for the OpenLiteSpeed backend under FreeBSD/podman.
#
# Adapted from integration.sh — Flow 089/091 paid 9+ iterations to make
#  this structure green across nginx/caddy/traefik/haproxy/apache; do NOT
#  restructure without re-verifying all assertions.
#
# Architecture (per Flow 089 DECISIONS §2 + §3, carried over verbatim):
# - OpenLiteSpeed runs in a Linux-emulated
#   docker.io/litespeedtech/openlitespeed:latest container under podman
#   (FreeBSD Linux compat — see Flow 088 DECISIONS §"A.2"). The image
#   is the SAME upstream used by the battle suite
#   (tests/integration/docker-compose.yml:111 — G13 verification: image
#   tag is taken from the battle suite, not guessed by analogy with
#   caddy:2-alpine / traefik:latest / haproxy:latest / httpd:latest).
# - arxsentinel runs NATIVE on the VM host (NOT in a container —
#   DECISIONS §2), with its CWD = $WORK_DIR so the relative paths in
#   sentinel-litespeed.yaml resolve correctly.
# - The attacker runs in a SECOND podman container (curlimages/curl) on
#   the same CNI network. All attacker requests share the curl
#   container's CNI IP (DECISIONS §3).
#
# KEY ARCHITECTURAL CHOICE: STOCK image, no custom build, no log-format
# patch.
#   Per Flow 091 DECISIONS §4 litespeed row + arx-core
#   pkg/parser/profiles.go:103-117, OLS by default emits Apache CLF
#   with User-Agent — exactly what the `litespeed` parser profile
#   (apacheCLFPattern) expects. No patch-ols-logformat.py invocation,
#   no LiteSpeedBackend.Dockerfile, no host-build + podman-load (the
#   G11 avoidance path recommended by the brief). This is the SAME
#   approach the battle suite uses: docker-compose.yml:110-116 just
#   runs the stock image with a host bind-mount on /usr/local/lsws/logs,
#   no build: section, no patched variant. The line at
#   docker-compose.yml:107-108 is explicit: "OLS docker template uses
#   /var/www/vhosts/localhost/html as docRoot and writes access logs
#   to logs/localhost.access.log — no config override needed."
#
#   The battle suite's `litespeed-backend:` service (a SEPARATE service
#   from `litespeed:`) is the one that uses LiteSpeedBackend.Dockerfile
#   + patch-ols-logformat.py — that service is for the proxy-chain
#   scenario where XFF must replace the proxy container IP, which is
#   Deferred 091.1 and out of P6's scope. P6 mirrors the battle
#   suite's `litespeed:` service (direct-only, no XFF, default OLS
#   format = CLF with UA).
#
# Per Flow 091 DECISIONS §2 (copy-then-adapt, no premature library
# extraction) the script structure is verbatim from integration.sh;
# backend-specific divergences are documented inline as WHY-comments
# at the point of divergence.
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
# Why log-grep readiness check (NOT wget):
#   Same rationale as integration.sh: every per-backend run script in
#   this flow has converged on log-grep for readiness, never wget
#   (caddy image has no wget, wget also has the stdio-buffering
#   gotcha that haproxy surfaced). The OLS master process writes a
#   startup banner to stdout that includes the literal substring
#   "LiteSpeed" (e.g. "[*] LiteSpeed/<version> starts successfully"
#   per the openlitespeed docker-entrypoint.sh source — citation
#   deferred to live dispatch if a tighter pattern is needed). The
#   conservative grep below matches "LiteSpeed" as a broad
#   substring; if P6.6 reveals a more specific marker, tighten the
#   grep — the conservative form is the safe default.
#
# Phase P6 step mapping (P6.2 sentinel-litespeed.yaml; P6.3 this
# script; P6.4 job wiring):
#   - P6.2: sentinel-litespeed.yaml (general.log_file: logs/
#     localhost.access.log, parser.profile: litespeed, output.
#     threat_log: output/threats-litespeed.log, blocklist.lists
#     [0].sources[0].url: mitchellkrogza upstream) — NO Dockerfile,
#     NO patch-ols-logformat.py for the DIRECT scenario (stock
#     image, G11 avoidance).
#   - P6.3: this file's skeleton + CNI network + OLS container
#     startup with bind-mounted log (steps 0-3 below).
#   - P6.3: sentinel host-process launch + "watching started" sync
#     (steps 4-5 below).
#   - P6.3: curl attacker with 8 attack blocks (probe + ua + 12
#     bruteforce + 6 crawler + 8 noasset + 60 rate + 1 overflow +
#     2 badbot) — step 6 below. Per Flow 092 Decision 7.
#   - P6.3: 12 assertions (THREAT+IP, Mozilla-absent, score/reason-
#     format, 7 module-name checks, badbot module, blocklist-
#     automaton-loaded) — step 7.
#   - P6.3: artifact persistence copy (step 8).
#   - Flow 092 (P6.7): proxy-chain scenario appended as Steps 10-16
#     (DECISIONS §1-§5). Same custom litespeed-arxsentinel:local
#     image (built on the host from
#     tests/integration/dockerfiles/LiteSpeedBackend.Dockerfile +
#     patch-ols-logformat.py — patches OLS's docker.conf to put
#     %{X-Forwarded-For}i in the client-IP field) on a dedicated
#     chain CNI network (10.89.6.0/24, N=6 per DECISIONS §2). The
#     direct scenario (Step 3) continues to use the stock
#     docker.io/litespeedtech/openlitespeed:latest image (no
#     patch) per the P6 design — chain and direct diverge only in
#     the backend image, NOT in the proxy: nginx-rp is the
#     universal proxy (DECISIONS §1). Assertion 4 verifies the
#     chain backend logs the real client IP (now XFF-resolved by
#     the patched image), not the proxy's connecting address
#     (ip-leak class).

set -eu

# ---------------------------------------------------------------------
# Step 0: locate inputs. REPO_ROOT is the workspace root ($GITHUB_WORKSPACE
# at workflow runtime). All three inputs are committed in this directory.
#
# This script lives at tests/integration-freebsd/litespeed/integration.sh —
# three path segments below the repo root, so dirname($0) needs three
# "../" to reach it (NOT two, which is what 088's
# tests/integration-freebsd/run-smoke.sh used, since that script is
# only two segments deep).
# ---------------------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
LITESPEED_DIR="$REPO_ROOT/tests/integration-freebsd/litespeed"
SENTINEL_BIN="$REPO_ROOT/arxsentinel"
SENTINEL_CFG_SRC="$LITESPEED_DIR/sentinel-litespeed.yaml"

# Sanity: both inputs must exist. A typo or missing build would
# silently produce an empty access log and the assertions would
# falsely PASS.
if [ ! -x "$SENTINEL_BIN" ]; then
    echo "[litespeed] FAIL: arxsentinel binary not found or not executable at $SENTINEL_BIN" >&2
    exit 1
fi
if [ ! -s "$SENTINEL_CFG_SRC" ]; then
    echo "[litespeed] FAIL: sentinel-litespeed.yaml missing or empty at $SENTINEL_CFG_SRC" >&2
    exit 1
fi

# ---------------------------------------------------------------------
# OLS-specific: default Listen port + log path (sourced from
# tests/integration/docker-compose.yml:106-116, the battle suite's
# litespeed: service, which we mirror verbatim for the direct-only
# test).
#
# Battle suite maps "8087:80" — the upstream OLS default Listen is
# :80 on the Example vhost (more precisely on the stock
# docker-entrypoint.sh "localhost" vhost — see OLS doc note: the
# docker template uses "localhost" as the vhost name, hence
# /usr/local/lsws/logs/localhost.access.log as the access-log path).
# We use :80 inside the CNI network (no host port-publish — the
# port is arbitrary from the host's perspective; G15 does not
# apply because the access is CNI-internal, not from the host).
#
# LSWS_PORT and LSWS_LOG are env-overridable so a future iteration
# that needs a different port (e.g. to avoid a CNI collision) can
# change them without touching the script body. Defaults match
# the upstream OLS docker template (battle suite line 107-108 +
# 116).
# ---------------------------------------------------------------------
LSWS_PORT="${LSWS_PORT:-80}"
LSWS_LOG_NAME="${LSWS_LOG_NAME:-localhost.access.log}"

# ---------------------------------------------------------------------
# Step 1: create $WORK_DIR + the bind-mounted subdirs. $WORK_DIR lives
# under $TMPDIR (set by the workflow as scoped TMPDIR — P6.4 carry of
# 088 G.1) so the cleanup trap's rm -rf lands in a tmpfs / workspace
# sync area, not under /var/db or /usr/local. The relative paths in
# sentinel-litespeed.yaml (logs/localhost.access.log, output/
# threats-litespeed.log) resolve against $WORK_DIR when the sentinel
# CWDs there in step 4.
#
# $WORK_DIR/logs/ is the host-side destination of the bind-mount in
# step 3 (mount $WORK_DIR/logs over /usr/local/lsws/logs inside the
# container). The OLS worker's accesslog directive writes to
# /usr/local/lsws/logs/localhost.access.log, which the bind-mount
# surfaces as $WORK_DIR/logs/localhost.access.log on the host. The
# host-native sentinel then tails that file in step 4.
#
# $WORK_DIR/webapp/ is the host-side source for the docRoot
# bind-mount: the stock OLS docker template uses
# /var/www/vhosts/localhost/html as the vhost's docRoot (battle
# suite docker-compose.yml:115), and an EMPTY docRoot causes OLS
# to return 403 to every request (the access log is what we want
# to exercise, but a 403 means the request was processed, so
# that's OK; the access log still gets the line). We create a
# minimal index.html so curl gets a 200 — the actual HTTP status
# code does not affect the smoke (we only assert on the threat
# log content), but a 200 keeps the access log lines consistent
# with the other five backends.
# ---------------------------------------------------------------------
WORK_DIR="${TMPDIR:-/tmp}/arx-litespeed-$$"
mkdir -p "$WORK_DIR/logs" "$WORK_DIR/output" "$WORK_DIR/webapp"
# 0755 is enough: sentinel runs as root on the FreeBSD host (no
# nonroot hardening yet — see Flow 089 Deferred 089.9 + 088 TD-8).
chmod 0755 "$WORK_DIR/output"
# Minimal index.html — single line, anything that returns 200 is fine.
printf 'arxsentinel-091-litespeed\n' > "$WORK_DIR/webapp/index.html"

# Stage inputs into $WORK_DIR so the sentinel CWD sees the
# sentinel-litespeed.yaml in a predictable layout. (No config file
# to bind-mount: stock OLS works out of the box per battle
# docker-compose.yml:108.)
cp "$SENTINEL_CFG_SRC" "$WORK_DIR/sentinel-litespeed.yaml"

# podman-network and container-name markers — used in cleanup() and
# step 3 (wait-for-litespeed). Set as empty strings so the trap is
# idempotent on early exit (e.g. if podman network create fails).
NETWORK="arx-net"
LITESPEED_CID=""

# Chain-scenario markers (Steps 10-16). Separate from the direct-scenario
# vars above so a failure in Step 3 cleanup() still leaves the chain
# cleanup code paths exercised (and vice versa). Empty defaults keep the
# trap idempotent if the chain section is never reached. Mirrors the
# apache integration.sh pattern (apache/integration.sh:179-181).
CHAIN_NETWORK="arx-chain-net"
LITESPEED_CHAIN_CID=""
LITESPEED_RP_CID=""

cleanup() {
    if [ -n "$LITESPEED_CID" ]; then
        podman rm -f "$LITESPEED_CID" >/dev/null 2>&1 || true
    fi
    if [ -n "$LITESPEED_CHAIN_CID" ]; then
        podman rm -f "$LITESPEED_CHAIN_CID" >/dev/null 2>&1 || true
    fi
    if [ -n "$LITESPEED_RP_CID" ]; then
        podman rm -f "$LITESPEED_RP_CID" >/dev/null 2>&1 || true
    fi
    # CNI networks do not auto-GC on job exit (DECISIONS §3 consequences):
    # remove the networks explicitly. Both direct and chain networks
    # are unconditionally attempted — podman network rm on a missing
    # network exits non-zero, hence the || true (matches the original
    # direct-scenario pattern + apache carry).
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
    # artifact path — P6.4 carry of 089 Task 3.6 / 4.3). The
    # workflow's actions/upload-artifact picks it up before the VM is
    # destroyed. If TMPDIR is NOT $GITHUB_WORKSPACE (local-debug use),
    # the user is responsible for cleanup; rm -rf is intentionally
    # omitted.
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------
# Step 2: create the CNI network. DECISIONS §3 — native `podman network
# create`, NOT podman-compose (which is not in FreeBSD pkg; pip install
# adds a non-FreeBSD-pkg dependency). The default CNI subnet (typically
# 10.88.0.0/16 on FreeBSD) is fine for the direct-litespeed test.
# ---------------------------------------------------------------------
echo "[litespeed] creating CNI network $NETWORK..."
podman network create "$NETWORK"

# ---------------------------------------------------------------------
# Step 3: start the OpenLiteSpeed container detached. Two bind-mounts:
#   1. $WORK_DIR/logs → /usr/local/lsws/logs
#      (OLS's docker template writes access logs to
#      /usr/local/lsws/logs/localhost.access.log — the bind-mount
#      surfaces that as $WORK_DIR/logs/localhost.access.log on the
#      host, the path the host-native sentinel tails in step 4)
#   2. $WORK_DIR/webapp → /var/www/vhosts/localhost/html:ro
#      (OLS's stock docker template uses
#      /var/www/vhosts/localhost/html as the vhost docRoot —
#      battle docker-compose.yml:107-108 + 115. Without a non-
#      empty docRoot OLS returns 403, which is fine for the
#      smoke but inconsistent with the other five backends; we
#      pre-populate $WORK_DIR/webapp/index.html in step 1.)
#
# --name litespeed is kept for operator convenience (`podman logs
# litespeed`, `podman exec litespeed ...` below) but is NOT used as
# a DNS name by the curl attacker — step 6 resolves the container's
# CNI IP via `podman inspect` instead, since the FreeBSD CNI bridge
# plugin has no dnsname resolver (G6; same as nginx + caddy +
# traefik + haproxy + apache).
#
# Fully-qualified docker.io/litespeedtech/openlitespeed:latest (NOT
# bare litespeedtech/openlitespeed:latest): the FreeBSD podman
# default /usr/local/share/containers/registries.conf has no
# unqualified-search-registries entry, so a short name fails with
# "did not resolve to an alias and no unqualified-search registries
# are defined" (G1; same class of bug as Flow 088 Decision F.4 and
# 091 integration.sh / integration.sh / integration.sh / integration.sh
# / integration.sh use of fully-qualified names). The "latest" tag
# was verified against tests/integration/docker-compose.yml:111
# (G13): the battle suite uses exactly `image:
# litespeedtech/openlitespeed:latest` on the same upstream, so
# there is NO tag guesswork in P6.6.
#
# --os=linux is REQUIRED: docker.io/litespeedtech/openlitespeed:latest's
# OCI image index has no "freebsd" OS variant, only linux/*. Without
# --os=linux, podman on FreeBSD defaults to looking for a
# freebsd-OS manifest and fails with "no image found in image
# index for architecture amd64 ... OS freebsd" (G2; same flag
# 088 podman-spike step 5 used for docker.io/alpine and 089
# integration.sh / 091 integration.sh / integration.sh / integration.sh
# / integration.sh use for their respective images).
#
# Why standalone `podman run` (NO `--pod`, per G7): podman on
# FreeBSD (podman 5.8.3, ocijail 0.6.0) breaks the linuxulator for
# containers launched inside a pod, even with identical flags.
# Decision 2 + G7 explicitly mandate standalone for every per-
# backend run script; podman-compose is recorded as technically
# infeasible (Deferred 091.7 Revised).
#
# Why port 80 (not 8080) — battle-suite parity, NOT a G15 risk:
#   The stock OLS docker template's vhost listens on :80
#   (battle docker-compose.yml:113 maps "8087:80" — host 8087 to
#   container 80). The OLS master process runs as root and binds
#   :80; the worker serves traffic. Inside the CNI (no host
#   port-publish), the port is arbitrary from the host's
#   perspective, but stock OLS serves :80 and overriding that
#   would require either (a) a custom httpd_config.xml (no
#   go — we agreed no Dockerfile for P6), or (b) an LSWS_PORT
#   env var (OLS does not honour one in the stock template).
#   Using :80 is the path of least surprise: the access log
#   format is the same regardless of port, and the curl attacker
#   in step 6 hits :80 directly via the container's CNI IP.
#   G15 (privileged-port bind as non-root) does NOT apply here
#   because the master process IS root; the same applies to
#   httpd (G15 used :8080 for httpd because the master was
#   already validated on :8080 in P5).
#
# CRITICAL: the WHY-comment block above MUST stay OUTSIDE the $(...)
# command substitution. If a comment line is inserted between the -v
# flag backslash-continuation and the image name, the comment (which
# has no trailing backslash) breaks the continuation chain -- the
# $(...) closes early and the image name becomes a separate broken
# command. sh -n and shellcheck do NOT catch this class of bug; it is
# a runtime bug, not a syntax bug. Same caveat as integration.sh:253
# and the caddy post-mortem in .tmp/coder-brief-091-p2-fix2.md.
# ---------------------------------------------------------------------
echo "[litespeed] starting OLS container (image: docker.io/litespeedtech/openlitespeed:latest, port: $LSWS_PORT)..."
LITESPEED_CID=$(podman run -d \
    --os=linux \
    --name litespeed \
    --network "$NETWORK" \
    -v "$WORK_DIR/logs:/usr/local/lsws/logs" \
    -v "$WORK_DIR/webapp:/var/www/vhosts/localhost/html:ro" \
    docker.io/litespeedtech/openlitespeed:latest)
echo "[litespeed] container $LITESPEED_CID started"

# Wait for OLS to be ready: log-grep pattern ONLY (no wget,
# following the caddy/traefik/apache lessons — see file header
# WHY-comment). The OLS master process writes a startup banner
# that includes the literal substring "LiteSpeed" — the
# conservative grep matches it. A 3s grace sleep after the
# pattern fires covers the post-banner init window (worker
# spawn + log file open + accesslog fd ready). If P6.6 reveals
# a more specific marker, tighten the grep; the conservative
# form is the safe default.
echo "[litespeed] waiting for OLS ready (timeout 30s)..."
DEADLINE=$(($(date +%s) + 30))
READY=0
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    # "[OK] litespeed: pid=NNNN." — confirmed exact startup line from
    # live dispatch 28560759487 (lowercase "litespeed", NOT "LiteSpeed"
    # as originally guessed — grep is case-sensitive by default, so
    # the mismatched-case pattern never matched, timing out the full
    # 30s despite OLS starting successfully within ~1s). Case-
    # insensitive grep now, matching both the confirmed real line and
    # any future banner variant.
    if podman logs litespeed 2>&1 | grep -qi "litespeed"; then
        sleep 3
        READY=1
        break
    fi
    sleep 1
done
if [ "$READY" -ne 1 ]; then
    echo "[litespeed] FAIL: OLS not ready within 30s" >&2
    echo "[litespeed] access log content (if any):" >&2
    cat "$WORK_DIR/logs/$LSWS_LOG_NAME" >&2 || true
    echo "[litespeed] podman logs (last 30 lines):" >&2
    podman logs --tail 30 litespeed >&2 || true
    exit 1
fi
echo "[litespeed] OLS ready"

# ---------------------------------------------------------------------
# Step 4: start the native sentinel. DECISIONS §2 — sentinel on host,
# NOT in a container. CWD = $WORK_DIR so the relative paths in
# sentinel-litespeed.yaml resolve. The sentinel writes its pid to
# /tmp/arxsentinel.pid (per the yaml) and its operational log to
# sentinel-litespeed.log under $WORK_DIR.
# ---------------------------------------------------------------------
echo "[litespeed] starting native sentinel (CWD=$WORK_DIR)..."
cd "$WORK_DIR"
"$SENTINEL_BIN" \
    --config "$WORK_DIR/sentinel-litespeed.yaml" \
    > "$WORK_DIR/sentinel-litespeed.log" 2>&1 &
SENTINEL_PID=$!
echo "[litespeed] sentinel started with PID $SENTINEL_PID"

# Step 5: wait for "watching started" in sentinel-litespeed.log. This
# sync prevents the host append in step 6 from racing the TailReader
# open+seek(EOF) (mirrors 088 run-smoke.sh step 3). The yaml's
# logging.debug: true is REQUIRED for the "TAIL watching started"
# line to be emitted (see sentinel-litespeed.yaml header).
echo "[litespeed] waiting for 'watching started' (timeout 30s)..."
DEADLINE=$(($(date +%s) + 30))
WATCHING=0
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    if grep -q "watching started" "$WORK_DIR/sentinel-litespeed.log" 2>/dev/null; then
        WATCHING=1
        break
    fi
    sleep 1
done
if [ "$WATCHING" -ne 1 ]; then
    echo "[litespeed] FAIL: 'watching started' not seen within 30s" >&2
    echo "[litespeed] sentinel log (last 50 lines):" >&2
    tail -50 "$WORK_DIR/sentinel-litespeed.log" >&2 || true
    kill "$SENTINEL_PID" 2>/dev/null || true
    exit 1
fi
echo "[litespeed] TailReader ready"

# ---------------------------------------------------------------------
# Step 6: drive attacks from a curl container. DECISIONS §3 said the
# curl container could resolve "litespeed" via container DNS — live
# runs for nginx/caddy/traefik/haproxy/apache disproved that: the
# FreeBSD `containernetworking-plugins` port ships the basic CNI
# bridge plugin only, NOT a dnsname plugin (G6; same as nginx +
# caddy + traefik + haproxy + apache). Resolve the OLS container's
# CNI IP via `podman inspect` instead of relying on DNS, and use
# the IP directly in the curl URL.
#
# Per Flow 092 DECISIONS §7 (close the Flow 091 Decision 9 gap): all
# 7 attack scenario blocks (probe, ua, bruteforce, crawler, noasset,
# rate, overflow) + the badbot (block 8) are now driven from a SINGLE
# curl container, mirroring tests/integration/scenarios.sh:80-183
# (battle suite source of truth). The previous P6.3 implementation
# sent only 3 requests (2 sqlmap-UA + 1 Mozilla) — exercising ONLY
# the `ua` module incidentally. The 8-block sequence is the
# battle-parity coverage (Flow 092 Decision 7 — same port, same
# assertion style, across all six per-backend jobs).
#
# Port :80 (NOT :8080): the stock OLS docker template's vhost Listen
# is :80 (battle docker-compose.yml:113 maps "8087:80"). The OLS
# master process runs as root inside the container and binds :80; the
# worker serves traffic. G15 (privileged-port bind as non-root) does
# NOT apply here because the master process IS root, unlike the
# httpd path which bound :8080 for the non-root-User constraint. This
# matches integration.sh's documented port choice (Step 3 WHY-comment
# in the LITESWS_PORT block above).
# ---------------------------------------------------------------------
SQLMAP_UA='sqlmap/1.7.11'
MOZILLA_UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'

# `index` (not dot-notation) is REQUIRED: $NETWORK contains a hyphen
# ("arx-net"), and a Go template map-key access via dot-notation
# (.Networks.arx-net.IPAddress) parses the hyphen as a subtraction
# operator and fails with "bad character U+002D '-'" (G8; live run
# 28477133986 hit this exact error). `index` takes the key as a
# string argument, sidestepping Go template identifier syntax rules.
LITESPEED_IP=$(podman inspect litespeed --format "{{(index .NetworkSettings.Networks \"${NETWORK}\").IPAddress}}")
if [ -z "$LITESPEED_IP" ]; then
    echo "[litespeed] FAIL: could not resolve litespeed container's CNI IP via podman inspect" >&2
    exit 1
fi
echo "[litespeed] litespeed container IP: $LITESPEED_IP"

# Generate the long URL path for the overflow scenario (block 7) on
# the HOST (not inside the curl container) so the value can be
# embedded as a literal in the -c "..." script string below.
#
# NOT scenarios.sh:169's `/dev/urandom | tr -dc 'a-zA-Z0-9'` recipe:
# G20 (proven live on nginx/caddy/traefik/haproxy/apache) —
# produces EMPTY output on this FreeBSD VM's native sh (BSD tr vs
# GNU tr, or /dev/urandom access under vmactions SSH — root cause
# not pinned). The overflow detector only checks byte length, not
# entropy, so a deterministic `awk` one-liner is sufficient:
# POSIX-standard, zero external-tool portability surface. Same fix
# as apache/integration.sh:427 and traefik/integration.sh:362.
LONG_PATH="/$(awk 'BEGIN { s = ""; for (i = 0; i < 2200; i++) s = s "a"; print s }')"
# Diagnostic (live run 28585617384 found the overflow assertion
# failing with no obvious quoting bug on static read) — print the
# byte length so a re-dispatch can confirm/rule out FreeBSD's tr(1)
# behaving differently from scenarios.sh's Linux/GNU-tr assumption
# for `-dc 'a-zA-Z0-9'`.
echo "[litespeed] LONG_PATH length: $(printf '%s' "$LONG_PATH" | wc -c) bytes"

# Pick the badbot UA the same way apache/integration.sh:438-442
# does: prefer the committed test fixture
# ($REPO_ROOT/tests/integration/blocklist/test-ua.txt) because it
# is the same file run.sh:122 produces from the FIRST literal
# pattern in the upstream mitchellkrogza list — a pattern the
# FreeBSD sentinel's blocklist automaton will also load (same
# upstream URL, see sentinel-litespeed.yaml blocklist.lists[0].
# sources[0].url — added in Flow 092 Task A6). Fallback
# "AhrefsBot" matches scenarios.sh:179 — a UA guaranteed to be
# in the upstream list as a regex literal.
if [ -s "$REPO_ROOT/tests/integration/blocklist/test-ua.txt" ]; then
    BADBOT_UA=$(head -1 "$REPO_ROOT/tests/integration/blocklist/test-ua.txt")
else
    BADBOT_UA="AhrefsBot"
fi
echo "[litespeed] using badbot UA for block 8: ${BADBOT_UA}/1.0"

# ONE curl container for ALL 8 blocks (NOT one per block) — mirrors
# apache/integration.sh:445-453 + traefik/integration.sh:391-408.
# Detectors (bruteforce, crawler, noasset, rate) are per-IP trackers;
# multiple attacker containers would each see only a fraction of the
# required request count → no fire → no threat log entry → false-
# negative assertion. The Mozilla UA legit request is folded into
# block 2 (ua) as the last request — same reasoning as
# apache/integration.sh:476-480 (assertion 2 only makes sense in
# the context of the scanner-UA attack on the same IP).
#
# The 8 blocks are verbatim ports from tests/integration/
# scenarios.sh:80-183 (per Flow 092 Decision 7) — each block's
# source line is annotated in the same WHY comment style as the
# rest of this file. Port :80 is the stock OLS docker template's
# default (battle docker-compose.yml:113).
echo "[litespeed] driving 8 attack blocks from a single curl container..."
ATTACK_SCRIPT="
# ── block 1: probe (scenarios.sh:82-90) ──
curl -sf -o /dev/null http://${LITESPEED_IP}/wp-login.php      || true
curl -sf -o /dev/null http://${LITESPEED_IP}/.env              || true
curl -sf -o /dev/null http://${LITESPEED_IP}/.git/config       || true
curl -sf -o /dev/null http://${LITESPEED_IP}/admin/config.php  || true
curl -sf -o /dev/null http://${LITESPEED_IP}/etc/passwd        || true
curl -sf -o /dev/null http://${LITESPEED_IP}/.aws/credentials  || true
curl -sf -o /dev/null http://${LITESPEED_IP}/xmlrpc.php        || true
# ── block 2: ua (scenarios.sh:94-100) + the legit Mozilla request ──
curl -sf -o /dev/null -A '${SQLMAP_UA}'     http://${LITESPEED_IP}/ || true
curl -sf -o /dev/null -A '${SQLMAP_UA}'     http://${LITESPEED_IP}/ || true
curl -sf -o /dev/null -A 'Nuclei/3.0'       http://${LITESPEED_IP}/ || true
curl -sf -o /dev/null -A 'masscan/1.3'      http://${LITESPEED_IP}/ || true
curl -sf -o /dev/null -A 'zgrab/0.x'        http://${LITESPEED_IP}/ || true
# Legit Mozilla request — kept in block 2 (NOT a separate block)
# because Assertion 2 (Mozilla UA absent from threat log) only
# makes sense in the context of the scanner-UA attack on the same
# IP. Mirrors apache/integration.sh:476-480 + traefik/
# integration.sh:429-437.
curl -sf -o /dev/null -A '${MOZILLA_UA}'    http://${LITESPEED_IP}/ || true
# ── block 3: bruteforce (scenarios.sh:104-120) ──
curl -sf -o /dev/null http://${LITESPEED_IP}/                      || true
curl -sf -o /dev/null http://${LITESPEED_IP}/                      || true
curl -sf -o /dev/null http://${LITESPEED_IP}/                      || true
curl -sf -o /dev/null http://${LITESPEED_IP}/missing-page-1        || true
curl -sf -o /dev/null http://${LITESPEED_IP}/missing-page-2        || true
curl -sf -o /dev/null http://${LITESPEED_IP}/missing-page-3        || true
curl -sf -o /dev/null http://${LITESPEED_IP}/missing-page-4        || true
curl -sf -o /dev/null http://${LITESPEED_IP}/missing-page-5        || true
curl -sf -o /dev/null http://${LITESPEED_IP}/missing-page-6        || true
curl -sf -o /dev/null http://${LITESPEED_IP}/missing-page-7        || true
curl -sf -o /dev/null http://${LITESPEED_IP}/missing-page-8        || true
curl -sf -o /dev/null http://${LITESPEED_IP}/missing-page-9        || true
curl -sf -o /dev/null http://${LITESPEED_IP}/missing-page-10       || true
curl -sf -o /dev/null http://${LITESPEED_IP}/missing-page-11       || true
curl -sf -o /dev/null http://${LITESPEED_IP}/missing-page-12       || true
# ── block 4: crawler (scenarios.sh:126-132) ──
curl -sf -o /dev/null http://${LITESPEED_IP}/items/1  || true
curl -sf -o /dev/null http://${LITESPEED_IP}/items/2  || true
curl -sf -o /dev/null http://${LITESPEED_IP}/items/3  || true
curl -sf -o /dev/null http://${LITESPEED_IP}/items/4  || true
curl -sf -o /dev/null http://${LITESPEED_IP}/items/5  || true
curl -sf -o /dev/null http://${LITESPEED_IP}/items/6  || true
# ── block 5: noasset (scenarios.sh:138-146) ──
curl -sf -o /dev/null http://${LITESPEED_IP}/           || true
curl -sf -o /dev/null http://${LITESPEED_IP}/           || true
curl -sf -o /dev/null http://${LITESPEED_IP}/           || true
curl -sf -o /dev/null http://${LITESPEED_IP}/info.php   || true
curl -sf -o /dev/null http://${LITESPEED_IP}/           || true
curl -sf -o /dev/null http://${LITESPEED_IP}/           || true
curl -sf -o /dev/null http://${LITESPEED_IP}/info.php   || true
curl -sf -o /dev/null http://${LITESPEED_IP}/           || true
# ── block 6: rate (scenarios.sh:151-161) — 60 requests in 2 waves with 1s gap ──
i=0; while [ \$i -lt 30 ]; do
    curl -sf -o /dev/null http://${LITESPEED_IP}/ || true
    i=\$((i+1))
done
sleep 1
i=0; while [ \$i -lt 30 ]; do
    curl -sf -o /dev/null http://${LITESPEED_IP}/ || true
    i=\$((i+1))
done
# ── block 7: overflow (scenarios.sh:169-172) — single URL with path > 2048 bytes ──
curl -sf -o /dev/null 'http://${LITESPEED_IP}${LONG_PATH}' || true
# ── block 8: badbot (scenarios.sh:180-183) — LAST on purpose ──
# scenarios.sh:177-178: 'Placed last among direct-server scenarios to
# give sentinels time to load patterns from the local blocklist-server
# container before the request arrives.' Same reasoning applies here
# (blocklist fetch is async from start, automaton rebuild on first
# successful fetch — badbot last gives the wall-clock budget). Two
# requests, not one, for the same threshold-crossing reason as the
# sqlmap pair in block 2 (the badbot detector's first hit may not
# cross the alert threshold on its own).
curl -sf -o /dev/null -A '${BADBOT_UA}/1.0' http://${LITESPEED_IP}/ || true
curl -sf -o /dev/null -A '${BADBOT_UA}/1.0' http://${LITESPEED_IP}/ || true
"

# Fully-qualified docker.io/curlimages/curl (NOT bare curlimages/curl)
# — same short-name resolution issue as the OLS image above (G1).
# --os=linux — same image-index reasoning as the OLS container
# above (curlimages/curl has no freebsd OS variant either) (G2).
podman run --rm --os=linux --network "$NETWORK" \
    --entrypoint /bin/sh \
    docker.io/curlimages/curl \
    -c "$ATTACK_SCRIPT" \
    >/dev/null 2>&1 \
    || echo "[litespeed] curl attacker exited non-zero (still check the access log)"
echo "[litespeed] attacks sent"

# Settling delay (live run 28598545541 found this necessary): the
# Step 7 poll loop below breaks as soon as the threat log has ANY
# content — typically within 1-2s of the FIRST attack block (probe)
# firing, well before OLS has flushed its own access log for the
# LAST attack blocks (rate=60 requests, overflow=1 request) sent in
# this same synchronous curl invocation. All 5 other backends
# (nginx/caddy/traefik/haproxy/apache) settle fast enough that this
# race never manifested; OLS's own access-log write/flush latency is
# evidently slower under this load. 3s is empirical headroom, not a
# principled bound — if a future run still shows rate/overflow
# missing, raise this further before suspecting a logic bug.
sleep 3

# ---------------------------------------------------------------------
# Step 7: poll the threat log for non-empty content. Timeout RAISED
# from 20s → 40s as part of Task A6 (Flow 092 Decision 7): the
# previous 3-request Step 6 finished in <1s of attack traffic; the
# new 8-block Step 6 sends ~7 + 6 + 15 + 6 + 8 + 60 + 1 + 2 = 105
# attack requests, with the rate block's 1s sleep and the
# sentinel's per-request scoring adding wall-clock cost on top. 40s
# is a conservative budget for the polling loop (the actual elapsed
# time in CI is typically 3-5s, the rest is margin for first-podman-
# pull + cold blocklist-fetch). Mirrors apache/integration.sh:558-559
# + traefik/integration.sh:519-520 (proven green pattern).
# ---------------------------------------------------------------------
THREAT_LOG="$WORK_DIR/output/threats-litespeed.log"
echo "[litespeed] polling $THREAT_LOG (timeout 40s)..."
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
    echo "[litespeed] FAIL: $THREAT_LOG not written within 40s" >&2
    echo "[litespeed] access log content (if any):" >&2
    cat "$WORK_DIR/logs/$LSWS_LOG_NAME" >&2 || true
    echo "[litespeed] sentinel log (last 80 lines):" >&2
    tail -80 "$WORK_DIR/sentinel-litespeed.log" >&2 || true
    exit 1
fi

# Dump the threat log for inline visibility.
LINES=$(cat "$THREAT_LOG")
echo "[litespeed] threat log content:"
printf '%s\n' "$LINES" | sed 's/^/  /'

# ---------------------------------------------------------------------
# Step 7a: extract the sqlmap-request source IP from the access log.
# DECISIONS §5 — the attacker's source IP is the curl container's
# CNI-assigned IP, which appears in access.log as the first field
# of the line containing the sqlmap UA. The apache CLF format
# prefixes the line with "<client_ip> ..." — the IP is the
# space-delimited first field, straightforward awk. (The litespeed
# profile uses apacheCLFPattern, so the field structure is
# byte-for-byte identical to httpd.)
# ---------------------------------------------------------------------
ACCESS_LOG="$WORK_DIR/logs/$LSWS_LOG_NAME"
if [ ! -s "$ACCESS_LOG" ]; then
    echo "[litespeed] FAIL: access log empty or missing at $ACCESS_LOG" >&2
    exit 1
fi
# grep the sqlmap UA (literal, no regex specials) then awk the first
# field. Safe even if the UA contains regex chars — grep treats it
# as a fixed string in this case (no -E flag).
SQLMAP_IP=$(grep "${SQLMAP_UA}" "$ACCESS_LOG" | awk '{print $1}' | head -1)
if [ -z "$SQLMAP_IP" ]; then
    echo "[litespeed] FAIL: could not extract sqlmap request IP from access log" >&2
    echo "[litespeed] access log content:" >&2
    cat "$ACCESS_LOG" >&2 || true
    exit 1
fi
echo "[litespeed] sqlmap request source IP: $SQLMAP_IP"

# Diagnostic (mirrors apache/integration.sh:617-622, traefik/
# integration.sh:576-581 — same overflow-assertion failure mode on
# run 28585617384): print the access-log line matching the long-path
# request, and its byte length, to see what OLS actually logged for
# it (full URI vs truncated vs never received). OLS's CLF output
# (default Combined Log Format with UA) writes a single line per
# request, so a > 2048-byte path in the request field still produces
# a parsable line; this diagnostic confirms the long path made it
# through OLS (not rejected at the HTTP layer) and into the access
# log.
OVERFLOW_LOG_LINE=$(grep -E '"GET /[a-zA-Z0-9]{100,}' "$ACCESS_LOG" | head -1)
if [ -n "$OVERFLOW_LOG_LINE" ]; then
    echo "[litespeed] overflow request access-log line length: $(printf '%s' "$OVERFLOW_LOG_LINE" | wc -c) bytes"
else
    echo "[litespeed] overflow request NOT FOUND in access log (long-path GET never logged)"
fi

# ---------------------------------------------------------------------
# Step 7b: assertions. Originally 3 per DECISIONS §5 (adapted from
# 088 run-smoke.sh — UA-based, not IP-based). EXTENDED to 12 per
# Flow 092 Task A6 / Decision 7: 1-3 retained, 4-10 are one
# `grep -qw "reason=<module>"` per attack scenario (mirrors
# tests/integration/verify.sh:144 assert_module's exact grep
# pattern), 11 is badbot module presence, 12 is the blocklist
# automaton-loaded check (mirrors verify.sh:109
# assert_blocklist_loaded's exact regex). A single FAIL on any
# assertion sets FAIL=1; the script reports all at the end (does
# not short-circuit, so the grader can see the full failure shape).
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
    echo "[litespeed] FAIL: assertion 1 - expected ' THREAT ' and IP '$SQLMAP_IP' in threat log" >&2
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
    echo "[litespeed] FAIL: assertion 2 - false positive: Mozilla UA appeared in threat log" >&2
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
    echo "[litespeed] FAIL: assertion 3 - $BAD_COUNT threat line(s) missing score=/reason=" >&2
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
        echo "[litespeed] FAIL: assertion - expected module '$module' in threat log (reason=)" >&2
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
    echo "[litespeed] FAIL: assertion 11 - badbot module not in threat log (expected reason=badbot:...)" >&2
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
# in sentinel-litespeed.yaml → upstream fetch → automaton rebuild
# → UA matching in block 8's requests. The operational log path is
# `output.operational_log: sentinel-litespeed.log` in
# sentinel-litespeed.yaml — relative to $WORK_DIR, which is the
# sentinel's CWD (set in Step 4).
SENTINEL_OP_LOG="$WORK_DIR/sentinel-litespeed.log"
if [ ! -s "$SENTINEL_OP_LOG" ] \
   || ! grep -qE 'automaton rebuilt \([1-9][0-9]* patterns\)' "$SENTINEL_OP_LOG"; then
    echo "[litespeed] FAIL: assertion 12 - blocklist automaton not loaded (no 'automaton rebuilt (N patterns)' with N>0 in $SENTINEL_OP_LOG)" >&2
    FAIL=1
fi

# ---------------------------------------------------------------------
# Step 8: persist artifacts for the workflow. The cleanup trap on
# EXIT (set in step 1) does NOT remove $WORK_DIR when TMPDIR is
# $GITHUB_WORKSPACE — the workflow's actions/upload-artifact picks
# up these files BEFORE the VM is destroyed (P6.4 carry of 089 Task
# 3.6 / 4.3). The copies here land at the top of $TMPDIR (=
# $GITHUB_WORKSPACE in CI) so the workflow's `cat
# $GITHUB_WORKSPACE/...` + `upload-artifact` at P6.4 can find them
# by name.
# ---------------------------------------------------------------------
if [ -s "$THREAT_LOG" ]; then
    cp "$THREAT_LOG" "${TMPDIR:-/tmp}/threats-litespeed.log.smoke"
fi
if [ -s "$ACCESS_LOG" ]; then
    cp "$ACCESS_LOG" "${TMPDIR:-/tmp}/litespeed-access.log"
fi

# ---------------------------------------------------------------------
# Steps 10-16: proxy-chain scenario. Flow 092 (DECISIONS §1-§6).
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
# chicken-and-egg problem (the proxy's `proxy_pass` target needs the
# backend's IP BEFORE the backend starts, and vice versa in principle
# — known-upfront IPs make both configs static, no rewrite-on-startup
# dance). It also makes this script's inline log readable: a fixed
# address in the proxy URL is easier to grep-and-know than a
# $LITESPEED_RP_IP capture. N=6 for litespeed (nginx=1, caddy=2,
# traefik=3, haproxy=4, apache=5, litespeed=6 — Flow 092 DECISIONS
# §2 "per-backend offset").
# ---------------------------------------------------------------------

# ---------------------------------------------------------------------
# Step 10: create the chain network with a dedicated subnet
# (10.89.6.0/24 for litespeed — per-backend offset, see Flow 092
# DECISIONS §2; litespeed = N=6 since nginx=1, caddy=2, traefik=3,
# haproxy=4, apache=5). A separate network from the direct-scenario's
# $NETWORK ("arx-net") keeps the two scenarios' CNI bridges
# independent — a podman network create with the same name as a
# pre-existing network exits non-zero, so re-use would need an "if
# exists" dance. A fresh network is the simpler path.
# ---------------------------------------------------------------------
echo "[litespeed] creating chain CNI network $CHAIN_NETWORK (subnet 10.89.6.0/24)..."
podman network create --subnet 10.89.6.0/24 "$CHAIN_NETWORK"

# Static IP assignment for the chain backend (DECISIONS §2/§3).
# .10 within 10.89.6.0/24 — chosen by convention (smallest non-zero
# suffix for the "primary" service in the network, .20 for the
# upstream proxy). Hard-coded, not derived, on purpose: see
# DECISIONS §2 "static IPs also make the chain-scenario shell
# script easier to read and debug from an inline log".
CHAIN_BACKEND_IP="10.89.6.10"
CHAIN_PROXY_IP="10.89.6.20"

# ---------------------------------------------------------------------
# Step 11: start the chain-scenario backend. THIS DIFFERS from the
# other 5 per-backend chain scenarios in ONE key way: litespeed's
# chain backend uses a CUSTOM-built image (litespeed-arxsentinel:
# local), NOT the stock docker.io/litespeedtech/openlitespeed:latest
# used by the direct scenario in Step 3.
#
# Why a custom image is REQUIRED for litespeed (and only litespeed):
#   The OLS XFF-trust mechanism (per DECISIONS §5 litespeed row's
#   `useIpInHeader` investigation note) is NOT a runtime-mountable
#   config directive — it requires patching
#   `/usr/local/lsws/conf/templates/docker.conf` at image build
#   time, injecting a `logFormat` directive that puts
#   `%{X-Forwarded-For}i` in the first (client-IP) field position.
#   This is the SAME class of fix as caddy's G21 (XFF-fallback log
#   FORMAT STRING, not a runtime "trust" config directive). The
#   patch-ols-logformat.py + LiteSpeedBackend.Dockerfile pair in
#   tests/integration/dockerfiles/ performs this exact patch —
#   this is the same Dockerfile the battle suite uses for its
#   `litespeed-backend:` service (docker-compose.yml:111-117
#   variant) for the proxy-chain scenario.
#
# The workflow's host-build step (the
# `.github/workflows/freebsd-integration.yml` `Build litespeed-
# arxsentinel image on host` step added in Flow 092) builds
# litespeed-arxsentinel:local on the ubuntu-latest runner (native
# Docker, no FreeBSD Linux-emul surface) and saves it to
# $GITHUB_WORKSPACE/litespeed-arxsentinel.tar. vmactions/freebsd-vm's
# pre-run rsync carries the tar into the VM at the same path, and
# `podman load -i ...` here imports it into the VM's podman store.
#
# Why we still run the podman load here (in addition to any
# possible workflow run:-level load): the host-build tar's
# destination path inside the VM is identical to
# $GITHUB_WORKSPACE/litespeed-arxsentinel.tar, and a
# `podman load -i` against a valid tar is idempotent (the image
# cache key is by tag+hash, so a re-load of the same tar is a
# no-op). Doing the load here — in Step 11, right before the
# chain backend container start — guarantees the image is
# available regardless of which workflow-level unblock-chain
# step also performs a load (DECISIONS §1-6 "deterministic
# pre-conditions for the assertion"). Same defensive style as
# caddy/integration.sh's pattern (caddy's pre-existing
# caddy-arxsentinel:local image is loaded by the workflow's
# `podman load -i caddy-arxsentinel.tar` step at freebsd-
# integration.yml:773; the integration.sh itself does not re-
# load because caddy's proven host-build step is older and
# always runs the load).
#
# Why NO bind-mount of a chain-specific config file (unlike
# nginx, caddy, traefik, haproxy, apache): the OLS logFormat
# patch is baked into the image (Dockerfile time), not applied
# via a runtime-mounted conf file. The chain backend's OLS
# vhost template already has the XFF-first logFormat when the
# container starts, so no `httpd-chain.conf` (or equivalent)
# file is needed. We bind-mount the SAME webapp + logs volumes
# the direct scenario uses (Step 3 above) — the patched OLS
# vhost template writes its XFF-first log lines to
# /usr/local/lsws/logs/localhost.access.log, which the bind-
# mount surfaces as $WORK_DIR/logs-chain/localhost.access.log
# on the host. Same webapp contents (arxsentinel-091-
# litespeed) — the chain attacker hits the same index.html.
#
# Port :80 (NOT :8080): the OLS chain backend uses the SAME
# stock vhost Listen :80 as the direct scenario (Step 3
# WHY-comment + battle docker-compose.yml:113). The OLS master
# process binds :80; no G15 risk (master IS root). The proxy
# in Step 12 sends requests to 10.89.6.10:80.
# ---------------------------------------------------------------------
echo "[litespeed] loading litespeed-arxsentinel:local from host-built tar (chain scenario)..."
if [ -s "$GITHUB_WORKSPACE/litespeed-arxsentinel.tar" ]; then
    podman load -i "$GITHUB_WORKSPACE/litespeed-arxsentinel.tar" \
        || echo "[litespeed] WARN: podman load litespeed-arxsentinel FAILED (chain backend start will fail)"
else
    echo "[litespeed] FAIL: \$GITHUB_WORKSPACE/litespeed-arxsentinel.tar not found or empty" >&2
    exit 1
fi

mkdir -p "$WORK_DIR/logs-chain"
echo "[litespeed] starting chain-scenario litespeed container on $CHAIN_BACKEND_IP..."
LITESPEED_CHAIN_CID=$(podman run -d \
    --os=linux \
    --name litespeed-chain \
    --network "$CHAIN_NETWORK" \
    --ip "$CHAIN_BACKEND_IP" \
    -v "$WORK_DIR/logs-chain:/usr/local/lsws/logs" \
    -v "$WORK_DIR/webapp:/var/www/vhosts/localhost/html:ro" \
    litespeed-arxsentinel:local)
echo "[litespeed] chain backend $LITESPEED_CHAIN_CID started"

# Wait-for-ready pattern identical to Step 3: log-grep on
# "litespeed" (case-insensitive — live run 28560759487 found the
# real line uses lowercase, the original `grep -q "LiteSpeed"`
# uppercased pattern never matched until switched to
# `grep -qi`) + 3s grace sleep for worker spawn + accesslog fd
# ready. Same conservative form proven on the direct-scenario
# litespeed:latest.
echo "[litespeed] waiting for chain backend ready (timeout 30s)..."
DEADLINE=$(($(date +%s) + 30))
READY=0
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    if podman logs litespeed-chain 2>&1 | grep -qi "litespeed"; then
        sleep 3
        READY=1
        break
    fi
    sleep 1
done
if [ "$READY" -ne 1 ]; then
    echo "[litespeed] FAIL: chain backend not ready within 30s" >&2
    echo "[litespeed] chain backend logs (last 30 lines):" >&2
    podman logs --tail 30 litespeed-chain >&2 || true
    exit 1
fi
echo "[litespeed] chain backend ready"

# ---------------------------------------------------------------------
# Step 12: start the proxy container. VERBATIM copy of the proven
# nginx-rp pattern from tests/integration-freebsd/apache/
# integration.sh (Step 12, lines 949-989) — same `docker.io/library/
# nginx:alpine` image, same `error_log /dev/stderr notice; include
# mime.types; open_log_file_cache off;` directive set (G17: reuse
# PROVEN template, not a minimal from-scratch one), with ONLY the
# `proxy_pass` target swapped to the litespeed chain backend's
# static IP ($CHAIN_BACKEND_IP = 10.89.6.10) and port :80.
#
# The decision to use nginx-rp as the universal proxy for ALL
# backends (not just nginx) is Flow 092 Decision 1 — one generic
# reverse-proxy pattern, ported per backend. The litespeed-direct-
# scenario job needs to exercise litespeed's XFF-resolved access
# log (via the custom litespeed-arxsentinel:local image's patched
# logFormat); which proxy sits in front of it is incidental
# (nginx-rp is the proven, battle-suite-parity choice).
#
# Port :80 (NOT :8080): the litespeed chain backend binds :80 (the
# stock OLS docker template default — battle docker-compose.yml:113
# maps "8087:80"). The master process IS root, so :80 binds cleanly
# inside the ocijail-launched container. The proxy here sends to
# 10.89.6.10:80.
# ---------------------------------------------------------------------
cat > "$WORK_DIR/litespeed-rp.conf" <<NGINX_RP_EOF
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

# Bind-mount /var/log/nginx for consistency with the proven template
# (nginx/integration.sh Step 12 does the same) — this script never
# reads the proxy's own log, but matching the proven container-start
# shape exactly (bind-mount + error_log /dev/stderr) removes it as a
# variable.
mkdir -p "$WORK_DIR/litespeed-rp"
echo "[litespeed] starting proxy container on $CHAIN_PROXY_IP..."
LITESPEED_RP_CID=$(podman run -d \
    --os=linux \
    --name litespeed-rp \
    --network "$CHAIN_NETWORK" \
    --ip "$CHAIN_PROXY_IP" \
    -v "$WORK_DIR/litespeed-rp.conf:/etc/nginx/nginx.conf:ro" \
    -v "$WORK_DIR/litespeed-rp:/var/log/nginx" \
    docker.io/library/nginx:alpine)
echo "[litespeed] proxy $LITESPEED_RP_CID started"

# Same wait-for-ready pattern as apache/chain proxy. nginx -t
# catches the heredoc-substituted config typo case; "start worker
# processes" in podman logs is the full-start signal.
echo "[litespeed] waiting for proxy ready (timeout 30s)..."
DEADLINE=$(($(date +%s) + 30))
READY=0
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    if podman exec litespeed-rp nginx -t >/dev/null 2>&1 \
       && podman logs litespeed-rp 2>&1 | grep -q "start worker processes"; then
        READY=1
        break
    fi
    sleep 1
done
if [ "$READY" -ne 1 ]; then
    echo "[litespeed] FAIL: proxy not ready within 30s" >&2
    echo "[litespeed] proxy logs (last 30 lines):" >&2
    podman logs --tail 30 litespeed-rp >&2 || true
    exit 1
fi
echo "[litespeed] proxy ready"

# ---------------------------------------------------------------------
# Step 13: drive attacks THROUGH the proxy. Same UA mix as Step 6
# (sqlmap x2 + Mozilla x1) but the URL is the proxy's static IP
# (http://10.89.6.20/), NOT the chain backend's IP. The proxy adds
# X-Forwarded-For with the curl container's CNI IP, and the chain
# backend's patched OLS logFormat
# (`%{X-Forwarded-For}i %l %u %t "%r" %>s %b` — baked into
# litespeed-arxsentinel:local by patch-ols-logformat.py at image
# build time) writes that real client IP as the logged address (the
# first field that the litespeed parser profile's apacheCLFPattern
# regex extracts). Mirror of the direct-scenario attack — same curl
# image, same attacker behavior, only the URL changes.
#
# --network $NETWORK: the curl container runs on the DIRECT-scenario
# network (arx-net), not the chain network. The two networks are
# isolated — a packet from arx-net cannot reach 10.89.6.20 by
# Layer-2 routing. This is the intended topology: the attacker sits
# on the same "outside" network as in Step 6, the proxy is the
# bridge. The curl container's CNI IP will therefore be on arx-net
# (different from the IP it would have if it were on arx-chain-net)
# — Step 14's assertion extracts the IP from the chain-backend's
# access log, so it doesn't matter that this IP is on a different
# network than the direct scenario's attacker IP.
# ---------------------------------------------------------------------
echo "[litespeed] driving proxy-chain attacks from curl container (sqlmap + Mozilla UAs)..."
podman run --rm --os=linux --network "$NETWORK" \
    --entrypoint /bin/sh \
    docker.io/curlimages/curl \
    -c "curl -sS -A '${SQLMAP_UA}' http://${CHAIN_PROXY_IP}/ ; curl -sS -A '${SQLMAP_UA}' http://${CHAIN_PROXY_IP}/ ; curl -sS -A '${MOZILLA_UA}' http://${CHAIN_PROXY_IP}/" \
    >/dev/null 2>&1 \
    || echo "[litespeed] chain curl attacker exited non-zero (still check the access log)"
echo "[litespeed] chain attacks sent"

# ---------------------------------------------------------------------
# Step 14: chain-specific assertion (4th). Wait for the chain-
# backend's access log to be written, extract the sqlmap-request
# source IP from IT (NOT from the direct-scenario access log), and
# verify that the extracted IP is the REAL client (curl container's
# CNI IP) — NOT the proxy's IP ($CHAIN_PROXY_IP).
#
# KEY DIFFERENCE from the other 5 per-backend chain scenarios:
# litespeed's chain backend uses a CUSTOM BUILT IMAGE
# (litespeed-arxsentinel:local) with a PATCHED logFormat directive
# baked in at image build time. The patched logFormat
# (`%{X-Forwarded-For}i %l %u %t "%r" %>s %b`, written by
# patch-ols-logformat.py during the host-build Dockerfile step)
# substitutes the leftmost X-Forwarded-For value for the client-IP
# field when XFF is present. So the chain access log line for an
# XFF-bearing request is:
#   <XFF-first-hop-IP> - - [<time>] "GET / HTTP/1.1" 200 ...
# instead of the default OLS combined-format:
#   <connecting-peer-IP> - - [<time>] "GET / HTTP/1.1" 200 ...
#
# If the patched image works (litespeed-arxsentinel:local is the
# custom build with the patch), the first field is the curl
# container's CNI IP — NOT the proxy's connecting address
# (10.89.6.20). If the patch is missing or the stock image is
# accidentally used, the first field would be 10.89.6.20 (the
# proxy) — the "ip-leak" class of failure the battle suite's
# assert_chain (verify.sh:188) calls out (class=ip-leak in its
# report). Mirrored here in this script's existing grep-based
# assertion style (Step 7b) — same FAIL=1 accumulator, same
# non-short-circuit report-at-end discipline.
#
# Same apache CLF access log path as the direct scenario
# (localhost.access.log — the OLS vhost name drives the log
# filename). The chain access log lives at
# $WORK_DIR/logs-chain/localhost.access.log on the host (the
# bind-mount of $WORK_DIR/logs-chain onto
# /usr/local/lsws/logs inside the chain container).
# ---------------------------------------------------------------------
CHAIN_ACCESS_LOG="$WORK_DIR/logs-chain/$LSWS_LOG_NAME"
echo "[litespeed] polling $CHAIN_ACCESS_LOG (timeout 20s)..."
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
    echo "[litespeed] FAIL: $CHAIN_ACCESS_LOG not written within 20s" >&2
    echo "[litespeed] proxy logs (last 30 lines):" >&2
    podman logs --tail 30 litespeed-rp >&2 || true
    exit 1
fi

# Extract the sqlmap-request source IP from the chain backend's
# access log. awk the first field (populated by the patched
# logFormat — the real client IP when XFF is present). head -1
# to pick the first match — same convention as Step 7a
# (deterministic, survives multiple hits).
#
# sed 's/^"//': live run 28598545541 found the patched OLS logFormat
# emits a stray leading `"` before the first field in the actual
# access log output (an OLS logFormat-string quirk, present before
# this flow's Dockerfile fork too — not introduced by the
# Referer/User-Agent fields this fork added). Stripping it here is a
# defensive normalization rather than a fix at the source: OLS's
# exact logFormat parsing rule for a leading quoted-placeholder
# wasn't worth chasing further for a single stray character that
# only affects string comparison, not the IP value itself.
CHAIN_SQLMAP_IP=$(grep "${SQLMAP_UA}" "$CHAIN_ACCESS_LOG" | awk '{print $1}' | head -1 | sed 's/^"//')
if [ -z "$CHAIN_SQLMAP_IP" ]; then
    echo "[litespeed] FAIL: could not extract sqlmap request IP from chain access log" >&2
    echo "[litespeed] chain access log content:" >&2
    cat "$CHAIN_ACCESS_LOG" >&2 || true
    exit 1
fi
echo "[litespeed] chain sqlmap request source IP (as logged by chain backend): $CHAIN_SQLMAP_IP"

# Assertion 4: the IP logged by the chain backend must NOT be the
# proxy's IP. If it IS the proxy's IP, the patched logFormat did
# not resolve the real client and OLS is logging the proxy's
# connecting address instead — the exact failure mode assert_chain
# in tests/integration/verify.sh:188 calls "ip-leak". Conversely,
# any non-proxy IP is treated as a PASS for this assertion (the
# detailed IP-correctness of the curl container's CNI assignment
# is not what we are asserting here; what matters is "not the
# proxy's IP"). Mirrors apache/integration.sh:1118-1121 +
# traefik/integration.sh:1028-1031.
if [ "$CHAIN_SQLMAP_IP" = "$CHAIN_PROXY_IP" ]; then
    echo "[litespeed] FAIL: assertion 4 - patched logFormat did not resolve proxy chain - logged proxy IP instead of real client IP (ip-leak)" >&2
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
# direct-scenario litespeed-access.log for an operator to grab.
# ---------------------------------------------------------------------
if [ -s "$CHAIN_ACCESS_LOG" ]; then
    cp "$CHAIN_ACCESS_LOG" "${TMPDIR:-/tmp}/litespeed-chain-access.log"
fi

# Step 16 (was Step 9): final report. Cleanup happens via the EXIT
# trap. FAIL=1 may have been set by either Step 7b's direct-scenario
# assertions OR Step 14's chain-scenario assertion — both
# accumulate into the same flag, both are reported by this single
# exit-code decision.
if [ "$FAIL" -ne 0 ]; then
    echo "[litespeed] FAIL: one or more assertions failed (see above)"
    exit 1
fi
echo "[litespeed] PASS: all assertions green - direct + proxy-chain FreeBSD/podman litespeed integration end-to-end works"
exit 0
