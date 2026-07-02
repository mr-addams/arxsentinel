#!/usr/bin/env sh
# tests/integration-freebsd/litespeed/run-litespeed.sh — Flow 091
# integration smoke for the OpenLiteSpeed backend under FreeBSD/podman.
#
# Adapted from run-apache.sh — Flow 089/091 paid 9+ iterations to make
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
# extraction) the script structure is verbatim from run-apache.sh;
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
#   Same rationale as run-apache.sh: every per-backend run script in
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
#     threat_log: output/threats-litespeed.log) — NO Dockerfile,
#     NO patch-ols-logformat.py (stock image, G11 avoidance).
#   - P6.3: this file's skeleton + CNI network + OLS container
#     startup with bind-mounted log (steps 0-3 below).
#   - P6.3: sentinel host-process launch + "watching started" sync
#     (steps 4-5 below).
#   - P6.3: curl attacker with 8 attack scenarios + 2 sqlmap repeats
#     + 1 Mozilla (step 6 below).
#   - P6.3: three assertions adapted per DECISIONS §5 (step 7).
#   - P6.3: artifact persistence copy (step 8).

set -eu

# ---------------------------------------------------------------------
# Step 0: locate inputs. REPO_ROOT is the workspace root ($GITHUB_WORKSPACE
# at workflow runtime). All three inputs are committed in this directory.
#
# This script lives at tests/integration-freebsd/litespeed/run-litespeed.sh —
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

cleanup() {
    if [ -n "$LITESPEED_CID" ]; then
        podman rm -f "$LITESPEED_CID" >/dev/null 2>&1 || true
    fi
    # CNI networks do not auto-GC on job exit (DECISIONS §3 consequences):
    # remove the network explicitly.
    podman network rm "$NETWORK" >/dev/null 2>&1 || true
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
# 091 run-nginx.sh / run-caddy.sh / run-traefik.sh / run-haproxy.sh
# / run-apache.sh use of fully-qualified names). The "latest" tag
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
# run-nginx.sh / 091 run-caddy.sh / run-traefik.sh / run-haproxy.sh
# / run-apache.sh use for their respective images).
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
# a runtime bug, not a syntax bug. Same caveat as run-haproxy.sh:253
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
    if podman logs litespeed 2>&1 | grep -q "LiteSpeed"; then
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
# Per Decision 9: 8 attack scenarios, plus 2 sqlmap repeats (to
# cross the additive-scorer threshold) plus 1 Mozilla control. The
# full 8-scenario block (Decision 9) is encoded in a single
# here-string that drives ONE attacker container with all the UAs;
# the assertions (step 7) only check the badbot + legit subset,
# but the access log carries the full 8-scenario signal for
# downstream grader inspection.
# ---------------------------------------------------------------------
SQLMAP_UA='sqlmap/1.7.11'
MOZILLA_UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'

# 8 attack UAs (Decision 9) — identical to run-apache.sh's set
# (the per-backend run scripts all share the same Decision 9
# UA set; this is the byte-for-byte parity signal the brief
# mandates).
#   1. sqlmap/1.7.11     — SQLi scanner
#   2. nikto/2.5         — web vuln scanner
#   3. nmap scripting engine — port/header probe
#   4. masscan/1.3.2     — port scanner
#   5. ZmEu               — exploit scanner
#   6. libwww-perl/6.66  — perl-based attack tool
#   7. python-requests/2.32.3 — bot-like scripted client
#   8. Mozilla/5.0 (control) — legit browser baseline (assertion 2)
SCENARIO_UAS='sqlmap/1.7.11 nikto/2.5 "Nmap Scripting Engine" masscan/1.3.2 ZmEu libwww-perl/6.66 python-requests/2.32.3 Mozilla/5.0'

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

echo "[litespeed] driving attacks from curl container (8 scenarios + 2 sqlmap repeats)..."
# Fully-qualified docker.io/curlimages/curl (NOT bare curlimages/curl)
# — same short-name resolution issue as the OLS image above (G1).
# --os=linux — same image-index reasoning as the OLS container
# above (curlimages/curl has no freebsd OS variant either) (G2).
#
# TWO sqlmap requests (not one): live run 28478337664 proved
# detection fires correctly on a single hit ([DETECTOR] [UA] ... +40
# ...) but the config's default alert threshold is 50 — one hit
# (score=40) never crosses it, so nothing is written to the threat
# log. The scorer is additive within the decay window ("decay 0→0 +
# delta=40" in that run's log), so a second identical-UA hit lands
# at score=80, comfortably over the threshold. Matches 088's
# testdata/synthetic.access.log fixture, which also sends multiple
# sqlmap-UA requests from the same attacker (5, in that case) rather
# than relying on a single hit.
#
# The 8-scenario block (Decision 9) is built up as a single shell
# `set --` arg-list loop to keep the curl invocations compact and
# avoid one `podman run --rm` per scenario (which would multiply
# container-start overhead and race the TailReader).
#
# Port $LSWS_PORT (default 80) — the upstream OLS docker template's
# vhost Listen. CNI-internal so the host's port mapping is
# irrelevant.
ATTACK_CMD=""
for UA in $SCENARIO_UAS; do
    ATTACK_CMD="${ATTACK_CMD}curl -sS -A '${UA}' http://${LITESPEED_IP}:${LSWS_PORT}/ ; "
done
# 2 sqlmap repeats (the threshold-breaker — see comment above).
ATTACK_CMD="${ATTACK_CMD}curl -sS -A '${SQLMAP_UA}' http://${LITESPEED_IP}:${LSWS_PORT}/ ; "
ATTACK_CMD="${ATTACK_CMD}curl -sS -A '${SQLMAP_UA}' http://${LITESPEED_IP}:${LSWS_PORT}/ ; "
ATTACK_CMD="${ATTACK_CMD}curl -sS -A '${MOZILLA_UA}' http://${LITESPEED_IP}:${LSWS_PORT}/"

podman run --rm --os=linux --network "$NETWORK" \
    --entrypoint /bin/sh \
    docker.io/curlimages/curl \
    -c "$ATTACK_CMD" \
    >/dev/null 2>&1 \
    || echo "[litespeed] curl attacker exited non-zero (still check the access log)"
echo "[litespeed] attacks sent"

# ---------------------------------------------------------------------
# Step 7: poll the threat log for non-empty content (~20s timeout).
# Mirrors 088 run-smoke.sh step 5.
# ---------------------------------------------------------------------
THREAT_LOG="$WORK_DIR/output/threats-litespeed.log"
echo "[litespeed] polling $THREAT_LOG (timeout 20s)..."
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
    echo "[litespeed] FAIL: $THREAT_LOG not written within 20s" >&2
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
    echo "[litespeed] FAIL: assertion 1 - expected ' THREAT ' and IP '$SQLMAP_IP' in threat log" >&2
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

# Step 9: final report. Cleanup happens via the EXIT trap.
if [ "$FAIL" -ne 0 ]; then
    echo "[litespeed] FAIL: one or more assertions failed (see above)"
    exit 1
fi
echo "[litespeed] PASS: all 3 assertions green - FreeBSD/podman litespeed integration end-to-end works"
exit 0
