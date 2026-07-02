#!/usr/bin/env sh
# tests/integration-freebsd/apache/integration.sh — Flow 091 integration
# smoke for the apache (httpd) backend under FreeBSD/podman.
#
# Adapted from integration.sh — Flow 089/091 paid 9+ iterations to make
#  this structure green across nginx/caddy/traefik/haproxy; do NOT
#  restructure without re-verifying all assertions.
#
# Architecture (per Flow 089 DECISIONS §2 + §3, carried over verbatim):
# - httpd runs in a Linux-emulated docker.io/library/httpd:latest
#   container under podman (FreeBSD Linux compat — see Flow 088 DECISIONS
#   §"A.2"). httpd is the official Apache HTTPD binary from the
#   docker.io/library/httpd image, which is the SAME upstream used by
#   the battle suite (tests/integration/docker-compose.yml:35 — G13
#   verification: image tag is taken from the battle suite, not guessed
#   by analogy with caddy:2-alpine / traefik:latest / haproxy:latest).
# - arxsentinel runs NATIVE on the VM host (NOT in a container —
#   DECISIONS §2), with its CWD = $WORK_DIR so the relative paths in
#   sentinel-apache.yaml resolve correctly.
# - The attacker runs in a SECOND podman container (curlimages/curl) on
#   the same CNI network. All attacker requests share the curl
#   container's CNI IP (DECISIONS §3).
#
# KEY ARCHITECTURAL CHOICE: bind-mount log (nginx/caddy/traefik pattern),
# NOT stdout-capture (haproxy pattern).
#   nginx/caddy/traefik all write the access log to a file the run-script
#   bind-mounts onto the container, so the host-native sentinel can tail
#   the host-side file directly. Apache's CustomLog directive in
#   tests/integration-freebsd/apache/httpd.conf targets a bind-mounted
#   path (/usr/local/apache2/logs/access.log, the official image's
#   default install prefix log directory), so we follow the same pattern
#   as nginx/caddy/traefik. The haproxy exception (its log target was
#   `log stdout ... format raw local0 info`, which has no file path)
#   does NOT apply here — CustomLog with a file path is a first-class
#   Apache feature, no special capture process needed. This means
#   integration.sh is simpler than integration.sh (no step 3b
#   `podman logs --follow` backgrounding, no $LOGS_PID for cleanup).
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
#   nginx used `podman exec nginx nginx -t` (config-validate) +
#   `podman logs | grep "start worker processes"` (startup-sync). The
#   traefik analogue proved that log-grep alone is sufficient (caddy
#   lesson: caddy:latest has no wget inside the image, so we
#   generalised to log-grep-only for traefik and beyond). The haproxy
#   readiness check polls `podman logs haproxy` directly for the
#   "Loading success" banner (also avoids the haproxy-specific stdio
#   full-buffering gotcha that `podman logs --follow > file` hits).
#   httpd follows the same pattern: the `podman logs apache` output
#   contains a startup line we grep for. The empirical pattern is
#   the httpd "AH00094: Command line: 'httpd -D FOREGROUND'" or
#   the "resuming normal operations" line that httpd writes to
#   error_log (which is /proc/1/fd/2, i.e. stdout, in our config);
#   the conservative grep below matches either. A 3s grace sleep
#   after the pattern fires covers the post-banner init window
#   (worker spawn + log file open + CustomLog fd ready). If P5.6
#   reveals a more specific marker, tighten the grep — the
#   conservative form is the safe default.
#
# Phase P5 step mapping (P5.2 httpd.conf + sentinel-apache.yaml; P5.3
# this script; P5.4 job wiring):
#   - P5.2: httpd.conf (Listen 8080, LogFormat combined with UA,
#     CustomLog to bind-mounted path, User www-data, DocumentRoot
#     default) + sentinel-apache.yaml (general.log_file: logs/
#     access.log, parser.profile: apache, output.threat_log:
#     output/threats-apache.log, blocklist.lists[0].sources[0].url:
#     mitchellkrogza upstream).
#   - P5.3: this file's skeleton + CNI network + httpd container
#     startup with bind-mounted log (steps 0-3 below).
#   - P5.3: sentinel host-process launch + "watching started" sync
#     (steps 4-5 below).
#   - P5.3: curl attacker with 8 attack blocks (probe + ua + 12
#     bruteforce + 6 crawler + 8 noasset + 60 rate + 1 overflow +
#     2 badbot) — step 6 below. Per Flow 092 Decision 7.
#   - P5.3: 12 assertions (THREAT+IP, Mozilla-absent, score/reason-
#     format, 7 module-name checks, badbot module, blocklist-
#     automaton-loaded) — step 7.
#   - P5.3: artifact persistence copy (step 8).
#   - Flow 092 (P5.7): proxy-chain scenario appended as Steps 10-16
#     (DECISIONS §1-§5). Same image (httpd:latest) on a dedicated
#     chain CNI network (10.89.5.0/24, N=5 per DECISIONS §2) with
#     chain-scenario httpd-chain.conf (LoadModule remoteip_module +
#     RemoteIPHeader X-Forwarded-For + RemoteIPInternalProxy
#     10.89.5.20/32 — battle-suite-proven pattern from
#     tests/integration/configs/httpd-proxy.conf:8-10, 21-22, with
#     G16 /proc-fd fix applied: ErrorLog /dev/stderr, NOT
#     /proc/1/fd/2). nginx-rp is the universal proxy (DECISIONS
#     §1); assertion 4 verifies the chain backend logs the real
#     client IP, not the proxy's connecting address (ip-leak class).

set -eu

# ---------------------------------------------------------------------
# Step 0: locate inputs. REPO_ROOT is the workspace root ($GITHUB_WORKSPACE
# at workflow runtime). All three inputs are committed in this directory.
#
# This script lives at tests/integration-freebsd/apache/integration.sh —
# three path segments below the repo root, so dirname($0) needs three
# "../" to reach it (NOT two, which is what 088's
# tests/integration-freebsd/run-smoke.sh used, since that script is
# only two segments deep).
# ---------------------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
APACHE_DIR="$REPO_ROOT/tests/integration-freebsd/apache"
APACHE_CONF="$APACHE_DIR/httpd.conf"
SENTINEL_BIN="$REPO_ROOT/arxsentinel"
SENTINEL_CFG_SRC="$APACHE_DIR/sentinel-apache.yaml"

# Sanity: all three inputs must exist. A typo or missing build would
# silently produce an empty access log and the assertions would
# falsely PASS.
if [ ! -s "$APACHE_CONF" ]; then
    echo "[apache] FAIL: httpd.conf missing or empty at $APACHE_CONF" >&2
    exit 1
fi
if [ ! -x "$SENTINEL_BIN" ]; then
    echo "[apache] FAIL: arxsentinel binary not found or not executable at $SENTINEL_BIN" >&2
    exit 1
fi
if [ ! -s "$SENTINEL_CFG_SRC" ]; then
    echo "[apache] FAIL: sentinel-apache.yaml missing or empty at $SENTINEL_CFG_SRC" >&2
    exit 1
fi

# ---------------------------------------------------------------------
# Step 1: create $WORK_DIR + the bind-mounted subdirs. $WORK_DIR lives
# under $TMPDIR (set by the workflow as scoped TMPDIR — P5.4 carry of
# 088 G.1) so the cleanup trap's rm -rf lands in a tmpfs / workspace
# sync area, not under /var/db or /usr/local. The relative paths in
# sentinel-apache.yaml (logs/access.log, output/threats-apache.log)
# resolve against $WORK_DIR when the sentinel CWDs there in step 4.
#
# $WORK_DIR/logs/ is the host-side destination of the bind-mount in
# step 3 (mount $WORK_DIR/logs over /usr/local/apache2/logs inside
# the container). The httpd worker's CustomLog directive writes to
# /usr/local/apache2/logs/access.log, which the bind-mount surfaces
# as $WORK_DIR/logs/access.log on the host. The host-native sentinel
# then tails that file in step 4.
# ---------------------------------------------------------------------
WORK_DIR="${TMPDIR:-/tmp}/arx-apache-$$"
mkdir -p "$WORK_DIR/logs" "$WORK_DIR/output"
# 0755 is enough: sentinel runs as root on the FreeBSD host (no
# nonroot hardening yet — see Flow 089 Deferred 089.9 + 088 TD-8).
chmod 0755 "$WORK_DIR/output"

# Stage inputs into $WORK_DIR so the httpd container bind-mount (for
# the CONFIG) and the sentinel CWD see them in a predictable layout.
cp "$APACHE_CONF" "$WORK_DIR/httpd.conf"
cp "$SENTINEL_CFG_SRC" "$WORK_DIR/sentinel-apache.yaml"

# podman-network and container-name markers — used in cleanup() and
# step 3 (wait-for-apache). Set as empty strings so the trap is
# idempotent on early exit (e.g. if podman network create fails).
NETWORK="arx-net"
APACHE_CID=""

# Chain-scenario markers (Steps 10-16). Separate from the direct-scenario
# vars above so a failure in Step 3 cleanup() still leaves the chain
# cleanup code paths exercised (and vice versa). Empty defaults keep the
# trap idempotent if the chain section is never reached. Mirrors the
# haproxy integration.sh pattern (haproxy/integration.sh:179-189) and
# traefik integration.sh pattern.
CHAIN_NETWORK="arx-chain-net"
APACHE_CHAIN_CID=""
APACHE_RP_CID=""

cleanup() {
    if [ -n "$APACHE_CID" ]; then
        podman rm -f "$APACHE_CID" >/dev/null 2>&1 || true
    fi
    if [ -n "$APACHE_CHAIN_CID" ]; then
        podman rm -f "$APACHE_CHAIN_CID" >/dev/null 2>&1 || true
    fi
    if [ -n "$APACHE_RP_CID" ]; then
        podman rm -f "$APACHE_RP_CID" >/dev/null 2>&1 || true
    fi
    # CNI networks do not auto-GC on job exit (DECISIONS §3 consequences):
    # remove the networks explicitly. Both direct and chain networks
    # are unconditionally attempted — podman network rm on a missing
    # network exits non-zero, hence the || true (matches the original
    # direct-scenario pattern + haproxy/traefik carry).
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
    # artifact path — P5.4 carry of 089 Task 3.6 / 4.3). The
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
# 10.88.0.0/16 on FreeBSD) is fine for the direct-apache test.
# ---------------------------------------------------------------------
echo "[apache] creating CNI network $NETWORK..."
podman network create "$NETWORK"

# ---------------------------------------------------------------------
# Step 3: start the httpd container detached. Two bind-mounts:
#   1. $WORK_DIR/httpd.conf → /usr/local/apache2/conf/httpd.conf:ro
#      (the official image reads this path on startup; bind-mounting
#      our config over the image's default is how we inject the
#      LogFormat-with-UA + Listen-8080 + User-www-data directives)
#   2. $WORK_DIR/logs → /usr/local/apache2/logs
#      (the CustomLog directive in our httpd.conf writes to
#      /usr/local/apache2/logs/access.log, which the bind-mount
#      surfaces as $WORK_DIR/logs/access.log on the host — the
#      path the host-native sentinel tails in step 4)
#
# --name apache is kept for operator convenience (`podman logs apache`,
# `podman exec apache ...` below) but is NOT used as a DNS name by the
# curl attacker — step 6 resolves the container's CNI IP via `podman
# inspect` instead, since the FreeBSD CNI bridge plugin has no
# dnsname resolver (G6; same as nginx + caddy + traefik + haproxy).
#
# Fully-qualified docker.io/library/httpd:latest (NOT bare httpd:latest):
# the FreeBSD podman default
# /usr/local/share/containers/registries.conf has no
# unqualified-search-registries entry, so a short name fails with
# "did not resolve to an alias and no unqualified-search registries
# are defined" (G1; same class of bug as Flow 088 Decision F.4 and
# 091 integration.sh / integration.sh / integration.sh / integration.sh
# use of fully-qualified names). The "latest" tag was verified
# against tests/integration/docker-compose.yml:35 (G13): the battle
# suite uses exactly `image: httpd:latest` on the same
# `docker.io/library/httpd:latest` upstream, so there is NO tag
# guesswork in P5.6.
#
# --os=linux is REQUIRED: docker.io/library/httpd:latest's OCI image
# index has no "freebsd" OS variant, only linux/*. Without
# --os=linux, podman on FreeBSD defaults to looking for a
# freebsd-OS manifest and fails with "no image found in image
# index for architecture amd64 ... OS freebsd" (G2; same flag
# 088 podman-spike step 5 used for docker.io/alpine and 089
# integration.sh / 091 integration.sh / integration.sh / integration.sh
# use for their respective images).
#
# Why standalone `podman run` (NO `--pod`, per G7): podman on FreeBSD
# (podman 5.8.3, ocijail 0.6.0) breaks the linuxulator for
# containers launched inside a pod, even with identical flags.
# Decision 2 + G7 explicitly mandate standalone for every per-
# backend run script; podman-compose is recorded as technically
# infeasible (Deferred 091.7 Revised).
#
# Why port 8080 (not 80) — G15 carry + apache-specific:
#   The official httpd image's master process runs as root and
#   binds the Listen port; the worker process runs as the
#   User/Group (www-data here). The master-process bind is not
#   the G15 risk (root CAN bind :80). HOWEVER, to keep all five
#   per-backend run scripts on the SAME port — reducing the
#   number of G15-style runtime surprises — we use :8080 (matching
#   integration.sh's port). The CNI network is internal-only
#   (no host port-publish), so the port is arbitrary; 8080 just
#   matches the established per-backend convention. The curl
#   attacker in step 6 hits :8080 directly via the container's
#   CNI IP.
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
echo "[apache] starting httpd container..."
APACHE_CID=$(podman run -d \
    --os=linux \
    --name apache \
    --network "$NETWORK" \
    -v "$WORK_DIR/httpd.conf:/usr/local/apache2/conf/httpd.conf:ro" \
    -v "$WORK_DIR/logs:/usr/local/apache2/logs" \
    docker.io/library/httpd:latest)
echo "[apache] container $APACHE_CID started"

# Wait for httpd to be ready: log-grep pattern ONLY (no wget,
# following the caddy/traefik lessons — see file header WHY-comment).
# The pattern matches EITHER the AH00094 startup marker
# ("Command line: 'httpd -D FOREGROUND'") OR the "resuming normal
# operations" line that httpd writes once the worker process
# initialises. Either one is a sufficient signal that httpd is
# accepting connections; the conservative OR pattern covers both
# the AH00094-only and AH00489-only configurations across httpd
# 2.4.x minor versions. A 3s grace sleep after the pattern
# fires covers the post-banner init window (CustomLog fd open
# + bind-mount sync between host and container). If P5.6 reveals
# a more specific marker, tighten the grep; the conservative
# form is the safe default.
echo "[apache] waiting for httpd ready (timeout 30s)..."
DEADLINE=$(($(date +%s) + 30))
READY=0
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    if podman logs apache 2>&1 | grep -qE "(resuming normal operations|AH00094: Command line)"; then
        sleep 3
        READY=1
        break
    fi
    sleep 1
done
if [ "$READY" -ne 1 ]; then
    echo "[apache] FAIL: httpd not ready within 30s" >&2
    echo "[apache] access log content (if any):" >&2
    cat "$WORK_DIR/logs/access.log" >&2 || true
    echo "[apache] podman logs (last 30 lines):" >&2
    podman logs --tail 30 apache >&2 || true
    exit 1
fi
echo "[apache] httpd ready"

# ---------------------------------------------------------------------
# Step 4: start the native sentinel. DECISIONS §2 — sentinel on host,
# NOT in a container. CWD = $WORK_DIR so the relative paths in
# sentinel-apache.yaml resolve. The sentinel writes its pid to
# /tmp/arxsentinel.pid (per the yaml) and its operational log to
# sentinel-apache.log under $WORK_DIR.
# ---------------------------------------------------------------------
echo "[apache] starting native sentinel (CWD=$WORK_DIR)..."
cd "$WORK_DIR"
"$SENTINEL_BIN" \
    --config "$WORK_DIR/sentinel-apache.yaml" \
    > "$WORK_DIR/sentinel-apache.log" 2>&1 &
SENTINEL_PID=$!
echo "[apache] sentinel started with PID $SENTINEL_PID"

# Step 5: wait for "watching started" in sentinel-apache.log. This
# sync prevents the host append in step 6 from racing the TailReader
# open+seek(EOF) (mirrors 088 run-smoke.sh step 3). The yaml's
# logging.debug: true is REQUIRED for the "TAIL watching started"
# line to be emitted (see sentinel-apache.yaml header).
echo "[apache] waiting for 'watching started' (timeout 30s)..."
DEADLINE=$(($(date +%s) + 30))
WATCHING=0
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    if grep -q "watching started" "$WORK_DIR/sentinel-apache.log" 2>/dev/null; then
        WATCHING=1
        break
    fi
    sleep 1
done
if [ "$WATCHING" -ne 1 ]; then
    echo "[apache] FAIL: 'watching started' not seen within 30s" >&2
    echo "[apache] sentinel log (last 50 lines):" >&2
    tail -50 "$WORK_DIR/sentinel-apache.log" >&2 || true
    kill "$SENTINEL_PID" 2>/dev/null || true
    exit 1
fi
echo "[apache] TailReader ready"

# ---------------------------------------------------------------------
# Step 6: drive attacks from a curl container. DECISIONS §3 said the
# curl container could resolve "apache" via container DNS — live runs
# for nginx/caddy/traefik/haproxy disproved that: the FreeBSD
# `containernetworking-plugins` port ships the basic CNI bridge
# plugin only, NOT a dnsname plugin (G6; same as nginx + caddy +
# traefik + haproxy). Resolve the httpd container's CNI IP via
# `podman inspect` instead of relying on DNS, and use the IP
# directly in the curl URL.
#
# Per Flow 092 DECISIONS §7 (close the Flow 091 Decision 9 gap): all 7
# attack scenario blocks (probe, ua, bruteforce, crawler, noasset, rate,
# overflow) + the badbot (block 8) are now driven from a SINGLE curl
# container, mirroring tests/integration/scenarios.sh:80-183 (battle
# suite source of truth). Mirrors the haproxy integration.sh pattern
# (proven green with 0 bugs, 2 consecutive dispatches — see Flow 092
# DECISIONS §7 "Battle-parity port"). Port `:8080` is required because
# httpd in this job binds :8080 (not :80 — see httpd.conf header
# WHY-comment on the per-backend-convention port).
# ---------------------------------------------------------------------
SQLMAP_UA='sqlmap/1.7.11'
MOZILLA_UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'

# `index` (not dot-notation) is REQUIRED: $NETWORK contains a hyphen
# ("arx-net"), and a Go template map-key access via dot-notation
# (.Networks.arx-net.IPAddress) parses the hyphen as a subtraction
# operator and fails with "bad character U+002D '-'" (G8; live run
# 28477133986 hit this exact error). `index` takes the key as a
# string argument, sidestepping Go template identifier syntax rules.
APACHE_IP=$(podman inspect apache --format "{{(index .NetworkSettings.Networks \"${NETWORK}\").IPAddress}}")
if [ -z "$APACHE_IP" ]; then
    echo "[apache] FAIL: could not resolve apache container's CNI IP via podman inspect" >&2
    exit 1
fi
echo "[apache] apache container IP: $APACHE_IP"

# Generate the long URL path for the overflow scenario (block 7) on
# the HOST (not inside the curl container) so the value can be
# embedded as a literal in the -c "..." script string below.
#
# NOT scenarios.sh:169's `/dev/urandom | tr -dc 'a-zA-Z0-9'` recipe:
# G20 (proven live on nginx/caddy/traefik/haproxy) — produces EMPTY
# output on this FreeBSD VM's native sh (BSD tr vs GNU tr, or
# /dev/urandom access under vmactions SSH — root cause not pinned).
# The overflow detector only checks byte length, not entropy, so a
# deterministic `awk` one-liner is sufficient: POSIX-standard, zero
# external-tool portability surface. Same fix as
# haproxy/integration.sh:467 and traefik/integration.sh:362.
LONG_PATH="/$(awk 'BEGIN { s = ""; for (i = 0; i < 2200; i++) s = s "a"; print s }')"
echo "[apache] LONG_PATH length: $(printf '%s' "$LONG_PATH" | wc -c) bytes"

# Pick the badbot UA the same way haproxy/integration.sh:477-481 does:
# prefer the committed test fixture ($REPO_ROOT/tests/integration/
# blocklist/test-ua.txt) because it is the same file run.sh:122
# produces from the FIRST literal pattern in the upstream mitchellkrogza
# list — a pattern the FreeBSD sentinel's blocklist automaton will also
# load (same upstream URL, see sentinel-apache.yaml blocklist.lists[0].
# sources[0].url — added in Flow 092 Task A5). Fallback "AhrefsBot"
# matches scenarios.sh:179.
if [ -s "$REPO_ROOT/tests/integration/blocklist/test-ua.txt" ]; then
    BADBOT_UA=$(head -1 "$REPO_ROOT/tests/integration/blocklist/test-ua.txt")
else
    BADBOT_UA="AhrefsBot"
fi
echo "[apache] using badbot UA for block 8: ${BADBOT_UA}/1.0"

# ONE curl container for ALL 8 blocks (NOT one per block) — mirrors
# haproxy/integration.sh:484-485 + traefik/integration.sh:411-413.
# Detectors (bruteforce, crawler, noasset, rate) are per-IP trackers;
# multiple attacker containers would each see only a fraction of the
# required request count → no fire → no threat log entry → false-
# negative assertion. The Mozilla UA legit request is folded into
# block 2 (ua) as the last request — same reasoning as
# traefik/integration.sh:428-437 (assertion 2 only makes sense in the
# context of the scanner-UA attack on the same IP).
#
# All 8 blocks are verbatim ports from tests/integration/
# scenarios.sh:80-183 (per Flow 092 Decision 7) — each block's source
# line is annotated in the same WHY comment style as the rest of
# this file. Port `:8080` is required because httpd in this job
# binds :8080.
echo "[apache] driving 8 attack blocks from a single curl container..."
ATTACK_SCRIPT="
# ── block 1: probe (scenarios.sh:82-90) ──
curl -sf -o /dev/null http://${APACHE_IP}:8080/wp-login.php      || true
curl -sf -o /dev/null http://${APACHE_IP}:8080/.env              || true
curl -sf -o /dev/null http://${APACHE_IP}:8080/.git/config       || true
curl -sf -o /dev/null http://${APACHE_IP}:8080/admin/config.php  || true
curl -sf -o /dev/null http://${APACHE_IP}:8080/etc/passwd        || true
curl -sf -o /dev/null http://${APACHE_IP}:8080/.aws/credentials  || true
curl -sf -o /dev/null http://${APACHE_IP}:8080/xmlrpc.php        || true
# ── block 2: ua (scenarios.sh:94-100) + the legit Mozilla request ──
curl -sf -o /dev/null -A '${SQLMAP_UA}'     http://${APACHE_IP}:8080/ || true
curl -sf -o /dev/null -A '${SQLMAP_UA}'     http://${APACHE_IP}:8080/ || true
curl -sf -o /dev/null -A 'Nuclei/3.0'       http://${APACHE_IP}:8080/ || true
curl -sf -o /dev/null -A 'masscan/1.3'      http://${APACHE_IP}:8080/ || true
curl -sf -o /dev/null -A 'zgrab/0.x'        http://${APACHE_IP}:8080/ || true
# Legit Mozilla request — kept in block 2 (NOT a separate block)
# because Assertion 2 (Mozilla UA absent from threat log) only
# makes sense in the context of the scanner-UA attack on the same
# IP. Mirrors traefik/integration.sh:428-437.
curl -sf -o /dev/null -A '${MOZILLA_UA}'    http://${APACHE_IP}:8080/ || true
# ── block 3: bruteforce (scenarios.sh:104-120) ──
curl -sf -o /dev/null http://${APACHE_IP}:8080/                      || true
curl -sf -o /dev/null http://${APACHE_IP}:8080/                      || true
curl -sf -o /dev/null http://${APACHE_IP}:8080/                      || true
curl -sf -o /dev/null http://${APACHE_IP}:8080/missing-page-1        || true
curl -sf -o /dev/null http://${APACHE_IP}:8080/missing-page-2        || true
curl -sf -o /dev/null http://${APACHE_IP}:8080/missing-page-3        || true
curl -sf -o /dev/null http://${APACHE_IP}:8080/missing-page-4        || true
curl -sf -o /dev/null http://${APACHE_IP}:8080/missing-page-5        || true
curl -sf -o /dev/null http://${APACHE_IP}:8080/missing-page-6        || true
curl -sf -o /dev/null http://${APACHE_IP}:8080/missing-page-7        || true
curl -sf -o /dev/null http://${APACHE_IP}:8080/missing-page-8        || true
curl -sf -o /dev/null http://${APACHE_IP}:8080/missing-page-9        || true
curl -sf -o /dev/null http://${APACHE_IP}:8080/missing-page-10       || true
curl -sf -o /dev/null http://${APACHE_IP}:8080/missing-page-11       || true
curl -sf -o /dev/null http://${APACHE_IP}:8080/missing-page-12       || true
# ── block 4: crawler (scenarios.sh:126-132) ──
curl -sf -o /dev/null http://${APACHE_IP}:8080/items/1  || true
curl -sf -o /dev/null http://${APACHE_IP}:8080/items/2  || true
curl -sf -o /dev/null http://${APACHE_IP}:8080/items/3  || true
curl -sf -o /dev/null http://${APACHE_IP}:8080/items/4  || true
curl -sf -o /dev/null http://${APACHE_IP}:8080/items/5  || true
curl -sf -o /dev/null http://${APACHE_IP}:8080/items/6  || true
# ── block 5: noasset (scenarios.sh:138-146) ──
curl -sf -o /dev/null http://${APACHE_IP}:8080/           || true
curl -sf -o /dev/null http://${APACHE_IP}:8080/           || true
curl -sf -o /dev/null http://${APACHE_IP}:8080/           || true
curl -sf -o /dev/null http://${APACHE_IP}:8080/info.php   || true
curl -sf -o /dev/null http://${APACHE_IP}:8080/           || true
curl -sf -o /dev/null http://${APACHE_IP}:8080/           || true
curl -sf -o /dev/null http://${APACHE_IP}:8080/info.php   || true
curl -sf -o /dev/null http://${APACHE_IP}:8080/           || true
# ── block 6: rate (scenarios.sh:151-161) — 60 requests in 2 waves with 1s gap ──
i=0; while [ \$i -lt 30 ]; do
    curl -sf -o /dev/null http://${APACHE_IP}:8080/ || true
    i=\$((i+1))
done
sleep 1
i=0; while [ \$i -lt 30 ]; do
    curl -sf -o /dev/null http://${APACHE_IP}:8080/ || true
    i=\$((i+1))
done
# ── block 7: overflow (scenarios.sh:169-172) — single URL with path > 2048 bytes ──
curl -sf -o /dev/null 'http://${APACHE_IP}:8080${LONG_PATH}' || true
# ── block 8: badbot (scenarios.sh:180-183) — LAST on purpose ──
# scenarios.sh:177-178: 'Placed last among direct-server scenarios to
# give sentinels time to load patterns from the local blocklist-server
# container before the request arrives.' Same reasoning applies here
# (blocklist fetch is async from start, automaton rebuild on first
# successful fetch — badbot last gives the wall-clock budget). Two
# requests, not one, for the same threshold-crossing reason as the
# sqlmap pair in block 2 (the badbot detector's first hit may not
# cross the alert threshold on its own).
curl -sf -o /dev/null -A '${BADBOT_UA}/1.0' http://${APACHE_IP}:8080/ || true
curl -sf -o /dev/null -A '${BADBOT_UA}/1.0' http://${APACHE_IP}:8080/ || true
"

podman run --rm --os=linux --network "$NETWORK" \
    --entrypoint /bin/sh \
    docker.io/curlimages/curl \
    -c "$ATTACK_SCRIPT" \
    >/dev/null 2>&1 \
    || echo "[apache] curl attacker exited non-zero (still check the access log)"
echo "[apache] attacks sent"

# ---------------------------------------------------------------------
# Step 7: poll the threat log for non-empty content. Timeout RAISED
# from 20s → 40s to match haproxy/integration.sh:604 (Step 6 now sends
# ~105 attack requests, vs. 12 in the original P5.6 smoke; the rate
# block's 1s sleep + sentinel per-request scoring add wall-clock cost on
# top). Mirrors haproxy/integration.sh:604-612 + the 40s polling loop
# proven green there. (Apache keeps the bind-mounted log pattern, so
# the readiness check still polls `podman logs apache` directly per
# the file header WHY-comment — no stdout-capture needed, no
# pipe-flush race to absorb the way haproxy's `podman logs --follow`
# workaround does.)
# ---------------------------------------------------------------------
THREAT_LOG="$WORK_DIR/output/threats-apache.log"
echo "[apache] polling $THREAT_LOG (timeout 40s)..."
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
    echo "[apache] FAIL: $THREAT_LOG not written within 20s" >&2
    echo "[apache] access log content (if any):" >&2
    cat "$WORK_DIR/logs/access.log" >&2 || true
    echo "[apache] sentinel log (last 80 lines):" >&2
    tail -80 "$WORK_DIR/sentinel-apache.log" >&2 || true
    exit 1
fi

# Dump the threat log for inline visibility.
LINES=$(cat "$THREAT_LOG")
echo "[apache] threat log content:"
printf '%s\n' "$LINES" | sed 's/^/  /'

# ---------------------------------------------------------------------
# Step 7a: extract the sqlmap-request source IP from the access log.
# DECISIONS §5 — the attacker's source IP is the curl container's
# CNI-assigned IP, which appears in access.log as the first field
# of the line containing the sqlmap UA. The apache CLF format
# prefixes the line with "<client_ip> ..." — the IP is the
# space-delimited first field, straightforward awk.
# ---------------------------------------------------------------------
ACCESS_LOG="$WORK_DIR/logs/access.log"
if [ ! -s "$ACCESS_LOG" ]; then
    echo "[apache] FAIL: access log empty or missing at $ACCESS_LOG" >&2
    exit 1
fi
# grep the sqlmap UA (literal, no regex specials) then awk the first
# field. Safe even if the UA contains regex chars — grep treats it
# as a fixed string in this case (no -E flag).
SQLMAP_IP=$(grep "${SQLMAP_UA}" "$ACCESS_LOG" | awk '{print $1}' | head -1)
if [ -z "$SQLMAP_IP" ]; then
    echo "[apache] FAIL: could not extract sqlmap request IP from access log" >&2
    echo "[apache] access log content:" >&2
    cat "$ACCESS_LOG" >&2 || true
    exit 1
fi
echo "[apache] sqlmap request source IP: $SQLMAP_IP"

# Diagnostic (mirrors haproxy/integration.sh:668-673, traefik/
# integration.sh:552-559 — same overflow-assertion failure mode on
# run 28585617384): print the access-log line matching the long-path
# request, and its byte length, to see what httpd actually logged for
# it (full URI vs truncated vs never received). httpd's combined
# format writes a single line per request, so a > 2048-byte path in
# the request field still produces a parsable line; this diagnostic
# confirms the long path made it through httpd (not rejected at the
# HTTP layer) and into the access log.
OVERFLOW_LOG_LINE=$(grep -E '"GET /[a-zA-Z0-9]{100,}' "$ACCESS_LOG" | head -1)
if [ -n "$OVERFLOW_LOG_LINE" ]; then
    echo "[apache] overflow request access-log line length: $(printf '%s' "$OVERFLOW_LOG_LINE" | wc -c) bytes"
else
    echo "[apache] overflow request NOT FOUND in access log (long-path GET never logged)"
fi

# ---------------------------------------------------------------------
# Step 7b: assertions. Originally 3 per DECISIONS §5 (adapted from
# 088 run-smoke.sh — UA-based, not IP-based). EXTENDED to 12 per
# Flow 092 Task A5 / Decision 7: 1-3 retained, 4-10 are one
# `grep -qw "reason=<module>"` per attack scenario (mirrors
# tests/integration/verify.sh:144 assert_module's exact grep
# pattern), 11 is badbot module presence, 12 is the blocklist
# automaton-loaded check (mirrors verify.sh:109
# assert_blocklist_loaded's exact regex). A single FAIL on any
# assertion sets FAIL=1; the script reports all at the end
# (does not short-circuit, so the grader can see the full failure
# shape).
# ---------------------------------------------------------------------
FAIL=0

# Assertion 1: ` THREAT ` substring AND sqlmap-attack source IP
# appear in the threat log. (088 run-smoke.sh assertion 1 with the
# IP extracted from access.log, NOT a fixed literal.)
if ! printf '%s\n' "$LINES" | grep -q " THREAT " \
   || ! printf '%s\n' "$LINES" | grep -q " $SQLMAP_IP "; then
    echo "[apache] FAIL: assertion 1 - expected ' THREAT ' and IP '$SQLMAP_IP' in threat log" >&2
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
    echo "[apache] FAIL: assertion 2 - false positive: Mozilla UA appeared in threat log" >&2
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
    echo "[apache] FAIL: assertion 3 - $BAD_COUNT threat line(s) missing score=/reason=" >&2
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
        echo "[apache] FAIL: assertion - expected module '$module' in threat log (reason=)" >&2
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
    echo "[apache] FAIL: assertion 11 - badbot module not in threat log (expected reason=badbot:...)" >&2
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
# in sentinel-apache.yaml → upstream fetch → automaton rebuild → UA
# matching in block 8's requests. The operational log path is
# `output.operational_log: sentinel-apache.log` in
# sentinel-apache.yaml — relative to $WORK_DIR, which is the
# sentinel's CWD (set in Step 4).
SENTINEL_OP_LOG="$WORK_DIR/sentinel-apache.log"
if [ ! -s "$SENTINEL_OP_LOG" ] \
   || ! grep -qE 'automaton rebuilt \([1-9][0-9]* patterns\)' "$SENTINEL_OP_LOG"; then
    echo "[apache] FAIL: assertion 12 - blocklist automaton not loaded (no 'automaton rebuilt (N patterns)' with N>0 in $SENTINEL_OP_LOG)" >&2
    FAIL=1
fi

# ---------------------------------------------------------------------
# Step 8: persist artifacts for the workflow. The cleanup trap on
# EXIT (set in step 1) does NOT remove $WORK_DIR when TMPDIR is
# $GITHUB_WORKSPACE — the workflow's actions/upload-artifact picks
# up these files BEFORE the VM is destroyed (P5.4 carry of 089 Task
# 3.6 / 4.3). The copies here land at the top of $TMPDIR (=
# $GITHUB_WORKSPACE in CI) so the workflow's `cat
# $GITHUB_WORKSPACE/...` + `upload-artifact` at P5.4 can find them
# by name.
# ---------------------------------------------------------------------
if [ -s "$THREAT_LOG" ]; then
    cp "$THREAT_LOG" "${TMPDIR:-/tmp}/threats-apache.log.smoke"
fi
if [ -s "$ACCESS_LOG" ]; then
    cp "$ACCESS_LOG" "${TMPDIR:-/tmp}/apache-access.log"
fi

# ---------------------------------------------------------------------
# Steps 10-16: proxy-chain scenario. Flow 092 (DECISIONS §2/§3/§5).
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
# $APACHE_RP_IP capture. N=5 for apache (nginx=1, caddy=2,
# traefik=3, haproxy=4, apache=5, litespeed=6 — Flow 092 DECISIONS
# §2 "per-backend offset").
# ---------------------------------------------------------------------

# ---------------------------------------------------------------------
# Step 10: create the chain network with a dedicated subnet
# (10.89.5.0/24 for apache — per-backend offset, see Flow 092
# DECISIONS §2; apache = N=5 since nginx=1, caddy=2, traefik=3,
# haproxy=4). A separate network from the direct-scenario's
# $NETWORK ("arx-net") keeps the two scenarios' CNI bridges
# independent — a podman network create with the same name as a
# pre-existing network exits non-zero, so re-use would need an "if
# exists" dance. A fresh network is the simpler path.
# ---------------------------------------------------------------------
echo "[apache] creating chain CNI network $CHAIN_NETWORK (subnet 10.89.5.0/24)..."
podman network create --subnet 10.89.5.0/24 "$CHAIN_NETWORK"

# Static IP assignment for the chain backend (DECISIONS §2/§3).
# .10 within 10.89.5.0/24 — chosen by convention (smallest non-zero
# suffix for the "primary" service in the network, .20 for the
# upstream proxy). Hard-coded, not derived, on purpose: see
# DECISIONS §2 "static IPs also make the chain-scenario shell
# script easier to read and debug from an inline log".
CHAIN_BACKEND_IP="10.89.5.10"
CHAIN_PROXY_IP="10.89.5.20"

# ---------------------------------------------------------------------
# Step 11: start the chain-scenario backend. SAME `docker.io/library/
# httpd:latest` image as Step 3 — proven to start on FreeBSD/podman
# by the direct scenario's Step 3 + readiness check. The chain
# httpd.conf is a SEPARATE file (not the direct-scenario
# $WORK_DIR/httpd.conf) for the same reason nginx uses
# nginx-chain.conf: the direct-scenario config has no
# mod_remoteip trust config (never needed; the attacker connects
# directly), and the chain-scenario config has the
# `LoadModule remoteip_module + RemoteIPHeader X-Forwarded-For +
# RemoteIPInternalProxy <proxy-ip>/32` directives that tell httpd
# to trust X-Forwarded-For from a specific proxy IP (DECISIONS §5
# apache row — battle-suite-proven pattern from
# tests/integration/configs/httpd-proxy.conf:8-10, 21-22). Keeping
# two files (no conditional logic in one) preserves the proven
# direct-scenario httpd.conf verbatim — Decision 4 (copy-then-
# adapt, no premature library extraction).
#
# XFF-trust mechanism for httpd (battle-suite-verified):
# tests/integration/configs/httpd-proxy.conf:8-10 + 21-22 uses
# THREE directives:
#   1. LoadModule remoteip_module modules/mod_remoteip.so  — the
#      module must be LOADED (otherwise the next two directives
#      are silently ignored — httpd starts but %h is unchanged
#      from %a, the connecting peer). mod_remoteip.so is present
#      in STOCK `docker.io/library/httpd:latest` (proven via
#      docker-compose.yml:124 — same image we already use; no
#      custom build needed, per Flow 092 Task 5 brief).
#   2. RemoteIPHeader X-Forwarded-For  — which header carries the
#      real client IP.
#   3. RemoteIPInternalProxy <proxy-ip>/32  — trust this CIDR's
#      XFF as authoritative. CRITICAL: /32, NOT a subnet
#      (DECISIONS §3 — one proxy per chain network, no need to
#      trust a range). The battle suite's `172.16.0.0/12` is for
#      Docker compose's default bridge which spans multiple
#      proxies; we have ONE proxy, so /32 is narrower and safer.
#   Effect: %h (first field of LogFormat) now resolves to the
#   leftmost UNTRUSTED IP — i.e. the original client (curl
#   container's CNI IP), NOT the proxy's IP. Without these
#   directives, %h = proxy IP, the parser sees 10.89.5.20, and
#   threat attribution collapses to "every attack came from the
#   proxy" — the "ip-leak" failure mode the battle suite's
#   assert_chain (verify.sh:188) calls out.
#
# G16 carry (Flow 091's linprocfs-on-FreeBSD bug): the battle
# httpd-proxy.conf uses `ErrorLog /proc/1/fd/2` — this does NOT
# work on FreeBSD (linprocfs does not populate /proc/1/fd/ the
# way a native Linux kernel does, and httpd's own config check
# aborts before startup with "AH02291: Cannot access directory
# '/proc/1/fd/' for main error log" — proven live in run
# 28559031208). We keep the direct-scenario's `ErrorLog
# /dev/stderr` (G16-mitigated form) and only add the 3
# mod_remoteip directives on top. The CustomLog path is also
# preserved as `/usr/local/apache2/logs/access.log` (the same
# bind-mounted file the direct scenario uses) so the chain
# backend's access log lands at $WORK_DIR/logs-chain/access.log
# on the host — bind-mounted by the `podman run -v
# $WORK_DIR/logs-chain:/usr/local/apache2/logs` flag below.
#
# Port :8080 (NOT :80): same non-root-privileged-port constraint
# as the direct scenario (httpd.conf header WHY-comment on the
# per-backend convention). The proxy in Step 12 sends requests
# to 10.89.5.10:8080, not :80.
# ---------------------------------------------------------------------
echo "[apache] preparing chain-scenario httpd.conf (with mod_remoteip trust for $CHAIN_PROXY_IP/32)..."
mkdir -p "$WORK_DIR/logs-chain"

# Insertion: the 3 mod_remoteip directives go AFTER the existing
# LoadModule unixd_module line and BEFORE the User www-data line.
# awk trick: the first pattern matches the unixd-module line,
# prints it, then sets a flag — the next two patterns are gated
# on that flag, so the 3 directives land on the 3 LINES
# IMMEDIATELY AFTER unixd, BEFORE User (mirrors the nginx
# realip-trust awk trick at nginx/integration.sh:725-738 — same
# "insert N lines after a unique anchor" pattern, identical
# mechanism). The pattern `LoadModule unixd_module` is unique in
# the source httpd.conf (one occurrence only, line 58).
awk '
    /LoadModule unixd_module/ {
        print
        just_inserted=1
        next
    }
    just_inserted {
        print "LoadModule remoteip_module modules/mod_remoteip.so"
        print "RemoteIPHeader X-Forwarded-For"
        print "RemoteIPInternalProxy '"$CHAIN_PROXY_IP"'/32"
        just_inserted=0
    }
    { print }
' "$WORK_DIR/httpd.conf" > "$WORK_DIR/httpd-chain.conf"

echo "[apache] starting chain-scenario httpd container on $CHAIN_BACKEND_IP..."
APACHE_CHAIN_CID=$(podman run -d \
    --os=linux \
    --name apache-chain \
    --network "$CHAIN_NETWORK" \
    --ip "$CHAIN_BACKEND_IP" \
    -v "$WORK_DIR/httpd-chain.conf:/usr/local/apache2/conf/httpd.conf:ro" \
    -v "$WORK_DIR/logs-chain:/usr/local/apache2/logs" \
    docker.io/library/httpd:latest)
echo "[apache] chain backend $APACHE_CHAIN_CID started"

# Wait-for-ready pattern identical to Step 3: log-grep on the
# "resuming normal operations" / "AH00094: Command line" pattern
# + 3s grace sleep for worker spawn + CustomLog fd ready. Same
# conservative form proven live on the direct-scenario chain
# backend.
echo "[apache] waiting for chain backend ready (timeout 30s)..."
DEADLINE=$(($(date +%s) + 30))
READY=0
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    if podman logs apache-chain 2>&1 | grep -qE "(resuming normal operations|AH00094: Command line)"; then
        sleep 3
        READY=1
        break
    fi
    sleep 1
done
if [ "$READY" -ne 1 ]; then
    echo "[apache] FAIL: chain backend not ready within 30s" >&2
    echo "[apache] chain backend logs (last 30 lines):" >&2
    podman logs --tail 30 apache-chain >&2 || true
    exit 1
fi
echo "[apache] chain backend ready"

# ---------------------------------------------------------------------
# Step 12: start the proxy container. VERBATIM copy of the proven
# nginx-rp pattern from tests/integration-freebsd/nginx/integration.sh
# (Step 12, lines 816-840) — same `docker.io/library/nginx:alpine`
# image, same `error_log /dev/stderr notice; include mime.types;
# open_log_file_cache off;` directive set (G17: reuse PROVEN template,
# not a minimal from-scratch one), with ONLY the `proxy_pass` target
# swapped to the apache chain backend's static IP
# ($CHAIN_BACKEND_IP = 10.89.5.10) and port :8080.
#
# The decision to use nginx-rp as the universal proxy for ALL backends
# (not just nginx) is Flow 092 Decision 1 — one generic reverse-proxy
# pattern, ported per backend. The apache-direct-scenario job needs
# to exercise apache's mod_remoteip-trust handling; which proxy sits
# in front of it is incidental (nginx-rp is the proven, battle-suite-
# parity choice).
#
# Port :8080 (NOT :80): the apache chain backend binds :8080 (same
# non-root-privileged-port constraint as Step 3 — see httpd.conf
# header WHY-comment). The battle suite's
# tests/integration/configs/httpd-proxy.conf:2 binds :80, but that
# runs as root in the Docker container — httpd:latest on FreeBSD's
# ocijail-launched container runs as a non-root user and can't bind
# :80. The choice is captured in DECISIONS §2/§3 — every FreeBSD
# apache chain backend listens on :8080.
# ---------------------------------------------------------------------
cat > "$WORK_DIR/apache-rp.conf" <<NGINX_RP_EOF
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
            proxy_pass http://${CHAIN_BACKEND_IP}:8080/;
        }
    }
}
NGINX_RP_EOF

# Bind-mount /var/log/nginx for consistency with the proven template
# (nginx/integration.sh Step 12 does the same) — this script never
# reads the proxy's own log, but matching the proven container-start
# shape exactly (bind-mount + error_log /dev/stderr) removes it as a
# variable.
mkdir -p "$WORK_DIR/apache-rp"
echo "[apache] starting proxy container on $CHAIN_PROXY_IP..."
APACHE_RP_CID=$(podman run -d \
    --os=linux \
    --name apache-rp \
    --network "$CHAIN_NETWORK" \
    --ip "$CHAIN_PROXY_IP" \
    -v "$WORK_DIR/apache-rp.conf:/etc/nginx/nginx.conf:ro" \
    -v "$WORK_DIR/apache-rp:/var/log/nginx" \
    docker.io/library/nginx:alpine)
echo "[apache] proxy $APACHE_RP_CID started"

# Same wait-for-ready pattern as nginx chain proxy. nginx -t catches
# the heredoc-substituted config typo case; "start worker processes"
# in podman logs is the full-start signal.
echo "[apache] waiting for proxy ready (timeout 30s)..."
DEADLINE=$(($(date +%s) + 30))
READY=0
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    if podman exec apache-rp nginx -t >/dev/null 2>&1 \
       && podman logs apache-rp 2>&1 | grep -q "start worker processes"; then
        READY=1
        break
    fi
    sleep 1
done
if [ "$READY" -ne 1 ]; then
    echo "[apache] FAIL: proxy not ready within 30s" >&2
    echo "[apache] proxy logs (last 30 lines):" >&2
    podman logs --tail 30 apache-rp >&2 || true
    exit 1
fi
echo "[apache] proxy ready"

# ---------------------------------------------------------------------
# Step 13: drive attacks THROUGH the proxy. Same UA mix as Step 6
# (sqlmap x2 + Mozilla x1) but the URL is the proxy's static IP
# (http://10.89.5.20/), NOT the chain backend's IP. The proxy adds
# X-Forwarded-For with the curl container's CNI IP, and the chain
# httpd's mod_remoteip+RemoteIPInternalProxy 10.89.5.20/32 config
# trusts that header and resolves the leftmost (real client) IP
# into %h — the first field of the LogFormat line that the parser
# and grader use to attribute the attack. Mirror of the direct-
# scenario attack — same curl image, same attacker behavior, only
# the URL changes.
#
# --network $NETWORK: the curl container runs on the DIRECT-scenario
# network (arx-net), not the chain network. The two networks are
# isolated — a packet from arx-net cannot reach 10.89.5.20 by
# Layer-2 routing. This is the intended topology: the attacker sits
# on the same "outside" network as in Step 6, the proxy is the
# bridge. The curl container's CNI IP will therefore be on arx-net
# (different from the IP it would have if it were on
# arx-chain-net) — Step 14's assertion extracts the IP from the
# chain-backend's access log, so it doesn't matter that this IP is
# on a different network than the direct scenario's attacker IP.
# ---------------------------------------------------------------------
echo "[apache] driving proxy-chain attacks from curl container (sqlmap + Mozilla UAs)..."
podman run --rm --os=linux --network "$NETWORK" \
    --entrypoint /bin/sh \
    docker.io/curlimages/curl \
    -c "curl -sS -A '${SQLMAP_UA}' http://${CHAIN_PROXY_IP}/ ; curl -sS -A '${SQLMAP_UA}' http://${CHAIN_PROXY_IP}/ ; curl -sS -A '${MOZILLA_UA}' http://${CHAIN_PROXY_IP}/" \
    >/dev/null 2>&1 \
    || echo "[apache] chain curl attacker exited non-zero (still check the access log)"
echo "[apache] chain attacks sent"

# ---------------------------------------------------------------------
# Step 14: chain-specific assertion (4th). Wait for the chain-backend's
# access log to be written, extract the sqlmap-request source IP from
# IT (NOT from the direct-scenario access log), and verify that the
# extracted IP is the REAL client (curl container's CNI IP) — NOT
# the proxy's IP ($CHAIN_PROXY_IP). If the mod_remoteip-trust config
# did NOT resolve the real client (e.g. mod_remoteip not loaded,
# RemoteIPInternalProxy not honoured, or LoadModule silently
# dropped by httpd 2.4.x's strict-mode config check), the logged
# IP would be the proxy's connecting address ($CHAIN_PROXY_IP) —
# that is the "ip-leak" class of failure the battle suite's
# assert_chain (verify.sh:188) calls out (class=ip-leak in its
# report). Mirrored here in this script's existing grep-based
# assertion style (Step 7b) — same FAIL=1 accumulator, same
# non-short-circuit report-at-end discipline.
#
# A note on UA-vs-NA-detection here: the chain scenario's detection
# fires off the SAME UA (sqlmap), so the threat log may contain
# entries from BOTH scenarios (direct Step 7's 8 blocks of
# requests and chain Step 13's three requests, all with the same
# UA, all from attackers the sentinel sees as the same kind of
# source). The check below is intentionally scoped to the
# chain-backend's OWN access log — that log only contains the
# chain scenario's three requests, and the logged IP field in
# that log is whatever the mod_remoteip-trust config resolved
# (which we want to be the real client, not the proxy).
# ---------------------------------------------------------------------
CHAIN_ACCESS_LOG="$WORK_DIR/logs-chain/access.log"
echo "[apache] polling $CHAIN_ACCESS_LOG (timeout 20s)..."
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
    echo "[apache] FAIL: $CHAIN_ACCESS_LOG not written within 20s" >&2
    echo "[apache] proxy logs (last 30 lines):" >&2
    podman logs --tail 30 apache-rp >&2 || true
    exit 1
fi

# Extract the sqlmap-request source IP from the chain backend's
# access log. The chain httpd.conf's LogFormat is
# `%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"` —
# with mod_remoteip processing, %h now resolves to the real
# client IP (the leftmost UNTRUSTED XFF — the curl container's
# CNI IP). awk the first field, head -1 picks the first match.
# Same convention as Step 7a (deterministic, survives multiple
# hits). Unlike haproxy's `%ci:%cp` format, httpd's combined
# format has NO port suffix, so no `cut -d: -f1` is needed.
CHAIN_SQLMAP_IP=$(grep "${SQLMAP_UA}" "$CHAIN_ACCESS_LOG" | awk '{print $1}' | head -1)
if [ -z "$CHAIN_SQLMAP_IP" ]; then
    echo "[apache] FAIL: could not extract sqlmap request IP from chain access log" >&2
    echo "[apache] chain access log content:" >&2
    cat "$CHAIN_ACCESS_LOG" >&2 || true
    exit 1
fi
echo "[apache] chain sqlmap request source IP (as logged by chain backend): $CHAIN_SQLMAP_IP"

# Assertion 4: the IP logged by the chain backend must NOT be the
# proxy's IP. If it IS the proxy's IP, the mod_remoteip-trust
# config did not resolve the real client and httpd is logging the
# proxy's connecting address instead — the exact failure mode
# assert_chain in tests/integration/verify.sh:188 calls "ip-leak".
# Conversely, any non-proxy IP is treated as a PASS for this
# assertion (the detailed IP-correctness of the curl container's
# CNI assignment is not what we are asserting here; what matters
# is "not the proxy's IP").
if [ "$CHAIN_SQLMAP_IP" = "$CHAIN_PROXY_IP" ]; then
    echo "[apache] FAIL: assertion 4 - mod_remoteip did not resolve proxy chain - logged proxy IP instead of real client IP (ip-leak)" >&2
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
# direct-scenario apache-access.log for an operator to grab.
# ---------------------------------------------------------------------
if [ -s "$CHAIN_ACCESS_LOG" ]; then
    cp "$CHAIN_ACCESS_LOG" "${TMPDIR:-/tmp}/apache-chain-access.log"
fi

# Step 16 (was Step 9): final report. Cleanup happens via the EXIT
# trap. FAIL=1 may have been set by either Step 7b's direct-scenario
# assertions OR Step 14's chain-scenario assertion — both
# accumulate into the same flag, both are reported by this single
# exit-code decision.
if [ "$FAIL" -ne 0 ]; then
    echo "[apache] FAIL: one or more assertions failed (see above)"
    exit 1
fi
echo "[apache] PASS: all assertions green - direct + proxy-chain FreeBSD/podman apache integration end-to-end works"
exit 0
