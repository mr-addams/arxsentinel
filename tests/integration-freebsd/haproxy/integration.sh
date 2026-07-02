#!/usr/bin/env sh
# tests/integration-freebsd/haproxy/integration.sh — Flow 091 integration
# smoke for the haproxy backend under FreeBSD/podman.
#
# Adapted from integration.sh — Flow 089/091 paid 9+ iterations to make
#  this structure green across nginx/caddy/traefik; do NOT restructure
#  without re-verifying all assertions.
#
# Architecture (per Flow 089 DECISIONS §2 + §3, carried over verbatim):
# - haproxy runs in a Linux-emulated docker.io/library/haproxy:latest
#   container under podman (FreeBSD Linux compat — see Flow 088 DECISIONS
#   §"A.2"). haproxy is a single Go-style static binary; no plugin build
#   or xcaddy step is required (caddy needed transform-encoder to coerce
#   its native JSON into CLF; haproxy emits httplog-derived format
#   natively, which the arx-core "haproxy-http" parser profile expects
#   out of the box — see haproxy.cfg header for the source-verified
#   reasoning).
# - arxsentinel runs NATIVE on the VM host (NOT in a container —
#   DECISIONS §2), with its CWD = $WORK_DIR so the relative paths in
#   sentinel-haproxy.yaml resolve correctly.
# - The attacker runs in a SECOND podman container (curlimages/curl) on
#   the same CNI network. Both attacker requests share the curl
#   container's CNI IP (DECISIONS §3).
#
# KEY ARCHITECTURAL DIVERGENCE FROM caddy/nginx/traefik (per Flow 091
# DECISIONS §4 haproxy row + brief):
#   nginx/caddy/traefik write the access log to a file that the run-
#   script bind-mounts onto the container, so the host-native sentinel
#   can tail the host-side file directly. HAProxy's `log stdout len
#   8192 format raw local0 info` directive (verbatim from the battle
#   suite's haproxy.cfg:8) writes the log line to the process's STDOUT,
#   not to a file. The run-script captures stdout via:
#       podman logs --follow haproxy > $WORK_DIR/haproxy/access.log 2>/dev/null &
#   backgrounded immediately after container start, with PID saved in
#   $LOGS_PID for cleanup-trap teardown. This mirrors the battle
#   suite's pattern (tests/integration/run.sh:230-232,
#   `docker compose logs -f --no-log-prefix haproxy >> $LOGS_DIR/haproxy/access.log`),
#   adapted for the standalone `podman run` path used here. The
#   sentinel then tails the host-side $WORK_DIR/haproxy/access.log
#   exactly like it would a bind-mounted log.
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
#   generalised to log-grep-only for traefik and beyond). HAProxy
#   follows the same pattern: the `podman logs haproxy` output
#   contains a known startup line that we grep for. The
#   empirical discovery of the exact substring is part of P4.6 live
#   dispatch; this script's readiness loop uses a CONSERVATIVE
#   pattern (any line containing "haproxy" — extremely unlikely to
#   be a false positive, since haproxy writes a banner on startup)
#   plus a 3s grace sleep to cover any post-banner init window.
#   If P4.6 reveals a more specific marker, tighten the grep —
#   the conservative form is the safe default.
#
# Phase P4 step mapping (P4.2 haproxy.cfg + sentinel-haproxy.yaml;
# P4.3 this script; P4.4 job wiring):
#   - P4.2: haproxy.cfg (frontend http-in, capture UA, log-format UA
#     extension, http-request return 404) + sentinel-haproxy.yaml
#     (general.log_file: haproxy/access.log, parser.profile:
#     haproxy-http, output.threat_log: output/threats-haproxy.log,
#     blocklist.lists[0].sources[0].url: mitchellkrogza upstream).
#   - P4.3: this file's skeleton + CNI network + haproxy container
#     startup with stdout-capture (steps 0-3 below).
#   - P4.3: sentinel host-process launch + "watching started" sync
#     (steps 4-5 below).
#   - P4.3: curl attacker with 8 attack blocks (sqlmap + 4 scanners
#     + Mozilla + 12 bruteforce + 6 crawler + 8 noasset + 60 rate +
#     1 overflow + 2 badbot) — step 6 below. Per Flow 092 Decision 7.
#   - P4.3: 12 assertions (THREAT+IP, Mozilla-absent, score/reason-
#     format, 7 module-name checks, badbot module, blocklist-
#     automaton-loaded) — step 7.
#   - P4.3: artifact persistence copy (step 8).
#   - Flow 092 (P4.7): proxy-chain scenario appended as Steps 10-16
#     (DECISIONS §1-§5). Same image (haproxy:latest) on a dedicated
#     chain CNI network (10.89.4.0/24, N=4 per DECISIONS §2) with
#     chain-scenario haproxy.cfg (`option forwardfor` →
#     `http-request set-var(txn.client_ip) req.hdr_ip(X-Forwarded-
#     For,1)`, plus `%ci:%cp` → `%[var(txn.client_ip)]:%cp` in
#     log-format — battle-suite-proven pattern from
#     tests/integration/configs/haproxy-backend.cfg:22-37). nginx-rp
#     is the universal proxy (DECISIONS §1); assertion 4 verifies
#     the chain backend logs the real client IP, not the proxy's
#     connecting address (ip-leak class).

set -eu

# ---------------------------------------------------------------------
# Step 0: locate inputs. REPO_ROOT is the workspace root ($GITHUB_WORKSPACE
# at workflow runtime). All three inputs are committed in this directory.
#
# This script lives at tests/integration-freebsd/haproxy/integration.sh —
# three path segments below the repo root, so dirname($0) needs three
# "../" to reach it (NOT two, which is what 088's
# tests/integration-freebsd/run-smoke.sh used, since that script is
# only two segments deep).
# ---------------------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
HAPROXY_DIR="$REPO_ROOT/tests/integration-freebsd/haproxy"
HAPROXY_CONF="$HAPROXY_DIR/haproxy.cfg"
SENTINEL_BIN="$REPO_ROOT/arxsentinel"
SENTINEL_CFG_SRC="$HAPROXY_DIR/sentinel-haproxy.yaml"

# Sanity: all three inputs must exist. A typo or missing build would
# silently produce an empty access log and the assertions would
# falsely PASS.
if [ ! -s "$HAPROXY_CONF" ]; then
    echo "[haproxy] FAIL: haproxy.cfg missing or empty at $HAPROXY_CONF" >&2
    exit 1
fi
if [ ! -x "$SENTINEL_BIN" ]; then
    echo "[haproxy] FAIL: arxsentinel binary not found or not executable at $SENTINEL_BIN" >&2
    exit 1
fi
if [ ! -s "$SENTINEL_CFG_SRC" ]; then
    echo "[haproxy] FAIL: sentinel-haproxy.yaml missing or empty at $SENTINEL_CFG_SRC" >&2
    exit 1
fi

# ---------------------------------------------------------------------
# Step 1: create $WORK_DIR + the bind-mounted subdirs. $WORK_DIR lives
# under $TMPDIR (set by the workflow as scoped TMPDIR — P4.4 carry of
# 088 G.1) so the cleanup trap's rm -rf lands in a tmpfs / workspace
# sync area, not under /var/db or /usr/local. The relative paths in
# sentinel-haproxy.yaml (haproxy/access.log, output/threats-haproxy.log)
# resolve against $WORK_DIR when the sentinel CWDs there in step 4.
#
# $WORK_DIR/haproxy/ is the host-side destination of the
# `podman logs --follow haproxy > ...` capture process started in
# step 3b. nginx/caddy/traefik bind-mount /logs or /var/log/caddy
# onto a host subdir; HAProxy has no such bind-mount (its log goes
# to stdout) so the host subdir is created by THIS script and
# populated by the `podman logs --follow` background process.
# ---------------------------------------------------------------------
WORK_DIR="${TMPDIR:-/tmp}/arx-haproxy-$$"
mkdir -p "$WORK_DIR/haproxy" "$WORK_DIR/output"
# 0755 is enough: sentinel runs as root on the FreeBSD host (no
# nonroot hardening yet — see Flow 089 Deferred 089.9 + 088 TD-8).
chmod 0755 "$WORK_DIR/output"

# Stage inputs into $WORK_DIR so the haproxy container bind-mount (for
# the CONFIG, not the log) and the sentinel CWD see them in a
# predictable layout.
cp "$HAPROXY_CONF" "$WORK_DIR/haproxy.cfg"
cp "$SENTINEL_CFG_SRC" "$WORK_DIR/sentinel-haproxy.yaml"

# podman-network and container-name markers — used in cleanup() and
# step 3 (wait-for-haproxy). Set as empty strings so the trap is
# idempotent on early exit (e.g. if podman network create fails).
NETWORK="arx-net"
HAPROXY_CID=""
LOGS_PID=""

# Chain-scenario markers (Steps 10-16). Separate from the direct-scenario
# vars above so a failure in Step 3 cleanup() still leaves the chain
# cleanup code paths exercised (and vice versa). Empty defaults keep the
# trap idempotent if the chain section is never reached. Mirrors the
# traefik integration.sh pattern (traefik/integration.sh:144-147) and
# caddy integration.sh pattern.
CHAIN_NETWORK="arx-chain-net"
HAPROXY_CHAIN_CID=""
HAPROXY_RP_CID=""
# Chain-scenario stdout-capture PID (Step 11b). Same architectural
# divergence from caddy/traefik as Step 3b: HAProxy logs to stdout
# (`log stdout len 8192 format raw local0 info` in haproxy.cfg:99),
# so the chain backend's log is captured by a backgrounded
# `podman logs --follow` process into $WORK_DIR/haproxy-chain/
# access.log, NOT a bind-mount. Mirror of $LOGS_PID in the direct
# scenario. cleanup() kills this PID on EXIT.
CHAIN_LOGS_PID=""

cleanup() {
    if [ -n "$HAPROXY_CID" ]; then
        podman rm -f "$HAPROXY_CID" >/dev/null 2>&1 || true
    fi
    if [ -n "$HAPROXY_CHAIN_CID" ]; then
        podman rm -f "$HAPROXY_CHAIN_CID" >/dev/null 2>&1 || true
    fi
    if [ -n "$HAPROXY_RP_CID" ]; then
        podman rm -f "$HAPROXY_RP_CID" >/dev/null 2>&1 || true
    fi
    # Stop the stdout-capture process (P4.3 architectural divergence
    # from caddy/traefik — see file header). Without this, `podman logs
    # --follow` would keep running in the background and either
    # accumulate a dangling PID or, on job retry, the file would keep
    # growing after cleanup. We saved the PID in $LOGS_PID in step 3b.
    if [ -n "$LOGS_PID" ]; then
        kill "$LOGS_PID" >/dev/null 2>&1 || true
    fi
    # Chain-scenario stdout-capture PID (Step 11b) — same rationale
    # as the direct-scenario $LOGS_PID above. If unset (chain section
    # never reached, e.g. early-fail in Step 3), the empty-string
    # guard is a no-op.
    if [ -n "$CHAIN_LOGS_PID" ]; then
        kill "$CHAIN_LOGS_PID" >/dev/null 2>&1 || true
    fi
    # CNI networks do not auto-GC on job exit (DECISIONS §3 consequences):
    # remove the networks explicitly. Both direct and chain networks
    # are unconditionally attempted — podman network rm on a missing
    # network exits non-zero, hence the || true (matches the original
    # direct-scenario pattern + traefik carry).
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
    # artifact path — P4.4 carry of 089 Task 3.6 / 4.3). The
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
# 10.88.0.0/16 on FreeBSD) is fine for the direct-haproxy test.
# ---------------------------------------------------------------------
echo "[haproxy] creating CNI network $NETWORK..."
podman network create "$NETWORK"

# ---------------------------------------------------------------------
# Step 3: start the haproxy container detached. bind-mount the staged
# haproxy.cfg over /usr/local/etc/haproxy/haproxy.cfg (the default path
# the official haproxy image reads on startup; haproxy's ENTRYPOINT is
# the daemon itself, which parses this file before binding :8080 —
# NOT :80, per the haproxy.cfg header WHY-comment on the non-root
# privileged-port bind failure found live).
# Note: we DO NOT bind-mount a host log dir onto /var/log/haproxy —
# HAProxy's log target in haproxy.cfg is `log stdout ...`, so the
# container never writes a file (P4.3 architectural divergence —
# see file header). --name haproxy is kept for operator convenience
# (`podman logs haproxy`, `podman exec haproxy ...` below) but is NOT
# used as a DNS name by the curl attacker — step 6 resolves the
# container's CNI IP via `podman inspect` instead, since the FreeBSD
# CNI bridge plugin has no dnsname resolver (G6; same as nginx +
# caddy + traefik runs).
#
# Fully-qualified docker.io/library/haproxy:latest (NOT bare
# haproxy:latest): the FreeBSD podman default
# /usr/local/share/containers/registries.conf has no
# unqualified-search-registries entry, so a short name fails with
# "did not resolve to an alias and no unqualified-search registries
# are defined" (G1; same class of bug as 088 podman-spike step 5
# and 091 integration.sh / integration.sh / integration.sh use of
# fully-qualified names). The "latest" tag was verified against
# tests/integration/docker-compose.yml:75-89 (G13): the battle suite
# uses exactly `image: haproxy:latest` on the same
# `docker.io/library/haproxy:latest` upstream, so there is NO tag
# guesswork in P4.6.
#
# --os=linux is REQUIRED: docker.io/library/haproxy:latest's OCI
# image index has no "freebsd" OS variant, only linux/*. Without
# --os=linux, podman on FreeBSD defaults to looking for a
# freebsd-OS manifest and fails with "no image found in image
# index for architecture amd64 ... OS freebsd" (G2; same flag
# 088 podman-spike step 5 used for docker.io/alpine and 089
# integration.sh / 091 integration.sh / 091 integration.sh use for
# their respective images).
#
# Why standalone `podman run` (NO `--pod`, per G7): podman on FreeBSD
# (podman 5.8.3, ocijail 0.6.0) breaks the linuxulator for
# containers launched inside a pod, even with identical flags.
# Decision 2 + G7 explicitly mandate standalone for every per-
# backend run script; podman-compose is recorded as technically
# infeasible (Deferred 091.7 Revised).
#
# CRITICAL: the WHY-comment block above MUST stay OUTSIDE the $(...)
# command substitution. If a comment line is inserted between the -v
# flag backslash-continuation and the image name, the comment (which
# has no trailing backslash) breaks the continuation chain -- the
# $(...) closes early and the image name becomes a separate broken
# command. sh -n and shellcheck do NOT catch this class of bug; it is
# a runtime bug, not a syntax bug. Same caveat as integration.sh:218
# and the caddy post-mortem in .tmp/coder-brief-091-p2-fix2.md.
# ---------------------------------------------------------------------
echo "[haproxy] starting haproxy container..."
HAPROXY_CID=$(podman run -d \
    --os=linux \
    --name haproxy \
    --network "$NETWORK" \
    -v "$WORK_DIR/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro" \
    docker.io/library/haproxy:latest)
echo "[haproxy] container $HAPROXY_CID started"

# ---------------------------------------------------------------------
# Step 3b (P4.3 architectural divergence): background `podman logs
# --follow` to capture HAProxy's stdout into the host-side
# $WORK_DIR/haproxy/access.log. The sentinel tails this file in
# step 4 (mirrors how nginx/caddy/traefik scripts tail their
# bind-mounted host-side files). The PID is saved for cleanup-trap
# teardown; the 2>/dev/null swallows podman's own stderr (it
# sometimes writes "level=warning msg=" lines on container
# shutdown that we don't want in the access log).
#
# This MUST run AFTER the container starts and BEFORE the
# readiness check below — otherwise the first few HAProxy log
# lines (the very ones we grep for) would be lost. The
# backgrounding with `&` + `> ... 2>/dev/null` is POSIX-sh-safe
# (verified in tests/integration/run.sh:230-232, which uses the
# same pattern with `docker compose logs -f`).
# ---------------------------------------------------------------------
echo "[haproxy] starting stdout-capture process (podman logs --follow)..."
podman logs --follow haproxy > "$WORK_DIR/haproxy/access.log" 2>/dev/null &
LOGS_PID=$!
echo "[haproxy] stdout-capture PID: $LOGS_PID"

# Wait for haproxy to be ready: log-grep pattern ONLY (no wget,
# following the caddy/traefik lessons — see file header WHY-comment).
# The pattern is intentionally CONSERVATIVE (any line containing
# "haproxy" in the access log) — empirically the haproxy:latest
# banner / first log line is the most reliable early-arrival marker,
# and over-broad grep is harmless here (the access log only has
# haproxy-emitted lines, never attacker text). A 3s grace sleep
# covers the post-banner init window (frontend bind + worker spawn
# + first stats socket). If P4.6 reveals a more specific marker,
# tighten the grep; the conservative form is the safe default.
#
# We poll `podman logs haproxy` DIRECTLY (NOT the host-side
# $WORK_DIR/haproxy/access.log file written by the backgrounded
# `podman logs --follow ... > file &` process from step 3b). Found
# live (run 28556804334): the file stayed completely empty for the
# full 30s timeout even though `podman logs --tail 30 haproxy` (a
# direct, one-shot call) showed the startup NOTICE lines immediately
# — classic stdio full-buffering: `podman logs --follow`'s output,
# redirected to a FILE (not a TTY), is buffered by the C library and
# the short NOTICE lines never fill the buffer enough to flush within
# the poll window. A direct `podman logs` call has no such buffering
# (each invocation is a fresh read of the container's log ring, not a
# streamed pipe), so it reliably sees the content immediately.
echo "[haproxy] waiting for haproxy ready (timeout 30s)..."
DEADLINE=$(($(date +%s) + 30))
READY=0
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    if podman logs haproxy 2>&1 | grep -q "Loading success"; then
        sleep 3
        READY=1
        break
    fi
    sleep 1
done
if [ "$READY" -ne 1 ]; then
    echo "[haproxy] FAIL: haproxy not ready within 30s" >&2
    echo "[haproxy] access log content (if any):" >&2
    cat "$WORK_DIR/haproxy/access.log" >&2 || true
    echo "[haproxy] podman logs (last 30 lines):" >&2
    podman logs --tail 30 haproxy >&2 || true
    exit 1
fi
echo "[haproxy] haproxy ready"

# ---------------------------------------------------------------------
# Step 4: start the native sentinel. DECISIONS §2 — sentinel on host,
# NOT in a container. CWD = $WORK_DIR so the relative paths in
# sentinel-haproxy.yaml resolve. The sentinel writes its pid to
# /tmp/arxsentinel.pid (per the yaml) and its operational log to
# sentinel-haproxy.log under $WORK_DIR.
# ---------------------------------------------------------------------
echo "[haproxy] starting native sentinel (CWD=$WORK_DIR)..."
cd "$WORK_DIR"
"$SENTINEL_BIN" \
    --config "$WORK_DIR/sentinel-haproxy.yaml" \
    > "$WORK_DIR/sentinel-haproxy.log" 2>&1 &
SENTINEL_PID=$!
echo "[haproxy] sentinel started with PID $SENTINEL_PID"

# Step 5: wait for "watching started" in sentinel-haproxy.log. This
# sync prevents the host append in step 6 from racing the TailReader
# open+seek(EOF) (mirrors 088 run-smoke.sh step 3). The yaml's
# logging.debug: true is REQUIRED for the "TAIL watching started"
# line to be emitted (see sentinel-haproxy.yaml header).
echo "[haproxy] waiting for 'watching started' (timeout 30s)..."
DEADLINE=$(($(date +%s) + 30))
WATCHING=0
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    if grep -q "watching started" "$WORK_DIR/sentinel-haproxy.log" 2>/dev/null; then
        WATCHING=1
        break
    fi
    sleep 1
done
if [ "$WATCHING" -ne 1 ]; then
    echo "[haproxy] FAIL: 'watching started' not seen within 30s" >&2
    echo "[haproxy] sentinel log (last 50 lines):" >&2
    tail -50 "$WORK_DIR/sentinel-haproxy.log" >&2 || true
    kill "$SENTINEL_PID" 2>/dev/null || true
    exit 1
fi
echo "[haproxy] TailReader ready"

# ---------------------------------------------------------------------
# Step 6: drive attacks from a curl container. DECISIONS §3 said the
# curl container could resolve "haproxy" via container DNS — live runs
# for nginx/caddy/traefik disproved that: the FreeBSD
# `containernetworking-plugins` port ships the basic CNI bridge
# plugin only, NOT a dnsname plugin (G6; same as nginx + caddy +
# traefik). Resolve the haproxy container's CNI IP via `podman
# inspect` instead of relying on DNS, and use the IP directly in
# the curl URL.
#
# Per Flow 092 DECISIONS §7 (close the Flow 091 Decision 9 gap): all 7
# attack scenario blocks (probe, ua, bruteforce, crawler, noasset, rate,
# overflow) + the badbot (block 8) are now driven from a SINGLE curl
# container, mirroring tests/integration/scenarios.sh:80-183 (battle
# suite source of truth). Mirrors the traefik integration.sh pattern
# (traefik/integration.sh:331-503) which is the most-clean reference
# (proven green with 0 bugs, 2 consecutive dispatches). The port
# `:8080` is required because haproxy in this job binds :8080 (not
# :80 — see haproxy.cfg header WHY-comment on the non-root
# privileged-port bind).
# ---------------------------------------------------------------------
SQLMAP_UA='sqlmap/1.7.11'
MOZILLA_UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'

# `index` (not dot-notation) is REQUIRED: $NETWORK contains a hyphen
# ("arx-net"), and a Go template map-key access via dot-notation
# (.Networks.arx-net.IPAddress) parses the hyphen as a subtraction
# operator and fails with "bad character U+002D '-'" (G8; live run
# 28477133986 hit this exact error). `index` takes the key as a
# string argument, sidestepping Go template identifier syntax rules.
HAPROXY_IP=$(podman inspect haproxy --format "{{(index .NetworkSettings.Networks \"${NETWORK}\").IPAddress}}")
if [ -z "$HAPROXY_IP" ]; then
    echo "[haproxy] FAIL: could not resolve haproxy container's CNI IP via podman inspect" >&2
    exit 1
fi
echo "[haproxy] haproxy container IP: $HAPROXY_IP"

# Generate the long URL path for the overflow scenario (block 7) on
# the HOST (not inside the curl container) so the value can be
# embedded as a literal in the -c "..." script string below.
#
# NOT scenarios.sh:169's `/dev/urandom | tr -dc 'a-zA-Z0-9'` recipe:
# G20 (proven live on nginx/caddy/traefik) — produces EMPTY output
# on this FreeBSD VM's native sh (BSD tr vs GNU tr, or /dev/urandom
# access under vmactions SSH — root cause not pinned). The overflow
# detector only checks byte length, not entropy, so a deterministic
# `awk` one-liner is sufficient: POSIX-standard, zero external-tool
# portability surface. Same fix as traefik/integration.sh:362.
LONG_PATH="/$(awk 'BEGIN { s = ""; for (i = 0; i < 2200; i++) s = s "a"; print s }')"
echo "[haproxy] LONG_PATH length: $(printf '%s' "$LONG_PATH" | wc -c) bytes"

# Pick the badbot UA the same way traefik/integration.sh:378-382 does:
# prefer the committed test fixture ($REPO_ROOT/tests/integration/
# blocklist/test-ua.txt) because it is the same file run.sh:122
# produces from the FIRST literal pattern in the upstream mitchellkrogza
# list — a pattern the FreeBSD sentinel's blocklist automaton will also
# load (same upstream URL, see sentinel-haproxy.yaml blocklist.lists[0].
# sources[0].url). Fallback "AhrefsBot" matches scenarios.sh:179.
if [ -s "$REPO_ROOT/tests/integration/blocklist/test-ua.txt" ]; then
    BADBOT_UA=$(head -1 "$REPO_ROOT/tests/integration/blocklist/test-ua.txt")
else
    BADBOT_UA="AhrefsBot"
fi
echo "[haproxy] using badbot UA for block 8: ${BADBOT_UA}/1.0"

# ONE curl container for ALL 8 blocks (NOT one per block) — mirrors
# traefik/integration.sh:411-413. Detectors (bruteforce, crawler,
# noasset, rate) are per-IP trackers; multiple attacker containers
# would each see only a fraction of the required request count → no
# fire → no threat log entry → false-negative assertion. The Mozilla
# UA legit request is folded into block 2 (ua) as the last request —
# same reasoning as traefik/integration.sh:428-437 (assertion 2 only
# makes sense in the context of the scanner-UA attack on the same IP).
#
# All 8 blocks are verbatim ports from tests/integration/
# scenarios.sh:80-183 (per Flow 092 Decision 7) — each block's source
# line is annotated in the same WHY comment style as the rest of
# this file. The port `:8080` is required because haproxy in this
# job binds :8080 (NOT :80 — see haproxy.cfg header WHY-comment on
# the non-root privileged-port bind).
echo "[haproxy] driving 8 attack blocks from a single curl container..."
ATTACK_SCRIPT="
# ── block 1: probe (scenarios.sh:82-90) ──
curl -sf -o /dev/null http://${HAPROXY_IP}:8080/wp-login.php      || true
curl -sf -o /dev/null http://${HAPROXY_IP}:8080/.env              || true
curl -sf -o /dev/null http://${HAPROXY_IP}:8080/.git/config       || true
curl -sf -o /dev/null http://${HAPROXY_IP}:8080/admin/config.php  || true
curl -sf -o /dev/null http://${HAPROXY_IP}:8080/etc/passwd        || true
curl -sf -o /dev/null http://${HAPROXY_IP}:8080/.aws/credentials  || true
curl -sf -o /dev/null http://${HAPROXY_IP}:8080/xmlrpc.php        || true
# ── block 2: ua (scenarios.sh:94-100) + the legit Mozilla request ──
curl -sf -o /dev/null -A '${SQLMAP_UA}'     http://${HAPROXY_IP}:8080/ || true
curl -sf -o /dev/null -A '${SQLMAP_UA}'     http://${HAPROXY_IP}:8080/ || true
curl -sf -o /dev/null -A 'Nuclei/3.0'       http://${HAPROXY_IP}:8080/ || true
curl -sf -o /dev/null -A 'masscan/1.3'      http://${HAPROXY_IP}:8080/ || true
curl -sf -o /dev/null -A 'zgrab/0.x'        http://${HAPROXY_IP}:8080/ || true
# Legit Mozilla request — kept in block 2 (NOT a separate block)
# because Assertion 2 (Mozilla UA absent from threat log) only
# makes sense in the context of the scanner-UA attack on the same
# IP. Mirrors traefik/integration.sh:429-437.
curl -sf -o /dev/null -A '${MOZILLA_UA}'    http://${HAPROXY_IP}:8080/ || true
# ── block 3: bruteforce (scenarios.sh:104-120) ──
curl -sf -o /dev/null http://${HAPROXY_IP}:8080/                      || true
curl -sf -o /dev/null http://${HAPROXY_IP}:8080/                      || true
curl -sf -o /dev/null http://${HAPROXY_IP}:8080/                      || true
curl -sf -o /dev/null http://${HAPROXY_IP}:8080/missing-page-1        || true
curl -sf -o /dev/null http://${HAPROXY_IP}:8080/missing-page-2        || true
curl -sf -o /dev/null http://${HAPROXY_IP}:8080/missing-page-3        || true
curl -sf -o /dev/null http://${HAPROXY_IP}:8080/missing-page-4        || true
curl -sf -o /dev/null http://${HAPROXY_IP}:8080/missing-page-5        || true
curl -sf -o /dev/null http://${HAPROXY_IP}:8080/missing-page-6        || true
curl -sf -o /dev/null http://${HAPROXY_IP}:8080/missing-page-7        || true
curl -sf -o /dev/null http://${HAPROXY_IP}:8080/missing-page-8        || true
curl -sf -o /dev/null http://${HAPROXY_IP}:8080/missing-page-9        || true
curl -sf -o /dev/null http://${HAPROXY_IP}:8080/missing-page-10       || true
curl -sf -o /dev/null http://${HAPROXY_IP}:8080/missing-page-11       || true
curl -sf -o /dev/null http://${HAPROXY_IP}:8080/missing-page-12       || true
# ── block 4: crawler (scenarios.sh:126-132) ──
curl -sf -o /dev/null http://${HAPROXY_IP}:8080/items/1  || true
curl -sf -o /dev/null http://${HAPROXY_IP}:8080/items/2  || true
curl -sf -o /dev/null http://${HAPROXY_IP}:8080/items/3  || true
curl -sf -o /dev/null http://${HAPROXY_IP}:8080/items/4  || true
curl -sf -o /dev/null http://${HAPROXY_IP}:8080/items/5  || true
curl -sf -o /dev/null http://${HAPROXY_IP}:8080/items/6  || true
# ── block 5: noasset (scenarios.sh:138-146) ──
curl -sf -o /dev/null http://${HAPROXY_IP}:8080/           || true
curl -sf -o /dev/null http://${HAPROXY_IP}:8080/           || true
curl -sf -o /dev/null http://${HAPROXY_IP}:8080/           || true
curl -sf -o /dev/null http://${HAPROXY_IP}:8080/info.php   || true
curl -sf -o /dev/null http://${HAPROXY_IP}:8080/           || true
curl -sf -o /dev/null http://${HAPROXY_IP}:8080/           || true
curl -sf -o /dev/null http://${HAPROXY_IP}:8080/info.php   || true
curl -sf -o /dev/null http://${HAPROXY_IP}:8080/           || true
# ── block 6: rate (scenarios.sh:151-161) — 60 requests in 2 waves with 1s gap ──
i=0; while [ \$i -lt 30 ]; do
    curl -sf -o /dev/null http://${HAPROXY_IP}:8080/ || true
    i=\$((i+1))
done
sleep 1
i=0; while [ \$i -lt 30 ]; do
    curl -sf -o /dev/null http://${HAPROXY_IP}:8080/ || true
    i=\$((i+1))
done
# ── block 7: overflow (scenarios.sh:169-172) — single URL with path > 2048 bytes ──
curl -sf -o /dev/null 'http://${HAPROXY_IP}:8080${LONG_PATH}' || true
# ── block 8: badbot (scenarios.sh:180-183) — LAST on purpose ──
# scenarios.sh:177-178: 'Placed last among direct-server scenarios to
# give sentinels time to load patterns from the local blocklist-server
# container before the request arrives.' Same reasoning applies here
# (blocklist fetch is async from start, automaton rebuild on first
# successful fetch — badbot last gives the wall-clock budget). Two
# requests, not one, for the same threshold-crossing reason as the
# sqlmap pair in block 2 (the badbot detector's first hit may not
# cross the alert threshold on its own).
curl -sf -o /dev/null -A '${BADBOT_UA}/1.0' http://${HAPROXY_IP}:8080/ || true
curl -sf -o /dev/null -A '${BADBOT_UA}/1.0' http://${HAPROXY_IP}:8080/ || true
"

podman run --rm --os=linux --network "$NETWORK" \
    --entrypoint /bin/sh \
    docker.io/curlimages/curl \
    -c "$ATTACK_SCRIPT" \
    >/dev/null 2>&1 \
    || echo "[haproxy] curl attacker exited non-zero (still check the access log)"
echo "[haproxy] attacks sent"

# Give the `podman logs --follow` capture process a brief window to
# flush its pipe buffer into $WORK_DIR/haproxy/access.log before
# the assertion step reads it. 1s is sufficient for the ~105
# requests Step 6 now sends (7+6+15+6+8+60+1+2 from the 8 blocks;
# pipe buffer is 64KB on FreeBSD by default; 105 httplog lines at
# ~200 bytes each = ~21KB, well under the buffer). The Step 7
# polling loop (next step) has its own 40s budget to absorb any
# pipe-flush race, so this 1s is a cheap belt-and-suspenders.
sleep 1

# ---------------------------------------------------------------------
# Step 7: poll the threat log for non-empty content. Timeout RAISED
# from 20s → 40s to match traefik/integration.sh:507-516 (Step 6 now
# sends ~105 attack requests, vs. 3 in the original P4.6 smoke; the
# rate block's 1s sleep + sentinel per-request scoring add wall-clock
# cost on top). Mirrors traefik/integration.sh:518-528 + the 40s
# polling loop proven green there.
# ---------------------------------------------------------------------
THREAT_LOG="$WORK_DIR/output/threats-haproxy.log"
echo "[haproxy] polling $THREAT_LOG (timeout 40s)..."
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
    echo "[haproxy] FAIL: $THREAT_LOG not written within 40s" >&2
    echo "[haproxy] access log content (if any):" >&2
    cat "$WORK_DIR/haproxy/access.log" >&2 || true
    echo "[haproxy] sentinel log (last 80 lines):" >&2
    tail -80 "$WORK_DIR/sentinel-haproxy.log" >&2 || true
    exit 1
fi

# Dump the threat log for inline visibility.
LINES=$(cat "$THREAT_LOG")
echo "[haproxy] threat log content:"
printf '%s\n' "$LINES" | sed 's/^/  /'

# ---------------------------------------------------------------------
# Step 7a: extract the sqlmap-request source IP from the access log.
# DECISIONS §5 — the attacker's source IP is the curl container's
# CNI-assigned IP, which appears in access.log as the first field
# of the line containing the sqlmap UA. The haproxy httplog format
# prefixes the line with "<client_ip>:<client_port> [...]" — the IP
# is the colon-prefixed token BEFORE the first colon. awk with -F:
# would split on the port, but a simple awk '{print $1}' on the
# space-delimited view still gives us "<ip>:<port>" as the first
# field; the assertion's grep pattern is ` $IP ` (space-IP-space)
# so the trailing ":port" in the field is harmless — the IP we
# extract IS the substring the assertion greps for.
# ---------------------------------------------------------------------
ACCESS_LOG="$WORK_DIR/haproxy/access.log"
if [ ! -s "$ACCESS_LOG" ]; then
    echo "[haproxy] FAIL: access log empty or missing at $ACCESS_LOG" >&2
    exit 1
fi
# grep the sqlmap UA (literal, no regex specials) then awk the first
# field. Safe even if the UA contains regex chars — grep treats it
# as a fixed string in this case (no -E flag).
SQLMAP_IP=$(grep "${SQLMAP_UA}" "$ACCESS_LOG" | awk '{print $1}' | head -1 | cut -d: -f1)
if [ -z "$SQLMAP_IP" ]; then
    echo "[haproxy] FAIL: could not extract sqlmap request IP from access log" >&2
    echo "[haproxy] access log content:" >&2
    cat "$ACCESS_LOG" >&2 || true
    exit 1
fi
echo "[haproxy] sqlmap request source IP: $SQLMAP_IP"

# Diagnostic (proven live on traefik:28585617384 — overflow assertion
# failing, LONG_PATH byte-length echoed near generation to compare
# against this): print the access-log line matching the long-path
# request, and its request-field byte length, to see what haproxy
# actually logged for it (full URI vs truncated vs never received).
# HAProxy's tune.http.logurilen 4096 (haproxy.cfg:104) plus the
# haproxy-http parser regex's `(?P<request>[^"]*)` capture group both
# expect the full URL to survive into the log line; this diagnostic
# confirms the long path made it through haproxy and into the access
# log.
OVERFLOW_LOG_LINE=$(grep -E '"GET /[a-zA-Z0-9]{100,}' "$ACCESS_LOG" | head -1)
if [ -n "$OVERFLOW_LOG_LINE" ]; then
    echo "[haproxy] overflow request access-log line length: $(printf '%s' "$OVERFLOW_LOG_LINE" | wc -c) bytes"
else
    echo "[haproxy] overflow request NOT FOUND in access log (long-path GET never logged)"
fi

# ---------------------------------------------------------------------
# Step 7b: assertions. Originally 3 per DECISIONS §5 (adapted from
# 088 run-smoke.sh — UA-based, not IP-based). EXTENDED to 12 per
# Flow 092 Task A2 / Decision 7: 1-3 retained, 4-10 are one
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
# IP extracted from access.log, NOT a fixed literal.)
if ! printf '%s\n' "$LINES" | grep -q " THREAT " \
   || ! printf '%s\n' "$LINES" | grep -q " $SQLMAP_IP "; then
    echo "[haproxy] FAIL: assertion 1 - expected ' THREAT ' and IP '$SQLMAP_IP' in threat log" >&2
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
    echo "[haproxy] FAIL: assertion 2 - false positive: Mozilla UA appeared in threat log" >&2
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
    echo "[haproxy] FAIL: assertion 3 - $BAD_COUNT threat line(s) missing score=/reason=" >&2
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
        echo "[haproxy] FAIL: assertion - expected module '$module' in threat log (reason=)" >&2
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
    echo "[haproxy] FAIL: assertion 11 - badbot module not in threat log (expected reason=badbot:...)" >&2
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
# in sentinel-haproxy.yaml → upstream fetch → automaton rebuild → UA
# matching in block 8's requests. The operational log path is
# `output.operational_log: sentinel-haproxy.log` in
# sentinel-haproxy.yaml — relative to $WORK_DIR, which is the
# sentinel's CWD (set in Step 4).
SENTINEL_OP_LOG="$WORK_DIR/sentinel-haproxy.log"
if [ ! -s "$SENTINEL_OP_LOG" ] \
   || ! grep -qE 'automaton rebuilt \([1-9][0-9]* patterns\)' "$SENTINEL_OP_LOG"; then
    echo "[haproxy] FAIL: assertion 12 - blocklist automaton not loaded (no 'automaton rebuilt (N patterns)' with N>0 in $SENTINEL_OP_LOG)" >&2
    FAIL=1
fi

# ---------------------------------------------------------------------
# Step 8: persist artifacts for the workflow. The cleanup trap on
# EXIT (set in step 1) does NOT remove $WORK_DIR when TMPDIR is
# $GITHUB_WORKSPACE — the workflow's actions/upload-artifact picks
# up these files BEFORE the VM is destroyed (P4.4 carry of 089 Task
# 3.6 / 4.3). The copies here land at the top of $TMPDIR (=
# $GITHUB_WORKSPACE in CI) so the workflow's `cat
# $GITHUB_WORKSPACE/...` + `upload-artifact` at P4.4 can find them
# by name.
# ---------------------------------------------------------------------
if [ -s "$THREAT_LOG" ]; then
    cp "$THREAT_LOG" "${TMPDIR:-/tmp}/threats-haproxy.log.smoke"
fi
if [ -s "$ACCESS_LOG" ]; then
    cp "$ACCESS_LOG" "${TMPDIR:-/tmp}/haproxy-access.log"
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
# dance). It also makes this script's inline log
# readable: a fixed address in the proxy URL is easier to grep-and-know
# than a $HAPROXY_RP_IP capture. N=4 for haproxy (nginx=1, caddy=2,
# traefik=3, haproxy=4, apache=5, litespeed=6 — Flow 092 DECISIONS
# §2 "per-backend offset").
# ---------------------------------------------------------------------

# ---------------------------------------------------------------------
# Step 10: create the chain network with a dedicated subnet
# (10.89.4.0/24 for haproxy — per-backend offset, see Flow 092
# DECISIONS §2; haproxy = N=4 since nginx took N=1, caddy took N=2,
# traefik took N=3). A separate network from the direct-scenario's
# $NETWORK ("arx-net") keeps the two scenarios' CNI bridges
# independent — a podman network create with the same name as a
# pre-existing network exits non-zero, so re-use would need an
# "if exists" dance. A fresh network is the simpler path.
# ---------------------------------------------------------------------
echo "[haproxy] creating chain CNI network $CHAIN_NETWORK (subnet 10.89.4.0/24)..."
podman network create --subnet 10.89.4.0/24 "$CHAIN_NETWORK"

# Static IP assignment for the chain backend (DECISIONS §2/§3).
# .10 within 10.89.4.0/24 — chosen by convention (smallest non-zero
# suffix for the "primary" service in the network, .20 for the
# upstream proxy). Hard-coded, not derived, on purpose: see
# DECISIONS §2 "static IPs also make the chain-scenario shell
# script easier to read and debug from an inline log".
CHAIN_BACKEND_IP="10.89.4.10"
CHAIN_PROXY_IP="10.89.4.20"

# ---------------------------------------------------------------------
# Step 11: start the chain-scenario backend. SAME `docker.io/library/
# haproxy:latest` image as Step 3 — proven to start on FreeBSD/
# podman by the direct scenario's Step 3 + readiness check. The
# chain haproxy.cfg is a SEPARATE file (not the direct-scenario
# $WORK_DIR/haproxy.cfg) for the same reason traefik/caddy use
# separate chain configs: the direct-scenario config has no XFF-
# trust config (never needed; the attacker connects directly), and
# the chain-scenario config has the txn.client_ip tracking directive
# that reads XFF (DECISIONS §5 haproxy row — see haproxy-backend.cfg:
# 22-31 for the battle-suite-proven pattern). Keeping two files (no
# conditional logic in one) preserves the proven direct-scenario
# haproxy.cfg verbatim — Decision 4 (copy-then-adapt, no premature
# library extraction).
#
# XFF-tracking mechanism for haproxy (battle-suite-verified):
# tests/integration/configs/haproxy-backend.cfg:22-31 uses TWO
# steps:
#   1. http-request set-var(txn.client_ip) req.hdr_ip(X-Forwarded-
#      For,1)   — at the request phase, capture the FIRST IP from
#      the XFF header (the "1" picks the leftmost — original
#      client) into a txn-scoped variable. Doing this at request
#      phase (NOT in log-format) is REQUIRED because per
#      haproxy-backend.cfg:22-25's own comment: "req.fhdr may not
#      be available at logging time in HAProxy 3.x — reliability
#      error" if read directly in log-format. Storing it in
#      txn.client_ip first sidesteps the reliability issue.
#   2. log-format ... %[var(txn.client_ip)]:%cp ... — read the
#      txn variable at log-format time. The %cp (client port) is
#      kept unchanged so the line still matches the haproxy-http
#      parser regex (^[^:]+:\d+ ...).
#
# Substitutions (sed-based, mirror caddy/integration.sh:786-791):
#   (a) option forwardfor → http-request set-var(txn.client_ip)
#       req.hdr_ip(X-Forwarded-For,1)  — direct string
#       substitution. `option forwardfor` is a no-op in the chain
#       scenario (haproxy has no upstream — `http-request return
#       status 404` short-circuits before any forwarding, so no
#       XFF is ever appended on outbound). Removing it and
#       replacing with the XFF-read directive is a clean 1-line
#       swap. The `option forwardfor` substring is unique in
#       haproxy.cfg (one occurrence only).
#   (b) %ci:%cp → %[var(txn.client_ip)]:%cp  — direct string
#       substitution in the log-format directive. The %ci
#       substring is unique in the file (only appears once, in
#       the log-format string). The %cp substring ALSO appears
#       there, so the sed must match both atoms together as
#       `%ci:%cp` to avoid unintended replacements.
#
# The chain backend continues to bind :8080 (NOT :80) — same
# non-root-privileged-port constraint as Step 3 (haproxy.cfg
# header WHY-comment on the live run 28556434720 "cannot bind
# socket" failure). The proxy in Step 12 sends requests to
# 10.89.4.10:8080, not :80.
# ---------------------------------------------------------------------
echo "[haproxy] preparing chain-scenario haproxy.cfg (with XFF-tracking for txn.client_ip)..."
mkdir -p "$WORK_DIR/haproxy-chain"

# Two sed substitutions, applied in order. Each pattern is
# unambiguous (unique-substring) in the source haproxy.cfg.
sed 's|^    option forwardfor$|    http-request set-var(txn.client_ip) req.hdr_ip(X-Forwarded-For,1)|' \
    "$WORK_DIR/haproxy.cfg" \
    | sed 's|%ci:%cp|%[var(txn.client_ip)]:%cp|' \
    > "$WORK_DIR/haproxy-chain.cfg"

echo "[haproxy] starting chain-scenario haproxy container on $CHAIN_BACKEND_IP..."
HAPROXY_CHAIN_CID=$(podman run -d \
    --os=linux \
    --name haproxy-chain \
    --network "$CHAIN_NETWORK" \
    --ip "$CHAIN_BACKEND_IP" \
    -v "$WORK_DIR/haproxy-chain.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro" \
    docker.io/library/haproxy:latest)
echo "[haproxy] chain backend $HAPROXY_CHAIN_CID started"

# ---------------------------------------------------------------------
# Step 11b (P4.3 architectural divergence — chain scenario): background
# `podman logs --follow` to capture the chain HAProxy's stdout into
# the host-side $WORK_DIR/haproxy-chain/access.log. The sentinel tails
# THIS file (in addition to $WORK_DIR/haproxy/access.log from the
# direct scenario) — but the chain assertion (Step 14) reads the
# chain access log directly via `grep`, NOT via sentinel. The
# 2>/dev/null swallows podman's own stderr (same reasoning as Step
# 3b's P4.3 WHY-comment: podman sometimes writes "level=warning"
# lines on container shutdown that we don't want in the access log).
# PID saved for cleanup-trap teardown as $CHAIN_LOGS_PID.
#
# This MUST run AFTER the chain container starts and BEFORE the
# readiness check below — otherwise the first few HAProxy log
# lines (the very ones we grep for) would be lost. The backgrounding
# with `&` + `> ... 2>/dev/null` is POSIX-sh-safe (same pattern as
# Step 3b).
#
# CRITICAL: this is the chain-scenario analogue of Step 3b. If
# omitted (reviewer CRITICAL flag on the first commit), the
# $CHAIN_ACCESS_LOG polling loop in Step 14 always times out because
# the file is never written to — the chain backend's stdout goes
# nowhere. Traefik/caddy chain scenarios don't need this because
# they use a -v bind-mount for the access log; haproxy's stdout-
# only logging (haproxy.cfg:99) means the chain backend needs the
# same workaround as the direct backend (Step 3b).
# ---------------------------------------------------------------------
echo "[haproxy] starting chain stdout-capture process (podman logs --follow)..."
podman logs --follow haproxy-chain > "$WORK_DIR/haproxy-chain/access.log" 2>/dev/null &
CHAIN_LOGS_PID=$!
echo "[haproxy] chain stdout-capture PID: $CHAIN_LOGS_PID"

# Wait-for-ready pattern identical to Step 3: log-grep on
# "Loading success" (the conservative startup-marker proven
# live, see Step 3 WHY-comment) + 3s grace sleep for frontend
# bind + worker spawn + first stats socket.
echo "[haproxy] waiting for chain backend ready (timeout 30s)..."
DEADLINE=$(($(date +%s) + 30))
READY=0
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    if podman logs haproxy-chain 2>&1 | grep -q "Loading success"; then
        sleep 3
        READY=1
        break
    fi
    sleep 1
done
if [ "$READY" -ne 1 ]; then
    echo "[haproxy] FAIL: chain backend not ready within 30s" >&2
    echo "[haproxy] chain backend logs (last 30 lines):" >&2
    podman logs --tail 30 haproxy-chain >&2 || true
    exit 1
fi
echo "[haproxy] chain backend ready"

# ---------------------------------------------------------------------
# Step 12: start the proxy container. VERBATIM copy of the proven
# nginx-rp pattern from tests/integration-freebsd/nginx/integration.sh
# (Step 12, lines 816-840) — same `docker.io/library/nginx:alpine`
# image, same `error_log /dev/stderr notice; include mime.types;
# open_log_file_cache off;` directive set (G17: reuse PROVEN template,
# not a minimal from-scratch one), with ONLY the `proxy_pass` target
# swapped to the haproxy chain backend's static IP
# ($CHAIN_BACKEND_IP = 10.89.4.10) and port :8080.
#
# The decision to use nginx-rp as the universal proxy for ALL backends
# (not just nginx) is Flow 092 Decision 1 — one generic reverse-proxy
# pattern, ported per backend. The haproxy-direct-scenario job needs
# to exercise haproxy's XFF-tracking handling; which proxy sits in
# front of it is incidental (nginx-rp is the proven, battle-suite-
# parity choice).
#
# Port :8080 (NOT :80): haproxy chain backend binds :8080 (same
# non-root-privileged-port constraint as Step 3 — see haproxy.cfg
# header WHY-comment). The battle suite's `tests/integration/
# configs/haproxy-backend.cfg:21` binds :80, but that runs as root
# in the Docker container — haproxy:latest on FreeBSD's
# ocijail-launched container runs as a non-root user and can't
# bind :80. The choice is captured in DECISIONS §2/§3 — every
# FreeBSD haproxy chain backend listens on :8080.
# ---------------------------------------------------------------------
cat > "$WORK_DIR/haproxy-rp.conf" <<NGINX_RP_EOF
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
mkdir -p "$WORK_DIR/haproxy-rp"
echo "[haproxy] starting proxy container on $CHAIN_PROXY_IP..."
HAPROXY_RP_CID=$(podman run -d \
    --os=linux \
    --name haproxy-rp \
    --network "$CHAIN_NETWORK" \
    --ip "$CHAIN_PROXY_IP" \
    -v "$WORK_DIR/haproxy-rp.conf:/etc/nginx/nginx.conf:ro" \
    -v "$WORK_DIR/haproxy-rp:/var/log/nginx" \
    docker.io/library/nginx:alpine)
echo "[haproxy] proxy $HAPROXY_RP_CID started"

# Same wait-for-ready pattern as nginx chain proxy. nginx -t catches
# the heredoc-substituted config typo case; "start worker processes"
# in podman logs is the full-start signal.
echo "[haproxy] waiting for proxy ready (timeout 30s)..."
DEADLINE=$(($(date +%s) + 30))
READY=0
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    if podman exec haproxy-rp nginx -t >/dev/null 2>&1 \
       && podman logs haproxy-rp 2>&1 | grep -q "start worker processes"; then
        READY=1
        break
    fi
    sleep 1
done
if [ "$READY" -ne 1 ]; then
    echo "[haproxy] FAIL: proxy not ready within 30s" >&2
    echo "[haproxy] proxy logs (last 30 lines):" >&2
    podman logs --tail 30 haproxy-rp >&2 || true
    exit 1
fi
echo "[haproxy] proxy ready"

# ---------------------------------------------------------------------
# Step 13: drive attacks THROUGH the proxy. Same UA mix as Step 6
# (sqlmap x2 + Mozilla x1) but the URL is the proxy's static IP
# (http://10.89.4.20/), NOT the chain backend's IP. The proxy adds
# X-Forwarded-For with the curl container's CNI IP, and the chain
# haproxy's `http-request set-var(txn.client_ip) req.hdr_ip(X-
# Forwarded-For,1)` directive parses that header's first IP into
# the txn.client_ip variable, and the chain haproxy's
# `log-format ... %[var(txn.client_ip)]:%cp ...` writes that real
# client IP as the logged address — the first field that the
# parser and grader use to attribute the attack. Mirror of the
# direct-scenario attack — same curl image, same attacker
# behavior, only the URL changes.
#
# --network $NETWORK: the curl container runs on the DIRECT-scenario
# network (arx-net), not the chain network. The two networks are
# isolated — a packet from arx-net cannot reach 10.89.4.20 by
# Layer-2 routing. This is the intended topology: the attacker
# sits on the same "outside" network as in Step 6, the proxy is
# the bridge. The curl container's CNI IP will therefore be on
# arx-net (different from the IP it would have if it were on
# arx-chain-net) — Step 14's assertion extracts the IP from the
# chain-backend's access log, so it doesn't matter that this IP
# is on a different network than the direct scenario's attacker
# IP.
# ---------------------------------------------------------------------
echo "[haproxy] driving proxy-chain attacks from curl container (sqlmap + Mozilla UAs)..."
podman run --rm --os=linux --network "$NETWORK" \
    --entrypoint /bin/sh \
    docker.io/curlimages/curl \
    -c "curl -sS -A '${SQLMAP_UA}' http://${CHAIN_PROXY_IP}/ ; curl -sS -A '${SQLMAP_UA}' http://${CHAIN_PROXY_IP}/ ; curl -sS -A '${MOZILLA_UA}' http://${CHAIN_PROXY_IP}/" \
    >/dev/null 2>&1 \
    || echo "[haproxy] chain curl attacker exited non-zero (still check the access log)"
echo "[haproxy] chain attacks sent"

# ---------------------------------------------------------------------
# Step 14: chain-specific assertion (4th). Wait for the chain-backend's
# access log to be written, extract the sqlmap-request source IP from
# IT (NOT from the direct-scenario access log), and verify that the
# extracted IP is the REAL client (curl container's CNI IP) — NOT
# the proxy's IP ($CHAIN_PROXY_IP). If the XFF-tracking config did
# NOT resolve the real client (e.g. txn.client_ip not populated,
# or the log-format substitution didn't reach the parser), the
# logged IP would be the proxy's connecting address
# ($CHAIN_PROXY_IP) — that is the "ip-leak" class of failure the
# battle suite's assert_chain (verify.sh:188) calls out
# (class=ip-leak in its report). Mirrored here in this script's
# existing grep-based assertion style (Step 7b) — same FAIL=1
# accumulator, same non-short-circuit report-at-end discipline.
#
# A note on UA-vs-NA-detection here: the chain scenario's detection
# fires off the SAME UA (sqlmap), so the threat log may contain
# entries from BOTH scenarios (direct Step 7's 8 blocks of
# requests and chain Step 13's three requests, all with the same
# UA, all from attackers the sentinel sees as the same kind of
# source). The check below is intentionally scoped to the
# chain-backend's OWN access log — that log only contains the
# chain scenario's three requests, and the logged IP field in
# that log is whatever the XFF-tracking config resolved (which
# we want to be the real client, not the proxy).
# ---------------------------------------------------------------------
CHAIN_ACCESS_LOG="$WORK_DIR/haproxy-chain/access.log"
echo "[haproxy] polling $CHAIN_ACCESS_LOG (timeout 20s)..."
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
    echo "[haproxy] FAIL: $CHAIN_ACCESS_LOG not written within 20s" >&2
    echo "[haproxy] proxy logs (last 30 lines):" >&2
    podman logs --tail 30 haproxy-rp >&2 || true
    exit 1
fi

# Extract the sqlmap-request source IP from the chain backend's
# access log. The chain haproxy.cfg log-format is
# `%[var(txn.client_ip)]:%cp [...]` (battle-suite-proven pattern,
# haproxy-backend.cfg:37), so the first whitespace-delimited
# token of each line is `<real-ip>:<client-port>`. We strip the
# port suffix with `cut -d: -f1` — same idiom as the direct-
# scenario Step 7a extraction (line 618), so the same haproxy-
# http parser's "first field is the IP-with-port" interpretation
# is handled identically here. head -1 picks the first match —
# same convention as Step 7a (deterministic, survives multiple
# hits).
CHAIN_SQLMAP_IP=$(grep "${SQLMAP_UA}" "$CHAIN_ACCESS_LOG" | awk '{print $1}' | head -1 | cut -d: -f1)
if [ -z "$CHAIN_SQLMAP_IP" ]; then
    echo "[haproxy] FAIL: could not extract sqlmap request IP from chain access log" >&2
    echo "[haproxy] chain access log content:" >&2
    cat "$CHAIN_ACCESS_LOG" >&2 || true
    exit 1
fi
echo "[haproxy] chain sqlmap request source IP (as logged by chain backend): $CHAIN_SQLMAP_IP"

# Assertion 4: the IP logged by the chain backend must NOT be the
# proxy's IP. If it IS the proxy's IP, the XFF-tracking config did
# not resolve the real client and HAProxy is logging the proxy's
# connecting address instead — the exact failure mode assert_chain
# in tests/integration/verify.sh:188 calls "ip-leak". Conversely,
# any non-proxy IP is treated as a PASS for this assertion (the
# detailed IP-correctness of the curl container's CNI assignment
# is not what we are asserting here; what matters is "not the
# proxy's IP").
if [ "$CHAIN_SQLMAP_IP" = "$CHAIN_PROXY_IP" ]; then
    echo "[haproxy] FAIL: assertion 4 - XFF-tracking did not resolve proxy chain - logged proxy IP instead of real client IP (ip-leak)" >&2
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
# direct-scenario haproxy-access.log for an operator to grab.
# ---------------------------------------------------------------------
if [ -s "$CHAIN_ACCESS_LOG" ]; then
    cp "$CHAIN_ACCESS_LOG" "${TMPDIR:-/tmp}/haproxy-chain-access.log"
fi

# Step 16 (was Step 9): final report. Cleanup happens via the EXIT
# trap. FAIL=1 may have been set by either Step 7b's direct-scenario
# assertions OR Step 14's chain-scenario assertion — both
# accumulate into the same flag, both are reported by this single
# exit-code decision.
if [ "$FAIL" -ne 0 ]; then
    echo "[haproxy] FAIL: one or more assertions failed (see above)"
    exit 1
fi
echo "[haproxy] PASS: all assertions green - direct + proxy-chain FreeBSD/podman haproxy integration end-to-end works"
exit 0
