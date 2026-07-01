#!/usr/bin/env sh
# tests/integration-freebsd/traefik/run-traefik.sh — Flow 091 integration
# smoke for the traefik backend under FreeBSD/podman.
#
# Adapted from run-caddy.sh — Flow 089/091 paid 9 iterations to make
#  this structure green; do NOT restructure without re-verifying all
#  assertions.
#
# Architecture (per Flow 089 DECISIONS §2 + §3, carried over verbatim):
# - traefik runs in a Linux-emulated docker.io/library/traefik:latest
#   container under podman (FreeBSD Linux compat — see Flow 088 DECISIONS
#   §"A.2"). traefik is a single Go-static binary; no plugin build or
#   xcaddy step is required (caddy needed transform-encoder to coerce
#   its native JSON into CLF; traefik emits CLF by default per the
#   arx-core "traefik" parser profile contract — see
#   sentinel-traefik.yaml header for the source-verified reasoning).
# - arxsentinel runs NATIVE on the VM host (NOT in a container —
#   DECISIONS §2), with its CWD = $WORK_DIR so the relative paths in
#   sentinel-traefik.yaml resolve correctly.
# - The attacker runs in a SECOND podman container (curlimages/curl) on
#   the same CNI network. Both attacker requests share the curl
#   container's CNI IP (DECISIONS §3).
#
# Per Flow 091 DECISIONS §2 (copy-then-adapt, no premature library
# extraction) the script structure is verbatim from run-caddy.sh;
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
# Why log-grep readiness check (NOT wget, like nginx; NOT just caddy
# version + log-grep):
#   nginx used `podman exec nginx nginx -t` (config-validate) +
#   `podman logs | grep "start worker processes"` (startup-sync). The
#   traefik analogue would be config-validate + startup log line, but
#   traefik:latest does NOT ship a `traefik --version`-style probe
#   via `podman exec` (the binary's main entrypoint is the daemon
#   itself; running `traefik version` via `podman exec` works but
#   adds no signal over the startup log line). Following the caddy
#   lesson (live dispatch 28550879869 — caddy:latest has no wget),
#   we AVOID `podman exec traefik wget` entirely and rely on the
#   log-grep pattern alone, which is independent of the binary's
#   presence in the image. Per the brief: "НЕ wget-based по
#   умолчанию. Используй log-grep паттерн как у nginx/caddy".
#
#   The traefik:v3 startup log emits (at INFO level) a line
#   containing "Traefik version" within the first second, followed
#   shortly by the entryPoint listener line. We grep for BOTH in
#   the readiness loop to cover two failure modes: (a) traefik
#   failed to start (no "Traefik version" line); (b) traefik started
#   but the entryPoint listener is not yet bound (caddy had a
#   similar gap in its own "server running" sync). The
#   character "msg=...entryPoint" matches the entryPoint listener
#   sync in the structured traefik log.
#
# Phase P3 step mapping (P3.2 traefik.yml + sentinel-traefik.yaml;
# P3.3 this script; P3.4 job wiring):
#   - P3.2: traefik.yml (entryPoint web:80, accessLog.filePath:
#     /logs/access.log, CLF default — no `format:` field per
#     arx-core "traefik" profile contract) + sentinel-traefik.yaml
#     (general.log_file: logs/access.log, parser.profile: traefik,
#     output.threat_log: output/threats-traefik.log).
#   - P3.3: this file's skeleton + CNI network + traefik container
#     startup (steps 0-3 below).
#   - P3.3: sentinel host-process launch + "watching started" sync
#     (steps 4-5 below).
#   - P3.3: curl attacker with sqlmap + Mozilla UAs (step 6 below).
#   - P3.3: three assertions adapted per DECISIONS §5 (step 7).
#   - P3.3: artifact persistence copy (step 8).

set -eu

# ---------------------------------------------------------------------
# Step 0: locate inputs. REPO_ROOT is the workspace root ($GITHUB_WORKSPACE
# at workflow runtime). All three inputs are committed in this directory.
#
# This script lives at tests/integration-freebsd/traefik/run-traefik.sh —
# three path segments below the repo root, so dirname($0) needs three
# "../" to reach it (NOT two, which is what 088's
# tests/integration-freebsd/run-smoke.sh used, since that script is
# only two segments deep).
# ---------------------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
TRAEFIK_DIR="$REPO_ROOT/tests/integration-freebsd/traefik"
TRAEFIK_CONF="$TRAEFIK_DIR/traefik.yml"
SENTINEL_BIN="$REPO_ROOT/arxsentinel"
SENTINEL_CFG_SRC="$TRAEFIK_DIR/sentinel-traefik.yaml"

# Sanity: all three inputs must exist. A typo or missing build would
# silently produce an empty access log and the assertions would
# falsely PASS.
if [ ! -s "$TRAEFIK_CONF" ]; then
    echo "[traefik] FAIL: traefik.yml missing or empty at $TRAEFIK_CONF" >&2
    exit 1
fi
if [ ! -x "$SENTINEL_BIN" ]; then
    echo "[traefik] FAIL: arxsentinel binary not found or not executable at $SENTINEL_BIN" >&2
    exit 1
fi
if [ ! -s "$SENTINEL_CFG_SRC" ]; then
    echo "[traefik] FAIL: sentinel-traefik.yaml missing or empty at $SENTINEL_CFG_SRC" >&2
    exit 1
fi

# ---------------------------------------------------------------------
# Step 1: create $WORK_DIR + the bind-mounted subdirs. $WORK_DIR lives
# under $TMPDIR (set by the workflow as scoped TMPDIR — P3.4 carry of
# 088 G.1) so the cleanup trap's rm -rf lands in a tmpfs / workspace
# sync area, not under /var/db or /usr/local. The relative paths in
# sentinel-traefik.yaml (logs/access.log, output/threats-traefik.log)
# resolve against $WORK_DIR when the sentinel CWDs there in step 4.
# ---------------------------------------------------------------------
WORK_DIR="${TMPDIR:-/tmp}/arx-traefik-$$"
mkdir -p "$WORK_DIR/logs" "$WORK_DIR/output"
# 0755 is enough: sentinel runs as root on the FreeBSD host (no
# nonroot hardening yet — see Flow 089 Deferred 089.9 + 088 TD-8).
chmod 0755 "$WORK_DIR/output"

# Stage inputs into $WORK_DIR so the traefik container bind-mount and
# the sentinel CWD see them in a predictable layout.
cp "$TRAEFIK_CONF" "$WORK_DIR/traefik.yml"
cp "$SENTINEL_CFG_SRC" "$WORK_DIR/sentinel-traefik.yaml"

# podman-network and container-name markers — used in cleanup() and
# step 3 (wait-for-traefik). Set as empty strings so the trap is
# idempotent on early exit (e.g. if podman network create fails).
NETWORK="arx-net"
TRAEFIK_CID=""

cleanup() {
    if [ -n "$TRAEFIK_CID" ]; then
        podman rm -f "$TRAEFIK_CID" >/dev/null 2>&1 || true
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
    # artifact path — P3.4 carry of 089 Task 3.6 / 4.3). The
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
# 10.88.0.0/16 on FreeBSD) is fine for the direct-traefik test.
# ---------------------------------------------------------------------
echo "[traefik] creating CNI network $NETWORK..."
podman network create "$NETWORK"

# ---------------------------------------------------------------------
# Step 3: start the traefik container detached. bind-mount the staged
# traefik.yml over /etc/traefik/traefik.yml (so traefik reads our
# config, not the image's default — traefik:latest's image has no
# config file by default and the daemon would exit immediately on
# start without one) and bind-mount $WORK_DIR/logs over /logs (so
# the access log lands at $WORK_DIR/logs/access.log on the host — the
# path the host-native sentinel reads in step 4). --name traefik is
# kept for operator convenience (`podman logs traefik`, `podman exec
# traefik ...` below) but is NOT used as a DNS name by the curl
# attacker — step 6 resolves the container's CNI IP via `podman
# inspect` instead, since the FreeBSD CNI bridge plugin has no
# dnsname resolver (G6; same as nginx + caddy runs).
#
# Fully-qualified docker.io/library/traefik:latest (NOT bare
# traefik:latest): the FreeBSD podman default
# /usr/local/share/containers/registries.conf has no
# unqualified-search-registries entry, so a short name fails with
# "did not resolve to an alias and no unqualified-search registries
# are defined" (G1; same class of bug as Flow 088 Decision F.4 and
# 091 P2.7 Bug 1).
#
# --os=linux is REQUIRED: traefik:latest's OCI image index has no
# "freebsd" OS variant, only linux/*. Without --os=linux, podman on
# FreeBSD defaults to looking for a freebsd-OS manifest and fails
# with "no image found in image index for architecture amd64 ...
# OS freebsd" (G2; same flag 088 podman-spike step 5 used for
# docker.io/alpine and 089 run-nginx.sh / 091 run-caddy.sh use for
# nginx/caddy).
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
# a runtime bug, not a syntax bug. Same caveat as run-caddy.sh:206
# and the caddy post-mortem in .tmp/coder-brief-091-p2-fix2.md.
# ---------------------------------------------------------------------
echo "[traefik] starting traefik container..."
TRAEFIK_CID=$(podman run -d \
    --os=linux \
    --name traefik \
    --network "$NETWORK" \
    -v "$WORK_DIR/traefik.yml:/etc/traefik/traefik.yml:ro" \
    -v "$WORK_DIR/logs:/logs" \
    docker.io/library/traefik:latest)
echo "[traefik] container $TRAEFIK_CID started"

# Wait for traefik to be ready: log-grep pattern ONLY (no wget
# following the caddy lesson — see header WHY-comment). The pattern
# combines "Traefik version" (process-startup-sync) AND
# "entryPoint" listener line (the entryPoint is bound and accepting
# traffic). Both must appear within the deadline; either alone is
# insufficient (a "Traefik version" line could appear during a
# config-parse failure, and an "entryPoint" line could be in a
# non-listening state in some edge cases).
echo "[traefik] waiting for traefik ready (timeout 30s)..."
DEADLINE=$(($(date +%s) + 30))
READY=0
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    if podman logs traefik 2>&1 | grep -q "Traefik version" \
       && podman logs traefik 2>&1 | grep -q "entryPoint"; then
        READY=1
        break
    fi
    sleep 1
done
if [ "$READY" -ne 1 ]; then
    echo "[traefik] FAIL: traefik not ready within 30s" >&2
    echo "[traefik] traefik logs (last 30 lines):" >&2
    podman logs --tail 30 traefik >&2 || true
    exit 1
fi
echo "[traefik] traefik ready"

# ---------------------------------------------------------------------
# Step 4: start the native sentinel. DECISIONS §2 — sentinel on host,
# NOT in a container. CWD = $WORK_DIR so the relative paths in
# sentinel-traefik.yaml resolve. The sentinel writes its pid to
# /tmp/arxsentinel.pid (per the yaml) and its operational log to
# sentinel-traefik.log under $WORK_DIR.
# ---------------------------------------------------------------------
echo "[traefik] starting native sentinel (CWD=$WORK_DIR)..."
cd "$WORK_DIR"
"$SENTINEL_BIN" \
    --config "$WORK_DIR/sentinel-traefik.yaml" \
    > "$WORK_DIR/sentinel-traefik.log" 2>&1 &
SENTINEL_PID=$!
echo "[traefik] sentinel started with PID $SENTINEL_PID"

# Step 5: wait for "watching started" in sentinel-traefik.log. This
# sync prevents the host append in step 6 from racing the TailReader
# open+seek(EOF) (mirrors 088 run-smoke.sh step 3). The yaml's
# logging.debug: true is REQUIRED for the "TAIL watching started"
# line to be emitted (see sentinel-traefik.yaml header).
echo "[traefik] waiting for 'watching started' (timeout 30s)..."
DEADLINE=$(($(date +%s) + 30))
WATCHING=0
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    if grep -q "watching started" "$WORK_DIR/sentinel-traefik.log" 2>/dev/null; then
        WATCHING=1
        break
    fi
    sleep 1
done
if [ "$WATCHING" -ne 1 ]; then
    echo "[traefik] FAIL: 'watching started' not seen within 30s" >&2
    echo "[traefik] sentinel log (last 50 lines):" >&2
    tail -50 "$WORK_DIR/sentinel-traefik.log" >&2 || true
    kill "$SENTINEL_PID" 2>/dev/null || true
    exit 1
fi
echo "[traefik] TailReader ready"

# ---------------------------------------------------------------------
# Step 6: drive attacks from a curl container. DECISIONS §3 said the
# curl container could resolve "traefik" via container DNS — live run
# 28476909225 (nginx) disproved that: nginx started fine and
# TailReader was watching, but access.log stayed empty and curl
# exited non-zero. The FreeBSD `containernetworking-plugins` port
# ships the basic CNI bridge plugin only, NOT a dnsname plugin (G6;
# same as nginx + caddy). Resolve the traefik container's CNI IP via
# `podman inspect` instead of relying on DNS, and use the IP directly
# in the curl URL.
# ---------------------------------------------------------------------
SQLMAP_UA='sqlmap/1.7.11'
MOZILLA_UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'

# `index` (not dot-notation) is REQUIRED: $NETWORK contains a hyphen
# ("arx-net"), and a Go template map-key access via dot-notation
# (.Networks.arx-net.IPAddress) parses the hyphen as a subtraction
# operator and fails with "bad character U+002D '-'" (G8; live run
# 28477133986 hit this exact error). `index` takes the key as a
# string argument, sidestepping Go template identifier syntax rules.
TRAEFIK_IP=$(podman inspect traefik --format "{{(index .NetworkSettings.Networks \"${NETWORK}\").IPAddress}}")
if [ -z "$TRAEFIK_IP" ]; then
    echo "[traefik] FAIL: could not resolve traefik container's CNI IP via podman inspect" >&2
    exit 1
fi
echo "[traefik] traefik container IP: $TRAEFIK_IP"

echo "[traefik] driving attacks from curl container (sqlmap + Mozilla UAs)..."
# Fully-qualified docker.io/curlimages/curl (NOT bare curlimages/curl) —
# same short-name resolution issue as the traefik image above (G1).
# --os=linux — same image-index reasoning as the traefik container
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
podman run --rm --os=linux --network "$NETWORK" \
    --entrypoint /bin/sh \
    docker.io/curlimages/curl \
    -c "curl -sS -A '${SQLMAP_UA}' http://${TRAEFIK_IP}/ ; curl -sS -A '${SQLMAP_UA}' http://${TRAEFIK_IP}/ ; curl -sS -A '${MOZILLA_UA}' http://${TRAEFIK_IP}/" \
    >/dev/null 2>&1 \
    || echo "[traefik] curl attacker exited non-zero (still check the access log)"
echo "[traefik] attacks sent"

# ---------------------------------------------------------------------
# Step 7: poll the threat log for non-empty content (~20s timeout).
# Mirrors 088 run-smoke.sh step 5.
# ---------------------------------------------------------------------
THREAT_LOG="$WORK_DIR/output/threats-traefik.log"
echo "[traefik] polling $THREAT_LOG (timeout 20s)..."
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
    echo "[traefik] FAIL: $THREAT_LOG not written within 20s" >&2
    echo "[traefik] access log content (if any):" >&2
    cat "$WORK_DIR/logs/access.log" >&2 || true
    echo "[traefik] sentinel log (last 80 lines):" >&2
    tail -80 "$WORK_DIR/sentinel-traefik.log" >&2 || true
    exit 1
fi

# Dump the threat log for inline visibility.
LINES=$(cat "$THREAT_LOG")
echo "[traefik] threat log content:"
printf '%s\n' "$LINES" | sed 's/^/  /'

# ---------------------------------------------------------------------
# Step 7a: extract the sqlmap-request source IP from the access log.
# DECISIONS §5 — the attacker's source IP is the curl container's
# CNI-assigned IP, which appears in access.log as the first field
# of the line containing the sqlmap UA. We extract that IP here
# (once) so assertions 1 and 2 below can use it.
# ---------------------------------------------------------------------
ACCESS_LOG="$WORK_DIR/logs/access.log"
if [ ! -s "$ACCESS_LOG" ]; then
    echo "[traefik] FAIL: access log empty or missing at $ACCESS_LOG" >&2
    exit 1
fi
# grep the sqlmap UA (literal, no regex specials) then awk the first
# field. Safe even if the UA contains regex chars — grep treats it
# as a fixed string in this case (no -E flag).
SQLMAP_IP=$(grep "${SQLMAP_UA}" "$ACCESS_LOG" | awk '{print $1}' | head -1)
if [ -z "$SQLMAP_IP" ]; then
    echo "[traefik] FAIL: could not extract sqlmap request IP from access log" >&2
    echo "[traefik] access log content:" >&2
    cat "$ACCESS_LOG" >&2 || true
    exit 1
fi
echo "[traefik] sqlmap request source IP: $SQLMAP_IP"

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
    echo "[traefik] FAIL: assertion 1 - expected ' THREAT ' and IP '$SQLMAP_IP' in threat log" >&2
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
    echo "[traefik] FAIL: assertion 2 - false positive: Mozilla UA appeared in threat log" >&2
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
    echo "[traefik] FAIL: assertion 3 - $BAD_COUNT threat line(s) missing score=/reason=" >&2
    FAIL=1
fi

# ---------------------------------------------------------------------
# Step 8: persist artifacts for the workflow. The cleanup trap on
# EXIT (set in step 1) does NOT remove $WORK_DIR when TMPDIR is
# $GITHUB_WORKSPACE — the workflow's actions/upload-artifact picks
# up these files BEFORE the VM is destroyed (P3.4 carry of 089 Task
# 3.6 / 4.3). The copies here land at the top of $TMPDIR (=
# $GITHUB_WORKSPACE in CI) so the workflow's `cat
# $GITHUB_WORKSPACE/...` + `upload-artifact` at P3.4 can find them
# by name.
# ---------------------------------------------------------------------
if [ -s "$THREAT_LOG" ]; then
    cp "$THREAT_LOG" "${TMPDIR:-/tmp}/threats-traefik.log.smoke"
fi
if [ -s "$ACCESS_LOG" ]; then
    cp "$ACCESS_LOG" "${TMPDIR:-/tmp}/traefik-access.log"
fi

# Step 9: final report. Cleanup happens via the EXIT trap.
if [ "$FAIL" -ne 0 ]; then
    echo "[traefik] FAIL: one or more assertions failed (see above)"
    exit 1
fi
echo "[traefik] PASS: all 3 assertions green - FreeBSD/podman traefik integration end-to-end works"
exit 0
