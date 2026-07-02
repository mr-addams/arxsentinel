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
#   - P2.3: curl attacker with sqlmap + Mozilla UAs (step 6 below).
#   - P2.3: three assertions adapted per DECISIONS §5 (step 7).
#   - P2.3: artifact persistence copy (step 8).

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

cleanup() {
    if [ -n "$CADDY_CID" ]; then
        podman rm -f "$CADDY_CID" >/dev/null 2>&1 || true
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

echo "[caddy] driving attacks from curl container (sqlmap + Mozilla UAs)..."
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
    -c "curl -sS -A '${SQLMAP_UA}' http://${CADDY_IP}/ ; curl -sS -A '${SQLMAP_UA}' http://${CADDY_IP}/ ; curl -sS -A '${MOZILLA_UA}' http://${CADDY_IP}/" \
    >/dev/null 2>&1 \
    || echo "[caddy] curl attacker exited non-zero (still check the access log)"
echo "[caddy] attacks sent"

# ---------------------------------------------------------------------
# Step 7: poll the threat log for non-empty content (~20s timeout).
# Mirrors 088 run-smoke.sh step 5.
# ---------------------------------------------------------------------
THREAT_LOG="$WORK_DIR/output/threats-caddy.log"
echo "[caddy] polling $THREAT_LOG (timeout 20s)..."
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
    echo "[caddy] FAIL: $THREAT_LOG not written within 20s" >&2
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
    echo "[caddy] FAIL: assertion 1 - expected ' THREAT ' and IP '$SQLMAP_IP' in threat log" >&2
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
echo "[caddy] PASS: all 3 assertions green - FreeBSD/podman caddy integration end-to-end works"
exit 0
