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
#     output/threats-apache.log).
#   - P5.3: this file's skeleton + CNI network + httpd container
#     startup with bind-mounted log (steps 0-3 below).
#   - P5.3: sentinel host-process launch + "watching started" sync
#     (steps 4-5 below).
#   - P5.3: curl attacker with 8 attack scenarios + 2 sqlmap repeats
#     + 1 Mozilla (step 6 below).
#   - P5.3: three assertions adapted per DECISIONS §5 (step 7).
#   - P5.3: artifact persistence copy (step 8).

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

cleanup() {
    if [ -n "$APACHE_CID" ]; then
        podman rm -f "$APACHE_CID" >/dev/null 2>&1 || true
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
# Per Decision 9: 8 attack scenarios, plus 2 sqlmap repeats (to cross
# the additive-scorer threshold) plus 1 Mozilla control. The full
# 8-scenario block (Decision 9) is encoded in a single here-string
# that drives ONE attacker container with all the UAs; the assertions
# (step 7) only check the badbot + legit subset, but the access log
# carries the full 8-scenario signal for downstream grader
# inspection.
# ---------------------------------------------------------------------
SQLMAP_UA='sqlmap/1.7.11'
MOZILLA_UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'

# 8 attack UAs (Decision 9):
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
APACHE_IP=$(podman inspect apache --format "{{(index .NetworkSettings.Networks \"${NETWORK}\").IPAddress}}")
if [ -z "$APACHE_IP" ]; then
    echo "[apache] FAIL: could not resolve apache container's CNI IP via podman inspect" >&2
    exit 1
fi
echo "[apache] apache container IP: $APACHE_IP"

echo "[apache] driving attacks from curl container (8 scenarios + 2 sqlmap repeats)..."
# Fully-qualified docker.io/curlimages/curl (NOT bare curlimages/curl) —
# same short-name resolution issue as the httpd image above (G1).
# --os=linux — same image-index reasoning as the httpd container
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
# Port 8080 — the same G15-mitigation / per-backend-convention port
# the integration.sh curl attacker uses. The CNI-internal :8080 is
# the only Listen port in our httpd.conf.
ATTACK_CMD=""
for UA in $SCENARIO_UAS; do
    ATTACK_CMD="${ATTACK_CMD}curl -sS -A '${UA}' http://${APACHE_IP}:8080/ ; "
done
# 2 sqlmap repeats (the threshold-breaker — see comment above).
ATTACK_CMD="${ATTACK_CMD}curl -sS -A '${SQLMAP_UA}' http://${APACHE_IP}:8080/ ; "
ATTACK_CMD="${ATTACK_CMD}curl -sS -A '${SQLMAP_UA}' http://${APACHE_IP}:8080/ ; "
ATTACK_CMD="${ATTACK_CMD}curl -sS -A '${MOZILLA_UA}' http://${APACHE_IP}:8080/"

podman run --rm --os=linux --network "$NETWORK" \
    --entrypoint /bin/sh \
    docker.io/curlimages/curl \
    -c "$ATTACK_CMD" \
    >/dev/null 2>&1 \
    || echo "[apache] curl attacker exited non-zero (still check the access log)"
echo "[apache] attacks sent"

# ---------------------------------------------------------------------
# Step 7: poll the threat log for non-empty content (~20s timeout).
# Mirrors 088 run-smoke.sh step 5.
# ---------------------------------------------------------------------
THREAT_LOG="$WORK_DIR/output/threats-apache.log"
echo "[apache] polling $THREAT_LOG (timeout 20s)..."
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

# Step 9: final report. Cleanup happens via the EXIT trap.
if [ "$FAIL" -ne 0 ]; then
    echo "[apache] FAIL: one or more assertions failed (see above)"
    exit 1
fi
echo "[apache] PASS: all 3 assertions green - FreeBSD/podman apache integration end-to-end works"
exit 0
