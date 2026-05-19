# ArxSentinel Integration Tests

End-to-end test suite that runs real web server containers, fires attack scenarios,
and verifies that arxsentinel's detectors and threat logs produce the expected output.

**55 checks in total:** 35 direct (5 servers × 7 detectors) + 20 proxy-chain (4 proxies × 5 backends).

---

## Quick start

```bash
# From the repository root — builds the binary and runs all 55 checks.
bash tests/integration/run.sh

# Skip rebuild if the binary is already up to date.
bash tests/integration/run.sh --skip-build
```

Expected output:

```
Results: 55 passed, 0 failed
(5 servers × 7 detectors = 35 direct checks)
(4 proxies × 5 backends = 20 proxy-chain checks)
(total: 55 checks)
```

### Requirements

- Docker with Compose v2 (`docker compose`)
- Go toolchain (only needed without `--skip-build`)
- ~2 GB free disk space (images are cached after the first run)

---

## What is tested

### Direct checks (35)

Each of the 5 web servers is attacked independently by 7 distinct scenarios.
arxsentinel monitors the server's access log and must detect the threat within the
session window. One check = one `(server, detector)` pair in the threat log.

| Server | Profile | Access log |
|--------|---------|------------|
| nginx | `combined` | `logs/nginx/access.log` |
| apache | `apache` | `logs/apache/access.log` |
| traefik | `traefik` | `logs/traefik/access.log` |
| caddy | `caddy` | `logs/caddy/access.log` |
| haproxy | `haproxy-http` | `logs/haproxy/access.log` |

| Detector | What triggers it | Scenario |
|----------|-----------------|----------|
| `probe` | Request to `/.env`, `/wp-login.php`, `/.git/config`, … | 7 sensitive-path requests |
| `ua` | Scanner User-Agent (`sqlmap`, `Nuclei`, `masscan`, …) | 5 requests with scanner UAs |
| `bruteforce` | 404 ratio > 60% after ≥ 10 requests | 15 requests, 12 to missing pages (80% 404) |
| `crawler` | ≥ 5 sequential numeric paths under one prefix | `/items/1` … `/items/6` |
| `noasset` | Page requests with zero asset (CSS/JS) requests | 8 HTML requests, 0 assets |
| `rate` | > 100 req/60 s from one IP | 30 + 30 requests with 1 s gap (≈ 60 req/s) |
| `overflow` | URL length > 2048 bytes | Single request with a 2200-char path |

### Proxy-chain checks (20)

Each proxy-chain check fires probe requests through one of 4 proxy layers to one
of 5 backend configurations. arxsentinel monitors the **backend's** access log.

**Invariant checked:** the threat log must contain a `THREAT` entry AND the proxy
container's IP must NOT appear in any threat line. If the backend logged the proxy
address instead of the attacker, the check fails with "proxy IP leaked".

| Proxy ↓ \ Backend → | nginx | apache | traefik | caddy | haproxy |
|---|---|---|---|---|---|
| traefik | ✅ | ✅ | ✅ | ✅ | ✅ |
| caddy | ✅ | ✅ | ✅ | ✅ | ✅ |
| haproxy | ✅ | ✅ | ✅ | ✅ | ✅ |
| nginx-rp | ✅ | ✅ | ✅ | ✅ | ✅ |

---

## Infrastructure

### Docker Compose services

```
┌─────────────────────────────────────────────────────────────────┐
│  Attacker containers (one per scenario, ephemeral)              │
│  Each gets a unique Docker IP → no cross-contamination          │
└───────────────────────┬─────────────────────────────────────────┘
                        │ HTTP
         ┌──────────────┼──────────────────────┐
         ▼              ▼                      ▼
  ┌─────────────┐  ┌───────────────────────────────────────────┐
  │Direct tests │  │         Proxy-chain tests                 │
  │             │  │                                           │
  │ nginx  :8081│  │  traefik  :8083 ─────────────────────────┤
  │ apache :8082│  │  caddy    :8084 ─────────────────────────┤
  │ traefik:8083│  │  haproxy  :8085 ─────────────────────────┤
  │ caddy  :8084│  │  nginx-rp :8086 ─────────────────────────┤
  │ haproxy:8085│  │                                           │
  └─────────────┘  │  Routes: /backend-<name>/ → backend      │
                   │                                           │
                   └──┬──────┬────────┬───────┬───────────────┘
                      │      │        │       │
                      ▼      ▼        ▼       ▼
              nginx:8080  apache  traefik  caddy  haproxy
              (proxy-    -proxy   -backend -backend -backend
               backend)
```

**Direct backends** (ports 8081–8085): serve static HTML + PHP, return real 200/404
responses so detectors see authentic HTTP status codes.

**Proxy layers** (ports 8083–8086): route path prefix `/backend-<name>/` to the
corresponding trusted backend after stripping the prefix. All four set
`X-Forwarded-For` with the client's real IP before forwarding.

**Proxy-chain backends** (no host ports — internal only):

| Service | Real IP mechanism | Log location |
|---------|------------------|--------------|
| nginx (`:8080`) | `ngx_http_realip_module` + `real_ip_header X-Forwarded-For` | `logs/nginx/access-proxy.log` |
| apache-proxy | `mod_remoteip` + `RemoteIPInternalProxy 172.16.0.0/12` | `logs/apache-proxy/access.log` |
| traefik-backend | `entryPoints.web.forwardedHeaders.trustedIPs` | `logs/traefik-proxy/access-proxy.log` |
| caddy-backend | Logs `{http.request.header.X-Forwarded-For}` directly as client IP via transform-encoder | `logs/caddy-proxy/access-proxy.log` |
| haproxy-backend | Custom `log-format` with `%[var(txn.client_ip)]` (txn var set from XFF at request time) | `logs/haproxy-proxy/access.log` |

### arxsentinel instances

`run.sh` starts 10 sentinel processes — one per monitored log file:

```
arxsentinel/nginx.yaml           → logs/nginx/access.log
arxsentinel/apache.yaml          → logs/apache/access.log
arxsentinel/traefik.yaml         → logs/traefik/access.log
arxsentinel/caddy.yaml           → logs/caddy/access.log
arxsentinel/haproxy.yaml         → logs/haproxy/access.log

arxsentinel/nginx-proxy.yaml     → logs/nginx/access-proxy.log
arxsentinel/apache-proxy.yaml    → logs/apache-proxy/access.log
arxsentinel/traefik-proxy.yaml   → logs/traefik-proxy/access-proxy.log
arxsentinel/caddy-proxy.yaml     → logs/caddy-proxy/access-proxy.log
arxsentinel/haproxy-proxy.yaml   → logs/haproxy-proxy/access.log
```

Each proxy-chain sentinel writes its threat log to `logs/threats/<backend>-proxy.log`.

---

## Test isolation model

Each call to `run_scenario NAME SCRIPT` spins up a **fresh Docker container** on the
integration network. Every container gets a unique IP address from the Docker IPAM pool
— that IP becomes the attacker's address in the access log.

```
run_scenario "probe"     → attacker IP: 172.18.0.N
run_scenario "ua"        → attacker IP: 172.18.0.M   (different container, different IP)
run_scenario "bruteforce"→ attacker IP: 172.18.0.K
...
```

Because arxsentinel's threat detector accumulates state **per IP**, fresh containers
guarantee that the `probe` scenario's IP never collides with the `bruteforce` scenario's
IP — each detector is triggered in clean isolation.

For proxy-chain scenarios the container is the **attacker** and the Docker network
assigns it a different IP from the proxy containers. `verify.sh` resolves the proxy
container's IP via `docker inspect` and asserts it never appears in the threat log.

---

## Proxy-chain mechanics

### The invariant

> The backend logs the **real client IP** (the attacker container's IP), not the
> intermediate proxy's IP.

This is validated by `assert_chain` in `verify.sh`:

```
1. grep for "THREAT" in logs/threats/<backend>-proxy.log  →  threat must exist
2. inspect proxy container IP via docker inspect
3. grep for that IP in any THREAT line                    →  must NOT appear
```

### How each backend extracts the real IP

All four proxy layers set `X-Forwarded-For: <attacker-ip>` before forwarding.
Each backend type uses its native mechanism to trust and log that header.

#### nginx (`ngx_http_realip_module`)

```nginx
set_real_ip_from  172.16.0.0/12;   # trust Docker proxy subnet
real_ip_header    X-Forwarded-For;
real_ip_recursive on;              # walk chain, pick first non-trusted IP
```

After processing, `$remote_addr` **is** the real client IP. The access log uses
`$remote_addr` directly — no auxiliary variable needed.

> **Why not `$realip_remote_addr`?** That variable holds the original TCP peer (the
> proxy IP). ArxSentinel reads the last field of the access log line as the client IP;
> `$remote_addr` (replaced by realip) is the correct choice.

#### Apache (`mod_remoteip`)

```apache
RemoteIPHeader         X-Forwarded-For
RemoteIPInternalProxy  172.16.0.0/12
```

`%h` in the log format resolves to the forwarded IP after `mod_remoteip` processing.

> **Why `RemoteIPInternalProxy` and not `RemoteIPTrustedProxy`?** In Docker Compose
> networks the proxy sits on the same private subnet as the backend. `InternalProxy`
> fully trusts the XFF chain from that CIDR; `TrustedProxy` adds an extra hop that
> can cause the proxy's IP to appear in `%h` in some configurations.

#### Traefik (`forwardedHeaders.trustedIPs`)

Static config (traefik.yml):

```yaml
entryPoints:
  web:
    forwardedHeaders:
      trustedIPs:
        - "172.16.0.0/12"
```

Traefik rewrites `X-Forwarded-For` in the CLF access log with the real client IP
when the incoming request comes from a trusted CIDR.

> **Traefik v3 note:** `serversTransport.forwardedHeaders` does not exist. The correct
> path is `entryPoints.<name>.forwardedHeaders.trustedIPs`.

#### Caddy (transform-encoder, log XFF directly)

Caddy does not provide a native mechanism to replace the logged client IP from
`X-Forwarded-For` without being the terminating edge (i.e., without `trusted_proxies`
applying to its own access log). The backend Caddyfile instead logs the XFF header
value directly as the client IP field in the CLF output via `transform-encoder`:

```caddyfile
log {
    format transform `{http.request.header.X-Forwarded-For} - {user_id} [{ts}] ...`
}
```

ArxSentinel's `caddy` profile regex matches `{http.request.header.X-Forwarded-For}`
in the `remote_addr` position.

#### HAProxy (custom `log-format` with `txn` variable)

```haproxy
http-request set-var(txn.client_ip) req.fhdr(X-Forwarded-For)
log-format "%[var(txn.client_ip)]:%cp [%tr] ..."
```

`req.fhdr(X-Forwarded-For)` is captured into a transaction variable at HTTP request
time and written in the log-format `%ci` position (client IP).

> **Why the `txn` variable pattern?** In HAProxy 3.x, using `req.fhdr(...)` directly
> in `log-format` causes `ALERT: sample fetch 'req.fhdr' may not be reliably used
> here because it needs 'HTTP request headers' which is not available at logging time`.
> A `txn` variable is always available at log time.

---

## CI integration

`.github/workflows/integration.yml` runs the full suite on every PR targeting `dev`
and on every push to `dev`. Both `dev-release.yml` and `release.yml` declare `needs:
integration`, so a release cannot be published if any check fails.

The CI workflow:
1. Builds the binary (`go build`)
2. Starts all containers (`docker compose up`)
3. Runs `scenarios.sh` (attack traffic)
4. Runs `verify.sh` (assert 55/55 PASS)

---

## Directory layout

```
tests/integration/
├── run.sh                  # Orchestrator: build → containers → scenarios → verify
├── scenarios.sh            # Attack traffic generator (one container per scenario)
├── verify.sh               # Assertions: 35 direct + 20 proxy-chain checks
├── docker-compose.yml      # 10 server/proxy containers + php-fpm
│
├── configs/                # Server configuration files
│   ├── nginx.conf          # Direct backend (port 80) + proxy-trusted backend (port 8080)
│   ├── httpd.conf          # Apache direct backend
│   ├── httpd-proxy.conf    # Apache with mod_remoteip (proxy-chain backend)
│   ├── traefik.yml         # Traefik as proxy layer (path-based routing to 5 backends)
│   ├── traefik-routes.yml  # Traefik dynamic routes
│   ├── traefik-backend.yml # Traefik as trusted backend (forwardedHeaders.trustedIPs)
│   ├── traefik-backend-routes.yml
│   ├── Caddyfile           # Caddy as proxy layer (handle_path to 5 backends)
│   ├── Caddyfile-backend   # Caddy as trusted backend (logs XFF as client IP)
│   ├── haproxy.cfg         # HAProxy as proxy layer (ACL path routing + forwardfor)
│   ├── haproxy-backend.cfg # HAProxy as trusted backend (txn var log-format)
│   └── nginx-rp.conf       # nginx as reverse proxy layer (4th proxy type)
│
├── arxsentinel/            # Sentinel config per monitored log
│   ├── nginx.yaml          # Direct: logs/nginx/access.log
│   ├── apache.yaml
│   ├── traefik.yaml
│   ├── caddy.yaml
│   ├── haproxy.yaml
│   ├── nginx-proxy.yaml    # Proxy-chain: logs/nginx/access-proxy.log
│   ├── apache-proxy.yaml
│   ├── traefik-proxy.yaml
│   ├── caddy-proxy.yaml
│   └── haproxy-proxy.yaml
│
├── dockerfiles/
│   └── Caddy.Dockerfile    # Caddy + transform-encoder plugin
│
├── logs/                   # Runtime — gitignored
│   ├── nginx/, apache/, traefik/, caddy/, haproxy/
│   ├── apache-proxy/, traefik-proxy/, caddy-proxy/, haproxy-proxy/
│   └── threats/            # Sentinel threat output (one file per instance)
│
└── webapp/                 # Static site served by all backends
    ├── index.html
    ├── style.css
    ├── app.js
    ├── info.php
    └── api/data.json
```

---

## Adding new tests

### New detector check (direct)

1. Add a `run_scenario "name" "..."` block to `scenarios.sh` with traffic that
   triggers the new detector against all 5 servers via `attack_all`.
2. Add the detector name to `MODULES` in `verify.sh`.
3. Run `bash tests/integration/run.sh --skip-build` and confirm the new count.

### New server profile (direct)

1. Add the server container to `docker-compose.yml` with a mounted log volume.
2. Write a server config under `configs/` and an arxsentinel config under `arxsentinel/`.
3. Start the sentinel instance in `run.sh` (mirror the existing loop).
4. Add the server name to `SERVERS` in both `scenarios.sh` and `verify.sh`.

### New proxy-chain combination

1. Add the proxy layer or backend service to `docker-compose.yml`.
2. Configure path routing (`/backend-<name>/`) in the proxy config.
3. For a new backend: add an arxsentinel config under `arxsentinel/` and start the
   instance in `run.sh`.
4. Add the combination to `CHAIN_PROXIES` or `CHAIN_BACKENDS` in `scenarios.sh`
   and `verify.sh`.
