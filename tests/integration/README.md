# Integration Tests — arxsentinel

## High-Level Overview

### Purpose

The integration test suite validates that arxsentinel correctly detects threats across
multiple backends, proxy chains, and Cloudflare scenarios. It runs end-to-end using
Docker containers, attacking each server with crafted HTTP requests and verifying that
sentinel's threat log records the correct attacker IP (not proxy IP).

### Infrastructure

```
Docker network: integration_default (172.16.0.0/12)
External network: integration_cf_ext_net (10.88.0.0/24) — attacker IP isolated from trusted proxies

Containers:
  Attackers: curlimages/curl (Alpine-based, one container per scenario)
  Backends:  nginx, apache, traefik, caddy, haproxy, litespeed
  Proxies:   traefik:80, caddy:80, haproxy:80, nginx-rp:80
  Simulators: cloudflare-sim, bogon-injector
```

### Matrix — 109 Checks

| Category | Formula | Count | Invariant Verified |
|---|---|---|---|
| DIRECT | 6 servers × 7 detectors | 42 | Each detector fires on every server |
| BADBOT | 5 servers (no litespeed) | 5 | UA blocklist fires on UA-logging servers |
| BLOCKLIST | 6 servers (automaton loaded) | 6 | Manager builds automaton from blocklist source |
| PROXY-CHAIN | 4 proxies × 6 backends | 24 | Threat log shows attacker IP, NOT proxy IP |
| CF-DIRECT | 6 backends | 6 | Threat log shows real IP, NOT CF-sim IP |
| CF-CHAIN | 4 proxies × 6 backends | 24 | Real IP survives two-hop CF→proxy→backend |
| CHAIN-GUARD | 2 warnings | 2 | cf-broken and bogon-victim write warnings |
| **TOTAL** | | **109** | |

Litespeed is excluded from BADBOT because OLS does not log User-Agent in standard CLF format.

---

## Deep Dive

### 1. Direct Tests (Scenario 1–8)

Each scenario spawns one attacker container on `integration_default`. All 6 backends are hit
sequentially via `attack_all` helper.

#### 1.1 probe — Sensitive Path Detection

**What is sent (per server, 7 curl commands):**
```
curl http://<srv>/wp-login.php
curl http://<srv>/.env
curl http://<srv>/.git/config
curl http://<srv>/admin/config.php
curl http://<srv>/etc/passwd
curl http://<srv>/.aws/credentials
curl http://<srv>/xmlrpc.php
```

**Expected in threat log:** THREAT entry with `class=probe` for each server.

**Why `-sf`:** Silently fails (no output) on 404/403 so the attacker container does not
pollute stdout. `|| true` ensures the script continues even if all curls fail.

---

#### 1.2 ua — Scanner User-Agent Detection

**What is sent (per server, 5 curl commands):**
```
curl -A "sqlmap/1.7.11"  http://<srv>/
curl -A "sqlmap/1.7.11"  http://<srv>/
curl -A "Nuclei/3.0"     http://<srv>/
curl -A "masscan/1.3"   http://<srv>/
curl -A "zgrab/0.x"      http://<srv>/
```

**Expected:** THREAT with `class=ua`, subtype referencing the matched UA string.

---

#### 1.3 bruteforce — 404 Ratio > 60%

**Pattern per server (15 requests):**
```
3 × GET / (200 OK)
12 × GET /missing-page-N (404)
```

After 10+ requests with >60% 404, `bruteforce` detector fires. 12/15 = 80% ratio.

**Expected:** THREAT with `class=bruteforce`. Threshold: `min_requests=10`.

---

#### 1.4 crawler — Sequential Numeric URLs

**Pattern per server (6 requests):**
```
GET /items/1
GET /items/2
GET /items/3
GET /items/4
GET /items/5
GET /items/6
```

Threshold: `min_sequential=5`. Five consecutive numeric URLs under the same path prefix
trigger detection.

**Expected:** THREAT with `class=crawler`.

---

#### 1.5 noasset — Page Requests Without Assets

**Pattern per server (8 requests):**
```
8 × GET / (or /info.php) — HTML page requests only, zero CSS/JS
```

`assetRatio = 0% < 10%` threshold. Fires after `min_page_requests=3`.

**Expected:** THREAT with `class=noasset`.

---

#### 1.6 rate — High Request Rate

**Pattern per server (60 requests):**
```
30 × GET / (burst 1)
sleep 1
30 × GET / (burst 2)
```

ApproxRate ≈ 30 req/s >> threshold (100/60 ≈ 1.67 req/s).

**Expected:** THREAT with `class=rate`.

---

#### 1.7 overflow — URL Path > 2048 Bytes

**What is sent (per server, 1 request):**
```bash
LONG_PATH="/$(head -c 20000 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 2200)"
curl "http://<srv>${LONG_PATH}"
```

Path length > 2048 bytes triggers `overflow` detector.

**Expected:** THREAT with `class=overflow`.

---

#### 1.8 badbot — Community Blocklist UA

**Pattern per server (2 requests):**
```
UA read from blocklist/test-ua.txt (fetched from blocklist-server:8090)
2 × curl -A "<badbot-ua>/1.0" http://<srv>/
```

**Expected:** THREAT with `class=badbot` on nginx, apache, traefik, caddy, haproxy.
**Excluded:** litespeed — OLS does not log User-Agent.

---

### 2. Infrastructure Tests

#### 2.1 Proxy-Chain Tests (Scenario 9)

**Topology:**
```
attacker (integration_default)
    ↓
traefik:80 / caddy:80 / haproxy:80 / nginx-rp:80
    ↓
nginx / apache / traefik / caddy / haproxy / litespeed
```

**What is sent (per proxy × backend, 5 curl commands):**
```
curl http://<proxy>:80/backend-<backend>/wp-login.php
curl http://<proxy>:80/backend-<backend>/.env
curl http://<proxy>:80/backend-<backend>/.git/config
curl http://<proxy>:80/backend-<backend>/admin/login.php
curl http://<proxy>:80/backend-<backend>/xmlrpc.php
```

**Invariant:** Threat log must show attacker IP (from `X-Forwarded-For`), NOT proxy container IP.
If proxy IP appears on a THREAT line → class=ip-leak → FAIL.

**24 combinations:** 4 proxies × 6 backends.

```
+---------+--------+--------+--------+--------+--------+--------+
| Proxy   | →nginx | →apa   | →trf   | →cad   | →hap   | →lite  |
+---------+--------+--------+--------+--------+--------+--------+
| traefik |   ✓    |   ✓    |   ✓    |   ✓    |   ✓    |   ✓    |
| caddy   |   ✓    |   ✓    |   ✓    |   ✓    |   ✓    |   ✓    |
| haproxy |   ✓    |   ✓    |   ✓    |   ✓    |   ✓    |   ✓    |
| nginx-rp|   ✓    |   ✓    |   ✓    |   ✓    |   ✓    |   ✓    |
+---------+--------+--------+--------+--------+--------+--------+
```

---

#### 2.2 Cloudflare Cases

All CF scenarios use `integration_cf_ext_net` (10.88.0.0/24) — attacker IP is outside trusted
proxy CIDR (172.16.0.0/12). This forces backends to extract real IP from `CF-Connecting-IP` /
`X-Forwarded-For`, preventing `real_ip_recursive` from consuming all trusted IPs and
falling back to cloudflare-sim container IP.

---

**Case 1 — CF-Direct: cloudflare-sim → product (Scenario 10)**

**Topology:**
```
attacker (10.88.0.x) → cloudflare-sim → nginx/apache/traefik/caddy/haproxy/litespeed
```

cloudflare-sim rewrites `X-Forwarded-For` to `$remote_addr` and adds `CF-Connecting-IP` header.
Each backend must extract real IP from these headers.

**5 paths per backend:** `/wp-login.php`, `/.env`, `/.git/config`, `/admin/login.php`, `/xmlrpc.php`

**Invariant:** Threat log shows attacker IP, NOT cloudflare-sim container IP.
If CF-sim IP appears → class=cf-ip-leak → FAIL.

**6 checks** (one per backend).

---

**Case 2 — CF-Chain: cloudflare-sim → our proxy → product (Scenario 11)**

**Topology:**
```
attacker (10.88.0.x) → cloudflare-sim → traefik/caddy/haproxy/nginx-rp → backend
```

Two-hop chain: CF headers set by cloudflare-sim, then proxy forwards to backend.
Real IP must survive both hops.

**3 paths per (proxy, backend) pair:** `/wp-login.php`, `/.env`, `/xmlrpc.php`

**Invariant:** Same as Case 1 — threat log shows attacker IP, not CF-sim IP.

**72 checks** (4 proxies × 6 backends × 3 paths).

---

**Case 3A — CF-Broken: cloudflare-sim → nginx-bare (Scenario 12A)**

nginx-bare has NO `real_ip_header` configured. It logs the TCP peer (cloudflare-sim container IP)
as client IP.

**2 requests:** `curl /wp-login.php` and `curl /.env` via cloudflare-sim:80/cf-bare/

**Chain-Guard response:** sentinel must detect cloudflare-sim container IP as within Cloudflare
IP range and write `cloudflare-ip-as-client` to `warnings/cf-broken.log`.

---

**Case 3B — Bogon Injection (Scenario 12B)**

bogon-injector adds `X-Forwarded-For: 10.0.0.1` before forwarding to nginx-bogon-victim.

nginx-bogon-victim trusts XFF from Docker subnet, logs 10.0.0.1 as client.

**Chain-Guard response:** sentinel must detect 10.0.0.1 as RFC 1918 bogon and write
`bogon-ip-as-client` to `warnings/bogon-victim.log`.

---

### 3. Safety Guards — Chain Guard

Chain Guard is a sentinel component that monitors backend logs for IPs that should never
appear as client IPs:

| Warning Type | Condition | Log File |
|---|---|---|
| `cloudflare-ip-as-client` | Backend logs a Cloudflare range IP as client | `warnings/cf-broken.log` |
| `bogon-ip-as-client` | Backend logs an RFC 1918 private IP as client | `warnings/bogon-victim.log` |

**Trigger conditions:**
- cf-broken: nginx-bare (no `real_ip_header`) logs CF-sim container IP → chain_guard detects
  CF IP range → writes warning
- bogon-victim: nginx-bogon-victim trusts XFF, logs 10.0.0.1 → chain_guard detects RFC 1918 →
  writes warning

**Verification:** `verify.sh` checks that each warning file contains the expected string.
Absence = FAIL.

---

## Developer's Guide

### Adding a New Backend Server

1. **Add server to arrays in `scenarios.sh` and `verify.sh`:**
   ```bash
   # scenarios.sh
   SERVERS=(nginx apache traefik caddy haproxy litespeed <NEW_SERVER>)
   
   # verify.sh
   SERVERS=(nginx apache traefik caddy haproxy litespeed <NEW_SERVER>)
   ```

2. **Create sentinel config:** `arxsentinel/<NEW_SERVER>.yaml`
   - Configure `real_ip_header` and `trusted_proxies` if the server sits behind a proxy
   - Set appropriate `log_format` / `log_path` for access log parsing

3. **Add to docker-compose.yml:** define `<NEW_SERVER>` container with the image and networks

4. **Update BADBOT_SERVERS** in `verify.sh` if the new server logs User-Agent:
   ```bash
   BADBOT_SERVERS=(nginx apache traefik caddy haproxy litespeed <UA_LOGGING_SERVER>)
   ```
   If it does NOT log UA (like litespeed), do NOT add it.

5. **Add to proxy-chain** if the new server will be a backend behind proxies:
   - No code changes needed — `CHAIN_BACKENDS` iterates over all servers
   - Ensure the proxy routes `/backend-<server>/` to the correct container

6. **Add to CF scenarios** if the server should be tested in CF-direct and CF-chain:
   - No code changes needed — `CHAIN_BACKENDS` covers all servers

7. **Run verification:**
   ```bash
   cd tests/integration
   docker compose up -d --build
   bash scenarios.sh
   bash verify.sh
   ```

---

### Adding a New Detector

1. **Add scenario to `scenarios.sh`:**
   ```bash
   run_scenario "<detector_name>" "$(attack_all '
   <curl commands using __SRV__ placeholder>
   ')"
   ```

2. **Add to MODULES array in `verify.sh`:**
   ```bash
   MODULES=(probe ua bruteforce crawler noasset rate overflow <NEW_DETECTOR>)
   ```

3. **Configure the detector** in each `arxsentinel/<SERVER>.yaml`:
   - Set appropriate thresholds (`min_requests`, `threshold`, etc.)
   - Ensure log format includes fields the detector needs

4. **Update expected count in documentation** (this README and matrix)

---

### Adding a New Proxy

1. **Add to `CHAIN_PROXIES` in `scenarios.sh`:**
   ```bash
   CHAIN_PROXIES=(
       "traefik:80"
       "caddy:80"
       "haproxy:80"
       "nginx-rp:80"
       "<NEW_PROXY>:80"
   )
   ```

2. **Add to `CF_CHAIN_PROXIES`** for CF Case 2:
   ```bash
   CF_CHAIN_PROXIES=(traefik caddy haproxy nginx-rp <NEW_PROXY>)
   ```

3. **Add proxy configuration** in `configs/` (e.g., `nginx-rp.conf` for nginx reverse proxy)

4. **Add to docker-compose.yml:** define `<NEW_PROXY>` container with networks

5. **Ensure routes** are configured so `/backend-<SERVER>/` proxies to the correct
   backend container

---

### Key Arrays Reference

```bash
# scenarios.sh
SERVERS=(nginx apache traefik caddy haproxy litespeed)   # backends
CHAIN_PROXIES=(traefik:80 caddy:80 haproxy:80 nginx-rp:80)
CHAIN_BACKENDS=(nginx apache traefik caddy haproxy litespeed)

# verify.sh
SERVERS=(nginx apache traefik caddy haproxy litespeed)   # backends
MODULES=(probe ua bruteforce crawler noasset rate overflow)  # core 7
BADBOT_SERVERS=(nginx apache traefik caddy haproxy litespeed)  # 5 (no litespeed)
```

---

### Network Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│ integration_default (172.16.0.0/12)                                  │
│                                                                      │
│   attacker-probe  ──→  nginx  apache  traefik  caddy  haproxy  lite│
│   attacker-ua          (all direct tests)                            │
│   attacker-bruteforce                                                │
│   attacker-crawler                                                    │
│   attacker-noasset                                                    │
│   attacker-rate                                                       │
│   attacker-overflow                                                  │
│   attacker-badbot                                                     │
│   attacker-bogon-injection ──→ bogon-injector ──→ nginx-bogon-victim│
│                                                                      │
│   traefik:80 ──┬──→ nginx  apache  traefik  caddy  haproxy  lite   │
│   caddy:80     │    (proxy-chain tests)                             │
│   haproxy:80   │                                                     │
│   nginx-rp:80  │                                                     │
│                │                                                     │
└────────────────┼────────────────────────────────────────────────────┘
                 │
┌────────────────┴──────────────────────────────────────────────────┐
│ integration_cf_ext_net (10.88.0.0/24)                              │
│   attacker-cf-direct ──→ cloudflare-sim ──→ nginx  apache  ...    │
│   attacker-cf-chain  ──→ cloudflare-sim ──→ traefik ──→ nginx     │
│   attacker-cf-broken ──→ cloudflare-sim ──→ nginx-bare           │
└────────────────────────────────────────────────────────────────────┘
```

**Why two networks?**
- Attacker on `integration_default` (172.16.x.x) shares the proxy CIDR range
- If attacker were on same network as proxies, `real_ip_recursive` would exhaust trusted IPs
  and fall back to cloudflare-sim container IP
- By placing attacker on `10.88.0.0/24` (outside 172.16.0.0/12), attacker IP is always treated
  as untrusted, forcing proper header extraction
