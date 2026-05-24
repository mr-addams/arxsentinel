# Cloudflare Real-IP Configuration Guide

When your origin server sits behind Cloudflare, all incoming connections come from
Cloudflare edge IPs, not from actual visitors. Without proper configuration:

- **Access logs** show Cloudflare IPs instead of real visitor IPs
- **Rate limiting** and **geo-blocking** break — they see one IP (Cloudflare's)
- **Security tools** cannot attribute attacks to the real source

Cloudflare sends the real client IP in the `CF-Connecting-IP` request header.
This guide explains how to extract that IP on each supported web server.

---

## Table of Contents

1. [Understanding Cloudflare Headers](#1-understanding-cloudflare-headers)
2. [Cloudflare IP Ranges — Keep Them Current](#2-cloudflare-ip-ranges--keep-them-current)
3. [Nginx](#3-nginx)
4. [Apache HTTP Server](#4-apache-http-server)
5. [Traefik](#5-traefik)
6. [Caddy](#6-caddy)
7. [HAProxy](#7-haproxy)
8. [LiteSpeed / OpenLiteSpeed](#8-litespeed--openlitespeed)
9. [Multi-Proxy Chains (CF → Your Proxy → Backend)](#9-multi-proxy-chains-cf--your-proxy--backend)
10. [Verifying Your Configuration](#10-verifying-your-configuration)
11. [Security Considerations](#11-security-considerations)

---

## 1. Understanding Cloudflare Headers

Cloudflare sends two key headers to the origin:

| Header | Format | Reliability |
|---|---|---|
| `CF-Connecting-IP` | Single IP address (e.g. `203.0.113.1`) | ✅ **Use this.** Always set by Cloudflare. Cannot be spoofed from outside Cloudflare's network. |
| `X-Forwarded-For` | Comma-separated chain (e.g. `203.0.113.1, 198.51.100.10`) | ⚠️ Can contain multiple IPs if client already had an XFF header. Cloudflare appends its own IP. First value may be spoofed. |
| `True-Client-IP` | Single IP address | Enterprise plan only. Same value as `CF-Connecting-IP`. |

**Recommendation:** Configure your server to read `CF-Connecting-IP` and **only trust it
when the connection arrives from a known Cloudflare IP range.** This prevents header spoofing.

---

## 2. Cloudflare IP Ranges — Keep Them Current

Cloudflare publishes its egress IP ranges at:

- IPv4: https://www.cloudflare.com/ips-v4
- IPv6: https://www.cloudflare.com/ips-v6

As of **May 2026**, the ranges are:

```
# IPv4
173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
104.16.0.0/13
104.24.0.0/14
172.64.0.0/13
131.0.72.0/22

# IPv6
2400:cb00::/32
2606:4700::/32
2803:f800::/32
2405:b500::/32
2405:8100::/32
2a06:98c0::/29
2c0f:f248::/32
```

> ⚠️ **Cloudflare adds new ranges occasionally.** Do NOT hardcode these in production
> without an update mechanism. See automation scripts below.

---

## 3. Nginx

Nginx uses the `ngx_http_realip_module` to replace `$remote_addr` with the value
from a trusted header.

### Step 1 — Create a Cloudflare IP config file

```nginx
# /etc/nginx/conf.d/cloudflare.conf

# === IPv4 ===
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 103.21.244.0/22;
set_real_ip_from 103.22.200.0/22;
set_real_ip_from 103.31.4.0/22;
set_real_ip_from 141.101.64.0/18;
set_real_ip_from 108.162.192.0/18;
set_real_ip_from 190.93.240.0/20;
set_real_ip_from 188.114.96.0/20;
set_real_ip_from 197.234.240.0/22;
set_real_ip_from 198.41.128.0/17;
set_real_ip_from 162.158.0.0/15;
set_real_ip_from 104.16.0.0/13;
set_real_ip_from 104.24.0.0/14;
set_real_ip_from 172.64.0.0/13;
set_real_ip_from 131.0.72.0/22;

# === IPv6 ===
set_real_ip_from 2400:cb00::/32;
set_real_ip_from 2606:4700::/32;
set_real_ip_from 2803:f800::/32;
set_real_ip_from 2405:b500::/32;
set_real_ip_from 2405:8100::/32;
set_real_ip_from 2a06:98c0::/29;
set_real_ip_from 2c0f:f248::/32;

# Use CF-Connecting-IP to restore the real client IP.
# X-Forwarded-For is an alternative but less reliable (spoofable first hop).
real_ip_header CF-Connecting-IP;

# real_ip_recursive: when the client IP passes through multiple proxies,
# consume all trusted IPs from XFF chain ($realip_remote_addr is the last
# untrusted IP). Required if you have an internal proxy between CF and nginx.
real_ip_recursive on;
```

### Step 2 — Include the config

Add to your server or http block:

```nginx
server {
    include /etc/nginx/conf.d/cloudflare.conf;
    # ...
}
```

### Step 3 — Verify

After reloading (`nginx -t && systemctl reload nginx`), check access logs:

```bash
# Before: 173.245.48.1 - - [24/May/2026:12:00:00 +0000] ...
# After:  203.0.113.1 - - [24/May/2026:12:00:00 +0000] ...
tail /var/log/nginx/access.log
```

### Automation Script

Run this via cron (weekly or monthly) to keep ranges current:

```bash
#!/bin/bash
# /etc/cron.weekly/update-cloudflare-nginx
set -euo pipefail
CONF=/etc/nginx/conf.d/cloudflare.conf

{
    echo "# Auto-generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# Source: https://www.cloudflare.com/ips"
    echo ""
    curl -s https://www.cloudflare.com/ips-v4 | while read ip; do
        echo "set_real_ip_from $ip;"
    done
    curl -s https://www.cloudflare.com/ips-v6 | while read ip; do
        echo "set_real_ip_from $ip;"
    done
    echo ""
    echo "real_ip_header CF-Connecting-IP;"
    echo "real_ip_recursive on;"
} > "$CONF.tmp"

mv "$CONF.tmp" "$CONF"
nginx -t && systemctl reload nginx
```

---

## 4. Apache HTTP Server

Apache uses `mod_remoteip` to replace `%h` (client IP in logs) with the value
from a trusted header.

### Step 1 — Enable mod_remoteip

```bash
sudo a2enmod remoteip    # Debian/Ubuntu
# or ensure the module is loaded:
# LoadModule remoteip_module modules/mod_remoteip.so
```

### Step 2 — Create remoteip config

```apache
# /etc/apache2/conf-available/remoteip.conf (Debian/Ubuntu)
# /etc/httpd/conf.d/remoteip.conf          (RHEL/CentOS)

RemoteIPHeader CF-Connecting-IP

# Cloudflare IPv4
RemoteIPTrustedProxy 173.245.48.0/20
RemoteIPTrustedProxy 103.21.244.0/22
RemoteIPTrustedProxy 103.22.200.0/22
RemoteIPTrustedProxy 103.31.4.0/22
RemoteIPTrustedProxy 141.101.64.0/18
RemoteIPTrustedProxy 108.162.192.0/18
RemoteIPTrustedProxy 190.93.240.0/20
RemoteIPTrustedProxy 188.114.96.0/20
RemoteIPTrustedProxy 197.234.240.0/22
RemoteIPTrustedProxy 198.41.128.0/17
RemoteIPTrustedProxy 162.158.0.0/15
RemoteIPTrustedProxy 104.16.0.0/13
RemoteIPTrustedProxy 104.24.0.0/14
RemoteIPTrustedProxy 172.64.0.0/13
RemoteIPTrustedProxy 131.0.72.0/22

# Cloudflare IPv6
RemoteIPTrustedProxy 2400:cb00::/32
RemoteIPTrustedProxy 2606:4700::/32
RemoteIPTrustedProxy 2803:f800::/32
RemoteIPTrustedProxy 2405:b500::/32
RemoteIPTrustedProxy 2405:8100::/32
RemoteIPTrustedProxy 2a06:98c0::/29
RemoteIPTrustedProxy 2c0f:f248::/32

# If you have internal proxies between CF and Apache, add them too:
# RemoteIPTrustedProxy 10.0.0.0/8
# RemoteIPTrustedProxy 172.16.0.0/12
```

You can also use `RemoteIPTrustedProxyList` with a separate file:

```apache
RemoteIPHeader CF-Connecting-IP
RemoteIPTrustedProxyList conf/trusted-proxies.lst
```

Where `conf/trusted-proxies.lst` contains one CIDR per line.

### Step 3 — Enable the config

```bash
sudo a2enconf remoteip    # Debian/Ubuntu
sudo systemctl reload apache2
```

### Step 4 — Update LogFormat (optional)

With `mod_remoteip`, `%h` in `LogFormat` is automatically replaced by the real
client IP. No format change is needed unless you also want to see the original
Cloudflare IP:

```apache
# %a is the real client IP (same as %h after mod_remoteip processing)
# %{CF-Connecting-IP}i logs the raw header value
LogFormat "%a %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
```

### Automation Script

```bash
#!/bin/bash
# /etc/cron.weekly/update-cloudflare-apache
set -euo pipefail
CONF=/etc/apache2/conf-available/remoteip.conf

{
    echo "# Auto-generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "RemoteIPHeader CF-Connecting-IP"
    echo ""
    echo "# Cloudflare IPv4"
    curl -s https://www.cloudflare.com/ips-v4 | sed 's/^/RemoteIPTrustedProxy /'
    echo ""
    echo "# Cloudflare IPv6"
    curl -s https://www.cloudflare.com/ips-v6 | sed 's/^/RemoteIPTrustedProxy /'
} > "$CONF.tmp"

mv "$CONF.tmp" "$CONF"
apache2ctl configtest && systemctl reload apache2
```

---

## 5. Traefik

Traefik uses `forwardedHeaders.trustedIPs` on entrypoints to trust incoming
`X-Forwarded-For` / `X-Real-IP` headers.

### Static Configuration

```yaml
# traefik.yml
entryPoints:
  web:
    address: ":80"
    forwardedHeaders:
      trustedIPs:
        # Cloudflare IPv4
        - "173.245.48.0/20"
        - "103.21.244.0/22"
        - "103.22.200.0/22"
        - "103.31.4.0/22"
        - "141.101.64.0/18"
        - "108.162.192.0/18"
        - "190.93.240.0/20"
        - "188.114.96.0/20"
        - "197.234.240.0/22"
        - "198.41.128.0/17"
        - "162.158.0.0/15"
        - "104.16.0.0/13"
        - "104.24.0.0/14"
        - "172.64.0.0/13"
        - "131.0.72.0/22"
        # Cloudflare IPv6
        - "2400:cb00::/32"
        - "2606:4700::/32"
        - "2803:f800::/32"
        - "2405:b500::/32"
        - "2405:8100::/32"
        - "2a06:98c0::/29"
        - "2c0f:f248::/32"
```

**How it works:** When the TCP peer is within `trustedIPs`, Traefik:
- Uses the leftmost IP from `X-Forwarded-For` as the client IP in access logs
- Passes that client IP to downstream services

> ⚠️ **Nuance:** Traefik reads `X-Forwarded-For` rather than `CF-Connecting-IP`.
> Cloudflare sets `X-Forwarded-For` to the same value as `CF-Connecting-IP` (single IP),
> so this works correctly. If you need `CF-Connecting-IP` awareness, use the
> [Traefik Cloudflare Plugin](https://github.com/danielbjornadal/traefik-cloudflare-plugin).

### CLI Equivalent

```bash
--entrypoints.web.forwardedHeaders.trustedIPs=173.245.48.0/20,103.21.244.0/22,...
```

### Automation

Use the `traefik-cloudflare-plugin` or a cron script that generates the YAML and
triggers a reload.

---

## 6. Caddy

Caddy has built-in Cloudflare support via the `trusted_proxies` directive with
the `cdn_ranges` module, which automatically fetches and maintains the IP ranges.

### Global Configuration (Caddyfile)

```
{
    servers {
        trusted_proxies {
            source cdn_ranges {
                interval 24h
                provider cloudflare
            }
        }
        trusted_proxies_strict
        client_ip_headers CF-Connecting-IP X-Forwarded-For
    }
}

:80 {
    reverse_proxy localhost:8080

    log {
        output file /var/log/caddy/access.log
    }
}
```

**Explanation:**
- `trusted_proxies { source cdn_ranges { ... } }` — auto-fetches Cloudflare IP
  ranges and refreshes them every 24 hours.
- `trusted_proxies_strict` — parses IP headers right-to-left (secure for proxies
  that append; Cloudflare appends to XFF).
- `client_ip_headers CF-Connecting-IP X-Forwarded-For` — prefers `CF-Connecting-IP`
  with fallback to `X-Forwarded-For`.

### Static Range Configuration (alternative)

If you prefer explicit ranges:

```
{
    servers {
        trusted_proxies static 173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22 2400:cb00::/32 2606:4700::/32 2803:f800::/32 2405:b500::/32 2405:8100::/32 2a06:98c0::/29 2c0f:f248::/32
        trusted_proxies_strict
        client_ip_headers CF-Connecting-IP X-Forwarded-For
    }
}
```

### Manual Range Configuration (Caddy JSON)

```json
{
  "apps": {
    "http": {
      "servers": {
        "srv0": {
          "trusted_proxies": {
            "ranges": [
              "173.245.48.0/20",
              "103.21.244.0/22",
              ...
            ],
            "strict": true
          },
          "client_ip_headers": ["CF-Connecting-IP", "X-Forwarded-For"]
        }
      }
    }
  }
}
```

### Verify

```bash
curl -H "CF-Connecting-IP: 203.0.113.1" http://localhost/
# Check logs → should show 203.0.113.1
```

---

## 7. HAProxy

HAProxy requires explicit ACLs to check the source IP against Cloudflare ranges,
then use `http-request set-src` to replace the client IP with `CF-Connecting-IP`.

### Step 1 — Create Cloudflare IP list

```bash
curl -s https://www.cloudflare.com/ips-v4 > /etc/haproxy/cf-ips.lst
curl -s https://www.cloudflare.com/ips-v6 >> /etc/haproxy/cf-ips.lst
```

### Step 2 — Configure frontend

```haproxy
# /etc/haproxy/haproxy.cfg

global
    # ...

defaults
    mode http
    log global
    option httplog
    timeout connect 5s
    timeout client  30s
    timeout server  30s

frontend http-in
    bind *:80

    # ACL: connection arrived from a Cloudflare IP
    acl from_cf src -f /etc/haproxy/cf-ips.lst
    acl cf_header_present req.hdr(CF-Connecting-IP) -m found

    # Replace src IP with the real client IP from CF-Connecting-IP
    # Only when the connection is from Cloudflare AND the header exists.
    http-request set-src req.hdr(CF-Connecting-IP) if from_cf cf_header_present

    # Forward the real IP in headers to backends
    http-request set-header X-Forwarded-For %[src] if from_cf
    http-request set-header X-Real-IP     %[src] if from_cf

    # Log format: %ci is now the real client IP
    log-format "%ci:%cp [%tr] %ft %b/%s %TR/%Tw/%Tc/%Tr/%Ta %ST %B %CC %CS %tsc %ac/%fc/%bc/%sc/%rc %sq/%bq %{+Q}r"

    default_backend web_servers

backend web_servers
    server app1 10.0.0.10:80 check
```

### Preserving the Original src (for firewall rules)

If you need the original Cloudflare source IP later:

```haproxy
frontend http-in
    bind *:80

    acl from_cf src -f /etc/haproxy/cf-ips.lst

    http-request set-var(txn.real_ip)  req.hdr(CF-Connecting-IP) if from_cf
    http-request set-var(txn.real_ip)  src                       if !from_cf

    # Save original src, replace with real IP
    http-request set-var(txn.original_src) src
    http-request set-src var(txn.real_ip) if from_cf

    # ... processing ...

    # Restore original src for logging or after processing
    # http-request set-src var(txn.original_src)
```

### Step 3 — Reload

```bash
haproxy -f /etc/haproxy/haproxy.cfg -c    # check config
systemctl reload haproxy
```

### Automation

```bash
#!/bin/bash
curl -s https://www.cloudflare.com/ips-v4 > /etc/haproxy/cf-ips.lst
curl -s https://www.cloudflare.com/ips-v6 >> /etc/haproxy/cf-ips.lst
```

---

## 8. LiteSpeed / OpenLiteSpeed

LiteSpeed can extract the real client IP using the `useIpInHeader` setting or by
overriding the log format to read `X-Forwarded-For`.

### Method A — useIpInHeader (recommended)

In the LiteSpeed admin panel or `httpd_config.conf`:

```xml
<virtualHost>
  <accessControl>
    useIpInHeader     1
    ipHeaderName      X-Forwarded-For
  </accessControl>
</virtualHost>
```

When behind Cloudflare, `X-Forwarded-For` is set to the same value as
`CF-Connecting-IP`. This causes LiteSpeed to extract the first IP from XFF
as the client IP.

### Method B — Custom Log Format

If `useIpInHeader` is unreliable (as seen in some Docker images), override the
access log format to use `X-Forwarded-For` in the client IP field:

```bash
# Patch the vhost template to replace %vh (virtual host) client IP field
# with %{X-Forwarded-For}i
```

Example Dockerfile patch (used in the ArxSentinel test suite):

```python
# patch-ols-logformat.py
import re

conf_path = "/usr/local/lsws/conf/httpd_config.conf"
with open(conf_path, "r") as f:
    content = f.read()

# Replace the first %vh (client IP field in log) with X-Forwarded-For
content = re.sub(
    r'logFormat\s+"[^"]*"',
    lambda m: m.group(0).replace(
        "httpd-access.log",
        'httpd-access.log" "\%{X-Forwarded-For}i \%l \%u \%t \\"\%r\\" %>s \%b \\"\%{Referer}i\\" \\"\%{User-Agent}i\\""',
        1
    ),
    content
)

with open(conf_path, "w") as f:
    f.write(content)
```

> **Note:** This example keeps the standard CLF structure so the parser can still
> extract fields. Adjust for your specific log format.

### Cloudflare Range Whitelist

LiteSpeed supports CIDR-based access control natively. Add Cloudflare ranges to
your firewall or LiteSpeed access control:

```xml
<accessControl>
  allow 173.245.48.0/20
  allow 103.21.244.0/22
  # ... all Cloudflare ranges from Section 2
  deny  all
</accessControl>
```

---

## 9. Multi-Proxy Chains (CF → Your Proxy → Backend)

If your architecture has **Cloudflare → Your Proxy → Backend**, each hop must
preserve the original client IP:

```
Visitor (203.0.113.1)
    │
    ▼
Cloudflare Edge
    ├─ Adds CF-Connecting-IP: 203.0.113.1
    ├─ Sets X-Forwarded-For: 203.0.113.1
    │
    ▼
Your Internal Proxy (e.g. nginx-rp, haproxy, traefik)
    ├─ Must forward CF-Connecting-IP as-is OR
    │  extract it and place it into X-Forwarded-For
    ├─ Must NOT replace XFF with its own IP for the first position
    │
    ▼
Backend Server
    ├─ Must trust "your proxy" IP ranges
    ├─ Must read the correct header (CF-Connecting-IP or X-Forwarded-For)
    └─ Must log the real client IP, not the proxy IP
```

### Proxy Rules per Server

| Role | What to configure |
|---|---|
| **Cloudflare edge** | (Automatic) Sets `CF-Connecting-IP` and `X-Forwarded-For` |
| **Nginx reverse proxy** | `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` (appends to existing XFF chain) |
| **Apache reverse proxy** | `mod_proxy` + `ProxyPreserveHost On` — XFF is appended automatically |
| **Traefik front proxy** | `forwardedHeaders.trustedIPs` with Cloudflare ranges; passes XFF through |
| **Caddy reverse proxy** | `reverse_proxy` with `trusted_proxies` — preserves incoming headers |
| **HAProxy front proxy** | `option forwardfor` — appends client IP to XFF; `http-request set-src` with CF-Connecting-IP |

### Backend Configurations for Chain

Each backend must trust the **internal proxy's IP range** (e.g. `172.16.0.0/12`
for Docker, or your VPC subnet) and read the correct header.

**Nginx backend:**
```nginx
set_real_ip_from 172.16.0.0/12;    # trust your internal proxy network
real_ip_header X-Forwarded-For;
real_ip_recursive on;               # consume all trusted proxy IPs from chain
```

**Apache backend:**
```apache
RemoteIPHeader X-Forwarded-For
RemoteIPInternalProxy 172.16.0.0/12
```

**Traefik backend:**
```yaml
entryPoints:
  web:
    forwardedHeaders:
      trustedIPs:
        - "172.16.0.0/12"
```

**HAProxy backend (extracting from XFF):**
```haproxy
http-request set-var(txn.client_ip) req.hdr_ip(X-Forwarded-For,1)
log-format "%[var(txn.client_ip)]:%cp ..."
```

### Invariant Rule

> If the real client IP appears in the access log on a THREAT line → PASS.
> If any proxy IP (Cloudflare, internal proxy) appears instead → FAIL (IP leak).

This is exactly what the ArxSentinel integration test suite validates.

---

## 10. Verifying Your Configuration

### Quick test (any server)

```bash
curl -H "CF-Connecting-IP: 203.0.113.1" http://your-server/
# Check access log — should show 203.0.113.1, not Cloudflare's IP
```

### Using the ArxSentinel Integration Tests

The integration test suite at `tests/integration/` verifies real-IP extraction
across all 6 products in both single-proxy and two-hop chain scenarios:

```bash
cd tests/integration
docker compose up -d --build
bash scenarios.sh
bash verify.sh
```

The test matrix covers:
- **Direct tests** (42 checks) — Each of 7 detectors fires correctly on each server
- **BADBOT** (6 checks) — UA blocklist detection on every server
- **BLOCKLIST** (6 checks) — Manager loaded patterns from blocklist source
- **Proxy-chain tests** (24 checks) — Real IP survives single proxy hop
- **CF-direct** (6 checks) — Real IP from `CF-Connecting-IP` on each server
- **CF-chain** (24 checks) — Real IP survives two-hop CF→proxy→backend
- **Chain guard** (2 checks) — Misconfigurations are detected

---

## 11. Security Considerations

### Always Validate the Source

Never trust `CF-Connecting-IP` (or any forwarded-header IP) unless you have
verified the connection came from an IP within Cloudflare's published ranges.
An attacker outside Cloudflare can set `CF-Connecting-IP` to any value.

### Block Direct Origin Access

Prevent attackers from bypassing Cloudflare and hitting your origin directly:

**Nginx:**
```nginx
server {
    listen 80;
    server_name origin.example.com;
    
    # Only allow Cloudflare IPs
    include /etc/nginx/conf.d/cloudflare.conf;
    
    location / {
        # Deny all non-Cloudflare traffic (after real_ip check)
        deny all;
    }
}
```

**Apache:**
```apache
<Location />
    Require ip 173.245.48.0/20
    # ... all Cloudflare ranges
</Location>
```

**Firewall (iptables/nftables):**
```bash
# If only Cloudflare should access ports 80/443
curl -s https://www.cloudflare.com/ips-v4 | xargs -I{} sudo nft add rule inet filter input ip saddr {} tcp dport {80,443} accept
sudo nft add rule inet filter input tcp dport {80,443} drop
```

### Do NOT Use mod_cloudflare

Cloudflare has deprecated `mod_cloudflare` for Apache. Use `mod_remoteip` instead —
it is actively maintained and gives you control over trusted proxy ranges.

### Keep Ranges Updated

Cloudflare adds new IP ranges periodically. Set up a cron job (weekly or monthly)
to refresh your configuration from `https://www.cloudflare.com/ips-v4` and
`https://www.cloudflare.com/ips-v6`.

### Use X-Forwarded-For Only When Necessary

`CF-Connecting-IP` is the preferred header because:
- It contains exactly one IP address (no parsing ambiguity)
- It cannot be spoofed from outside Cloudflare's network
- It is set by Cloudflare's edge, not by the client

Only fall back to `X-Forwarded-For` when you have a multi-proxy chain and need
to see the full hop chain.

---

## References

- [Cloudflare: Restoring Original Visitor IPs](https://developers.cloudflare.com/support/troubleshooting/restoring-visitor-ips/restoring-original-visitor-ips/)
- [Cloudflare IP Ranges](https://www.cloudflare.com/ips/)
- [Nginx ngx_http_realip_module docs](https://nginx.org/en/docs/http/ngx_http_realip_module.html)
- [Apache mod_remoteip docs](https://httpd.apache.org/docs/2.4/mod/mod_remoteip.html)
- [Traefik forwardedHeaders docs](https://doc.traefik.io/traefik/routing/entrypoints/#forwarded-headers)
- [Caddy trusted_proxies docs](https://caddyserver.com/docs/caddyfile/options#trusted-proxies)
- [Caddy cdn_ranges module](https://caddyserver.com/docs/json/apps/dns01proxy/trusted_proxies/cdn_ranges)
- [HAProxy set-src docs](https://docs.haproxy.org/current/configuration.html#4.0-http-request%20set-src)
- [LiteSpeed useIpInHeader docs](https://docs.litespeedtech.com/lsws/config/)
