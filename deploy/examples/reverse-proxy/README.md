# Deployment behind a reverse proxy

> **Warning:** if your HTTP server sits behind a proxy and the real client IP is not configured correctly,
> ArxSentinel will score the **proxy's IP address** instead of the real attacker.
> Fail2Ban will then ban your own proxy — taking the site down for everyone.

## How it works

```
[Client 1.2.3.4] → [Proxy] → X-Forwarded-For: 1.2.3.4 → [HTTP server]
                                                                 ↓
                              ngx_http_realip_module replaces $remote_addr
                              with the first non-trusted IP in the XFF chain
                                                                 ↓
                                                           access.log
                                                                 ↓
                                                          ArxSentinel
```

nginx's `ngx_http_realip_module` reads `X-Forwarded-For` from a trusted proxy and
replaces `$remote_addr` with the real client IP before the log line is written.
ArxSentinel reads `$remote_addr` from the access log — no extra variable needed.

## Ready-made configs

Full working examples for each proxy are in this directory:

| Proxy | Files |
|-------|-------|
| **HAProxy** | [`haproxy/haproxy.cfg`](haproxy/haproxy.cfg), [`nginx.conf`](haproxy/nginx.conf) |
| **Traefik** | [`traefik/traefik.yml`](traefik/traefik.yml), [`nginx.conf`](traefik/nginx.conf) |
| **Caddy** | [`caddy/Caddyfile`](caddy/Caddyfile), [`nginx.conf`](caddy/nginx.conf) |
| **nginx as RP** | [`nginx-rp/nginx-upstream.conf`](nginx-rp/nginx-upstream.conf), [`nginx-origin.conf`](nginx-rp/nginx-origin.conf) |

Each example includes both the proxy config and the origin nginx config with
`set_real_ip_from`, `real_ip_header X-Forwarded-For`, `real_ip_recursive on`,
and the `combined_realip` log format using `$remote_addr` as the real-IP field.

## Minimum nginx config (any proxy)

```nginx
http {
    # Replace with your actual proxy IP or CIDR.
    # Docker Compose: 172.16.0.0/12    Same host: 127.0.0.1
    set_real_ip_from  <proxy-ip-or-cidr>;

    # All major proxies (HAProxy, Traefik, Caddy, nginx) set X-Forwarded-For.
    real_ip_header    X-Forwarded-For;

    # Walk the XFF chain — picks the first non-trusted IP as the real client.
    real_ip_recursive on;

    # After realip processing, $remote_addr IS the real client IP.
    log_format combined_realip
        '$remote_addr - $remote_user [$time_local] '
        '"$request" $status $body_bytes_sent '
        '"$http_referer" "$http_user_agent" "$remote_addr"';

    server {
        access_log /var/log/nginx/access.log combined_realip;
        ...
    }
}
```

## Cloudflare

If nginx sits directly behind Cloudflare, use `CF-Connecting-IP` instead of `X-Real-IP`
(Cloudflare sets it from their edge; `X-Forwarded-For` can be spoofed by clients).

Generate `set_real_ip_from` lines for all Cloudflare CIDR ranges:

```bash
sudo scripts/update-cloudflare-ips.sh /etc/nginx/cloudflare-real-ip.conf
```

Add to `nginx.conf`:

```nginx
http {
    include /etc/nginx/cloudflare-real-ip.conf;  # set_real_ip_from for all CF ranges
    real_ip_header CF-Connecting-IP;
    ...
}
```

**Auto-update IP ranges** (Cloudflare updates them periodically):

```bash
# Add to cron — every Monday at 03:00
0 3 * * 1 /path/to/update-cloudflare-ips.sh /etc/nginx/cloudflare-real-ip.conf && nginx -t && nginx -s reload
```

## Chain Guard — detecting broken IP extraction

ArxSentinel continuously checks whether the client IP in each log entry is a real,
routable address. If it detects a Cloudflare/CDN edge IP or a bogon/CGNAT address
appearing as the client IP, it writes a `CHAIN_WARN` to `warnings.log`.

**Why this matters:** when a proxy IP appears as the client, all of ArxSentinel's
detectors score the wrong address — they are effectively blind. Fail2Ban may ban your
own Cloudflare edge instead of the attacker, taking the site offline for all visitors.
This is a misconfiguration, not an attack.

**What triggers a warning:**

| Condition | Warning | Fix |
|-----------|---------|-----|
| Cloudflare IP as client | `cloudflare-ip-as-client` | Configure `real_ip_header CF-Connecting-IP` (nginx), `RemoteIPHeader CF-Connecting-IP` (Apache), `trustedProxies` (Traefik/Caddy) |
| Bogon / RFC 1918 as client | `bogon-ip-as-client` | An upstream proxy is injecting private IPs into XFF; verify the proxy chain and add its IP to `set_real_ip_from` |
| CGNAT (100.64.0.0/10) as client | `bogon-ip-as-client` | Carrier-grade NAT upstream — configure `real_ip_header` to extract the real IP from XFF |

**Configuration:**

```yaml
chain_guard:
  enabled: true
  warnings_log: /var/log/arxsentinel/warnings.log
  cloudflare:
    enabled: true
    refresh_interval: 24h     # re-fetches Cloudflare CIDR lists automatically
    sources:
      - https://www.cloudflare.com/ips-v4/
      - https://www.cloudflare.com/ips-v6/
  bogon:
    enabled: true             # RFC 1918, CGNAT, loopback, link-local, documentation ranges
```

**Monitoring the warnings log:**

```bash
# Check for any chain guard warnings
grep CHAIN_WARN /var/log/arxsentinel/warnings.log

# Count by type
grep -c cloudflare-ip-as-client /var/log/arxsentinel/warnings.log
grep -c bogon-ip-as-client /var/log/arxsentinel/warnings.log
```
