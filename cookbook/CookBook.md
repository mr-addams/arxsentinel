# ArxSentinel Cookbook

Ready-to-use configurations for common deployment scenarios.
Copy the file that matches your setup, fill in the placeholders, and run.

## Config Structure

Every recipe follows the ArxSentinel pipeline order:

```
Sources → Processors → Sinks → Executors
```

| Section | Role | Required |
|---------|------|----------|
| `streams.inputs` | Log sources | ✅ |
| `scoring` | Threat thresholds | ✅ |
| `detectors` | 8 built-in processors | ✅ |
| `whitelist.custom` | Trusted IPs/CIDRs/UAs | ✅ |
| `chain_guard` | Proxy chain integrity | optional |
| `streams.outputs` | Threat sinks | ✅ |
| `executors` | Automated response | executor recipes only |
| [config.reference.yaml](config.reference.yaml) | Complete reference for all parameters | — |

## Table of Contents

- [Fail2Ban (file-based logging)](#fail2ban)
- [Syslog (network log transport)](#syslog)
- [HTTP source (push/pull log receiver)](#http)
- [Cloudflare Executor (automated IP banning)](#cloudflare)
- [MikroTik Executor (RouterOS address-list)](#mikrotik)
- [Nginx Executor (blocklist file + reload)](#nginx-executor)
- [Infrastructure: Server Configs](#server-configs)
- [Infrastructure: Reverse Proxy / Real-IP](#reverse-proxy)
- [Infrastructure: Kubernetes](#kubernetes)

---

## Fail2Ban

Writes threat events to a log file. Fail2Ban reads it and bans IPs via iptables/nftables.
No executor required — works out of the box with any Fail2Ban jail.

| Recipe | Description | File |
|--------|-------------|------|
| nginx basic | Single nginx site, combined log format | [fail2ban/nginx-basic.yaml](fail2ban/nginx-basic.yaml) |
| nginx multi-stream | Two nginx vhosts sharing one threat log | [fail2ban/nginx-multi-stream.yaml](fail2ban/nginx-multi-stream.yaml) |
| nginx + WordPress | WordPress-specific probe paths | [fail2ban/nginx-wordpress.yaml](fail2ban/nginx-wordpress.yaml) |
| nginx + Laravel | Laravel-specific probe paths | [fail2ban/nginx-laravel.yaml](fail2ban/nginx-laravel.yaml) |
| nginx + Drupal | Drupal-specific probe paths | [fail2ban/nginx-drupal.yaml](fail2ban/nginx-drupal.yaml) |
| Apache | Apache Combined Log Format | [fail2ban/apache.yaml](fail2ban/apache.yaml) |
| Caddy | Caddy transform-encoder log format | [fail2ban/caddy.yaml](fail2ban/caddy.yaml) |
| HAProxy | HAProxy httplog via rsyslog | [fail2ban/haproxy.yaml](fail2ban/haproxy.yaml) |
| Traefik | Traefik CLF access log | [fail2ban/traefik.yaml](fail2ban/traefik.yaml) |
| LiteSpeed | LiteSpeed / OpenLiteSpeed access log | [fail2ban/litespeed.yaml](fail2ban/litespeed.yaml) |

### Docker

Docker Compose stack for running ArxSentinel + Fail2Ban in containers.

| File | Purpose |
|------|---------|
| [fail2ban/docker/config.yaml](fail2ban/docker/config.yaml) | ArxSentinel config for Docker deployment |
| [fail2ban/docker/docker-compose.yml](fail2ban/docker/docker-compose.yml) | Compose stack: arxsentinel + fail2ban |

---

## Syslog

Receive nginx (or any web server) access logs directly over the network using the
built-in syslog source. No shared log files, no log rotation, no volume mounts.
nginx streams access log lines to ArxSentinel via UDP or TCP — ArxSentinel listens,
strips the syslog envelope, and processes the embedded access log line normally.

**Nginx configuration** (add to `nginx.conf` or a site block):
```nginx
access_log syslog:server=127.0.0.1:5514,facility=local7,tag=nginx,severity=info combined;
```

**When to use syslog instead of file:**
- Containerised deployments where shared volumes are inconvenient
- Multiple nginx workers on different hosts sending to one ArxSentinel instance
- Environments where log files are not persisted (ephemeral containers, read-only fs)
- Integration with rsyslog / syslog-ng for log aggregation pipelines
- HAProxy natively sends logs to syslog (no file or rsyslog needed at all)

| Recipe | Description | File |
|--------|-------------|------|
| nginx + Fail2Ban | UDP syslog → ArxSentinel → threats.log | [syslog/nginx-fail2ban.yaml](syslog/nginx-fail2ban.yaml) |
| nginx + Cloudflare | UDP syslog → ArxSentinel → Cloudflare automated banning | [syslog/nginx-cloudflare.yaml](syslog/nginx-cloudflare.yaml) |
| nginx multi-stream | Two vhosts on separate syslog ports | [syslog/nginx-multi-stream.yaml](syslog/nginx-multi-stream.yaml) |
| HAProxy | UDP syslog → ArxSentinel → threats.log (native HAProxy syslog client) | [syslog/haproxy.yaml](syslog/haproxy.yaml) |
| Traefik | rsyslog relay → ArxSentinel → threats.log | [syslog/traefik.yaml](syslog/traefik.yaml) |
| Caddy | UDP syslog (net logger) → ArxSentinel → threats.log | [syslog/caddy.yaml](syslog/caddy.yaml) |
| LiteSpeed | rsyslog relay → ArxSentinel → threats.log | [syslog/litespeed.yaml](syslog/litespeed.yaml) |

### Docker

Zero-volume Docker Compose: nginx sends logs to ArxSentinel container over the
internal Docker network — no shared volume mount needed.

| File | Purpose |
|------|---------|
| [syslog/docker/config.yaml](syslog/docker/config.yaml) | ArxSentinel config for syslog Docker deployment |
| [syslog/docker/docker-compose.yml](syslog/docker/docker-compose.yml) | Compose stack: nginx → syslog → arxsentinel |

---

## HTTP

HTTP/HTTPS log receiver supporting 9 push protocols and pull mode.
Use when vendors push logs directly to ArxSentinel over HTTP.

**When to use HTTP source:**
- Cloudflare Logpush, AWS Firehose, GCP Pub/Sub push
- Loki push API, OTLP HTTP logs, Azure Monitor export, Splunk HEC
- NDJSON streams with field extraction
- Polling remote endpoints (pull mode)
- Receiving logs over HTTPS with TLS

| Recipe | Description | File |
|--------|-------------|------|
| Full reference with examples | 9 protocols + pull + TLS | [http/CookBook.md](http/CookBook.md) |

---

## Cloudflare

ArxSentinel sends THREAT events to the Cloudflare API to ban IPs via firewall rules.
Requires a Cloudflare API token with Account → IP Lists → Edit permission.

| Recipe | Description | File |
|--------|-------------|------|
| nginx basic | Single nginx site + Cloudflare banning | [cloudflare/nginx-basic.yaml](cloudflare/nginx-basic.yaml) |
| nginx multi-stream | Two nginx vhosts, shared Cloudflare executor | [cloudflare/nginx-multi-stream.yaml](cloudflare/nginx-multi-stream.yaml) |
| nginx + WordPress | WordPress probe paths + Cloudflare banning | [cloudflare/nginx-wordpress.yaml](cloudflare/nginx-wordpress.yaml) |
| Traefik | Traefik access log + Cloudflare banning | [cloudflare/traefik.yaml](cloudflare/traefik.yaml) |

### Docker

| File | Purpose |
|------|---------|
| [cloudflare/docker/config.yaml](cloudflare/docker/config.yaml) | ArxSentinel config for Docker + Cloudflare |
| [cloudflare/docker/docker-compose.yml](cloudflare/docker/docker-compose.yml) | Compose stack: arxsentinel with Cloudflare executor |

---

## MikroTik

ArxSentinel sends THREAT events to the MikroTik RouterOS REST API to add IPs to an address-list.
Requires RouterOS 7.x with REST API enabled.

| Recipe | Description | File |
|--------|-------------|------|
| nginx basic | Single nginx site + MikroTik address-list | [mikrotik/nginx-basic.yaml](mikrotik/nginx-basic.yaml) |
| nginx multi-stream | Two nginx vhosts, shared MikroTik executor | [mikrotik/nginx-multi-stream.yaml](mikrotik/nginx-multi-stream.yaml) |

### Docker

| File | Purpose |
|------|---------|
| [mikrotik/docker/config.yaml](mikrotik/docker/config.yaml) | ArxSentinel config for Docker + MikroTik |
| [mikrotik/docker/docker-compose.yml](mikrotik/docker/docker-compose.yml) | Compose stack: arxsentinel with MikroTik executor |

---

## Nginx Executor

ArxSentinel writes threat IPs to an nginx-compatible blocklist file and triggers a reload.
No external dependencies — pure nginx geo + map.

| Recipe | Description | File |
|--------|-------------|------|
| nginx basic | Single nginx site + blocklist reload | [nginx-executor/nginx-basic.yaml](nginx-executor/nginx-basic.yaml) |

### Docker

| File | Purpose |
|------|---------|
| [nginx-executor/docker/config.yaml](nginx-executor/docker/config.yaml) | ArxSentinel config for Docker + nginx executor |
| [nginx-executor/docker/docker-compose.yml](nginx-executor/docker/docker-compose.yml) | Compose stack: arxsentinel with nginx blocklist reload |

---

## Server Configs

Snippets for configuring your web server to produce logs ArxSentinel can parse.

| File | Purpose |
|------|---------|
| [server-configs/nginx-json-logformat.conf](server-configs/nginx-json-logformat.conf) | JSON log format for nginx (structured parsing) |
| [server-configs/apache-httpd.conf](server-configs/apache-httpd.conf) | Combined log format for Apache httpd |
| [server-configs/Caddyfile](server-configs/Caddyfile) | transform-encoder config for Caddy access log |
| [server-configs/haproxy.cfg](server-configs/haproxy.cfg) | httplog format for HAProxy |
| [server-configs/litespeed-httpd.conf](server-configs/litespeed-httpd.conf) | Combined log format for LiteSpeed |

---

## Reverse Proxy / Real-IP

When ArxSentinel runs behind a reverse proxy, the client IP in the log may be
the proxy's IP instead of the real visitor. These configs fix that.

| Setup | Proxy config | Origin nginx config |
|-------|-------------|---------------------|
| nginx behind nginx | [reverse-proxy/nginx-rp/nginx-upstream.conf](reverse-proxy/nginx-rp/nginx-upstream.conf) | [reverse-proxy/nginx-rp/nginx-origin.conf](reverse-proxy/nginx-rp/nginx-origin.conf) |
| nginx behind Caddy | [reverse-proxy/caddy/Caddyfile](reverse-proxy/caddy/Caddyfile) | [reverse-proxy/caddy/nginx.conf](reverse-proxy/caddy/nginx.conf) |
| nginx behind HAProxy | [reverse-proxy/haproxy/haproxy.cfg](reverse-proxy/haproxy/haproxy.cfg) | [reverse-proxy/haproxy/nginx.conf](reverse-proxy/haproxy/nginx.conf) |
| nginx behind Traefik | [reverse-proxy/traefik/traefik.yml](reverse-proxy/traefik/traefik.yml) | [reverse-proxy/traefik/nginx.conf](reverse-proxy/traefik/nginx.conf) |

---

## Kubernetes

| File | Purpose |
|------|---------|
| [kubernetes/daemonset.yaml](kubernetes/daemonset.yaml) | DaemonSet: one ArxSentinel per node, tailing host logs |
| [kubernetes/sidecar.yaml](kubernetes/sidecar.yaml) | Sidecar: one ArxSentinel per pod, tailing container logs |
| [kubernetes/configmap.yaml](kubernetes/configmap.yaml) | ConfigMap with default ArxSentinel configuration |