# ArxSentinel

[![Release](https://img.shields.io/github/v/release/mr-addams/arxsentinel?include_prereleases&label=release)](https://github.com/mr-addams/arxsentinel/releases)
[![Build](https://github.com/mr-addams/arxsentinel/actions/workflows/release.yml/badge.svg)](https://github.com/mr-addams/arxsentinel/actions/workflows/release.yml)
[![License](https://img.shields.io/badge/license-GPL--3.0-blue)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go)](go.mod)
[![Platforms](https://img.shields.io/badge/linux-amd64%20%7C%20arm64-lightgrey?logo=linux)](https://github.com/mr-addams/arxsentinel/releases)
[![Packages](https://img.shields.io/badge/packages-deb%20%7C%20rpm%20%7C%20pacman-blue)](https://github.com/mr-addams/arxsentinel/releases)

A vigilant sentinel for your web server — reads HTTP access logs in real time, scores every IP through 7 behavioural detectors, and bans attackers via Fail2Ban. Works with nginx, Apache, Caddy, Traefik, HAProxy.

Supports **nginx, Apache, Caddy, Traefik, and HAProxy** via built-in profiles. nginx works out of the box with no profile needed. Caddy and HAProxy require minimal one-time setup. Custom log formats supported via regex. Watch multiple log files in a single process.

```
access.log → TailReader → whitelist → tracker → scorer → threats.log → Fail2Ban → iptables
```

## Supported HTTP servers

### Compatibility table

| Server | Profile | Setup required |
|--------|---------|----------------|
| nginx | *(default — no profile needed)* | None — nginx combined log format works out of the box |
| Apache | `apache` | None — default CLF format |
| Traefik | `traefik` | None — default access log (CLF) |
| Caddy | `caddy` | [xcaddy](https://github.com/caddyserver/xcaddy) + [transform-encoder](https://github.com/caddyserver/transform-encoder) plugin |
| HAProxy | `haproxy-http` | `option httplog` in haproxy.cfg + rsyslog to write to file |

> **nginx:** no `profile:` setting is needed. The default CombinedParser handles nginx combined log format out of the box. Set only `general.log_file` pointing to your access log.

Built-in profiles — no regex or field mapping required. Set `parser.profile` to the server name for Apache, Traefik, Caddy, or HAProxy:

**Example — Apache:**

```yaml
parser:
  profile: "apache"

general:
  log_file: /var/log/apache2/access.log

output:
  threat_log: /var/log/arxsentinel/threats.log
```

Ready-made configs for each server are in [`deploy/examples/`](deploy/examples/):

```
deploy/examples/
├── apache/      httpd.conf + sentinel-config.yaml
├── caddy/       Caddyfile + sentinel-config.yaml
├── traefik/     traefik.yml + sentinel-config.yaml
└── haproxy/     haproxy.cfg + sentinel-config.yaml
```

> **Note — HAProxy timestamps:** HAProxy includes milliseconds in the timestamp
> (`14:30:00.123`), which does not match the expected time format. Sentinel falls
> back to `time.Time{}` for that field. Rate-window detection uses wall-clock time
> regardless, so all detectors work correctly.

> **Note — Caddy:** Caddy v2's built-in JSON encoder outputs nested objects. The
> `caddy` profile requires the
> [caddy-transform-encoder](https://github.com/caddyserver/transform-encoder) plugin
> to produce CLF output. See `deploy/examples/caddy/Caddyfile` for the setup.

## Features

- **7 detectors:** probe scanning, rate anomaly, suspicious User-Agent, bruteforce (404 ratio), sequential crawler, no-asset bot, URL overflow / WAF bypass
- **Bot DNS verification:** Googlebot, Bingbot, Yandex, DuckDuckGo and others are verified via rDNS/fDNS — legitimate crawlers are never banned
- **Multi-stream:** watch multiple log files in one process — full pipeline isolation per stream
- **Whitelist:** IPs, CIDRs, UA substrings — configurable exclusion lists
- **Linear score decay:** points decay over `observation_window`, no false bans from old traffic
- **Prometheus metrics:** `/metrics` on configurable port (default `:9117`), optional bcrypt basic auth; Grafana dashboard included
- **Health endpoint:** `/health` always returns `200 {"status":"ok"}` — no credentials required; ready for Docker `HEALTHCHECK`, k8s probes, and load balancers
- **JSON log format:** switch to JSON log parsing via `parser.log_format: "json"` — no recompilation needed
- **SIGHUP reload:** config, scorer, parser and whitelist are rebuilt without restarting the daemon
- **Graceful shutdown:** line buffer is drained on SIGTERM
- **Systemd + logrotate + Fail2Ban:** ready-to-use deploy configs included

## Requirements

- Linux x86_64 or arm64 with systemd
- Fail2Ban
- An HTTP server writing access logs in a supported format (nginx, Apache, Caddy, Traefik, HAProxy — or custom regex)

## Installation

### Quick install — any distro (recommended)

Auto-detects your distro and architecture, downloads the correct package from GitHub Releases,
installs it with your package manager, enables and starts the service:

```bash
curl -fsSL https://raw.githubusercontent.com/mr-addams/arxsentinel/main/scripts/get.sh | sudo bash
```

Works on Debian, Ubuntu, Fedora, RHEL, AlmaLinux, Rocky Linux, and Arch Linux.
Requires `curl` and `sudo`. Fail2Ban is installed automatically if missing.

The service starts immediately and works with nginx out of the box — no profile needed. Edit the config to switch to another server (apache, caddy, traefik, haproxy-http, or a custom regex):

```bash
sudo nano /etc/arxsentinel/config.yaml
sudo systemctl kill -s HUP arxsentinel   # reload without restart
```

---

### Debian / Ubuntu — manual package

Download the `.deb` package for your architecture from the [Releases](https://github.com/mr-addams/arxsentinel/releases) page and install it:

```bash
# amd64
sudo apt install ./arxsentinel_<version>_linux_amd64.deb

# arm64
sudo apt install ./arxsentinel_<version>_linux_arm64.deb
```

`apt install` automatically resolves dependencies (`fail2ban`), installs the systemd unit, Fail2Ban filter/jail, logrotate config, and creates the `arxsentinel` system user.

After installation, edit the config and start the service:

```bash
sudo nano /etc/arxsentinel/config.yaml
sudo systemctl enable --now arxsentinel
```

### Fedora / RHEL / AlmaLinux / Rocky Linux

Download the `.rpm` package for your architecture from the [Releases](https://github.com/mr-addams/arxsentinel/releases) page and install it:

```bash
# amd64
sudo dnf install ./arxsentinel_<version>_linux_amd64.rpm

# arm64
sudo dnf install ./arxsentinel_<version>_linux_arm64.rpm
```

`dnf install` resolves dependencies, installs the systemd unit to `/usr/lib/systemd/system/`, Fail2Ban filter/jail, logrotate config, and creates the `arxsentinel` system user.

After installation, edit the config and start the service:

```bash
sudo nano /etc/arxsentinel/config.yaml
sudo systemctl enable --now arxsentinel
```

> **RHEL 8 / CentOS Stream 8:** use `dnf` or `rpm -i` directly. Fail2Ban may require the EPEL repository:
> `sudo dnf install epel-release && sudo dnf install fail2ban`

### Arch Linux / Manjaro

Download the `.pkg.tar.zst` package for your architecture from the [Releases](https://github.com/mr-addams/arxsentinel/releases) page and install it:

```bash
# amd64
sudo pacman -U arxsentinel_<version>_linux_amd64.pkg.tar.zst

# arm64
sudo pacman -U arxsentinel_<version>_linux_arm64.pkg.tar.zst
```

The package installs the systemd unit to `/usr/lib/systemd/system/`, Fail2Ban config files, logrotate config, and creates the `arxsentinel` system user.

After installation, edit the config and start the service:

```bash
sudo nano /etc/arxsentinel/config.yaml
sudo systemctl enable --now arxsentinel
```

> **Fail2Ban on Arch:** install it with `sudo pacman -S fail2ban` before or after installing arxsentinel.

### Build from source

Requires Go 1.19+:

```bash
git clone https://github.com/mr-addams/arxsentinel
cd arxsentinel
sudo ./scripts/install.sh
sudo systemctl enable --now arxsentinel
```

## Configuration

Config file: `/etc/arxsentinel/config.yaml` (created from `config.yaml` during installation).  
Override path: `ARXSENTINEL_CONFIG=/path/to/config.yaml`.

Key parameters:

```yaml
general:
  log_file: /var/log/nginx/access.log   # log file to watch (nginx example; see also: streams:)
  stats_interval: 300s                  # STATS output interval to operational log

parser:
  # profile: "apache"  # set for non-nginx servers: apache | caddy | traefik | haproxy-http
  #                     # nginx combined log format works without any profile setting

scoring:
  alert_threshold: 50    # score → WARN in threat log
  ban_threshold: 80      # score → THREAT + Fail2Ban ban
  observation_window: 300s  # score accumulation / decay window

detectors:
  probe:
    enabled: true
    score: 25
    paths: [/.env, /.git/config, /wp-config.php, ...]  # probe path list

  rate:
    enabled: true
    threshold: 100   # requests per window
    window: 60s
    score: 25

  useragent:
    enabled: true
    scanner_score: 40     # Nuclei, sqlmap, Nikto
    grabber_score: 20     # wget, HTTrack
    automation_score: 15  # python-requests, aiohttp
    empty_ua_score: 30

  bruteforce:
    enabled: true
    min_requests: 10
    ratio_threshold: 0.6  # >60% of responses are 404
    score: 30

  crawler:
    enabled: true
    min_sequential: 5  # /page/1, /page/2, ... N in a row
    score: 20

  noasset:
    enabled: true
    min_page_requests: 3
    asset_ratio_threshold: 0.1  # <10% of requests go to static assets
    score: 20

  overflow:
    enabled: true
    max_url_length: 2048
    suspicious_params: [bypass, shell, cmd, exec, eval]
    score: 30

whitelist:
  fake_bot_score: 35      # penalty for a bot UA that fails DNS verification
  dns_verify_timeout: 2s  # DNS verification timeout per pipeline request
  custom:
    ips: [127.0.0.1]
    cidrs: [10.0.0.0/8]
    ua_substrings: [internal-monitor]

output:
  threat_log: /var/log/arxsentinel/threats.log
  operational_log: /var/log/arxsentinel/sentinel.log
```

> **yaml.v3 limitation:** if a section is present in config.yaml (e.g., `scoring:`), it must include **all** fields — any omitted fields will be zeroed out. Sections missing from the file entirely will use Go defaults.

## Detectors

| Detector | Trigger | Default score |
|----------|---------|---------------|
| **probe** | request to .env, .git, wp-config.php, etc. | 25 per request |
| **rate** | >100 requests per 60s | 25 |
| **useragent** | scanner / grabber / automation / empty UA | 15–40 |
| **bruteforce** | >60% of responses are 404 with ≥10 requests | 30 |
| **crawler** | ≥5 sequential numeric URLs (/page/1..N) | 20 |
| **noasset** | <10% requests to static assets with ≥3 page requests | 20 |
| **overflow** | URL >2048 chars or WAF bypass keywords | 30 |

Score accumulates with linear decay over `observation_window`. Reaching `alert_threshold` writes a WARN; reaching `ban_threshold` writes a THREAT and triggers Fail2Ban.

## Whitelist

The whitelist tells ArxSentinel: "these are friendly — skip them entirely." There are two independent mechanisms: **automatic bot verification** (search engines) and **custom exclusions** (your own IPs, subnets, tools).

### Automatic bot verification (Googlebot, Bingbot, Yandex, etc.)

ArxSentinel knows the User-Agent strings of all major search bots. When a bot arrives, it performs a DNS check to confirm the bot is genuine:

1. Reverse-DNS lookup on the IP → gets a hostname (e.g. `crawl-66-249-66-1.googlebot.com`)
2. Forward-DNS on that hostname → must resolve back to the same IP
3. The hostname must end with one of Google's known domains (`.googlebot.com`, `.google.com`)

If both checks pass → the bot is legitimate → skipped, no score added.  
If the checks fail → the UA claims to be Googlebot but the IP is not Google → `fake_bot_score` penalty (default 35) is added instead.

Built-in verified bots: Google, Bing, Yandex, DuckDuckBot, Baidu, Apple, GPTBot, ClaudeBot, and others — see the `whitelist.bots` section in `config.yaml`.

**No configuration needed** — verification is automatic. DNS results are cached (`dns_cache.positive_ttl: 24h`) so it doesn't slow down processing.

### Custom whitelist

Add your own IPs, subnets, and tools to the `whitelist.custom` section:

```yaml
whitelist:
  custom:
    ips:           []
    cidrs:         []
    ua_substrings: []
```

Requests matching any entry are skipped **before** any detector runs — no score is ever added.

---

#### `ips` — specific IP addresses

List individual IP addresses that should never be checked.

```yaml
whitelist:
  custom:
    ips:
      - "192.168.1.50"    # office workstation
      - "10.99.99.1"      # internal monitoring server
      - "203.0.113.42"    # your home IP
```

Use this for: your own servers, known partners, office machines, developer laptops.

---

#### `cidrs` — IP ranges (subnets)

A CIDR is a compact way to write a range of IP addresses. Instead of listing hundreds of IPs, you write one line.

How to read it: `192.168.1.0/24` means "all addresses from `192.168.1.0` to `192.168.1.255`" — an entire block of 256 addresses. The number after `/` tells how many addresses are in the block:

| Notation | Range | Addresses |
|----------|-------|-----------|
| `10.0.0.1/32` | exactly `10.0.0.1` | 1 (single IP) |
| `192.168.1.0/24` | `192.168.1.0` – `192.168.1.255` | 256 |
| `10.0.0.0/8` | `10.0.0.0` – `10.255.255.255` | ~16 million |

```yaml
whitelist:
  custom:
    cidrs:
      - "192.168.0.0/16"    # entire office/VPN network
      - "10.0.0.0/8"        # all private 10.x.x.x addresses
      - "172.16.0.0/12"     # Docker / internal network
```

> **How to find your subnet?** Ask your system administrator, or check the network settings of your server. Hosting providers often give you a block like `185.220.100.0/22` for your cluster.

Use this for: office networks, VPN subnets, Cloudflare IP ranges, CDN edge nodes, your hosting cluster.

---

#### `ua_substrings` — User-Agent substrings

If a request contains this string anywhere in its User-Agent header, it is whitelisted. Matching is **case-insensitive**.

```yaml
whitelist:
  custom:
    ua_substrings:
      - "UptimeRobot"          # uptime monitoring service
      - "internal-healthcheck" # your own monitoring script
      - "MySEOCrawler/"        # your SEO tool
      - "Screaming Frog SEO"   # Screaming Frog crawler
      - "Ahrefs"               # Ahrefs bot
      - "Semrush"              # SEMrush crawler
```

> **For SEO tools:** if your SEO crawler is getting flagged (it sends many requests quickly, or has a suspicious UA), add its name here. Check the exact UA string in your access log:
> ```bash
> grep -i "screaming\|ahrefs\|semrush\|moz\|sitebulb" /var/log/nginx/access.log | awk -F'"' '{print $6}' | sort -u
> ```

**A substring is enough** — you don't need the full string. `"Ahrefs"` will match `"AhrefsBot/7.0"` and any future version.

---

### Applying changes

All whitelist changes apply **without restarting the daemon** — send a reload signal:

```bash
# Reload config (whitelist, detectors, thresholds — everything except log file path)
systemctl kill -s HUP arxsentinel

# Or via PID file
kill -HUP $(cat /var/run/arxsentinel.pid)
```

Changes take effect within seconds. The operational log will show:

```
[CONFIG] reloaded: whitelist updated
```

### Full example

```yaml
whitelist:
  fake_bot_score: 35        # penalty for fake Googlebot/Bingbot impersonation
  dns_verify_timeout: "2s"  # DNS verification timeout

  custom:
    ips:
      - "203.0.113.42"      # developer's home IP
      - "10.99.99.1"        # Zabbix monitoring

    cidrs:
      - "192.168.0.0/16"    # office and VPN
      - "10.0.0.0/8"        # private network

    ua_substrings:
      - "UptimeRobot"
      - "Screaming Frog SEO Spider"
      - "AhrefsBot"
      - "SemrushBot"
      - "MJ12bot"           # Majestic crawler
```

## Architecture

```
access.log (nginx / apache / caddy / traefik / haproxy)
       │
  TailReader (inotify, logrotate-aware)
       │
  lines chan (buffered, size LinesBufSize)
       │
  whitelist.Matcher ──→ custom IP/CIDR/UA? → skip
       │
  whitelist.Verifier ──→ bot UA? → rDNS/fDNS → verified? → skip
       │                                     → fake bot? → +FakeBotScore
  tracker.Update(*IPState)
    ├── TotalRequests, Requests404
    ├── pathBuf (ring buffer, last 64 paths)
    └── sliding window rate counters
       │
  scorer.Evaluate(ipState, entry)
    ├── decay accumulated score
    ├── run 7 detectors
    └── determine verdict (score → level)
       │
  output.ThreatLogger ──→ threats.log ──→ Fail2Ban ──→ iptables ban
                      └──→ sentinel.log (operational)
```

Background goroutines:
- **TailReader** — file watching via fsnotify, handles mv/copytruncate logrotate
- **GC** — removes inactive IPs every `gc_interval` (default 60s)
- **Stats** — prints `STATS processed/tracked/threats/suspicious` every `stats_interval`
- **SIGHUP listener** — converts the signal into a channel event for the main loop

## Multi-stream monitoring

Run one sentinel process that watches multiple log files simultaneously — one pipeline per domain, full isolation.

### Config

```yaml
streams:
  - name: site1
    log_file: /var/log/nginx/site1.access.log
    threat_log: /var/log/arxsentinel/site1.threats.log
  - name: site2
    log_file: /var/log/apache2/site2.access.log
    threat_log: /var/log/arxsentinel/site2.threats.log
    profile: apache
```

> **Note:** `streams:` and `general.log_file` are mutually exclusive. Use one or the other.

Each stream gets its own tracker, scorer, whitelist state, and threat log. A crash or slow scan on one stream does not affect others.

### Backward compatibility

The classic single-file config (`general.log_file`) keeps working — it is silently converted to a single unnamed stream (`stream=""` label on metrics). No config migration needed.

### Fail2Ban multi-stream

Each stream writes its own `threat_log` file. Create one Fail2Ban jail per file:

```ini
# /etc/fail2ban/jail.d/arxsentinel-site1.conf
[arxsentinel-site1]
enabled  = true
filter   = arxsentinel
logpath  = /var/log/arxsentinel/site1.threats.log
maxretry = 1
bantime  = 86400

[arxsentinel-site2]
enabled  = true
filter   = arxsentinel
logpath  = /var/log/arxsentinel/site2.threats.log
maxretry = 1
bantime  = 86400
```

### Grafana

The dashboard includes a **Stream** variable. Select one or multiple streams to filter all panels. Import `deploy/grafana/arxsentinel-dashboard.json` (v2).

---

## Logs

**Operational log** (`/var/log/arxsentinel/sentinel.log`) — daemon's working log:

```
2026-04-02 14:33:10 [STARTUP] arxsentinel v1.0.0 started
2026-04-02 14:33:12 [THREAT] 45.134.26.8 score=85 modules=probe,rate reason="..."
2026-04-02 14:38:10 [STATS] processed=14320 tracked=87 threats=3 suspicious=12
```

Tags: `STARTUP`, `SHUTDOWN`, `CONFIG`, `THREAT`, `WHITELIST`, `STATS`, `GC`, `ERROR`, `WARN`.  
Debug tags (`PARSER`, `TAIL`, `DETECTOR`, `SCORER`) are visible only when `logging.debug: true`.

**Threat log** (`/var/log/arxsentinel/threats.log`) — read by Fail2Ban:

```
2026-04-02T14:33:12Z THREAT 45.134.26.8 score=85 modules=probe,rate reason="probe:/.env,rate:142rps"
2026-04-02T14:35:01Z WARN   92.63.104.12 score=55 modules=useragent reason="ua:Nuclei/3.1.0"
```

Fail2Ban failregex: `THREAT <HOST> score=\d+` (file `deploy/fail2ban/filter.d/arxsentinel.conf`).

## Management

```bash
# Status and logs
systemctl status arxsentinel
journalctl -u arxsentinel -f

# Reload config without restart (SIGHUP)
kill -HUP $(cat /var/run/arxsentinel.pid)
# or
systemctl kill -s HUP arxsentinel

# Stop (graceful — drains the line buffer)
systemctl stop arxsentinel

# Manual ban/unban via Fail2Ban
fail2ban-client status arxsentinel
fail2ban-client set arxsentinel unbanip 1.2.3.4
```

**What is updated on SIGHUP:** scorer (detectors + thresholds), whitelist matcher, debug/color flags, log file paths.  
**What is NOT updated:** tracker (IP state), DNS cache, TailReader (access.log path requires a restart).

## JSON log format

By default ArxSentinel parses nginx combined log format (no profile needed) or the format defined by the active profile (apache, caddy, traefik, or haproxy-http).  
It also supports JSON log format — switch via `config.yaml` without recompilation.

The examples below use nginx. For other servers, adapt the `log_format` directive to your server's equivalent.

### Step 1 — Configure your HTTP server (nginx example)

Add the appropriate `log_format` to your `nginx.conf` (`http {}` block).
Ready-to-use configs are also in [`deploy/examples/nginx-json-logformat.conf`](deploy/examples/nginx-json-logformat.conf).

**Direct nginx (no reverse proxy)** — `$remote_addr` is the real client IP:

```nginx
log_format sentinel_json_direct escape=json
    '{'
        '"remote_addr":"$remote_addr",'
        '"time_iso8601":"$time_iso8601",'
        '"request":"$request",'
        '"status":"$status",'
        '"bytes_sent":"$bytes_sent",'
        '"http_referer":"$http_referer",'
        '"http_user_agent":"$http_user_agent"'
    '}';

access_log /var/log/nginx/access.log sentinel_json_direct;
```

**Behind a reverse proxy** — configure `ngx_http_realip_module` (see
[Deployment behind a reverse proxy](#deployment-behind-a-reverse-proxy)).
After realip processing, `$remote_addr` already holds the real client IP,
so the same `sentinel_json_direct` format works unchanged — no separate proxy variant needed.

### Step 2 — Update sentinel config

```yaml
parser:
  log_format: "json"   # "combined" (default) | "json"
```

The change takes effect on the next **SIGHUP** — no restart needed:

```bash
kill -HUP $(cat /var/run/arxsentinel.pid)
```

### Custom field names

If your log format uses different key names, override the mapping:

```yaml
parser:
  log_format: "json"
  json_fields:
    remote_addr: "client"
    time:        "ts"
    request:     "req"
    status:      "code"
    bytes_sent:  "size"
    referer:     "ref"
    user_agent:  "ua"
    real_ip:     "ip"
```

Unknown fields in the JSON log line are silently ignored — only the mapped fields are consumed.

## Deployment behind a reverse proxy

> **Warning:** if your HTTP server sits behind a proxy and the real client IP is not configured correctly,
> ArxSentinel will score the **proxy's IP address** instead of the real attacker.
> Fail2Ban will then ban your own proxy — taking the site down for everyone.

### How it works

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

### Ready-made configs

Full working examples for each proxy are in `deploy/examples/reverse-proxy/`:

| Proxy | Files |
|-------|-------|
| **HAProxy** | [`haproxy/haproxy.cfg`](deploy/examples/reverse-proxy/haproxy/haproxy.cfg), [`nginx.conf`](deploy/examples/reverse-proxy/haproxy/nginx.conf) |
| **Traefik** | [`traefik/traefik.yml`](deploy/examples/reverse-proxy/traefik/traefik.yml), [`nginx.conf`](deploy/examples/reverse-proxy/traefik/nginx.conf) |
| **Caddy** | [`caddy/Caddyfile`](deploy/examples/reverse-proxy/caddy/Caddyfile), [`nginx.conf`](deploy/examples/reverse-proxy/caddy/nginx.conf) |
| **nginx as RP** | [`nginx-rp/nginx-upstream.conf`](deploy/examples/reverse-proxy/nginx-rp/nginx-upstream.conf), [`nginx-origin.conf`](deploy/examples/reverse-proxy/nginx-rp/nginx-origin.conf) |

Each example includes both the proxy config and the origin nginx config with
`set_real_ip_from`, `real_ip_header X-Forwarded-For`, `real_ip_recursive on`,
and the `combined_realip` log format using `$remote_addr` as the real-IP field.

### Minimum nginx config (any proxy)

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

### Cloudflare

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

## CMS-specific configurations

Ready-made `probe.paths` overrides for the most common PHP stacks are in
`deploy/examples/cms/`. Copy the relevant paths into your `config.yaml`:

| File | Target |
|------|--------|
| [`wordpress.yaml`](deploy/examples/cms/wordpress.yaml) | WordPress — `wp-login.php`, `xmlrpc.php`, REST user enumeration |
| [`laravel.yaml`](deploy/examples/cms/laravel.yaml) | Laravel — `.env`, `/storage/`, `/vendor/`, Telescope, Horizon |
| [`drupal.yaml`](deploy/examples/cms/drupal.yaml) | Drupal — `/user/login`, `settings.php`, `update.php` |
| [`joomla.yaml`](deploy/examples/cms/joomla.yaml) | Joomla — `/administrator/`, `configuration.php` |
| [`generic-php.yaml`](deploy/examples/cms/generic-php.yaml) | Custom PHP apps — phpinfo, phpMyAdmin, Adminer, backup files |

**How to apply a CMS config:**

1. Open `deploy/examples/cms/<cms>.yaml` and copy the `paths:` list.
2. Paste it into your `config.yaml` under `detectors.probe.paths:`.
3. Reload without restart: `kill -HUP $(pgrep arxsentinel)` — or `systemctl kill -s HUP arxsentinel`.

The paths **extend** (not replace) the built-in sensitive-path list by default.
To use only your custom list, set `detectors.probe.paths:` to exactly the paths you want.

## Custom log format (regex)

Use any text log format by supplying a Go regex with named capture groups.

```yaml
parser:
  log_format: "regex"
  regex_pattern: '(?P<remote_addr>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d+) (?P<bytes_sent>\d+) "(?P<http_referer>[^"]*)" "(?P<http_user_agent>[^"]*)"'
```

### Named groups

| Group | Required | Description |
|-------|----------|-------------|
| `remote_addr` | ✅ | Client or proxy IP address |
| `time` | ✅ | Request time (`02/Jan/2006:15:04:05 -0700` format) |
| `request` | ✅ | Full request line: `METHOD /path HTTP/x.x` |
| `status` | ✅ | HTTP response code |
| `bytes_sent` | ✅ | Response size in bytes |
| `http_referer` | optional | Referer header value |
| `http_user_agent` | optional | User-Agent header value |
| `real_ip` | optional | Real client IP from a trusted proxy header |

Missing optional groups produce empty fields in the parsed entry — sentinel still works, just without referer/UA/real-IP data.

### Example: HAProxy HTTP log

```yaml
parser:
  log_format: "regex"
  regex_pattern: '(?P<remote_addr>\S+):\d+ \S+ \S+/\S+ \d+/\d+/\d+/\d+/\d+ (?P<status>\d+) (?P<bytes_sent>\d+) .* "(?P<request>[^"]*)"'
```

### Common mistakes

- **Missing mandatory group** — sentinel exits at startup with a clear error message listing the missing group name.
- **Unanchored pattern** — the regex is applied with `FindStringSubmatch`, so it matches anywhere in the line. Anchor with `^` / `$` if needed.
- **Wrong time format** — only `02/Jan/2006:15:04:05 -0700` (nginx `$time_local`) is parsed. ISO 8601 timestamps are not parsed; time-based features still work with zero time.

---

## Prometheus metrics

Enable in `config.yaml`:

```yaml
metrics:
  enabled: true
  listen_addr: ":9117"   # port for the metrics HTTP server
  # Optional basic auth — leave username empty to disable:
  username: ""
  password_hash: ""      # bcrypt hash; see deploy/grafana/README.md for generation
```

### Endpoints

| Endpoint | Auth | Description |
|----------|------|-------------|
| `/metrics` | optional basic auth | Prometheus scrape endpoint |
| `/health` | none | Liveness probe — always returns `200 {"status":"ok"}` |

The `/health` endpoint requires no credentials and is safe to expose to load balancers,
Docker `HEALTHCHECK`, and k8s liveness/readiness probes.

### Available metrics

| Metric | Type | Description |
|--------|------|-------------|
| `arxsentinel_lines_processed_total` | Counter | Log lines processed |
| `arxsentinel_threats_total{level}` | Counter | Threats by level (`THREAT` / `WARN`) |
| `arxsentinel_detector_hits_total{detector}` | Counter | Hits per detector name |
| `arxsentinel_tracked_ips` | Gauge | Currently tracked IPs |
| `arxsentinel_suspicious_ips` | Gauge | IPs with score above alert threshold |

### Prometheus scrape config

```yaml
scrape_configs:
  - job_name: "arxsentinel"
    static_configs:
      - targets: ["localhost:9117"]
    # basic_auth:          # only if auth is enabled in sentinel config
    #   username: "prometheus"
    #   password: "your-plaintext-password"
```

For Grafana dashboard setup see [`deploy/grafana/README.md`](deploy/grafana/README.md).

---

## Troubleshooting

**Daemon fails to start — threat log error:**  
Check permissions on `/var/log/arxsentinel/` — the directory must be owned by the `arxsentinel` user.

**Fail2Ban is not banning — check log format:**  
```bash
fail2ban-regex /var/log/arxsentinel/threats.log /etc/fail2ban/filter.d/arxsentinel.conf
```

**Too many false WARNs — reduce sensitivity:**  
Lower the `score` or raise thresholds (`threshold`, `ratio_threshold`) in the config, then `kill -HUP`.

**Debug pipeline — enable debug mode:**  
```yaml
logging:
  debug: true
```
Restart or `kill -HUP`. The operational log will show `[PARSER]`, `[DETECTOR]`, `[SCORER]` lines for every request.

**High memory usage:**  
Reduce `state.max_tracked_ips` (default 100000; each IP ≈ 2.5 KB → 100k ≈ 250 MB).

---

[Русская документация →  README.ru.md](README.ru.md)
