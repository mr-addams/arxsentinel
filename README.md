# nginx-sentinel

Real-time nginx access.log analysis daemon. Tracks per-IP behaviour, accumulates a score through 7 detectors, and writes suspicious IPs to a threat log — Fail2Ban reads it and bans the attackers.

```
nginx access.log → TailReader → whitelist → tracker → scorer → threats.log → Fail2Ban → iptables
```

## Features

- **7 detectors:** probe scanning, rate anomaly, suspicious User-Agent, bruteforce (404 ratio), sequential crawler, no-asset bot, URL overflow / WAF bypass
- **Bot DNS verification:** Googlebot, Bingbot, Yandex, DuckDuckGo and others are verified via rDNS/fDNS — legitimate crawlers are never banned
- **Whitelist:** IPs, CIDRs, UA substrings — configurable exclusion lists
- **Linear score decay:** points decay over `observation_window`, no false bans from old traffic
- **SIGHUP reload:** config, scorer and whitelist are rebuilt without restarting the daemon
- **Graceful shutdown:** line buffer is drained on SIGTERM
- **Systemd + logrotate + Fail2Ban:** ready-to-use deploy configs included

## Requirements

- Linux x86_64 or arm64 with systemd
- Fail2Ban
- nginx with `$real_ip` in log_format (or standard combined format using `$remote_addr`)

## Installation

### Debian / Ubuntu — recommended

Download the `.deb` package for your architecture from the [Releases](https://github.com/mr-addams/nginx-sentinel/releases) page and install it:

```bash
# amd64
sudo apt install ./nginx-sentinel_<version>_linux_amd64.deb

# arm64
sudo apt install ./nginx-sentinel_<version>_linux_arm64.deb
```

`apt install` automatically resolves dependencies (`fail2ban`), installs the systemd unit, Fail2Ban filter/jail, logrotate config, and creates the `nginx-sentinel` system user.

After installation, edit the config and start the service:

```bash
sudo nano /etc/nginx-sentinel/config.yaml
sudo systemctl enable --now nginx-sentinel
```

### Build from source

Requires Go 1.19+:

```bash
git clone https://github.com/mr-addams/nginx-sentinel
cd nginx-sentinel
sudo ./scripts/install.sh
sudo systemctl enable --now nginx-sentinel
```

## Configuration

Config file: `/etc/nginx-sentinel/config.yaml` (created from `config.yaml` during installation).  
Override path: `NGINX_SENTINEL_CONFIG=/path/to/config.yaml`.

Key parameters:

```yaml
general:
  log_file: /var/log/nginx/access.log   # nginx access.log to watch
  stats_interval: 300s                  # STATS output interval to operational log

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
  threat_log: /var/log/nginx-sentinel/threats.log
  operational_log: /var/log/nginx-sentinel/sentinel.log
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

## Architecture

```
nginx access.log
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

## Logs

**Operational log** (`/var/log/nginx-sentinel/sentinel.log`) — daemon's working log:

```
2026-04-02 14:33:10 [STARTUP] nginx-sentinel v0.1 started
2026-04-02 14:33:12 [THREAT] 45.134.26.8 score=85 modules=probe,rate reason="..."
2026-04-02 14:38:10 [STATS] processed=14320 tracked=87 threats=3 suspicious=12
```

Tags: `STARTUP`, `SHUTDOWN`, `CONFIG`, `THREAT`, `WHITELIST`, `STATS`, `GC`, `ERROR`, `WARN`.  
Debug tags (`PARSER`, `TAIL`, `DETECTOR`, `SCORER`) are visible only when `logging.debug: true`.

**Threat log** (`/var/log/nginx-sentinel/threats.log`) — read by Fail2Ban:

```
2026-04-02T14:33:12Z THREAT 45.134.26.8 score=85 modules=probe,rate reason="probe:/.env,rate:142rps"
2026-04-02T14:35:01Z WARN   92.63.104.12 score=55 modules=useragent reason="ua:Nuclei/3.1.0"
```

Fail2Ban failregex: `THREAT <HOST> score=\d+` (file `deploy/fail2ban/filter.d/nginx-sentinel.conf`).

## Management

```bash
# Status and logs
systemctl status nginx-sentinel
journalctl -u nginx-sentinel -f

# Reload config without restart (SIGHUP)
kill -HUP $(cat /var/run/nginx-sentinel.pid)
# or
systemctl kill -s HUP nginx-sentinel

# Stop (graceful — drains the line buffer)
systemctl stop nginx-sentinel

# Manual ban/unban via Fail2Ban
fail2ban-client status nginx-sentinel
fail2ban-client set nginx-sentinel unbanip 1.2.3.4
```

**What is updated on SIGHUP:** scorer (detectors + thresholds), whitelist matcher, debug/color flags, log file paths.  
**What is NOT updated:** tracker (IP state), DNS cache, TailReader (access.log path requires a restart).

## Behind a Reverse Proxy (Cloudflare)

If nginx sits behind Cloudflare, `$remote_addr` in the logs will be a Cloudflare IP, not the real client. nginx-sentinel would then score Cloudflare's addresses → Fail2Ban would ban Cloudflare → the site goes down for everyone.

**Solution: `ngx_http_realip_module`**

Generate the nginx config with Cloudflare IP ranges and include it:

```bash
# Generate and save the config
sudo scripts/update-cloudflare-ips.sh /etc/nginx/cloudflare-real-ip.conf
```

Add to `nginx.conf`:

```nginx
http {
    include /etc/nginx/cloudflare-real-ip.conf;
    ...
}
```

nginx will then replace `$remote_addr` with the real client IP (from the `CF-Connecting-IP` header) before writing to the log — nginx-sentinel works without any changes.

**Auto-update IP ranges** (Cloudflare updates them periodically):

```bash
# Add to cron — every Monday at 03:00
0 3 * * 1 /path/to/update-cloudflare-ips.sh /etc/nginx/cloudflare-real-ip.conf && nginx -t && nginx -s reload
```

> **Why `CF-Connecting-IP` and not `X-Forwarded-For`:** `X-Forwarded-For` can be spoofed by the client before it reaches Cloudflare. `CF-Connecting-IP` is set by Cloudflare itself and cannot be supplied by the client.

## Troubleshooting

**Daemon fails to start — threat log error:**  
Check permissions on `/var/log/nginx-sentinel/` — the directory must be owned by the `nginx-sentinel` user.

**Fail2Ban is not banning — check log format:**  
```bash
fail2ban-regex /var/log/nginx-sentinel/threats.log /etc/fail2ban/filter.d/nginx-sentinel.conf
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
