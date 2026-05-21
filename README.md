# ArxSentinel

[![Release](https://img.shields.io/github/v/release/mr-addams/arxsentinel?include_prereleases&label=release)](https://github.com/mr-addams/arxsentinel/releases)
[![Build](https://github.com/mr-addams/arxsentinel/actions/workflows/release.yml/badge.svg)](https://github.com/mr-addams/arxsentinel/actions/workflows/release.yml)
[![License](https://img.shields.io/badge/license-GPL--3.0-blue)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go)](go.mod)
[![Platforms](https://img.shields.io/badge/linux-amd64%20%7C%20arm64-lightgrey?logo=linux)](https://github.com/mr-addams/arxsentinel/releases)
[![Packages](https://img.shields.io/badge/packages-deb%20%7C%20rpm%20%7C%20pacman-blue)](https://github.com/mr-addams/arxsentinel/releases)

A vigilant sentinel for your web server — reads HTTP access logs in real time, scores every IP through 8 behavioural detectors, and bans attackers via Fail2Ban. Works with nginx, Apache, Caddy, Traefik, HAProxy, LiteSpeed, and OpenLiteSpeed.

Supports **nginx, Apache, Caddy, Traefik, HAProxy, LiteSpeed, and OpenLiteSpeed** via built-in profiles. nginx works out of the box with no profile needed. Caddy and HAProxy require minimal one-time setup. Custom log formats supported via regex. Watch multiple log files in a single process.

```
access.log → TailReader → whitelist → tracker → scorer → threats.log → Fail2Ban → iptables
```

## Supported HTTP servers

### Compatibility table

| Server | Profile | Setup required |
|--------|---------|----------------|
| nginx | *(default — no profile needed)* | None — nginx combined log format works out of the box |
| Apache | `apache` | None — default CLF format |
| Traefik | `traefik` | Add `fields.headers.names.User-Agent/Referer: keep` to accessLog — see [`deploy/examples/traefik/`](deploy/examples/traefik/) |
| LiteSpeed / OpenLiteSpeed | `litespeed` | None — default CLF format |
| Caddy | `caddy` | [xcaddy](https://github.com/caddyserver/xcaddy) + [transform-encoder](https://github.com/caddyserver/transform-encoder) plugin — see [`deploy/examples/caddy/`](deploy/examples/caddy/) |
| HAProxy | `haproxy-http` | `http-request capture` + custom `log-format` with UA — see [`deploy/examples/haproxy/`](deploy/examples/haproxy/) |

> Each release includes a **Tested product versions** table with the exact server versions the build was validated against — see [GitHub Releases](https://github.com/mr-addams/arxsentinel/releases).

> **nginx:** no `profile:` setting is needed. The default CombinedParser handles nginx combined log format out of the box. Set only `general.log_file` pointing to your access log.

Built-in profiles — no regex or field mapping required. Set `parser.profile` to the server name for Apache, Traefik, Caddy, HAProxy, LiteSpeed, or OpenLiteSpeed:

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
├── haproxy/     haproxy.cfg + sentinel-config.yaml
└── litespeed/   httpd_config.conf + sentinel-config.yaml
```

> **Note — LiteSpeed / OpenLiteSpeed:** Both LSWS and OLS emit Apache CLF by default —
> no server-side changes required. Log path: `/usr/local/lsws/logs/access.log`
> (server-wide) or `/usr/local/lsws/logs/<vhostname>/access.log` (per virtual host).
> Behind a reverse proxy: enable "Use Client IP in Header" in WebAdmin so `%h` logs
> the real client IP. See `deploy/examples/litespeed/` for the full config.

> **Note — Caddy:** Caddy v2's built-in JSON encoder outputs nested objects. The
> `caddy` profile requires the
> [caddy-transform-encoder](https://github.com/caddyserver/transform-encoder) plugin
> to produce CLF output. See `deploy/examples/caddy/Caddyfile` for the setup.

## Features

- **8 detectors:** probe scanning, rate anomaly, suspicious User-Agent, bruteforce (404 ratio), sequential crawler, no-asset bot, URL overflow / WAF bypass, community bad-bot blocklist
- **Chain Guard:** detects Cloudflare/CDN edge IPs and bogon/RFC 1918/CGNAT addresses appearing as client IPs — signals a misconfigured proxy chain before ArxSentinel's detectors go blind
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
- An HTTP server writing access logs in a supported format (nginx, Apache, Caddy, Traefik, HAProxy, LiteSpeed, OpenLiteSpeed — or custom regex)

## Installation

### Quick install — any distro (recommended)

Auto-detects your distro and architecture, downloads the correct package from GitHub Releases,
installs it with your package manager, enables and starts the service:

```bash
curl -fsSL https://raw.githubusercontent.com/mr-addams/arxsentinel/main/scripts/get.sh | sudo bash
```

Works on Debian, Ubuntu, Fedora, RHEL, AlmaLinux, Rocky Linux, and Arch Linux.
Requires `curl` and `sudo`. Fail2Ban is installed automatically if missing.

The service starts immediately and works with nginx out of the box — no profile needed. Edit the config to switch to another server (apache, caddy, traefik, haproxy-http, litespeed, or a custom regex):

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

### Docker

Distroless image (~12 MB), runs as non-root uid 65532, exposes Prometheus metrics on `:9117`.

```bash
docker run -d \
  -v /var/log/nginx/access.log:/var/log/nginx/access.log:ro \
  -v /var/log/arxsentinel:/var/log/arxsentinel \
  -p 127.0.0.1:9117:9117 \
  ghcr.io/mr-addams/arxsentinel:latest
```

See [README.docker.md](README.docker.md) for Docker Compose setup, volume mounts, env var overrides, and Fail2Ban integration.

### Kubernetes (Helm)

DaemonSet topology — one pod per node, reads the node's access log via `hostPath`.

```bash
helm install arxsentinel ./deploy/container/k8s/arxsentinel \
  --set logVolume.hostPath=/var/log/nginx \
  --set threatLog.hostPath=/var/log/arxsentinel
```

See [README.helm.md](README.helm.md) for values reference, Prometheus Operator integration, and cloud deployment notes.

## Configuration

Config file: `/etc/arxsentinel/config.yaml` (created from `config.yaml` during installation).  
Override path: `ARXSENTINEL_CONFIG=/path/to/config.yaml`.

Key parameters:

```yaml
general:
  log_file: /var/log/nginx/access.log   # log file to watch (nginx example; see also: streams:)
  stats_interval: 300s                  # STATS output interval to operational log

parser:
  # profile: "apache"  # set for non-nginx servers: apache | caddy | traefik | haproxy-http | litespeed
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

  badbot:
    enabled: true
    score: 60
    check_ua: true
    check_referrer: false   # opt-in: also match the Referer header (~7108 referrer patterns)

blocklist:
  storage: ""              # "" = in-memory; file path = bbolt (survives restarts)
  lists:
    - name: badbot-ua
      refresh_interval: 24h
      sources:
        - url: "https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-user-agents.list"
          format: plain_text
    - name: badbot-ref
      refresh_interval: 24h
      sources:
        - url: "https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-referrer-words.list"
          format: plain_text

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
| **badbot** | UA (or Referer) matches community blocklist (~685 patterns) | 60 |

Score accumulates with linear decay over `observation_window`. Reaching `alert_threshold` writes a WARN; reaching `ban_threshold` writes a THREAT and triggers Fail2Ban.

## Whitelist

ArxSentinel provides automatic bot verification (search engines) and custom exclusion lists
(IPs, CIDRs, User-Agent substrings). Whitelisted requests skip all detectors entirely.

See [README.whitelist.md](README.whitelist.md) for configuration details and examples.

## Architecture

```
access.log (nginx / apache / caddy / traefik / haproxy / litespeed)
       │
  TailReader (inotify, logrotate-aware)
       │
  lines chan (buffered, size LinesBufSize)
       │
  whitelist.Matcher ──→ custom IP/CIDR/UA? → skip
       │
  chaincheck.Checker ──→ Cloudflare/bogon IP? → warnings.log (CHAIN_WARN)
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
    ├── run 8 detectors
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

**Warnings log** (`chain_guard.warnings_log`) — infrastructure misconfiguration alerts:

```
2026-05-20T12:34:56Z CHAIN_WARN cloudflare-ip-as-client ip=172.64.0.1 cidr=172.64.0.0/13 log=/var/log/nginx/access.log
2026-05-20T12:34:57Z CHAIN_WARN bogon-ip-as-client ip=10.0.0.1 cidr=10.0.0.0/8 log=/var/log/nginx/access.log
```

Warnings are distinct from threats: `CHAIN_WARN` means ArxSentinel cannot reliably identify
the real attacker IP. Fix the underlying infrastructure issue (see [Chain Guard](#chain-guard--detecting-broken-ip-extraction))
and the warnings will stop.

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

## Log Formats

ArxSentinel supports three log format modes: **combined** (default nginx), **JSON** (no recompilation needed), and **custom regex** for arbitrary text formats.

See [README.log-formats.md](README.log-formats.md) for full configuration examples, field mappings, and common mistakes.

## Reverse proxy & Chain Guard

Full guide for deployment behind a reverse proxy (HAProxy, Traefik, Caddy, nginx), including IP extraction configuration and Chain Guard (broken IP chain detection).

See [`deploy/examples/reverse-proxy/README.md`](deploy/examples/reverse-proxy/README.md).

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


---

## Prometheus metrics

Enable metrics in `config.yaml`, configure Prometheus scraping, set up bcrypt password hashing, and import the Grafana dashboard.

Full guide: [`deploy/grafana/README.md`](deploy/grafana/README.md)

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

## Third-party data

The **badbot** detector fetches its blocklists from [nginx-ultimate-bad-bot-blocker](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker), an outstanding community project created and maintained by **[Mitchell Krog (@mitchellkrogza)](https://github.com/mitchellkrogza)** and its contributors. The project curates ~685 bad User-Agent patterns and ~7108 bad referrer words, updated almost daily — an enormous effort that benefits the entire web.

Licensed under [MIT](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/blob/master/LICENSE.md). The lists are downloaded at runtime and are not bundled with ArxSentinel.

Heartfelt thanks to Mitchell Krog and every contributor to that project — your dedication makes the web a safer place for everyone.

---

[Русская документация → README.ru.md](README.ru.md) | [Українська документація → README.uk.md](README.uk.md)
