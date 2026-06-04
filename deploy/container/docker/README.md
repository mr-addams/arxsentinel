# ArxSentinel — Docker deployment guide

ArxSentinel ships as a distroless Docker image (~12 MB, amd64 + arm64).
It runs as a non-root user (uid 65532), exposes Prometheus metrics on `:9117`,
and writes threat events to a bind-mounted directory that Fail2Ban reads on the host.

## Quick start

```bash
# Create the threat log directory (writable by container uid 65532)
sudo mkdir -p /var/log/arxsentinel
sudo chown 65532:65532 /var/log/arxsentinel

# Run with defaults — watches /var/log/nginx/access.log
docker run -d \
  --name arxsentinel \
  --restart unless-stopped \
  -v /var/log/nginx/access.log:/var/log/nginx/access.log:ro \
  -v /var/log/arxsentinel:/var/log/arxsentinel \
  -p 127.0.0.1:9117:9117 \
  ghcr.io/mr-addams/arxsentinel:latest
```

## Docker Compose

```bash
cd deploy/container/docker

# Copy and adjust the env file
cp .env.example .env
# Edit .env: set LOG_FILE and THREAT_LOG_DIR

# Create threat log directory
sudo mkdir -p /var/log/arxsentinel
sudo chown 65532:65532 /var/log/arxsentinel

# Start
docker compose up -d

# Check logs
docker compose logs -f arxsentinel
```

The Compose file is at [`deploy/container/docker/docker-compose.yml`](deploy/container/docker/docker-compose.yml).

## Configuration

### Volume mounts

| Mount point in container | Purpose | Mode |
|---|---|---|
| `/var/log/nginx/access.log` | Access log to watch | `ro` |
| `/var/log/arxsentinel` | Threat log + operational log | `rw` |
| `/etc/arxsentinel/config.yaml` | Custom config (optional) | `ro` |
| `/tmp` | PID file | `rw` (tmpfs) |

### Environment variables

All scalar config fields can be overridden via `ARXSENTINEL_*` environment variables.
They take priority over the mounted `config.yaml`.

> **Note:** Array fields (paths, extra patterns, bot configs) cannot be set via env vars.
> Configure them in a mounted `config.yaml` instead.

#### General, logging, and parser

| Variable | Type | Default | Description |
|---|---|---|---|
| `ARXSENTINEL_GENERAL_LOG_FILE` | string | `/var/log/nginx/access.log` | Access log path inside container |
| `ARXSENTINEL_GENERAL_PID_FILE` | string | `/tmp/arxsentinel.pid` | PID file path |
| `ARXSENTINEL_GENERAL_LINES_BUF_SIZE` | int | `1000` | Channel buffer size |
| `ARXSENTINEL_GENERAL_TAIL_RETRY_INTERVAL` | duration | `5s` | Tail retry on unavailable file |
| `ARXSENTINEL_GENERAL_STATS_INTERVAL` | duration | `300s` | Stats log interval |
| `ARXSENTINEL_LOGGING_DEBUG` | bool | `false` | Enable debug log tags |
| `ARXSENTINEL_LOGGING_CONSOLE_COLOR` | bool | `false` | ANSI color output |
| `ARXSENTINEL_PARSER_PROFILE` | string | `` | Server profile: `apache`, `caddy`, `traefik`, `haproxy-http` |
| `ARXSENTINEL_PARSER_LOG_FORMAT` | string | `combined` | Log format: `combined`, `json`, `regex` |
| `ARXSENTINEL_PARSER_REGEX_PATTERN` | string | `` | Go regex (required when `log_format=regex`) |
| `ARXSENTINEL_PARSER_TIMEZONE` | string | `UTC` | Timezone (reserved, not connected) |
| `ARXSENTINEL_PARSER_JSON_REMOTE_ADDR` | string | `remote_addr` | JSON key → client IP (log_format=json) |
| `ARXSENTINEL_PARSER_JSON_TIME` | string | `time_iso8601` | JSON key → timestamp |
| `ARXSENTINEL_PARSER_JSON_REQUEST` | string | `request` | JSON key → request line |
| `ARXSENTINEL_PARSER_JSON_STATUS` | string | `status` | JSON key → HTTP status |
| `ARXSENTINEL_PARSER_JSON_BYTES_SENT` | string | `bytes_sent` | JSON key → response size |
| `ARXSENTINEL_PARSER_JSON_REFERER` | string | `http_referer` | JSON key → Referer header |
| `ARXSENTINEL_PARSER_JSON_USER_AGENT` | string | `http_user_agent` | JSON key → User-Agent header |
| `ARXSENTINEL_PARSER_JSON_REAL_IP` | string | `real_ip` | JSON key → real client IP (behind proxy) |

#### Scoring and state

| Variable | Type | Default | Description |
|---|---|---|---|
| `ARXSENTINEL_SCORING_ALERT_THRESHOLD` | int | `50` | WARN threshold |
| `ARXSENTINEL_SCORING_BAN_THRESHOLD` | int | `80` | THREAT (ban) threshold |
| `ARXSENTINEL_SCORING_OBSERVATION_WINDOW` | duration | `300s` | Score decay window |
| `ARXSENTINEL_SCORING_DECAY` | string | `linear` | Decay algorithm |
| `ARXSENTINEL_STATE_GC_INTERVAL` | duration | `60s` | Garbage collection interval |
| `ARXSENTINEL_STATE_MAX_TRACKED_IPS` | int | `100000` | Max tracked IPs (LRU eviction) |

#### Detectors

| Variable | Type | Default | Description |
|---|---|---|---|
| `ARXSENTINEL_DETECTORS_PROBE_ENABLED` | bool | `true` | Enable probe scanner |
| `ARXSENTINEL_DETECTORS_PROBE_SCORE` | int | `25` | Score per probe path hit |
| `ARXSENTINEL_DETECTORS_BRUTEFORCE_ENABLED` | bool | `true` | Enable 404-ratio bruteforce |
| `ARXSENTINEL_DETECTORS_BRUTEFORCE_MIN_REQUESTS` | int | `10` | Min requests before check |
| `ARXSENTINEL_DETECTORS_BRUTEFORCE_RATIO_THRESHOLD` | float | `0.6` | 404 ratio threshold |
| `ARXSENTINEL_DETECTORS_BRUTEFORCE_SCORE` | int | `30` | Score per bruteforce hit |
| `ARXSENTINEL_DETECTORS_CRAWLER_ENABLED` | bool | `true` | Enable sequential crawler |
| `ARXSENTINEL_DETECTORS_CRAWLER_MIN_SEQUENTIAL` | int | `5` | Min sequential requests before trigger |
| `ARXSENTINEL_DETECTORS_CRAWLER_SCORE` | int | `20` | Score per crawler hit |
| `ARXSENTINEL_DETECTORS_NOASSET_ENABLED` | bool | `true` | Enable no-asset bot detector |
| `ARXSENTINEL_DETECTORS_NOASSET_MIN_PAGE_REQUESTS` | int | `3` | Min page requests before check |
| `ARXSENTINEL_DETECTORS_NOASSET_ASSET_RATIO_THRESHOLD` | float | `0.1` | Asset ratio threshold |
| `ARXSENTINEL_DETECTORS_NOASSET_SCORE` | int | `20` | Score per no-asset hit |
| `ARXSENTINEL_DETECTORS_RATE_ENABLED` | bool | `true` | Enable rate anomaly |
| `ARXSENTINEL_DETECTORS_RATE_WINDOW` | duration | `60s` | Rate counting window |
| `ARXSENTINEL_DETECTORS_RATE_THRESHOLD` | int | `100` | Requests per window to trigger |
| `ARXSENTINEL_DETECTORS_RATE_SCORE` | int | `25` | Score per rate hit |
| `ARXSENTINEL_DETECTORS_USERAGENT_ENABLED` | bool | `true` | Enable UA anomaly detector |
| `ARXSENTINEL_DETECTORS_USERAGENT_SCANNER_SCORE` | int | `40` | Score for scanner UAs |
| `ARXSENTINEL_DETECTORS_USERAGENT_GRABBER_SCORE` | int | `20` | Score for grabber UAs |
| `ARXSENTINEL_DETECTORS_USERAGENT_AUTOMATION_SCORE` | int | `15` | Score for automation tool UAs |
| `ARXSENTINEL_DETECTORS_USERAGENT_EMPTY_UA_SCORE` | int | `30` | Score for empty UA |
| `ARXSENTINEL_DETECTORS_OVERFLOW_ENABLED` | bool | `true` | Enable overflow/WAF bypass |
| `ARXSENTINEL_DETECTORS_OVERFLOW_MAX_URL_LENGTH` | int | `2048` | URL length threshold |
| `ARXSENTINEL_DETECTORS_OVERFLOW_SCORE` | int | `30` | Score per overflow hit |
| `ARXSENTINEL_DETECTORS_BADBOT_ENABLED` | bool | `true` | Enable community blocklist |
| `ARXSENTINEL_DETECTORS_BADBOT_SCORE` | int | `60` | Score per blocklist match |
| `ARXSENTINEL_DETECTORS_BADBOT_CHECK_UA` | bool | `true` | Match UA against badbot-ua list |
| `ARXSENTINEL_DETECTORS_BADBOT_CHECK_REFERRER` | bool | `false` | Match Referer against badbot-ref list |

#### Whitelist, chain guard, output, metrics

| Variable | Type | Default | Description |
|---|---|---|---|
| `ARXSENTINEL_WHITELIST_FAKE_BOT_SCORE` | int | `35` | Fake bot penalty score |
| `ARXSENTINEL_WHITELIST_DNS_VERIFY_TIMEOUT` | duration | `2s` | Bot DNS verification timeout |
| `ARXSENTINEL_WHITELIST_DNS_CACHE_POSITIVE_TTL` | duration | `24h` | Positive DNS cache TTL |
| `ARXSENTINEL_WHITELIST_DNS_CACHE_NEGATIVE_TTL` | duration | `1h` | Negative DNS cache TTL |
| `ARXSENTINEL_WHITELIST_DNS_CACHE_IP_LIST_REFRESH` | duration | `24h` | Bot IP range refresh interval |
| `ARXSENTINEL_WHITELIST_CUSTOM_IPS` | CSV | `` | Trusted IPs (comma-separated) |
| `ARXSENTINEL_WHITELIST_CUSTOM_CIDRS` | CSV | `` | Trusted subnets (comma-separated) |
| `ARXSENTINEL_CHAIN_GUARD_ENABLED` | bool | `false` | Enable proxy chain integrity check |
| `ARXSENTINEL_CHAIN_GUARD_WARNINGS_LOG` | string | `` | Warning log path (required if enabled) |
| `ARXSENTINEL_CHAIN_GUARD_CLOUDFLARE_ENABLED` | bool | `true` | Enable Cloudflare IP range check |
| `ARXSENTINEL_CHAIN_GUARD_CLOUDFLARE_REFRESH_INTERVAL` | duration | `24h` | Cloudflare IP list refresh interval |
| `ARXSENTINEL_CHAIN_GUARD_BOGON_ENABLED` | bool | `true` | Enable bogon/RFC1918/CGNAT check |
| `ARXSENTINEL_BLOCKLIST_STORAGE` | string | `` | Persistent blocklist cache path |
| `ARXSENTINEL_OUTPUT_THREAT_LOG` | string | `/var/log/arxsentinel/threats.log` | Threat log path |
| `ARXSENTINEL_OUTPUT_OPERATIONAL_LOG` | string | `/var/log/arxsentinel/sentinel.log` | Operational log path |
| `ARXSENTINEL_METRICS_ENABLED` | bool | `false` | Enable Prometheus endpoint |
| `ARXSENTINEL_METRICS_LISTEN_ADDR` | string | `:9117` | Metrics listen address |
| `ARXSENTINEL_METRICS_USERNAME` | string | `` | Basic auth username |
| `ARXSENTINEL_METRICS_PASSWORD_HASH` | string | `` | bcrypt hash of password |
| `ARXSENTINEL_PIPELINE_BUFFER_SIZE` | int | `8192` | Channel buffer depth (increase for burst traffic) |
| `ARXSENTINEL_PIPELINE_SHUTDOWN_TIMEOUT` | duration | `15s` | Graceful shutdown drain window |

Full list: all `ARXSENTINEL_<SECTION>_<FIELD>` variables are defined in
`internal/sys/config/config.go` (`applyEnvOverrides` function).

### Custom config file

Mount your own `config.yaml` to override the image defaults:

```bash
docker run -d \
  -v ./my-config.yaml:/etc/arxsentinel/config.yaml:ro \
  -v /var/log/nginx/access.log:/var/log/nginx/access.log:ro \
  -v /var/log/arxsentinel:/var/log/arxsentinel \
  ghcr.io/mr-addams/arxsentinel:latest
```

## Prometheus integration

The metrics endpoint is enabled by default in the Docker image.

```bash
# Verify the endpoint
curl http://localhost:9117/metrics | grep arx

# Add to Prometheus — paste the job from deploy/container/docker/prometheus-scrape.yml
# into your prometheus.yml scrape_configs section.
```

Grafana dashboards: see [`deploy/grafana/`](deploy/grafana/) for ready-to-import JSON dashboards.

### Basic auth for metrics

```bash
# Generate a bcrypt hash (cost 10):
htpasswd -bnBC 10 "" your-password | tr -d ':\n'

# Set via env vars:
docker run -d \
  -e ARXSENTINEL_METRICS_USERNAME=prometheus \
  -e 'ARXSENTINEL_METRICS_PASSWORD_HASH=$2y$10$...' \
  ...
```

## Fail2Ban integration

ArxSentinel writes threat events to the host directory mounted at `/var/log/arxsentinel`.
Configure Fail2Ban on the host to read `threats.log` from that directory:

```ini
# /etc/fail2ban/jail.d/arxsentinel.conf
[arxsentinel]
enabled  = true
filter   = arxsentinel
logpath  = /var/log/arxsentinel/threats.log
maxretry = 1
bantime  = 3600
```

The Fail2Ban filter and jail configs are in [`deploy/fail2ban/`](deploy/fail2ban/).

## Multi-stream monitoring

To watch multiple log files independently, mount a custom `config.yaml` that uses the
`streams:` section instead of `general.log_file`:

```yaml
# config.yaml
streams:
  - name: site1
    inputs:
      - type: file
        path: /logs/site1.access.log
        parser: combined
    outputs:
      - type: file
        path: /threats/site1.threats.log
        format: fail2ban
  - name: site2
    inputs:
      - type: file
        path: /logs/site2.access.log
        parser: combined
    outputs:
      - type: file
        path: /threats/site2.threats.log
        format: fail2ban
```

```bash
docker run -d \
  -v ./config.yaml:/etc/arxsentinel/config.yaml:ro \
  -v /var/log/nginx:/logs:ro \
  -v /var/log/arxsentinel:/threats \
  ghcr.io/mr-addams/arxsentinel:latest
```

> **YAML-only features** — the following cannot be configured via env vars and require
> a custom `config.yaml`:
> `streams:`, `inputs:`, `outputs:`, `executors:`, `pipelines:`, per-detector `paths:` arrays.
> Source types `exec`, `syslog` (network syslog receiver; `addr: udp://0.0.0.0:5514`), and `http` (HTTP/HTTPS log receiver; push/pull) are also YAML-only.
> Full copy-paste-ready examples: `/etc/arxsentinel/config.yaml.example` (inside the container)
> or [`config.reference.yaml`](../../../../cookbook/config.reference.yaml) in the repository.

## Building locally

```bash
# Build the image (requires Docker Buildx)
docker build -f deploy/container/docker/Dockerfile --build-arg VERSION=$(cat VERSION) -t arxsentinel:local .

# Run container integration tests (requires the image built above)
go test -v -tags container ./tests/container/ -timeout 120s
```

## Image details

| Property | Value |
|---|---|
| Base image | `gcr.io/distroless/static-debian12:nonroot` |
| User | `nonroot` (uid 65532) |
| Exposed port | `9117` (Prometheus metrics) |
| Size | ~12 MB |
| Architectures | `linux/amd64`, `linux/arm64` |
| Registry | `ghcr.io/mr-addams/arxsentinel` |
