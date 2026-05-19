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
cd deploy/docker

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

The Compose file is at [`deploy/docker/docker-compose.yml`](deploy/docker/docker-compose.yml).

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

| Variable | Type | Default | Description |
|---|---|---|---|
| `ARXSENTINEL_GENERAL_LOG_FILE` | string | `/var/log/nginx/access.log` | Access log path inside container |
| `ARXSENTINEL_GENERAL_PID_FILE` | string | `/tmp/arxsentinel.pid` | PID file path |
| `ARXSENTINEL_LOGGING_DEBUG` | bool | `false` | Enable debug log tags |
| `ARXSENTINEL_LOGGING_CONSOLE_COLOR` | bool | `false` | ANSI color output |
| `ARXSENTINEL_PARSER_PROFILE` | string | `` | Server profile: `apache`, `caddy`, `traefik`, `haproxy-http` |
| `ARXSENTINEL_PARSER_LOG_FORMAT` | string | `combined` | Log format: `combined`, `json`, `regex` |
| `ARXSENTINEL_SCORING_ALERT_THRESHOLD` | int | `50` | Alert threshold |
| `ARXSENTINEL_SCORING_BAN_THRESHOLD` | int | `80` | Ban threshold |
| `ARXSENTINEL_SCORING_OBSERVATION_WINDOW` | duration | `300s` | Score window |
| `ARXSENTINEL_STATE_GC_INTERVAL` | duration | `60s` | GC interval |
| `ARXSENTINEL_STATE_MAX_TRACKED_IPS` | int | `100000` | Max tracked IPs |
| `ARXSENTINEL_METRICS_ENABLED` | bool | `true` | Enable Prometheus endpoint |
| `ARXSENTINEL_METRICS_LISTEN_ADDR` | string | `:9117` | Metrics listen address |
| `ARXSENTINEL_METRICS_USERNAME` | string | `` | Basic auth username |
| `ARXSENTINEL_METRICS_PASSWORD_HASH` | string | `` | bcrypt hash of password |
| `ARXSENTINEL_OUTPUT_THREAT_LOG` | string | `/var/log/arxsentinel/threats.log` | Threat log path |
| `ARXSENTINEL_OUTPUT_OPERATIONAL_LOG` | string | `/var/log/arxsentinel/sentinel.log` | Operational log path |
| `ARXSENTINEL_WHITELIST_CUSTOM_IPS` | CSV | `` | Trusted IPs (comma-separated) |
| `ARXSENTINEL_WHITELIST_CUSTOM_CIDRS` | CSV | `` | Trusted subnets (comma-separated) |

Full list: all `ARXSENTINEL_<SECTION>_<FIELD>` variables are documented in
`internal/sys/config/config.go`.

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

# Add to Prometheus — paste the job from deploy/docker/prometheus-scrape.yml
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

To watch multiple log files, mount a custom `config.yaml` that uses the `streams:` section
instead of `general.log_file`:

```yaml
# config.yaml
streams:
  - name: site1
    log_file: /logs/site1.access.log
    threat_log: /threats/site1.threats.log
  - name: site2
    log_file: /logs/site2.access.log
    threat_log: /threats/site2.threats.log
```

```bash
docker run -d \
  -v ./config.yaml:/etc/arxsentinel/config.yaml:ro \
  -v /var/log/nginx:/logs:ro \
  -v /var/log/arxsentinel:/threats \
  ghcr.io/mr-addams/arxsentinel:latest
```

## Building locally

```bash
# Build the image (requires Docker Buildx)
docker build --build-arg VERSION=$(cat VERSION) -t arxsentinel:local .

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
