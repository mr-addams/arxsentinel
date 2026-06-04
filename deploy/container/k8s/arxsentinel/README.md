# ArxSentinel — Helm chart deployment guide

The ArxSentinel Helm chart deploys a DaemonSet that runs one pod per node,
reads the node's access log via `hostPath`, and writes threat events to a
configurable host directory for Fail2Ban integration.

## Prerequisites

- Helm 3.x
- Kubernetes 1.24+
- Docker image accessible from the cluster (`ghcr.io/mr-addams/arxsentinel`)

## Quick install

```bash
# Watch /var/log/nginx on every node, metrics only (no Fail2Ban)
helm install arxsentinel ./deploy/container/k8s/arxsentinel \
  --set logVolume.hostPath=/var/log/nginx
```

## Full install — bare-metal / k3s with Fail2Ban

```bash
# Create the threat log directory on every node:
# (run on each node, or use a DaemonSet init container)
sudo mkdir -p /var/log/arxsentinel
sudo chown 65532:65532 /var/log/arxsentinel

helm install arxsentinel ./deploy/container/k8s/arxsentinel \
  --set logVolume.hostPath=/var/log/nginx \
  --set threatLog.hostPath=/var/log/arxsentinel
```

## Values reference

| Key | Type | Default | Description |
|---|---|---|---|
| `image.repository` | string | `ghcr.io/mr-addams/arxsentinel` | Image repository |
| `image.tag` | string | `""` | Image tag; defaults to `Chart.AppVersion` |
| `image.pullPolicy` | string | `IfNotPresent` | Image pull policy |
| `logVolume.hostPath` | string | `/var/log/nginx` | Host path containing the access log |
| `logFile` | string | `access.log` | Access log filename inside `logVolume.hostPath` |
| `threatLog.hostPath` | string | `""` | Host path for threat log; empty = no hostPath mount |
| `metrics.enabled` | bool | `true` | Enable Prometheus `/metrics` endpoint |
| `metrics.port` | int | `9117` | Metrics port |
| `service.type` | string | `ClusterIP` | Kubernetes Service type |
| `serviceMonitor.enabled` | bool | `false` | Create a Prometheus Operator `ServiceMonitor` |
| `serviceMonitor.namespace` | string | `monitoring` | Namespace of the Prometheus Operator |
| `serviceMonitor.interval` | string | `30s` | Scrape interval |
| `resources.limits.cpu` | string | `200m` | CPU limit |
| `resources.limits.memory` | string | `128Mi` | Memory limit |
| `resources.requests.cpu` | string | `20m` | CPU request |
| `resources.requests.memory` | string | `32Mi` | Memory request |
| `tolerations` | list | `[]` | Node tolerations |
| `nodeSelector` | object | `{}` | Node selector |
| `env` | object | see values.yaml | `ARXSENTINEL_*` env var overrides |
| `extraEnv` | list | `[]` | Additional env vars (arbitrary key/value pairs) |

## Fail2Ban integration (bare-metal / k3s)

Set `threatLog.hostPath` to a directory present on every node.
Fail2Ban on the host reads `threats.log` from that directory:

```bash
helm upgrade arxsentinel ./deploy/container/k8s/arxsentinel \
  --set threatLog.hostPath=/var/log/arxsentinel
```

Configure Fail2Ban on the host:

```ini
# /etc/fail2ban/jail.d/arxsentinel.conf
[arxsentinel]
enabled  = true
filter   = arxsentinel
logpath  = /var/log/arxsentinel/threats.log
maxretry = 1
bantime  = 3600
```

Filter and jail configs: [`deploy/fail2ban/`](deploy/fail2ban/).

## Prometheus Operator integration (ServiceMonitor)

```bash
helm upgrade arxsentinel ./deploy/container/k8s/arxsentinel \
  --set serviceMonitor.enabled=true \
  --set serviceMonitor.namespace=monitoring \
  --set serviceMonitor.additionalLabels.release=prometheus
```

The `ServiceMonitor` targets port `metrics` (9117) on the ArxSentinel `ClusterIP` service.

## Watching control-plane nodes

By default, DaemonSet pods are not scheduled on control-plane nodes. Add a toleration:

```bash
helm upgrade arxsentinel ./deploy/container/k8s/arxsentinel \
  --set "tolerations[0].key=node-role.kubernetes.io/control-plane" \
  --set "tolerations[0].operator=Exists" \
  --set "tolerations[0].effect=NoSchedule"
```

## Config overrides via env vars

The `env` values map directly to `ARXSENTINEL_*` environment variables.
They take priority over the ConfigMap-rendered `config.yaml`:

```yaml
# values-production.yaml
env:
  ARXSENTINEL_SCORING_BAN_THRESHOLD: "60"
  ARXSENTINEL_SCORING_OBSERVATION_WINDOW: "600s"
  ARXSENTINEL_METRICS_USERNAME: "prometheus"
  ARXSENTINEL_METRICS_PASSWORD_HASH: "$2y$10$..."
```

```bash
helm upgrade arxsentinel ./deploy/container/k8s/arxsentinel -f values-production.yaml
```

> **Note:** Array fields (probe paths, bot configs, extra patterns) cannot be set via env vars.
> Override them by editing the ConfigMap or mounting a separate config file.

### Full env var reference

> Full examples with all YAML-only sections: [`config.reference.yaml`](../../../cookbook/config.reference.yaml) in the repository root.

Arrays are marked **YAML-only** — configure via ConfigMap `config.yaml` or a mounted config file.
Source types `exec`, `syslog` (network syslog receiver; `addr: udp://0.0.0.0:5514`), and `http` (HTTP/HTTPS log receiver; push/pull) are also YAML-only.

#### General, logging, parser

| Variable | Type | Default | Description |
|---|---|---|---|
| `ARXSENTINEL_GENERAL_LOG_FILE` | string | `/var/log/nginx/access.log` | Access log path |
| `ARXSENTINEL_GENERAL_PID_FILE` | string | `/tmp/arxsentinel.pid` | PID file path |
| `ARXSENTINEL_GENERAL_LINES_BUF_SIZE` | int | `1000` | Channel buffer size |
| `ARXSENTINEL_GENERAL_TAIL_RETRY_INTERVAL` | duration | `5s` | Tail retry interval |
| `ARXSENTINEL_GENERAL_STATS_INTERVAL` | duration | `300s` | Stats log interval |
| `ARXSENTINEL_LOGGING_DEBUG` | bool | `false` | Enable debug log tags |
| `ARXSENTINEL_LOGGING_CONSOLE_COLOR` | bool | `false` | ANSI color output |
| `ARXSENTINEL_PARSER_PROFILE` | string | `` | Server profile (apache, caddy, traefik, haproxy-http) |
| `ARXSENTINEL_PARSER_LOG_FORMAT` | string | `combined` | Log format (combined, json, regex) |
| `ARXSENTINEL_PARSER_REGEX_PATTERN` | string | `` | Go regex (required for regex format) |
| `ARXSENTINEL_PARSER_TIMEZONE` | string | `UTC` | Timezone (reserved) |
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
| `ARXSENTINEL_SCORING_DECAY` | string | `linear` | Decay algorithm (YAML-only) |
| `ARXSENTINEL_STATE_GC_INTERVAL` | duration | `60s` | GC interval |
| `ARXSENTINEL_STATE_MAX_TRACKED_IPS` | int | `100000` | Max tracked IPs |

#### Detectors — probe, bruteforce, crawler, no-asset

| Variable | Type | Default | Description |
|---|---|---|---|
| `ARXSENTINEL_DETECTORS_PROBE_ENABLED` | bool | `true` | Enable probe scanner |
| `ARXSENTINEL_DETECTORS_PROBE_SCORE` | int | `25` | Score per probe path hit |
| `ARXSENTINEL_DETECTORS_PROBE_PATHS` | array | _(29 paths)_ | **YAML-only** |
| `ARXSENTINEL_DETECTORS_BRUTEFORCE_ENABLED` | bool | `true` | Enable 404-ratio bruteforce |
| `ARXSENTINEL_DETECTORS_BRUTEFORCE_MIN_REQUESTS` | int | `10` | Min requests before check |
| `ARXSENTINEL_DETECTORS_BRUTEFORCE_RATIO_THRESHOLD` | float | `0.6` | 404 ratio threshold |
| `ARXSENTINEL_DETECTORS_BRUTEFORCE_SCORE` | int | `30` | Score per bruteforce hit |
| `ARXSENTINEL_DETECTORS_CRAWLER_ENABLED` | bool | `true` | Enable sequential crawler |
| `ARXSENTINEL_DETECTORS_CRAWLER_MIN_SEQUENTIAL` | int | `5` | Min sequential requests |
| `ARXSENTINEL_DETECTORS_CRAWLER_SCORE` | int | `20` | Score per crawler hit |
| `ARXSENTINEL_DETECTORS_NOASSET_ENABLED` | bool | `true` | Enable no-asset bot |
| `ARXSENTINEL_DETECTORS_NOASSET_MIN_PAGE_REQUESTS` | int | `3` | Min page requests |
| `ARXSENTINEL_DETECTORS_NOASSET_ASSET_RATIO_THRESHOLD` | float | `0.1` | Asset ratio threshold |
| `ARXSENTINEL_DETECTORS_NOASSET_SCORE` | int | `20` | Score per no-asset hit |
| `ARXSENTINEL_DETECTORS_NOASSET_ASSET_EXTENSIONS` | array | _(12 ext)_ | **YAML-only** |

#### Detectors — rate, user-agent, overflow, badbot

| Variable | Type | Default | Description |
|---|---|---|---|
| `ARXSENTINEL_DETECTORS_RATE_ENABLED` | bool | `true` | Enable rate anomaly |
| `ARXSENTINEL_DETECTORS_RATE_WINDOW` | duration | `60s` | Rate counting window |
| `ARXSENTINEL_DETECTORS_RATE_THRESHOLD` | int | `100` | Requests per window |
| `ARXSENTINEL_DETECTORS_RATE_SCORE` | int | `25` | Score per rate hit |
| `ARXSENTINEL_DETECTORS_USERAGENT_ENABLED` | bool | `true` | Enable UA anomaly |
| `ARXSENTINEL_DETECTORS_USERAGENT_SCANNER_SCORE` | int | `40` | Scanner UA score |
| `ARXSENTINEL_DETECTORS_USERAGENT_GRABBER_SCORE` | int | `20` | Grabber UA score |
| `ARXSENTINEL_DETECTORS_USERAGENT_AUTOMATION_SCORE` | int | `15` | Automation tool UA score |
| `ARXSENTINEL_DETECTORS_USERAGENT_EMPTY_UA_SCORE` | int | `30` | Empty UA score |
| `ARXSENTINEL_DETECTORS_USERAGENT_EXTRA_SCANNER_PATTERNS` | array | `[]` | **YAML-only** |
| `ARXSENTINEL_DETECTORS_USERAGENT_EXTRA_GRABBER_PATTERNS` | array | `[]` | **YAML-only** |
| `ARXSENTINEL_DETECTORS_USERAGENT_EXTRA_AUTOMATION_PATTERNS` | array | `[]` | **YAML-only** |
| `ARXSENTINEL_DETECTORS_OVERFLOW_ENABLED` | bool | `true` | Enable overflow/WAF bypass |
| `ARXSENTINEL_DETECTORS_OVERFLOW_MAX_URL_LENGTH` | int | `2048` | URL length threshold |
| `ARXSENTINEL_DETECTORS_OVERFLOW_SCORE` | int | `30` | Score per overflow hit |
| `ARXSENTINEL_DETECTORS_OVERFLOW_SUSPICIOUS_PARAMS` | array | _(7 params)_ | **YAML-only** |
| `ARXSENTINEL_DETECTORS_BADBOT_ENABLED` | bool | `true` | Enable community blocklist |
| `ARXSENTINEL_DETECTORS_BADBOT_SCORE` | int | `60` | Score per blocklist match |
| `ARXSENTINEL_DETECTORS_BADBOT_CHECK_UA` | bool | `true` | Match UA against badbot-ua |
| `ARXSENTINEL_DETECTORS_BADBOT_CHECK_REFERRER` | bool | `false` | Match Referer against badbot-ref |

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
| `ARXSENTINEL_WHITELIST_BOTS` | array | _(11 bots)_ | **YAML-only** |
| `ARXSENTINEL_CHAIN_GUARD_ENABLED` | bool | `false` | Enable proxy chain check |
| `ARXSENTINEL_CHAIN_GUARD_WARNINGS_LOG` | string | `` | Warning log path |
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

### Basic auth for metrics

When metrics basic auth is configured, the `ARXSENTINEL_METRICS_PASSWORD_HASH` field
must contain a **bcrypt hash** (not a plain-text password). Generate one with:

```bash
htpasswd -bnBC 10 "" your-password | tr -d ':\n'
```

Example values.yaml:

```yaml
env:
  ARXSENTINEL_METRICS_USERNAME: "prometheus"
  ARXSENTINEL_METRICS_PASSWORD_HASH: "$2y$10$..."
```

> **Warning:** In Helm values, the `$` signs in the bcrypt hash must be escaped
> or wrapped in single quotes to prevent Helm templating from interpreting them.
> Use `$2y$10$...` directly in `values.yaml` — Helm handles raw `$` in simple env vars.
> If you encounter rendering errors, verify the hash has no characters that Helm interprets:
> `env | grep ARXSENTINEL_METRICS_PASSWORD_HASH` inside the pod to confirm the hash is intact.

## Cloud environments (managed Kubernetes)

In managed cloud clusters (EKS, GKE, AKS), nodes may lack Fail2Ban or host-level
iptables access. The `hostPath` threat log approach does not integrate with cloud
firewall APIs.

**Current recommendation:** leave `threatLog.hostPath` empty and monitor threat
events via the Prometheus metrics endpoint. Block IPs at the load balancer / WAF level
based on Prometheus alerts.

**Planned:** Output Plugins (future release) will enable sending threat events directly
to databases, message queues, webhooks, and cloud firewall APIs — removing the Fail2Ban
dependency for cloud deployments.

## Upgrade

```bash
helm upgrade arxsentinel ./deploy/container/k8s/arxsentinel
```

Pods are restarted automatically when the ConfigMap checksum changes.

## Uninstall

```bash
helm uninstall arxsentinel
```

`hostPath` directories on nodes are not removed — clean them up manually if needed.
