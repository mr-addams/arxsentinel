# ArxSentinel — Docker Deployment Guide

## Quick start

```bash
docker run -d \
  -v /var/log/nginx:/var/log/nginx:ro \
  -v /var/log/arxsentinel:/var/log/arxsentinel \
  -v /etc/arxsentinel:/etc/arxsentinel:ro \
  ghcr.io/mr-addams/arxsentinel:latest
```

The default configuration reads `/var/log/nginx/access.log` and writes threats to
`/var/log/arxsentinel/threats.log` in Fail2Ban-compatible format.

---

## Pipe / container mode (Universal I/O)

When running as a sidecar or in a pipeline, use the `--input` and `--output` flags
to override the config file I/O sections entirely.

### stdin → stdout (JSON)

```bash
# Pipe nginx access log through ArxSentinel, get JSON threat events on stdout.
docker logs -f nginx | arxsentinel --input=stdin --output=stdout,json
```

### docker-compose sidecar with named pipe

```yaml
services:
  nginx:
    image: nginx:alpine
    volumes:
      - logs:/var/log/nginx

  arxsentinel:
    image: ghcr.io/mr-addams/arxsentinel:latest
    command: ["--input=stdin", "--output=stdout,json"]
    stdin_open: true
    depends_on: [nginx]
    volumes:
      - logs:/var/log/nginx:ro

volumes:
  logs:
```

### Kubernetes — log-forwarding sidecar

```yaml
containers:
  - name: arxsentinel
    image: ghcr.io/mr-addams/arxsentinel:latest
    args: ["--input=stdin", "--output=stdout,json"]
    stdin: true
```

Pipe the main container's log stream into the sidecar via a shared emptyDir volume
or a log-forwarding agent (Fluentd, Vector, Promtail).

---

## Output formats

| Flag | Format | Use case |
|------|--------|----------|
| `--output=stdout` | Fail2Ban text line | Legacy tooling, Fail2Ban socket |
| `--output=stdout,json` | JSON envelope | Log aggregators (Loki, Splunk, Datadog) |
| `--output=stdout,fail2ban` | Fail2Ban text line | Explicit default |

JSON envelope example:
```json
{
  "timestamp": "2026-05-26T14:33:12Z",
  "level": "THREAT",
  "stream": "",
  "source": "stdin",
  "source_type": "stdin",
  "ip": "1.2.3.4",
  "score": 85,
  "modules": ["probe", "bad_bot"],
  "reason": "probe:env:3,bad_bot:known"
}
```

---

## Multi-output (config file)

To write to both a Fail2Ban file and stdout simultaneously, use the `outputs:` section
in your config instead of CLI flags:

```yaml
inputs:
  - type: file
    path: /var/log/nginx/access.log

outputs:
  - type: file
    path: /var/log/arxsentinel/threats.log
    format: fail2ban
  - type: stdout
    format: json
```

---

## Log rotation (SIGHUP)

ArxSentinel reopens its output file sinks on `SIGHUP`. Configure logrotate:

```
/var/log/arxsentinel/threats.log {
    daily
    rotate 30
    compress
    postrotate
        kill -HUP $(cat /run/arxsentinel/arxsentinel.pid) 2>/dev/null || true
    endscript
}
```

---

## Metrics

Prometheus metrics are available on `:9117/metrics` when `metrics.enabled: true` in config.

New Universal I/O counters:

| Metric | Labels | Description |
|--------|--------|-------------|
| `arxsentinel_input_lines_total` | stream, source, source_type | Lines read from sources |
| `arxsentinel_output_events_total` | stream, sink, sink_type | Threat events written to sinks |
| `arxsentinel_output_dropped_total` | stream, sink, reason | Events dropped (Phase 2: async sinks) |
