# Roadmap

Ideas and planned features for future releases.
Items are not guaranteed — they reflect current thinking and may be reprioritised.

---

## v0.3.0

### Multi-stream support (multiple log files in one process)

**Problem:** servers hosting multiple domains each have a separate nginx `access.log`.
Today the only option is running one `nginx-sentinel` instance per domain — separate
configs, separate ports, N × memory.

**Proposed solution:** a `streams:` section in `config.yaml` that lets a single process
watch multiple log files simultaneously, with full isolation between streams at every
layer — tracker, scorer, whitelist, threat log, and metrics.

```yaml
streams:
  - name: site1
    log_file: /var/log/nginx/site1.access.log
    threat_log: /var/log/nginx-sentinel/site1.threats.log
    # Optional per-stream config overrides (scoring, detectors, whitelist)

  - name: site2
    log_file: /var/log/nginx/site2.access.log
    threat_log: /var/log/nginx-sentinel/site2.threats.log
```

**Metrics isolation:** all streams report to the same `/metrics` endpoint, but every
counter and gauge carries a `stream` label — the native Prometheus approach for
multi-instance data on a single scrape target:

```
nginx_sentinel_threats_total{level="THREAT", stream="site1"} 12
nginx_sentinel_threats_total{level="THREAT", stream="site2"} 3
nginx_sentinel_tracked_ips{stream="site1"} 47
nginx_sentinel_tracked_ips{stream="site2"} 11
```

**Scope:**
- `PipelineContext` becomes per-stream; each stream runs in its own goroutine set
- Metrics registry redesigned to accept a `stream` label on all vectors
- SIGHUP rebuilds all stream pipelines without dropping the metrics HTTP server
- Fail2Ban threat log remains per-stream (one file per domain)
- Backward compatible: existing single `general.log_file` config continues to work
  (treated as a single unnamed stream)

---

## Backlog (unscheduled)

- **GeoIP enrichment** — add country/ASN label to threat log and metrics
- **Rate-limit exemptions per path** — exclude `/api/health` and similar from rate detector
- **Webhook notifications** — HTTP POST on THREAT event (Slack, Telegram, generic)
- **eBPF tail reader** — replace inotify-based tail with eBPF for lower latency on
  high-throughput logs
