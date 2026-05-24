# Roadmap

Ideas and planned features for future releases.
Items are not guaranteed — they reflect current thinking and may be reprioritised.

---

## Stage 1 — v0.3.0 (nginx-sentinel repo)

Universal parser support + multi-stream. Developed in the current repo.
After v0.3.0 ships, the project migrates to **arx-sentinel**.

### Flow #13 — Multi-stream support

Watch multiple log files in one process with full per-stream isolation.
Decisions are documented in `.opencode/config/opencode/architecture/adr/` (ADR-001+).

```yaml
streams:
  - name: site1
    log_file: /var/log/nginx/site1.access.log
    threat_log: /var/log/nginx-sentinel/site1.threats.log
  - name: site2
    log_file: /var/log/nginx/site2.access.log
    threat_log: /var/log/nginx-sentinel/site2.threats.log
```

Metrics carry a `stream` label on all counters/gauges. Backward compatible:
`general.log_file` continues to work as a single unnamed stream.

### Flow #14 — Regex parser

Custom text log format via named capture groups:

```yaml
parser:
  log_format: "regex"
  regex_pattern: '(?P<remote_addr>\S+) .* "(?P<request>[^"]+)" (?P<status>\d+) (?P<bytes_sent>\d+).*'
```

### Flow #15 — Built-in server profiles

Drop-in support for Apache, Caddy, Traefik, HAProxy:

```yaml
parser:
  profile: "apache"   # apache | caddy | traefik | haproxy-http
```

Each profile ships with a `deploy/examples/<server>/` config and README section.

### Flow #16 — Release v0.3.0

---

## Stage 2 — v1.0.0 (arx-sentinel repo)

Migration and rebrand. All development from this point happens in `mr-addams/arx-sentinel`.
**Language rule:** all code, comments, flows, and docs switch to English at migration.
Documentation continues in EN + RU + UK.

### Flow #17 — Repo migration

- Create `mr-addams/arx-sentinel`, push current code with full git history
- Archive `nginx-sentinel` with a redirect notice in README
- Update `get.sh` repo reference, CI workflows, GitHub Pages source

### Flow #18 — Core rebrand

- Binary: `nginx-sentinel` → `arxsentinel`
- Systemd unit: `nginx-sentinel.service` → `arxsentinel.service`
- Config path: `/etc/nginx-sentinel/` → `/etc/arxsentinel/`
- Log path: `/var/log/nginx-sentinel/` → `/var/log/arxsentinel/`
- Prometheus metrics: `nginx_sentinel_*` → `arx_sentinel_*` (breaking — documented in CHANGELOG)
- `scripts/migrate.sh` — automatic config migration for existing users
- Fail2Ban filter updated

### Flow #19 — Landing pages + SEO rebrand

- Name: ArxSentinel across all three landing pages (EN/RU/UK)
- Tagline: "works with nginx, Apache, Caddy, Traefik, HAProxy"
- JSON-LD, canonical URLs, og:url, hreflang → new repo URLs
- README rewritten for ArxSentinel

### Flow #20 — Release v1.0.0

VERSION 1.0.0, CHANGELOG with migration notes from 0.x.

---

## Backlog (unscheduled)

- **GeoIP enrichment** — country/ASN label in threat log and metrics
- **Rate-limit exemptions per path** — exclude `/api/health` and similar from rate detector
- **Webhook notifications** — HTTP POST on THREAT event (Slack, Telegram, generic)
- **eBPF tail reader** — replace inotify-based tail with eBPF for lower latency
