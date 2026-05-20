# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

- **Detector #8: badbot** — community-curated bad-bot blocklist detector.
  Fetches ~685 User-Agent patterns and ~7108 bad referrer words from
  [nginx-ultimate-bad-bot-blocker](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker)
  (MIT, by [Mitchell Krog @mitchellkrogza](https://github.com/mitchellkrogza) and contributors).
  Patterns are matched via Aho-Corasick automaton (O(text_len) per request).
  - `check_ua: true` — matches User-Agent header (default on)
  - `check_referrer: false` — matches Referer header (opt-in; 7k patterns, higher FP risk)
  - Graceful degradation: score=0 until first successful fetch; old automata
    preserved on fetch error

### Changed

- **Internal: `internal/core/blocklist.Manager`** — extracted from BadBotDetector
  into a standalone package that owns all pattern lists, per-list refresh goroutines,
  Aho-Corasick automata, and optional bbolt persistence.
  - `Manager.Match(list, text)` is the single public API; thread-safe, O(text\_len)
  - `Manager.Update(ctx, cfg)` replaces goroutines on SIGHUP without pointer change
  - `Manager.Close()` cancels all goroutines and closes bbolt
  - BadBotDetector is now a thin wrapper; no goroutines, no storage logic
- **Config: new top-level `blocklist:` section** — separates data management
  (sources, refresh schedule, bbolt path) from detection policy (`detectors.badbot`).
  `badbot` no longer has `sources`, `refresh_interval`, or `storage` fields.
  Pattern lists are named (`badbot-ua`, `badbot-ref`) and configured independently.
- **Config: optional bbolt persistence** (`blocklist.storage`) — empty string (default)
  uses in-memory only; a file path enables persistence across restarts for sub-second
  automaton rebuild without a network fetch.
- **Dependencies**: `github.com/rrethy/ahocorasick v1.0.0`, `go.etcd.io/bbolt v1.4.3`

---

## [1.0.0] — 2026-05-18

### Added

- **ArxSentinel branding** — project renamed from `nginx-sentinel` to `arxsentinel`;
  binary, service unit, config paths, and Fail2Ban filter all updated accordingly
- **Universal web server support** — documented profiles for Apache, Caddy, Traefik,
  and HAProxy; nginx is now "first example" rather than the only supported target
- **Migration script** — `scripts/migrate.sh` automates upgrade from `nginx-sentinel`:
  stops the old service, copies config to new path, enables `arxsentinel.service`,
  updates Fail2Ban jail; idempotent with dry-run mode
- **Grafana legacy dashboard** — `deploy/grafana/nginx-sentinel-dashboard-legacy.json`
  preserved for users who need to migrate dashboards manually
- **Updated landing pages** — EN/RU/UK versions rebranded to ArxSentinel with
  multi-stream and server profile highlights; SEO metadata and hreflang updated

### Changed

- **Binary name**: `nginx-sentinel` → `arxsentinel`
- **Systemd unit**: `nginx-sentinel.service` → `arxsentinel.service`
- **Default config directory**: `/etc/nginx-sentinel/` → `/etc/arxsentinel/`
- **Default log directory**: `/var/log/nginx-sentinel/` → `/var/log/arxsentinel/`
- **Fail2Ban filter file**: `nginx-sentinel.conf` → `arxsentinel.conf`
- **Prometheus metric prefix**: `nginx_sentinel_*` → `arx_sentinel_*` (all metrics)
- **Grafana dashboard**: all panels updated to `arx_sentinel_*` metric names;
  `$stream` multi-select variable retained from v0.3.0

### Breaking Changes

- All Prometheus metric names changed: `nginx_sentinel_*` → `arx_sentinel_*`
- Service unit and binary renamed — existing init scripts, cron jobs, and monitoring
  rules referencing `nginx-sentinel` must be updated
- Config path changed — the old `/etc/nginx-sentinel/config.yaml` is not read
  automatically; use `scripts/migrate.sh` or copy manually

---

### Upgrading from 0.x to 1.0.0

Run `scripts/migrate.sh` for an automated upgrade, or follow the table below.

| What changed | Before (0.x) | After (1.0.0) | Action |
|---|---|---|---|
| Binary name | `nginx-sentinel` | `arxsentinel` | Update shell scripts and cron jobs |
| Systemd unit | `nginx-sentinel.service` | `arxsentinel.service` | `systemctl disable nginx-sentinel && systemctl enable arxsentinel` |
| Config directory | `/etc/nginx-sentinel/` | `/etc/arxsentinel/` | `cp /etc/nginx-sentinel/config.yaml /etc/arxsentinel/config.yaml` |
| Log directory | `/var/log/nginx-sentinel/` | `/var/log/arxsentinel/` | Update `general.log_file` in config if overridden |
| Fail2Ban filter | `nginx-sentinel.conf` | `arxsentinel.conf` | Update `/etc/fail2ban/jail.local`: `filter = arxsentinel` |
| Metric prefix | `nginx_sentinel_*` | `arx_sentinel_*` | Update all PromQL queries and alert rules (see below) |
| Grafana dashboard | v0.3 JSON | v1.0 JSON | Re-import `deploy/grafana/arxsentinel-dashboard.json` |

**Prometheus migration — metric rename examples:**

```promql
# Before (0.x)
nginx_sentinel_threats_total{level="THREAT"}
nginx_sentinel_lines_processed_total
nginx_sentinel_tracked_ips
nginx_sentinel_detector_hits_total{detector="bruteforce"}

# After (1.0.0)
arx_sentinel_threats_total{level="THREAT"}
arx_sentinel_lines_processed_total
arx_sentinel_tracked_ips
arx_sentinel_detector_hits_total{detector="bruteforce"}
```

All metric names follow the pattern: replace `nginx_sentinel_` prefix with `arx_sentinel_`.
The `stream` label introduced in v0.3.0 is unchanged.

---

## [0.3.0] — 2026-05-18

### Added

- **Multi-stream monitoring** — `streams:` config block to watch multiple nginx log files
  simultaneously; each stream runs in an isolated goroutine with its own tracker, scorer,
  whitelist matcher, and threat log; SIGHUP fan-out reloads all streams without restart
- **Regex parser** — `parser.log_format: "regex"` with named capture groups; mandatory
  groups: `remote_addr`, `time`, `request`, `status`, `bytes_sent`; optional: `real_ip`,
  `http_referer`, `http_user_agent`; invalid pattern → startup error with clear message
- **Built-in server profiles** — `parser.profile` field selects a preconfigured parser:
  `apache` (Combined Log Format), `caddy` (CLF via transform-encoder), `traefik`
  (CLF default), `haproxy-http` (httplog format); profile takes priority over `log_format`
- **Deploy examples** — `deploy/examples/apache/`, `caddy/`, `traefik/`, `haproxy/` with
  server config + `sentinel-config.yaml` per profile
- **Prometheus stream label** — all metrics are now `*Vec` with `stream` label; single-stream
  deployments use `stream=""` for backward compatibility
- **Grafana stream variable** — `$stream` multi-select variable cascades from `$job`;
  all 8 dashboard panels updated with `stream=~"$stream"` filter; dashboard version bumped to v2

### Changed

- `buildParser()` priority: `parser.profile` → `parser.log_format` → default combined
- `general.log_file` default moved to lazy-apply in backward-compat block; no longer
  set in `defaultConfig()` — prevents false mutual-exclusion error with `streams:`
- `utils.Init()` and `utils.Reload()` accept empty `threatLogPath`; each stream opens
  its own threat file via `utils.OpenThreatLog()`

### Migration notes — Prometheus / Grafana

Metrics gained a `stream` label in v0.3.0. Existing PromQL queries must be updated:

```promql
# Before (v0.2.x)
nginx_sentinel_threats_total{level="THREAT"}

# After (v0.3.x) — single-stream deployment (stream label is empty string)
nginx_sentinel_threats_total{level="THREAT", stream=""}

# After (v0.3.x) — aggregate across all streams
sum(nginx_sentinel_threats_total{level="THREAT"})
```

The bundled Grafana dashboard JSON (`deploy/grafana/nginx-sentinel-dashboard.json`)
is updated for v0.3. Re-import it to get the `$stream` variable and updated panels.
Dashboards created from v0.2 JSON will continue to work but will not show per-stream
breakdown until re-imported.

---

## [0.2.0] — 2026-05-17

### Added

- **Prometheus exporter** — `/metrics` endpoint on a configurable port (default `:9117`);
  counters for lines processed, threats by level, detector hits; gauges for tracked and
  suspicious IPs (`internal/sys/metrics/`)
- **Basic auth for `/metrics`** — optional bcrypt-protected access via
  `metrics.username` / `metrics.password_hash` in config; timing-safe username comparison
- **Grafana dashboard** — provisioning-ready JSON with 8 panels (Threat Rate, Lines/s,
  Tracked IPs, Detector Breakdown, WARN/THREAT ratio); `$job` multi-select variable;
  import guide in `deploy/grafana/README.md`
- **JSON log format** — `parser.log_format: "json"` selects a new JSON parser with
  configurable field mapping (`parser.json_fields`); supports nginx `$time_iso8601`
  with `+HH:MM` and `+HHMM` timezone variants; unknown fields silently ignored
- **Reverse proxy examples** — ready-to-use configs for HAProxy, Traefik, Caddy, and
  nginx-as-RP in `deploy/examples/reverse-proxy/`; Cloudflare `CF-Connecting-IP` snippet
  included in the nginx-rp example
- **CMS probe-path configs** — `deploy/examples/cms/` with WordPress, Laravel, Drupal,
  Joomla, and generic-PHP `probe.paths` overrides
- **E2E test scenarios** — IPv6 attacker (`TestE2EIPv6Attacker`), slow automation scan
  (`TestE2ESlowAttack`), false-positive check for 200-line legit traffic
  (`TestE2EFalsePositive`), whitelisted IP exclusion (`TestE2EWhitelistedCustomIP`)

### Changed

- `PipelineContext` now includes a `Parser` field; parser is rebuilt on SIGHUP so
  `log_format` changes take effect without restart
- `parser.log_format` comparison is now case-insensitive (normalised to lowercase after
  YAML load)

### Fixed

- CI: dev-release tag creation retries on race condition when multiple PRs merge
  simultaneously (retry loop with `git fetch --tags` before each attempt)

---

## [0.1.3] — 2026-05-17

### Added

- Landing pages: EN/RU/UK versions with cyberpunk design, 2-tab install, 7-card feature
  overview, quick-install script, Cloudflare/reverse-proxy card
- Landing page security hardening: self-hosted fonts, CSP header, `rel="noopener"` fix,
  `copyToClipboard` rewrite

### Fixed

- Orbitron font applied consistently to footer credits and copyright across all landing
  pages

---

## [0.1.1] — 2026-05-17

### Added

- CI pipeline: branch-based release flow — `dev` builds pre-releases, `main` triggers
  full releases via goreleaser
- Bilingual source code and scripts (all comments and identifiers translated to English)
- CI: updated GitHub Actions to Node 24 (`checkout@v6`, `setup-go@v6`,
  `goreleaser-action@v7`)

---

## [0.1.0] — initial release

### Added

- Core pipeline: `TailReader` → whitelist → tracker → scorer → threat logger
- 7 detectors: probe, rate, useragent, bruteforce, crawler, noasset, overflow
- Bot DNS verification: Googlebot, Bingbot, Yandex, DuckDuckGo verified via rDNS/fDNS
- Whitelist: custom IPs, CIDRs, UA substrings; fake-bot penalty
- Linear score decay over configurable `observation_window`
- SIGHUP config reload without daemon restart
- Graceful shutdown with line-buffer drain on SIGTERM
- Prometheus-compatible `/metrics` endpoint (added in 0.2.0)
- Packaging: `.deb`, `.rpm`, `.pkg.tar.zst` via goreleaser; systemd unit, logrotate,
  Fail2Ban filter/jail included
- Fail2Ban integration: `failregex` matching the threat-log format

[1.0.0]: https://github.com/mr-addams/arxsentinel/compare/v0.3.0...v1.0.0
[0.3.0]: https://github.com/mr-addams/arxsentinel/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/mr-addams/arxsentinel/compare/v0.1.3...v0.2.0
[0.1.3]: https://github.com/mr-addams/arxsentinel/compare/v0.1.1...v0.1.3
[0.1.1]: https://github.com/mr-addams/arxsentinel/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/mr-addams/arxsentinel/releases/tag/v0.1.0
