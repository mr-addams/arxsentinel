# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.2.0]: https://github.com/mr-addams/nginx-sentinel/compare/v0.1.3...v0.2.0
[0.1.3]: https://github.com/mr-addams/nginx-sentinel/compare/v0.1.1...v0.1.3
[0.1.1]: https://github.com/mr-addams/nginx-sentinel/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/mr-addams/nginx-sentinel/releases/tag/v0.1.0
