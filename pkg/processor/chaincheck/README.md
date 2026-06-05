# pkg/processor/chaincheck — ChainCheck Processor

ChainCheckProcessor enriches log entries with proxy-chain metadata — it checks the real client IP against Cloudflare CIDR ranges and bogon address lists. It never drops entries; instead it sets `entry.ChainIssue` with the detection result. Used upstream of scoring to tag traffic from known proxies or invalid source addresses.

The pipeline calls `Process` for every structured log entry that reaches the processor stage. The consumer is the next stage in the pipeline (typically a scoring detector) — it reads `entry.ChainIssue` to inform its decision.

## Plugin Identity

| Field | Value |
|-------|-------|
| PluginID | `"chaincheck"` |
| Version | `v1.0.0` |
| Role | `RoleProcessor` |
| Input | `TypeStructured` |
| Output | `TypeStructured` |
| Tags | `["enrichment", "proxy-chain", "infrastructure"]` |

## Module Layout

```
pkg/processor/chaincheck/
├── manifest.go          # Manifest() method
├── processor.go         # ChainCheckProcessor struct, New, Process
├── register.go          # init() registration, param extraction helpers
```

## Configuration Reference

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `cloudflare_enabled` | bool | no | `false` | Enable Cloudflare CIDR matching |
| `bogon_enabled` | bool | no | `true` | Enable bogon address detection |
| `cloudflare_refresh_interval` | duration | no | `24h` | Interval to refresh Cloudflare CIDR list |
| `cloudflare_sources` | []string | no | cloudflare.com ips-v4, ips-v6 | URLs for Cloudflare CIDR lists |

Parameters passed via `map[string]any` in processor factory.

## Behaviour Details

- **Input:** `*plugin.LogEntry` with `RealIP` (primary) or `RemoteAddr` (fallback).
- **Process:**
  1. Parse IP address from entry.
  2. If `cloudflare_enabled` and IP matches Cloudflare CIDR → `entry.ChainIssue = "cloudflare:ip/cidr"`.
  3. If `bogon_enabled` and IP is bogon → `entry.ChainIssue = "bogon:ip"`.
  4. Always returns `(entry, nil)` — enrichment only, no drop.
- **Bogon explanation (for operators):** Bogon = non-public / reserved IP addresses that should never appear as the client IP in access logs of a production server. If they do appear, the proxy chain is broken (the `real_ip_header` is misconfigured or not set). Concrete ranges from `bogon.go`:
  - RFC 1918: `10/8`, `172.16/12`, `192.168/16`
  - CGNAT (RFC 6598): `100.64/10` — commonly seen when an ISP uses Carrier-Grade NAT
  - Loopback: `127/8`, `::1/128`
  - Link-local: `169.254/16`, `fe80::/10`
  - Documentation: `192.0.2/24`, `198.51.100/24`, `203.0.113/24`
  - Unspecified/reserved: `0/8`, `240/4`
  - IPv6 unique local (RFC 4193): `fc00::/7`
  For an operator: **a bogon is always a problem** with the proxy-chain configuration or a broken `real_ip_header`.
- **Behaviour on Cloudflare refresh failure (graceful degradation):**
  - On startup: the fallback list is loaded synchronously in `NewCloudflareChecker` (`cloudflare.go:124`) — `c.nets = parseCIDRList(append(fallbackCloudflareV4, fallbackCloudflareV6...))`. `IsLoaded()` returns true immediately — it does not wait for the first HTTP request.
  - In the background: refresh runs on a ticker. If a fetch fails, the error is logged via `utils.Log`, but `nets` are not replaced.
  - If **all sources are down** (`len(collected)==0`, `cloudflare.go:236-240`): the function `return`s without replacing — the old list is preserved (*"graceful degradation, not empty list"*).
  - Mechanism: `sync.RWMutex` protects `c.nets` — reads (`Contains`) only block each other (`RLock`), writes (`fetchAll`) are exclusive (`Lock`).
  - **Conclusion:** on a refresh error, **the old cache is preserved** (fallback or last successful fetch). There is no degradation to an empty list and no blocking of checks.
- **Cloudflare CIDR Refresh:** Background refresh at configurable interval; sources are HTTP URLs returning CIDR lists.
- **Checker:** Uses `internal/core/chaincheck.Checker` for actual CIDR matching.

## Close / Shutdown

- No explicit `Close()` — processor has no persistent resources.

## Metrics and Stats

- No metrics counters declared in the processor interface.
- ChainCheckProcessor does not implement `Stats()`.

## Constructors

```go
func NewChainCheckProcessor(cfg chaincheck.Config) (*ChainCheckProcessor, error)
```

## Registration

```go
func init() {
    processor.Register("chaincheck", factory)
}
// factory: extracts params via boolParam, durationParam, stringSliceParam helpers
// compile-time checks: var _ processor.Factory = factory; var _ plugin.Processor = (*ChainCheckProcessor)(nil)
```

The `init()` function registers the factory with the central `processor` registry. The factory extracts typed parameters from the raw `map[string]any` configuration using safe helpers.

## Helper Functions (register.go)

- `boolParam(params, key, default)` — safe bool extraction with fallback
- `durationParam(params, key, default)` — safe time.Duration extraction with fallback
- `stringSliceParam(params, key, default)` — safe []string extraction with fallback

## Quick-Start Example

```yaml
processors:
  - plugin: chaincheck
    cloudflare_enabled: true
    bogon_enabled: true
    cloudflare_refresh_interval: 24h
    cloudflare_sources:
      - https://www.cloudflare.com/ips-v4
      - https://www.cloudflare.com/ips-v6
```

```bash
# Chaincheck enriches every entry with proxy-chain info before scoring
arxsentinel --config /etc/arxsentinel/config.yaml
```

## Dependencies

- `internal/core/chaincheck` — Checker, Config
- `pkg/plugin` — Manifest, LogEntry, Processor
- `pkg/processor` — processor register
