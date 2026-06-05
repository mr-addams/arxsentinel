# pkg/processor/whitelist — Whitelist Processor

WhitelistProcessor filters out known-good traffic — whitelisted IPs, whitelisted user-agents, and verified legitimate bots. It drops entries that match whitelist rules, passes through entries for scoring if they match fake-bot patterns, and leaves unmatched entries untouched. Used as a first-stage filter to reduce noise in threat scoring.

The pipeline calls `Process` for every structured log entry that reaches the processor stage. The consumer is the next stage in the pipeline (typically a scoring detector) — it receives only entries that survived whitelist filtering.

## Plugin Identity

| Field | Value |
|-------|-------|
| PluginID | `"whitelist"` |
| Version | `v1.0.0` |
| Role | `RoleProcessor` |
| Input | `TypeStructured` |
| Output | `TypeStructured` |
| Tags | `["filter", "whitelist", "bot-verification"]` |

## Module Layout

```
pkg/processor/whitelist/
├── manifest.go          # var Manifest (package-level, not method)
├── processor.go         # WhitelistProcessor struct, New, Name, Manifest, Process
├── register.go          # init() registration, param extraction with panic recovery
```

## Configuration Reference

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `whitelist_config` | `config.WhitelistConfig` | yes | – | Whitelist rules (IPs, UAs, bot patterns) |
| `resolver` | `whitelist.Resolver` | yes | – | DNS resolver for bot verification (injectable) |

## Behaviour Details

- **Pipeline semantics:**
  - `(nil, nil)` → **drop** the entry (whitelisted)
  - `(*LogEntry, nil)` → **pass through** for scoring
- **Process stages (sequential):**
  1. `IsWhitelistedIP(entry.RealIP)` → if match → drop (`nil, nil`)
  2. `IsWhitelistedUA(entry.UserAgent)` → if match → drop (`nil, nil`)
  3. `MatchBot(entry)` → if match (potential bot) → DNS Verify via Verifier:
     - Verified **real bot** → drop (`nil, nil`)
     - **Fake bot** (DNS mismatch) → pass through for scoring (`entry, nil`)
  4. No match at all → pass through (`entry, nil`)
- **DNS Verification:** Uses `corewhitelist.Verifier` with configurable `dnsTimeout`. Production resolver: `net.Resolver{PreferGo: true}`.

## Close / Shutdown

- No explicit `Close()`.

## Metrics and Stats

- No metrics counters declared. WhitelistProcessor does not implement `Stats()`.

## Constructors

```go
func NewWhitelistProcessor(cfg config.WhitelistConfig, resolver corewhitelist.Resolver) (*WhitelistProcessor, error)
```

## Registration

```go
func init() {
    processor.Register("whitelist", factory)
}
// factory: extracts "whitelist_config" (config.WhitelistConfig) and "resolver" (whitelist.Resolver)
//          from params map[string]any. Uses panic recovery (defer recover).
```

The `init()` function registers the factory with the central `processor` registry. The factory extracts typed parameters from the raw `map[string]any` configuration by parameter key, wrapped in panic recovery for safety.

## Constants (register.go)

- `ParamKeyWhitelistConfig = "whitelist_config"`
- `ParamKeyResolver = "resolver"`

## Quick-Start Example

```yaml
processors:
  - plugin: whitelist
    whitelist_config:
      ips:
        - 10.0.0.0/8
      user_agents:
        - "internal-monitor/1.0"
      bot_patterns:
        - "Googlebot"
        - "bingbot"
      dns_timeout: 2s
```

```bash
# Whitelist filters out known-good traffic before scoring runs
arxsentinel --config /etc/arxsentinel/config.yaml
```

## Dependencies

- `internal/core/whitelist` — Matcher, Verifier, IPCache, Resolver
- `internal/sys/config` — WhitelistConfig
- `pkg/plugin` — Manifest, LogEntry, Processor
- `pkg/processor` — processor register
- Standard library: `net` (for production resolver)
