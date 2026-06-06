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
- **DNS timeout path (what is returned):** `MatchBot` is called in `processor.go:83` — when the User Agent matches a bot pattern. `Verify` is run with `context.WithTimeout(context.Background(), p.dnsTimeout)` (`processor.go:84`). DNS timeout → PTR lookup (`LookupAddr`) or fDNS (`LookupHost`) returns an error. `verifyRDNS()` returns `false` (`verifier.go:160-164`, `180-184`) → `verified=false`, `isFakeBot=true` (for `rdns` / `rdns_ipjson`). **Critical:** `processor.go` **does not check the result of `Verify`** (line 86: return values are ignored!). It always returns `entry, nil` (`processor.go:89`) — **pass-through**. DNS timeout → the entry flows downstream (is not dropped). This is intentional: `FakeBotScore` is assigned by downstream detectors, not here.
- **Panic recovery in factory (register.go):** The factory (`register.go:33-49`) is wrapped in `defer recover()`. Reason: the factory performs a **type assertion from `map[string]any`**: `cfg.Params[ParamKeyWhitelistConfig].(config.WhitelistConfig)` (line 40) and `cfg.Params[ParamKeyResolver].(corewhitelist.Resolver)` (line 44). If params do not contain the correct types — the type assertion panics. Without `recover`: a panic in an `init()`-registered factory would kill the whole process on startup. With `recover`: the panic is converted into a returned `err` (`fmt.Errorf("whitelist: factory panic: %v", r)`), so the process can start without this processor (or emit a meaningful error). **Where it lives:** in `register.go`, not in `processor.go`, because this protects the entry point — the factory is called by the registry infrastructure, and a panic there is not controlled by the caller.

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
