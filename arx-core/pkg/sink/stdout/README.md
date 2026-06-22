# pkg/sink/stdout — Stdout Sink

StdoutSink writes threat events directly to the process standard output in one of three formats (fail2ban, JSON, or Sentinel-threat NDJSON). Used for debugging, piping to external tools, or containerised deployments where stdout is the log stream. Supports an injectable writer for testing.

The pipeline calls `Write` for every scored event that reaches the sink stage. The consumer is whatever process or pipeline reads `os.Stdout` of the Arxsentinel daemon (a shell pipe, a log shipper, a container runtime, or a developer terminal).

## Plugin Identity

| Field | Value |
|-------|-------|
| PluginID | `"stdout"` |
| Version | `v1.0.0` |
| Role | `RoleSink` |
| Input | `TypeScoredEvent` |
| Output | `TypeNone` |
| Tags | `["stdout", "console"]` |

## Module Layout

```
pkg/sink/stdout/
├── manifest.go          # Manifest() method
├── register.go          # init() registration, factory
├── sink.go              # StdoutSink struct, NewStdoutSink, Write, Close, Stats
├── sink_test.go         # Unit tests (151 lines)
```

## Configuration Reference

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `format` | string | yes | – | Output format: `"fail2ban"`, `"json"`, or `"sentinel-threat"` |

## Behaviour Details

- **Startup:** `NewStdoutSink(format)` creates sink with `os.Stdout` as writer. `NewStdoutSinkWithWriter(w, format)` allows injecting any `*os.File` for tests.
- **Write:** Switch on format (same three formats as file sink). Mutex-locked write to underlying file handle.
- **Drop Policy:** No drop — if write fails, error is returned and `Errors` counter incremented.
- **Close:** No-op — stdout is never closed by the sink.

## Close / Shutdown

- `Close()` is a no-op — the process owns `os.Stdout`.

## Metrics and Stats

| Counter | Type | Description | Incremented When |
|---------|------|-------------|------------------|
| `EventsWritten` | atomic.Int64 | Events successfully written | After each successful write |
| `Dropped` | atomic.Int64 | Events dropped (always 0) | Never incremented (no drop path) |
| `Errors` | atomic.Int64 | Write errors | On write failure |

## Constructors

```go
func NewStdoutSink(format string) *StdoutSink
func NewStdoutSinkWithWriter(w *os.File, format string) *StdoutSink  // test helper
```

## Registration

```go
func init() {
    pkgsink.Register("stdout", factory)
    pkgsink.RegisterManifest("stdout", manifest)
}
// factory: NewStdoutSink(cfg.Format)
```

The `init()` function registers both the factory and the manifest with the central `pkgsink` registry. The factory passes `cfg.Format` directly to `NewStdoutSink`.

## Quick-Start Example

```yaml
sinks:
  - plugin: stdout
    format: json
```

```bash
# Pipe JSON threats to jq for human-readable inspection
arxsentinel --config /etc/arxsentinel/config.yaml | jq .

# Or to a file with rotation by the OS logrotate
arxsentinel --config /etc/arxsentinel/config.yaml >> /var/log/arxsentinel/threats.json
```

## Tests

- 151 lines of unit tests in `sink_test.go`.
- Tests use `NewStdoutSinkWithWriter` to inject a pipe or temp file.

## Dependencies

- Standard library: `os`, `sync`, `sync/atomic`
- `pkg/plugin` — Manifest, ThreatEvent, SinkStats
- `pkg/sink` — pkgsink register helpers
