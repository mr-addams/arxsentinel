# pkg/sink/file — File Sink

FileSink writes threat events to a file on disk in one of three formats (fail2ban, JSON, or Sentinel-threat NDJSON). Supports log rotation via SIGHUP-triggered `Reload()`. Used for forensic storage, fail2ban integration, or as a persistent event log.

The pipeline calls `Write` for every scored event that reaches the sink stage. The consumer is the file on disk; the sink owns the file handle for its lifetime, rotates it on `Reload()`, and closes it on `Close()`.

## Plugin Identity

| Field | Value |
|-------|-------|
| PluginID | `"file"` |
| Version | `v1.0.0` |
| Role | `RoleSink` |
| Input | `TypeScoredEvent` |
| Output | `TypeNone` |
| Tags | `["file", "fail2ban", "json", "log-rotation"]` |

## Module Layout

```
pkg/sink/file/
├── manifest.go          # Manifest() method
├── register.go          # init() registration, factory
├── sink.go              # FileSink struct, NewFileSink, Write, Close, Reload
```

## Configuration Reference

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `path` | string | yes | – | Filesystem path to output file |
| `format` | string | yes | – | Output format: `"fail2ban"`, `"json"`, or `"sentinel-threat"` |

Validation:
- `path != ""` — enforced in `NewFileSink`
- `format` must be one of: `"fail2ban"`, `"json"`, `"sentinel-threat"` — validated

## Behaviour Details

- **Startup:** `NewFileSink(path, format)` validates parameters, calls `openSinkFile(path)` which opens with `os.OpenFile(CREATE|APPEND|WRONLY, 0644)`. Parent directory auto-created via `ensureSinkDir` → `MkdirAll(0755)`.
- **Write:** Switch on `format` (`FormatJSON`, `FormatSentinelThreat`, `FormatFail2Ban` as default). Mutex-locked write to `*os.File`. If `f == nil` → event is silently dropped (counter `Dropped++`).
- **Drop Policy:** Events dropped only when file handle is nil.
- **Log Rotation:** `Reload()` closes current file and reopens. Called externally on SIGHUP.

## Close / Shutdown

- `Close()` acquires mutex, calls `Sync()` + `Close()` on file, sets `f = nil`.

## Metrics and Stats

| Counter | Type | Description | Incremented When |
|---------|------|-------------|------------------|
| `EventsWritten` | atomic.Int64 | Events successfully written to file | After each successful write |
| `Dropped` | atomic.Int64 | Events dropped due to nil file handle | On nil `f` path in Write |
| `Errors` | atomic.Int64 | Write errors | On file write error |

## Constructors

```go
func NewFileSink(path, format string) (*FileSink, error)
```

## Registration

```go
func init() {
    pkgsink.Register("file", factory)
    pkgsink.RegisterManifest("file", manifest)
}
// factory: NewFileSink(cfg.Path, cfg.Format)
```

The `init()` function registers both the factory and the manifest with the central `pkgsink` registry. The factory passes `cfg.Path` and `cfg.Format` directly to `NewFileSink`.

## Quick-Start Example

```yaml
sinks:
  - plugin: file
    path: /var/log/arxsentinel/threats.log
    format: sentinel-threat
```

```bash
# Send SIGHUP to rotate the log file
kill -HUP $(pidof arxsentinel)
```

## Dependencies

- Standard library: `os`, `sync`, `sync/atomic`
- `pkg/plugin` — Manifest, ThreatEvent, SinkStats
- `pkg/sink` — pkgsink register helpers
