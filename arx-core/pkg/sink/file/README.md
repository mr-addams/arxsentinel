# pkg/sink/file — File sink

`FileSink` writes threat events to a file on disk in one of three
formats (fail2ban line, JSON, or sentinel-threat NDJSON). The sink
supports log rotation via `Reload()`, which closes and reopens the
file. Use it for forensic storage, integration with fail2ban-style
consumers, or persistent event logs.

The pipeline calls `Write` for every scored event that reaches the
sink stage. The sink owns the file handle for its lifetime, rotates
it on `Reload()`, and closes it on `Close()`.

## Plugin identity

| Field | Value |
|---|---|
| `PluginID` | `"file"` |
| `PluginVersion` | `1.0.0` |
| `Role` | `plugin.RoleSink` |
| `Input` | `plugin.TypeScoredEvent` |
| `Output` | `plugin.TypeNone` |
| `Tags` | `["file", "fail2ban", "json", "log-rotation"]` |

## Package layout

```
pkg/sink/file/
├── manifest.go   # Manifest() method
├── register.go   # init() registration and factory
└── sink.go       # FileSink struct, NewFileSink, Write, Close, Reload
```

## Configuration

| Field | Type | Required | Description |
|---|---|---|---|
| `path` | string | yes | Filesystem path to the output file. |
| `format` | string | yes | Output format: `"fail2ban"`, `"json"`, or `"sentinel-threat"`. |

Validation:

- `path != ""` — enforced in `NewFileSink`.
- `format` must be one of `"fail2ban"`, `"json"`, `"sentinel-threat"` —
  validated in `NewFileSink`.

## Behaviour

- **Startup.** `NewFileSink(path, format)` validates the parameters and
  calls `openSinkFile(path)`, which opens with
  `os.OpenFile(O_CREATE|O_APPEND|O_WRONLY, 0644)`. The parent directory
  is auto-created via `MkdirAll(..., 0755)` if it does not exist.
- **Write.** Switches on `format` (`FormatJSON`, `FormatSentinelThreat`,
  `FormatFail2Ban` as default). The shared file handle is protected by
  a mutex. If the handle is `nil` (closed between format and lock
  acquisition, e.g. after a `Reload` error), the event is dropped and
  the `Dropped` counter is incremented.
- **Log rotation.** `Reload()` closes the current file handle and
  reopens it. Call it externally when the operator wants to rotate
  logs (typically in response to `SIGHUP` or a configuration change).
- **Close.** Acquires the mutex, calls `Sync()` + `Close()` on the
  file, and sets the handle to `nil`.

## Public API

```go
type FileSink struct{ /* unexported fields */ }

func NewFileSink(path, format string) (*FileSink, error)
func (s *FileSink) Name() string
func (s *FileSink) Write(ctx context.Context, event plugin.ThreatEvent) error
func (s *FileSink) Close() error
func (s *FileSink) Reload() error
func (s *FileSink) Stats() plugin.SinkStats
func (s *FileSink) Manifest() plugin.Manifest
```

`ctx` is accepted to satisfy `plugin.Sink` but is intentionally unused:
file I/O here is a single short syscall bounded by the mutex, so
cancellation has no meaningful target.

## Registration

```go
func init() {
    pkgsink.Register("file", factory)
    pkgsink.RegisterManifest("file", manifest)
}
// factory: NewFileSink(cfg.Path, cfg.Format)
```

The `init()` function registers both the factory and the manifest with
the central sink registry (`pkg/sink`). The factory passes `cfg.Path`
and `cfg.Format` directly to `NewFileSink`.

## Configuration example

```yaml
sinks:
  - plugin: file
    path: /var/log/myservice/threats.log
    format: sentinel-threat
```

## Log rotation example

```bash
# Trigger log rotation by sending SIGHUP to the host process.
kill -HUP $(pidof myservice)
```

## Dependencies

- Standard library — `os`, `sync`, `sync/atomic`.
- `pkg/plugin` — `Manifest`, `ThreatEvent`, `SinkStats`.
- `pkg/sink` — sink registry helpers.
- `pkg/sink/format` — `FormatJSON`, `FormatSentinelThreat`, `FormatFail2Ban`.
