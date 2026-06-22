# pkg/sink/stdout — Stdout Sink

The `stdout` sink writes scored `plugin.ThreatEvent` records directly to
the arx-core process's standard output in one of three formats:
`fail2ban`, `json`, or `sentinel-threat`. Use it for interactive
debugging, piping scored events into shell tooling (`jq`, `grep`, log
shippers), and containerised deployments where stdout is the canonical
log stream. A test-only constructor accepts any `*os.File` so unit tests
can capture writes without touching the real process stdout.

## Plugin identity

| Field          | Value                    |
|----------------|--------------------------|
| PluginID       | `stdout`                 |
| PluginVersion  | `1.0.0`                  |
| Role           | `plugin.RoleSink`        |
| InputType      | `plugin.TypeScoredEvent` |
| OutputType     | `plugin.TypeNone`        |
| Tags           | `["stdout", "console"]`  |

## Configuration

| Field    | Type   | Required | Description                                                      |
|----------|--------|----------|------------------------------------------------------------------|
| `Format` | string | yes      | One of `fail2ban`, `json`, `sentinel-threat`. Unknown values are rejected at construction. |

## Public API

```go
// StdoutSink writes threat events to an *os.File (typically os.Stdout)
// in a fixed output format. Safe for concurrent Write calls — the
// underlying file write is serialised through an internal mutex.
type StdoutSink struct { /* unexported */ }

// NewStdoutSink returns a StdoutSink writing to os.Stdout in format.
// Returns an error if format is not one of fail2ban | json | sentinel-threat.
func NewStdoutSink(format string) (*StdoutSink, error)

// NewStdoutSinkWithWriter returns a StdoutSink writing to w in format.
// Test helper — inject a pipe or temp file to capture output without
// touching the real process stdout.
func NewStdoutSinkWithWriter(w *os.File, format string) (*StdoutSink, error)

func (s *StdoutSink) Name() string                       // always "stdout"
func (s *StdoutSink) Write(ctx context.Context, event plugin.ThreatEvent) error
func (s *StdoutSink) Close() error                       // no-op
func (s *StdoutSink) Stats() plugin.SinkStats            // EventsWritten, Dropped, Errors
func (s *StdoutSink) Manifest() plugin.Manifest
```

`Close` is intentionally a no-op — the process owns `os.Stdout`, not the
sink. `Write` accepts a `context.Context` to satisfy `plugin.Sink` but
does not honour cancellation: stdout writes are short syscalls serialised
through a mutex, so cancellation would add complexity without changing
observable behaviour.

## Registration

```go
func init() {
    pkgsink.Register("stdout", func(_ context.Context, cfg pkgsink.SinkConfig) (plugin.Sink, error) {
        return NewStdoutSink(cfg.Format)
    })
    pkgsink.RegisterManifest("stdout", (&StdoutSink{}).Manifest())
}
```

The factory passes `cfg.Format` straight to `NewStdoutSink`; an invalid
format is rejected at construction with a descriptive error rather than
silently producing zero output.

## Counters

| Counter         | Source         | Notes                                       |
|-----------------|----------------|---------------------------------------------|
| `EventsWritten` | `atomic.Int64` | Incremented after each successful write     |
| `Dropped`       | `atomic.Int64` | Always 0 — no buffering, no drop path       |
| `Errors`        | `atomic.Int64` | Marshalling or write failures               |

## Example

```yaml
sinks:
  - type: stdout
    format: json
```

Pipe the resulting JSON stream through `jq` for human-readable inspection
in development, or redirect to a file and let the host's log-rotation
infrastructure handle retention:

```bash
arx-core --config ./config.yaml | jq .
arx-core --config ./config.yaml >> /var/log/arx-core/threats.json
```

## Dependencies

- `pkg/plugin` — `Sink`, `SinkStats`, `ThreatEvent`, `Manifest`.
- `pkg/sink` — `Register`, `RegisterManifest`, `SinkConfig`.
- `pkg/sink/format` — `FormatFailban`, `FormatJSON`, `FormatSentinelThreat` helpers.
- Standard library: `os`, `sync`, `sync/atomic`, `context`, `fmt`.