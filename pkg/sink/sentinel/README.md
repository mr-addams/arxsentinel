# pkg/sink/sentinel — Sentinel-Threat Sink

SentinelThreatSink bridges scored events into the Sentinel Hub executor subsystem. It pushes events to a bounded queue managed by the executor — if the queue is full, events are silently dropped (back-pressure). Used for internal event pipeline where Sentinel Hub consumes threats from the queue.

The pipeline calls `Write` for every scored event that reaches the sink stage. The consumer is the executor queue inside the Sentinel Hub; the sink does not own queue lifecycle — it registers and unregisters itself with the executor subsystem.

## Plugin Identity

| Field | Value |
|-------|-------|
| PluginID | `"sentinel-threat"` |
| Version | `v1.0.0` |
| Role | `RoleSink` |
| Input | `TypeScoredEvent` |
| Output | `TypeNone` |
| Tags | `["sentinel", "hub-bridge", "executor-queue"]` |

## Module Layout

```
pkg/sink/sentinel/
├── manifest.go          # Manifest() method
├── register.go          # init() registration, factory
├── sink.go              # SentinelThreatSink struct, New, Write, Close, Stats
```

## Configuration Reference

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | yes | – | Sink name passed to executor.RegisterSink |
| `bufferSize` | int | no | 0 (default queue size) | Bounded channel capacity for executor queue |

Validation: `name` validated for non-empty inside `NewSentinelThreatSink`.

## Behaviour Details

- **Startup:** `NewSentinelThreatSink(name, bufferSize)` calls `executor.RegisterSink(name, bufferSize)`. If `bufferSize == 0`, executor uses its internal default.
- **Write:** Calls `q.Push(ctx, event)` on the executor queue. If `ErrQueueFull` → `dropped++` and returns `nil` (silent drop).
- **Drop Policy:** Silent drop when queue is full — no error propagated to caller.
- **No Metrics for EventsWritten:** `Stats()` only returns `Dropped`; `EventsWritten` is not tracked.
- **No Output Format:** Raw `ThreatEvent` passed to queue — no serialization.

## Close / Shutdown

- `Close()` calls `executor.Unregister(name)` — removes sink from executor registry.

## Metrics and Stats

| Counter | Type | Description | Incremented When |
|---------|------|-------------|------------------|
| `Dropped` | atomic.Int64 | Events dropped due to full queue | On `ErrQueueFull` from `q.Push` |

> Note: No `EventsWritten` counter — total pushed events are not tracked.

## Constructors

```go
func NewSentinelThreatSink(name string, bufferSize int) *SentinelThreatSink
```

## Registration

```go
func init() {
    pkgsink.Register("sentinel-threat", factory)
    pkgsink.RegisterManifest("sentinel-threat", manifest)
}
// factory: NewSentinelThreatSink(cfg.Name, 0) — bufferSize hardcoded to 0
```

The `init()` function registers both the factory and the manifest with the central `pkgsink` registry. The factory calls `NewSentinelThreatSink` with `bufferSize` hardcoded to `0` (executor uses its internal default queue size).

## Quick-Start Example

```yaml
sinks:
  - plugin: sentinel-threat
    name: hub-main
```

```bash
# Events flow into the executor queue; Sentinel Hub consumes from there
arxsentinel --config /etc/arxsentinel/config.yaml
```

## Dependencies

- `pkg/executor` — RegisterSink, Unregister, queue.Queue
- `pkg/executor/queue` — Queue interface, ErrQueueFull
- `pkg/plugin` — Manifest, ThreatEvent, SinkStats
- `pkg/sink` — pkgsink register helpers
