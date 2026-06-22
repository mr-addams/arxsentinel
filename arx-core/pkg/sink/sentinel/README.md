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
| `name` | string | yes | – | Sink name passed to executor.AttachWriter |
| `bufferSize` | int | no | 0 (default queue size) | Bounded channel capacity for executor queue |

Validation: `name` validated for non-empty inside `NewSentinelThreatSink`.

## Behaviour Details

- **Startup:** `NewSentinelThreatSink(name, bufferSize)` calls `executor.AttachWriter(name, bufferSize)`. If `bufferSize == 0`, executor uses its internal default.
- **Write:** Calls `q.Push(ctx, event)` on the executor queue. If `ErrQueueFull` → `dropped++` and returns `nil` (silent drop).
- **Drop Policy:** Silent drop when queue is full — no error propagated to caller.
- **No Metrics for EventsWritten:** `Stats()` only returns `Dropped`; `EventsWritten` is not tracked.
- **No Output Format:** Raw `ThreatEvent` passed to queue — no serialization.

## Close / Shutdown

- `Close()` calls `executor.DetachWriter(name)` — removes sink from executor registry.

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

## Inter-Pipeline Routing

This sink is the **output half** of the Named Channel Switch bridge. Any
`plugin.ThreatEvent` written here is consumed by whichever reader attaches
to the same name. There is no "inter-pipeline" config knob — the routing
falls out of the NCS map. Three concrete topologies are supported.

### Pipeline A → Pipeline B (the canonical bridge)

Pipeline A writes ThreatEvents to a named NCS queue; Pipeline B reads them
back through a `sentinel` source. The two pipelines can be:

- Two `streams[]` blocks inside the same ArxSentinel process (the
  in-process case, queue backend defaults to `memory`).
- Two separate ArxSentinel processes pointing at the same `bbolt` file
  or the same `redis` key.

```yaml
# pipeline-a.yaml — writes
outputs:
  - plugin: sentinel-threat
    name: inter-pipeline
    bufferSize: 1000
```

```yaml
# pipeline-b.yaml — reads
inputs:
  - type: sentinel
    addr: ncs://inter-pipeline
```

The sink's `name:` field must equal the source's `addr:` field
(`ncs://<name>`). The wiring validator
(`pkg/pipeline/validator.go:ValidateExecutorWiring`) catches a mismatch
at startup.

### Same-process fan-in

A single pipeline can both write and read the NCS through this sink
and its sibling `sentinel` source. Useful for routing ThreatEvents
from one detector chain into a second, specialised chain (e.g. only
high-score events into a stricter scorer). See
`pkg/source/sentinel/README.md` for the full example.

### Plugin-only routing chain

A pipeline whose only job is to forward events from one NCS queue to
another — a routing layer in front of multiple specialised downstream
pipelines. The pipeline declares a `sentinel` source (reads from NCS)
and a `sentinel-threat` sink (writes to NCS); the rest of the
processing chain is empty.

### Operational notes

- The sink **does not own queue lifecycle in the bbolt/redis case**
  (`AttachWriterWithQueue` is used by `RegisterSinkFromConfig`); the
  pre-registered queue from `preRegisterExecutorQueues` outlives the
  sink. The sink still calls `DetachWriter` on `Close()` to decrement
  the writer refcount, but the queue itself is closed by the last
  `DetachWriter`, not by this sink in isolation.
- The default `bufferSize: 0` means "use the executor's default". For
  pipeline-to-pipeline scenarios where the downstream reader is in a
  different process, set an explicit `bufferSize` (e.g. `1000`) to
  avoid blocking the pipeline when the reader briefly falls behind.
- For the full NCS contract, see `pkg/executor/README.md`. For the
  queue backend selection guide, see `pkg/executor/queue/README.md`.

## Dependencies

- `pkg/executor` — AttachWriter, DetachWriter, queue.Queue
- `pkg/executor/queue` — Queue interface, ErrQueueFull
- `pkg/plugin` — Manifest, ThreatEvent, SinkStats
- `pkg/sink` — pkgsink register helpers
