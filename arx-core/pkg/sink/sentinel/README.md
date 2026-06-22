# pkg/sink/sentinel — Queue-bridge sink

`SentinelThreatSink` is a sink plugin that bridges scored events into
another component via the executor queue (`pkg/ncs` / `pkg/executor/queue`).
It pushes events to a bounded queue — if the queue is full, events are
silently dropped (back-pressure). The plugin is consumed by a separate
process or goroutine that reads from the same named queue.

The pipeline calls `Write` for every scored event that reaches the
sink stage. The sink does not own the queue lifecycle — it registers
and unregisters itself through `pkg/ncs`.

## Plugin identity

| Field | Value |
|---|---|
| `PluginID` | `"sentinel-threat"` |
| `PluginVersion` | `1.0.0` |
| `Role` | `plugin.RoleSink` |
| `Input` | `plugin.TypeScoredEvent` |
| `Output` | `plugin.TypeNone` |
| `Tags` | `["sentinel", "hub-bridge", "executor-queue"]` |

## Package layout

```
pkg/sink/sentinel/
├── manifest.go   # Manifest() method
├── register.go   # init() registration and factory
└── sink.go       # SentinelThreatSink struct, New, Write, Close, Stats
```

## Configuration

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `name` | string | yes | — | Queue name passed to `ncs.AttachWriter`. |
| `bufferSize` | int | no | `0` (default queue size) | Bounded channel capacity for the executor queue. |

Validation: `name` is checked for non-empty inside `NewSentinelThreatSink`.

## Behaviour

- **Startup.** `NewSentinelThreatSink(name, bufferSize)` calls
  `ncs.AttachWriter(name, bufferSize)`. When `bufferSize == 0`, the
  NCS applies its internal default.
- **Write.** Calls `q.Push(ctx, event)` on the executor queue. If
  `queue.ErrQueueFull` is returned, the sink increments its dropped
  counter and returns `nil` — silent drop, no error propagation.
- **Back-pressure.** The dropped counter is incremented per dropped
  event; nothing else changes.
- **Close.** `Close()` calls `ncs.DetachWriter(name)` to decrement the
  writer reference count. The queue is closed when the last sink
  deregisters.

## Public API

```go
type SentinelThreatSink struct{ /* unexported fields */ }

func NewSentinelThreatSink(name string, bufferSize int) (*SentinelThreatSink, error)
func (s *SentinelThreatSink) Name() string
func (s *SentinelThreatSink) Write(ctx context.Context, event plugin.ThreatEvent) error
func (s *SentinelThreatSink) Close() error
func (s *SentinelThreatSink) Stats() plugin.SinkStats
func (s *SentinelThreatSink) Manifest() plugin.Manifest
```

## Registration

```go
func init() {
    pkgsink.Register("sentinel-threat", factory)
    pkgsink.RegisterManifest("sentinel-threat", manifest)
}
// factory: NewSentinelThreatSink(cfg.Name, 0) — bufferSize is hard-coded to 0.
```

The `init()` function registers both the factory and the manifest with
the central sink registry (`pkg/sink`). The factory ignores `ctx` and
constructs the sink with `bufferSize = 0`, leaving queue sizing to NCS.

## Inter-component routing

This sink is the **output half** of the Named Channel Switch bridge.
Any `plugin.ThreatEvent` written here is consumed by whichever reader
attaches to the same name. There is no extra configuration knob —
routing falls out of the NCS map. Three concrete topologies:

### Component A → Component B (the canonical bridge)

Component A writes threat events to a named NCS queue; Component B
reads them back through a corresponding source. The two components can
be:

- Two `streams[]` blocks inside the same arx-core process (the
  in-process case — queue backend defaults to `memory`).
- Two separate arx-core processes pointing at the same `bbolt` file
  or the same `redis` key.

The sink's `name:` field must equal the source's `addr:` field
(`ncs://<name>`). The wiring validator catches a mismatch at startup.

### Same-process fan-in

A single pipeline can both write and read the NCS through this sink
and its sibling source. Useful for routing threat events from one
detector chain into a second, specialised chain (for example, only
high-score events into a stricter scorer).

### Plugin-only routing chain

A pipeline whose only job is to forward events from one NCS queue to
another — a routing layer in front of multiple specialised downstream
pipelines. The pipeline declares a source (reads from NCS) and a
`SentinelThreatSink` (writes to NCS); the rest of the processing chain
is empty.

### Operational notes

- The sink **does not own queue lifecycle in the bbolt/redis case**
  (`AttachWriterWithQueue` is used by `RegisterSinkFromConfig`); the
  pre-registered queue outlives the sink. The sink still calls
  `DetachWriter` on `Close()` to decrement the writer refcount, but
  the queue itself is closed by the last `DetachWriter`, not by this
  sink in isolation.
- The default `bufferSize: 0` means "use the NCS default". For
  cross-process scenarios where the downstream reader is in a
  different process, set an explicit `bufferSize` (e.g. `1000`) to
  avoid blocking the pipeline when the reader briefly falls behind.

## Dependencies

- `pkg/executor/queue` — `Queue` interface, `ErrQueueFull`.
- `pkg/ncs` — `AttachWriter`, `DetachWriter`.
- `pkg/plugin` — `Manifest`, `ThreatEvent`, `SinkStats`.
- `pkg/sink` — sink registry helpers.
