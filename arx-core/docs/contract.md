# arx-core Core Contract

Public reference of the `arx-core` runtime contract between the core engine and Product plugins.

> Source of truth: `arx-core/pkg/runtime/` — types live in `types.go`, `spec.go`, `run_options.go`; the engine lives in `engine.go`. This document mirrors those files byte-for-byte; if it disagrees with the code, the code wins.

## Purpose

This document is the reference for the **public runtime contract** that the core engine (`pkg/runtime`) exposes to Product. It is read by:

- Product-side implementers who write `LineProcessor` / `LineProcessorFactory` / `Sink` / `Source` plugins.
- Reviewers verifying that core stays domain-agnostic (boundary rule, ADR-002).
- Future maintainers porting the engine.

The contract is intentionally minimal and value-typed. Everything in this file is exported from `arx-core/pkg/runtime`. Private helpers (`runPipeline`, `dispatchEntry`, `runStats`, `logTag`, `sourceMetadata`, `noopLogFn`, `defaultBufferSize`, `defaultStatsInterval`) are described only where the public contract depends on them.

## Boundary rule (one-line reminder)

`pkg/runtime` imports **only** stdlib + `github.com/mr-addams/arx-core/pkg/{plugin,input}`. No `arxsentinel/...`. Security-domain words are forbidden in type names, field names, and comments. Detectors / scoring / threat-intel / block-lists are Product-built and reach core only through opaque closures in `LineProcessorFactory.Build`.

---

## Data model (`pkg/plugin`)

The contract types below describe the runtime *control* surface. The *data*
surface — what actually flows between plugins — lives in `pkg/plugin` and is
documented in [`pkg/plugin/README.md`](../pkg/plugin/README.md):

- **`Envelope`** — transport metadata (`Timestamp/Stream/Source/SourceType/Level`)
  that the engine reads for metrics and routing. The only payload-shaped data
  the engine inspects.
- **`Event{Envelope; Payload any}`** — the generic event carrier. `Payload` is
  opaque; the owning plugins agree on its concrete type, the engine never reads it.
- **`FieldDecl` + `Manifest.Produces`/`Consumes`** — the field-level contract a
  plugin declares so the pipeline can verify producer↔consumer compatibility at
  startup.

These types are the generic data model: the core defines the envelope it
processes and the opaque carrier it transports, while concrete payload shapes
belong to the plugins that produce and consume them.

---

## Contract elements

The elements below are ordered by the source file they live in.

### 1. `Action` (struct, value type)

Source: `types.go`.

```go
type Action struct {
    Skip        bool
    ThreatEvent *plugin.ThreatEvent
}
```

Semantics:

- `Skip == true` — the row is dropped. Downstream stages / sinks see nothing. Filter/gate semantics.
- `Skip == false`, `ThreatEvent == nil` — the row passed through cleanly. No event is published.
- `Skip == false`, `ThreatEvent != nil` — the engine fans the event out to every `Sink` on the pipeline.
- `Skip == true`, `ThreatEvent != nil` — the skip wins (the engine treats the row as dropped and does not publish). Implementations should not set both.

`Action` is a **value type**, no mutexes, copy on every return. The runtime never interprets the contents beyond the three branches above. `processor.Process` must be deterministic for the same `(entry, state)` pair — the engine relies on this to keep a single goroutine per pipeline.

### 2. `EventContext` (struct)

Source: `types.go`.

```go
type EventContext struct {
    StreamName   string
    PipelineName string
    SourceName   string
    SourceType   string
    PipelineIdx  int
}
```

Static, per-pipeline. Populated **once** at pipeline start (`runPipeline` in `engine.go`) and never mutated between rows. `SourceName`/`SourceType` are derived from the first entry in `PipelineSpec.Sources` via `sourceMetadata`: names prefixed with `file:` resolve to `sourceType="file"`, otherwise `"stdin"`. `PipelineIdx` mirrors `PipelineSpec.Idx` so processors can read their own position without zipped iteration.

### 3. `ProcessorState` (type alias)

Source: `types.go`.

```go
type ProcessorState = any
```

Opaque — the runtime never dereferences or interprets it. Returned exactly once from `LineProcessorFactory.Build`; passed as the `state` parameter to every `LineProcessor.Process` for the lifetime of the pipeline (or until the next successful `Reload`). Use this to hold block-lists, compiled detector sets, atomics — whatever the Product processor needs.

### 4. `LineProcessor` (interface)

Source: `types.go`.

```go
type LineProcessor interface {
    Process(ctx context.Context, entry *plugin.LogEntry, state ProcessorState, evctx EventContext) Action
}
```

Contract:

- Called **sequentially in a single goroutine per pipeline**. There is no concurrent dispatch within one pipeline.
- `state` is whatever `factory.Build` (or the most recent `factory.Reload`) returned.
- `evctx` is the static per-pipeline `EventContext`; do not mutate it.
- Must be deterministic for the same `(entry, state)`.
- The runtime does not interpret the returned `Action` beyond `Skip`/`ThreatEvent` checks.

### 5. `LineProcessorFactory` (interface)

Source: `types.go`.

```go
type LineProcessorFactory interface {
    Build(streamName, pipeName string, pipeIdx int, shared SharedResources) (ProcessorState, error)
    Reload(old ProcessorState, ctx context.Context) (ProcessorState, error)
}
```

- `Build` is called **once** when the pipeline starts. It typically resolves detectors via `PluginRegistry`, opens resources (block-lists, chain-checkers — all opaque), and returns the `ProcessorState`. On error, the pipeline logs and exits; `Run` continues with sibling pipelines.
- `Reload` is called on SIGHUP-equivalent (one receive from `reloadCh`). It must return a **new** `ProcessorState`. The engine atomically swaps it into the pipeline-local `ps` variable; subsequent rows use the new state. `old` is provided so the Product side can copy forward unchanged fields.
- **Both methods must be thread-safe**: under concurrent reload of sibling pipelines, `Build`/`Reload` may be invoked from different goroutines.

In `engine.Run`, the factory is also type-asserted to `LineProcessor` — see §13. Product types normally implement both interfaces on the same struct.

### 6. `Reloader` (interface, optional)

Source: `types.go`.

```go
type Reloader interface {
    Reload() error
}
```

Separate from `LineProcessorFactory.Reload`: it does not take `old state`, because Product stores its current state internally and decides how to fetch it. Used both by processors and by sinks (for example, `FileSink` calls it on log-rotation). `engine.Run`'s reload handler does `if r, ok := sink.(Reloader); ok { r.Reload() }` for every sink in the pipeline.

### 7. `LogFn` (type)

Source: `types.go`.

```go
type LogFn func(tag, msg, level string)
```

The general-purpose logging signature. `level` is one of `info`, `warn`, `error`, `debug`. The engine calls it with tags including `RUNTIME` (lifecycle), `RELOAD` (config reload), `SINK` (write errors), `STATS` (periodic counters). If Product passes `nil` to `Run`, the engine substitutes a `noopLogFn` internally — passing `nil` is safe and not an error.

### 8. `SharedResources` (struct)

Source: `types.go`.

```go
type SharedResources struct {
    BlocklistManager any
    ChainChecker     any
    WarningsWriter   any
    MetricsCallbacks *MetricsCallbacks
}
```

Filled **once** by Product at engine start. The runtime does **not** dereference `BlocklistManager`, `ChainChecker`, or `WarningsWriter` — they are typed `any` precisely so the security domain does not leak into core. The runtime only passes the struct through to `factory.Build`, where Product-side closures pick fields out.

`MetricsCallbacks` is the one field the runtime actively uses — see §9.

### 9. `MetricsCallbacks` (struct, nil-safe)

Source: `types.go`.

```go
type MetricsCallbacks struct {
    RecordLine        func(streamName, pipelineName, sourceName, sourceType string)
    RecordThreat      func(streamName, pipelineName, level string)
    RecordInputLine   func(streamName, pipelineName, sourceName, sourceType string)
    RecordDetectorHit func(streamName, pipelineName, moduleName string)
    RecordOutputEvent func(streamName, pipelineName, sinkName string)
    UpdateGauges      func(streamName, pipelineName string, trackedIPs, suspicious int64)
}
```

**Nil-safe contract**: every call from the engine **must** be guarded by `if cb != nil && cb.<Field> != nil`. A Product that registers no metrics at all is fine; a Product that registers `MetricsCallbacks` but leaves one field nil is also fine.

Callback semantics:

- `RecordLine` — fires on **every** row, **before** `processor.Process`, even if the eventual `Action.Skip == true`. It marks "row received".
- `RecordInputLine` — sibling of `RecordLine`, distinguished by where in the pipeline the row is observed (engine currently calls `RecordLine`; `RecordInputLine` is reserved for future stages).
- `RecordThreat` — fires only when `action.ThreatEvent != nil`, carrying `ThreatEvent.Level` (e.g. `"THREAT"`, `"WARN"`).
- `RecordDetectorHit` — Product calls this from inside its own `Process` / `Build` closures when a specific detector module fires; the engine itself does not invoke it.
- `RecordOutputEvent` — fires after each successful `sink.Write` (one event per sink that succeeded).
- `UpdateGauges` — fired periodically from the stats goroutine with the latest `processedCount` and `eventCount` snapshots; Product-typed metrics register Prometheus gauges here.

All callbacks are called **synchronously** in the pipeline goroutine. Implementations must be non-blocking (atomic counters are typical).

### 10. `PipelineSpec` (struct)

Source: `spec.go`.

```go
type PipelineSpec struct {
    Name    string
    Idx     int
    Sources []plugin.Source
    Sinks   []plugin.Sink
}
```

- `Name` — axis label `pipeline_name` for logs and metrics.
- `Idx` — position in `StreamSpec.Pipelines` (`0..len-1`), forwarded verbatim into `EventContext.PipelineIdx`.
- `Sources` — already-built `plugin.Source` instances, Product constructs them before calling `Run`. The engine feeds them into `coreinput.Merge` for fan-in.
- `Sinks` — already-built `plugin.Sink` instances. The engine fans every `ThreatEvent` out to all of them.

**Detectors do not appear here.** Product passes them via closure into `LineProcessorFactory.Build`. `PipelineSpec` describes *what* runs; `factory.Build` describes *how* (including detector wiring).

### 11. `StreamSpec` (struct)

Source: `spec.go`.

```go
type StreamSpec struct {
    Name            string
    TrackerGroup    string
    BufferSize      int
    ShutdownTimeout time.Duration
    StatsInterval   time.Duration
    Pipelines       []PipelineSpec
}
```

- `Name` — stable stream identifier (log/metric axis).
- `TrackerGroup` — tracker-pool group name; runtime does not interpret, Product passes through to its closures.
- `BufferSize` — channel size between stages. `0` means the engine uses its internal default (`1000`).
- `ShutdownTimeout` — upper bound on graceful shutdown of all stream goroutines.
- `StatsInterval` — period for the stats goroutine. `0` means the engine uses its internal default (`30s`).
- `Pipelines` — pipelines to run in parallel within this stream.

### 12. `RunOptions` (struct, reserved)

Source: `run_options.go`.

```go
type RunOptions struct {
    BufferSize      int
    ShutdownTimeout time.Duration
    TrackerGroup    string
}
```

> **NOTE — reserved type, not yet wired.** `RunOptions` exists in `run_options.go` as a future-consolidation candidate for the parameters currently embedded in `StreamSpec`. **Today's `Run` signature does not take `RunOptions`** — the relevant fields are passed directly via `StreamSpec` (`BufferSize`, `ShutdownTimeout`, `TrackerGroup`). The type is documented faithfully so Product implementers know it exists, but it must not be passed to `Run` yet — there is no parameter for it.

### 13. `Run` (top-level function)

Source: `engine.go`.

```go
func Run(
    ctx context.Context,
    streamSpec StreamSpec,
    factory LineProcessorFactory,
    shared SharedResources,
    reloadCh <-chan struct{},
    logFn LogFn,
) error
```

Behaviour:

- If `logFn == nil`, substitutes `noopLogFn`. Safe to pass `nil`.
- Type-asserts `factory.(LineProcessor)`. If the assertion fails, returns an error: `runtime.Run: factory %T must also implement LineProcessor`. This is a fail-fast guard, not a panic.
- Installs a per-stream `defer recover` so a panic in one pipeline does not kill siblings.
- Logs `RUNTIME` start line with stream name and pipeline count.
- For each pipeline in `streamSpec.Pipelines`, starts a goroutine that calls `runPipeline`.
- `wg.Wait()` blocks until every pipeline goroutine returns.
- Returns `nil` on clean shutdown of every pipeline. Returns an error only if the `LineProcessor` type-assertion fails. `ctx.Err()` propagates from each pipeline through normal drain-and-exit logic.

`reloadCh == nil` or any receive on `reloadCh` triggers `factory.Reload(old, ctx)` followed by `sink.Reload()` for each sink that implements `Reloader` (e.g. `FileSink` log rotation). The engine atomically swaps in the new `ProcessorState`.

`ctx.Done()` triggers drain: the pipeline reads every remaining entry from the `Merge` channel using `context.Background()` (since `ctx` is already cancelled) and then returns.

### 14. Processor skeleton

A Product processor typically implements **both** `LineProcessorFactory` and `LineProcessor` on one type, so that `engine.Run`'s type-assertion succeeds.

```go
// Example: a Product processor that filters lines by source IP.
type myProcessor struct { /* detectors/state refs here */ }

func (p *myProcessor) Build(streamName, pipeName string, pipeIdx int, shared SharedResources) (ProcessorState, error) {
    state := &myState{ blocklist: shared.BlocklistManager }
    return state, nil
}

func (p *myProcessor) Reload(old ProcessorState, ctx context.Context) (ProcessorState, error) {
    // rebuild state from current config; return new state
    return &myState{}, nil
}

func (p *myProcessor) Process(ctx context.Context, entry *plugin.LogEntry, state ProcessorState, evctx EventContext) Action {
    st := state.(*myState)
    if st.shouldSkip(entry) {
        return Action{Skip: true}
    }
    if ev := st.detectThreat(entry); ev != nil {
        return Action{ThreatEvent: ev}
    }
    return Action{}
}
```

Because `engine.Run` type-asserts `factory.(LineProcessor)`, the same `*myProcessor` value is passed both as `LineProcessorFactory` (for `Build`/`Reload`) and as `LineProcessor` (for per-row `Process`).

---

## Index of contract symbols (canonical list)

Verified by `grep -E "^(type|func) " arx-core/pkg/runtime/{types,spec,run_options,engine}.go`:

```
types.go:type Action struct { ... }
types.go:type EventContext struct { ... }
types.go:type ProcessorState = any
types.go:type LineProcessor interface { ... }
types.go:type LineProcessorFactory interface { ... }
types.go:type Reloader interface { ... }
types.go:type LogFn func(tag, msg, level string)
types.go:type SharedResources struct { ... }
types.go:type MetricsCallbacks struct { ... }
spec.go:type PipelineSpec struct { ... }
spec.go:type StreamSpec struct { ... }
run_options.go:type RunOptions struct { ... }
engine.go:func Run(ctx context.Context, streamSpec StreamSpec, factory LineProcessorFactory, shared SharedResources, reloadCh <-chan struct{}, logFn LogFn) error
```

(The grep additionally surfaces private helpers — `runPipeline`, `dispatchEntry`, `runStats`, `logTag`, `sourceMetadata`, `noopLogFn` — which are described above where the public contract depends on them.)
