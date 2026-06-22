# arx-core Architecture

Engine lifecycle, NCS wiring, fan-in contracts, the generic `runtime.Run` execution model.

> Source of truth: `arx-core/pkg/runtime/` — types in `types.go`, `spec.go`, `run_options.go`; the engine in `engine.go`. This document mirrors those files. If it disagrees with the code, the code wins. Cross-reference with `arx-core/docs/contract.md` for symbol-level definitions.

## 1. Overview

`arx-core` is a **generic, line-oriented telemetry pipeline engine**. It is deliberately domain-agnostic: it knows nothing about security, scoring, detectors, threat intel, block-lists, or chain-of-proxies checks. It only knows the runtime contract — rows in, `Action`s out, sinks fanned-out, metrics callbacks, reload.

**Boundary rule (ADR-002).** `pkg/runtime` imports **only** stdlib and `github.com/mr-addams/arx-core/pkg/{plugin,input}`. Nothing from `arxsentinel/...`. Security-domain words are forbidden in type names, field names, and comments inside `pkg/runtime`. All detectors, scoring, block-lists, threat intel are Product-built and reach core only through opaque closures in `LineProcessorFactory.Build`.

Product code lives elsewhere in the repository (e.g. `sentinel-...` packages). Product reads YAML, builds plugins via `PluginRegistry`, assembles `StreamSpec`/`PipelineSpec`, and hands the result to `runtime.Run`.

## 2. `runtime.Run` — top-level entry

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

Execution model:

1. If `logFn == nil`, substitute `noopLogFn` (the engine never panics on nil logger).
2. Type-assert `factory.(LineProcessor)`. If the assertion fails, return an error: `runtime.Run: factory %T must also implement LineProcessor`. This is a deliberate fail-fast guard.
3. Install a per-stream `defer recover` so one panicking pipeline does not bring down its siblings.
4. Log `RUNTIME` start line.
5. For each pipeline in `streamSpec.Pipelines`, start a goroutine that calls `runPipeline`. Join with `wg.Wait()`.
6. Log `RUNTIME` done line and return `nil`.

`reloadCh == nil` is treated identically to "no reloads". Each receive on `reloadCh` is a SIGHUP-equivalent for the stream.

## 3. Pipeline lifecycle (`runPipeline`)

One pipeline goroutine, started per `PipelineSpec` in `streamSpec.Pipelines`. Sequence:

1. **Build state.** `factory.Build(streamName, pipeName, pipeIdx, shared)` returns a `ProcessorState`. On error: log `RUNTIME` line with the tag, return (do not crash the stream).
2. **Allocate per-pipeline atomics.** `processedCount atomic.Int64` and `eventCount atomic.Int64`. The stats goroutine reads these snapshots in parallel.
3. **Build `EventContext`.** Static fields: `StreamName`, `PipelineName`, `PipelineIdx`. If `len(pipe.Sources) > 0`, set `SourceName` and `SourceType` from `sourceMetadata(pipe.Sources)`:
   - If the first source's `Name()` is prefixed with `file:` → `sourceType = "file"`.
   - Otherwise → `sourceType = "stdin"`.
4. **Resolve buffer size.** `bufSize = streamSpec.BufferSize`. If `0`, fall back to `defaultBufferSize` (1000, hardcoded inside engine — not part of the contract).
5. **Fan-in sources.** `entries := coreinput.Merge(ctx, pipe.Sources, bufSize, coreinput.LogFn(logFn))`. Each source runs in its own goroutine; `Merge` returns a single `entries <-chan *plugin.LogEntry`. `input.LogFn` and `runtime.LogFn` are distinct named types — the engine converts explicitly.
6. **Start stats goroutine.** `go runStats(...)` with `statsInterval = streamSpec.StatsInterval` (or `defaultStatsInterval` = 30s if zero).
7. **Main select loop** — three cases:

   - **`ctx.Done()`** — log `RUNTIME` shutdown line, then drain remaining entries:
     ```go
     for entry := range entries {
         dispatchEntry(context.Background(), entry, processor, ps, evctx, pipe.Sinks, shared, &processedCount, &eventCount, logFn)
     }
     ```
     `context.Background()` is used because `ctx` is already cancelled — any downstream `context.WithTimeout(ctx, …)` would be immediately cancelled. After drain, log "drain done" and return.

   - **`<-reloadCh`** (SIGHUP-equivalent) — call `factory.Reload(ps, ctx)`. On error, log `RELOAD` warn and continue (do not swap). On success, atomically assign `ps = newPs`. Then iterate `pipe.Sinks`; for each one that implements `Reloader`, call `sink.Reload()` (e.g. `FileSink` rotating its output file). Log `RELOAD` info at the end. Product reads the new config inside `factory.Reload` itself.

   - **`entry, ok := <-entries`** — if `!ok`, all sources exited without panic (or shutdown finished); log `RUNTIME` "channel closed, exiting" and return. If `ok`, call `dispatchEntry(ctx, entry, processor, ps, evctx, pipe.Sinks, shared, &processedCount, &eventCount, logFn)`.

The goroutine also has a `defer recover` so a panic is logged with tag `RUNTIME` as `error`, not propagated.

## 4. `dispatchEntry` — one-row processing

Source: `engine.go`. Called once per `*plugin.LogEntry` arriving from `entries`. Pure function over its arguments plus the atomics. Steps in order:

1. `processedCount.Add(1)`.
2. **`RecordLine` callback (nil-safe)** — fires **before** `processor.Process`, even on rows that will end up `Skip == true`. Guard: `if cb := shared.MetricsCallbacks; cb != nil && cb.RecordLine != nil { cb.RecordLine(evctx.StreamName, evctx.PipelineName, evctx.SourceName, evctx.SourceType) }`.
3. `action := processor.Process(ctx, entry, ps, evctx)`.
4. If `action.Skip`, return.
5. If `action.ThreatEvent == nil`, return (row passed silently — no event, no fan-out).
6. **Count threats.** If `action.ThreatEvent.Level == "THREAT"`, `eventCount.Add(1)`. The engine has no level semantics of its own — it uses the literal string `"THREAT"` from `plugin.ThreatEvent`. `"WARN"` does **not** increment `eventCount` (matches the legacy `processLine` semantics).
7. **`RecordThreat` callback (nil-safe)** — `cb.RecordThreat(streamName, pipelineName, action.ThreatEvent.Level)`.
8. **Fan-out to sinks.** Iterate `sinks` (order not guaranteed). For each: `sink.Write(ctx, *action.ThreatEvent)`. On error: log `SINK` line with the tag, **continue** to the next sink. Errors do **not** stop the pipeline — one broken sink must not kill the rest. On success: **`RecordOutputEvent` callback (nil-safe)** — `cb.RecordOutputEvent(streamName, pipelineName, sink.Name())`.

The error-tolerance on sink writes is a deliberate design choice, not an oversight.

## 5. NCS wiring

NCS (Named Channel Switch) lives in `arx-core/pkg/ncs/` as `channelswitch.go`. It is a singleton that maps named channels to in-memory / `bbolt` / Redis-backed queues with fan-in. NCS is **Product infrastructure** — the runtime does **not** call into it.

How NCS fits in:

- Product builds NCS-backed `Source` and `Sink` plugins (e.g. `sentinel-source`, `sentinel-sink`) that speak the `plugin.Source` / `plugin.Sink` interfaces.
- Product places these plugins into `PipelineSpec.Sources` and `PipelineSpec.Sinks`.
- The engine sees them as ordinary `plugin.Source` / `plugin.Sink` instances and feeds them into `coreinput.Merge` (for sources) or iterates them in `dispatchEntry` (for sinks).
- NCS's own queue mechanics, persistence, and routing are invisible to the engine.

For details on NCS itself, see `arx-core/pkg/ncs/README.md`.

## 6. SIGHUP-reload contract

The reload contract spans two interfaces:

- `LineProcessorFactory.Reload(old ProcessorState, ctx context.Context) (ProcessorState, error)` — **mandatory**. Receives the previous `ProcessorState` and returns a new one. The engine swaps `ps` atomically; subsequent rows use the new state.
- `Reloader.Reload() error` — **optional**. Used by anything that needs to refresh itself in-place without going through the factory: sinks like `FileSink` (rotate log files), processors that hold mutable external state. The engine does `if r, ok := sink.(Reloader); ok { r.Reload() }` for every sink on each reload event.

**Thread-safety.** `Build` and `Reload` may be invoked concurrently for sibling pipelines. Product implementations **must** be thread-safe. The engine itself is serial per pipeline (single goroutine), so `Build`/`Reload` and `Process` do not race inside one pipeline — but they can race across pipelines.

Failure modes:

- `factory.Reload` returns `error` → engine logs `RELOAD` warn, does **not** swap `ps`, continues with the old state.
- `sink.Reload` returns `error` → engine logs `RELOAD` warn with sink name, continues to the next sink.

## 7. Defaults

Two defaults are hardcoded inside `engine.go` as private constants — they are **implementation details**, not part of the public contract:

- `defaultBufferSize = 1000` — used when `StreamSpec.BufferSize == 0`.
- `defaultStatsInterval = 30 * time.Second` — used when `StreamSpec.StatsInterval == 0`.

Product should pass non-zero values when it cares; the defaults exist so a minimally-configured Product still runs.

A third fallback — `noopLogFn(_, _, _ string)` — is substituted when `Run`'s `logFn == nil`. It is also a private function and not exported.

## 8. What changed post-081

Prior to flow 081, the per-pipeline / per-stream orchestration logic (`runStream`, `runPipeline`, `processLine`) lived **inside the Product layer** (described in the now-legacy `docs/ARCHITECTURE.md` at the project root, product-side). After 081:

- The orchestration migrated into `arx-core/pkg/runtime/engine.go` as `Run` (top-level entry) and `runPipeline` / `dispatchEntry` / `runStats` (unexported helpers).
- The Product-side `docs/ARCHITECTURE.md` now describes only the product-security layer (detectors, scoring, threat-intel plumbing). It no longer describes pipeline lifecycle.
- This split is the concrete instantiation of ADR-002 (core/product boundary).

## 9. Boundary rule (recap)

`pkg/runtime` imports only:

- stdlib (`context`, `fmt`, `strings`, `sync`, `sync/atomic`, `time`).
- `github.com/mr-addams/arx-core/pkg/plugin` — shared DTOs (`LogEntry`, `ThreatEvent`, `Source`, `Sink`).
- `github.com/mr-addams/arx-core/pkg/input` — `coreinput.Merge` for fan-in.

Anything beyond that violates ADR-002. Reviewers must reject PRs that:

- Add `arxsentinel/...` imports in `pkg/runtime/`.
- Introduce security-domain words into type / field / comment names inside `pkg/runtime/`.
- Move detector wiring / scoring / threat-intel logic into `pkg/runtime/`. Those belong to Product, passed via closures in `factory.Build`.

---

## Index of engine symbols (canonical list)

Verified by `grep -E "^(type|func) " arx-core/pkg/runtime/{types,spec,run_options,engine}.go`. Public symbols:

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

Private engine helpers (described above):

```
engine.go:func runPipeline(...)
engine.go:func dispatchEntry(...)
engine.go:func runStats(...)
engine.go:func logTag(streamName, pipelineName string) string
engine.go:func sourceMetadata(sources []plugin.Source) (name, sourceType string)
engine.go:func noopLogFn(_, _, _ string)
```

Constants `defaultBufferSize = 1000` and `defaultStatsInterval = 30 * time.Second` live inside `engine.go` and are not part of the contract.
