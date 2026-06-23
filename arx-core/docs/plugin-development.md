# Plugin Development

How to author source / processor / detector / executor / sink plugins for `arx-core`.

> Source: derived from the core plugin contracts in `arx-core/pkg/plugin/*.go`
> (interfaces), `arx-core/pkg/{source,sink,detector,processor,executor}/registry.go`
> (registry APIs), and the engine contract in `arx-core/docs/contract.md` (how a
> product layer wraps a plugin into the runtime).
>
> Status: populated by Flow 082 Phase 3.

## 1. Overview

`arx-core` is a generic, line-oriented telemetry pipeline engine. It defines
five plugin roles — **source**, **processor**, **detector**, **executor**,
**sink** — each with a small Go interface declared in `arx-core/pkg/plugin/`.

A plugin is a regular Go package that:

1. Implements one (or more) of the role interfaces.
2. Declares its identity and data contract in a `Manifest`.
3. Registers itself in the role registry from `init()`.
4. Is wired into the binary via a blank import by the host application.

The framework discovers plugins by name — no central factory list, no
import-time wiring beyond the blank import.

```
plugin role ── implements ──▶ pkg/plugin/{source,sink,detector,processor,executor}.go
plugin ── registers in ──▶ pkg/{source,sink,detector,processor,executor}/registry.go
plugin ── blank-imported by ──▶ host binary's main package
host binary ── calls ──▶ pkgsource.Build / pkgsink.Build / pkgdetector.Build / …
host binary ── feeds into ──▶ runtime.Run (engine) — see arx-core/docs/architecture.md
```

### 1.1 Plugin role summary

| Role      | Interface (in `pkg/plugin/`) | Registry (in `pkg/<role>/`)                | One-line responsibility |
|-----------|------------------------------|--------------------------------------------|--------------------------|
| `source`   | `Source`                      | `pkg/source`                               | Read inputs, emit `*Event` (Payload=opaque, often `*parser.LogEntry`) |
| `processor`| `Processor`                   | `pkg/processor`                            | Enrich or filter `*Event` |
| `detector` | `Detector`                    | `pkg/detector`                             | Analyse entry against per-IP state, return score |
| `executor` | `Executor`                    | `pkg/executor`                             | Pull events from an `EventSource`, perform an action |
| `sink`     | `Sink`                        | `pkg/sink`                                 | Persist / forward `*Event` records (Payload cast done in Product `Formatter`) |

Cross-references:

- For the runtime contract (`LineProcessor`, `Action`, `EventContext`,
  `Run`, `SharedResources`), see `arx-core/docs/contract.md`.
- For engine lifecycle (startup, fan-in, reload, shutdown), see
  `arx-core/docs/architecture.md`.
- For build profiles and tree-shaking of compiled-in transports, see
  `arx-core/docs/build-profiles.md`.

---

## 2. Choose a role

Pick exactly one role per plugin. The interface and registry determine the
shape of `init()`, `Register(...)`, and how the host binary consumes it.

### 2.1 Source — read inputs

Use `source` when you need to read data from an external system: a file on
disk, a network socket, an HTTP webhook, a stdin pipe, an NCS queue.

A source owns its parser and delivers `*plugin.Event` values (the generic
event carrier: `Event{Envelope, Payload any}`). For HTTP/file/stdin/syslog
sources the payload is typically `*parser.LogEntry` (see
[`pkg/parser/event_bridge.go`](../pkg/parser/event_bridge.go) — `WrapLogEntry` /
`UnwrapLogEntry`); for sentinel/exec sources the payload shape is owned by
the source itself.
`Run` blocks until `ctx` is cancelled or an unrecoverable error occurs;
`Close` releases file handles and OS resources.

The source fills the **transport** part of `Envelope`
(`Timestamp` / `Stream` / `Source` / `SourceType`); `Level` is left empty
until a downstream Product processor (scorer) sets it. The engine never
inspects `Event.Payload` itself — only `Envelope` is a generic DTO.

### 2.2 Processor — enrich or filter

Use `processor` when you need to transform or enrich a `*plugin.Event` in the
middle of a pipeline. The generic Event is the carrier (`Event{Envelope, Payload}`);
processors may inspect or replace `Payload` (commonly `*parser.LogEntry`) and
may also update `Envelope.Level`. Processors are value-typed — return the
(possibly modified) event on success, `(nil, nil)` to drop it, or a non-nil
error on actual processing failure.

Processors are optional in `arx-core` itself — the engine contract in
`arx-core/docs/contract.md` uses `LineProcessor` for the product wrapper
that contains the per-row logic. The `Processor` interface here is the
coarser-grained version that operates outside the runtime engine.

### 2.3 Detector — score entries

Use `detector` when you need to analyse a `*plugin.Event` against per-IP
history and return a threat-score contribution. Detectors are **stateless**:
every input they need arrives in the `plugin.IPView` parameter at call time.
The detector reads `entry.Payload` (typically `*parser.LogEntry`); it does
NOT set `Envelope.Level` — that is the scorer's responsibility in Product.

```go
type Detector interface {
    Name() string
    Detect(sv IPView, entry *plugin.Event) DetectResult
    Manifest() Manifest
}
```

### 2.4 Executor — perform actions

Use `executor` when you need to run an action in response to detection
results (block a request, dispatch a webhook, run a remediation script).
Executors pull events from an `EventSource` (typically an NCS queue) inside
their own goroutine — they never receive events via a direct call from the
pipeline.

```go
type Executor interface {
    Name() string
    Type() string
    Run(ctx context.Context, source EventSource) error
    Manifest() Manifest
    Stats() ExecutorStats
}
```

`EventSource` is the consumer side of a `queue.Queue`; see
`arx-core/pkg/executor/queue` for backends.

### 2.5 Sink — persist events

Use `sink` when you need to deliver `ThreatEvent` records to an external
destination (file, stdout, syslog, HTTP webhook, Kafka). Sinks are passive —
`Write` is called synchronously by the engine for every event that
survives processing.

```go
type Sink interface {
    Name() string
    Write(ctx context.Context, event ThreatEvent) error
    Close() error
    Manifest() Manifest
    Stats() SinkStats
}
```

### 2.6 Sink vs Executor — when to use which

A **sink** writes event data. It is stateless and idempotent at the I/O
level.

An **executor** enforces policy against external state. It may hold a
dedup map, manage TTL timers, call external APIs with retry logic, and
auto-reverse actions (e.g. lift a block after a configured duration).

If your plugin needs deduplication, TTL-based cleanup, distributed
delivery, or retry / circuit-breaker logic — use an executor. Otherwise,
a sink is simpler.

---

## 3. Plugin interfaces (source of truth)

All interfaces live in `arx-core/pkg/plugin/`. They are the single source
of truth — this section mirrors them byte-for-byte; if it disagrees with
the code, the code wins.

### 3.1 `Source`

```go
type Source interface {
    Name() string
    Run(ctx context.Context, out chan<- *LogEntry) error
    Close() error
    Manifest() Manifest
    Stats() SourceStats
}
```

Contract:

- `Name` returns a human-readable identifier; convention is
  `"file:/path/to/access.log"`, `"stdin"`, `"http://:9514"`.
- `Run` blocks until `ctx.Done()` or unrecoverable error. Must NOT close
  `out` — the Merge function owns it. Drop policy is non-blocking send;
  dropped entries increment `Stats().Dropped`.
- `Close` is always called by the pipeline after `Run` returns (regardless
  of whether `Run` returned an error).
- `Manifest` declares plugin identity and data contract.
- `Stats` returns a point-in-time snapshot of operational counters.

### 3.2 `Sink`

```go
type Sink interface {
    Name() string
    Write(ctx context.Context, event ThreatEvent) error
    Close() error
    Manifest() Manifest
    Stats() SinkStats
}
```

Contract:

- `Write` is called synchronously per event; it must be safe for
  concurrent calls.
- `ctx` allows the caller to cancel an in-flight delivery (e.g. shutdown).
- `Close` flushes buffered data and releases resources.
- `SinkStats`: `EventsWritten`, `Dropped`, `Errors`.

### 3.3 `Detector`

```go
type IPView interface {
    GetIP() string
    GetTotalRequests() int
    GetRequests404() int
    RecentPaths() []string
    ApproxRate(window time.Duration) float64
}

type DetectResult struct {
    Score  int    // 0 = clean; > 0 contributes to the row's threat score
    Module string // detector identifier, e.g. "probe", "rate"
    Reason string // trigger detail, e.g. "env_probe:3", "rate:142rps"
}

type Detector interface {
    Name() string
    Detect(sv IPView, entry *LogEntry) DetectResult
    Manifest() Manifest
}
```

Contract: detectors are stateless. Per-IP state lives in `IPView`, provided
by the pipeline at call time.

### 3.4 `Executor`

```go
type EventSource interface {
    Pop(ctx context.Context) (ThreatEvent, error)
}

type ExecutorStats struct {
    Executed int64
    Skipped  int64
    Errors   int64
    Swept    int64
}

type Executor interface {
    Name() string
    Type() string
    Run(ctx context.Context, source EventSource) error
    Manifest() Manifest
    Stats() ExecutorStats
}
```

Contract: `Run` is called as a goroutine and returns when `ctx` is
cancelled. Implementations own startup sync, deduplication, TTL management,
retry / circuit-breaker logic, and batch accumulation.

### 3.5 `Processor`

```go
type Processor interface {
    Name() string
    Process(ctx context.Context, entry *LogEntry) (*LogEntry, error)
    Manifest() Manifest
}
```

Contract: return `(nil, nil)` to drop the entry; return an error only on
actual processing failure, never for filter logic.

### 3.6 `Manifest`, `Role`, `DataType`

```go
type Role string
const (
    RoleSource    Role = "source"
    RoleProcessor Role = "processor"
    RoleDetector  Role = "detector"
    RoleExecutor  Role = "executor"
    RoleSink      Role = "sink"
)

type DataType string
const (
    TypeRawLog      DataType = "raw_log"
    TypeStructured  DataType = "structured"
    TypeScoredEvent DataType = "scored_event"
    TypeAny         DataType = "any"
    TypeNone        DataType = "none"
)

type Manifest struct {
    PluginID      string
    PluginVersion string
    Role          Role
    InputType     DataType
    OutputType    DataType
    Tags          []string
}
```

Every plugin exposes a `Manifest()` so the pipeline framework can verify
compatibility of roles and data types before any data flows.

### 3.7 Shared types

```go
type LogEntry struct {
    RemoteAddr string    // TCP peer (may be proxy or load balancer)
    RemoteUser string    // Basic Auth user; "-" for anonymous
    Time       time.Time // server-side request start time
    Method     string
    RawURI     string
    Path       string
    Query      string
    Protocol   string
    Status     int
    BytesSent  int64
    Referer    string
    UserAgent  string
    RealIP     string    // last IP from $real_ip; == RemoteAddr when real_ip == "-"
    ChainIssue string    // optional upstream marker (filled by a chaincheck-style processor)
}

type ThreatEvent struct {
    Timestamp  time.Time
    Level      string    // "WARN" or "THREAT"
    Stream     string    // stream name; empty in single-stream mode
    Source     string    // source name
    SourceType string    // source kind
    IP         string    // client IP that triggered the event
    Score      int
    Modules    []string
    Reason     string
    RawLine    string
}

type SourceStats struct{ LinesRead, ParseErrors, Dropped int64 }
type SinkStats   struct{ EventsWritten, Dropped, Errors int64 }
```

---

## 4. Registries and the init() + blank-import pattern

Every role has a registry package — `pkg/source`, `pkg/sink`, `pkg/detector`,
`pkg/processor`, `pkg/executor`. Each registry exposes three things:

| Function                                 | Purpose |
|------------------------------------------|---------|
| `Register(name string, f Factory)`        | Called from `init()` in the plugin package. Panics on duplicate name. |
| `Build(name string, cfg, opts)`          | Called by the host binary when constructing a plugin instance. |
| `Names() []string`                        | Sorted list of registered names. Safe to call concurrently. |
| `RegisterManifest(name, plugin.Manifest)`| Optional; lets the validator read a plugin's data contract without constructing it. |

The three-step wiring is the same for every role:

1. **Plugin package** — `init()` calls `pkgsource.Register("my-source", factory)`.
2. **Host binary** — `_ "host/path/to/my-source"` blank-imports the package,
   triggering the `init()` at program startup.
3. **Host binary config layer** — reads the YAML config, calls
   `pkgsource.Build(name, cfg, opts)`, and passes the resulting `plugin.Source`
   into `PipelineSpec.Sources` (for `runtime.Run`).

Because `Register` panics on duplicates, a typo is caught at startup. The
factory must be safe to call concurrently from `Build` — though in practice
`Build` is called during configuration loading, before the engine starts.

### 4.1 Example — syslog source registers itself

```go
// arx-core/pkg/source/syslog/register.go
package syslog

import (
    "github.com/mr-addams/arx-core/pkg/plugin"
    pkgsource "github.com/mr-addams/arx-core/pkg/source"
)

func init() {
    pkgsource.Register("syslog", func(cfg pkgsource.InputConfig, opts pkgsource.BuildOptions) (plugin.Source, error) {
        return New(cfg.Addr, opts.Parser, opts.LogFn)
    })
    pkgsource.RegisterManifest("syslog", (&SyslogSource{}).Manifest())
}
```

The host binary blank-imports it:

```go
// host binary's plugin aggregation file
package main

import (
    _ "github.com/mr-addams/arx-core/pkg/source/syslog" // registers "syslog"
    _ "github.com/mr-addams/arx-core/pkg/source/file"   // registers "file"
    _ "github.com/mr-addams/arx-core/pkg/sink/stdout"   // registers "stdout"
)
```

### 4.2 Build-time tree-shaking

Plugins that are not blank-imported are eliminated by the linker. The
build-profile mechanism (see `arx-core/docs/build-profiles.md`) is the
human-readable declaration of which blank-imports end up in the binary.

### 4.3 Disabled plugins

For `detector` and `processor`, `Build` returns `(nil, nil)` when
`cfg.Enabled == false`. Callers must handle a nil plugin — the contract
is "silent skip" for disabled entries, even if the name is unknown.

---

## 5. The five-file pattern

The recommended structure for a single plugin package:

```
pkg/<role>/<plugin-name>/
├── manifest.go      — Manifest() method, Role/DataType declaration
├── config.go        — Config struct, DefaultConfig(), parseConfig()
├── impl.go          — the type itself: methods that satisfy the role interface
├── register.go      — init() calling <role>.Register(name, factory)
└── impl_test.go     — unit tests for the plugin
```

This is a convention, not a strict requirement — the registry only requires
that *some* `init()` calls `Register`. The five-file split is convenient
because each file has one responsibility and reviewers can scan
`register.go` to see the wire-up at a glance.

### 5.1 `manifest.go`

```go
package myfilter

import "github.com/mr-addams/arx-core/pkg/plugin"

// Manifest returns the plugin's identity and data contract.
func (p *MyFilter) Manifest() plugin.Manifest {
    return plugin.Manifest{
        PluginID:      "my-filter",
        PluginVersion: "1.0.0",
        Role:          plugin.RoleProcessor,
        InputType:     plugin.TypeStructured,
        OutputType:    plugin.TypeStructured,
    }
}
```

Fields:

| Field           | Description                                              |
|-----------------|----------------------------------------------------------|
| `PluginID`      | Unique identifier used in YAML config (lowercase, hyphen-separated). |
| `PluginVersion` | Semantic version of the plugin.                          |
| `Role`          | One of `RoleSource`, `RoleProcessor`, `RoleDetector`, `RoleExecutor`, `RoleSink`. |
| `InputType`     | `DataType` the plugin expects to receive.                |
| `OutputType`    | `DataType` the plugin produces.                          |
| `Tags`          | Free-form labels for selection and filtering.            |

### 5.2 `config.go`

```go
package myfilter

// Config holds user-configurable parameters for MyFilter.
type Config struct {
    DropPrefix string   `yaml:"drop_prefix"`
    MinBytes   int      `yaml:"min_bytes"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
    return Config{
        DropPrefix: "/health",
        MinBytes:   0,
    }
}

// parseConfig extracts a Config from a generic params map, with safe
// fallbacks for missing or wrongly-typed values.
func parseConfig(params map[string]any) Config {
    c := DefaultConfig()
    if v, ok := params["drop_prefix"].(string); ok {
        c.DropPrefix = v
    }
    if v, ok := params["min_bytes"].(int); ok {
        c.MinBytes = v
    }
    return c
}
```

### 5.3 `impl.go` — the role interface

For a processor, the typical implementation is a value-type with
`Process` returning `(nil, nil)` to drop the entry:

```go
package myfilter

import (
    "context"
    "fmt"
    "strings"

    "github.com/mr-addams/arx-core/pkg/parser"
    "github.com/mr-addams/arx-core/pkg/plugin"
)

// MyFilter drops entries whose Path starts with DropPrefix, or whose body
// is below MinBytes. It is a pure-function processor — no state.
type MyFilter struct {
    cfg Config
}

// Name returns the plugin's human-readable name.
func (p *MyFilter) Name() string { return "my-filter" }

// Process implements plugin.Processor.
func (p *MyFilter) Process(ctx context.Context, entry *plugin.Event) (*plugin.Event, error) {
	if entry == nil {
		return nil, nil
	}
	le, ok := entry.Payload.(*parser.LogEntry)
	if !ok {
		return nil, fmt.Errorf("my-filter: unexpected payload type %T", entry.Payload)
	}
	if p.cfg.DropPrefix != "" && strings.HasPrefix(le.Path, p.cfg.DropPrefix) {
		return nil, nil // drop
	}
	if p.cfg.MinBytes > 0 && le.BytesSent < int64(p.cfg.MinBytes) {
		return nil, nil // drop
	}
	return entry, nil
}

// NewMyFilter creates a configured filter instance.
func NewMyFilter(cfg Config) *MyFilter { return &MyFilter{cfg: cfg} }
```

### 5.4 `register.go`

```go
package myfilter

import (
    "github.com/mr-addams/arx-core/pkg/plugin"
    pkgproc "github.com/mr-addams/arx-core/pkg/processor"
)

func init() {
    pkgproc.Register("my-filter", func(cfg pkgproc.ProcessorConfig) (plugin.Processor, error) {
        return NewMyFilter(parseConfig(cfg.Params)), nil
    })
}
```

The factory closure receives the role's `Config` struct from
`Build(name, cfg, opts)`. For processors, that's
`pkg/processor.ProcessorConfig{Enabled, Params}`. For detectors, it's
`pkg/detector.DetectorConfig{Enabled, Params, Exec}` plus a
`SharedResources` argument. For sources/sinks, the registry passes a
role-specific `InputConfig` / `SinkConfig` and an `opts` `BuildOptions`
bundle. Always check the registry you are calling for the exact signature.

### 5.5 `impl_test.go`

```go
package myfilter

import (
    "context"
    "testing"

    "github.com/mr-addams/arx-core/pkg/parser"
    "github.com/mr-addams/arx-core/pkg/plugin"
)

func TestManifest(t *testing.T) {
    p := NewMyFilter(DefaultConfig())
    m := p.Manifest()
    if m.PluginID != "my-filter" {
        t.Fatalf("expected 'my-filter', got %q", m.PluginID)
    }
    if m.Role != plugin.RoleProcessor {
        t.Fatalf("expected RoleProcessor, got %v", m.Role)
    }
}

func TestProcessDropsByPrefix(t *testing.T) {
	p := NewMyFilter(Config{DropPrefix: "/health"})
	entry := &plugin.Event{Payload: &parser.LogEntry{Path: "/health/live"}}
	got, err := p.Process(context.Background(), entry)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if got != nil {
        t.Fatalf("expected drop (nil entry), got %+v", got)
    }
}
```

---

## 6. Lifecycle hooks

### 6.1 Source lifecycle

| Stage        | Source owns                                      | Pipeline owns                              |
|--------------|---------------------------------------------------|---------------------------------------------|
| Construct    | Allocate buffers, open files, parse config.       | Decide which `Source` to instantiate.       |
| `Run`        | Read data, parse lines, send `*LogEntry` to `out`. | Call `coreinput.Merge(ctx, sources, bufSize, …)` to fan-in. |
| Cancellation | Observe `ctx.Done()`, close file handles, exit.   | Cancel the context to signal shutdown.      |
| `Close`      | Release OS resources.                              | Always call `Close()` after `Run` returns, even on error. |

`Run` MUST honour `ctx.Done()` — the engine calls `Run` in a goroutine
and a source that ignores the context will block shutdown indefinitely.

### 6.2 Sink lifecycle

| Stage        | Sink owns                                         | Pipeline owns                              |
|--------------|---------------------------------------------------|---------------------------------------------|
| Construct    | Open file / connect socket / spawn subprocess.    | Decide which `Sink` to instantiate.        |
| `Write`      | Serialize and emit one `ThreatEvent`.              | Call `Write` once per surviving event.      |
| `Close`      | Flush, close file handle, release resources.      | Call `Close()` once during shutdown.        |

`Write` is called synchronously by the engine per event. Async sinks (e.g.
ones that buffer internally) must be non-blocking on `Write` and surface
back-pressure through `Stats().Dropped`.

### 6.3 Detector lifecycle

`Detect` is called once per `(IPView, LogEntry)` pair. It is stateless and
must be safe to call concurrently across different IPs. Per-IP state lives
in `IPView` and is owned by the pipeline.

### 6.4 Executor lifecycle

`Run` is called in its own goroutine with an `EventSource` (a queue handle).
The executor loops on `source.Pop(ctx)`, performs its action, and exits
when `ctx` is cancelled. The executor owns:

- Startup sync (loading remote state, e.g. an existing block list).
- Deduplication (skip already-known IPs).
- TTL management (auto-reverse after a configured duration).
- Retry / circuit-breaker logic on external API failures.
- Batch accumulation and flush, where applicable.

Implementations must be safe for concurrent access only via the
`EventSource` — no external goroutines call methods on the executor after
`Run` starts.

### 6.5 Processor lifecycle

`Process` is called once per entry. It is stateless and must return
deterministically for the same `(entry, ctx)` pair (the engine relies on
this for single-goroutine-per-pipeline semantics). Return `(nil, nil)` to
drop; return an error only on processing failure.

### 6.6 Stats

Every plugin exposes a `Stats() ...Stats` method. The engine pulls these
counters periodically (the `STATS` log tag in `runtime.Run`); product
implementations may also publish them via Prometheus.

`SourceStats` carries `LinesRead`, `ParseErrors`, `Dropped`.
`SinkStats` carries `EventsWritten`, `Dropped`, `Errors`.
`ExecutorStats` carries `Executed`, `Skipped`, `Errors`, `Swept`.

All counters are incremented via `sync/atomic` and are safe to read
concurrently from a metrics endpoint without taking a lock.

---

## 7. Wiring a plugin into the runtime

`arx-core`'s `pkg/runtime` package defines the engine. A host binary
(product) does the following at startup:

```go
import (
    "github.com/mr-addams/arx-core/pkg/runtime"
    "github.com/mr-addams/arx-core/pkg/plugin"
    pkgsource "github.com/mr-addams/arx-core/pkg/source"
    pkgsink   "github.com/mr-addams/arx-core/pkg/sink"

    // Blank imports trigger init() in each plugin package.
    _ "github.com/mr-addams/arx-core/pkg/source/syslog"
    _ "github.com/mr-addams/arx-core/pkg/sink/file"
)

func main() {
    src, _ := pkgsource.Build("syslog", pkgsource.InputConfig{Addr: "udp://:5514"}, opts)
    snk, _ := pkgsink.Build(ctx, pkgsink.SinkConfig{Type: "file", Path: "/var/log/events.log", Format: "json"})

    spec := runtime.StreamSpec{
        Name: "default",
        Pipelines: []runtime.PipelineSpec{
            {Name: "p0", Idx: 0, Sources: []plugin.Source{src}, Sinks: []plugin.Sink{snk}},
        },
    }
    factory := /* your LineProcessorFactory — see arx-core/docs/contract.md */
    shared  := runtime.SharedResources{ /* product-side shared state — see contract.md §8 */ }
    _ = runtime.Run(ctx, spec, factory, shared, reloadCh, logFn)
}
```

The product-side `LineProcessorFactory` is what wraps the per-row logic
(detector chains, scoring, thresholding) into the engine contract. See
`arx-core/docs/contract.md` §5 (`LineProcessorFactory`) for the full
interface and §14 for the processor skeleton. That factory is **not** a
plugin — it is a product-layer type that consumes compiled-in detectors
through the `LineProcessor` interface.

Boundary rule (recap from `arx-core/docs/architecture.md` §1):

> `pkg/runtime` imports only stdlib + `pkg/{plugin,input}`. No imports of
> product-side packages. Detectors / scoring / threat-intel plumbing live
> on the product side and reach the engine only through the opaque
> `ProcessorState` returned from `LineProcessorFactory.Build`.

---

## 8. External exec+JSON plugins

For plugins written in languages other than Go (Python, Rust, Node.js, bash),
`arx-core/pkg/execplugin` provides the exec+JSON protocol. An external
plugin communicates over stdin/stdout with newline-delimited JSON (NDJSON),
one JSON object per line.

### 8.1 Protocol

All messages carry `"v":"1"` (protocol version). The host binary spawns the
plugin as a subprocess and pipes NDJSON lines through `pkg/execplugin`'s
`ManagedProcess`.

The protocol covers four actions: `detect`, `write` (sink), `poll` (source),
`run` (executor). Each action has a request shape and a response shape; the
details are in `arx-core/pkg/execplugin/protocol.go`.

### 8.2 Environment variables

When the host binary spawns an exec plugin, it sets:

| Variable                      | Value                                                  |
|-------------------------------|--------------------------------------------------------|
| `ARXSENTINEL_PLUGIN_PARAMS`   | JSON-encoded map of the plugin's YAML `params:`.       |

The plugin decodes this in its `main()` and uses the parameters during
initialization. Source of truth: `arx-core/pkg/execplugin/detector.go`.

### 8.3 Hooking an exec plugin

For a detector:

```yaml
detectors:
  - name: my-ml-detector
    enabled: true
    exec: /opt/plugins/my_ml_detector.py
    params:
      model_path: /opt/models/v1.bin
      threshold: 0.7
```

The `exec:` field tells `pkg/detector.Build` to instantiate an
`execplugin.ExecDetector` instead of looking up a compiled-in factory.

For a source / sink / executor, the equivalent YAML config uses the
role-specific `exec:` field; see `arx-core/pkg/{source,sink,executor}/registry.go`
for the exact field name.

### 8.4 When to use exec+JSON

- The plugin is in a language other than Go (Python, Rust, Node.js, bash).
- The plugin needs an independent release cycle (you can rebuild it without
  rebuilding the host binary).
- The plugin requires resource isolation (sandbox, container, separate
  machine via an HTTP proxy).
- Third-party / vendor-supplied plugins that you do not want to compile in.

Compiled-in plugins are still preferred when latency is critical
(microsecond-level), when the plugin needs to share memory with the host
binary, or when you want a single static deployment artefact.

---

## 9. Testing your plugin

### 9.1 Unit tests (compiled-in)

Place `impl_test.go` next to `impl.go`. The test uses the plugin's
constructor directly, exercises the role methods, and asserts on the
return values. Use a mock `IPView` for detectors — Go structural typing
means a tiny struct that satisfies `plugin.IPView` is enough:

```go
type mockView struct {
    ip string
    total int
    fourOhFour int
    paths []string
    rate float64
}

func (m *mockView) GetIP() string                  { return m.ip }
func (m *mockView) GetTotalRequests() int          { return m.total }
func (m *mockView) GetRequests404() int            { return m.fourOhFour }
func (m *mockView) RecentPaths() []string          { return m.paths }
func (m *mockView) ApproxRate(time.Duration) float64 { return m.rate }
```

For sources, drive `Run` with a `chan<- *plugin.Event` and a cancellable
context, then assert on the entries received.

For sinks, construct the sink against a `*os.File` (or a test helper
constructor that accepts any `io.Writer`), call `Write` with a sample
`*plugin.Event` (Payload set to a product-owned struct, e.g.
`&threat.ThreatEvent{...}`) plus a product-side `Formatter` for byte-level
encoding, and read the file back.

### 9.2 Integration tests (exec+JSON)

Pipe NDJSON into the plugin binary and assert on its stdout:

```bash
echo '{"v":"1","action":"detect","entry":{...},"state":{...}}' \
    | /opt/plugins/my_ml_detector.py
```

Wrap this in a Go integration test that uses `os/exec` to spawn the
binary and `bufio.Scanner` to read the response.

---

## 10. Checklist before shipping a plugin

- [ ] **Manifest** — `PluginID`, `PluginVersion`, `Role`, `InputType`, `OutputType` populated.
- [ ] **Config** — struct with `yaml` tags and a `DefaultConfig()` function. `parseConfig()` falls back safely on missing/wrongly-typed values.
- [ ] **Impl** — implements the correct interface (`plugin.Source`, `plugin.Processor`, `plugin.Detector`, `plugin.Sink`, or `plugin.Executor`).
- [ ] **Register** — `init()` calls the role's `Register(name, factory)` (and optionally `RegisterManifest(name, manifest)`).
- [ ] **Lifecycle** — `Run` honours `ctx.Done()`. `Close` releases resources safely and idempotently. `Stats` uses `sync/atomic` counters.
- [ ] **Tests** — at minimum: manifest contract + one happy-path test per exported method. Detectors should test against a mock `IPView`.
- [ ] **Blank import** — host binary has `_ "host/path/to/plugin"` next to all other blank imports.
- [ ] **Boundary rule** — the package does not import `arxsentinel/...` (the product layer). The engine (`pkg/runtime`) is not touched by plugins.

---

## 11. See also

- `arx-core/docs/contract.md` — runtime contract: `Run`, `LineProcessor`, `Action`, `EventContext`, `SharedResources`, `MetricsCallbacks`.
- `arx-core/docs/architecture.md` — engine lifecycle: `runPipeline`, `dispatchEntry`, NCS wiring, fan-in, shutdown.
- `arx-core/docs/build-profiles.md` — `arx_tag` sentinel, profile YAMLs, tree-shaking of compiled-in transports.
- `arx-core/pkg/plugin/` — the five role interfaces (`source.go`, `sink.go`, `detector.go`, `processor.go`, `executor.go`), `manifest.go`, `roles.go`, `datatypes.go`, `types.go`.
- `arx-core/pkg/{source,sink,detector,processor,executor}/registry.go` — registry APIs.
- `arx-core/pkg/execplugin/` — exec+JSON protocol, `ManagedProcess`, `ProtoVersion`.
- `arx-core/pkg/executor/queue/` — `Queue` interface and `memory` / `bbolt` / `redis` backends used by executors.