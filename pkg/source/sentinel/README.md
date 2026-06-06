# `pkg/source/sentinel` — Sentinel Source

Sentinel source plugin for ArxSentinel. Reads `plugin.ThreatEvent` records from
the in-process **Named Channel Switch** (NCS) — registered in
`pkg/executor/channelswitch.go` — and delivers them to the pipeline as
`*plugin.LogEntry`. This is the **reverse direction** of the existing
`pkg/sink/sentinel/` sink: where the sink lets a pipeline *push* ThreatEvents
into the NCS, this source lets another pipeline (or the same one) *pull*
them back out and process them through the normal chain
(parser → whitelist → scorer → executor).

The two plugins are intentionally split across two directories to honour the
`source` / `sink` separation that ArxSentinel enforces everywhere else. They
share a single wire format — `plugin.ThreatEvent` — which is what makes the
NCS act as a typed in-process message bus between pipeline components.

- **Plugin ID:** `sentinel`
- **Plugin version:** `1.0.0`
- **Role:** `Source`
- **Input type:** `none`
- **Output type:** `structured`
- **Tags:** `sentinel`, `ncs`, `pipeline-bridge`, `internal-bus`

## Module Layout

```
pkg/source/sentinel/
├── manifest.go     # Plugin metadata
├── register.go     # Self-registration in the source registry
├── source.go       # SentinelSource — main implementation
└── source_test.go  # Unit tests
```

---

## Modes

Sentinel is a single-mode source: it reads from one named NCS queue and
forwards everything it finds downstream. The interesting distinction is
**how the queue gets populated**, which is what changes the operational
shape of the deployment.

### Pipeline-Bridge Mode (canonical use case)

Two pipelines share a single NCS queue name. Pipeline A declares a
`sentinel-threat` sink with `name: shared-events`; Pipeline B declares a
`sentinel` source with `addr: ncs://shared-events`. The NCS is the bus,
the source / sink pair is the contract.

This is the default mode described in Decision 5 of flow 061 and is what
`cookbook/config.reference.yaml` demonstrates.

### Same-Process Fan-In Mode

A single pipeline can also write into the NCS and read from it within
the same process — useful for routing ThreatEvents from one detector
chain into a second, specialised chain (e.g. only high-score events go
into a stricter chain). The source is unaware of the topology; it just
sees a `queue.Queue` handle.

### Plugin-Only Mode

The pipeline declares no `inputs:` of its own (or uses an empty stub
`file` source) and feeds the source via a `sentinel-threat` sink owned by
a completely independent process. As long as the queue name matches and
the NCS is reachable (always true in-process), the wiring works.

---

## Address Scheme

The source address uses a custom scheme to keep the configuration
unambiguous and to fail-fast on typos:

| Scheme       | Example                        | Parsed queue name |
|--------------|--------------------------------|-------------------|
| `ncs://`     | `ncs://shared-events`          | `shared-events`   |
| _anything else_ | `shared-events`             | rejected at `New()` |

The scheme lives in the constant `addrScheme` and is enforced by
`parseAddr()`. An address that does not start with `ncs://` produces
`sentinel source: invalid sentinel address "…": expected "ncs://"
scheme`. An address with an empty queue name (e.g. `ncs://`) produces
`queue name is empty`. Both errors are raised synchronously from `New()`
during pipeline startup, so a malformed config never reaches `Run()`.

The queue name must match the `name:` field of a writer that has already
called `executor.AttachWriter(name, …)` — otherwise `AttachReader` fails
and the source cannot be constructed. The pipeline startup
(`cmd/arxsentinel/main.go`) registers writers before constructing
readers, but the order is part of the contract: the source side is
strictly a *consumer* of a queue that someone else owns.

---

## Wire Protocol — `plugin.ThreatEvent`

The contract between `pkg/sink/sentinel/` and `pkg/source/sentinel/` is
the `plugin.ThreatEvent` struct, defined in `pkg/plugin/`:

| Field       | Type                | Source semantics                                                       |
|-------------|---------------------|------------------------------------------------------------------------|
| `Timestamp` | `time.Time`         | Wall-clock time of the detection (set by the writer).                  |
| `Level`     | `string`            | Severity tag (e.g. `WARN`, `THREAT`).                                  |
| `Stream`    | `string`            | Logical stream the writer was attached to.                             |
| `Source`    | `string`            | Free-form origin (e.g. `nginx`, `cloudflare`).                         |
| `IP`        | `string`            | Client IP. **Mandatory**: an empty IP is rejected at the source.      |
| `Score`     | `int`               | Aggregate score at the moment of detection.                            |
| `Modules`   | `[]string`          | Detector modules that fired.                                           |
| `Reason`    | `string`            | Human-readable explanation; surfaced as `LogEntry.UserAgent`.          |

The queue backend stores `ThreatEvent` values as opaque Go values — no
serialisation is performed in-process, no JSON is touched. The
translation to `LogEntry` happens in the source's `threatToEntry()`
function and nowhere else. Operators debugging the bridge should look
at `event.IP`, `event.Score`, and `event.Reason`; those are the only
fields the source consumes.

The `IP` field is the **only mandatory** one from the source's
perspective. A `ThreatEvent` that reaches the source with an empty `IP`
is logged and dropped, never forwarded to the pipeline.

---

## Configuration Reference

The sentinel source has a single configurable field — the queue address
— because the rest of its behaviour is fully described by the
`plugin.ThreatEvent` schema and the NCS contract.

| Field   | Type     | Default | Required | Description                                                       |
|---------|----------|---------|----------|-------------------------------------------------------------------|
| `type`  | `string` | —       | **yes**  | Must be `"sentinel"`.                                             |
| `addr`  | `string` | —       | **yes**  | Address of the NCS queue in the form `ncs://<queue-name>`.        |

The source does not consult a `parser:` — `plugin.ThreatEvent` is
already a structured Go value, so the `parser` slot is unused. The
`BuildOptions.Parser` passed to the factory closure in `register.go` is
silently ignored.

### Validation Rules

- A non-`sentinel` `type` produces the standard registry error
  `unknown type "…"` from `pkg/source`.
- A missing or malformed `addr` produces a wrapped error from
  `parseAddr()` during `New()`.
- A valid `addr` whose queue name has no writer registered in the NCS
  produces an error from `executor.AttachReader()` during `New()`. The
  pipeline fails to start — this is enforced by the wiring validation
  introduced in flow 061 / Task 2.

---

## Behaviour Details

### Run Loop

`Run(ctx context.Context, out chan<- *plugin.LogEntry) error` runs the
source until the context is cancelled or the NCS queue is closed.

For every iteration of the loop the source calls
`q.Pop(ctx)` on the queue handle obtained from
`executor.AttachReader(name)`. The result is one of:

- **`context.Canceled` / `context.DeadlineExceeded`** — the context was
  cancelled. The source returns `nil`; this is a normal shutdown.
- **`queue.ErrQueueClosed`** — the writer side called
  `executor.DetachWriter(name)` on the last writer and the queue is
  drained. The source returns `nil`; normal shutdown.
- **any other error** — a transient queue backend failure (network,
  disk, etc.). The error is logged via `logFn("SENTINEL", …, "error")`
  when `logFn` is non-nil, and the loop continues. The source never
  crashes on a transient backend error.
- **a `plugin.ThreatEvent`** — handed to `threatToEntry()`; the result
  is then offered to the `out` channel.

### Per-Event Processing

For every `plugin.ThreatEvent` received from `q.Pop(ctx)`:

1. The internal counter `linesRead` is incremented.
2. `threatToEntry(event)` is called.
3. If the function returns `nil` (the event has an empty `IP`), the
   `parseErrors` counter is incremented, a debug-level log entry is
   emitted, and the loop continues. An empty-IP event cannot be matched
   against any pipeline rule, so it is dropped at the boundary.
4. Otherwise the resulting `*plugin.LogEntry` is offered to `out` via a
   non-blocking send (`select { case out <- entry: default: … }`).
   When the channel is at capacity, the entry is discarded and the
   `dropped` counter is incremented.

### Wire Mapping — ThreatEvent → LogEntry

`threatToEntry()` performs a fixed, structural translation. It exists
exactly so that downstream pipeline stages (whitelist, scorer,
executor) can treat a sentinel-sourced entry the same as a log-line
entry from `stdin` or `http`:

| `LogEntry` field | Source on `plugin.ThreatEvent` | Notes |
|------------------|--------------------------------|-------|
| `Time`           | `event.Timestamp`              | Set by the writer at the time of detection. |
| `RemoteAddr`     | `event.IP`                     | TCP-style field, used by any rule that matches on client IP. |
| `RealIP`         | `event.IP`                     | Identical to `RemoteAddr` — kept separate so the existing downstream code that branches on `RealIP` (e.g. whitelist, whois) needs no changes. |
| `UserAgent`      | `event.Reason`                 | Carries the human-readable reason string the writer attached. |
| `ChainIssue`     | constant `"sentinel:event"`     | Marker so downstream stages can tell sentinel-sourced entries from log-sourced ones. |

All other `LogEntry` fields are left at their zero values. A sentinel
event carries no HTTP method, URI, status code, or referer — those are
properties of a log line, not a detection result.

### Drop Policy

Sends to the `out` channel are non-blocking. When the channel is full
the entry is discarded and the `dropped` counter is incremented. There
is no backpressure on the NCS side: a stalled downstream does not slow
down the queue backend. This matches the D3 drop policy used by the
other source plugins (`stdin`, `syslog`, `http`).

### Internal Constants

| Constant     | Value      | Purpose                                                                  |
|--------------|------------|--------------------------------------------------------------------------|
| `addrScheme` | `"ncs://"` | Prefix that marks the address as an NCS queue reference.                 |

The queue's own buffer size is **not** configured here — it is set by
the writer side (`pkg/sink/sentinel/`, `bufferSize` parameter) and by
the queue backend (`memory` / `bbolt` / `redis`, see
`pkg/executor/queue/`). The source always reads from the queue that the
writer registered.

---

## EOF and Cancellation

The source has three exit paths, all clean:

- **Context cancellation** — `ctx.Done()` fires. The in-flight
  `q.Pop(ctx)` returns `context.Canceled` and `Run()` returns `nil`.
  The source does not touch the NCS handle on its way out: the writer
  side owns the queue lifecycle.
- **Queue closed by writer** — the last writer calls
  `executor.DetachWriter(name)`. The queue backend closes and
  `q.Pop(ctx)` returns `queue.ErrQueueClosed`. The source treats this
  as a normal shutdown and returns `nil`. Any events that were in
  flight at the moment of closure have already been delivered in
  previous iterations; the source is not expected to re-read after
  `ErrQueueClosed`.
- **Transient backend error** — a network blip, a disk error, a Redis
  timeout. The error is logged at level `error` and the loop continues.
  `Run()` does **not** return. This is the only exit path that does
  not terminate the source.

### Close()

`Close()` is a **no-op** on the `SentinelSource`. The NCS queue's
lifecycle is owned by the writer side: the source attaches as a reader
in `New()` and never needs to detach. There is no `AttachReader` /
`DetachReader` symmetry on purpose — a source is allowed to disappear
without warning, but a writer disappearing while readers are still
attached would orphan the queue.

---

## Metrics and Stats

The source exposes three runtime counters via
`Stats() plugin.SourceStats`:

| Counter       | Type   | Description                                                          | Incremented when                                                       |
|---------------|--------|----------------------------------------------------------------------|------------------------------------------------------------------------|
| `linesRead`   | int64  | ThreatEvents received from the NCS queue.                            | Every successful `q.Pop(ctx)` call, regardless of whether the entry was sent to `out`. |
| `parseErrors` | int64  | ThreatEvents with an empty `IP`.                                     | `threatToEntry(event)` returns `nil`; the event is logged and skipped. |
| `dropped`     | int64  | Entries discarded because `out` was at capacity.                     | The non-blocking send to `out` falls into the `default` branch.        |

All three counters are updated with `sync/atomic` and are safe to read
from the metrics endpoint without taking a lock. There is intentionally
**no** "queue depth" counter — that metric lives on the queue
backend's own statistics endpoint (where one exists) and not on the
source.

---

## Constructors

Two constructors are exposed for the same `SentinelSource` type:

```go
// Production: parses addr, calls executor.AttachReader(name).
func New(addr string, logFn func(tag, msg, level string)) (*SentinelSource, error)

// Testable: injects a queue.Queue directly. Used by unit tests
// to avoid touching the global NCS singleton.
func NewWithQueue(name string, q queue.Queue, logFn func(tag, msg, level string)) *SentinelSource
```

`New()` is the entry point used by the registry factory closure in
`register.go`. It performs three things, in order:

1. `parseAddr(addr)` — validates the `ncs://<name>` shape.
2. `executor.AttachReader(name)` — obtains a `queue.Queue` handle from
   the NCS singleton. This step **must** find a registered writer with
   the same name, otherwise it returns an error and the source cannot
   be constructed.
3. `newWithQueue(name, q, logFn)` — populates the struct fields.

`NewWithQueue` skips steps 1 and 2 and is used by every test in
`source_test.go`. Production code paths go through `New()` only.

Both constructors accept a nil-safe `logFn`. When `nil`, the source
falls back to no logging — every diagnostic branch is guarded with an
`if s.logFn != nil` check, so a nil callback is a deliberate "stay
quiet" mode used by tests.

---

## Registration

The plugin is registered in `init()`:

```go
pkgsource.Register("sentinel", func(cfg pkgsource.InputConfig, opts pkgsource.BuildOptions) (plugin.Source, error) {
    return New(cfg.Addr, opts.LogFn)
})
pkgsource.RegisterManifest("sentinel", (&SentinelSource{}).Manifest())
```

The factory closure receives the `InputConfig.Addr` and
`BuildOptions.LogFn` from the pipeline builder; `BuildOptions.Parser`
is ignored. The manifest is registered separately so the pipeline
framework can advertise the plugin's input / output types before any
factory call is made.

---

## Quick-Start Examples

The following snippets are self-contained, copy-pasteable fragments
for `inputs[]`. Each one assumes the rest of the ArxSentinel stream
configuration is in place.

### Pipeline A → NCS → Pipeline B (canonical bridge)

Pipeline A writes ThreatEvents into the NCS via a `sentinel-threat`
sink; Pipeline B reads them back out via this `sentinel` source. The
two YAML files are typically run as two separate `arxsentinel` processes
(or as two `streams[]` blocks in a single process).

Pipeline A — `pipeline-a.yaml`:

```yaml
inputs:
  - type: file
    path: /var/log/nginx/access.log

outputs:
  - type: sentinel-threat
    name: inter-pipeline   # the NCS queue name
    bufferSize: 1000
```

Pipeline B — `pipeline-b.yaml`:

```yaml
inputs:
  - type: sentinel
    addr: ncs://inter-pipeline   # matches the sink name above

executors:
  - name: cf-block
    type: cloudflare
    sources:
      - name: threat-stream
        # (no explicit `queue:` here → defaults to in-process memory queue)
```

### Same-process fan-in

Route events from one pipeline chain into a second, specialised chain
without crossing a process boundary:

```yaml
# First chain: low threshold to catch everything.
# Second chain: stricter scorer that only acts on the survivors.
streams:
  - name: catch-all
    inputs:
      - type: file
        path: /var/log/nginx/access.log
    outputs:
      - type: sentinel-threat
        name: shared-events

  - name: strict
    inputs:
      - type: sentinel
        addr: ncs://shared-events
    scoring:
      ban_threshold: 95
    executors:
      - name: cf-block
        type: cloudflare
        sources:
          - name: threat-stream
```

### Plugin-only chain (no core processing)

A pipeline whose only job is to forward events from one NCS queue to
another — e.g. a routing layer in front of multiple specialised
pipelines. The `parser:` slot is empty because `plugin.ThreatEvent` is
already structured.

```yaml
inputs:
  - type: sentinel
    addr: ncs://ingress

outputs:
  - type: sentinel-threat
    name: fanout-east
```

---

## Edge Cases

**Empty IP in ThreatEvent.**
If `ThreatEvent.IP == ""`, the event is silently dropped: `parseErrors`
counter is incremented and `Run` continues to the next item. The
downstream pipeline never sees the entry. This protects against
partially-constructed events that upstream sinks may push during
error-recovery paths.

**Startup order: writer must register before reader.**
`New()` calls `executor.AttachReader(name)`. If no sink has called
`executor.AttachWriter(name)` (or `RegisterSinkFromConfig`) for that
name yet, `AttachReader` returns `"source %q not found"` and the
source fails to build — the pipeline aborts at startup. Always ensure
that executor queue pre-registration (`preRegisterExecutorQueues`) or
the sentinel-threat sink in the pipeline is wired before the sentinel
source is constructed.

**Queue close vs ctx-cancel race.**
Both `ErrQueueClosed` (from the last writer calling `DetachWriter`) and
`context.Canceled` (from the application shutting down) cause `Run` to
return `nil`. The two can race: whichever fires first wins. Either path
is safe — no events are lost because the queue is drained until it
blocks or closes before ctx propagates.

**NCS name mismatch (typo in YAML).**
If `addr: ncs://my-queue` does not match the name registered by the
sentinel-threat sink (e.g. the sink uses `name: my_queue`), `AttachReader`
returns an error at startup rather than silently reading from an empty
queue. Use `ValidateExecutorWiring` output on startup to catch mismatches
before the daemon goes live.

## Dependencies

Standard library:

- `context` — cancellation propagation into `q.Pop(ctx)`.
- `errors` — `errors.Is` checks for `context.Canceled`,
  `context.DeadlineExceeded`, and `queue.ErrQueueClosed`.
- `fmt` — error wrapping and log message formatting.
- `strings` — `HasPrefix` / `TrimPrefix` for address parsing.
- `sync/atomic` — counters (`linesRead`, `parseErrors`, `dropped`).

Project:

- `pkg/executor` — `AttachReader(name)` to obtain the NCS queue handle.
- `pkg/executor/queue` — `queue.Queue` interface (`Pop`, `Push`) and
  the sentinel `ErrQueueClosed` error.
- `pkg/plugin` — `Source`, `Manifest`, `SourceStats`, `LogEntry`, and
  the `ThreatEvent` wire format shared with `pkg/sink/sentinel/`.
- `pkg/source` — registry (`Register`, `RegisterManifest`,
  `InputConfig`, `BuildOptions`).
