# `pkg/executor` — Named Channel Switch (NCS)

`pkg/executor` hosts two responsibilities that the rest of ArxSentinel relies
on at runtime:

1. **The executor registry** (`registry.go`) — the factory map that turns a
   `type: cloudflare` / `mikrotik` / `nginx` block in YAML into a running
   `plugin.Executor` with its config, sources, and lifecycle.
2. **The Named Channel Switch** (NCS) — the in-process message bus that
   connects pipeline sinks to executor sources through *named* queues. The
   NCS lives in `channelswitch.go` and is what makes pipeline-to-pipeline
   routing possible (see flow 061, Decision 5).

This document focuses on the NCS. The executor registry is documented
inline (`registry.go`) and in the per-executor packages
(`pkg/executor/cloudflare/`, `pkg/executor/mikrotik/`, `pkg/executor/nginx/`).

---

## What is the NCS

The Named Channel Switch is a **package-level singleton** that maps
`name → queue.Queue`. Producers register a queue under a name, consumers
look it up by the same name. There is no broadcasting: each name has
exactly one underlying queue, and any number of readers can attach to it.

The name "switch" is deliberate (flow 061, Decision 9). A *hub* would imply
broadcast semantics — every reader gets every message. A *switch* implies
addressed routing — the writer picks a name, the reader picks the same
name, and the queue is theirs alone. That is what NCS implements.

```
                 ┌──────────────────────────────────┐
                 │  Named Channel Switch (NCS)      │
                 │                                  │
   producer ───► │  AttachWriter("threats", q)      │ ───► reader(s)
   (sink)        │  AttachReader("threats")         │       (executor source)
                 │  DetachWriter("threats")         │
                 │                                  │
                 │  map[name] → queue.Queue         │
                 └──────────────────────────────────┘
```

NCS is in-process. It does not implement any cross-process transport —
it is a Go map protected by a mutex. The "queue" it returns can itself
be backed by `memory` (in-process channel), `bbolt` (on-disk file), or
`redis` (cross-process). See `pkg/executor/queue/` for the backend
trade-offs.

---

## Public API

| Function | Role | Lifetime |
|----------|------|----------|
| `AttachWriter(name, bufferSize)` | Register a `MemoryQueue` under `name`; returns the queue. | Writer calls `DetachWriter` when done. |
| `AttachWriterWithQueue(name, q)` | Register an externally-created queue (bbolt/redis) under `name`. | Same. |
| `AttachReader(name)` | Look up the queue registered under `name`; returns it for reading. | Reader does not detach (see below). |
| `DetachWriter(name)` | Remove the writer from the registry; close the queue. | Once. Calling it twice is a no-op. |
| `RegisterSinkFromConfig(name, cfg)` | Create the appropriate queue backend from `QueueConfig` and register it. | Same as `AttachWriter*`. |

The reader API is intentionally one-sided: there is no `DetachReader`.
A source is allowed to disappear without warning, but a writer
disappearing while readers are still attached would orphan the queue
(flow 061, Decision 5 / Task 3.1). The writer side is the canonical
owner of the queue lifecycle.

`AttachReader` returns an error when the name is unknown — this is the
mechanism `pkg/source/sentinel/` uses to fail fast on a typo. Combined
with `ValidateExecutorWiring` (see below), the wiring of any pipeline
that crosses the NCS is checked at startup, not at runtime.

---

## Architecture: pipeline-to-pipeline routing

The NCS is the bus that turns two independent pipelines into one logical
data flow. There is no special "inter-pipeline" mode — any combination of
the existing sink and source plugins will do.

### The pattern

```
   process A                                 process B
 ┌──────────────┐                         ┌──────────────┐
 │  pipeline A  │                         │  pipeline B  │
 │              │                         │              │
 │  inputs:     │                         │  inputs:     │
 │    - file    │                         │    - sentinel│
 │              │                         │      addr:   │
 │  outputs:    │                         │      ncs://  │
 │    - sentinel│                         │      threats │
 │      name:   │      ┌──────────┐       │              │
 │      threats │ ────►│   NCS    │──────►│  executors:  │
 │              │      │ "threats"│       │    - cloudfl.│
 └──────────────┘      └──────────┘       └──────────────┘
```

The NCS is the same singleton in both processes? No — by default, NCS
is per-process. The two processes above share an NCS queue only if the
queue backend is `bbolt` (same file) or `redis` (same key). The
`memory` backend cannot cross a process boundary; it is the right
choice when both ends live in the same ArxSentinel instance (the common
case for in-process fan-in or for tests).

### What is required to wire two pipelines through the NCS

1. A **sink** that writes `plugin.ThreatEvent` values into a named queue.
   The canonical choice is `pkg/sink/sentinel/` — the
   `sentinel-threat` sink plugin. It calls `AttachWriter(name, bufSize)`
   from its `New` constructor.
2. A **source** that reads the same `plugin.ThreatEvent` values out of
   the named queue. The canonical choice is `pkg/source/sentinel/` —
   the `sentinel` source plugin. It parses `ncs://<name>` from the
   `addr:` field and calls `AttachReader(name)`.
3. **Matching names.** The sink's `name:` field must equal the source's
   `addr: ncs://<name>`. A mismatch is caught at startup by
   `ValidateExecutorWiring` (see below) before any goroutine is
   launched.

That is all. There is no extra glue, no "inter-pipeline" config
section, no new code.

### Why two separate plugins for the same data

`pkg/sink/sentinel/` and `pkg/source/sentinel/` are kept in different
directories on purpose. ArxSentinel's plugin framework enforces a hard
`source / sink` split (enforced by separate registries in `pkg/source/` and `pkg/sink/`, with roles defined in `pkg/plugin/roles.go`); a plugin that
both reads and writes would violate it and lose the static type
information that the wiring validator relies on. The two plugins share
a single wire format — `plugin.ThreatEvent` — which is the smallest
surface that lets them interoperate.

### Same-process fan-in

The same pair of plugins also covers the **single-process** case: a
pipeline that wants to split its event stream into a second,
specialised chain (e.g. only high-score events into a stricter scorer).
Both plugins run inside the same ArxSentinel process, the queue is
`memory`, and the contract is identical — only the topology is
simpler.

### Plugin-only chains

A pipeline can declare a `sentinel` source and a `sentinel-threat`
sink with no other plugin in between. This is the
**plugin-only routing chain**: events enter from the NCS, get re-emitted
into a different NCS queue, and exit. Use cases include:

- A fan-out layer in front of several specialised downstream pipelines.
- A re-labelling layer that swaps one executor chain for another
  (e.g. during a canary deploy).

The NCS handles this without any new code — the validator simply checks
that the source's `addr:` matches some sink's `name:`, and at runtime
the in-process map routes the events.

---

## Queue backends

The queue returned by `AttachReader` is a `queue.Queue`. There are
three backends, all live in `pkg/executor/queue/`:

| Backend | Storage | Process model | When to use |
|---------|---------|---------------|-------------|
| `memory` | in-process channel | single process | dev, tests, low-latency in-process fan-in |
| `bbolt` | file on disk | single writer, multiple readers (same file) | prod bare-metal / Docker; persistence without an external service |
| `redis` | Redis list | distributed, multi-replica | K8s / multi-replica deployments that need a shared queue |

The backend is selected per-`ExecutorSourceRef` through the `queue:`
config block (flow 061, Decision 1). When the block is absent, the NCS
falls back to `memory` with the default buffer size.

See `pkg/executor/queue/README.md` for the full selection guide and
the trade-off matrix.

---

## Validation: `ValidateExecutorWiring`

`pkg/pipeline/validator.go` exposes a static check that runs at
startup, before any pipeline goroutine is started. It catches three
classes of NCS mistakes (flow 061, Decisions 2 and 5):

1. **Reader without writer** — an executor source references a name
   that no sink has registered. The pipeline aborts with
   `"executor … wired to unknown channel '<name>'"`.
2. **Writer without reader** — a `sentinel-threat` sink is registered
   with a name that no executor source reads. The pipeline aborts with
   `"channel '<name>' has writer but no reader"`. This is the check
   that prevents unbounded queue growth in inter-pipeline deployments
   where the second pipeline forgets to start.
3. **Type mismatch** — a channel produced by sink type `A` is read by a
   source that expects type `B`. The pipeline aborts with
   `"channel '<name>' produces … but executor … expects …"`.

The validator works on the parsed config, not on the runtime NCS state.
That is a deliberate trade-off: it cannot catch a *runtime* dangling
channel (a writer that outlives its reader), but it covers every
case where a typo or a forgotten `sources:` block would otherwise
result in a silent deadlock at runtime.

`cmd/arxsentinel/main.go` calls `validateConfig` (which wraps
`ValidateExecutorWiring`) immediately after `config.LoadConfig` and
before any pipeline goroutine starts, so a misconfigured config never
reaches the running system.

---

## Startup ordering: writer first, reader second

The pipeline startup sequence in `cmd/arxsentinel/main.go` is the
canonical reference:

1. `config.LoadConfig` — read YAML.
2. `validateConfig` — run `ValidateExecutorWiring`. Fail fast on error.
3. `preRegisterExecutorQueues` — for every `sources[].queue: { type:
   bbolt|redis }` block, call `RegisterSinkFromConfig` so the named
   queue exists in the NCS before any reader tries to attach.
4. `runStream` → `buildSinks` — instantiate every `sentinel-threat`
   sink. Each sink's `New` calls `executor.AttachWriter(name, bufSize)`.
5. `time.Sleep(200ms)` — small grace period to let the writer-side
   goroutines finish registering.
6. `startExecutors` — for every executor source, call
   `executor.AttachReader(name)`. This succeeds because step 3 or
   step 4 already created the queue.

This order is part of the contract. The reader side
(`pkg/source/sentinel/source.go` → `New` → `AttachReader`) is allowed
to fail if the writer side has not run yet, and the wiring validator
exists precisely to make sure that the order will work before any
goroutine starts.

---

## Shutdown ordering

`cmd/arxsentinel/main.go` reverses the writer/reader order on shutdown:

1. The application context is cancelled. Sources that were blocked in
   `q.Pop(ctx)` unblock with `context.Canceled` and return.
2. `executor.DetachWriter(name)` is called for every source name. This
   closes the underlying queue.
3. Readers that were still draining see `queue.ErrQueueClosed` from
   `q.Pop` and return.
4. `execWg.Wait()` blocks until every executor goroutine has exited.

The order matters: cancelling the context first lets in-flight
`Pop` calls exit, and only then is the queue closed. Reversing the two
would risk dropping events that the readers were about to consume.

---

## Why the NCS is a singleton

There is exactly one NCS per process. This is by design:

- The executor map (`hubQueues` / `hubRefs`) is package-level state.
  Splitting it would force every reader and writer to know which
  instance to talk to, which is exactly the configuration the NCS is
  supposed to remove.
- In tests, the singleton is a problem — every test would share the
  same global map. To work around this, `pkg/source/sentinel/` exposes
  a `NewWithQueue` constructor that skips the registry and accepts a
  queue handle directly. Tests use that path; production code goes
  through `New`. `pkg/sink/sentinel/` tests use `NewSentinelThreatSink`
  with a pre-registered queue name.

If a future feature requires more than one NCS per process, the change
is localised: replace the package-level `var` with a struct, inject it
through a context value, and update the three call sites in
`channelswitch.go`. No consumer code needs to change — the public
API stays the same.

---

## See also

- `pkg/source/sentinel/README.md` — INPUT side of the bridge, with
  examples of canonical pipeline-A → pipeline-B wiring.
- `pkg/sink/sentinel/README.md` — OUTPUT side of the bridge.
- `pkg/executor/queue/README.md` — queue backends and the
  selection guide.
- `pkg/pipeline/validator.go` — the wiring validator.
- `cmd/arxsentinel/main.go` — the startup / shutdown sequence that
  implements the writer-first, reader-second contract.
- Flow 061, Decision 5 — the architectural decision that
  pipeline-to-pipeline routing is documentation, not code.
