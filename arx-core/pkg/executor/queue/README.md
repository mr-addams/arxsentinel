# `pkg/executor/queue` — NCS Queue Backends

`*plugin.Event` values cross pipeline and executor boundaries through
a **`queue.Queue`** — a small interface with four methods (`Push`, `Pop`,
`Len`, `Close`). The queue itself is a storage primitive; it is *not* the
Named Channel Switch. The NCS (`pkg/runtime/`) holds queues by name; the
queue is the storage that backs a given NCS channel.

Three implementations live in this package. All three implement the same
`Queue` interface, so the NCS — and any plugin that calls `Pop` or
`Push` — is backend-agnostic. Choosing a backend is a **deployment**
decision, made through YAML (`ExecutorSourceRef.queue`), not a code
change.

| Backend | Storage | Process model | When to use |
|---------|---------|---------------|-------------|
| [`memory`](#memory-queue) | in-process channel | single process | dev, tests, low-latency in-process fan-in |
| [`bbolt`](#bbolt-queue) | file on disk | single writer, multiple readers (same file) | prod bare-metal / Docker; persistence without an external service |
| [`redis`](#redis-queue) | Redis list | distributed, multi-replica | k8s / multi-replica deployments that need a shared queue |

The full selection criteria — when to pick which backend — are in
[**Queue Backend Selection Guide**](#queue-backend-selection-guide)
below.

---

## The `Queue` interface

```go
// pkg/executor/queue/queue.go
type Queue interface {
    Push(ctx context.Context, payload []byte) error
    Pop(ctx context.Context) ([]byte, error)
    Len() int
    Close() error
}
```

Two sentinel errors are returned by every backend:

- `ErrQueueFull` — `Push` was called while the queue was at capacity.
  Sinks that hit this error may either block (with `ctx`) or drop the
  event; see the sink's documentation for its policy.
- `ErrQueueClosed` — `Push` or `Pop` was called after `Close`. Callers
  should treat this as a signal to terminate their loop.

`BboltQueue` additionally defines `ErrQueueCorrupted` for malformed
bucket state (seq/read counters or stored events).

All three backends are safe for concurrent `Push` and `Pop` calls.

---

## Memory Queue

`NewMemoryQueue(bufferSize int) *MemoryQueue` — in-process bounded
channel. Events live only as long as the process; they are lost on
restart.

- **Capacity:** `bufferSize` events; if `≤ 0`, defaults to `1000`.
- **Persistence:** none. On process exit, everything in flight is gone.
- **Multi-reader:** every reader attached to the same NCS name
  receives every event in the underlying channel (the same Queue
  instance is shared through the NCS).
- **Cross-process:** **no.** Memory queues are pure Go channels and
  cannot be shared with another process.

### When it shines

- Unit and integration tests (no file system, no external service).
- Single-process pipelines with a source and a sink inside the same
  `arx-core` instance.
- The default when `queue:` is absent from `ExecutorSourceRef` —
  zero-config, zero-dependency.

### When it bites

- **Process restart drops the in-flight buffer.** If the pipeline
  crashes, every queued `ThreatEvent` is lost. For bare-metal prod
  with any uptime requirement, choose `bbolt` or `redis`.
- **Back-pressure is strict.** `Push` returns `ErrQueueFull`
  immediately if the buffer is full and the context has not been
  cancelled. The buffer is fixed at the package's `DefaultBufferSize`
  (1000) and is not exposed via `QueueConfig`.

---

## Bbolt Queue

`NewBboltQueue(path, bucket string, log logger.Logger) (*BboltQueue, error)` —
events persisted in a single bbolt file. Survives process restarts; one
file per executor (or per NCS channel name).

`log` is the operational logger used for the `QUEUE` tag (one call site
in `Pop` — the "event lost during shutdown" warning). If `nil` is
passed, the constructor replaces it with `pkg/logger.Nop` — the queue
never crashes on a log call. The queue package is not
registry-registered; callers (the NCS for production, tests for unit)
instantiate it directly.

- **Capacity:** unbounded on disk. Memory is the constraint — `Len()`
  is `seq - read`, where both are uint64 counters stored in the
  bucket.
- **Persistence:** full. Every `Push` is fsync'd (via bbolt's default
  `fsync` mode) before the caller's goroutine returns from
  `safeSend`.
- **Multi-reader:** any number of `Pop` callers, but **only one
  process can open the file in read-write mode** (bbolt uses flock).
  For multi-process read access, run a single writer and either share
  the file via `redis` or split the writer/reader across different
  buckets.
- **Cross-process:** **only via a single writer.** Two `arx-core`
  processes pointing at the same `.db` file conflict on the bbolt
  lock. For two-process collaboration, use `redis`.

### When it shines

- **Single-instance production** — bare-metal VM, systemd service,
  single-container Docker. The queue survives a restart and
  reconnects without dropping a single event.
- **No external dependencies.** bbolt is embedded, the file is
  self-contained. No Redis to install, no network to monitor.
- **Audit trail.** The `.db` file can be inspected with `bolt` CLI
  tools; the bbolt bucket holds every event in JSON form until
  consumed.

### When it bites

- **Disk fills up.** The bucket is append-only until `Pop` removes
  the claimed key and advances the read pointer atomically via the
  write goroutine. If consumers fall behind, the file grows
  monotonically. Monitor `Len()` and provision enough disk.
- **100 ms poll on `Pop`.** When the queue is empty, `Pop` retries
  every 100 ms — cheap, but it sets a floor on latency for the
  first event after an idle period. If events arrive continuously,
  `Pop` claims them without waiting for the tick.
- **No multi-process writes.** A second process opening the same
  file fails the bbolt lock. If you need horizontal scale, switch
  to `redis`.

---

## Redis Queue

`NewRedisQueue(url, key string) (*RedisQueue, error)` — events stored
in a Redis list (`LPUSH` / `BRPOP`). Survives process restarts and is
shared across replicas.

- **Capacity:** bounded by available Redis memory (`maxmemory`).
- **Persistence:** whatever Redis is configured for. With default
  `RDB` or `AOF`, events survive a Redis restart. With
  `maxmemory-policy noeviction`, the server rejects writes when
  full — `Push` returns the error.
- **Multi-reader / multi-writer:** **yes.** Any number of
  `arx-core` instances can `Push` and `Pop` the same key, and
  Redis hands each event to exactly one consumer (Redis lists are
  not pub/sub).
- **Cross-process:** **yes.** This is the only backend that supports
  multi-replica deployments.

### When it shines

- **Kubernetes / multi-replica.** Several `arx-core` pods share
  the same queue. A failure or rolling restart of one pod does not
  stall event delivery — the other pods keep consuming.
- **Operational tooling already runs Redis.** Adding arx-core to
  an existing Redis-backed stack is one less moving part.
- **Long-distance pipelines.** Two `arx-core` processes in
  different data centres, sharing a queue over a private link.

### When it bites

- **External dependency.** Redis must be reachable from every
  arx-core instance, and it must be sized for the event
  throughput. A Redis outage halts the pipeline.
- **Network latency floor.** Every `Push` and `Pop` is a network
  round-trip. For a single-process pipeline on a single host, this
  is strictly slower than `memory` and roughly the same as `bbolt`
  (one fsync vs one network hop).
- **Serialization overhead.** Each event crosses the wire as JSON.
  The marshalling cost is negligible compared to the network
  round-trip, but it is real for high-volume pipelines.

---

## Configuration

`ExecutorSourceRef.queue` selects the backend and its parameters.
All fields are optional; an absent `queue:` block means **memory**
with the default buffer.

```go
// pkg/executor/queue/config.go
type QueueConfig struct {
    Type   QueueType `yaml:"type"`             // memory | bbolt | redis
    Path   string    `yaml:"path,omitempty"`   // bbolt: .db file path
    Bucket string    `yaml:"bucket,omitempty"` // bbolt: bucket name (Required — caller must set explicitly; core has no default, Phase 5)
    URL    string    `yaml:"url,omitempty"`    // redis: redis://[user:pass@]host:port[/db]
    Key    string    `yaml:"key,omitempty"`    // redis: list key (Required — caller must set explicitly; core has no default, Phase 5)
}
```

```yaml
# Memory — default. Buffer size is not configurable via YAML;
# QueueConfig has no `buffer`/`bufferSize` field. The buffer is
# the package's default (DefaultBufferSize = 1000).
executors:
  - name: cf-block
    sources:
      - name: cf-stream
        queue:
          type: memory

  # Bbolt — persistent single-host queue.
  - name: cf-block
    sources:
      - name: cf-stream
        queue:
          type: bbolt
          path: /var/lib/arx-core/cf-stream.db
          bucket: q

  # Redis — distributed, multi-replica.
  - name: cf-block
    sources:
      - name: cf-stream
        queue:
          type: redis
          url: redis://redis.svc:6379
          key: arx-core:queue:cf-stream
```

The configuration is consumed by the NCS in `pkg/runtime/`, which
constructs the right backend from `QueueConfig.Type` and registers it
under the channel name. After registration, every consumer attached
to that name receives the same queue instance — the backend is
invisible to the executor.

---

## Queue Backend Selection Guide

The choice between `memory`, `bbolt`, and `redis` is dominated by
**process model** and **durability requirement**. The following
decision rules are derived from the trade-offs above.

### Rule 1 — Default to `memory`

When in doubt, use `memory`. It is the default when `queue:` is
absent, it is the fastest, and it is the simplest to reason about
(no filesystem, no network). It is correct for **every** deployment
that does not need cross-process delivery or persistence.

**Use `memory` for:**

- Local development (`arx-core --config ./dev.yaml`).
- Unit and integration tests.
- Single-process production where losing the in-flight buffer on
  restart is acceptable (a few minutes of events, replayed from
  source on the next start).
- Any pipeline that already has another persistence layer upstream
  (e.g. a `file` source that is rotated and archived).

**Skip `memory` when:**

- The pipeline processes security events that must be acted on
  even after a crash.
- Two processes need to share the queue.

### Rule 2 — Use `bbolt` for prod single-instance

`bbolt` is the right answer for **any** production deployment that
runs a single `arx-core` instance (bare-metal, systemd,
single-replica Docker) and needs events to survive a restart.

**Use `bbolt` for:**

- Single-host production with persistence requirements.
- Compliance / audit scenarios where the queue file is the
  authoritative buffer.
- Air-gapped environments where adding Redis is not an option.

**Skip `bbolt` when:**

- More than one `arx-core` process needs to read or write the
  same queue — bbolt's file lock forbids this.
- The queue must be reachable from a different host.

### Rule 3 — Use `redis` for k8s and multi-replica

`redis` is the only backend that supports multiple writers and
multiple readers across processes. It is the right answer for
horizontal scale.

**Use `redis` for:**

- Kubernetes deployments with more than one pod.
- Any topology that runs multiple `arx-core` instances and
  needs them to share a queue.
- Long-distance pipelines (different hosts, different data
  centres).
- Production where a Redis outage is already a managed, alerted
  dependency.

**Skip `redis` when:**

- You are running a single instance — `bbolt` is cheaper and
  faster.
- Adding Redis would be the first external dependency in an
  otherwise self-contained deployment.

### Decision matrix

| Scenario | Backend |
|----------|---------|
| Local dev / tests | `memory` |
| Single-replica prod, no crash recovery | `memory` |
| Single-replica prod, must survive restart | `bbolt` |
| Multi-replica prod, k8s, shared state | `redis` |
| Cross-host / cross-DC pipelines | `redis` |
| Air-gapped prod, no external services | `bbolt` |

### Mixing backends

Different executor sources in the same pipeline can use different
backends — the choice is per `ExecutorSourceRef`, not per
arx-core instance. A typical mixed deployment looks like:

```yaml
executors:
  # Source-A lives on the same host as the pipeline → bbolt.
  - name: source-a-block
    sources:
      - name: source-a-stream
        queue:
          type: bbolt
          path: /var/lib/arx-core/a.db

  # Source-B lives in another region → redis.
  - name: source-b-block
    sources:
      - name: source-b-stream
        queue:
          type: redis
          url: redis://redis.eu-west:6379
          key: arx-core:queue:source-b-stream
```

This is by design. The NCS does not care which backend a given
queue name uses; the executor that reads from it does not care
either. Per-source choice keeps each executor's queue at its
natural deployment location.

---

## Operational notes

- **Backpressure.** All three backends surface `ErrQueueFull` from
  `Push`. Sinks that care drop or block per their own policy. If
  you see a growing `Dropped` counter, increase buffer size
  (memory), provision more disk (bbolt), or scale Redis (redis).
- **Graceful shutdown.** `Close` is idempotent on every backend.
  The pipeline's shutdown sequence cancels the application context
  first, waits for `Pop` callers to return, and only then calls
  `Close`. Reversing this order risks dropping in-flight events.
- **Inspecting a bbolt file.** The bbolt CLI (`go install
  go.etcd.io/bbolt/cmd/bbolt@latest`) can dump a queue's contents
  for debugging:

  ```bash
  bbolt page /var/lib/arx-core/a.db
  bbolt get /var/lib/arx-core/a.db q <key> --format hex
  ```

  The bucket is JSON-serialised `*plugin.Event` records
  keyed by an internal `uint64` sequence. Iterating the page
  shows the full backlog.
- **Redis observability.** `LLEN arx-core:queue:<name>` reports
  the current depth; `LRANGE … 0 9` peeks at the ten oldest
  events. Standard Redis monitoring applies.

---

## See also

- `pkg/runtime/` — the NCS itself, including the writer-first /
  reader-second startup contract.
- `pkg/executor/registry.go` — `RegisterExecutor` / `RegisterSink`,
  the entry points plugins use to wire executors and sinks into
  the runtime.
- `docs/plugin-development.md` — how to build a plugin that reads
  from a queue via `EventSource`.
- `docs/architecture.md` — runtime lifecycle and NCS wiring.