# pkg/ncs — Named Channel Switch (NCS)

In-process singleton that connects named pipeline sinks (writers) with executor
sources (readers). The package owns the dispatch table; each queue lives behind
a `queue.Queue` interface and may be in-memory, bbolt, or redis — chosen at
registration time.

## Public API

All five entry points operate on the global singleton and are safe for
concurrent use.

| Function | Purpose |
|---|---|
| `AttachWriter(name, bufferSize)` | Register a fresh in-memory queue under `name` and return it for `Push`. If the name already exists, the existing queue is reused (fan-in) and the reference counter is incremented. |
| `AttachWriterWithQueue(name, q)` | Register an externally-built `queue.Queue` (e.g. bbolt, redis) under `name`. Same fan-in semantics as `AttachWriter`. |
| `RegisterSinkFromConfig(name, cfg, log)` | Build the queue from a `queue.QueueConfig` (memory / bbolt / redis) and register it. First registration wins; later calls do fan-in. |
| `AttachReader(name)` | Return the previously registered queue for `Pop`. Returns an error if no queue is registered under `name`. |
| `DetachWriter(name)` | Decrement the reference counter. The queue is closed and removed only when the last sink deregisters. |

## Boundary (ADR-002)

`pkg/ncs` is a Core package. It imports ONLY Core siblings:

- `pkg/executor/queue` — the queue interface and its backends
- `pkg/logger` — typed logger used by `RegisterSinkFromConfig`
- `pkg/plugin` — `plugin.EventSource` compile-time assertion

It does NOT import anything from `internal/`. It does NOT use any
security-vocabulary (threat/ban/whitelist/blocklist/chainguard/chaincheck) and
does NOT issue verdicts (`WARN`/`THREAT`/`BAN`). NCS is pure plumbing.

## Rationale

Extracted from `pkg/executor` per ADR-002 (Phase 2.1.2, blocking pre-task).
The singleton was the only piece of `pkg/executor` with no dependency on
plugin registration, manifests, or executor lifecycle. Moving it into its own
Core package unlocks the subsequent `pkg/executor` registry extraction to
`arx-core` and keeps `pkg/ncs` reusable from any pipeline component.

Reference: `docs/architecture/adr/002-telemetrycore-boundary.md`.