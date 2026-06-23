# pkg/ncs — Named Channel Switch

In-process singleton that connects named pipeline sinks (writers) with
executor sources (readers). The package owns the dispatch table; each
queue lives behind a `queue.Queue` interface and may be in-memory,
bbolt, or redis — chosen at registration time.

## Public API

All five entry points operate on the package-level singleton and are
safe for concurrent use.

| Function | Purpose |
|---|---|
| `AttachWriter(name, bufferSize)` | Register a fresh in-memory queue under `name` and return it for `Push`. If the name already exists, the existing queue is reused (fan-in) and the reference counter is incremented. |
| `AttachWriterWithQueue(name, q)` | Register an externally-built `queue.Queue` (e.g. bbolt, redis) under `name`. Same fan-in semantics as `AttachWriter`. |
| `RegisterSinkFromConfig(name, cfg, log)` | Build the queue from a `queue.QueueConfig` (memory / bbolt / redis) and register it. First registration wins; later calls do fan-in. |
| `AttachReader(name)` | Return the previously registered queue for `Pop`. Returns an error if no queue is registered under `name`. |
| `DetachWriter(name)` | Decrement the reference counter. The queue is closed and removed only when the last sink deregisters. |

## Boundary

`pkg/ncs` is a Core package. It imports only Core siblings:

- `pkg/executor/queue` — the queue interface and its backends.
- `pkg/logger` — typed logger used by `RegisterSinkFromConfig`.
- `pkg/plugin` — `plugin.EventSource` compile-time assertion.

It does not import any host-internal package. It contains no
product-specific vocabulary — NCS is pure plumbing.

## Why a singleton

No DI framework, no middleware, no config wiring. Two call sites
(pipeline and executor) that never import each other. A singleton is
the simplest correct bridge.

## Thread safety

`RWMutex` — `AttachWriter`, `AttachWriterWithQueue`, and `DetachWriter`
take the write lock; `AttachReader` takes the read lock.

## Usage example

```go
import (
    "context"
    "github.com/mr-addams/arx-core/pkg/ncs"
)

// Writer side (sink): register or join a named queue.
q, err := ncs.AttachWriter("hub-main", 1000)
if err != nil {
    return err
}
defer ncs.DetachWriter("hub-main")

_ = q.Push(ctx, event)

// Reader side (executor): consume from the same name.
rq, err := ncs.AttachReader("hub-main")
if err != nil {
    return err
}
for {
    ev, err := rq.Pop(ctx)
    if err != nil {
        break
    }
    _ = ev
}
```
