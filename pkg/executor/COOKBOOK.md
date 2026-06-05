# NCS Cookbook — Practical Routing Patterns

The [Named Channel Switch](../README.md) (NCS) is the in-process bus
that connects pipeline sinks to executor sources through named
queues. The public API — `AttachWriter`, `AttachReader`,
`DetachWriter`, `RegisterSinkFromConfig` — is small. The interesting
part is the **topology** you build on top of it.

This cookbook collects the routing patterns that the NCS supports
"out of the box", without any new code. Each pattern is a
copy-pasteable YAML fragment with a short explanation of when to
use it and what its trade-offs are.

The full NCS contract — the writer-first / reader-second startup
order, why the NCS is a singleton, what `ValidateExecutorWiring`
catches — lives in [`pkg/executor/README.md`](../README.md). The
backend trade-offs (memory vs bbolt vs redis) live in
[`pkg/executor/queue/README.md`](../queue/README.md). This document
focuses on **how to wire the patterns**.

---

## 1. Plugin-only chain (pure routing, no core processing)

A pipeline whose only job is to forward events from one NCS queue to
another. Useful as a fan-out layer, a re-labelling layer, or a
canary-routing layer in front of specialised downstream pipelines.

```yaml
# routing-layer.yaml
inputs:
  - type: sentinel
    addr: ncs://ingress            # read from NCS queue "ingress"

outputs:
  - type: sentinel-threat
    name: fanout-east              # write to NCS queue "fanout-east"
```

`plugin.ThreatEvent` enters the pipeline through the `sentinel`
source, is re-emitted by the `sentinel-threat` sink, and exits
through the new NCS queue. Nothing in between — the `parser:`
slot stays empty because `plugin.ThreatEvent` is already a
structured event.

**Why use it:**

- Decouple the producer (e.g. a log parser chain) from the
  consumers (multiple specialised chains). The producer writes to
  one queue; the routing layer re-emits to several queues by
  replicating the pipeline.
- A/B test two executor chains side by side: route to
  `chain-canary` for 10% of events and `chain-stable` for the
  rest, by running two instances of this routing layer with
  different `outputs[].name` values.
- Bridge NCS name spaces: take events from queue `legacy` and
  forward them into a queue `next-gen` during a migration.

**Trade-offs:**

- Adds an extra `Push`/`Pop` round trip on every event. Negligible
  for in-process `memory` queues, measurable for `redis` over a
  network.
- The NCS queue name is now a *contract* between this routing
  layer and the next pipeline — renaming it requires updating two
  YAML files.

---

## 2. Chain forwarding (A → B → executor)

Two pipelines chain through the NCS so each one runs in its own
process (or at least its own stream) with its own lifecycle. This
is the canonical inter-pipeline bridge.

```yaml
# pipeline-a.yaml — produces threats
inputs:
  - type: file
    path: /var/log/nginx/access.log

outputs:
  - type: sentinel-threat
    name: inter-pipeline           # NCS queue name (the contract)
```

```yaml
# pipeline-b.yaml — consumes threats and acts on them
inputs:
  - type: sentinel
    addr: ncs://inter-pipeline     # matches pipeline-a's "name:"

executors:
  - name: cf-block
    type: cloudflare
    sources:
      - name: threat-stream
        # (no `queue:` → default memory; or pick bbolt/redis to
        #  share with another pipeline-b replica)
```

**Why use it:**

- Different lifecycles. Pipeline A may restart hourly for log
  rotation; pipeline B must keep running to act on queued
  threats.
- Different scaling units. Pipeline A is CPU-bound (log parsing);
  pipeline B is I/O-bound (API calls to Cloudflare). Run them on
  different hosts.
- Different trust boundaries. Pipeline A reads logs from a shared
  volume; pipeline B holds the Cloudflare API token. Keeping them
  in separate processes lets you scope the credentials narrowly.

**Trade-offs:**

- The NCS queue name becomes a deployment contract. The wiring
  validator (`pkg/pipeline/validator.go:ValidateExecutorWiring`)
  catches a mismatch at startup, but renaming the queue is still
  a two-file change.
- The two pipelines need a shared backend if they run in different
  processes. Use `bbolt` if both processes are on the same host
  (different files are fine — one file per queue), or `redis` for
  cross-host.

---

## 3. Same-process fan-in (one pipeline, two chains)

A single ArxSentinel process can run multiple `streams[]` blocks
that share an NCS queue. This is the in-process version of chain
forwarding — useful when the split is logical (different
executors, different actions) rather than operational. The shared
`scoring:` block sits at the root so every stream uses the same
threat model.

```yaml
scoring:
  ban_threshold: 50                # shared across all streams

streams:
  # First chain: catch everything with the shared threshold.
  - name: catch-all
    inputs:
      - type: file
        path: /var/log/nginx/access.log
    executors:
      - name: cf-block-soft
        type: cloudflare
        sources:
          - name: high-confidence
        # soft challenge via rate-limit rule

    outputs:
      - type: sentinel-threat
        name: high-confidence      # forward only the survivors

  # Second chain: same scorer, harder action.
  - name: strict
    inputs:
      - type: sentinel
        addr: ncs://high-confidence
    executors:
      - name: cf-block-hard
        type: cloudflare
        sources:
          - name: high-confidence
        # hard block via IP access rule
```

**Why use it:**

- Two-stage filtering without two processes. The first chain
  catches everything; the second chain only sees the survivors.
- Different executor actions on the same scored event — e.g. one
  Cloudflare executor soft-challenges, the other hard-blocks.
- Tests and demos. The whole pattern runs in a single process
  with a `memory` queue, so it is fast to spin up locally.

**Trade-offs:**

- Both chains share the same process lifecycle. If arxsentinel
  crashes, both chains restart together — there is no independent
  scaling.
- The NCS queue is `memory` only. If you need persistence for
  the in-flight events, split the chains into two processes
  (pattern 2).

---

## 4. Multi-backend deployment (one executor per backend)

The choice of `memory` / `bbolt` / `redis` is per
`ExecutorSourceRef`, not per arxsentinel instance. A single pipeline
can run several executors, each with the backend that fits its
operational shape.

```yaml
executors:
  # Cloudflare lives on the same host — persistent, but no cross-process need.
  - name: cf-block
    type: cloudflare
    sources:
      - name: cf-stream
        queue:
          type: bbolt
          path: /var/lib/arxsentinel/cf.db
          bucket: q

  # MikroTik lives in another region — share state via redis.
  - name: mk-block
    type: mikrotik
    sources:
      - name: mk-stream
        queue:
          type: redis
          url: redis://redis.eu-west:6379
          key: arxsentinel:queue:mk-stream

  # In-process detector chain — memory is enough.
  - name: detect-local
    type: nginx
    sources:
      - name: local-stream
        # (no queue: block → memory with default buffer = 1000)
```

**Why use it:**

- Match each executor's queue to its operational reality. The
  NCS does not care which backend a queue uses; the executor that
  reads from it does not care either.
- Migrate gradually. Switch the `cf-block` queue from `memory` to
  `bbolt` to add persistence, without touching `mk-block` or
  `detect-local`.

**Trade-offs:**

- More moving parts to monitor: one disk usage metric for bbolt,
  one Redis connection per pod for redis, one in-process buffer
  for memory.
- The `bbolt` queue's file path and the `redis` queue's URL must
  be reachable from the running arxsentinel process. A bad
  `path:` or `url:` is caught at startup by
  `RegisterSinkFromConfig`, not at runtime.

---

## 5. Cross-process bridge with shared backend

Two `arxsentinel` processes, one in region A, one in region B,
share a queue over a private network. The queue is `redis` (or
`bbolt` on a shared filesystem, but `redis` is the typical choice).

```yaml
# region-a.yaml
inputs:
  - type: file
    path: /var/log/nginx/region-a.access.log

outputs:
  - type: sentinel-threat
    name: shared-threats
    # (sinks don't pick the queue backend — see below)
```

```yaml
# region-b.yaml
inputs:
  - type: sentinel
    addr: ncs://shared-threats

executors:
  - name: cf-block
    type: cloudflare
    sources:
      - name: threat-stream
        queue:
          type: redis
          url: redis://redis.shared:6379
          key: arxsentinel:queue:shared-threats
```

The producer side (region A) writes to the NCS name
`shared-threats`. The NCS in region A's process is local — it
needs the queue to be backed by a redis client that talks to the
shared redis. To make that happen, the producer pipeline must
also declare a `queue:` block on its **executors** (or be wired
to a sentinel input with the right backend), or region A and
region B must run with the same NCS configuration.

In practice, cross-process bridge topologies are most often built
by giving **each side** a small `arxsentinel` config that pins the
shared queue to the shared backend. The two configs agree on the
queue name and the redis key. The wiring validator ensures the
name is consistent.

**Why use it:**

- Disaster-recovery or multi-region routing. Two arxsentinel
  instances in different regions can drain a single shared
  threat feed.
- Centralised threat aggregation. Many small arxsentinel
  instances (e.g. one per edge POP) push into a central
  aggregator, which then fans out to a single set of executors.

**Trade-offs:**

- Redis is now a critical dependency. A Redis outage halts event
  delivery on both sides.
- Network round-trip latency adds up. For sub-millisecond
  routing, keep the queue in-process (pattern 3) or on the same
  host (`bbolt`, pattern 4).

---

## 6. Canary routing (read NCS, re-emit twice)

A variation of the plugin-only chain that emits events to **two**
downstream queues, with one queue receiving a sample of events
(canary) and the other receiving the rest (stable). Useful for
rolling out a new executor chain alongside the current one.

```yaml
# canary-router.yaml
inputs:
  - type: sentinel
    addr: ncs://all-threats

outputs:
  # Stable: every event.
  - type: sentinel-threat
    name: stable-chain

  # Canary: 1% of events. Implemented by an executor or a
  # score-based filter; see the project's filtering plugins.
  # For a 50/50 split, run two instances of this router with
  # different addr values.
```

A true probabilistic split needs a plugin that samples events
before re-emitting. The pattern above is the structural
skeleton — pair it with whichever filter or sampler your
deployment uses.

**Why use it:**

- Roll out a new executor chain with limited blast radius. Send
  1% of events to `canary-chain`, watch the metrics, then
  re-point the stable queue at the new chain.
- Blue/green deploys. Toggle the router config to switch from
  `green-chain` to `blue-chain` with one YAML edit and a
  pipeline restart.

**Trade-offs:**

- The split ratio lives in plugin logic, not in NCS. The NCS
  only sees the two output queues.
- Re-emitting to two queues means every event is duplicated on
  the way out. The downstream executor chains must be
  idempotent (see the per-executor `dedup_window` config in
  `pkg/dedup/`).

---

## Operational checklist

Before any of these patterns go into production, work through
this list:

1. **Pick the backend per executor** using
   [`pkg/executor/queue/README.md`](../queue/README.md#queue-backend-selection-guide).
2. **Verify the writer-first order.** The pipeline startup in
   `cmd/arxsentinel/main.go` calls `preRegisterExecutorQueues`
   (for `bbolt`/`redis`) before `buildSinks` (for `memory`). If
   you write a custom main, mirror this order.
3. **Run the wiring validator.** It catches reader-without-writer
   and writer-without-reader at startup — exactly the class of
   silent failure these patterns risk.
4. **Plan buffer sizes for `sentinel-threat` sinks that cross a
   process boundary.** `bufferSize` is not a `SinkConfig` field —
   it is determined by the queue backend that consumes the sink's
   output (see `pkg/executor/queue/README.md`). For cross-process
   sinks, size the downstream queue (bbolt disk, redis memory,
   memory channel) to the expected burst.
5. **Monitor `Len()`** on every queue. A growing queue means
   consumers are falling behind. `bbolt` queues grow on disk;
   `redis` queues grow in Redis memory; `memory` queues drop
   with `ErrQueueFull`.
6. **Plan the shutdown.** The pipeline cancels its context, then
   calls `DetachWriter` for every writer. The order matters —
   see `pkg/executor/README.md` (Shutdown ordering).

---

## See also

- [`pkg/executor/README.md`](../README.md) — NCS architecture,
  public API, writer-first / reader-second contract.
- [`pkg/executor/queue/README.md`](../queue/README.md) — backend
  trade-offs and selection guide.
- [`pkg/source/sentinel/README.md`](../../source/sentinel/README.md)
  — sentinel source, with three quick-start examples that
  overlap with this cookbook.
- [`pkg/sink/sentinel/README.md`](../../sink/sentinel/README.md) —
  sentinel-threat sink, including the inter-pipeline routing
  section.
- Flow 061, Decision 5 — the architectural decision that
  pipeline-to-pipeline routing is documentation, not code.
