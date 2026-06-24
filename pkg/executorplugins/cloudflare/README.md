# `pkg/executorplugins/cloudflare` — Cloudflare Executor

Cloudflare executor plugin for ArxSentinel. Consumes scored `ThreatEvent`
records from the pipeline, batches them, and pushes the resulting IP block
list into a Cloudflare account-level List via the Lists API v4. The list
is the integration surface for downstream WAF rules — a `block` action
on it stops traffic at the edge without touching the customer origin.

- **Plugin ID:** `cloudflare`
- **Plugin version:** `1.0.0`
- **Role:** `Executor`
- **Input type:** `scored_event`
- **Output type:** `none`
- **Tags:** `cloudflare`, `waf`, `api`

## Module Layout

```
pkg/executorplugins/cloudflare/
├── manifest.go    # Plugin metadata
├── config.go      # Config struct + defaults + validation
├── client.go      # CFClient interface + HTTPCFClient (Lists API v4)
├── executor.go    # CloudflareExecutor — run loop, batching, sweep
└── register.go    # init() — registry wiring
```

---

## Configuration Reference

The executor is declared under `executors[]` in the stream configuration.
All fields are parsed from the per-executor `config:` map; duration fields
accept either a Go-style string (`"24h"`, `"30s"`) parsed by
`time.ParseDuration`, or an integer interpreted as **seconds**.

| Field           | Type            | Default                    | Required | Description                                                                |
|-----------------|-----------------|----------------------------|----------|----------------------------------------------------------------------------|
| `api_token`     | `string`        | —                          | **yes**  | Cloudflare API token with `Account: Account Filter Lists: Edit` permission. |
| `account_id`    | `string`        | —                          | **yes**  | Cloudflare account ID. The list is created at the account level.           |
| `list_name`     | `string`        | `"arxsentinel_blocklist"`  | no       | Name of the List resource. Created on first run if it does not exist.      |
| `min_level`     | `string`        | `"THREAT"`                 | no       | Minimum event level to act on. One of `INFO`, `WARN`, `THREAT`.            |
| `ttl`           | `time.Duration` | `24h`                      | no       | Ban lifetime. `> 0`. String via `time.ParseDuration` or int(seconds).      |
| `max_items`     | `int`           | `0` (no limit)             | no       | Cap on the number of items in the list. `0` disables the cap.              |
| `dedup_window`  | `time.Duration` | —                          | no       | Intra-batch dedup window. String or int(seconds).                          |
| `batch_size`    | `int`           | `100`                      | no       | Maximum events bundled into a single bulk add.                             |
| `flush_interval`| `time.Duration` | `10s`                      | no       | Maximum time to wait before flushing a partial batch.                      |
| `instance_id`   | `string`        | resolved at runtime        | no       | Stable identifier of this agent instance. Used in the list comment.        |
| `comment_extra` | `string`        | —                          | no       | Free-form suffix appended to the comment of every entry this instance adds. |
| `api_base_url`  | `string`        | `https://api.cloudflare.com/client/v4` | no | Override for tests or proxied environments.                          |

### Validation Rules

- `api_token` and `account_id` are mandatory — missing values cause a
  startup error.
- `min_level` must be one of `INFO`, `WARN`, `THREAT`. Any other value is
  rejected at startup.
- `ttl` must be strictly positive (`> 0`). A zero or negative TTL is
  rejected to prevent permanent bans that would otherwise need a separate
  clear path.
- Duration fields (`ttl`, `dedup_window`, `flush_interval`) are parsed by
  `time.ParseDuration` from string, or interpreted as integer seconds
  when a numeric value is supplied.
- `instance_id` resolution chain: explicit `cfg.instance_id` →
  `/var/lib/arxsentinel/instance.id` → `/etc/machine-id` → random UUID.
  The first non-empty source wins; the random UUID is the final fallback.

---

## Behaviour Details

### Run Loop

`Run(ctx context.Context, in <-chan *plugin.ThreatEvent) error` runs the
executor until context cancellation. The sequence is:

1. **Connect.** Build an `HTTPCFClient` with a `30s` HTTP timeout, Bearer
   token from `cfg.api_token`, and the configured `api_base_url`.
2. **FindOrCreateList.** `GET /accounts/{id}/rules/lists?name=…` followed
   by a `POST …/lists` on miss. Bounded by a `30s` startup timeout;
   failure terminates `Run()`.
3. **syncExisting.** Load the current list contents into the local
   `banned` map so events received immediately after startup do not
   produce duplicate add operations. Network errors are logged but
   **non-fatal** — the executor proceeds with an empty map.
4. **Buffer.** Each event is offered to an internal flush channel. Events
   below `min_level` are dropped silently.
5. **Flush.** When the buffer reaches `batch_size` (default `100`) or
   `flush_interval` (default `10s`) elapses, whichever comes first, the
   buffered IPs are pushed as a single bulk add operation.
6. **Sweep.** A periodic timer fires every `ttl / 4` (with a hard floor
   of `15m`) and evicts expired entries from the Cloudflare list.

### Flush Strategy

The executor races two conditions on every batched event:

- **Count trigger.** When the in-memory buffer holds `batch_size` events
  (default `100`), the batch is committed immediately.
- **Time trigger.** When `flush_interval` (default `10s`) elapses since
  the last flush, the partial batch is committed.

The committed batch is sent to `AddItems`, which issues a single
`POST /accounts/{id}/rules/lists/{listID}/items` and returns an
`operation_id`. The executor then polls `PollBulkOperation` with
**exponential backoff** (`500ms` → `16s`, up to `6` attempts ≈ `31.5s`).

Bulk operation statuses observed are `"pending"`, `"completed"`,
`"failed"`. A `failed` status aborts the batch — the events stay in the
buffer for the next flush attempt and the `errors` counter is
incremented.

### Sweep / TTL Eviction

A sweep cycle runs every `ttl / 4`, with a hard minimum of `15 minutes`
to avoid hammering the API. Each cycle:

1. Calls `GetAllItems(listID)` to fetch the current list contents.
2. Computes `expiry = addedAt + ttl` for every entry. Entries with
   `expiry <= now` are scheduled for removal.
3. Issues a bulk `RemoveItems` and polls the operation to completion
   using the same exponential-backoff scheme as the add path.
4. Updates the local `banned` map to drop the evicted entries.

If the sweep fails (network error, non-2xx response, `failed` bulk
status), the entries are kept in `banned` and retried on the next
sweep. The error is logged and the `errors` counter is incremented.

### Deduplication

The `banned` map is pre-populated in `syncExisting` and updated
synchronously on every successful flush. Its purpose is **intra-batch
deduplication**: events for the same IP that arrive while the previous
batch is still being processed are dropped before they reach the buffer.
Pre-registration on receive catches duplicates that would otherwise slip
through between the buffer-and-flush boundary.

The `dedup_window` field narrows the map to entries added within the
last `dedup_window`. Entries older than the window are evicted from the
map on every flush, keeping memory bounded for long-lived executors.

### Rate Limiting / 429 Handling

Cloudflare returns HTTP `429` when the account-level request rate is
exceeded. The executor retries the failed request up to `3` times with
a fixed `5s` backoff between attempts. If all retries fail, the batch
is abandoned and the events are re-buffered for the next flush.

### Instance ID Resolution

The instance identifier marks every entry this agent has added, so the
sweep step (and any future multi-instance tooling) can distinguish
entries produced by different sentinels running against the same
account. The resolution chain is:

1. `cfg.instance_id` if set and non-empty.
2. Contents of `/var/lib/arxsentinel/instance.id` if the file is
   readable and non-empty.
3. Contents of `/etc/machine-id` if the file is readable and non-empty.
4. A freshly generated random UUID v4 as the final fallback.

The resolved value is stable for the lifetime of the process and
embedded in every comment of the form
`sentinel-<instanceID>[ <comment_extra>]`.

### Internal Constants

| Constant                   | Value            | Purpose                                                       |
|----------------------------|------------------|---------------------------------------------------------------|
| `defaultAPIBaseURL`        | `https://api.cloudflare.com/client/v4` | Default Cloudflare API root.                  |
| `defaultHTTPTimeout`       | `30s`            | Per-request HTTP client timeout.                              |
| `defaultStartupTimeout`    | `30s`            | Maximum time to wait for the initial `FindOrCreateList`.      |
| `defaultBatchSize`         | `100`            | Default events-per-bulk threshold.                            |
| `defaultFlushInterval`     | `10s`            | Default time-based flush trigger.                             |
| `defaultTTL`               | `24h`            | Default ban lifetime.                                         |
| `defaultListName`          | `arxsentinel_blocklist` | Default list name when `list_name` is unset.            |
| `defaultMinLevel`          | `"THREAT"`       | Default minimum event level.                                  |
| `minSweepInterval`         | `15m`            | Floor for the sweep cadence.                                  |
| `pollMaxAttempts`          | `6`              | Maximum number of bulk-op status polls.                       |
| `pollInitialBackoff`       | `500ms`          | First poll backoff; doubles on each attempt.                  |
| `pollMaxBackoff`           | `16s`            | Cap on the per-attempt poll backoff.                          |
| `maxRetries`               | `3`              | Maximum retries on HTTP `429`.                                |
| `retryBackoff`             | `5s`             | Fixed delay between retry attempts.                           |
| `commentPrefix`            | `"sentinel-"`    | Prefix of the comment stamped on every entry.                 |
| `instanceIDPath`           | `/var/lib/arxsentinel/instance.id` | First lookup for the resolved instance ID.   |
| `machineIDPath`            | `/etc/machine-id`                 | Second lookup for the resolved instance ID.  |

---

## EOF, Cancellation, and Shutdown

The executor exits through one of three paths:

- **Context cancellation.** The main loop selects on `ctx.Done()` and
  returns the context error. Any in-flight bulk operation is allowed to
  finish its current attempt; no new flushes are started. The `pending`
  bulk `operation_id` and the time it was issued are tracked in
  `pendingMu`/`pendingOpID`/`pendingOpAt` so a future restart can resume
  or clean up the in-flight operation.
- **Startup failure.** A failure in `FindOrCreateList` (timeout,
  authentication error, network error) terminates `Run()` before the
  event loop starts. The stream supervisor will see the error and decide
  whether to retry.
- **Fatal sweep failure.** Sweep errors are **non-fatal**: they are
  logged, the `errors` counter is incremented, and the next sweep
  attempts a fresh `GetAllItems`. The executor only exits on
  cancellation.

---

## Metrics and Stats

The executor exposes three runtime counters via
`Stats() plugin.ExecutorStats`:

| Counter    | Type   | Description                                                    | Incremented when                                                                  |
|------------|--------|----------------------------------------------------------------|-----------------------------------------------------------------------------------|
| `executed` | int64  | Events successfully pushed into the Cloudflare list.           | The bulk `AddItems` operation completes with `status == "completed"`.             |
| `skipped`  | int64  | Events dropped due to level filter or dedup.                   | The event's level is below `min_level`, or the IP is already in `banned`.         |
| `errors`   | int64  | Errors during add, remove, sweep, or startup.                  | HTTP non-2xx, bulk op `failed`, `FindOrCreateList` timeout, or sweep I/O error.   |

All three counters use `sync/atomic` and are safe to read from the
metrics endpoint without taking the executor lock.

---

## Constructors

```go
func NewCloudflareExecutor(cfg executor.ExecutorConfig, log logger.Logger) (plugin.Executor, error)
```

`NewCloudflareExecutor` is the public constructor. It accepts an
`executor.ExecutorConfig` (the generic `pkg/executor` descriptor: the
`Name`/`Type`/`Config` map forwarded by `Build`), decodes the `Config`
from the inner `Config` map, validates the required fields, and returns
a fully initialized `*CloudflareExecutor`.

`log` is the operational logger used for `EXECUTOR`/`CONFIG` tags. If `nil`
is passed, the constructor replaces it with `pkg/logger.Nop` — the executor
never crashes on a log call. The registry-based factory (`newCloudflareFactory`)
forwards the logger injected by `Build` (this restores real EXECUTOR-tag
diagnostics that were previously silently swallowed by `logger.Nop`;
the factory no longer passes `Nop` for this branch).
Pre-1.2 callers that
relied on the implicit `internal/sys/utils.Log` should pass
`internal/sys/utils.AsLogger()` once that bridge exists.

The HTTP client is **not** constructed here — it is built lazily inside
`Run` so that constructor failures are limited to configuration errors
and never to network reachability. The list lookup (`FindOrCreateList`)
is the first call that actually touches the Cloudflare API.

---

## Registration

The plugin is registered in `init()`:

```go
func init() {
    executor.Register("cloudflare", newCloudflareFactory)
    executor.RegisterManifest("cloudflare", (&CloudflareExecutor{}).Manifest())
}
```

`newCloudflareFactory` is the registry factory. It receives a
stream-level `executor.ExecutorConfig` plus the logger forwarded by
`Build`, and delegates to `NewCloudflareExecutor(cfg, log)`. The factory
takes `executor.ExecutorConfig` directly (no `config.ExecutorItem` wrapping)
and does not hard-code `logger.Nop` —
`log` is what `cmd/arxsentinel` injects via `utils.AsLogger()`. The
manifest is registered separately so the agent can introspect plugin
metadata before instantiating the executor.

---

## Quick-Start Examples

The following snippets are self-contained, copy-pasteable fragments for
`executors[]`. Each one assumes the rest of the ArxSentinel stream
configuration is in place, including at least one source named
`sentinel-cf` and a matching detector chain.

### Basic blocklist

```yaml
executors:
  - name: cloudflare-blocklist
    type: cloudflare
    sources:
      - name: sentinel-cf
    config:
      api_token: "YOUR_CF_API_TOKEN"
      account_id: "YOUR_CF_ACCOUNT_ID"
```

`list_name`, `min_level`, `ttl`, `batch_size`, and `flush_interval` all
fall back to their defaults.

### With all options

```yaml
executors:
  - name: cloudflare-blocklist
    type: cloudflare
    sources:
      - name: sentinel-cf
    config:
      api_token: "YOUR_CF_API_TOKEN"
      account_id: "YOUR_CF_ACCOUNT_ID"
      list_name: "arxsentinel_blocklist"
      min_level: "THREAT"
      ttl: "24h"
      max_items: 10000
      batch_size: 100
      flush_interval: "10s"
      comment_extra: "edge-prod-1"
      instance_id: "sentinel-edge-01"
```

### Multiple named executor instances

Two executors targeting different accounts or lists, sharing the same
source:

```yaml
executors:
  - name: cloudflare-prod
    type: cloudflare
    sources:
      - name: sentinel-cf
    config:
      api_token: "PROD_TOKEN"
      account_id: "PROD_ACCOUNT_ID"
      list_name: "arxsentinel_prod"

  - name: cloudflare-staging
    type: cloudflare
    sources:
      - name: sentinel-cf
    config:
      api_token: "STAGING_TOKEN"
      account_id: "STAGING_ACCOUNT_ID"
      list_name: "arxsentinel_staging"
      min_level: "WARN"
      ttl: "1h"
```

---

## Dependencies

Standard library:

- `context` — cancellation propagation and request scoping.
- `crypto/rand`, `encoding/hex` — UUID v4 generation for the instance-ID fallback.
- `encoding/json` — request and response bodies for the Cloudflare API.
- `net/http` — HTTP client for the Cloudflare Lists API.
- `os` — `/var/lib/arxsentinel/instance.id` and `/etc/machine-id` reads.
- `sync`, `sync/atomic` — mutex around the `banned` map, pending bulk operation state, runtime counters.
- `time`, `fmt`, `strings` — durations, backoff calculation, timeouts, log message formatting, string handling.

Project:

- `pkg/logger` — `Logger` interface + `Nop` default (injected; replaces pre-1.2 `internal/sys/utils.Log`).
- `pkg/plugin` — `Executor`, `ThreatEvent`, `EventSource`, `Manifest`, `ExecutorStats`.
- `pkg/executor` — `ExecutorConfig` generic descriptor + registry (`Register`, `RegisterManifest`).

> Note: this package no longer imports
> `internal/sys/config`. The legacy `config.ExecutorItem` shape is kept
> only in `internal/sys/config` for YAML migrate compatibility and will
> be removed by a later cleanup flow.
