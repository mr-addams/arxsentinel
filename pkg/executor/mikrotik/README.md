# `pkg/executor/mikrotik` — MikroTik Executor

MikroTik executor plugin for ArxSentinel. Consumes scored `ThreatEvent`
records from the pipeline, batches them, and pushes the resulting IP
block list into a RouterOS device through its REST API. The integration
surface is the firewall address-list: a `dst-address-list` rule on the
input chain drops matching traffic at the router, which makes the
executor a good fit for edge and embedded deployments where the agent
runs alongside RouterOS on the same device. Targets RouterOS v7.18.2+.

- **Plugin ID:** `mikrotik`
- **Plugin version:** `1.0.0`
- **Role:** `Executor`
- **Input type:** `scored_event`
- **Output type:** `none`
- **Tags:** `routeros-v7`, `v7.18.2+`, `rest-api`, `embedded-capable`

## Module Layout

```
pkg/executor/mikrotik/
├── manifest.go    # Plugin metadata
├── config.go      # Config struct + defaults + validation
├── client.go      # Client interface + HTTPClient (RouterOS REST API)
├── executor.go    # MikroTikExecutor — run loop, batching, sweep
└── register.go    # init() — registry wiring
```

---

## Configuration Reference

The executor is declared under `executors[]` in the stream configuration.
All fields are parsed from the per-executor `config:` map; duration fields
accept either a Go-style string (`"24h"`, `"30s"`) parsed by
`time.ParseDuration`, or an integer interpreted as **seconds**.

| Field           | Type            | Default                    | Required | Description                                                              |
|-----------------|-----------------|----------------------------|----------|--------------------------------------------------------------------------|
| `host`          | `string`        | —                          | **yes**  | RouterOS host or IP. Resolved by the standard Go HTTP client.            |
| `port`          | `int`           | `443`                      | no       | RouterOS REST API port.                                                  |
| `username`      | `string`        | —                          | **yes**  | RouterOS user with `write` access to `/ip/firewall/address-list`.        |
| `password`      | `string`        | —                          | **yes**  | RouterOS password. Sent as Basic Auth on every request.                  |
| `list_name`     | `string`        | `"arxsentinel_blocklist"`  | no       | Address-list name. Created lazily by RouterOS on first add.              |
| `ttl`           | `time.Duration` | `24h`                      | no       | Ban lifetime. `0` means **permanent** — sweep is skipped.                |
| `sentinel_id`   | `string`        | —                          | **yes**  | Stable identifier of the producing agent. Used to filter list entries.  |
| `tls_verify`    | `bool`          | `true`                     | no       | Verify the server certificate (`InsecureSkipVerify` toggled accordingly).|
| `ca_file`       | `string`        | —                          | no       | Path to a PEM-encoded CA bundle. Appended to the system trust store.     |
| `use_tls`       | `bool`          | `true`                     | no       | Use HTTPS for the REST API. Set `false` only for trusted lab networks.   |
| `batch_size`    | `int`           | `10`                       | no       | Maximum events bundled into a single flush window.                       |
| `flush_interval`| `time.Duration` | `30s`                      | no       | Maximum time to wait before flushing a partial batch.                    |
| `min_level`     | `string`        | `"THREAT"`                 | no       | Minimum event level to act on. One of `INFO`, `WARN`, `THREAT`.          |

### Validation Rules

- `host`, `username`, `password`, and `sentinel_id` are mandatory —
  missing values cause a startup error.
- `min_level` must be one of `INFO`, `WARN`, `THREAT`. Any other value
  is rejected at startup.
- `tls_verify` and `use_tls` default to `true` — TLS is on by default
  and certificate validation is enforced unless explicitly disabled.
- Duration fields (`ttl`, `flush_interval`) are parsed by
  `time.ParseDuration` from string, or interpreted as integer seconds
  when a numeric value is supplied.
- `ttl = 0` is a valid configuration: the executor adds entries
  **without** a `timeout` field, which RouterOS interprets as
  permanent. Sweep is skipped in this case.

---

## Behaviour Details

### Run Loop

`Run(ctx context.Context, in <-chan *plugin.ThreatEvent) error` runs the
executor until context cancellation. The sequence is:

1. **syncExisting.** Call `Client.List` and load existing entries into
   the local `banned` map, filtering by comment prefix `"sentinel-"`
   followed by the configured `sentinel_id`. The filter ensures the
   executor only owns entries it has produced — entries from other
   agents or manual `ip firewall address-list` commands are ignored.
   Network errors are **non-fatal**: the executor proceeds with an
   empty map and a warning is logged.
2. **Buffer.** Each event is offered to an internal flush channel.
   Events below `min_level` are dropped silently.
3. **Flush.** When the buffer reaches `batch_size` (default `10`) or
   `flush_interval` (default `30s`) elapses, whichever comes first, the
   buffered IPs are pushed one at a time through `Client.Add`.
4. **Sweep.** A periodic timer fires every `ttl / 4` (with a hard floor
   of `15m`) and deletes expired entries owned by this executor. Sweep
   is skipped entirely when `ttl == 0` (permanent bans).

### Flush Strategy

The executor races two conditions on every batched event:

- **Count trigger.** When the in-memory buffer holds `batch_size` events
  (default `10`), the batch is committed.
- **Time trigger.** When `flush_interval` (default `30s`) elapses since
  the last flush, the partial batch is committed.

The committed batch is sent to `Client.Add` **per IP** — RouterOS does
not expose a bulk-add endpoint for `address-list`. For each IP:

1. The `banned` map is consulted. A hit means the IP is already in the
   list and the event is skipped (the `skipped` counter is incremented).
2. On a miss, `Client.Add` is called with an `AddressListEntry`
   containing the address, the configured `list_name`, a
   RouterOS-formatted `Timeout` (see [Duration to RouterOS
   Format](#duration-to-routeros-format)), and a `Comment` of the form
   `sentinel-<sentinel_id>`.
3. On a successful response, the returned entry `.id` is recorded in
   the `banned` map and the `executed` counter is incremented.
4. On any error, the event stays out of `banned` for the next attempt
   and the `errors` counter is incremented.

Unlike the Cloudflare executor, the MikroTik path is strictly
**per-IP**: there is no bulk-add and therefore no intra-batch
deduplication concern beyond the `banned` map check.

### Sweep / TTL Eviction

A sweep cycle runs every `ttl / 4`, with a hard minimum of `15 minutes`
to avoid hammering the device. Sweep is **skipped entirely** when
`ttl == 0` — permanent bans must be cleared by hand.

Each cycle:

1. Calls `Client.List` to fetch the current list contents.
2. For every entry whose comment starts with `sentinel-<sentinel_id>`,
   compute `expiry = addedAt + ttl`. Entries with `expiry <= now` are
   scheduled for removal.
3. Issues `Client.Delete(entry.ID)` for each scheduled entry. Per-IP
   delete matches the per-IP add — RouterOS does not expose a bulk
   delete on this resource.
4. Removes the entry from the local `banned` map and decrements the
   `executed` counter.

If a delete fails, the entry stays in `banned` and is retried on the
next sweep. The error is logged and the `errors` counter is incremented.

### Deduplication

The `banned` map is pre-populated in `syncExisting` and updated
synchronously on every successful `Add`. Its purpose is straightforward:
events for an IP that is already in the list are skipped before the API
call. Because the MikroTik path is per-IP rather than per-batch, the
`banned` map does not need a separate intra-batch dedup mechanism — a
miss in the map is sufficient to proceed with `Add`.

A `dedup_window` is not exposed in the MikroTik config: the in-list
presence alone is the source of truth, and `syncExisting` keeps the
map accurate at startup and on every sweep.

### TLS Configuration

TLS is on by default (`use_tls = true`, `tls_verify = true`):

- When `use_tls` is `false`, the executor connects to `http://…`. This
  is only acceptable on trusted, isolated lab networks; production
  deployments must keep it `true`.
- When `tls_verify` is `true` and `ca_file` is empty, the system trust
  store is used.
- When `tls_verify` is `true` and `ca_file` is set, the PEM contents of
  the file are appended to the system trust store and used for chain
  validation. The file is read once at executor construction.
- When `tls_verify` is `false`, the underlying `tls.Config` is built
  with `InsecureSkipVerify = true`. A warning is logged at startup
  to make the insecure posture visible.

### Duration to RouterOS Format

RouterOS does not accept Go's `time.Duration` string (`"24h0m0s"`). The
`durationToRouterOS` helper emits the RouterOS-native form used in the
`Timeout` field of `AddressListEntry`. It produces the largest unit
first (`d`, then `h`, then `m`, then `s`) and drops zero-value
suffixes. The empty string for `0` is the RouterOS convention for a
permanent entry.

| Go duration | RouterOS form           |
|-------------|-------------------------|
| `0`         | `""` (empty, permanent) |
| `30m`       | `"30m"`                 |
| `1h30m`     | `"1h30m"`               |
| `24h`       | `"1d"`                  |
| `36h`       | `"1d12h"`               |
| `48h`       | `"2d"`                  |
| `1h12m30s`  | `"1h12m30s"`            |

### Internal Constants

| Constant                 | Value                       | Purpose                                                       |
|--------------------------|-----------------------------|---------------------------------------------------------------|
| `defaultPort`            | `443`                       | Default REST API port.                                        |
| `defaultListName`        | `arxsentinel_blocklist`     | Default address-list name.                                   |
| `defaultTTL`             | `24h`                       | Default ban lifetime.                                         |
| `defaultBatchSize`       | `10`                        | Default events-per-flush threshold.                          |
| `defaultFlushInterval`   | `30s`                       | Default time-based flush trigger.                             |
| `defaultMinLevel`        | `"THREAT"`                  | Default minimum event level.                                  |
| `defaultUseTLS`          | `true`                      | Default value for `use_tls`.                                  |
| `defaultTLSVerify`       | `true`                      | Default value for `tls_verify`.                               |
| `sentinelPrefix`         | `"sentinel-"`               | Prefix of the comment stamped on every entry this executor adds. |
| `defaultSweepInterval`   | `15m`                       | Floor for the sweep cadence.                                  |
| `httpTimeout`            | `30s`                       | Per-request HTTP client timeout.                              |

---

## EOF, Cancellation, and Shutdown

The executor exits through one of three paths:

- **Context cancellation.** The main loop selects on `ctx.Done()`,
  performs a final best-effort flush of any buffered events, and
  returns the context error. Pending in-flight `Add` and `Delete`
  calls are allowed to complete on their own; new calls are not
  started after the final flush.
- **Startup failure.** A failure in the constructor (missing
  required field, `ca_file` read error) terminates the executor before
  `Run` is called. The stream supervisor will see the error and decide
  whether to retry.
- **Fatal flush/sweep failure.** Per-IP errors are **non-fatal**: they
  are logged, the `errors` counter is incremented, and the next batch
  attempts a fresh `Add`/`Delete`. The executor only exits on
  cancellation.

---

## Metrics and Stats

The executor exposes three runtime counters via
`Stats() plugin.ExecutorStats`:

| Counter    | Type   | Description                                                    | Incremented when                                                                  |
|------------|--------|----------------------------------------------------------------|-----------------------------------------------------------------------------------|
| `executed` | int64  | Events successfully added to the address-list.                 | `Client.Add` returns a non-empty `.id`. Decremented on every successful sweep delete. |
| `skipped`  | int64  | Events dropped due to level filter or dedup.                   | The event's level is below `min_level`, or the IP is already in `banned`.         |
| `errors`   | int64  | Errors during add, delete, or sweep.                           | HTTP non-2xx, network error, or sweep failure.                                    |

All three counters use `sync/atomic` and are safe to read from the
metrics endpoint without taking the executor lock.

---

## Constructors

```go
func NewMikroTikExecutor(cfg config.ExecutorItem) (plugin.Executor, error)
```

`NewMikroTikExecutor` is the public constructor. It accepts a
`config.ExecutorItem` (the deserialized per-executor block from the YAML
configuration), decodes the `Config` from the `Config` map, validates
the required fields, builds the underlying `Client`, and returns a
fully initialized `*MikroTikExecutor`.

Unlike the Cloudflare executor, the HTTP client **is** built here:
`Client` construction only performs configuration work (TLS config
build, `ca_file` read, transport wiring) and never opens a connection.
The first real call to RouterOS is the `syncExisting` `List` at the top
of `Run`.

---

## Registration

The plugin is registered in `init()`:

```go
func init() {
    executor.Register("mikrotik", newMikroTikFactory)
    executor.RegisterManifest("mikrotik", (&MikroTikExecutor{}).Manifest())
}
```

`newMikroTikFactory` is the registry factory. It receives a
stream-level `executor.ExecutorConfig`, wraps it into a
`config.ExecutorItem`, and delegates to `NewMikroTikExecutor`. The
manifest is registered separately so the agent can introspect plugin
metadata before instantiating the executor.

---

## Quick-Start Examples

The following snippets are self-contained, copy-pasteable fragments for
`executors[]`. Each one assumes the rest of the ArxSentinel stream
configuration is in place, including at least one source named
`sentinel-mt` and a matching detector chain.

### Basic blocklist

```yaml
executors:
  - name: mikrotik-blocklist
    type: mikrotik
    sources:
      - name: sentinel-mt
    config:
      host: "192.168.88.1"
      username: "arxsentinel"
      password: "ROUTEROS_PASSWORD"
      sentinel_id: "edge-01"
```

`port`, `list_name`, `ttl`, `batch_size`, `flush_interval`, `use_tls`,
and `tls_verify` all fall back to their defaults.

### With custom TLS

Custom CA bundle, with verification enabled:

```yaml
executors:
  - name: mikrotik-blocklist
    type: mikrotik
    sources:
      - name: sentinel-mt
    config:
      host: "router.example.com"
      port: 443
      username: "arxsentinel"
      password: "ROUTEROS_PASSWORD"
      sentinel_id: "edge-01"
      use_tls: true
      tls_verify: true
      ca_file: "/etc/arxsentinel/routeros-ca.pem"
```

Insecure lab network (verification disabled, HTTP fallback explicit):

```yaml
executors:
  - name: mikrotik-blocklist
    type: mikrotik
    sources:
      - name: sentinel-mt
    config:
      host: "192.168.88.1"
      username: "arxsentinel"
      password: "ROUTEROS_PASSWORD"
      sentinel_id: "edge-01"
      use_tls: false
```

### Permanent bans (TTL=0)

`ttl: 0` is interpreted by the executor as a request for permanent
entries: the `Timeout` field is sent empty, RouterOS keeps the entry
forever, and the executor skips its sweep cycle entirely.

```yaml
executors:
  - name: mikrotik-blocklist
    type: mikrotik
    sources:
      - name: sentinel-mt
    config:
      host: "192.168.88.1"
      username: "arxsentinel"
      password: "ROUTEROS_PASSWORD"
      sentinel_id: "edge-01"
      ttl: 0
```

Permanent entries can only be cleared by hand from RouterOS, by
deleting every address-list entry whose comment starts with
`sentinel-<sentinel_id>`.

---

## Dependencies

Standard library:

- `bytes` — request body construction for `PUT`/`DELETE`.
- `context` — cancellation propagation and request scoping.
- `crypto/tls`, `crypto/x509` — `tls.Config` building, system trust store and CA bundle loading.
- `encoding/json` — request and response bodies for the RouterOS REST API.
- `net/http` — HTTP client for the RouterOS REST API.
- `os` — `ca_file` read.
- `sync`, `sync/atomic` — mutex around the `banned` map, runtime counters.
- `time`, `fmt`, `strings`, `strconv` — durations, sweep cadence, timeouts, log message formatting, comment construction, numeric parsing fallbacks.

Project:

- `internal/sys/config` — `config.ExecutorItem` (per-executor configuration block).
- `internal/sys/utils` — `utils.Log` (default logger).
- `pkg/plugin` — `Executor`, `ThreatEvent`, `EventSource`, `Manifest`, `ExecutorStats`.
- `pkg/executor` — registry (`Register`, `RegisterManifest`).
