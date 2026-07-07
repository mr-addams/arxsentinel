# `pkg/executorplugins/opnsense` — OPNsense Executor

OPNsense executor plugin for ArxSentinel. Consumes scored `ThreatEvent`
records from the pipeline and pushes the resulting IP block list into an
OPNsense firewall through the **REST API** exposed by the PHP
`api/firewall/alias_util` controller. The integration surface is a
single user-declared **alias** of type `Host`, `Network`, or `External`
(Firewall → Aliases): each ThreatEvent becomes an independent
`alias_util/add` call that updates the underlying `pfctl` table
immediately. A periodic TTL-sweep issues independent
`alias_util/delete` calls for every expired IP. There is no batching
buffer, no flush interval, no filter reload — every accepted event is
applied point-by-point right away, mirroring the MikroTik executor
rather than the OpenWrt batching model. Targets OPNsense 24.x / 25.x
with the default `pf` packet filter and the built-in REST API.

- **Plugin ID:** `opnsense`
- **Plugin version:** `1.0.0`
- **Role:** `Executor`
- **Input type:** `scored_event`
- **Output type:** `none`
- **Tags:** `rest`, `pf`, `alias_util`, `freebsd`

## Module Layout

```
pkg/executorplugins/opnsense/
├── manifest.go    # Plugin metadata
├── config.go      # Config struct + defaults + validation
├── client.go      # Client interface + HTTPClient (REST + Basic Auth)
├── executor.go    # OpnsenseExecutor — run loop, point add, sweep, syncExisting
└── register.go    # init() — registry wiring
```

The `executor_test.go` companion (mocks, config validation, run-loop
harness) is delivered separately in the unit-test task; the
five-file-plus-test shape mirrors the MikroTik and OpenWrt reference
plugins one-for-one.

---

## Prerequisites

The executor depends on a small set of firewall-side conditions. None
of them require building software; they are configuration steps the
operator performs on the device.

1. **A user-declared alias of type `Host`, `Network`, or `External`.**
   The plugin does **not** create the alias — that responsibility
   lives with the operator's UI configuration, exactly like every
   other alias on the device. Create the alias in
   **Firewall → Aliases** before starting the plugin:

   - Click **+ Add** in the top-right of the Aliases page.
   - Set **Name** to the value the plugin will use in its
     `alias_name` config field (e.g. `arxsentinel_blocklist`).
   - Set **Type** to one of `Host`, `Network`, or `External`.
   - Leave the **Content** empty (or seed a single placeholder);
     the plugin manages the entries from this point on.
   - Save and **Apply** the change so the alias lands in
     `pfctl`/the running config.

   The plugin addresses the alias by **name** in every
   `alias_util/add`, `alias_util/delete`, and `alias_util/list`
   call. Other alias types (`URL Table (IPs)`, `Port`, `GeoIP`,
   `URL`, `MAC`, etc.) are **not supported by `alias_util`** and
   will return HTTP 422 on every operation. See
   [Troubleshooting](#troubleshooting) and DECISIONS.md Decision 3
   for the rationale on the type restriction.

   > **Persistence caveat (External type only).** Aliases of type
   > `External` are *non-persistent*: changes made through
   > `alias_util` (add / delete) do **not** survive a router
   > reload or reboot — the alias content is reset to whatever is
   > stored in the XML config on next boot. Aliases of type
   > `Host` and `Network` are persistent; the plugin's bans
   > survive a reboot and will be re-claimed by the next
   > `syncExisting` (see [syncExisting
   > Semantics](#syncexisting-semantics)). If the firewall is
   > expected to be reloaded often (firmware updates, scheduled
   > config reverts) and bans must survive across reloads, prefer
   > `Host` or `Network` over `External`.

2. **An API key with read/write access to the alias endpoints.**
   The plugin authenticates with **HTTP Basic Auth** (the OPNsense
   REST API does not use sessions; every request is a fresh Basic
   Auth challenge). The key is generated once in the OPNsense UI:

   - Navigate to **System → Access → Users**.
   - Click the user that will own the API credentials (a
     dedicated service account is recommended; `root` is fine
     for lab setups but discouraged in production).
   - Scroll down to the **API keys** section.
   - Click **+ Add** to generate a new key.
   - **Download the `.ini` file** OPNsense offers immediately
     after creation — the file contains the `key` and `secret`
     values and is shown **only once**. The plugin consumes
     these two values verbatim (`api_key` = the `key` field,
     `api_secret` = the `secret` field).
   - The user must have access to the `Firewall → Alias` API
     endpoints. On a default ACL this is granted automatically;
     on a hardened install, verify the matching ACL file in
     `/usr/local/opnsense/mvc/app/library/OPNsense/Firewall/`
     is intact or extend the ACL to grant the user access to
     the alias controller.

   The user is not required to be a member of the `admins` group
   *per se*, only to be granted access to the alias endpoints
   through the API ACL. Default installs grant this to every
   account that can log in to the web UI.

3. **TLS configuration.** OPNsense ships with a **self-signed
   certificate by default**. The plugin exposes a `tls_verify`
   field to control verification:

   - **Lab / development:** set `tls_verify: false`. The Go
     HTTP client is configured with `InsecureSkipVerify: true`
     and accepts the self-signed certificate. The risk of
     man-in-the-middle interception is acceptable in a lab
     network and the friction of installing the self-signed
     CA in the agent's trust store is avoided.
   - **Production:** set `tls_verify: true` (the default).
     The Go HTTP client validates the firewall's certificate
     against the system trust store. Either install the
     OPNsense CA into the agent's trust store, or replace the
     self-signed certificate with one issued by a public CA
     (e.g. via Let's Encrypt DNS-01 ACME on a routable OPNsense host).
     The plugin does not have its own `ca_file` knob — mount
     the CA into the agent's container and use the standard
     `SSL_CERT_FILE` / `SSL_CERT_DIR` environment variables.

> **Note:** the original design considered using OPNsense's
> `filter/apply` endpoint to batch alias updates behind a single
> filter reload — the same pattern that the OpenWrt plugin uses
> with `uci.commit` + `rc.init reload`. That pattern is **not
> applicable here**: `alias_util/add` and `alias_util/delete`
> update the underlying `pfctl` table directly, and the
> `filter/apply` endpoint is part of a separate savepoint /
> rollback mechanism for firewall *rules*, not aliases. There is
> no expensive reload to amortize, so the executor issues
> independent point calls per event instead. See DECISIONS.md
> Decision 1 for the rationale on the mikrotik-style model.

---

## Configuration Reference

The executor is declared under `executors[]` in the stream
configuration. All fields are parsed from the per-executor `config:`
map; duration fields accept either a Go-style string (`"24h"`,
`"30s"`) parsed by `time.ParseDuration`, or an integer interpreted
as **seconds**.

| Field          | Type            | Default         | Required | Description                                                              |
|----------------|-----------------|-----------------|----------|--------------------------------------------------------------------------|
| `host`         | `string`        | —               | **yes**  | Firewall hostname or IP. Resolved by the standard Go HTTP client.        |
| `port`         | `int`           | `443`           | no       | Port of the OPNsense web UI (REST API).                                  |
| `scheme`       | `string`        | `"https"`       | no       | `"http"` or `"https"`. Production OPNsense is HTTPS-only.                |
| `api_key`      | `string`        | —               | **yes**  | OPNsense API username (Basic Auth `user`). See [Prerequisites](#prerequisites). |
| `api_secret`   | `string`        | —               | **yes**  | OPNsense API password (Basic Auth `pass`). See [Prerequisites](#prerequisites). |
| `tls_verify`   | `bool`          | `true`          | no       | Verify the firewall's TLS certificate. Set `false` for self-signed lab setups. |
| `alias_name`   | `string`        | —               | **yes**  | Name of the pre-declared alias (Firewall → Aliases). Type must be `Host`, `Network`, or `External`. |
| `ttl`          | `time.Duration` | —               | **yes**  | Ban lifetime. Must be `> 0` — the plugin owns expiry tracking.           |
| `min_level`    | `string`        | `"THREAT"`      | no       | Minimum event level to act on. One of `INFO`, `WARN`, `THREAT`.          |
| `dedup_window` | `time.Duration` | `0` (disabled)  | no       | Skip re-banning an IP within this window after a successful add.         |

> **No `batch_size` / `flush_interval` — by design.** Unlike the
> OpenWrt executor, the OPNsense `Config` does **not** expose
> `batch_size` or `flush_interval`. The architectural model is
> mikrotik-style: every accepted event becomes one independent
> `alias_util/add` call right away, and every expired IP becomes
> one independent `alias_util/delete` call on the next sweep.
> `alias_util/add` updates the underlying `pfctl` table per-call —
> there is no expensive filter/apply to amortize, so a batching
> buffer would add latency and complexity without a corresponding
> firewall benefit. The sweep cadence is derived from
> `ttl / 4` (with a `15m` floor) inside the executor and is
> intentionally not exposed as a config field either; see
> [Sweep / TTL Eviction](#sweep--ttl-eviction) and DECISIONS.md
> Decision 8 for the rationale.

### Validation Rules

- `host`, `api_key`, `api_secret`, and `alias_name` are mandatory —
  missing values cause a startup error.
- `ttl` is **mandatory and must be `> 0`**. The plugin does not
  support permanent bans: a `ttl` of `0` is rejected at startup.
  The reasoning is the same as the OpenWrt executor: the plugin
  owns expiry tracking through an active sweep, and a zero or
  negative TTL would make the sweep unusable.
- `min_level` must be one of `INFO`, `WARN`, `THREAT`. Any other
  value is rejected at startup.
- `scheme` must be `"http"` or `"https"`. Anything else is
  rejected.
- Duration fields (`ttl`, `dedup_window`) are parsed by
  `time.ParseDuration` from string, or interpreted as integer
  seconds when a numeric value is supplied.
- `dedup_window = 0` is a valid configuration: deduplication falls
  back to the in-list (`banned` map) check only. A positive value
  adds a recent-ban suppression layer on top.

---

## Behaviour Details

### Run Loop

`Run(ctx context.Context, source plugin.EventSource) error` runs the
executor until context cancellation. The sequence is:

1. **syncExisting.** Issue `GET /api/firewall/alias_util/list/{name}`
   on the configured alias and load the returned addresses into the
   local `banned` map. The OPNsense `alias_util/list` payload
   exposes only the address strings — it does **not** carry
   per-entry timestamps. After a daemon restart, the executor
   therefore applies the **conservative TTL assumption** and gives
   every pre-existing entry a fresh `expireAt = now + cfg.ttl`
   (see [syncExisting Semantics](#syncexisting-semantics)).
   Network errors are **non-fatal**: the executor proceeds with an
   empty map and a warning is logged.
2. **Filter.** Each event is offered to an internal channel. The
   event payload is type-asserted to `*threat.ThreatEvent`; any
   other payload type is logged and dropped. Events below
   `min_level` are dropped silently. Events that pass the dedup
   window or that are already in the local `banned` map are also
   dropped silently.
3. **Point add.** An event that survives filtering is applied
   **immediately** through a single `alias_util/add` REST call
   with body `{"address":"<ip>"}`. The call updates the
   underlying `pfctl` table on the firewall right away; there is
   no buffer, no flush, no filter reload. The local `banned` map
   is updated and the dedup window is marked only on a successful
   add.
4. **Sweep.** A periodic timer fires every `ttl / 4` (with a hard
   floor of `15m`) and triggers the sweep. The sweep walks the
   `banned` map under the executor lock, collects the expired
   IPs, releases the lock, and issues an independent
   `alias_util/delete` call for every expired IP. See
   [Sweep / TTL Eviction](#sweep--ttl-eviction).

### REST Transport

Every firewall-side operation is an HTTP request against the
OPNsense REST API. Authentication is **Basic Auth** — every
request sets `Authorization: Basic <base64(api_key:api_secret)>`.
No session token is negotiated: the firewall re-authenticates
on every call. The endpoints are:

- `POST /api/firewall/alias_util/add/{alias_name}` —
  body `{"address":"<ip>"}`, response `{"result":"saved"}` on
  success.
- `POST /api/firewall/alias_util/delete/{alias_name}` —
  body `{"address":"<ip>"}`, response `{"result":"ok"}` on
  success.
- `GET /api/firewall/alias_util/list/{alias_name}` — response
  carries the current set of addresses; the exact JSON shape
  is described in [List Response Format](#list-response-format).

The client always sends `Content-Type: application/json` on
mutating calls. A `User-Agent` header is set to identify the
plugin (`ArxSentinel-opnsense/1.0.0`) — OPNsense does not
require it, but it shows up in the firewall's request log and
helps the operator correlate plugin activity with the events
they see in **Firewall → Log Files → Backend**.

HTTP timeout is fixed at `30s` per call (matches the MikroTik
and OpenWrt clients). Long enough for the small JSON payloads
`alias_util` produces, short enough to surface a stuck firewall
promptly through context cancellation. Any non-2xx response is
treated as a hard error: the executor logs the status code and
the response body (truncated to 512 bytes), increments the
`errors` counter, and does **not** mutate the local `banned`
map or the dedup window — the next event for the same IP will
retry the add. This is the "flaky-safe" property that keeps the
executor from poisoning local state during a transient OPNsense
outage.

### Why mikrotik-Style, Not openwrt-Batching

The OpenWrt executor batches add / delete operations behind a
single `uci.commit` + `rc.init reload` cycle because the
`fw4` firewall recreates the entire nftables ruleset on every
reload — issuing a reload per ban would block the routing
plane on every event. The OPNsense executor has no such
constraint: `alias_util/add` and `alias_util/delete` operate
directly on the `pfctl` table and apply the change per-call.
There is no filter/apply step to amortize (the `filter/apply`
endpoint is part of a separate savepoint/rollback mechanism
for *rules*, not aliases), so a batching buffer would add
latency and complexity without a corresponding firewall
benefit. The plugin therefore:

- Issues an **independent** `alias_util/add` for every accepted
  event.
- Issues an **independent** `alias_util/delete` for every
  expired IP on the sweep cycle.
- Carries no `pending` slice, no flush ticker, and no final
  flush on shutdown.

This is the same model the MikroTik executor follows (one
REST call per event), and it is documented as a deliberate
choice in DECISIONS.md Decision 1. The single-tenant alias
model — the plugin assumes exclusive ownership of the
configured alias, with no per-entry ownership tracking — is
also identical to the OpenWrt executor's ipset model: every
entry in the alias is "ours" by construction, and the plugin
will happily evict a manually-added entry once its TTL runs
out on the same logic that owns the rest of the alias.

### Sweep / TTL Eviction

A sweep cycle runs every `ttl / 4`, with a hard minimum of
`15m` (matches the OpenWrt and MikroTik executors — a 4-second
TTL would otherwise yield a 1-second sweep ticker, which is
wasteful). The cadence is computed once at the top of `Run`
and is **not** exposed as a config field: changing it without
changing `ttl` would yield a sweep that either thrashes the
firewall (too frequent) or fails to evict bans (too rare). The
right knob to tune is `ttl` itself.

The sweep is a two-phase operation:

1. **Collect (under lock).** Walk the `banned` map and copy
   every `record` whose `expireAt <= now` into a local
   `expired` slice. The lock is held only for the map walk —
   no network I/O happens under the lock.
2. **Delete (without lock).** For each IP in the `expired`
   slice, issue a `alias_util/delete` call. On a 2xx response
   with `result == "ok"`, remove the IP from the `banned` map
   and increment the `swept` counter. On any error, log it,
   increment the `errors` counter, and leave the IP in the
   map — the next sweep cycle will retry.

There is no batched delete and no equivalent of OpenWrt's
`del_list` call: `alias_util/delete` accepts exactly one
address per request (the body is `{"address":"..."}`), so
each expired IP requires its own REST call. Holding the lock
during deletes would serialize network waits and block
incoming events; the two-phase design avoids that.

### syncExisting Semantics

`GET /api/firewall/alias_util/list/{name}` returns the current
set of addresses in the alias but does **not** carry per-entry
timestamps. After a daemon restart, the executor therefore
cannot know when each pre-existing IP was added. The plugin
applies a **conservative TTL assumption**:

- Every pre-existing entry is loaded into the `banned` map
  with `addedAt = now` and `expireAt = now + cfg.ttl`.
- This grants every pre-existing ban a full fresh TTL window
  on restart, rather than expiring them immediately or
  guessing an arbitrary `addedAt`.

Side effect: a long-lived daemon restart effectively **extends**
bans by up to one TTL. This is acceptable for a WAF use case
(false negatives on unbanning are far less harmful than
missing a ban) and is the same trade-off the OpenWrt and
MikroTik executors make.

`syncExisting` errors are non-fatal: a transient firewall
outage at startup must not crash the daemon. The ban list is
rebuilt as events arrive and on the next sweep.

### Deduplication

The executor layers two checks before issuing
`alias_util/add`:

1. **Dedup window** (`dedup_window`). A short-lived set
   populated only on **successful** `alias_util/add` results.
   The point of the window is to suppress redundant bans for
   IPs that were just banned and have since been swept out of
   the `banned` map. Setting `dedup_window = 0` disables the
   window entirely.
2. **Local `banned` map.** The authoritative "is this IP
   currently considered banned by us" check. Populated by
   `syncExisting` and updated on every successful add /
   delete.

Both checks are pure lookups: a failed `alias_util/add` does
**not** poison either structure, and the next event for the
same IP will retry naturally. This is the "flaky-safe"
property — the executor must keep looping through firewall
outages without losing events or creating phantom bans.

### List Response Format

The exact JSON shape of the `alias_util/list` endpoint is not
formally documented. Across observed OPNsense 24.x / 25.x
releases, the payload is a single object with a `content`
field that holds the alias' addresses as a newline-separated
string:

```json
{
  "rows": [],
  "content": "1.2.3.4\n5.6.7.8\n10.0.0.0/24"
}
```

The client parses the `content` string by splitting on `\n`
and trimming each line. A `rows` array is also accepted as a
fallback — the client prefers `rows` when present and
non-empty (future-proofs against OPNsense moving to a
structured representation in a later release). See DECISIONS.md
Decision 2 for the open-issue status of this format.

This parsing strategy is documented in `client.go` as a known
limitation. Operators integrating against a heavily-modified
OPNsense fork should test `ListEntries` against their build
before relying on the executor in production.

### Internal Constants

| Constant                 | Value                       | Purpose                                                       |
|--------------------------|-----------------------------|---------------------------------------------------------------|
| `defaultPort`            | `443`                       | Default OPNsense web UI port.                                 |
| `defaultScheme`          | `"https"`                   | Default URL scheme.                                          |
| `defaultTLSVerify`       | `true`                      | Default certificate verification policy.                      |
| `defaultMinLevel`        | `"THREAT"`                  | Default minimum event level.                                 |
| `defaultSweepInterval`   | `15m`                       | Floor for the sweep cadence.                                 |
| `httpTimeout`            | `30s`                       | Per-request HTTP client timeout.                             |
| `errBodyLimit`           | `512`                       | Max bytes of an error response body included in log lines.    |

---

## EOF, Cancellation, and Shutdown

The executor exits through one of three paths:

- **Context cancellation.** The main loop selects on
  `ctx.Done()` and returns the context error. There is **no
  final flush** to perform — the executor holds no pending
  buffer, so cancellation is a clean immediate return. Any
  in-flight `alias_util/add` or `alias_util/delete` call is
  bound by the HTTP client's 30s timeout / context
  propagation, and will be torn down together with the
  goroutine that issued it.
- **Source closed cleanly (no `ctx` cancellation).** The
  pop-against-source loop returns, the channel closes, the
  main loop sees the closed channel and returns `nil`. Again
  no buffer to drain.
- **Startup failure.** A failure in `parseConfig` (missing
  required field, bad `ttl`, unknown `min_level`, …)
  terminates the executor before `Run` is called. The stream
  supervisor will see the error and decide whether to retry.
  A `syncExisting` failure is **not** a startup failure: the
  executor starts anyway with an empty `banned` map and a
  warning is logged.

Per-call errors (`add` / `delete` / `list`) are **non-fatal**:
they are logged, the `errors` counter is incremented, and the
next event re-tries the operation. The executor only exits
on cancellation or clean source closure.

---

## Metrics and Stats

The executor exposes four runtime counters via
`Stats() plugin.ExecutorStats`:

| Counter    | Type   | Description                                                              | Incremented when                                                                  |
|------------|--------|--------------------------------------------------------------------------|-----------------------------------------------------------------------------------|
| `executed` | int64  | Events successfully added to the alias.                                  | `alias_util/add` returned without error and the entry made it into the `banned` map. |
| `skipped`  | int64  | Events dropped due to level filter or dedup.                             | The event's level is below `min_level`, the dedup window contains the IP, the `banned` map already contains the IP. |
| `errors`   | int64  | Errors during `alias_util/add`, `alias_util/delete`, or `syncExisting`. | The corresponding REST call returns a non-2xx status, a `result == "failed"` envelope, a network error, or a JSON decode error. |
| `swept`    | int64  | Bans removed by the periodic sweep.                                       | `alias_util/delete` returned without error and the entry was removed from `banned`. |

All four counters use `sync/atomic` and are safe to read from
the metrics endpoint without taking the executor lock.

---

## Constructors

```go
func NewOpnsenseExecutor(cfg executor.ExecutorConfig, log logger.Logger) (plugin.Executor, error)
```

`NewOpnsenseExecutor` is the public constructor. It accepts an
`executor.ExecutorConfig` (the generic `pkg/executor`
descriptor: the `Name` / `Type` / `Config` map forwarded by
`Build`), decodes the `Config` from the inner `Config` map,
validates the required fields, builds the underlying
`HTTPClient`, instantiates the dedup window from
`cfg.DedupWindow`, and returns a fully initialized
`*OpnsenseExecutor`.

`log` is the operational logger used for the `EXECUTOR` tag.
A `nil` is replaced with `pkg/logger.Nop` so downstream code
never has to nil-check. The registry-based factory
(`newOpnsenseFactory`) forwards the logger injected by
`Build`.

Construction is **side-effect-free**: no network I/O happens
until `Run` is called. The first real call to the firewall is
the `syncExisting` `alias_util/list` GET at the top of `Run`.

---

## Registration

The plugin is registered in `init()`:

```go
func init() {
    executor.Register("opnsense", newOpnsenseFactory)
    executor.RegisterManifest("opnsense", (&OpnsenseExecutor{}).Manifest())
}
```

`newOpnsenseFactory` is the registry factory. It receives a
stream-level `executor.ExecutorConfig` plus the logger
forwarded by `Build`, and delegates to
`NewOpnsenseExecutor(cfg, log)`. The factory takes
`executor.ExecutorConfig` directly (no `config.ExecutorItem`
wrapping) and does not hard-code `logger.Nop` — `log` is what
`cmd/arxsentinel` injects via `utils.AsLogger()`. The manifest
is registered separately so the agent can introspect plugin
metadata before instantiating the executor.

The package is blank-imported from
`cmd/arxsentinel/plugins_full.go`, and the plugin is listed
in `profiles/full.yaml` next to the MikroTik and OpenWrt
entries.

---

## Quick-Start Examples

The following snippets are self-contained, copy-pasteable
fragments for `executors[]`. Each one assumes the rest of the
ArxSentinel stream configuration is in place, including at
least one source named `sentinel-opnsense` and a matching
detector chain, and that the prerequisite alias has been
declared in the OPNsense UI (see [Prerequisites](#prerequisites)).

### Basic blocklist

```yaml
executors:
  - name: opnsense-blocklist
    type: opnsense
    sources:
      - name: sentinel-opnsense
    config:
      host: "192.168.1.1"
      api_key: "YOUR_API_KEY"
      api_secret: "YOUR_API_SECRET"
      alias_name: "arxsentinel_blocklist"
      ttl: "24h"
```

`port`, `scheme`, `tls_verify`, and `min_level` all fall back
to their defaults. The default `scheme` is `"https"` and the
default `port` is `443`, which matches a stock OPNsense
install. The default `tls_verify` is `true` — flip it to
`false` if the firewall is presenting the stock self-signed
certificate and the agent's trust store does not include the
OPNsense CA.

### With custom tls_verify and dedup_window

A lab setup against an OPNsense VM with a self-signed
certificate, plus a 30s dedup window to suppress re-bans for
the same IP within 30 seconds of a successful add:

```yaml
executors:
  - name: opnsense-blocklist
    type: opnsense
    sources:
      - name: sentinel-opnsense
    config:
      host: "opnsense.lab.local"
      api_key: "YOUR_API_KEY"
      api_secret: "YOUR_API_SECRET"
      tls_verify: false
      alias_name: "arxsentinel_blocklist"
      ttl: "1h"
      min_level: "WARN"
      dedup_window: "30s"
```

`tls_verify: false` configures the Go HTTP client with
`InsecureSkipVerify: true` — acceptable for a closed lab
network where MITM is not a realistic threat, and avoids the
friction of installing the OPNsense CA into the agent's
trust store. Production deployments should keep
`tls_verify: true` and ship the CA alongside the agent (see
[Prerequisites](#prerequisites)).

---

## Troubleshooting

Most "my bans are not taking effect" reports trace back to one
of the following root causes. Walk them in order.

### 1. `alias_util/add` returns HTTP 422

The configured alias is of a type other than `Host`,
`Network`, or `External` (most commonly `URL Table (IPs)` or
`Port`). OPNsense's `alias_util` controller accepts only the
three types listed above; other types return 422 on every
operation. Fix the alias in **Firewall → Aliases** by either
re-creating it as `Host` / `Network` / `External`, or by
updating the plugin's `alias_name` to point at a different
alias that has the right type. See [Prerequisites](#prerequisites)
and DECISIONS.md Decision 3 for the rationale.

### 2. `alias_util/add` returns HTTP 404

The configured `alias_name` does not exist on the firewall.
Verify with:

```sh
curl -u "API_KEY:API_SECRET" \
  https://<host>/api/firewall/alias_util/list/<alias_name>
```

A 404 here means the alias is missing from the OPNsense
config — go to **Firewall → Aliases** and create it (or fix
the `alias_name` in the plugin config to match an alias that
already exists). Note that the OPNsense UI requires a manual
**Apply** after creating or modifying an alias before the
REST API can see it; an unapplied alias is a common source of
404s on a freshly created entry.

### 3. `alias_util/add` returns HTTP 401

The API key / secret are wrong, or the user does not have
permission to access the alias controller. Verify the key /
secret by re-downloading the `.ini` from **System → Access →
Users** and comparing against the plugin config. If the
credentials are correct, the issue is an ACL restriction —
see the next item.

### 4. `alias_util/add` returns HTTP 403

The API user is authenticated but lacks access to the
firewall alias endpoints. This is typical of hardened
installs where the user ACL has been stripped. Verify the
matching ACL file under
`/usr/local/opnsense/mvc/app/library/OPNsense/Firewall/` is
intact, or extend the ACL to grant the user access to the
alias controller. On a default install, every user that can
log in to the web UI has access — 403 on a default install
indicates the user has been created with the "API access"
checkbox unchecked.

### 5. TLS handshake error on the first call

The firewall is presenting the stock self-signed certificate
and `tls_verify` is at its default of `true`. Either flip
`tls_verify: false` for a lab / development setup, or
install the OPNsense CA into the agent's trust store (the
CA can be exported from **System → Trust → Authorities**)
and set `SSL_CERT_FILE` / `SSL_CERT_DIR` to point at it. See
[Prerequisites](#prerequisites) for the production guidance.

### 6. Bans appear in the alias but traffic is not dropped

The OPNsense firewall has no rule referencing the alias.
`alias_util` only manages the alias content; it does not
create or modify firewall rules. In **Firewall → Rules**,
add a rule (block / reject) on the appropriate interface
with **Source** set to the alias name (OPNsense renders
aliases as a selectable alias in the rule's source
dropdown). The plugin does not manage rules, only alias
entries.

### 7. Bans disappear after a router reboot

The alias is of type `External`. Per the OPNsense design,
External aliases are *non-persistent* across reboots — the
content is reset to whatever is stored in the XML config on
next boot. Re-create the alias as `Host` or `Network` if
persistence is required. See
[Prerequisites](#prerequisites) for the full caveat.

### 8. Bans appear and disappear too fast / too slowly

The plugin's `ttl` is the source of truth for entry
lifetime, **not** any native OPNsense timeout. The local
`banned` map is what drives the sweep, and it is reloaded
conservatively on restart (see [syncExisting
Semantics](#syncexisting-semantics)). If the configured
`ttl` is `30s` but the sweep cadence is the `15m` floor, an
entry will remain in the alias for at least one sweep cycle.
This is intentional — see [Sweep / TTL
Eviction](#sweep--ttl-eviction).

---

## Dependencies

Standard library:

- `bytes` — request body construction for `alias_util` POSTs.
- `context` — cancellation propagation and request scoping.
- `crypto/tls` — `InsecureSkipVerify` toggle for self-signed certificates.
- `encoding/json` — request/response encoding for the REST API.
- `fmt` — error wrapping and log message formatting.
- `io` — `io.ReadAll` for response body capture.
- `net/http` — HTTP client for the alias_util REST endpoint.
- `net/url` — `url.PathEscape` for the alias name path segment.
- `os` — stderr fallback for unparseable payloads.
- `strings` — newline-split of the `content` field in `alias_util/list`.
- `sync`, `sync/atomic` — mutex around the `banned` map, runtime counters.
- `time` — sweep intervals, TTL arithmetic, `time.ParseDuration`.

Project:

- `pkg/logger` — `Logger` interface + `Nop` default (injected; replaces pre-1.2 `internal/sys/utils.Log`).
- `pkg/plugin` — `Executor`, `ThreatEvent`, `EventSource`, `Manifest`, `ExecutorStats`.
- `pkg/executor` — `ExecutorConfig` generic descriptor + registry (`Register`, `RegisterManifest`).
- `pkg/dedup` — `dedup.Window` for the optional `dedup_window` suppression layer.
- `internal/threat` — `ThreatEvent` payload type (the executor type-asserts `Event.Payload` to `*threat.ThreatEvent` to extract the IP and level fields).

> Note: this package does not import `internal/sys/config`. The
> legacy `config.ExecutorItem` shape is kept only in
> `internal/sys/config` for YAML migrate compatibility and will
> be removed by a later cleanup flow.
