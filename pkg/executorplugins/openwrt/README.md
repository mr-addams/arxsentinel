# `pkg/executorplugins/openwrt` — OpenWrt Executor

OpenWrt executor plugin for ArxSentinel. Consumes scored `ThreatEvent`
records from the pipeline, batches them, and pushes the resulting IP
block list into an OpenWrt router through the **ubus** JSON-RPC
endpoint exposed by `uhttpd-mod-ubus`. The integration surface is an
`nftables` ipset declared in the `firewall` UCI config: a forward /
input rule referencing the ipset drops matching traffic at the
router, which makes the executor a good fit for edge and embedded
deployments where the agent runs alongside the routing stack. Targets
OpenWrt with the `fw4` firewall (nftables) and the stock `rpcd`
core plugins (`uci`, `rc`).

- **Plugin ID:** `openwrt`
- **Plugin version:** `1.0.0`
- **Role:** `Executor`
- **Input type:** `scored_event`
- **Output type:** `none`
- **Tags:** `ubus`, `fw4`, `nftables`, `uci`

## Module Layout

```
pkg/executorplugins/openwrt/
├── manifest.go    # Plugin metadata
├── config.go      # Config struct + defaults + validation
├── client.go      # Client interface + HTTPClient (ubus JSON-RPC 2.0)
├── executor.go    # OpenwrtExecutor — run loop, batched flush, sweep
└── register.go    # init() — registry wiring
```

The `executor_test.go` companion (mocks, config validation, run-loop
harness) is delivered separately in the unit-test task; the seven-file
shape mirrors the MikroTik reference plugin one-for-one.

---

## Prerequisites

The executor depends on a small set of router-side conditions. None of
them require building software; they are configuration steps the
operator performs on the device.

1. **`uhttpd` with the `uhttpd-mod-ubus` module.** The base
   `uhttpd` build that ships with most OpenWrt images does **not**
   include the ubus bridge. If `POST /ubus` returns 404 on the
   configured port, install the module on the router:
   ```sh
   opkg update
   opkg install uhttpd-mod-ubus
   /etc/init.d/uhttpd restart
   ```
   The module is the same one LuCI uses; the install path is the
   one documented by the OpenWrt project.

2. **`rpcd` core plugins `uci` and `rc`.** The plugin drives firewall
   state through the standard rpcd core objects (`uci` for the
   config store, `rc` for service lifecycle). These plugins ship
   with the default `rpcd` package and are enabled out of the box
   for any session authenticated as the router's `root` user. Verify
   with:
   ```sh
   ubus list | grep -E '^(uci|rc|session)$'
   ```
   If `uci` or `rc` is missing, install `rpcd` (and on hardened
   builds, ensure the matching ACLs are not stripped from
   `/usr/share/rpcd/acl.d/`).

3. **A user-declared UCI ipset section.** The plugin does **not**
   create the ipset — that responsibility lives with the operator's
   UCI config, exactly like every other ipset rule on the device.
   The minimum block looks like:
   ```sh
   # NAMED section (firewall.arxsentinel_blocklist=ipset) — required.
   # The plugin's uci.add_list/del_list/get calls address the section by
   # this identifier directly ("section": ipset_name). An anonymous
   # section (`uci add firewall ipset`, addressed internally as
   # @ipset[N]) would NOT be reachable by name and every add_list call
   # would fail with "not found".
   uci set firewall.arxsentinel_blocklist=ipset
   uci set firewall.arxsentinel_blocklist.name='arxsentinel_blocklist'
   uci set firewall.arxsentinel_blocklist.match='src_ip'
   uci add_list firewall.arxsentinel_blocklist.entry='1.2.3.4'   # seed; plugin manages thereafter
   uci set firewall.drop_blocklist=rule
   uci set firewall.drop_blocklist.name='Drop-blocklist'
   uci set firewall.drop_blocklist.src='wan'
   uci set firewall.drop_blocklist.dest='*'
   uci set firewall.drop_blocklist.ipset='arxsentinel_blocklist'
   uci set firewall.drop_blocklist.target='DROP'
   uci commit firewall
   /etc/init.d/firewall reload
   ```
   The section identifier used here (`arxsentinel_blocklist`) is the
   value you put into the plugin's `ipset_name` config field — it must
   match the UCI *section name*, not merely the ipset's `option name`
   value (they happen to be the same string in this example, which is
   the recommended convention, but only the section identifier is what
   `uci.add_list`/`uci.del_list`/`uci.get` actually address). The
   plugin treats the section as fully owned by this instance (no
   prefix filter, unlike the MikroTik plugin — see [Sweep / TTL
   Eviction](#sweep--ttl-eviction)).

   > **Verification status:** the exact `option match` and
   > `option family` keywords accepted by `fw4` are confirmed by
   > the fw4 reference docs as of the time of writing (`src_ip`,
   > `src_net`, `dst_ip`, `dst_net`). The required-versus-optional
   > status of `option family` (`ipv4` / `ipv6`) is the only
   > sub-detail left as **unresolved** until a real-device
   > integration run is available; the plugin is family-agnostic
   > and passes the IP through verbatim.

4. **rpcd ACL for the `uci` and `rc` objects.** The default ACL
   shipped with `rpcd` grants `root` and `admin` sessions access to
   the core objects. No ACL file is required for the standard
   admin credentials. If you have hardened the device and stripped
   the default ACLs, see [Troubleshooting](#troubleshooting).

> **Note:** the original design considered using the `luci2.firewall`
> ubus object for direct ipset mutation. That object **does not
> exist** on a current `fw4` build — the LuCI2 project is archived,
> the `firewall4` package ships no rpcd plugin named `luci2`, and
> searches for `add_ipset_entry` in `openwrt/luci` return zero
> results. The plugin therefore drives the canonical `uci`+`rc`
> path. See DECISIONS.md Decision 3.

---

## Configuration Reference

The executor is declared under `executors[]` in the stream configuration.
All fields are parsed from the per-executor `config:` map; duration fields
accept either a Go-style string (`"24h"`, `"30s"`) parsed by
`time.ParseDuration`, or an integer interpreted as **seconds**.

| Field             | Type            | Default                    | Required | Description                                                                  |
|-------------------|-----------------|----------------------------|----------|------------------------------------------------------------------------------|
| `host`            | `string`        | —                          | **yes**  | Router hostname or IP. Resolved by the standard Go HTTP client.              |
| `port`            | `int`           | `80`                       | no       | Port of `uhttpd-mod-ubus`.                                                   |
| `scheme`          | `string`        | `"http"`                   | no       | `"http"` or `"https"`. Most stock images serve `/ubus` over plain HTTP.      |
| `username`        | `string`        | —                          | **yes**  | rpcd user with `write` access to the `firewall` UCI config.                  |
| `password`        | `string`        | —                          | **yes**  | rpcd password. Sent on every `session.login` call.                           |
| `ipset_name`      | `string`        | —                          | **yes**  | UCI *section identifier* of the ipset (`firewall.<ipset_name>=ipset`) — a named section, not an anonymous `@ipset[N]`. See [Prerequisites](#prerequisites). |
| `ttl`             | `time.Duration` | —                          | **yes**  | Ban lifetime. Must be `> 0` — the plugin owns expiry tracking.               |
| `session_timeout` | `time.Duration` | `5m`                       | no       | Lifetime of an `ubus_rpc_session` token. Re-login is triggered before this.  |
| `sentinel_id`     | `string`        | —                          | **yes**  | Stable identifier of the producing agent. Embedded in every ban record.      |
| `batch_size`      | `int`           | `10`                       | no       | Maximum events bundled into a single flush window.                           |
| `flush_interval`  | `time.Duration` | `30s`                      | no       | Maximum time to wait before flushing a partial batch.                        |
| `min_level`       | `string`        | `"THREAT"`                 | no       | Minimum event level to act on. One of `INFO`, `WARN`, `THREAT`.              |
| `dedup_window`    | `time.Duration` | `0` (disabled)             | no       | Skip re-banning an IP within this window after a successful add.             |

### Validation Rules

- `host`, `username`, `password`, `ipset_name`, and `sentinel_id` are
  mandatory — missing values cause a startup error.
- `ttl` is **mandatory and must be `> 0`**. The plugin does not
  support permanent bans: a `ttl` of `0` is rejected at startup.
  The reasoning is the **batched sweep model** (see [Flush
  Strategy](#flush-strategy)): with native nftables timeouts the
  plugin would have to rely on per-entry counters that `fw4`
  resets on every reload, and the local sweep tracker requires a
  finite TTL to evict anything.
- `min_level` must be one of `INFO`, `WARN`, `THREAT`. Any other
  value is rejected at startup.
- `scheme` must be `"http"` or `"https"`. Anything else is rejected.
- `session_timeout` must be `> 0`. The default (5m) is the stock
  `uhttpd-mod-ubus` value and is fine for almost every deployment.
- Duration fields (`ttl`, `session_timeout`, `flush_interval`,
  `dedup_window`) are parsed by `time.ParseDuration` from string,
  or interpreted as integer seconds when a numeric value is
  supplied.
- `dedup_window = 0` is a valid configuration: deduplication falls
  back to the in-list (`banned` map) check only. A positive value
  adds a recent-ban suppression layer on top.

---

## Behaviour Details

### Run Loop

`Run(ctx context.Context, source plugin.EventSource) error` runs the
executor until context cancellation. The sequence is:

1. **syncExisting.** Issue `uci.get` on the configured ipset section
   and load the current `entry` list into the local `banned` map.
   The UCI store does not preserve per-entry timestamps, so every
   pre-existing entry receives the **conservative TTL assumption**
   `expireAt = now + cfg.ttl` (see [syncExisting
   Semantics](#syncexisting-semantics)). Network errors are
   **non-fatal**: the executor proceeds with an empty map and a
   warning is logged.
2. **Buffer.** Each event is offered to an internal channel. The
   event payload is type-asserted to `*threat.ThreatEvent`; any
   other payload type is logged and dropped.
3. **Filter.** Events below `min_level` are dropped silently. Events
   that pass the dedup window or that are already in the local
   `banned` map are also dropped silently.
4. **Flush.** When the buffer reaches `batch_size` (default `10`)
   or `flush_interval` (default `30s`) elapses, whichever comes
   first, the buffered IPs are pushed through the batched
   `add_list` + `commit` + `reload` cycle (see next).
5. **Sweep.** A periodic timer fires every `ttl / 4` (with a hard
   floor of `15m`) and triggers a **sweep-only** flush — pending
   events are skipped, locally-expired IPs are removed. The sweep
   reuses the same batched path (one `del_list`, one `commit`,
   one `reload`) and is therefore free to coexist with normal
   event traffic.

### ubus JSON-RPC Transport

Every router-side operation is a `POST /ubus` with a
[JSON-RPC 2.0 envelope](https://www.jsonrpc.org/specification) of
the form:

```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "method": "call",
  "params": ["<session_id>", "<object>", "<method>", { ... }]
}
```

- The first authentication call (`session.login`) is made with the
  canonical null session ID
  `"00000000000000000000000000000000"`. The response contains
  `ubus_rpc_session`; the plugin stores it and uses it for every
  subsequent call.
- The session token expires after `session_timeout` (default 5m).
  The client re-logs-in transparently before the next call when
  the cached token is older than the configured lifetime.
- Mutating calls are issued against two core objects only:
  - `uci` — `get` (for `syncExisting`), `add_list`, `del_list`,
    `commit` (for the `firewall` config).
  - `rc` — `init` with `{name: "firewall", action: "reload"}` (the
    ubus equivalent of `/etc/init.d/firewall reload`).
- The `result` payload of a successful call is a 2-element JSON
  array `[code, data]`. The client asserts `code == 0` and
  surfaces `data` to the caller.

### Why `uci`+`rc`, Not `luci2.firewall`

The LuCI2 firewall object — `add_ipset_entry`,
`delete_ipset_entry`, `get_ipsets` — does **not exist** in current
OpenWrt releases:

- A code search across `openwrt/luci` for `add_ipset_entry`
  returns zero matches.
- The `firewall4` package ships no rpcd plugin named `luci2`.
- The "LuCI2" project is archived; the relevant wiki page lives
  on `oldwiki.archive` and is not part of the supported stack.

The core `rpcd` plugins `uci` and `rc` are available on every
default install, ACLed for the `root` user out of the box, and
expose every primitive the plugin needs. The plugin therefore
writes through `uci.add_list` / `uci.del_list` / `uci.commit` and
reloads through `rc.init`. See DECISIONS.md Decision 3 for the
spike that produced this conclusion.

### Flush Strategy

The executor races three conditions:

- **Count trigger.** When the in-memory buffer holds
  `batch_size` events (default `10`), the batch is committed.
- **Time trigger.** When `flush_interval` (default `30s`) elapses
  since the last flush, the partial batch is committed.
- **Sweep trigger.** When the periodic sweep timer fires, a
  sweep-only cycle is run.

Every cycle — whether triggered by events, time, or sweep —
collapses to the **same** UCI transaction:

1. A single `uci.add_list` call with the **full batch** of
   pending-to-add IPs (`values: [...]`).
2. A single `uci.del_list` call with the **full batch** of
   locally-expired IPs (only emitted when the sweep trigger
   brought any).
3. A single `uci.commit` for the `firewall` config.
4. A single `rc.init` reload.

The "one add, one del, one commit, one reload" invariant is
deliberate and load-bearing:

- `fw4 reload` re-creates the entire nftables ruleset from the
  UCI config on every apply. Issuing a reload per ban would
  block the routing plane on every event and would still not
  help TTL (see [Sweep / TTL Eviction](#sweep--ttl-eviction)).
- Issuing a reload per **sweep deletion** would yield a
  thundering-herd problem once the ban list grows.
- A reload is skipped entirely when both the add list and the
  del list are empty (i.e. a sweep tick on an idle system
  produces no router traffic at all).

This is the key behavioural difference from the MikroTik
executor, which can issue independent deletes because
RouterOS' address-list carries a per-entry timeout and does
not need a global reload after a delete.

### Sweep / TTL Eviction

A sweep cycle runs every `ttl / 4`, with a hard minimum of
`15m` (matching the MikroTik executor — a 4-second TTL would
otherwise yield a 1-second sweep ticker, which is wasteful).
Sweep is **not** a separate code path: it reuses the batched
flush with a nil pending slice. The `flush()` function detects
the empty pending list and skips the `add_list` call; if the
expired list is also empty, the cycle is a complete no-op.

Each sweep deletion:

1. Walks the `banned` map under the executor lock, collecting
   every `record` whose `expireAt <= now` into an `expired`
   slice.
2. Issues a single `uci.del_list` with the slice contents.
3. Issues the shared `uci.commit` + `rc.init` reload.
4. Removes the entries from the `banned` map and increments
   the `swept` counter on success.

Unlike the MikroTik executor, the OpenWrt executor does **not**
filter by `sentinel_id` during sweep. The ipset section is
expected to be a **dedicated** section owned entirely by this
executor instance (see [Prerequisites](#prerequisites)); the
plugin will happily evict a manually-added entry if its TTL
runs out, on the same logic that owns the rest of the
section.

### syncExisting Semantics

`uci.get` returns the current `entry` list but does not carry
per-entry timestamps. After a daemon restart, the executor
therefore cannot know when each pre-existing IP was added. The
plugin applies a **conservative TTL assumption**:

- Every pre-existing entry is loaded into the `banned` map
  with `addedAt = now` and `expireAt = now + cfg.ttl`.
- This grants every pre-existing ban a full fresh TTL window
  on restart, rather than expiring them immediately or
  guessing an arbitrary `addedAt`.

Side effect: a long-lived daemon restart effectively **extends**
bans by up to one TTL. This is acceptable for a WAF use case
(false negatives on unbanning are far less harmful than missing
a ban) and is the same trade-off the MikroTik executor makes.

`syncExisting` errors are non-fatal: a transient router outage
at startup must not crash the daemon. The ban list is rebuilt
as events arrive and on the next sweep.

### Deduplication

The executor layers two checks before issuing `add_list`:

1. **Dedup window** (`dedup_window`). A short-lived set
   populated only on **successful** `add_list` results. The
   point of the window is to suppress redundant bans for IPs
   that were just banned and have since been swept out of the
   `banned` map. Setting `dedup_window = 0` disables the
   window entirely.
2. **Local `banned` map.** The authoritative "is this IP
   currently considered banned by us" check. Populated by
   `syncExisting` and updated on every successful add /
   delete.

Both checks are pure lookups: a failed `add_list` does **not**
poison either structure, and the next event for the same IP
will retry naturally. This is the "flaky-safe" property —
the executor must keep looping through router outages without
losing events or creating phantom bans.

### Internal Constants

| Constant                 | Value                       | Purpose                                                       |
|--------------------------|-----------------------------|---------------------------------------------------------------|
| `defaultPort`            | `80`                        | Default `uhttpd-mod-ubus` port.                              |
| `defaultScheme`          | `"http"`                    | Default URL scheme.                                          |
| `defaultSessionTimeout`  | `5m`                        | Default ubus session lifetime.                               |
| `defaultBatchSize`       | `10`                        | Default events-per-flush threshold.                          |
| `defaultFlushInterval`   | `30s`                       | Default time-based flush trigger.                            |
| `defaultMinLevel`        | `"THREAT"`                  | Default minimum event level.                                 |
| `nullSession`            | `000…0000` (32 zeros)       | Canonical session ID for `session.login`.                    |
| `defaultSweepInterval`   | `15m`                       | Floor for the sweep cadence.                                 |
| `httpTimeout`            | `30s`                       | Per-request HTTP client timeout.                             |

---

## EOF, Cancellation, and Shutdown

The executor exits through one of three paths:

- **Context cancellation.** The main loop selects on
  `ctx.Done()`, performs a final best-effort flush of any
  buffered events, and returns the context error. The
  best-effort flush reuses the same batched path; an error on
  the final flush is logged and counted but does not block
  the return — the caller is already shutting down.
- **Source closed cleanly (no `ctx` cancellation).** The
  pop-against-source loop returns, the channel closes, the
  main loop performs a final flush, and `Run` returns `nil`.
- **Startup failure.** A failure in `parseConfig` (missing
  required field, bad `ttl`, unknown `min_level`, …)
  terminates the executor before `Run` is called. The stream
  supervisor will see the error and decide whether to retry.
  A `syncExisting` failure is **not** a startup failure: the
  executor starts anyway with an empty `banned` map.

Per-flush errors (`add_list` / `del_list` / `commit` /
`reload`) are **non-fatal**: they are logged, the `errors`
counter is incremented, and the next event re-tries the
operation. The executor only exits on cancellation or clean
source closure.

---

## Metrics and Stats

The executor exposes four runtime counters via
`Stats() plugin.ExecutorStats`:

| Counter    | Type   | Description                                                              | Incremented when                                                                  |
|------------|--------|--------------------------------------------------------------------------|-----------------------------------------------------------------------------------|
| `executed` | int64  | Events successfully added to the ipset.                                  | `add_list` returned without error and the entry made it into the `banned` map.   |
| `skipped`  | int64  | Events dropped due to level filter or dedup.                             | The event's level is below `min_level`, the dedup window contains the IP, the `banned` map already contains the IP, or the event is dropped by the in-flush `banned` filter. |
| `errors`   | int64  | Errors during `add_list`, `del_list`, `commit`, `reload`, or `sync`.    | The corresponding ubus call returns non-zero ubus code, HTTP error, or network error. |
| `swept`    | int64  | Bans removed by the periodic sweep.                                       | `del_list` returned without error and the entry was removed from `banned`.        |

All four counters use `sync/atomic` and are safe to read from
the metrics endpoint without taking the executor lock.

---

## Constructors

```go
func NewOpenwrtExecutor(cfg executor.ExecutorConfig, log logger.Logger) (plugin.Executor, error)
```

`NewOpenwrtExecutor` is the public constructor. It accepts an
`executor.ExecutorConfig` (the generic `pkg/executor`
descriptor: the `Name` / `Type` / `Config` map forwarded by
`Build`), decodes the `Config` from the inner `Config` map,
validates the required fields, builds the underlying
`HTTPClient`, instantiates the dedup window from
`cfg.DedupWindow`, and returns a fully initialized
`*OpenwrtExecutor`.

`log` is the operational logger used for the `EXECUTOR` tag.
A `nil` is replaced with `pkg/logger.Nop` so downstream code
never has to nil-check. The registry-based factory
(`newOpenwrtFactory`) forwards the logger injected by
`Build`; pre-1.2 callers that relied on the implicit
`internal/sys/utils.Log` should pass
`internal/sys/utils.AsLogger()` once that bridge exists.

Construction is **side-effect-free**: no network I/O happens
until `Run` is called. The first real call to the router is
the `syncExisting` `uci.get` at the top of `Run`.

---

## Registration

The plugin is registered in `init()`:

```go
func init() {
    executor.Register("openwrt", newOpenwrtFactory)
    executor.RegisterManifest("openwrt", (&OpenwrtExecutor{}).Manifest())
}
```

`newOpenwrtFactory` is the registry factory. It receives a
stream-level `executor.ExecutorConfig` plus the logger
forwarded by `Build`, and delegates to
`NewOpenwrtExecutor(cfg, log)`. The factory takes
`executor.ExecutorConfig` directly (no `config.ExecutorItem`
wrapping) and does not hard-code `logger.Nop` — `log` is what
`cmd/arxsentinel` injects via `utils.AsLogger()`. The manifest
is registered separately so the agent can introspect plugin
metadata before instantiating the executor.

The package is blank-imported from
`cmd/arxsentinel/plugins_full.go`, and the plugin is listed
in `profiles/full.yaml` next to the MikroTik entry.

---

## Quick-Start Examples

The following snippets are self-contained, copy-pasteable
fragments for `executors[]`. Each one assumes the rest of the
ArxSentinel stream configuration is in place, including at
least one source named `sentinel-owrt` and a matching detector
chain, and that the prerequisite UCI ipset section has been
declared on the router (see [Prerequisites](#prerequisites)).

### Basic blocklist

```yaml
executors:
  - name: openwrt-blocklist
    type: openwrt
    sources:
      - name: sentinel-owrt
    config:
      host: "192.168.1.1"
      username: "root"
      password: "ROUTER_PASSWORD"
      ipset_name: "arxsentinel_blocklist"
      ttl: "24h"
      sentinel_id: "edge-01"
```

`port`, `scheme`, `session_timeout`, `batch_size`,
`flush_interval`, and `min_level` all fall back to their
defaults. The default `scheme` is `"http"` and the default
`port` is `80`, which matches a stock `uhttpd` install.

### With custom session_timeout and batch_size

Tightening the session lifetime to 1 minute (e.g. for a
hardened `uhttpd` config with a custom rpcd session timeout)
and raising the batch size for a high-traffic detector:

```yaml
executors:
  - name: openwrt-blocklist
    type: openwrt
    sources:
      - name: sentinel-owrt
    config:
      host: "router.example.com"
      username: "root"
      password: "ROUTER_PASSWORD"
      ipset_name: "arxsentinel_blocklist"
      ttl: "1h"
      sentinel_id: "edge-01"
      session_timeout: "1m"
      batch_size: 50
      flush_interval: "15s"
      min_level: "WARN"
      dedup_window: "30s"
```

This configuration re-logs in every minute (in case the rpcd
build was hardened to expire sessions faster than the
default), flushes every 15 seconds or every 50 events,
whichever comes first, and skips events below `WARN`. The
`dedup_window` of 30s suppresses re-bans for the same IP
within 30 seconds of a successful add.

### HTTPS for a TLS-fronted deployment

If the router's `/ubus` is fronted by a TLS reverse proxy
(typical when LuCI is exposed over HTTPS):

```yaml
executors:
  - name: openwrt-blocklist
    type: openwrt
    sources:
      - name: sentinel-owrt
    config:
      host: "router.example.com"
      port: 443
      scheme: "https"
      username: "root"
      password: "ROUTER_PASSWORD"
      ipset_name: "arxsentinel_blocklist"
      ttl: "24h"
      sentinel_id: "edge-01"
```

The default Go HTTP transport validates certificates against
the system trust store. For a private-CA setup, mount the CA
into the agent's container and use the standard
`SSL_CERT_FILE` / `SSL_CERT_DIR` environment variables — the
plugin does not have its own `ca_file` knob.

---

## Troubleshooting

Most "my bans are not taking effect" reports trace back to one
of the following root causes. Walk them in order.

### 1. `POST /ubus` returns 404

`uhttpd-mod-ubus` is not installed. Install it on the router:

```sh
opkg update && opkg install uhttpd-mod-ubus
/etc/init.d/uhttpd restart
```

Verify with `curl -X POST http://<host>/ubus -d '{}'` — the
response should be a JSON-RPC parse error, not a 404.

### 2. `session.login` returns a non-zero ubus code

The configured credentials do not match a user with access
to the `uci` and `rc` core objects. The default ACL
(`/usr/share/rpcd/acl.d/`) grants `root` and `admin` sessions
full access. If you have hardened the device, check that the
matching ACL file is intact:

```sh
ls /usr/share/rpcd/acl.d/
cat /usr/share/rpcd/acl.d/*.json | grep -E 'uci|"rc"'
```

If the ACL was stripped, restore the defaults or write a
custom ACL that grants the plugin's user access to `uci` and
`rc`.

### 3. `uci.get` returns empty / `uci.commit` returns non-zero

The ipset section does not exist or has the wrong name. The
plugin's `ipset_name` config field must match the **UCI
section name** (not the `option name` value), i.e. the
identifier in `firewall.<section_name>`. Verify with:

```sh
uci show firewall | grep ipset
```

You should see a section like
`firewall.arxsentinel_blocklist=ipset`. If the section is
named differently, fix the section name on the router or
update `ipset_name` in the plugin config to match.

### 4. Bans appear in UCI but traffic is not dropped

The `firewall` UCI config has no rule referencing the
ipset. `uci set firewall.@rule[-1].ipset='<name>'` and reload
firewall — the plugin does not manage firewall rules, only
ipset entries. See [Prerequisites](#prerequisites) for the
minimal rule.

### 5. Bans appear and disappear too fast / too slowly

The plugin's `ttl` is the source of truth for entry
lifetime, **not** the nftables native timeout. The local
`banned` map is what drives sweep, and it is reloaded
conservatively on restart (see [syncExisting
Semantics](#syncexisting-semantics)). If the configured `ttl`
is `30s` but the sweep interval is the `15m` floor, an entry
will be in the ipset for at least one sweep cycle. This is
intentional — see [Flush
Strategy](#flush-strategy).

### 6. The log fills with "session expired" messages

The router's `uhttpd` was rebuilt with a custom session
timeout shorter than the plugin's `session_timeout`. Either
lengthen the plugin's `session_timeout` or shorten the
server's session lifetime so the re-login cadence matches
expectations.

---

## Dependencies

Standard library:

- `bytes` — request body construction for `POST /ubus`.
- `context` — cancellation propagation and request scoping.
- `encoding/json` — JSON-RPC 2.0 envelope and ubus response decoding.
- `fmt` — error wrapping and log message formatting.
- `net/http` — HTTP client for the ubus JSON-RPC endpoint.
- `os` — stderr fallback for unparseable payloads.
- `sync`, `sync/atomic` — mutex around the `banned` map, runtime counters.
- `time` — flush intervals, sweep cadence, session timeout, TTL arithmetic, `time.ParseDuration`.

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
