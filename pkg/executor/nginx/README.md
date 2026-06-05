# `pkg/executor/nginx` — Nginx Executor

Nginx executor plugin for ArxSentinel. Consumes scored threat events from the
pipeline and writes their IP addresses into a flat, nginx-compatible blocklist
file. When a reload command is configured, the executor invokes it after every
flush so that nginx picks up the updated blocklist without manual intervention.
The file-based design avoids any HTTP control-plane dependency on nginx itself:
the executor only ever touches the filesystem and (optionally) runs a shell
command, which makes it the simplest of the three executors in the project and
the natural choice for air-gapped or read-only environments.

- **Plugin ID:** `nginx`
- **Plugin version:** `1.0.0`
- **Role:** `Executor`
- **Input type:** `scored event`
- **Output type:** `none`
- **Tags:** `nginx`, `file-based`

## Module Layout

```
pkg/executor/nginx/
├── config.go       # Config struct, DefaultConfig, parseConfig
├── executor.go     # NginxExecutor — main implementation
├── manifest.go     # Plugin metadata
├── register.go     # init() registration
└── README.md       # (this file)
```

---

## Configuration Reference

The executor is declared under `executors[]` in the stream configuration. The
executor accepts a single required field plus a number of optional tuning
knobs:

| Field            | Type       | Default  | Required | Description                                                              |
|------------------|------------|----------|----------|--------------------------------------------------------------------------|
| `list_file`      | `string`   | —        | **yes**  | Path to the IP blocklist file. Format: `<ip> 1;` per line.               |
| `state_file`     | `string`   | `""`     | no       | Optional path for JSON TTL persistence: `{"ip": "ISO8601-timestamp"}`.   |
| `min_level`      | `string`   | `THREAT` | no       | Minimum threat level to act on: `INFO`, `WARN`, or `THREAT`.             |
| `ttl`            | `duration` | `24h`    | no       | Auto-unban duration. Positive only.                                      |
| `batch_size`     | `int`      | `10`     | no       | Maximum events accumulated before a forced flush.                        |
| `flush_interval` | `duration` | `30s`    | no       | Maximum time between partial flushes.                                    |
| `reload_cmd`     | `string`   | `""`     | no       | Shell command to reload nginx after each write (e.g. `nginx -s reload`). |
| `reload_timeout` | `duration` | `30s`    | no       | Timeout for the reload command.                                          |

The `duration` fields (`ttl`, `flush_interval`, `reload_timeout`) accept either
a string with a Go-style suffix (`"5m"`, `"2h30m"`, `"45s"`) or an integer
number of seconds. Internally the struct uses `time.Duration`, which has no
sensible `encoding/json` representation, so the json tag is `json:"-"` and the
values are recovered from a raw `map[string]any` during `parseConfig`.

### Validation Rules

- `list_file` must not be empty. An empty value produces a startup error.
- `min_level` must be one of the three constants `INFO`, `WARN`, or `THREAT`.
  Anything else is rejected at startup.
- `ttl` must be strictly positive (`> 0`). A zero or negative TTL is rejected
  by `NewNginxExecutor` because a non-positive TTL would either ban
  permanently or never ban at all.
- If `reload_cmd` is empty, the executor logs a `WARNING` at startup and
  switches to **passive mode** — the file is written, but no reload is
  triggered. The operator is expected to reload nginx by hand or by some
  external mechanism (file watcher, k8s reload controller, etc.).

---

## Behaviour Details

### Run Loop

`Run(ctx context.Context, source plugin.EventSource) error` is the main entry
point. The executor must outlive the goroutine that calls it, so the function
returns only when the source closes or `ctx` is cancelled.

1. **Startup sync** — `syncExisting()` reads the current contents of
   `list_file` (and `state_file` if present) to populate the in-memory
   `banned` map. The executor therefore starts every run with a complete view
   of the current state, even across process restarts.
2. **Tickers** — two timers are started:
   - `flushTicker` at `cfg.FlushInterval` (default `30s`).
   - `sweepTicker` at `cfg.TTL / 4`, with a floor of `15 minutes`
     (`defaultSweepInterval`). The `/4` heuristic keeps the sweep cheap
     while still reacting to expiries within a quarter of a TTL.
3. **Event loop** — a single goroutine calls `source.Pop(ctx)` and forwards
   each scored event into an unbuffered internal channel. The main `select`
   loop reacts to four sources:
   - `ctx.Done()` → perform a final `flushLocked` + `sweep` and return
     `ctx.Err()`.
   - Event from the internal channel → check `min_level`, deduplicate, add
     to the in-memory `banned` map and to the write buffer.
   - `flushTicker.C` → flush the buffer to disk (even if it is partial).
   - `sweepTicker.C` → drop expired IPs from the map and rewrite the file
     if anything changed.

### Startup Sync

`syncExisting()` reconciles the on-disk blocklist with the in-memory state
when the executor starts. The function performs three steps:

1. Read `list_file` line by line with a `bufio.Scanner`. Each line that
   matches the expected `<ip> 1;` shape is added to the `banned` map with a
   timestamp of `time.Now()` — the executor does not know, at this point,
   when those IPs were originally banned.
2. If `state_file` is configured and readable, decode the JSON map of
   `ip → ISO8601-timestamp` and overwrite the timestamps from step 1. This
   restores the original TTL windows so a restart does not artificially
   prolong every ban by an extra full TTL.
3. If `state_file` is missing or unparseable, the executor logs a `WARNING`
   and keeps the `time.Now()` timestamps from step 1. The TTL clock simply
   restarts. This is the **graceful degradation** path — a corrupted state
   file is never fatal.

### Batching

Events are accumulated in an in-memory write buffer before they hit the
disk. The buffer is bounded by `cfg.BatchSize` (default `10`). A flush is
triggered by either of two conditions, whichever fires first:

- **Size trigger** — the buffer length reaches `cfg.BatchSize`. The flush
  is performed synchronously inside the event-handling case of the main
  `select`.
- **Time trigger** — `flushTicker` fires. Even if the buffer contains a
  single event, it is written. This guarantees a maximum staleness of
  `cfg.FlushInterval`, so a slow trickle of threats is still applied
  without operator-visible lag.

A duplicate check (`isDuplicate(ip)`) is performed before an event enters
the buffer. The check takes an `RLock` on the executor mutex and looks the
IP up in the `banned` map. **Importantly, the IP is also pre-registered in
`banned` *before* it is added to the buffer** — this catches duplicates
that arrive in the same batch, which would otherwise both pass the
duplicate check (they are not yet on disk) and both end up in the buffer.

### File Write

Writes are **atomic at the filesystem level**. The executor never rewrites
`list_file` in place; instead, it:

1. Builds the full file content in memory (header + one line per banned IP).
2. Creates the destination directory with `os.MkdirAll` if it does not
   exist.
3. Writes the content to `<list_file>.tmp` and calls `os.File.Sync()` to
   flush the data to the underlying storage.
4. Renames `<list_file>.tmp` over `list_file` with `os.Rename`. The rename
   is atomic on POSIX filesystems, so a concurrent `nginx` reload will
   always see either the old or the new file in full, never a half-written
   intermediate state.

The file starts with a single header line:

```
# managed by arxsentinel — do not edit manually
```

After the header, every banned IP occupies exactly one line in the canonical
`<ip> 1;` form, with a trailing newline. nginx `geo` and `map` blocks parse
this format natively, and any tooling that already understands the format
will continue to work without modification.

### Sweep

`sweep(ctx)` is the periodic garbage collector for the in-memory map and
the on-disk file. It is invoked from the `sweepTicker` arm of the main
`select`:

1. Iterate over `banned` and drop any entry where
   `time.Since(addedAt) > cfg.TTL`.
2. If at least one entry was dropped, the file is rewritten with the
   reduced map.
3. **Even if the map becomes empty** after the sweep, the file is still
   written — an empty file is the only way to unban an IP from nginx's
   point of view. A passive executor that never wrote an empty file would
   leave stale entries on disk forever.

The sweep is therefore the mechanism that implements the TTL contract:
bans are added by events and removed by time. Without the sweep, the
`banned` map would only grow.

### State File

The optional `state_file` is the executor's persistence layer for the
original TTL timestamps. It is written after every successful flush, so a
crash between flushes loses at most one batch of new bans — and even then,
the file on disk is always consistent because of the atomic write.

The on-disk format is a JSON object whose keys are the banned IPs and
whose values are ISO-8601 strings produced by `time.Format(time.RFC3339)`:

```json
{
  "203.0.113.42": "2026-06-05T11:24:18Z",
  "198.51.100.7": "2026-06-05T11:18:02Z"
}
```

Recovery is handled in `syncExisting()` (see above). If the file is
corrupted, the executor logs a `WARNING`, keeps the data on disk, and
restarts the TTL clock from `time.Now()` — the worst case is that some
bans live up to one extra TTL after a restart, which is acceptable
behaviour for a defensive system.

### Reload Command

When `cfg.ReloadCmd` is non-empty, the executor invokes the command after
every successful flush via `sh -c "<reload_cmd>"` with a context bounded
by `cfg.ReloadTimeout` (default `30s`):

- **Success** — combined output is silently discarded. The command is
  assumed to have done its job.
- **Failure** — the `CombinedOutput` of the command is logged at
  `ERROR` level, along with the exit code. The on-disk blocklist is
  still considered valid; the operator must investigate why the reload
  failed (missing binary, wrong path, insufficient permissions, etc.).
- **Timeout** — the context fires before the command returns, the
  process is killed by the context machinery, and an error is logged.
- **Empty reload_cmd** — passive mode. No command is invoked; the file
  is written and that is all. This is the only path that produces a
  `WARNING` at startup.

The choice of `sh -c` rather than a direct exec is deliberate: it lets
operators use shell features (pipes, `&&`, `sudo`, environment variable
expansion) to wrap the actual nginx reload in whatever control sequence
their deployment requires.

### Internal Constants

| Constant                  | Value             | Purpose                                                                                  |
|---------------------------|-------------------|------------------------------------------------------------------------------------------|
| `defaultSweepInterval`    | `15 * time.Minute` | Floor for the sweep ticker. The actual interval is `max(TTL/4, defaultSweepInterval)`.   |
| `fileHeader`              | `# managed by arxsentinel — do not edit manually\n` | First line of the blocklist file, marks the file as machine-managed.        |

---

## Metrics and Stats

The executor exposes three runtime counters via
`Stats() plugin.ExecutorStats`:

| Counter    | Type   | Description                                                  |
|------------|--------|--------------------------------------------------------------|
| `executed` | int64  | Events successfully written to the blocklist (banned).       |
| `skipped`  | int64  | Events below `min_level` or duplicates of an already-banned IP. |
| `errors`   | int64  | Write or reload failures.                                    |

All three counters are updated with `sync/atomic` and are safe to read
from the metrics endpoint without taking a lock. The counters give
operators a quick read on the executor's actual workload: a high
`skipped` count usually means the upstream detector is producing a lot of
`INFO` events; a non-zero `errors` count warrants an immediate check of
the log stream for write or reload failures.

---

## Constructor

```go
func NewNginxExecutor(cfg config.ExecutorItem) (plugin.Executor, error)
```

The constructor runs the full startup sequence and returns a fully
initialised executor:

1. Call `parseConfig(cfg.Config)` to apply defaults, extract the
   duration fields from the raw config map, JSON-round-trip the
   non-duration fields, and run the validation rules.
2. Re-check that `cfg.TTL > 0`. The `parseConfig` function trusts the
   raw duration value; the constructor enforces the semantic contract.
3. Log a `WARNING` if `cfg.ReloadCmd == ""` to make the passive-mode
   behaviour visible in the startup log.
4. Return an `*NginxExecutor` with an empty `banned` map. The map is
   populated by `syncExisting()` once `Run` starts, not by the
   constructor.

The returned value implements the `plugin.Executor` interface and is
ready to be passed to a stream's `executors[]` list.

---

## Registration

The plugin is registered in `init()`:

```go
func init() {
    executor.Register("nginx", newNginxFactory)
    executor.RegisterManifest("nginx", (&NginxExecutor{}).Manifest())
}

func newNginxFactory(cfg executor.ExecutorConfig) (plugin.Executor, error) {
    item := config.ExecutorItem{
        Name:   cfg.Name,
        Type:   cfg.Type,
        Config: cfg.Config,
    }
    return NewNginxExecutor(item)
}
```

The `init()` pattern is the same as for the other executors in the
project — the factory function adapts the generic `ExecutorConfig` to
the executor-specific `config.ExecutorItem` shape, then delegates to
`NewNginxExecutor`. The manifest is registered eagerly so the agent can
report the plugin's metadata (ID, version, role, input/output types,
tags) before any executor is instantiated.

---

## Quick-Start Examples

The following snippets are self-contained, copy-pasteable fragments for
`executors[]`. Each one assumes the rest of the ArxSentinel stream
configuration is in place.

### Minimal — list file only

The smallest valid configuration. The executor writes to the file, but
nginx must be reloaded by some external mechanism.

```yaml
executors:
  - name: nginx-blocklist
    type: nginx
    config:
      list_file: /etc/nginx/conf.d/arxsentinel-blocklist.conf
```

### Full — state file and reload command

Production-style configuration. The state file makes bans survive an
agent restart with their original TTL windows; the reload command makes
the blocklist live in nginx within `flush_interval` seconds without
operator intervention.

```yaml
executors:
  - name: nginx-blocklist
    type: nginx
    config:
      list_file:      /etc/nginx/conf.d/arxsentinel-blocklist.conf
      state_file:     /var/lib/arxsentinel/nginx-bans.json
      min_level:      THREAT
      ttl:            24h
      batch_size:     10
      flush_interval: 30s
      reload_cmd:     "nginx -s reload"
      reload_timeout: 30s
```

### Docker — reload through a sidecar

In a container deployment the agent may not have direct access to the
nginx master process. The reload command can be a `docker exec` call
into the nginx container, gated by a shared network namespace or an
authenticated socket.

```yaml
executors:
  - name: nginx-blocklist
    type: nginx
    config:
      list_file:      /var/run/nginx/conf.d/arxsentinel-blocklist.conf
      state_file:     /var/lib/arxsentinel/nginx-bans.json
      min_level:      THREAT
      ttl:            12h
      batch_size:     20
      flush_interval: 15s
      reload_cmd:     "docker exec nginx nginx -s reload"
      reload_timeout: 10s
```

### Passive — write only, no reload

When the operator prefers to drive reloads from a separate watcher (a
`systemd.path` unit, a `kubectl rollout restart`, an external CI job),
the executor can be configured without a `reload_cmd`. The startup
`WARNING` is the only signal that the executor is in passive mode.

```yaml
executors:
  - name: nginx-blocklist
    type: nginx
    config:
      list_file:  /etc/nginx/conf.d/arxsentinel-blocklist.conf
      state_file: /var/lib/arxsentinel/nginx-bans.json
      ttl:        48h
```

---

## Dependencies

Standard library:

- `bufio` — scanner for reading the existing `list_file` at startup.
- `context` — cancellation propagation into both the event loop and the
  reload command.
- `encoding/json` — state file marshal and unmarshal.
- `fmt` — log message formatting.
- `os` — file I/O, `os.Rename` for atomic writes, `os.MkdirAll` for
  directory creation.
- `os/exec` — reload command execution via `sh -c`.
- `path/filepath` — directory creation helpers.
- `strings` — line processing and trimming.
- `sync` — `sync.RWMutex` protecting the `banned` map.
- `sync/atomic` — counters for the stats endpoint.
- `time` — TTL arithmetic, ticker construction, `time.Duration` for
  configuration values.

Project:

- `internal/sys/config` — `ExecutorItem` shape passed to the
  constructor.
- `internal/sys/utils` — `utils.Log` (default logger).
- `pkg/plugin` — `Executor`, `Manifest`, `ExecutorStats`, `ThreatEvent`,
  `EventSource`.
- `pkg/executor` — registry (`Register`, `RegisterManifest`,
  `ExecutorConfig`).
