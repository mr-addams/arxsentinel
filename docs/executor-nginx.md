# nginx Executor

## Purpose

The nginx Executor bans threat IPs by writing them into a plain IP blocklist file. arxsentinel
only writes the file; you include it into your nginx configuration however suits your setup.
It runs autonomously: a dedicated goroutine reads `ThreatEvent`s from a Named Channel Hub source,
accumulates them, and writes a formatted list file. A periodic sweep removes expired bans
based on a configurable TTL.

**Quick start:** see `cookbook/nginx-executor/nginx-basic.yaml` for a minimal working configuration.

---

## Configuration

### Config fields (`executors[].config`)

| Field | Type | Default | Description |
|---|---|---|---|
| `list_file` | `string` | *required* | Path to the IP blocklist file that nginx includes (e.g. `/etc/nginx/conf.d/arxsentinel_autoblock.list`) |
| `state_file` | `string` | `""` (disabled) | Optional path for JSON TTL persistence — saves `{"ip": "timestamp"}` after every flush/sweep |
| `min_level` | `string` | `"THREAT"` | Minimum event level to act on: `INFO` \| `WARN` \| `THREAT` |
| `ttl` | `duration` | `24h` | Auto-unban duration. Go format: `24h`, `1h30m`, `3600s` |
| `batch_size` | `int` | `10` | IPs per batch write trigger |
| `flush_interval` | `duration` | `30s` | Max time before a partial batch is flushed |
| `reload_cmd` | `string` | `""` (passive) | Shell command to reload nginx after write (e.g. `nginx -s reload`). Empty = no auto-reload |
| `reload_timeout` | `duration` | `30s` | Timeout for the reload command |

### Source wiring (`executors[].sources`)

Each executor must declare at least one `sources` entry matching a `sentinel-threat` sink name
in the streams configuration:

```yaml
executors:
  - name: nginx-blocklist
    type: nginx
    sources:
      - name: sentinel-cf          # must match sentinel-threat sink name in streams
    config: ...

streams:
  - name: main
    outputs:
      - type: sentinel-threat
        name: sentinel-cf          # feeds this executor
```

### Queue backends

Same as Cloudflare executor — see `docs/executor-cloudflare.md`.

---

## Example Configuration

Minimal working config — see also `cookbook/nginx-executor/nginx-basic.yaml`:

```yaml
streams:
  - name: main
    inputs:
      - type: file
        path: /var/log/nginx/access.log
    outputs:
      - type: sentinel-threat
        name: sentinel-cf
      - type: file
        path: /var/log/arxsentinel/threats.log
        format: fail2ban

executors:
  - name: nginx-blocklist
    type: nginx
    sources:
      - name: sentinel-cf
    config:
      list_file: /etc/nginx/conf.d/arxsentinel_autoblock.list
      state_file: /var/lib/arxsentinel/nginx-state.json
      min_level: "THREAT"
      ttl: "24h"
      batch_size: 10
      flush_interval: "30s"
      reload_cmd: "nginx -s reload"
```

---

## Using the blocklist file in nginx

The executor writes banned IPs to `list_file` in the format `<ip> 1;` (one entry per line).
How you include and apply this file in your nginx configuration is entirely up to you —
arxsentinel does not prescribe a method.

---

## Lifecycle

### 1. Construction — `NewNginxExecutor`

1. Parses and validates config (`parseConfig`): required fields, level, TTL.
2. Logs a WARNING if `reload_cmd` is empty (bans are written but nginx is not reloaded).

### 2. Run loop — `Run(ctx, source)`

Called in its own goroutine by `startExecutors`. The loop:

1. **syncExisting** — reads the current `list_file` to populate the `banned` map.
   Optionally reads `state_file` (JSON) to recover TTL timestamps.
   IPs without state entries get `addedAt = now`.
2. Reads `ThreatEvent`s from `source.Pop(ctx)` via an internal fan-out goroutine.
3. Filters by `min_level` and deduplication (`banned` map).
4. Accumulates events in a buffer. Flushes when:
   - buffer reaches `batch_size`, or
   - `flush_interval` ticker fires (with events in buffer).
5. Runs `sweep` on a separate ticker (`TTL/4`, floor 15 min).
6. On context cancellation or source close: flushes remaining buffer, runs final sweep, exits.

### 3. Flush

`flush` writes the entire `banned` map to the list file:

1. Builds a string with header `"# managed by arxsentinel — do not edit manually\n"`
   and one `"<ip> 1;\n"` per banned IP.
2. Calls `writeFile` — atomic write via `.tmp` + `os.Rename` (prevents nginx from
   reading a partially written file).
3. Optionally saves state file (JSON).
4. Calls `runReload` if `reload_cmd` is non-empty.

### 4. Sweep

Periodic removal of expired bans:

1. Iterates `banned` map, removes IPs where `time.Since(addedAt) > TTL`.
2. If any IPs were removed, rewrites the list file and runs reload.
3. No-op if no IPs expired — no disk write, no reload.

### 5. Shutdown

`Run` exits when `ctx` is cancelled or source is closed. Bans remain in the
list file until their TTL expires or the operator removes them manually.

> **Note:** `SIGHUP` (reload) applies only to detectors, scoring, and blocklists.
> Executor configuration changes (list_file, reload_cmd, sources) require a full
> `systemctl restart arxsentinel`.

---

## Reload behavior

### `reload_cmd` empty (passive mode)

The executor writes the list file but does not reload nginx.
A WARNING is logged at startup to alert the operator.
Useful when:
- nginx is configured to reload periodically via cron.
- The operator prefers manual reloads after reviewing new bans.
- The list file is read by a different mechanism (e.g., OpenResty `lua_shared_dict`).

### `reload_cmd` non-empty

The executor runs `sh -c "<reload_cmd>"` after every successful write:

- Default timeout: 30s (configurable via `reload_timeout`).
- If the command times out, the context is cancelled and the process is killed.
- `CombinedOutput` is logged on error for debugging.
- Reload failures increment the `Errors` counter but do not stop the executor.

---

## Troubleshooting

### `list_file must not be empty`

Missing required field. Set `list_file` to a writable path.

### File not writable

- Check directory permissions: the user running arxsentinel must have write access.
- The executor uses atomic write (`.tmp` + `os.Rename`), which requires write
  permission on the **directory**, not just the file.
- Check disk space: a full filesystem will cause write errors.

### Reload fails

- Check nginx configuration syntax: `nginx -t` before restart.
- Check reload command timeout: if nginx takes longer than `reload_timeout` to
  reload, increase the timeout or reduce batch sizes.
- Check combined output in arxsentinel logs for nginx error messages.

### State file corruption

If the state file contains invalid JSON, it is ignored with a WARNING at startup.
TTL is calculated from `addedAt = now` for all IPs — bans are not shortened,
but may live longer than configured until the next restart with a valid state file.

### Bans not applied

- nginx not reloaded: set `reload_cmd: "nginx -s reload"` or reload manually.
- Wrong `list_file` path: verify the path matches the `include` directive in nginx config.
- Blocklist file not included: the file is useless unless your nginx configuration
  reads and applies it (however your nginx configuration consumes it).
