# Cloudflare Executor

## Purpose

The Cloudflare Executor bans threat IPs by adding them to a Cloudflare IP List.
It runs autonomously: a dedicated goroutine reads `ThreatEvent`s from a Named Channel Hub
source, batches them, and issues bulk API calls to Cloudflare.
A periodic sweep removes expired bans based on a configurable TTL.

**Quick start:** see `cookbook/cloudflare/nginx-basic.yaml` for a minimal working configuration.

---

## Configuration

### Config fields (`executors[].config`)

| Field | Type | Default | Description |
|---|---|---|---|
| `api_token` | `string` | *required* | Cloudflare API token — Account > Lists > Edit permission |
| `account_id` | `string` | *required* | Cloudflare account ID |
| `list_name` | `string` | `"arxsentinel_blocklist"` | IP list name (created automatically if absent) |
| `min_level` | `string` | `"THREAT"` | Minimum event level to act on: `INFO` \| `WARN` \| `THREAT` |
| `ttl` | `duration` | `24h` | Auto-unban duration. Go format: `24h`, `1h30m`, `3600s` |
| `max_items` | `int` | `0` (unlimited) | Max list size. Cloudflare Free tier hard limit: 10 000 |
| `batch_size` | `int` | `100` | IPs per bulk API call |
| `flush_interval` | `duration` | `10s` | Max time before a partial batch is sent |
| `instance_id` | `string` | `""` (hostname) | Ban comment prefix. Auto-detected from hostname if empty |
| `comment_extra` | `string` | `""` | Optional suffix appended to ban comment: `"sentinel-<id> <extra>"`. Max 50 chars |

### Source wiring (`executors[].sources`)

Each executor must declare at least one `sources` entry matching a `sentinel-threat` sink name
in the streams configuration:

```yaml
executors:
  - name: cf-ban
    type: cloudflare
    sources:
      - name: sentinel-cf          # must match sentinel-threat sink name in streams
    config: ...

streams:
  - name: main
    outputs:
      - type: sentinel-threat
        name: sentinel-cf          # feeds this executor
```

### Queue backends (`executors[].sources[].queue`)

By default, events are held in memory (lost on restart). For persistent queuing:

| Backend | `type` | Use case | Extra fields |
|---|---|---|---|
| `memory` | `memory` | Dev/testing, single process | — |
| `bbolt` | `bbolt` | Bare-metal, Docker on host | `path` (required) |
| `redis` | `redis` | k8s, cloud, multi-replica | `url` (required) |

```yaml
sources:
  - name: sentinel-cf
    queue:
      type: bbolt
      path: /var/lib/arxsentinel/queue-cf.db
```

---

## Example Configuration

Minimal working config — see also `cookbook/cloudflare/nginx-basic.yaml`:

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
  - name: cf-ban
    type: cloudflare
    sources:
      - name: sentinel-cf
    config:
      api_token: "YOUR_CF_API_TOKEN"
      account_id: "YOUR_CF_ACCOUNT_ID"
      list_name: "arxsentinel_blocklist"
      min_level: "THREAT"
      ttl: "24h"
      batch_size: 100
      flush_interval: "10s"
```

---

## Lifecycle

### 1. Construction — `NewCloudflareExecutor`

1. Parses and validates config (`parseConfig`): required fields, level, TTL.
2. Creates HTTP client; calls `FindOrCreateList` (30s timeout).
3. Calls `syncExisting` — loads current list items into local `banned` map
   (`addedByExecutor: false`; these will be swept when TTL expires).

### 2. Run loop — `Run(ctx, source)`

Called in its own goroutine by `startExecutors`. The loop:

1. Reads `ThreatEvent`s from `source.Pop(ctx)` via an internal fan-out goroutine.
2. Filters by `min_level` and deduplication (`banned` map).
3. Accumulates events in a buffer. Flushes when:
   - buffer reaches `batch_size`, or
   - `flush_interval` ticker fires (with events in buffer).
4. Runs `sweep` on a separate ticker (`TTL/4`, floor 15 min).
5. On context cancellation or source close: flushes remaining buffer, runs final sweep, exits.

### 3. Flush — async bulk ops

`flush` sends buffered IPs to Cloudflare via `AddItems` (bulk API call):

1. Calls `waitForPendingOp` — if a previous bulk operation is still pending, polls it with
   exponential backoff (500ms → 16s, 6 attempts ≈ 31.5s total). Clears on `completed` or `failed`.
2. Calls `AddItems` via `doWithRetry` — retries up to 3× on HTTP 429 with 5s backoff.
3. Saves the returned `operationID` as `pendingOpID`.
4. Records banned IPs in local map.

CF allows **one pending bulk operation per account**. `waitForPendingOp` enforces this.

### 4. Sweep

Periodic removal of expired bans (runs every `TTL/4`, floor 15 min):

1. Collects IPs from `banned` where `addedAt + TTL < now` and `cfItemID != ""`.
2. Calls `RemoveItems` (bulk API, async — same pending-op gate as flush).
3. Removes collected IPs from local `banned` map.

### 5. Shutdown

`Run` exits when `ctx` is cancelled or source is closed. No remote cleanup — entries remain
in the Cloudflare list until their TTL expires or `arxsentinel cleanup --cf` is run.

> **Note:** `SIGHUP` (reload) applies only to detectors, scoring, and blocklists.
> Executor configuration changes (credentials, list name, sources) require a full
> `systemctl restart arxsentinel`.

---

## Multi-sentinel setup

When multiple arxsentinel instances protect the same Cloudflare account, use `instance_id`
to distinguish their bans:

```yaml
config:
  instance_id: "prod-eu-1"   # ban comment: "sentinel-prod-eu-1"
  comment_extra: "eu-dc"     # ban comment: "sentinel-prod-eu-1 eu-dc"
```

To clean up bans from a specific instance:
```bash
arxsentinel cleanup --cf --account-id YOUR_ID --api-token YOUR_TOKEN --instance prod-eu-1
```

---

## Cloudflare Requirements

- **API token**: Account → Lists → Edit permission
- **Free tier**: max 10 lists × 10 000 items/list; max 1M modifications per 12h
- **Rate limits**: 429 responses are retried automatically (up to 3×, 5s backoff)
- **Pending ops**: CF allows only 1 pending bulk operation per account; the executor queues
  flushes until the previous op completes

### WAF rule (required to block traffic)

The executor only manages the IP List. To block traffic, create a WAF Custom Rule:

1. Cloudflare Dashboard → your domain → **Security** → **WAF** → **Custom Rules** → **Create rule**
2. Configure:
   - Field: **IP Source Address** / is in list / `arxsentinel_blocklist`
   - Action: **Block**
3. Deploy.

> Without this rule, IPs are added to the list but traffic is **not blocked**.

---

## Troubleshooting

### `APIToken must not be empty` / `AccountID must not be empty`
Missing required fields in `config`. Set `api_token` and `account_id`.

### IP not banned (events skipped)
- `min_level` too high: lower to `"WARN"` or `"INFO"`.
- IP already in `banned` map (dedup): check with `arxsentinel cleanup --cf --dry-run`.
- Queue full: increase `batch_size` or check queue backend.

### Bans disappear too fast
- TTL too short. Integer values are parsed as **seconds** (`3600` = 1h, not 3600h).
- Verify: `ttl: "24h"` (with quotes and unit suffix).

### `max_items` reached
Set `max_items: 0` (unlimited) or reduce `ttl` to sweep faster.
Cloudflare Free hard limit is 10 000 — above that, `AddItems` will fail.

### 429 Too Many Requests
The executor retries automatically (3×, 5s). If retries are exhausted, events are dropped
and counted in `Errors`. Consider increasing `flush_interval` to reduce API call frequency.

### Pending operation timeout
If a bulk operation takes >31.5s, the executor logs a warning and proceeds. The operation
may still complete asynchronously in Cloudflare — check the CF dashboard if IPs appear late.
