# Cloudflare Executor

## Purpose

The Cloudflare Executor manages Cloudflare IP blocklists. It receives threat events from the
pipeline, filters them by severity level, and adds the offending IP addresses to a Cloudflare
IP List. A background sweep goroutine periodically removes expired bans based on a configurable
TTL, keeping the list clean without manual intervention.

## Configuration

| Field | Type | Default | Description |
|---|---|---|---|
| `api_token` | `string` | *required* | Cloudflare API token with Account > Lists > Edit permission |
| `account_id` | `string` | *required* | Cloudflare account ID |
| `list_name` | `string` | `"arxsentinel-blocklist"` | Name of the IP list in Cloudflare (created if it does not exist) |
| `min_level` | `string` | `"THREAT"` | Minimum threat level to act on: `INFO`, `WARN`, or `THREAT` |
| `ttl` | `duration` | `24h` | Time-to-live for a banned IP before it is automatically removed |
| `max_items` | `int` | `0` (unlimited) | Maximum number of items in the list (Cloudflare free tier limit: 10 000) |

### Field details

- **`ttl`** — parsed via `time.ParseDuration`, accepts Go duration strings (`24h`, `1h30m`, `3600s`).
  An integer value is treated as seconds. Must be positive.
- **`max_items`** — when set to `0` the limit is disabled. When the limit is reached, new events are
  silently skipped (counted in `Skipped` stats).

## Example Configuration

```yaml
executors:
  - name: cloudflare-blocklist
    type: cloudflare
    config:
      api_token: "YOUR_CF_API_TOKEN"
      account_id: "YOUR_CF_ACCOUNT_ID"
      list_name: "arxsentinel-blocklist"
      min_level: "THREAT"
      ttl: "24h"
      max_items: 10000
```

## Lifecycle

The executor follows four phases:

### 1. Construction — `NewCloudflareExecutor`

1. Parses the configuration block via `parseConfig()` — validates required fields, threat level,
   and TTL.
2. Creates an HTTP client for Cloudflare API communication.
3. Calls `FindOrCreateList()` — either locates an existing IP list by name or creates a new one
   (context timeout: 30 seconds).
4. Calls `syncExisting()` — loads all current items from the remote list into the local in-memory
   `banned` map. These items are marked as `addedByExecutor: false` (pre-existing, not managed by
   this instance).
5. Starts the background sweep goroutine (`sweepExpired`) that runs on a configurable interval
   (see Sweep below).

### 2. Execution — `Execute(ctx, event)`

Called for each incoming `ThreatEvent`. The decision logic:

1. **Level validation** — if the event level is not one of `INFO`, `WARN`, `THREAT` → skip.
2. **Level filtering** — if the event level is below `min_level` → skip.
3. **Duplicate check** — if the IP is already in the local `banned` map → skip.
4. **Capacity check** — if `max_items > 0` and the map is full → skip.
5. **Add to Cloudflare** — calls `AddItem()` on the API. On failure the IP is removed from the
   local map and the error counter is incremented.
6. **Record** — stores the Cloudflare item ID returned by the API alongside the timestamp.

Each outcome is counted in `Executed`, `Skipped`, or `Errors` stats respectively.

### 3. Sweep — `sweepExpired` (background goroutine)

A background goroutine that periodically removes expired bans:

- **Interval**: `TTL / 4`, with a floor of 15 minutes.
- **What it does**:
  1. If any local records lack a Cloudflare item ID, it refreshes the mapping by re-fetching the
     remote list (`ListItems`).
  2. Iterates over the local `banned` map and collects all records whose `addedAt + TTL` is in the
     past and have a non-empty `cfItemID`.
  3. Calls `RemoveItems()` on the Cloudflare API to delete the expired entries.
  4. Removes the entries from the local map (double-checks TTL to avoid race conditions).

### 4. Shutdown — `Close()`

Cancels the sweep context, then waits for the sweep goroutine to finish (`wg.Wait()`).
No cleanup of the Cloudflare list — entries remain in the remote list until their TTL expires
or they are removed externally.

## Cloudflare Requirements

- **API token permissions**: Account → Lists → Edit
- **API token format**: 40-character hex string issued from the Cloudflare dashboard
- **Account ID**: Found in the Cloudflare dashboard URL or the Account Details page
- **Free tier limits**:
  - Maximum 10 IP lists per account
  - Maximum 10 000 items per list
- **Rate limits**: The Cloudflare API rate-limits List operations; the executor does not implement
  retry logic (depends on the HTTP client timeout).

## Troubleshooting

### 1. `APIToken must not be empty`

The `api_token` field is missing or empty in the configuration. Ensure the token is provided:

```yaml
api_token: "your_40_character_cloudflare_api_token"
```

### 2. `create list` failure

The list could not be found or created. Common causes:

- The list name (`list_name`) already exists but is in a different scope or account.
- The free tier limit of 10 lists has been reached — delete unused lists or use an existing one.
- The API token lacks the `Account > Lists > Edit` permission.

### 3. IP not blocked (events are skipped)

Events arrive but nothing is added to the Cloudflare list. Check:

- **`min_level` is too high** — if `min_level` is set to `"THREAT"`, events with level `"INFO"`
  or `"WARN"` are silently skipped. Lower to `"WARN"` or `"INFO"` if needed.
- **Duplicate IPs** — an IP already in the list is skipped (logged as `Skipped`).

### 4. Items disappear from the list (TTL too short)

Bans are removed from the Cloudflare list after `ttl` elapses. If bans disappear sooner than
expected:

- The TTL duration is parsed from configuration — verify the unit (e.g., `24h`, `1h30m`).
- An integer value is treated as **seconds**, not minutes.
- The sweep interval is `TTL / 4` — bans may be removed up to `TTL / 4` after the actual TTL
  expiry.

### 5. `max_items` reached (skipped in logs)

When the number of banned IPs reaches `max_items`, new events are silently skipped and counted
in the `Skipped` stat. To diagnose:

- Check executor stats: `Stats().Skipped` grows while `Stats().Executed` stays flat.
- Increase `max_items` (up to 10 000 for Cloudflare free tier) or set to `0` to disable the
  limit.
- If the list is full, consider reducing `ttl` so expired items are swept faster.
