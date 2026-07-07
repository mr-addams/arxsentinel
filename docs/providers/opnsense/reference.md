# OPNsense Executor Reference

## Config Fields

| Field | Type | Default | Required | Description |
|-------|------|---------|----------|-------------|
| `host` | string | — | **yes** | Firewall hostname or IP. Resolved by the standard Go HTTP client. |
| `port` | int | `443` | no | Port of the OPNsense web UI (REST API). |
| `scheme` | string | `"https"` | no | `"http"` or `"https"`. Production OPNsense is HTTPS-only. |
| `api_key` | string | — | **yes** | OPNsense API username (HTTP Basic Auth `user`). Generated in **System → Access → Users → API keys**. |
| `api_secret` | string | — | **yes** | OPNsense API password (HTTP Basic Auth `pass`). Same `.ini` as `api_key`. |
| `tls_verify` | bool | `true` | no | Verify the firewall's TLS certificate. Set `false` for stock self-signed lab setups. |
| `alias_name` | string | — | **yes** | Name of the pre-declared alias in **Firewall → Aliases**. Type must be `Host`, `Network`, or `External` — `alias_util` rejects other types with HTTP 422. |
| `ttl` | duration | — | **yes** | Ban lifetime. Must be `> 0` — the plugin owns expiry tracking and does not support permanent bans. |
| `min_level` | string | `"THREAT"` | no | Minimum event level to act on: `INFO`, `WARN`, or `THREAT`. |
| `dedup_window` | duration | `0` (disabled) | no | Skip re-banning an IP within this window after a successful add. |

### No `batch_size` / `flush_interval` — by design

Unlike the OpenWrt executor, the OPNsense `Config` does **not** expose
`batch_size` or `flush_interval`. The architectural model is
mikrotik-style: every accepted event becomes one independent
`alias_util/add` call right away, and every expired IP becomes one
independent `alias_util/delete` call on the next sweep.
`alias_util/add` updates the underlying `pfctl` table per-call — there
is no expensive filter/apply to amortize, so a batching buffer would
add latency and complexity without a corresponding firewall benefit.
The sweep cadence is derived from `ttl / 4` (with a `15m` floor)
inside the executor and is intentionally not exposed as a config field
either.

### Validation Rules

- `host`, `api_key`, `api_secret`, and `alias_name` are mandatory —
  missing values cause a startup error.
- `ttl` is **mandatory and must be `> 0`**. The plugin does not support
  permanent bans: a `ttl` of `0` is rejected at startup. The reasoning
  is the same as the OpenWrt executor: the plugin owns expiry tracking
  through an active sweep, and a zero or negative TTL would make the
  sweep unusable.
- `min_level` must be one of `INFO`, `WARN`, `THREAT`. Any other value
  is rejected at startup.
- `scheme` must be `"http"` or `"https"`. Anything else is rejected.
- Duration fields (`ttl`, `dedup_window`) are parsed by
  `time.ParseDuration` from string, or interpreted as integer seconds
  when a numeric value is supplied.
- `dedup_window = 0` is a valid configuration: deduplication falls back
  to the in-list (`banned` map) check only. A positive value adds a
  recent-ban suppression layer on top.

## REST API Mapping

| Config Field | REST Endpoint | Direction | Notes |
|--------------|---------------|-----------|-------|
| `host` + `port` + `scheme` | Base URL | `→` | `https://{host}:{port}/api/firewall/alias_util/...` |
| `api_key` + `api_secret` | `Authorization: Basic <base64(key:secret)>` | `→` | No session token is negotiated — every request is a fresh Basic Auth challenge |
| `alias_name` | URL path segment `{alias_name}` | `→` | The plugin addresses the alias by name; the name is escaped via `url.PathEscape` before being placed in the path |
| `tls_verify` | `tls.Config.InsecureSkipVerify` | internal | When `false`, the Go HTTP transport skips certificate validation against the system trust store |
| `ttl` | Local sweep tracker | internal | Not pushed to the firewall — the plugin owns expiry; the `pfctl` table holds entries with no native timeout |
| `dedup_window` | `dedup.Window` | internal | Suppresses redundant `alias_util/add` calls for the same IP within the configured window after a successful add |
| — | `POST /api/firewall/alias_util/add/{alias_name}` | `→` | Body `{"address":"<ip>"}`, response `{"result":"saved"}` or `{"result":"ok"}` on success — the client accepts either |
| — | `POST /api/firewall/alias_util/delete/{alias_name}` | `→` | Body `{"address":"<ip>"}`, response `{"result":"saved"}` or `{"result":"ok"}` on success — the client accepts either |
| — | `GET /api/firewall/alias_util/list/{alias_name}` | `→` | Returns the current set of addresses; payload shape is `{"rows": [...], "content": "1.2.3.4\n5.6.7.8\n..."}` — the client prefers `rows` when non-empty, falls back to splitting `content` on `\n` |

### Request Envelope

Every firewall-side operation is an HTTP request against the OPNsense
REST API. The client sends `Content-Type: application/json` on
mutating calls. HTTP timeout is
fixed at `30s` per call — long enough for the small JSON payloads
`alias_util` produces, short enough to surface a stuck firewall
promptly through context cancellation. Any non-2xx response is treated
as a hard error: the executor logs the status code and the response
body (truncated to 512 bytes), increments the `errors` counter, and
does **not** mutate the local `banned` map or the dedup window — the
next event for the same IP will retry the add. This is the
"flaky-safe" property that keeps the executor from poisoning local
state during a transient OPNsense outage.

### Run Loop (one add per event, one delete per expired IP)

The executor issues **independent** point calls — there is no batching
buffer, no flush ticker, no filter/apply step to amortize:

1. **syncExisting.** A single `GET /api/firewall/alias_util/list/{name}`
   loads the pre-existing addresses into the local `banned` map with
   the conservative TTL assumption (`expireAt = now + cfg.ttl` for
   every pre-existing entry). Network errors are non-fatal: the
   executor proceeds with an empty map and a warning is logged.
2. **Point add.** An event that survives filtering is applied
   **immediately** through a single `alias_util/add` REST call with
   body `{"address":"<ip>"}`. The call updates the underlying `pfctl`
   table on the firewall right away.
3. **Sweep.** A periodic timer fires every `ttl / 4` (with a hard
   floor of `15m`). The sweep walks the `banned` map under the
   executor lock, collects the expired IPs, releases the lock, and
   issues an independent `alias_util/delete` call for every expired
   IP.

There is no equivalent of OpenWrt's `uci.commit` + `rc.init reload`
cycle, no `filter/apply` step, and no final flush on shutdown — the
executor holds no pending buffer, so cancellation is a clean immediate
return.

## Compatible Versions

- **Supported baseline:** OPNsense 24.x / 25.x with the default `pf`
  packet filter and the built-in REST API.
- **Required core component:** the `api/firewall/alias_util`
  controller (ships with the default OPNsense install — no plugin
  install required).
- **Architecture:** FreeBSD (OPNsense's base).

### Why No `filter/apply` Step

The `filter/apply` endpoint is part of a separate savepoint / rollback
mechanism for firewall *rules*, not aliases. `alias_util/add` and
`alias_util/delete` operate directly on the `pfctl` table and apply
the change per-call — there is no expensive reload to amortize, so the
executor issues independent point calls per event rather than
batching them behind a filter reload.

### Alias Type Restriction

The OPNsense `alias_util` controller accepts only aliases of type
`Host`, `Network`, or `External`. Other alias types (`URL Table (IPs)`,
`Port`, `GeoIP`, `URL`, `MAC`, …) return HTTP 422 on every operation.
The plugin does not create or modify the alias itself — that
responsibility lives with the operator's UI configuration.

## Hardening: Minimal API ACL Scope

The default OPNsense ACL grants every account that can log in to the
web UI access to the alias controller. No ACL file is required for
the standard user. If the device has been hardened and the default
ACLs have been stripped, the API user only needs access to the
`Firewall → Alias` endpoints. Verify by checking that the matching
ACL under
`/usr/local/opnsense/mvc/app/library/OPNsense/Firewall/` is intact, or
extend the ACL to grant the user access to the alias controller. On a
default install, a freshly created user with the "API access"
checkbox enabled is sufficient — 403 on a default install indicates
the "API access" checkbox has been left unchecked on the user.

A dedicated service account is recommended for production; `root` is
acceptable for lab setups but discouraged in production. The user is
not required to be a member of the `admins` group *per se*, only to be
granted access to the alias endpoints through the API ACL.

## OPNsense Prerequisites

The executor depends on a small set of firewall-side conditions. None
of them require building software; they are configuration steps the
operator performs on the device.

### 1. A user-declared alias of type `Host`, `Network`, or `External`

The plugin does **not** create the alias — that responsibility lives
with the operator's UI configuration, exactly like every other alias
on the device. Create the alias in **Firewall → Aliases** before
starting the plugin:

- Click **+ Add** in the top-right of the Aliases page.
- Set **Name** to the value the plugin will use in its `alias_name`
  config field (e.g. `arxsentinel_blocklist`).
- Set **Type** to one of `Host`, `Network`, or `External`.
- Leave the **Content** empty (or seed a single placeholder); the
  plugin manages the entries from this point on.
- Save and **Apply** the change so the alias lands in
  `pfctl` / the running config.

The OPNsense UI requires a manual **Apply** after creating or
modifying an alias before the REST API can see it; an unapplied alias
is a common source of 404s on a freshly created entry.

> **Persistence caveat (External type only).** Aliases of type
> `External` are *non-persistent*: changes made through `alias_util`
> (add / delete) do **not** survive a router reload or reboot — the
> alias content is reset to whatever is stored in the XML config on
> next boot. Aliases of type `Host` and `Network` are persistent; the
> plugin's bans survive a reboot and will be re-claimed by the next
> `syncExisting`. If the firewall is expected to be reloaded often
> (firmware updates, scheduled config reverts) and bans must survive
> across reloads, prefer `Host` or `Network` over `External`.

### 2. An API key with read/write access to the alias endpoints

The plugin authenticates with **HTTP Basic Auth** (the OPNsense REST
API does not use sessions; every request is a fresh Basic Auth
challenge). The key is generated once in the OPNsense UI:

- Navigate to **System → Access → Users**.
- Click the user that will own the API credentials (a dedicated
  service account is recommended; `root` is fine for lab setups but
  discouraged in production).
- Scroll down to the **API keys** section.
- Click **+ Add** to generate a new key.
- **Download the `.ini` file** OPNsense offers immediately after
  creation — the file contains the `key` and `secret` values and is
  shown **only once**. The plugin consumes these two values verbatim
  (`api_key` = the `key` field, `api_secret` = the `secret` field).
- The user must have access to the `Firewall → Alias` API endpoints.
  On a default ACL this is granted automatically; on a hardened
  install, verify the matching ACL file in
  `/usr/local/opnsense/mvc/app/library/OPNsense/Firewall/` is intact
  or extend the ACL to grant the user access to the alias controller.

### 3. A firewall rule referencing the alias

`alias_util` only manages the alias content; it does **not** create or
modify firewall rules. In **Firewall → Rules**, add a rule
(block / reject) on the appropriate interface with **Source** set to
the alias name (OPNsense renders aliases as a selectable alias in the
rule's source dropdown). The plugin does not manage rules, only alias
entries.

## TLS Recommendations

- **Production:** set `tls_verify: true` (the default). The Go HTTP
  client validates the firewall's certificate against the system trust
  store. Either install the OPNsense CA into the agent's trust store,
  or replace the self-signed certificate with one issued by a public
  CA (e.g. via Let's Encrypt DNS-01 ACME on a routable OPNsense host).
- **Lab / development:** OPNsense ships with a **self-signed
  certificate by default**. Set `tls_verify: false` — the Go HTTP
  client is configured with `InsecureSkipVerify: true` and accepts
  the self-signed certificate. The risk of man-in-the-middle
  interception is acceptable in a lab network and the friction of
  installing the self-signed CA in the agent's trust store is
  avoided.

The plugin does not have its own `ca_file` knob. The default Go HTTP
transport validates certificates against the system trust store. For a
private-CA setup, mount the CA into the agent's container and use the
standard `SSL_CERT_FILE` / `SSL_CERT_DIR` environment variables. The
CA can be exported from **System → Trust → Authorities**.

## System Requirements

The OPNsense executor is **always** an external deployment: the agent
runs on a separate host and reaches the firewall over the network.
There is no embedded-container recipe for OPNsense, in contrast to the
MikroTik `device-mode-container` deployment.

| Component | Requirement |
|-----------|-------------|
| Agent host | Any Linux host with network reachability to the firewall's REST API (VPS, dedicated server, or a host on the same network as the firewall). |
| Firewall CPU | Unaffected — the executor issues at most a handful of `alias_util` calls per event; no measurable load. |
| Firewall RAM | Unaffected — the executor owns no firewall-side state beyond the alias itself. |
| Architecture | None — the agent does not run on the firewall. |
| Firewall firmware | OPNsense 24.x / 25.x with the default `pf` packet filter. |

## Timeout / Duration Format

Duration fields (`ttl`, `dedup_window`) are parsed by
`time.ParseDuration` from string, or interpreted as integer seconds
when a numeric value is supplied:

| Config Value | Parsed As | Effect |
|--------------|-----------|--------|
| `"24h"` | `24 * time.Hour` | 1-day ban |
| `"30m"` | `30 * time.Minute` | 30-minute ban |
| `"7d"` | — | **Rejected** — `time.ParseDuration` does not understand `d` (days) |
| `"1h30m"` | `90 * time.Minute` | 90-minute ban |
| `3600` (int) | `3600 * time.Second` | 1-hour ban |
| `0` (int) | `0` | Rejected at startup for `ttl` (must be `> 0`); `0` for `dedup_window` is valid and disables dedup |

Standard Go `time.ParseDuration` syntax is supported: `ns`, `us`/`µs`,
`ms`, `s`, `m`, `h`. For ban lifetimes longer than a day, use the hour
unit (e.g. `"168h"` for one week) — there is no day literal.

The sweep interval is calculated as `ttl / 4` with a hard minimum of
15 minutes — matching the OpenWrt and MikroTik executors — so a very
short TTL does not produce a wasteful sub-second sweep ticker.
