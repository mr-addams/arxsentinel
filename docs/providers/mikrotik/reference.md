# MikroTik Executor Reference

## Config Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `host` | string | — | RouterOS hostname or IP address (required) |
| `port` | int | `443` | REST API port |
| `username` | string | — | RouterOS username (required) |
| `password` | string | — | RouterOS password (required) |
| `list_name` | string | `"arxsentinel_blocklist"` | Address-list name to manage |
| `ttl` | duration | `24h` | Ban TTL — RouterOS timeout format string (e.g. `"24h"`, `"7d"`) or seconds as int |
| `sentinel_id` | string | — | Unique identifier for this executor instance — used as address-list comment prefix (required) |
| `tls_verify` | bool | `true` | Verify RouterOS TLS certificate |
| `batch_size` | int | `10` | Max events per flush batch |
| `flush_interval` | duration | `"30s"` | Periodic flush interval — RouterOS timeout string or seconds as int |
| `min_level` | string | `"THREAT"` | Minimum event level to act on: `INFO`, `WARN`, or `THREAT` |

## RouterOS API Mapping

| Config Field | RouterOS API Field | Direction | Notes |
|-------------|-------------------|-----------|-------|
| `host` + `port` | Base URL | `→` | `https://{host}:{port}/rest` |
| `username` | Basic auth user | `→` | HTTP Basic Authentication |
| `password` | Basic auth password | `→` | HTTP Basic Authentication |
| `list_name` | `list` | `→` | `PUT /ip/firewall/address-list` body field |
| `ttl` | `timeout` | `→` | Converted by `durationToRouterOS()`. Empty string → permanent |
| `sentinel_id` | `comment` | `→` | Prefixed as `sentinel-{sentinel_id}` |
| `tls_verify` | TLS config | `→` | `InsecureSkipVerify = !tls_verify` |
| — | `.id` | `←` | Returned by RouterOS on PUT, used for DELETE operations |

### API Endpoints

| Operation | HTTP Method | Path |
|-----------|-------------|------|
| Add entry | `PUT` | `/rest/ip/firewall/address-list` |
| List entries | `GET` | `/rest/ip/firewall/address-list?list={list_name}` |
| Delete entry | `DELETE` | `/rest/ip/firewall/address-list/{.id}` |

## Compatible Versions

- **Supported baseline:** RouterOS v7.18.2+
- **Tested versions:** v7.18.2, v7.20.8, v7.21.4

### Breaking Change: PUT vs /add

RouterOS v7.20.8+ removed the `/add` suffixed endpoint for address-list.
ArxSentinel uses `PUT /rest/ip/firewall/address-list` which works across all
supported versions (7.18.2 through 7.21.4+).

If you are integrating with scripts written for older RouterOS versions, note
that `POST /rest/ip/firewall/address-list/add` is **no longer available** on v7.20.8+.

## Hardening: Minimal RouterOS User Rights

Create a dedicated user for ArxSentinel with minimal required permissions:

```
/user/add name=arxsentinel group=arxsentinel password="..."
/user/group/add name=arxsentinel policy=read,write,api,rest-api
```

Required policies: `read`, `write`, `api`, `rest-api`.

Omit `ssh`, `ftp`, `telnet`, `local`, `reboot`, `dude`, `policy`, `test`, `web`,
`sensitive`, `winbox`. None of these are required for REST API address-list operations.

## SSL/TLS Recommendations

- **Production:** Keep `tls_verify: true`. Use a valid certificate on RouterOS
  (e.g. Let's Encrypt via `/certificate/add`) or a properly self-signed cert
  that is trusted by the ArxSentinel host.
- **Testing/CHR:** Set `tls_verify: false` only for self-signed certificates on
  CHR test instances. Never disable verification in production.

RouterOS certificate setup:

```
/certificate/add name=rest-api-cn common-name=router.example.com days=3650 key-usage=tls-server
/certificate/sign rest-api-cn
/ip/service/set rest certificate=rest-api-cn
```

## System Requirements

### Container (embedded on RouterOS)

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| RAM | 256 MB | 512 MB |
| Architecture | arm64, arm/v7 | arm64 |
| Container package | `container` | latest |
| RouterOS mode | `device-mode-container` | — |

### External (VPS / dedicated host)

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| RAM | 128 MB | 256 MB |
| Architecture | amd64 (CHR), arm64 | amd64 |
| OS | Linux (any distro) | Alpine / Debian |

## Timeout Format

The `ttl` field accepts Go `time.Duration` strings or integer seconds:

| Config Value | RouterOS Timeout | Effect |
|-------------|------------------|--------|
| `"24h"` | `1d` | 1 day ban |
| `"90m"` | `1h30m` | 90 minute ban |
| `"7d"` | `7d` | 7 day ban |
| `"1h30m"` | `1h30m` | 90 minute ban |
| `3600` (int) | `1h` | 1 hour ban |
| `0` | `""` (empty) | **Permanent** — never swept |

The conversion in `durationToRouterOS()` outputs only non-zero components
(e.g. `25h` → `1d1h`, not `1d1h0m0s`). A zero duration produces an empty string,
which RouterOS interprets as a permanent entry.

The sweep interval is calculated as `TTL / 4` with a minimum of 15 minutes.
When TTL is zero (permanent), no sweep occurs.