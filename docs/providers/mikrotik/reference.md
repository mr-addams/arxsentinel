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
| `ca_file` | string | `""` | Path to PEM-encoded CA certificate for verifying RouterOS TLS cert. Empty = system trust store. Ignored when `tls_verify: false`. |
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
| `ca_file` | TLS RootCAs pool | `→` | PEM cert loaded and added to x509.CertPool; overrides system trust store |
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

## RouterOS Prerequisites

ArxSentinel uses the **RouterOS REST API**, which runs on the same port as the
web interface (`www` or `www-ssl`). You must enable one of these services before
the executor can connect.

### Enable the service and restrict access

**Production (HTTPS, recommended):**

```
/ip/service/set www-ssl address=<arxsentinel-host-ip>/32
/ip/service/enable www-ssl
```

**Local / testing (HTTP, no certificate required):**

```
/ip/service/set www address=<arxsentinel-host-subnet>
/ip/service/enable www
```

Always set `address=` to restrict the service to the specific IP or subnet where
ArxSentinel runs. Leaving it empty (all addresses) exposes the web interface to the
entire network.

Example for a VPS at `10.99.99.10` on the management network `10.99.99.0/24`:

```
/ip/service/set www-ssl address=10.99.99.0/24
/ip/service/enable www-ssl
```

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
/ip/service/set www-ssl certificate=rest-api-cn
```

### Internal CA / Self-Signed Certificate

When RouterOS uses a certificate from an internal CA or a self-signed cert,
set `ca_file` to avoid disabling verification entirely:

```yaml
config:
  tls_verify: true
  ca_file: "/etc/arxsentinel/ca/mikrotik-ca.crt"   # path inside container
```

Export the CA from RouterOS:
```
/certificate/export-certificate <cert-name> export-passphrase=""
# Downloads <cert-name>.crt — copy to ArxSentinel host
```

**Docker:** mount the CA file as a read-only volume:
```yaml
volumes:
  - /path/to/mikrotik-ca.crt:/etc/arxsentinel/ca/mikrotik-ca.crt:ro
```

**Kubernetes:** store in ConfigMap and mount:
```yaml
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: mikrotik-ca
data:
  mikrotik-ca.crt: |
    -----BEGIN CERTIFICATE-----
    <base64-encoded-cert>
    -----END CERTIFICATE-----
```
```yaml
# deployment volumes:
volumes:
  - name: mikrotik-ca
    configMap:
      name: mikrotik-ca
volumeMounts:
  - name: mikrotik-ca
    mountPath: /etc/arxsentinel/ca
    readOnly: true
```

> When `ca_file` is set and `tls_verify: true`, ArxSentinel uses only the
> provided CA — not the system trust store. Ensure the file contains the full
> certificate chain if intermediate CAs are involved.

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