# OpenWrt Executor Reference

## Config Fields

| Field | Type | Default | Required | Description |
|-------|------|---------|----------|-------------|
| `host` | string | — | **yes** | Router hostname or IP. Resolved by the standard Go HTTP client. |
| `port` | int | `80` | no | Port of `uhttpd-mod-ubus`. |
| `scheme` | string | `"http"` | no | `"http"` or `"https"`. Most stock images serve `/ubus` over plain HTTP. |
| `username` | string | — | **yes** | rpcd user with `write` access to the `firewall` UCI config. |
| `password` | string | — | **yes** | rpcd password. Sent on every `session.login` call. |
| `ipset_name` | string | — | **yes** | UCI **section identifier** of the ipset (`firewall.<ipset_name>=ipset`) — a named section, not an anonymous `@ipset[N]`. |
| `ttl` | duration | — | **yes** | Ban lifetime. Must be `> 0` — the plugin owns expiry tracking and does not support permanent bans. |
| `session_timeout` | duration | `"5m"` | no | Lifetime of an `ubus_rpc_session` token. Re-login is triggered before this elapses. |
| `batch_size` | int | `10` | no | Maximum events bundled into a single flush window. |
| `flush_interval` | duration | `"30s"` | no | Maximum time to wait before flushing a partial batch. |
| `min_level` | string | `"THREAT"` | no | Minimum event level to act on: `INFO`, `WARN`, or `THREAT`. |
| `dedup_window` | duration | `0` (disabled) | no | Skip re-banning an IP within this window after a successful add. |

### Validation Rules

- `host`, `username`, `password`, `ipset_name`, and `ttl` are mandatory —
  missing values cause a startup error.
- `ttl` is **mandatory and must be `> 0`**. The plugin does not support
  permanent bans: a `ttl` of `0` is rejected at startup. The reason is the
  batched sweep model — with native nftables timeouts the plugin would
  have to rely on per-entry counters that `fw4` resets on every reload,
  and the local sweep tracker requires a finite TTL to evict anything.
- `min_level` must be one of `INFO`, `WARN`, `THREAT`. Any other value
  is rejected at startup.
- `scheme` must be `"http"` or `"https"`. Anything else is rejected.
- `session_timeout` must be `> 0`. The default (5m) is the stock
  `uhttpd-mod-ubus` value and is fine for almost every deployment.

## ubus / UCI API Mapping

| Config Field | ubus Object / Method | Direction | Notes |
|--------------|----------------------|-----------|-------|
| `host` + `port` + `scheme` | Base URL | `→` | `POST {scheme}://{host}:{port}/ubus` |
| `username` + `password` | `session.login` | `→` | Authenticated with the canonical null session ID `000…0000` (32 zeros); response carries `ubus_rpc_session` |
| `ipset_name` | `uci.add_list` / `uci.del_list` / `uci.get` (config: `firewall`, section: `<ipset_name>`) | `→` | The plugin addresses the section by its UCI identifier; an anonymous section (`@ipset[N]`) is not reachable by name |
| `ttl` | Local sweep tracker | internal | Not pushed to the router — the plugin owns expiry; `fw4` reloads reset per-entry counters |
| `session_timeout` | `ubus_rpc_session` lifetime | `→` | The client re-logs in transparently before the cached token is older than the configured lifetime |
| `batch_size` + `flush_interval` | `uci.add_list` / `uci.del_list` | `→` | One `add_list` per flush with the full batch of pending IPs; one `del_list` per sweep with the expired IPs |
| — | `uci.commit` (config: `firewall`) | `→` | Single commit per flush cycle |
| — | `rc.init` (`{name: "firewall", action: "reload"}`) | `→` | Single `firewall` reload per flush cycle; skipped when both add and del lists are empty |

### ubus JSON-RPC Envelope

Every router-side operation is a `POST /ubus` with a JSON-RPC 2.0 envelope
of the form:

```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "method": "call",
  "params": ["<session_id>", "<object>", "<method>", { ... }]
}
```

The `result` payload of a successful call is a 2-element JSON array
`[code, data]`. The client asserts `code == 0` and surfaces `data` to the
caller.

### Flush Cycle (one add, one del, one commit, one reload)

Every cycle — whether triggered by events, time, or sweep — collapses to
the **same** UCI transaction:

1. A single `uci.add_list` call with the full batch of pending-to-add IPs
   (`values: [...]`).
2. A single `uci.del_list` call with the full batch of locally-expired IPs
   (only emitted when the sweep trigger brought any).
3. A single `uci.commit` for the `firewall` config.
4. A single `rc.init` reload.

A reload is skipped entirely when both the add list and the del list are
empty — a sweep tick on an idle system produces no router traffic at all.

## Compatible Versions

- **Supported baseline:** OpenWrt 22.03+ with the `fw4` firewall
  (nftables-based).
- **Required core packages:** `uhttpd` + `uhttpd-mod-ubus`, `rpcd` with
  the default `uci` and `rc` core plugins.

### Why Not `luci2.firewall`

The `luci2.firewall` ubus object — `add_ipset_entry`,
`delete_ipset_entry`, `get_ipsets` — does **not exist** in current
OpenWrt releases:

- A code search across `openwrt/luci` for `add_ipset_entry` returns
  zero matches.
- The `firewall4` package ships no rpcd plugin named `luci2`.
- The "LuCI2" project is archived; the relevant wiki page lives on
  `oldwiki.archive` and is not part of the supported stack.

The plugin therefore drives the canonical `uci` + `rc` path exposed by
the stock `rpcd` core plugins. The `luci2.firewall` shortcut sometimes
referenced in older write-ups is not available on a current `fw4` build.

## Hardening: Minimal rpcd ACL Scope

The default rpcd ACL shipped with `rpcd` grants `root` and `admin`
sessions access to the core `uci` and `rc` objects — no ACL file is
required for the standard admin credentials. If you have hardened the
device and stripped the default ACLs, the plugin's user only needs access
to the `uci` and `rc` core objects. Verify with:

```sh
ls /usr/share/rpcd/acl.d/
cat /usr/share/rpcd/acl.d/*.json | grep -E 'uci|"rc"'
```

The minimum ACL file (`/usr/share/rpcd/acl.d/arxsentinel.json`) that
grants a dedicated user access to the core objects the plugin uses:

```json
{
  "acls": {
    "access-group": {
      "uci": [ "read", "write" ],
      "rc":  [ "exec" ]
    }
  },
  "users": {
    "arxsentinel": {
      "acls": [ "access-group" ]
    }
  }
}
```

`access-group` here is an arbitrary ACL name; the only requirement is
that it grants `read` + `write` to `uci` and `exec` to `rc`, and that
the `arxsentinel` user is bound to it. The plugin does not call any
other rpcd object — every other ACL can be omitted or stripped.

## OpenWrt Prerequisites

The executor depends on a small set of router-side conditions. None of
them require building software; they are configuration steps the
operator performs on the device.

### 1. `uhttpd-mod-ubus`

The base `uhttpd` build that ships with most OpenWrt images does **not**
include the ubus bridge. If `POST /ubus` returns 404 on the configured
port, install the module on the router:

```sh
opkg update
opkg install uhttpd-mod-ubus
/etc/init.d/uhttpd restart
```

The module is the same one LuCI uses; the install path is the one
documented by the OpenWrt project.

### 2. `rpcd` core plugins `uci` and `rc`

The plugin drives firewall state through the standard rpcd core objects
(`uci` for the config store, `rc` for service lifecycle). These plugins
ship with the default `rpcd` package and are enabled out of the box
for any session authenticated as the router's `root` user. Verify with:

```sh
ubus list | grep -E '^(uci|rc|session)$'
```

If `uci` or `rc` is missing, install `rpcd` (and on hardened builds,
ensure the matching ACLs are not stripped from `/usr/share/rpcd/acl.d/`).

### 3. A user-declared UCI ipset section

The plugin does **not** create the ipset — that responsibility lives
with the operator's UCI config, exactly like every other ipset rule on
the device. The minimum block looks like:

```sh
# NAMED section (firewall.arxsentinel_blocklist=ipset) — required.
# The plugin's uci.add_list/del_list/get calls address the section by
# this identifier directly ("section": ipset_name). An anonymous
# section (uci add firewall ipset, addressed internally as @ipset[N])
# would NOT be reachable by name and every add_list call would fail
# with "not found".
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

The section identifier used here (`arxsentinel_blocklist`) is the value
you put into the plugin's `ipset_name` config field — it must match the
UCI **section name**, not merely the ipset's `option name` value (they
happen to be the same string in this example, which is the recommended
convention, but only the section identifier is what `uci.add_list` /
`uci.del_list` / `uci.get` actually address).

The exact `option match` and `option family` keywords accepted by `fw4`
are confirmed by the fw4 reference docs (`src_ip`, `src_net`, `dst_ip`,
`dst_net`); the required-versus-optional status of `option family`
(`ipv4` / `ipv6`) is family-agnostic at the plugin level — the plugin
passes the IP through verbatim.

### 4. rpcd ACL for the `uci` and `rc` objects

The default ACL shipped with `rpcd` grants `root` and `admin` sessions
access to the core objects. No ACL file is required for the standard
admin credentials. If you have hardened the device and stripped the
default ACLs, see [Hardening: Minimal rpcd ACL Scope](#hardening-minimal-rpcd-acl-scope).

## TLS Recommendations

- **Production:** If the router's `/ubus` is fronted by a TLS reverse
  proxy (typical when LuCI is exposed over HTTPS), set
  `scheme: "https"` and a non-default `port` (e.g. `443`).
- **Default install:** Most stock images serve `/ubus` over plain HTTP
  on port 80. The default `scheme: "http"` is appropriate for that
  setup; do not enable HTTPS at the ubus layer without a corresponding
  proxy.

The plugin does not have its own `ca_file` knob. The default Go HTTP
transport validates certificates against the system trust store. For a
private-CA setup, mount the CA into the agent's container and use the
standard `SSL_CERT_FILE` / `SSL_CERT_DIR` environment variables.

## System Requirements

The OpenWrt executor is **always** an external deployment: the agent
runs on a separate host and reaches the router over the network. There
is no embedded-container recipe for OpenWrt, in contrast to the MikroTik
`device-mode-container` deployment.

| Component | Requirement |
|-----------|-------------|
| Agent host | Any Linux host with network reachability to the router's ubus endpoint (VPS, dedicated server, or a second device on the LAN). |
| Router CPU | Unaffected — the executor issues at most a handful of ubus calls per flush cycle; no measurable load. |
| Router RAM | Unaffected — the executor owns no router-side state. |
| Architecture | None — the agent does not run on the router. |
| Router firmware | OpenWrt 22.03+ with `fw4` (nftables). |

## Timeout / Duration Format

Duration fields (`ttl`, `session_timeout`, `flush_interval`,
`dedup_window`) are parsed by `time.ParseDuration` from string, or
interpreted as integer seconds when a numeric value is supplied:

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
15 minutes — matching the MikroTik executor — so a very short TTL does
not produce a wasteful sub-second sweep ticker.
