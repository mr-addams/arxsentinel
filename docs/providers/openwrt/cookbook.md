# OpenWrt Executor Cookbook

## Recipe 1: Basic Setup

ArxSentinel runs on a separate host and pushes the IP block list to an
OpenWrt router over the **ubus** JSON-RPC endpoint exposed by
`uhttpd-mod-ubus`. Bans land in a user-declared UCI ipset section, and a
matching firewall rule drops matching traffic at the router.

### Minimal Configuration

```yaml
executors:
  - name: openwrt-blocklist
    type: openwrt
    sources:
      - name: sentinel-owrt
    config:
      host: "192.168.1.1"
      username: "root"
      password: "${OPENWRT_PASSWORD}"
      ipset_name: "arxsentinel_blocklist"
      ttl: "24h"
```

`port`, `scheme`, `session_timeout`, `batch_size`, `flush_interval`,
and `min_level` all fall back to their defaults. The default `scheme`
is `"http"` and the default `port` is `80`, which matches a stock
`uhttpd` install.

### Router Prerequisites

#### 1. Install `uhttpd-mod-ubus`

The base `uhttpd` build that ships with most OpenWrt images does **not**
include the ubus bridge. Install it on the router:

```sh
opkg update
opkg install uhttpd-mod-ubus
/etc/init.d/uhttpd restart
```

#### 2. Declare a named UCI ipset and a matching firewall rule

The plugin does **not** create the ipset — that responsibility lives
with the operator's UCI config. The section must be **named** (not
anonymous `@ipset[N]`), because the plugin's `uci.add_list` /
`uci.del_list` / `uci.get` calls address the section by its UCI
identifier.

```sh
# Named section — required. The plugin addresses the section by
# this identifier directly. An anonymous @ipset[N] is not reachable
# by name and every add_list call would fail with "not found".
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

The section identifier (`arxsentinel_blocklist`) is the value you put
into the plugin's `ipset_name` config field — it must match the UCI
**section name**, not merely the ipset's `option name` value (they
happen to be the same string in this example, which is the recommended
convention).

#### 3. Verify `rpcd` exposes the `uci` and `rc` core objects

```sh
ubus list | grep -E '^(uci|rc|session)$'
```

The default ACL shipped with `rpcd` grants `root` and `admin` sessions
access to the core objects. No ACL file is required for the standard
admin credentials. If you have hardened the device and stripped the
default ACLs, see [reference.md — Hardening: Minimal rpcd ACL
Scope](reference.md#hardening-minimal-rpcd-acl-scope).

### Verification

#### Sanity-check the ubus endpoint

```sh
curl -X POST http://192.168.1.1/ubus -d '{}'
```

Expected: a JSON-RPC parse error, **not** a 404. A 404 here means
`uhttpd-mod-ubus` is not installed — go back to step 1.

#### Confirm the ipset is reachable by name

```sh
uci show firewall | grep ipset
```

You should see a section like
`firewall.arxsentinel_blocklist=ipset`. If the section is named
differently, fix the section name on the router or update `ipset_name`
in the plugin config to match.

#### Confirm the firewall rule references the ipset

```sh
uci show firewall | grep -E 'ipset|target'
```

You should see the `drop_blocklist` rule with
`ipset='arxsentinel_blocklist'` and `target='DROP'`. If the rule is
missing, the plugin will populate the ipset but traffic will not be
dropped — see Recipe 2, item 4.

#### Confirm a ban lands in the ipset after the agent starts

After the agent has been running for one `flush_interval` (default 30s)
and at least one `THREAT`-level event has flowed through, list the
section entries:

```sh
uci show firewall.arxsentinel_blocklist
```

The `entry=` lines should include the IP of the simulated threat.

---

## Recipe 2: Troubleshooting

Most "my bans are not taking effect" reports trace back to one of the
following root causes. Walk them in order.

### 1. `POST /ubus` returns 404

`uhttpd-mod-ubus` is not installed. Install it on the router:

```sh
opkg update && opkg install uhttpd-mod-ubus
/etc/init.d/uhttpd restart
```

Verify with `curl -X POST http://<host>/ubus -d '{}'` — the response
should be a JSON-RPC parse error, not a 404.

### 2. `session.login` returns a non-zero ubus code

The configured credentials do not match a user with access to the
`uci` and `rc` core objects. The default ACL
(`/usr/share/rpcd/acl.d/`) grants `root` and `admin` sessions full
access. If you have hardened the device, check that the matching ACL
file is intact:

```sh
ls /usr/share/rpcd/acl.d/
cat /usr/share/rpcd/acl.d/*.json | grep -E 'uci|"rc"'
```

If the ACL was stripped, restore the defaults or write a custom ACL
that grants the plugin's user access to `uci` and `rc`. The
[reference.md — Hardening: Minimal rpcd ACL
Scope](reference.md#hardening-minimal-rpcd-acl-scope) section shows the
minimum ACL file that satisfies the plugin.

### 3. `uci.get` returns empty / `uci.commit` returns non-zero

The ipset section does not exist or has the wrong name. The plugin's
`ipset_name` config field must match the **UCI section name** (not the
`option name` value), i.e. the identifier in
`firewall.<section_name>`. Verify with:

```sh
uci show firewall | grep ipset
```

You should see a section like
`firewall.arxsentinel_blocklist=ipset`. If the section is named
differently, fix the section name on the router or update `ipset_name`
in the plugin config to match.

Note: anonymous sections created with `uci add firewall ipset` (and
addressed internally as `@ipset[N]`) are **not** reachable by name —
every `add_list` call against one will fail with "not found". Use a
**named** section.

### 4. Bans appear in UCI but traffic is not dropped

The `firewall` UCI config has no rule referencing the ipset. Add one
and reload firewall:

```sh
uci set firewall.drop_blocklist=rule
uci set firewall.drop_blocklist.name='Drop-blocklist'
uci set firewall.drop_blocklist.src='wan'
uci set firewall.drop_blocklist.dest='*'
uci set firewall.drop_blocklist.ipset='arxsentinel_blocklist'
uci set firewall.drop_blocklist.target='DROP'
uci commit firewall
/etc/init.d/firewall reload
```

The plugin does not manage firewall rules — only ipset entries. The
rule is a router-side prerequisite; see Recipe 1 step 2 for the full
initial declaration.

### 5. Bans appear and disappear too fast / too slowly

The plugin's `ttl` is the source of truth for entry lifetime, **not**
the nftables native timeout. The local `banned` map is what drives
sweep, and it is reloaded conservatively on restart: every pre-existing
entry receives `expireAt = now + cfg.ttl` (a fresh TTL window) — see
[reference.md — ubus / UCI API Mapping](reference.md#ubus--uci-api-mapping)
and the underlying `syncExisting` behaviour in the plugin README.

If the configured `ttl` is `30s` but the sweep interval is the `15m`
floor, an entry will be in the ipset for at least one sweep cycle.
This is intentional: a `30s` TTL would otherwise yield a
`7.5s` sweep ticker, which is wasteful, so the floor kicks in.

A long-lived daemon restart therefore effectively **extends** bans by
up to one TTL — every pre-existing entry is granted a fresh TTL window
on reload. This is acceptable for a WAF use case (false negatives on
unbanning are far less harmful than missing a ban) and is the same
trade-off the MikroTik executor makes.

### 6. The log fills with "session expired" messages

The router's `uhttpd` was rebuilt with a custom session timeout
shorter than the plugin's `session_timeout`. The plugin re-logs in
transparently before the cached token is older than the configured
lifetime, so these messages indicate the re-login cadence is racing
the server's expiry. Either:

- lengthen the plugin's `session_timeout` (default `5m`) to match the
  server's lifetime, or
- shorten the server's session lifetime so the re-login cadence
  matches expectations.

### Common Errors

| Error | Likely Cause | Fix |
|-------|--------------|-----|
| `POST /ubus` returns 404 | `uhttpd-mod-ubus` not installed | `opkg install uhttpd-mod-ubus && /etc/init.d/uhttpd restart` |
| `session.login` non-zero ubus code | Wrong credentials, or `uci` / `rc` ACL stripped | Verify user; check `/usr/share/rpcd/acl.d/*.json` for `uci` and `rc` entries |
| `uci.get` returns empty / `add_list` "not found" | `ipset_name` does not match a named UCI section | Use a named section (`firewall.<name>=ipset`), not `@ipset[N]`; update `ipset_name` to match |
| Bans in UCI but no traffic drop | No firewall rule referencing the ipset | Add a `rule` section with `ipset='<ipset_name>'` and `target='DROP'`; `uci commit firewall && /etc/init.d/firewall reload` |
| TLS handshake error with `scheme: "https"` | Private-CA cert not trusted by the agent host | Mount the CA into the agent container; set `SSL_CERT_FILE` / `SSL_CERT_DIR` (the plugin has no `ca_file` knob) |
| Repeated "session expired" log lines | `session_timeout` longer than the server's session lifetime | Match `session_timeout` to the server, or shorten the server's session lifetime |
