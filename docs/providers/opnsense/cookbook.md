# OPNsense Executor Cookbook

## Recipe 1: Basic Setup

ArxSentinel runs on a separate host and pushes the IP block list to an
OPNsense firewall over the **REST API** exposed by the PHP
`api/firewall/alias_util` controller. Bans land in a user-declared alias
in **Firewall → Aliases**, and a matching firewall rule drops matching
traffic at the pf packet filter.

### Minimal Configuration

```yaml
executors:
  - name: opnsense-blocklist
    type: opnsense
    sources:
      - name: sentinel-opnsense
    config:
      host: "192.168.1.1"
      api_key: "YOUR_API_KEY"
      api_secret: "YOUR_API_SECRET"
      alias_name: "arxsentinel_blocklist"
      ttl: "24h"
```

`port`, `scheme`, `tls_verify`, and `min_level` all fall back to their
defaults. The default `scheme` is `"https"` and the default `port` is
`443`, which matches a stock OPNsense install. The default `tls_verify`
is `true` — flip it to `false` if the firewall is presenting the stock
self-signed certificate and the agent's trust store does not include
the OPNsense CA.

### Firewall Prerequisites

#### 1. Declare a named alias of a supported type

The plugin does **not** create the alias — that responsibility lives
with the operator's UI configuration. The alias must be of type
`Host`, `Network`, or `External`; other types (`URL Table (IPs)`,
`Port`, `GeoIP`, `URL`, `MAC`, …) are **not supported by
`alias_util`** and will return HTTP 422 on every operation.

In the OPNsense web UI:

1. Navigate to **Firewall → Aliases**.
2. Click **+ Add** in the top-right of the Aliases page.
3. Set **Name** to the value the plugin will use in its `alias_name`
   config field (e.g. `arxsentinel_blocklist`).
4. Set **Type** to one of `Host`, `Network`, or `External`.
5. Leave the **Content** empty (or seed a single placeholder); the
   plugin manages the entries from this point on.
6. Save and **Apply** the change so the alias lands in `pfctl` / the
   running config.

> **Persistence caveat (External type only).** Aliases of type
> `External` are *non-persistent*: changes made through
> `alias_util` (add / delete) do **not** survive a router reload or
> reboot — the alias content is reset to whatever is stored in the
> XML config on next boot. If the firewall is expected to be reloaded
> often (firmware updates, scheduled config reverts) and bans must
> survive across reloads, prefer `Host` or `Network` over `External`.
> See Recipe 2, item 7 for the matching symptom.

#### 2. Generate an API key with access to the alias controller

The plugin authenticates with **HTTP Basic Auth** — every request
sets `Authorization: Basic <base64(api_key:api_secret)>`. No session
token is negotiated; the firewall re-authenticates on every call.

In the OPNsense web UI:

1. Navigate to **System → Access → Users**.
2. Click the user that will own the API credentials (a dedicated
   service account is recommended; `root` is fine for lab setups but
   discouraged in production).
3. Scroll down to the **API keys** section.
4. Click **+ Add** to generate a new key.
5. **Download the `.ini` file** OPNsense offers immediately after
   creation — the file contains the `key` and `secret` values and is
   shown **only once**. The plugin consumes these two values verbatim
   (`api_key` = the `key` field, `api_secret` = the `secret` field).
6. Make sure the user has access to the `Firewall → Alias` API
   endpoints. On a default ACL this is granted automatically; on a
   hardened install, verify the matching ACL file in
   `/usr/local/opnsense/mvc/app/library/OPNsense/Firewall/` is intact
   or extend the ACL to grant the user access to the alias
   controller.

The user is not required to be a member of the `admins` group
*per se*, only to be granted access to the alias endpoints through
the API ACL. Default installs grant this to every account that can
log in to the web UI.

#### 3. Add a firewall rule that references the alias

`alias_util` only manages the alias content; it does **not** create
or modify firewall rules. Without a rule, IPs in the alias will be
listed but matching traffic will not be dropped — see Recipe 2,
item 6 for the matching symptom.

In the OPNsense web UI:

1. Navigate to **Firewall → Rules**.
2. Click **+ Add** on the appropriate interface (typically `WAN`).
3. Set **Action** to **Block** (or **Reject** if you want the sender
   to be told).
4. Set **Source** to **Single host or alias** and pick the alias
   declared in step 1 from the alias dropdown (OPNsense renders
   aliases as a selectable alias in the rule's source dropdown).
5. Save and **Apply** the change.

### Verification

#### Sanity-check the alias is reachable through the REST API

```sh
curl -u "API_KEY:API_SECRET" \
  https://192.168.1.1/api/firewall/alias_util/list/arxsentinel_blocklist
```

Expected: a JSON body with a `content` field (e.g.
`{"rows":[],"content":""}`) on a freshly created alias. A 404 here
means the alias is missing or has not been **Apply**'d yet — go back
to step 1.

#### Sanity-check the firewall rule references the alias

In the OPNsense UI, navigate to **Firewall → Rules** and confirm the
rule on the relevant interface has the alias selected as **Source**.
If the rule is missing, the plugin will populate the alias but
traffic will not be dropped — see Recipe 2, item 6.

#### Confirm a ban lands in the alias after the agent starts

After the agent has been running and at least one `THREAT`-level
event has flowed through, list the alias entries:

```sh
curl -u "API_KEY:API_SECRET" \
  https://192.168.1.1/api/firewall/alias_util/list/arxsentinel_blocklist
```

The `content` field should include the IP of the simulated threat.
Alternatively, in the OPNsense UI, **Firewall → Aliases** shows the
alias' **Content** column updated with the banned IP.

---

## Recipe 2: Troubleshooting

Most "my bans are not taking effect" reports trace back to one of the
following root causes. Walk them in order.

### 1. `alias_util/add` returns HTTP 422

The configured alias is of a type other than `Host`, `Network`, or
`External` (most commonly `URL Table (IPs)` or `Port`). OPNsense's
`alias_util` controller accepts only the three types listed above;
other types return 422 on every operation. Fix the alias in
**Firewall → Aliases** by either re-creating it as `Host` /
`Network` / `External`, or by updating the plugin's `alias_name` to
point at a different alias that has the right type.

### 2. `alias_util/add` returns HTTP 404

The configured `alias_name` does not exist on the firewall. Verify
with:

```sh
curl -u "API_KEY:API_SECRET" \
  https://<host>/api/firewall/alias_util/list/<alias_name>
```

A 404 here means the alias is missing from the OPNsense config — go
to **Firewall → Aliases** and create it (or fix the `alias_name` in
the plugin config to match an alias that already exists). Note that
the OPNsense UI requires a manual **Apply** after creating or
modifying an alias before the REST API can see it; an unapplied
alias is a common source of 404s on a freshly created entry.

### 3. `alias_util/add` returns HTTP 401

The API key / secret are wrong, or the user does not have permission
to access the alias controller. Verify the key / secret by
re-downloading the `.ini` from **System → Access → Users** and
comparing against the plugin config. If the credentials are
correct, the issue is an ACL restriction — see the next item.

### 4. `alias_util/add` returns HTTP 403

The API user is authenticated but lacks access to the firewall
alias endpoints. This is typical of hardened installs where the
user ACL has been stripped. Verify the matching ACL file under
`/usr/local/opnsense/mvc/app/library/OPNsense/Firewall/` is intact,
or extend the ACL to grant the user access to the alias controller.
On a default install, every user that can log in to the web UI has
access — 403 on a default install indicates the user has been
created with the "API access" checkbox unchecked.

### 5. TLS handshake error on the first call

The firewall is presenting the stock self-signed certificate and
`tls_verify` is at its default of `true`. Either flip
`tls_verify: false` for a lab / development setup, or install the
OPNsense CA into the agent's trust store (the CA can be exported
from **System → Trust → Authorities**) and set `SSL_CERT_FILE` /
`SSL_CERT_DIR` to point at it. The plugin has no `ca_file` knob
of its own — production deployments keep `tls_verify: true` and
ship the CA alongside the agent.

### 6. Bans appear in the alias but traffic is not dropped

The OPNsense firewall has no rule referencing the alias. `alias_util`
only manages the alias content; it does not create or modify firewall
rules. In **Firewall → Rules**, add a rule (block / reject) on the
appropriate interface with **Source** set to the alias name (OPNsense
renders aliases as a selectable alias in the rule's source
dropdown). The plugin does not manage rules, only alias entries.

### 7. Bans disappear after a router reboot

The alias is of type `External`. Per the OPNsense design, External
aliases are *non-persistent* across reboots — the content is reset
to whatever is stored in the XML config on next boot. Re-create
the alias as `Host` or `Network` if persistence is required. See
[Recipe 1, step 1](#1-declare-a-named-alias-of-a-supported-type)
for the full caveat.

### Common Errors

| Error | Likely Cause | Fix |
|-------|--------------|-----|
| `alias_util/add` returns HTTP 422 | Alias type is not `Host` / `Network` / `External` | Re-create the alias as one of the supported types, or update `alias_name` to point at a supported alias |
| `alias_util/add` returns HTTP 404 | `alias_name` does not exist on the firewall, or alias has not been **Apply**'d | Create the alias in **Firewall → Aliases** and click **Apply**; or fix `alias_name` to match an existing alias |
| `alias_util/add` returns HTTP 401 | Wrong API key / secret | Re-download the `.ini` from **System → Access → Users** and compare against the plugin config |
| `alias_util/add` returns HTTP 403 | User authenticated but lacks ACL access to the alias controller | Check `/usr/local/opnsense/mvc/app/library/OPNsense/Firewall/` ACL files; on a default install, enable the "API access" checkbox on the user |
| TLS handshake error | Self-signed certificate, `tls_verify: true` | Set `tls_verify: false` for lab setups, or install the OPNsense CA into the agent's trust store and set `SSL_CERT_FILE` / `SSL_CERT_DIR` |
| Bans appear in alias but traffic is not dropped | No firewall rule references the alias | Add a rule in **Firewall → Rules** with **Source** set to the alias name |
| Bans disappear after reboot | Alias type is `External` (non-persistent) | Re-create the alias as `Host` or `Network` |
