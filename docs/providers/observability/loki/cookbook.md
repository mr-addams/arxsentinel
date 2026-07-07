# Loki Sink Cookbook

This cookbook is the **deeper-dive** companion to
`docs/providers/observability/loki/reference.md` (the field-by-field
reference) and the `cookbook/observability/loki-basic.yaml` quick-start
recipe (the minimum working config). Where a recipe here needs a known
field name, the field list comes from `reference.md` — this cookbook does
not invent new knobs. Recipes here go **deeper than the basic recipe**:
multi-tenant Loki with Grafana Cloud Basic Auth, mTLS to a self-hosted
Loki behind a private CA, and a runbook for the most common
misconfigurations.

The authoritative wire-format details (push body shape, header table,
timestamp encoding) are in `reference.md`; the canonical sink-package
behaviour (batching, flush loop, `buildHTTPClient`, formatter injection)
is in arx-core's
[`pkg/sink/loki/README.md`](https://github.com/mr-addams/arx-core). Read
those first if you have not — the recipes below assume the field names
are already familiar.

---

## Recipe 1: Multi-Tenant Loki with Grafana Cloud Basic Auth

A self-hosted Loki deployment with `X-Scope-OrgID` for tenant isolation
**and** HTTP Basic Auth in front of it (Grafana Cloud Loki uses exactly
this pattern: the tenant ID goes in the `X-Scope-OrgID` header, and
Basic Auth credentials are the Loki instance ID + an API key with
`logs:write` scope).

For a single-tenant, no-auth setup start from
[`cookbook/observability/loki-basic.yaml`](../../../cookbook/observability/loki-basic.yaml).
This recipe shows the realistic variant the basic recipe does not cover
— the `loki_tenant_id`, `loki_username`, and `loki_password` fields all
working together.

### Configuration

```yaml
streams:
  - name: main
    inputs:
      - type: file
        path: /var/log/nginx/access.log
        parser: combined
    outputs:
      - type: loki
        loki_url: "https://logs-prod-eu-west.grafana.net"
        loki_labels:
          job: arxsentinel
          env: production
          component: waf
        format: json

        # ── Multi-tenant header (X-Scope-OrgID) ──
        loki_tenant_id: "74236"            # tenant identifier for this Loki org

        # ── HTTP Basic Auth (Grafana Cloud convention) ──
        # In Grafana Cloud: loki_username = instance ID (a number),
        # loki_password = API key with `logs:write` scope.
        # Must be set together — arx-core's parseConfig rejects a
        # half-configured credential pair.
        loki_username: "74236"
        loki_password: "${GRAFANA_CLOUD_LOKI_API_KEY}"

        # ── Batching and compression ──
        loki_batch_size: 200               # lines per push; default 100
        loki_flush_interval: "2s"          # max time between flushes; default "5s"
        loki_gzip: true                    # gzip-encode request bodies
```

### What the wire looks like

The push request has these headers set by the sink (in addition to
`Content-Type: application/json`, always):

| Header | Value | Source |
|--------|-------|--------|
| `X-Scope-OrgID` | `74236` | `loki_tenant_id` |
| `Authorization` | `Basic <base64("74236:<api-key>")>` | `loki_username` + `loki_password` (only set when **both** are non-empty) |
| `Content-Encoding` | `gzip` | `loki_gzip: true` |

The body is the standard Loki envelope — see `reference.md` §Loki HTTP
API Mapping for the exact shape. The sink **does not inspect event
payloads**; the Formatter (`format: json` here) renders each event into
the `values[]` line entries.

### Verification

After restarting the daemon (`systemctl restart arxsentinel` — the sink
is constructed at startup, not reloaded via SIGHUP), check that a single
push succeeds:

```bash
# Tail the daemon log for "loki sink" and confirm there are no 4xx/5xx.
journalctl -u arxsentinel -f | grep -i loki

# In Grafana, query the stream to confirm the labels land correctly:
# {job="arxsentinel", env="production", component="waf"}
```

If you see `401 Unauthorized` — `loki_username` and `loki_password` are
set, but the API key is wrong, or does not have the `logs:write` scope.
If you see `403 Forbidden` — the tenant ID (`loki_tenant_id`) is wrong
for this Loki org, or the key does not have access to this tenant.

---

## Recipe 2: mTLS to a Self-Hosted Loki Behind a Private CA

The most operationally common non-trivial Loki deployment: Loki sits
behind a private CA, and the sink presents a client certificate. This
recipe shows the `loki_tls_cert` + `loki_tls_key` pair **together with**
`loki_ca_cert` — the three fields that distinguish "I trust a private
CA" (one config) from "I authenticate to the server with a client cert"
(another config). The two are independent and the sink explicitly
supports running with either, both, or neither.

For a CA-only config (no mTLS) — the common case for Loki behind a
self-signed reverse proxy — drop the `loki_tls_cert` and `loki_tls_key`
lines and keep only `loki_ca_cert`.

### Configuration

```yaml
streams:
  - name: main
    inputs:
      - type: file
        path: /var/log/nginx/access.log
        parser: combined
    outputs:
      - type: loki
        loki_url: "https://loki.internal.corp:3100"
        loki_labels:
          job: arxsentinel
          env: production

        # ── mTLS: client certificate + key (must be set TOGETHER) ──
        loki_tls_cert: /etc/arxsentinel/tls/loki-client.crt
        loki_tls_key:  /etc/arxsentinel/tls/loki-client.key

        # ── Private CA that signed Loki's server cert ──
        # Independent of the client-cert pair — pinning a private CA
        # does not require mTLS, and mTLS does not require a private CA.
        loki_ca_cert:  /etc/arxsentinel/tls/loki-internal-ca.crt
```

### Prerequisites

**1. Issue the client certificate.**

The private CA that signs Loki's server cert should also issue the
client cert. Generate a key + CSR and submit to your internal CA:

```bash
openssl genrsa -out loki-client.key 2048
openssl req -new -key loki-client.key -out loki-client.csr \
  -subj "/CN=arxsentinel/O=security"
# Submit loki-client.csr to your internal CA; receive loki-client.crt
```

**2. File permissions.**

The daemon runs as a non-root user; the cert files must be readable by
it. Following the same pattern as the MikroTik cookbook's CA file
permissions (root-owned, group-readable by the daemon group):

```bash
mkdir -p /etc/arxsentinel/tls
cp loki-client.crt loki-client.key loki-internal-ca.crt /etc/arxsentinel/tls/
chown root:arxsentinel /etc/arxsentinel/tls/*
chmod 640 /etc/arxsentinel/tls/*
```

**3. Verify the CA pins the right name.**

The CA bundle you point at with `loki_ca_cert` must chain to the
certificate Loki serves. If you point at the wrong CA, the TLS handshake
fails with `x509: certificate signed by unknown authority` — the error
appears in the daemon log on every flush attempt.

**4. Restart the daemon.**

Sinks are constructed once at startup and do not respond to SIGHUP —
the same rule as the MikroTik executor. `kill -HUP` reloads only
detectors, scoring, and blocklists; executor/sink config changes
require a full restart:

```bash
systemctl restart arxsentinel
```

### Verification

```bash
# Confirm the daemon parsed the config without "loki" / "tls" errors.
journalctl -u arxsentinel --since "-1m" | grep -Ei "loki|tls"

# Force a flush by sending one event and watch the daemon log.
journalctl -u arxsentinel -f

# If you have openssl, a manual TLS probe confirms the cert chain
# works from the host running the daemon (replace host:port with your
# Loki's address):
openssl s_client -connect loki.internal.corp:3100 \
  -CAfile /etc/arxsentinel/tls/loki-internal-ca.crt \
  -cert /etc/arxsentinel/tls/loki-client.crt \
  -key /etc/arxsentinel/tls/loki-client.key \
  -servername loki.internal.corp \
  </dev/null
```

If the `s_client` handshake completes with `Verify return code: 0 (ok)`,
the daemon will succeed on the same path.

---

## Recipe 3: Troubleshooting

### Pushes return `400 Bad Request`

Loki rejects the request body. The most common causes — in order of
likelihood — are:

| Cause | What you'll see | Fix |
|-------|----------------|-----|
| `loki_labels` is empty | Validation error at startup, not at first push | Reference `reference.md` — the labels map must be non-empty; this is the arxsentinel-side fail-fast check in `validateSinks()`. |
| Timestamp is encoded as a JSON number, not a string | First push returns 400; subsequent pushes also 400 | This is a sink-package bug, not your config — Loki requires the timestamp in `values[]` to be a **JSON string of nanoseconds**. arx-core's Loki sink encodes it correctly as `strconv.FormatInt(..., 10)`; report if you see this behaviour. |
| `loki_url` does not include the scheme | `parseConfig` rejects the config at startup | Must start with `http://` or `https://`. Plain `loki.internal:3100` is rejected. |

### Pushes return `401 Unauthorized`

`loki_username` and `loki_password` are set, but the credentials are
wrong, or the API key lacks the `logs:write` scope. Check the key in
Grafana Cloud → "API Keys" and confirm the scope includes Logs write.

### Pushes return `403 Forbidden`

The `X-Scope-OrgID` header is set (`loki_tenant_id` is non-empty) but
the tenant ID does not match the credentials, or the API key is for a
different Loki org. Common when copying a config from one environment
to another and forgetting to change `loki_tenant_id`.

### TLS handshake fails

| Error in daemon log | Likely cause | Fix |
|---------------------|-------------|-----|
| `x509: certificate signed by unknown authority` | `loki_ca_cert` not set, or points at the wrong CA | Set `loki_ca_cert` to the PEM bundle of the private CA that signed Loki's server cert. |
| `tls: failed to find any PEM data in certificate input` | `loki_ca_cert` path exists but the file is not a valid PEM | Re-export the CA cert; verify with `openssl x509 -in <file> -noout -text`. |
| `tls: no certificates found` (mTLS) | `loki_tls_cert` set, `loki_tls_key` not (or vice versa) | arx-core's `parseConfig` rejects a half-configured cert pair at startup. Set both, or set neither. |

### `dropped` and `errors` counters keep climbing

The sink reports these via `Stats()`. Both increment on any non-2xx
response — a failed batch is **lost**, not retried. The contract is
"failed batch is dropped" (see arx-core's `pkg/sink/loki/README.md`
§Behaviour). A short-term response is to lower `loki_batch_size` so
each failed push loses fewer lines; a real fix is the underlying
misconfiguration (most often a 4xx from Loki that the daemon log will
show).

### Grafana query returns nothing, but the daemon log shows `2xx`

The push succeeded, but the labels in your Grafana query do not match
the labels you set in `loki_labels`. Loki's labels are **exact-match
selectors** in `{key="value"}` syntax — `env=production` will not match
`env="prod"`. Check the actual labels your sink sent by querying
`{job="arxsentinel"}` (with no other selector) and inspecting the
discovered stream.

### Common field-name mistakes

| You wrote | Loki expects | Notes |
|-----------|--------------|-------|
| `url` (no prefix) | `loki_url` | The sink reads from the `Loki*`-prefixed Go struct fields. |
| `loki_label` (singular) | `loki_labels` | The field is a map, plural. |
| `tenant` or `org_id` | `loki_tenant_id` | Field name mirrors the arx-core Go struct field. |
| `basic_auth` (nested map) | `loki_username` + `loki_password` | Two flat fields, not a nested map. |
