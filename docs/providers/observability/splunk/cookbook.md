# Splunk Sink Cookbook

This cookbook is the **deeper-dive** companion to
`docs/providers/observability/splunk/reference.md` (the field-by-field
reference) and the `cookbook/observability/splunk-basic.yaml` quick-start
recipe (the minimum working config). Where a recipe here needs a known
field name, the field list comes from `reference.md` — this cookbook
does not invent new knobs. Recipes here go **deeper than the basic
recipe**: mTLS to a self-hosted HEC instance behind a self-signed-cert
reverse proxy, the HEC token generation and source-type metadata flow,
and a runbook for the most common misconfigurations.

The authoritative wire-format details (event-stream body shape, the
`Authorization: Splunk <token>` header, the numeric `time` field) are
in `reference.md`; the canonical sink-package behaviour (batching,
flush loop, `buildHTTPClient`, formatter injection) is in arx-core's
[`pkg/sink/splunk/README.md`](https://github.com/mr-addams/arx-core).
Read those first if you have not — the recipes below assume the field
names are already familiar.

---

## Recipe 1: mTLS to a Self-Hosted HEC Behind a Self-Signed Cert

The most operationally common non-trivial Splunk deployment: HEC sits
behind a reverse proxy (NGINX, HAProxy, or the Splunk HTTP listener
itself) that terminates TLS with a self-signed cert, and the sink
presents a client certificate for authentication. This recipe shows
**both** the mTLS pair (`splunk_tls_cert` + `splunk_tls_key`) and the
private-CA pin (`splunk_ca_cert`) — the three fields together cover the
full "private CA + client cert" case that the basic recipe does not
touch.

> **Why this is the common case for Splunk, but not for Loki or
> Datadog:** Splunk's default install uses a self-signed certificate
> for the management/HEC port. Loki, by contrast, is typically
> fronted by a public CA (Grafana Cloud), and Datadog's public regional
> intake endpoints serve publicly-trusted certs — neither requires
> `*_ca_cert` in the typical deployment. The
> `reference.md` §TLS Posture sections spell this contrast out in
> detail.

For a single-host setup with no mTLS and a publicly-trusted cert, start
from
[`cookbook/observability/splunk-basic.yaml`](../../../cookbook/observability/splunk-basic.yaml).

### Configuration

```yaml
streams:
  - name: main
    inputs:
      - type: file
        path: /var/log/nginx/access.log
        parser: combined
    outputs:
      - type: splunk
        splunk_url: "https://splunk-hec.internal.corp:8088"
        splunk_token: "${SPLUNK_HEC_TOKEN}"
        format: json

        # ── HEC metadata fields (stamped on every event) ──
        # See Recipe 2 for how to coordinate splunk_sourcetype with
        # Splunk's props.conf / transforms.conf on the indexer side.
        splunk_index: "main"
        splunk_source: "arxsentinel"
        splunk_sourcetype: "arxsentinel:json"
        splunk_host: "edge-01"

        # ── mTLS: client certificate + key (must be set TOGETHER) ──
        splunk_tls_cert: /etc/arxsentinel/tls/splunk-client.crt
        splunk_tls_key:  /etc/arxsentinel/tls/splunk-client.key

        # ── Private CA that signed the HEC reverse proxy's cert ──
        # This is the field operators will reach for FIRST in practice
        # for Splunk — see reference.md §TLS Posture. Independent of
        # the client-cert pair: pinning a CA does not require mTLS.
        splunk_ca_cert:  /etc/arxsentinel/tls/splunk-internal-ca.crt

        # ── Batching and compression ──
        splunk_batch_size: 200             # events per push; default 100
        splunk_flush_interval: "2s"        # max time between flushes; default "5s"
        splunk_gzip: true                  # gzip-encode request bodies
```

### What the wire looks like

The push request has these headers set by the sink (in addition to
`Content-Type: application/json`, always):

| Header | Value | Source |
|--------|-------|--------|
| `Authorization` | `Splunk <token>` | `splunk_token` (the literal keyword `Splunk` precedes the token — **not** `Bearer` and **not** `Basic`) |
| `Content-Encoding` | `gzip` | `splunk_gzip: true` |

The body is **N concatenated JSON event objects back-to-back** — no
wrapping array, no commas, no newlines between them. The
`reference.md` §API Endpoints block has the exact shape. Per-event, the
fields are:

- `time` — JSON number, fractional seconds, 3-decimal precision
  (encoded via `strconv.FormatFloat(..., 'f', 3, 64)` in arx-core). A
  quoted-string `time` is rejected by HEC.
- `event` — the formatted log line (JSON envelope here).
- `sourcetype`, `source`, `index`, `host` — only appended when the
  matching `splunk_*` config field is non-empty.

### Prerequisites

**1. Generate the client certificate.**

Same flow as Recipe 2 in the Loki cookbook: a CSR submitted to the
internal CA that signs the HEC proxy's cert. Resulting files end up at
the three paths referenced above.

**2. File permissions.**

The daemon runs as a non-root user; the cert files must be readable by
it:

```bash
mkdir -p /etc/arxsentinel/tls
cp splunk-client.crt splunk-client.key splunk-internal-ca.crt /etc/arxsentinel/tls/
chown root:arxsentinel /etc/arxsentinel/tls/*
chmod 640 /etc/arxsentinel/tls/*
```

**3. Restart the daemon.**

Sinks are constructed once at startup and do not respond to SIGHUP —
the same rule as the Loki and MikroTik recipes:

```bash
systemctl restart arxsentinel
```

### Verification

```bash
# Confirm the daemon parsed the config without "splunk" / "tls" errors.
journalctl -u arxsentinel --since "-1m" | grep -Ei "splunk|tls"

# Test the TLS handshake with openssl — replace host:port with your
# HEC's address. A `Verify return code: 0 (ok)` means the daemon will
# succeed on the same path.
openssl s_client -connect splunk-hec.internal.corp:8088 \
  -CAfile /etc/arxsentinel/tls/splunk-internal-ca.crt \
  -cert /etc/arxsentinel/tls/splunk-client.crt \
  -key /etc/arxsentinel/tls/splunk-client.key \
  -servername splunk-hec.internal.corp \
  </dev/null

# Force a flush by sending one event, then check the indexer
# (`index=main sourcetype="arxsentinel:json"`) in Splunk Web.
```

If the `s_client` handshake completes with `Verify return code: 0 (ok)`
but the daemon still reports TLS errors, the most common cause is
permissions on the cert files (the daemon user cannot read them) — see
the permissions block above.

---

## Recipe 2: HEC Token Generation and Source-Type Metadata

Splunk HEC auth is a per-input token, not a user/password pair. The
token is generated on the Splunk side, copied into the arxsentinel
config, and rotated independently of the daemon. The four metadata
fields (`splunk_index`, `splunk_source`, `splunk_sourcetype`,
`splunk_host`) are optional static scalars — when set, they appear on
every event and let Splunk's indexer apply per-source parsing rules
without needing to detect the format.

This recipe covers the **platform-side setup** (how to create the HEC
token, where to enable the input, how to set up the indexer-side
metadata rules) and the **arxsentinel-side wiring** (how to plumb the
token and the four metadata fields into the YAML).

### Splunk-side: enable HEC and create a token

**1. Enable the HTTP Event Collector (one-time per Splunk deployment).**

In Splunk Web: **Settings → Data Inputs → HTTP Event Collector →
Global Settings → Enable (Token Authentication Enabled = true) → Save.**

Or from the CLI on the Splunk host:

```
./splunk enable http-event-collector
```

**2. Create a new HEC token for arxsentinel.**

In Splunk Web: **Settings → Data Inputs → HTTP Event Collector → New
Token → Name: `arxsentinel-prod` → Index: `main` → Source type:
`arxsentinel:json` (a placeholder; you can refine on the indexer
side) → Create Token → Copy the token value.**

The token is the value you put in `splunk_token` in the arxsentinel
config. **Treat it like a password** — HEC tokens are bearer tokens
and the `Authorization: Splunk <token>` header is the only auth check.

> ⚠️ The token is shown **once** in Splunk Web. If you lose it, you
> must disable the old token and create a new one. There is no "show
> me the token again" UI.

**3. Set up the indexer-side sourcetype parsing (recommended).**

The `arxsentinel:json` sourcetype is a placeholder; to make Splunk
parse the JSON envelope (the `format: json` output of the sink) into
indexed fields, add a `props.conf` entry on the indexer:

```ini
# $SPLUNK_HOME/etc/system/local/props.conf
[arxsentinel:json]
KV_MODE = json
INDEXED_EXTRACTIONS = json
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%LZ
```

Then restart Splunk (`./splunk restart`) to apply the change. After
this, every event with `sourcetype=arxsentinel:json` is parsed field-by
-field in Splunk search — `index=main sourcetype="arxsentinel:json" |
table _time, src_ip, level` works directly.

### arxsentinel-side: plumb the token and metadata

The token comes from a secret store or environment; the four metadata
fields are plain YAML scalars:

```yaml
streams:
  - name: main
    inputs:
      - type: file
        path: /var/log/nginx/access.log
        parser: combined
    outputs:
      - type: splunk
        splunk_url: "https://splunk.example.com:8088"
        splunk_token: "${SPLUNK_HEC_TOKEN}"   # from a secret store, not committed
        format: json

        # ── The four static metadata fields ──
        # Empty → field omitted from the event body (HEC's token
        # defaulting / routing rules apply for index). Set explicitly
        # when you want to pin a value regardless of the input.
        splunk_index: "main"                   # target index
        splunk_source: "arxsentinel"           # source field; distinguishes inputs
        splunk_sourcetype: "arxsentinel:json"  # pairs with props.conf on the indexer
        splunk_host: "edge-01"                 # static host; overrides per-event hostname
```

### Token rotation

HEC tokens are rotatable without daemon restart — but only if the
arxsentinel side reads from a file/env that you can update. The
recommended pattern:

1. Update the token in your secret store (env var, file, vault).
2. The daemon's next flush uses the new value (the sink reads
   `splunk_token` once at `NewSink` time — see arx-core's README §
   Startup — so a config change requires a daemon restart for the
   change to take effect).
3. Restart: `systemctl restart arxsentinel`.
4. Disable the old token in Splunk Web once the daemon is on the new
   one and pushing successfully.

For zero-downtime rotation, run two parallel HEC tokens: a "current"
and a "next". Update the daemon config to use "next", restart, verify,
then disable "current" in Splunk.

---

## Recipe 3: Troubleshooting

### Pushes return `403 Forbidden`

This is the most operationally important HEC failure mode. The most
common causes — in order:

| Cause | What you'll see | Fix |
|-------|----------------|-----|
| `splunk_token` is empty | Validation error at startup, not at first push | The arxsentinel-side fail-fast check in `validateSinks()` requires `splunk_token` non-empty. The sink will not even start. |
| `splunk_token` is wrong or revoked | First push returns 403; subsequent pushes also 403 | Re-issue a token in Splunk Web (Settings → Data Inputs → HTTP Event Collector → find the token → Enable). The daemon does not need to restart if you update the secret in place; for config-driven tokens, restart. |
| `splunk_token` belongs to a different indexer's HEC | First push returns 403 | Confirm the HEC endpoint at `splunk_url` is the same Splunk deployment that issued the token. Cross-deployment tokens are 403s. |
| `Authorization: Bearer <token>` (wrong scheme) | All pushes return 403 | HEC uses the **literal keyword `Splunk`** before the token — see `reference.md` §HEC API Mapping. The sink sets the header correctly; if you see this in the wire (via `mitmproxy` or similar), the sink was misconfigured to use a generic Bearer client. |

### Pushes return `400 Bad Request`

HEC rejects the request body. The most common causes:

| Cause | What you'll see | Fix |
|-------|----------------|-----|
| Event `time` field is a JSON string, not a number | First push returns 400 | This is a sink-package bug, not your config — HEC requires `time` as a JSON number of fractional seconds. arx-core's Splunk sink encodes it correctly via `strconv.FormatFloat(..., 'f', 3, 64)`; report if you see this. |
| `Content-Type` is not `application/json` | First push returns 400 | The sink always sends `application/json`; if you see a different content type on the wire, something upstream is rewriting the request. |
| `splunk_url` does not include the scheme | `parseConfig` rejects the config at startup | Must start with `http://` or `https://`. Plain `splunk.example.com:8088` is rejected. |

### TLS handshake fails

| Error in daemon log | Likely cause | Fix |
|---------------------|-------------|-----|
| `x509: certificate signed by unknown authority` | `splunk_ca_cert` not set, or points at the wrong CA — **the most common real-world case for Splunk** | Set `splunk_ca_cert` to the PEM bundle of the CA that signed the HEC reverse proxy's cert. |
| `tls: failed to find any PEM data in certificate input` | `splunk_ca_cert` path exists but the file is not a valid PEM | Re-export the CA cert; verify with `openssl x509 -in <file> -noout -text`. |
| `tls: no certificates found` (mTLS) | `splunk_tls_cert` set, `splunk_tls_key` not (or vice versa) | arx-core's `parseConfig` rejects a half-configured cert pair at startup. Set both, or set neither. |

### Events appear in Splunk but with no parsed fields

The `format: json` output is being shipped as a single quoted string in
the `event` field, not parsed into indexed fields. This means the
indexer does not have a `props.conf` entry for the `sourcetype` you set
— see Recipe 2 step 3 for the `[arxsentinel:json]` `KV_MODE = json`
configuration.

### Events appear in Splunk with the wrong timestamp

Splunk's indexed time comes from one of three sources, in priority
order: the `time` field in the event (the sink's behaviour), the
filename (not applicable for HEC), or HEC's ingestion time. The sink
sets `time` to the source event's envelope timestamp in fractional
seconds. If the timestamp is wildly off (e.g. years in the future), the
most likely cause is the source event has a mis-set timestamp — check
the `nginx` log parser configuration upstream of the sink.

### `dropped` and `errors` counters keep climbing

The sink reports these via `Stats()`. Both increment on any non-2xx
response — a failed batch is **lost**, not retried (see arx-core's
`pkg/sink/splunk/README.md` §Behaviour). A short-term response is to
lower `splunk_batch_size` so each failed push loses fewer lines; a
real fix is the underlying misconfiguration (most often a 403 from
HEC that the daemon log will show).

### Common field-name mistakes

| You wrote | Splunk expects | Notes |
|-----------|----------------|-------|
| `url` (no prefix) | `splunk_url` | The sink reads from the `Splunk*`-prefixed Go struct fields. |
| `token` (no prefix) | `splunk_token` | Same. |
| `sourcetype` (no prefix) | `splunk_sourcetype` | Same. |
| `splunk_index: "main"` but events land in `default` | The HEC token has an index default that overrides | Either set the index on the HEC token (per-token default) **or** omit `splunk_index` from the config to let HEC defaulting apply. Setting both is a tie-break on the indexer side. |
