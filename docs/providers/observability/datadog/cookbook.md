# Datadog Sink Cookbook

This cookbook is the **deeper-dive** companion to
`docs/providers/observability/datadog/reference.md` (the field-by-field
reference) and the `cookbook/observability/datadog-basic.yaml`
quick-start recipe (the minimum working config). Where a recipe here
needs a known field name, the field list comes from `reference.md` —
this cookbook does not invent new knobs. Recipes here go **deeper than
the basic recipe**: EU-region routing with static `ddtags`, Datadog API
key generation and regional site selection, and a runbook for the
**single most common operational footgun** — picking the wrong region
for your account, which silently accepts pushes with a `2xx` response
and makes logs invisible from your actual account region.

The authoritative wire-format details (top-level JSON array, the
`DD-API-KEY` custom header, the optional millisecond `timestamp` field)
are in `reference.md`; the canonical sink-package behaviour (batching,
flush loop, `buildHTTPClient`, formatter injection) is in arx-core's
[`pkg/sink/datadog/README.md`](https://github.com/mr-addams/arx-core).
Read those first if you have not — the recipes below assume the field
names are already familiar.

---

## Recipe 1: EU-Region Routing with Static `ddtags`

A Datadog account on `datadoghq.eu` (an EU-region site) needs a
matching intake URL — and the API key only works against the URL of
the site that issued it. This recipe shows the realistic EU-region
variant the basic recipe does not cover: a regional URL, a site-pinned
API key, static `ddtags` for cost attribution, and the four static
metadata fields (`ddsource`, `ddtags`, `hostname`, `service`) all
working together.

For a US-region single-tenant setup start from
[`cookbook/observability/datadog-basic.yaml`](../../../cookbook/observability/datadog-basic.yaml).

### Configuration

```yaml
streams:
  - name: main
    inputs:
      - type: file
        path: /var/log/nginx/access.log
        parser: combined
    outputs:
      - type: datadog
        # ── EU-region intake URL (matches a datadoghq.eu API key) ──
        # Picking the wrong region for your account silently accepts
        # the push with a 2xx response, but the logs are not queryable
        # from your actual account region. See reference.md §Regional
        # URL Table and Recipe 3 below.
        datadog_url: "https://http-intake.logs.datadoghq.eu"
        datadog_api_key: "${DD_API_KEY_EU}"

        # ── Static metadata fields (stamped on every log object) ──
        # Datadog's own comma-separated tag syntax for ddtags — NOT
        # a YAML map. Empty → field omitted.
        datadog_source:  "nginx"                       # ddsource
        datadog_service: "arxsentinel"                 # service tag
        datadog_hostname: "edge-eu-01"                 # hostname tag
        datadog_tags: "env:prod,team:security,region:eu"  # ddtags

        # ── Batching and compression ──
        # Hard upper bound from Datadog: datadog_batch_size > 1000 is
        # rejected at parseConfig time. Default is 100. Datadog
        # recommends gzip in production.
        datadog_batch_size: 500                        # ≤ 1000; default 100
        datadog_flush_interval: "5s"                   # max time between flushes
        datadog_gzip: true                             # gzip-encode request bodies

        format: json                                   # JSON envelope; consumed by Log Explorer
```

### What the wire looks like

The push request has these headers set by the sink (in addition to
`Content-Type: application/json`, always):

| Header | Value | Source |
|--------|-------|--------|
| `DD-API-KEY` | `<api_key>` | `datadog_api_key` (a **custom header**, NOT `Authorization`) |
| `Content-Encoding` | `gzip` | `datadog_gzip: true` |

The body is a **top-level JSON array of log objects** — `[{...},
{...}, ...]` — with no wrapping envelope object. Each entry has:

- `message` — the formatted log line (JSON envelope here).
- `ddsource`, `ddtags`, `hostname`, `service` — only appended when the
  matching `datadog_*` config field is non-empty.
- `timestamp` — JSON number, unix milliseconds, **OPTIONAL**. The field
  is omitted when the source event's `Envelope.Timestamp` is zero;
  Datadog then falls back to its own ingestion time.

The complete shape is in `reference.md` §Datadog Logs API v2 Mapping.

### Verification

```bash
# Confirm the daemon parsed the config without "datadog" errors.
journalctl -u arxsentinel --since "-1m" | grep -i datadog

# In Datadog Log Explorer:
#   service:arxsentinel env:prod
# Should return the recent events. If the query returns nothing, the
# push is going to a different region — see Recipe 3.
```

---

## Recipe 2: Datadog API Key Generation and Regional Site Selection

Datadog's auth model is a per-org **API key** (not a user/password, not
an OAuth token), scoped to the Datadog site that issued it. The API
key only works against the intake URL of the same site. Pushing to a
wrong-region URL **does not return an error** — the request succeeds
with `2xx`, but the logs are not queryable from your account. This
recipe covers the **Datadog-side setup** (how to create the key, how
to pick the right region, how to scope the key minimally) and the
**arxsentinel-side wiring**.

### Step 1 — Identify your Datadog site and region

The site is the hostname you log in to:

| Site URL | Region | Intake URL (for `datadog_url`) |
|----------|--------|--------------------------------|
| `app.datadoghq.com` | US | `https://http-intake.logs.datadoghq.com` |
| `app.us3.datadoghq.com` | US3 | `https://http-intake.logs.us3.datadoghq.com` |
| `app.us5.datadoghq.com` | US5 | `https://http-intake.logs.us5.datadoghq.com` |
| `app.datadoghq.eu` | EU | `https://http-intake.logs.datadoghq.eu` |
| `app.ap1.datadoghq.com` | AP1 | `https://http-intake.logs.ap1.datadoghq.com` |
| `app.ap2.datadoghq.com` | AP2 | `https://http-intake.logs.ap2.datadoghq.com` |
| `app.uk1.datadoghq.com` | UK1 | `https://http-intake.logs.uk1.datadoghq.com` |
| `app.us2.ddog-gov.com` | US2 (Gov) | `https://http-intake.logs.us2.ddog-gov.com` |

The full list is in `reference.md` §Regional URL Table.

> ⚠️ **The footgun this table is designed to prevent:** the
> `datadog_url` field is **regional** — there is one URL per Datadog
> site. The API key is **also regional** — a key issued for
> `datadoghq.com` will be accepted by `http-intake.logs.datadoghq.eu`
> with a `2xx` response, but the logs will not appear in your
> `datadoghq.eu` account. Datadog does not return an error on a
> cross-region push; the operator must match the URL to the site.
> See Recipe 3 for the runbook.

### Step 2 — Create the API key

In Datadog Web: **Organization Settings → API Keys → New API Key →
Name: `arxsentinel-prod` → Save.**

> **API Key vs Application Key — the other footgun.** Datadog has
> two key types. The Logs intake requires an **API Key** (created
> via Organization Settings → API Keys). An **Application Key** (created
> via Organization Settings → Application Keys) is for the broader
> Datadog API and **does not work** for the Logs intake. Supplying an
> Application Key returns `403 Forbidden` with no in-band signal that
> the problem is "wrong key type" — see Recipe 3.

> Treat the API key like a password. HEC-style bearer tokens (Loki
> and Splunk) are the equivalent; the same operational hygiene applies.

### Step 3 — Plumb the key into arxsentinel

The key comes from a secret store or environment; the URL is the
regional URL from the table:

```yaml
streams:
  - name: main
    inputs:
      - type: file
        path: /var/log/nginx/access.log
        parser: combined
    outputs:
      - type: datadog
        # Match the URL to the site that issued the API key.
        datadog_url: "https://http-intake.logs.datadoghq.eu"  # EU
        datadog_api_key: "${DD_API_KEY_EU}"                    # from secret store
        format: json
```

### Key rotation

Datadog API keys are rotatable without daemon restart — but only if
the arxsentinel side reads from a file/env that you can update. The
sink reads `datadog_api_key` once at `NewSink` time (see arx-core's
README §Startup), so a config change requires a daemon restart for the
change to take effect:

1. Create a new API key in Datadog Web (keep the old one enabled for
   the rollover window).
2. Update the secret store with the new key.
3. Restart: `systemctl restart arxsentinel`.
4. Verify pushes succeed (Recipe 1's verification step).
5. Disable the old key in Datadog Web.

---

## Recipe 3: Troubleshooting

> This runbook focuses on the **Datadog-specific** failure modes that
> the Loki and Splunk troubleshooting recipes do not cover. The shared
> HTTP-sink failure modes (TLS handshake, gzip body, content-type
> negotiation) are covered in those recipes — the field-name conventions
> are the only difference.

### The "logs not visible" runbook (the wrong-region footgun)

**Symptom:** the daemon log shows successful pushes (`2xx` responses
from Datadog, no errors). The `Stats()` output shows
`events_written` increasing. But in Datadog Log Explorer, the query
`service:arxsentinel` returns **zero results** — or results that
clearly belong to a different account.

**Most likely cause:** the `datadog_url` and the API key are
**region-mismatched** — the key was issued for one Datadog site, and
the URL points at a different one. Datadog does **not** return an error
on a cross-region push; the push succeeds with `2xx`, the body is
accepted, and the logs are simply not queryable from your account.

**How to confirm:**

1. Check the site your account is on: log in to Datadog Web and look at
   the URL — `app.datadoghq.com` vs `app.datadoghq.eu` vs `app.us3.…`
   vs etc.
2. Check the `datadog_url` in your arxsentinel config. It must be the
   intake URL of **the same site**.
3. Check the API key's origin: Organization Settings → API Keys → find
   the key → confirm it belongs to the same org and site.
4. If site and key are both correct, check that the `service` /
   `ddsource` / `ddtags` in your Log Explorer query actually match
   the values in the config (and the values in the events). The query
   `service:arxsentinel` will not match `service:"ArxSentinel"` —
   Log Explorer tag values are case-sensitive.

**Fix:** update `datadog_url` to the intake URL of the site that
issued the key, restart the daemon, and re-query. There is no data
recovery for the lost pushes — the logs were accepted by the
wrong-region intake, but Datadog does not propagate them back to your
account region.

> This is a **real, documented operational footgun**, not a
> hypothetical. arx-core's `pkg/sink/datadog/README.md` §Regional URL
> table calls it out by name; the sink deliberately does not attempt
> a client-side check (Datadog does not expose a key→region lookup
> API), and the operator is responsible for matching `datadog_url` to
> the region of the account that issued the key.

### Pushes return `403 Forbidden`

The most operationally important Datadog failure mode. The most common
causes — in order:

| Cause | What you'll see | Fix |
|-------|----------------|-----|
| `datadog_api_key` is empty | Validation error at startup, not at first push | The arxsentinel-side fail-fast check in `validateSinks()` requires `datadog_api_key` non-empty. The sink will not even start. |
| `datadog_api_key` is wrong or revoked | First push returns 403; subsequent pushes also 403 | Re-issue a key in Datadog Web (Organization Settings → API Keys → New API Key). Update the secret store, restart the daemon. |
| **Wrong key type — Application Key where API Key is required** | First push returns 403; **the body is not parsed** by the sink so there is no in-band signal that this is the problem | Re-issue the key from Organization Settings → **API Keys** (not Application Keys). The Logs intake requires an API Key. |
| `datadog_url` is a typo (different domain) | Connection refused / DNS error, not 403 | Confirm the URL is in the regional table. A common typo is `logs.datadoghq.com` instead of `http-intake.logs.datadoghq.com`. |

### Pushes return `400 Bad Request`

Datadog rejects the request body. The most common causes:

| Cause | What you'll see | Fix |
|-------|----------------|-----|
| `datadog_batch_size > 1000` | `parseConfig` rejects the config at startup | Datadog's hard limit is 1000 logs per request; the sink explicitly rejects higher values rather than splitting the batch. Set `datadog_batch_size <= 1000`. |
| `Content-Type` is not `application/json` | First push returns 400 | The sink always sends `application/json`; if you see a different content type on the wire, something upstream is rewriting the request. |
| `datadog_url` does not include the scheme | `parseConfig` rejects the config at startup | Must start with `http://` or `https://`. Plain `http-intake.logs.datadoghq.com` is rejected. |

### TLS handshake fails

| Error in daemon log | Likely cause | Fix |
|---------------------|-------------|-----|
| `x509: certificate signed by unknown authority` | A **corporate TLS-inspecting proxy** in front of the Datadog intake, intercepting and re-signing the TLS connection with an internal CA | Set `datadog_ca_cert` to the PEM bundle of the proxy's CA. **Note:** unlike Splunk, Datadog's public regional endpoints serve publicly-trusted certs — `datadog_ca_cert` is rarely needed in practice. The field is intended for the proxy case. |
| `tls: failed to find any PEM data in certificate input` | `datadog_ca_cert` path exists but the file is not a valid PEM | Re-export the CA cert; verify with `openssl x509 -in <file> -noout -text`. |
| `tls: no certificates found` (mTLS) | `datadog_tls_cert` set, `datadog_tls_key` not (or vice versa) | arx-core's `parseConfig` rejects a half-configured cert pair at startup. Set both, or set neither. |

### `dropped` and `errors` counters keep climbing

The sink reports these via `Stats()`. Both increment on any non-2xx
response — a failed batch is **lost**, not retried (see arx-core's
`pkg/sink/datadog/README.md` §Behaviour). A short-term response is to
lower `datadog_batch_size` so each failed push loses fewer lines; a
real fix is the underlying misconfiguration (most often a 403 that the
daemon log will show).

### Common field-name mistakes

| You wrote | Datadog expects | Notes |
|-----------|-----------------|-------|
| `url` (no prefix) | `datadog_url` | The sink reads from the `Datadog*`-prefixed Go struct fields. |
| `api_key` (no prefix) | `datadog_api_key` | Same. |
| `tags` (no prefix, YAML map) | `datadog_tags` (string, comma-separated) | Datadog's `ddtags` uses the platform's own comma-separated tag syntax — **not** a YAML map. `env:prod,team:sre`, not `{env: prod, team: sre}`. |
| `datadog_tags: "env:prod team:sre"` (space-separated) | `datadog_tags` is **comma-separated** | Datadog parses `ddtags` on commas, not spaces. A space-separated string is treated as a single malformed tag. |
| `Authorization: <api_key>` (Bearer-style) | `DD-API-KEY: <api_key>` (custom header) | Datadog's auth is a **custom header**, not `Authorization`. The sink sets it correctly; if you see an `Authorization` header on the wire, the sink was misconfigured. |
