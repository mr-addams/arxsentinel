# Datadog Sink Reference

Egress sink that forwards pipeline events to the Datadog Logs API v2
intake. This document is the arxsentinel-side reference — it documents the
arxsentinel YAML configuration that wraps arx-core's `pkg/sink/datadog`
package. For behaviour beyond the flat config (batching internals,
flush-loop details, buildHTTPClient wiring), see arx-core's own
[`pkg/sink/datadog/README.md`](https://github.com/mr-addams/arx-core).

## Config Fields

All fields live at the top level of an `outputs[]` entry — there is no
nested `config:` block (sinks are not executors). Field names below are the
exact arxsentinel YAML keys (snake_case, mirroring arx-core's
`pkgsink.SinkConfig` Go struct fields 1:1).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | — | Must be `"datadog"` (required). Selects the sink package at build time. |
| `format` | string | — | Product-side format hint — see `formatterForFormat()` in `internal/sys/config/config.go`. Use `json` for SIEM-style envelopes; `fail2ban` for line-based log streams. The sink package itself does not read this field; arxsentinel resolves it to a `format.Formatter` and injects it on `NewSink`. |
| `datadog_url` | string | — | Full base URL of the Datadog Logs intake endpoint, including region (e.g. `"https://http-intake.logs.datadoghq.com"`). **Required** for `type: datadog`. The path `/api/v2/logs` is appended at request time. See *Regional URL table* below. |
| `datadog_api_key` | string | — | Datadog API key, sent as the custom `DD-API-KEY` header. **Required** for `type: datadog` — Datadog rejects every request with `403 Forbidden` if the key is empty. |
| `datadog_source` | string | `""` | Optional static `ddsource` value stamped on every log object. Empty → field omitted. |
| `datadog_tags` | string | `""` | Optional static `ddtags` value, in Datadog's own comma-separated tag syntax (e.g. `"env:prod,team:sre"`). Empty → field omitted. |
| `datadog_hostname` | string | `""` | Optional static `hostname` value stamped on every log object. Empty → field omitted. |
| `datadog_service` | string | `""` | Optional static `service` value stamped on every log object. Empty → field omitted. |
| `datadog_batch_size` | int | `100` | Max log objects per push request. `0` → default `100`; negative → error at arx-core's `parseConfig`. **> 1000 → error at arx-core's `parseConfig` (Datadog's hard limit; the sink deliberately rejects the configuration rather than silently splitting the batch across multiple POSTs).** |
| `datadog_flush_interval` | string (duration) | `"5s"` | Max time between flushes. Parsed via `time.ParseDuration` (e.g. `"5s"`, `"250ms"`). Empty → default `5s`. |
| `datadog_gzip` | bool | `false` | When `true`, the request body is gzipped and `Content-Encoding: gzip` is set. Datadog recommends this for production; default is operator opt-in (`false`). |
| `datadog_tls_cert` | string | `""` | Path to client TLS certificate (PEM) for mTLS. **Must be set together with `datadog_tls_key`**. Independent of `datadog_ca_cert`. Uncommon for Datadog's public endpoints. |
| `datadog_tls_key` | string | `""` | Path to client TLS private key (PEM) for mTLS. **Must be set together with `datadog_tls_cert`**. |
| `datadog_ca_cert` | string | `""` | Path to CA certificate (PEM) used to verify Datadog's certificate. **Rarely needed in practice for Datadog's public regional endpoints** — they serve publicly-trusted certs. The field is intended for operators behind a corporate TLS-inspecting proxy whose intercepted certificate chain is signed by an internal CA. |

arxsentinel's `validateSinks()` (in `internal/sys/config/config.go`)
fail-fast checks **only** that `datadog_url` and `datadog_api_key` are both
non-empty for `type: datadog`. Deeper validation (URL scheme, coupled-field
pair checks, batch-size bounds including the 1000-log hard limit, duration
parsing) lives in arx-core's `parseConfig` — see arx-core's
[`pkg/sink/datadog/README.md`](https://github.com/mr-addams/arx-core)
§Configuration for the full list of arx-core-side validation rules.

## Datadog Logs API v2 Mapping

The table below maps each arxsentinel-side YAML field to the corresponding
position in the actual HTTP request. Direction `→` means "the field is sent
in the request"; `←` means "the field is read from the response" (this
sink reads nothing from the response — non-2xx is treated as a hard error).

| Config Field | Datadog API Field | Direction | Notes |
|--------------|------------------|-----------|-------|
| `datadog_url` | Base URL | `→` | `POST {datadog_url}/api/v2/logs`. The `datadog_url` is **regional** — see *Regional URL table* below. |
| `datadog_api_key` | `DD-API-KEY` header | `→` | **A custom header, NOT `Authorization`**. Datadog's own auth scheme, distinct from both Loki's `Authorization: Basic` and Splunk's `Authorization: Splunk <token>`. |
| `datadog_source` | `ddsource` (per-log field) | `→` | Appended to the per-log object when non-empty. |
| `datadog_tags` | `ddtags` (per-log field) | `→` | Appended to the per-log object when non-empty. Datadog's own comma-separated tag syntax, **not** a YAML map. |
| `datadog_hostname` | `hostname` (per-log field) | `→` | Appended to the per-log object when non-empty. |
| `datadog_service` | `service` (per-log field) | `→` | Appended to the per-log object when non-empty. |
| `datadog_batch_size` + `datadog_flush_interval` | Batching policy | `→` | Applied internally; not visible on the wire. |
| `datadog_gzip` | `Content-Encoding` header + body transform | `→` | `Content-Encoding: gzip`; body is gzipped before POST. |
| `datadog_tls_cert` + `datadog_tls_key` | TLS client certificate | `→` | Loaded via `tls.LoadX509KeyPair`, installed in `tlsConfig.Certificates`. Presented during the TLS handshake. |
| `datadog_ca_cert` | TLS RootCAs pool | `→` | PEM loaded via `x509.NewCertPool().AppendCertsFromPEM`; replaces the system trust store on the connection's `*http.Transport`. |
| `format` | `message` (per-log field) | `→` | The sink calls the injected `format.Formatter` to render each event; the rendered bytes become the `message` field of the per-log object. The sink never inspects `event.Payload` directly. |
| (event timestamp) | `timestamp` (per-log field) | `→` | **JSON number, unix milliseconds** — encoded via `event.Envelope.Timestamp.UnixMilli()`. **OPTIONAL** — the field is omitted from the log object when the source event's `Envelope.Timestamp` is the zero value; Datadog then falls back to its own ingestion time. |
| — | `Content-Type` header | `→` | Always `application/json`. |

### API Endpoints

| Operation | HTTP Method | Path |
|-----------|-------------|------|
| Push log batch | `POST` | `{datadog_url}/api/v2/logs` |

A single batch is sent as **a top-level JSON array of log objects** —
`[{...}, {...}, ...]` — with no wrapping envelope object. The body starts
with `[` and ends with `]`, and `len(arr) == N` where N is the number of
flushed lines. The body is a valid JSON document on its own and can be
`json.Unmarshal`'d directly.

Per-element, the array entry is:

```json
{
  "message":   "<formatter-output-line>",
  "ddsource":  "<datadog_source, omitted when empty>",
  "ddtags":    "<datadog_tags, omitted when empty>",
  "hostname":  "<datadog_hostname, omitted when empty>",
  "service":   "<datadog_service, omitted when empty>",
  "timestamp": 1717777777000
}
```

`timestamp` is omitted when the source event's `Envelope.Timestamp` is
zero — Datadog then stamps the log with its own ingestion time rather
than mis-stamping it at the Unix epoch.

This framing is the third variant in the arx-core fleet's "three distinct
framings" trio (Loki envelope, Splunk concatenated objects, Datadog
top-level array), together with the matching "three distinct timestamp
encodings" trio — Loki (mandatory JSON string of nanoseconds), Splunk
(mandatory JSON number of fractional seconds), Datadog (optional JSON
number of milliseconds). See arx-core's `pkg/sink/datadog/README.md`
§Behaviour for the full contrast.

## Response Handling

Any non-2xx status code is treated as an error. The response body is
discarded; the error returned to the pipeline is the status code. The sink
**does not retry or requeue** — a failed batch is lost (`dropped` and
`errors` counters are incremented in the sink's `Stats()` output).

The most operationally important failure mode is `403 Forbidden`, which
Datadog returns when the configured key is invalid **OR when the wrong key
type is supplied where a Datadog API key is required**. Specifically,
supplying a Datadog **Application Key** (intended for the broader Datadog
API) where a Datadog **API Key** is required for the Logs intake is a
documented footgun: the request returns `403`, the body is not parsed, and
the operator sees only `unexpected status 403`. There is no in-band
signal that the problem is "wrong key type" — the operator must recognise
the pattern from the configured key string itself.

## Regional URL Table

> ⚠️ **Footgun:** picking the wrong region for your account silently
> accepts the push with a `2xx` response, but the logs are not queryable
> from your actual account region. Datadog does not return an error on a
> cross-region push — your push succeeds, the response is happy, and
> your logs are simply not visible from the region your API key belongs
> to. The sink does not validate "URL matches API key region" — that
> check is not possible from the client side (Datadog does not expose a
> key→region lookup), and the operator is responsible for matching
> `datadog_url` to the region of the Datadog account that issued the
> API key.

| Region | Site | Intake URL |
|--------|------|------------|
| US | `datadoghq.com` | `https://http-intake.logs.datadoghq.com` |
| EU | `datadoghq.eu` | `https://http-intake.logs.datadoghq.eu` |
| AP1 | `ap1.datadoghq.com` | `https://http-intake.logs.ap1.datadoghq.com` |
| AP2 | `ap2.datadoghq.com` | `https://http-intake.logs.ap2.datadoghq.com` |
| UK1 | `uk1.datadoghq.com` | `https://http-intake.logs.uk1.datadoghq.com` |
| US2 (Gov) | `us2.ddog-gov.com` | `https://http-intake.logs.us2.ddog-gov.com` |
| US3 | `us3.datadoghq.com` | `https://http-intake.logs.us3.datadoghq.com` |
| US5 | `us5.datadoghq.com` | `https://http-intake.logs.us5.datadoghq.com` |

## TLS Posture

Unlike `pkg/sink/mqtt` (where TLS wiring is intentionally not exposed), the
Datadog sink has real, working TLS support out of the box:

- **`https://` with no TLS material configured** — the Go stdlib
  `http.DefaultTransport` performs the TLS handshake and validates against
  the system trust store. **Datadog's public regional intake endpoints
  (`http-intake.logs.datadoghq.com`, `…datadoghq.eu`, `…ap1.`, `…ap2.`,
  `…uk1.`, `…us3.`, `…us5.`, `…us2.ddog-gov.com`) all serve
  publicly-trusted certificates** — a standard system trust store
  validates them out of the box, so `datadog_ca_cert` is **rarely needed
  in practice** for the documented public endpoints.
- **mTLS** — set `datadog_tls_cert` + `datadog_tls_key` together. The PEM
  pair is loaded and the resulting `tls.Certificate` is presented during
  the handshake.
- **Custom CA** — set `datadog_ca_cert` to point at a PEM CA bundle.
  Common case: corporate TLS-inspecting proxy that intercepts and
  re-signs the TLS connection with an internal CA. Without a proxy, this
  is unnecessary on Datadog's public endpoints.

This is the **explicit contrast with `pkg/sink/splunk`**: Splunk's default
install uses a self-signed certificate, so `splunk_ca_cert` is the primary
real-world need. For Datadog's public endpoints, that scenario does not
arise.

What is **not** exposed (intentionally out of scope for this sink):
`InsecureSkipVerify`, minimum TLS version pin, custom verify-mode knobs.
These are deliberate omissions — see arx-core's
`pkg/sink/datadog/README.md` §TLS status for the rationale.

## Build Profile

The `datadog` sink is registered only in the `full` build profile (Flow 097
DECISIONS.md Decision 3). The `iot` and `minimal` profiles do not include
this sink. The blank-import lives in
`cmd/arxsentinel/plugins_full.go` and the registration entry in
`profiles/full.yaml`.

## See Also

- arx-core's [`pkg/sink/datadog/README.md`](https://github.com/mr-addams/arx-core)
  — the canonical reference for the sink package itself (batching, flush
  loop, buildHTTPClient, formatter injection, full YAML examples,
  behaviour contract, future work).
- [Datadog Logs API reference](https://docs.datadoghq.com/api/latest/logs/)
  — upstream spec for `POST /api/v2/logs` (body shape, the `DD-API-KEY`
  custom header, response codes, the optional millisecond `timestamp`
  field, the `ddsource` / `ddtags` / `hostname` / `service` static
  scalars).
- `docs/providers/observability/datadog/cookbook.md` (Flow 097 Task 7.3b)
  — extended YAML examples: minimal (US region), full with batching/gzip/
  metadata, regional URL table, mTLS behind a corporate TLS-inspecting
  proxy.
