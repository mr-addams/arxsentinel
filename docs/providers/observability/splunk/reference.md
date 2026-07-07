# Splunk Sink Reference

Egress sink that forwards pipeline events to a Splunk HTTP Event Collector
(HEC) instance via the HEC JSON-mode endpoint. This document is the
arxsentinel-side reference — it documents the arxsentinel YAML configuration
that wraps arx-core's `pkg/sink/splunk` package. For behaviour beyond the
flat config (batching internals, flush-loop details, buildHTTPClient
wiring), see arx-core's own
[`pkg/sink/splunk/README.md`](https://github.com/mr-addams/arx-core).

## Config Fields

All fields live at the top level of an `outputs[]` entry — there is no
nested `config:` block (sinks are not executors). Field names below are the
exact arxsentinel YAML keys (snake_case, mirroring arx-core's
`pkgsink.SinkConfig` Go struct fields 1:1).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | — | Must be `"splunk"` (required). Selects the sink package at build time. |
| `format` | string | — | Product-side format hint — see `formatterForFormat()` in `internal/sys/config/config.go`. Use `json` for SIEM-style envelopes; `fail2ban` for line-based log streams. The sink package itself does not read this field; arxsentinel resolves it to a `format.Formatter` and injects it on `NewSink`. |
| `splunk_url` | string | — | Base URL of the Splunk HEC endpoint, e.g. `"https://splunk.example.com:8088"`. **Required** for `type: splunk`. |
| `splunk_token` | string | — | HEC token, sent as `Authorization: Splunk <token>`. **Required** for `type: splunk` — Splunk rejects every request with `403 Forbidden` if the token is empty. |
| `splunk_source_type` | string | `""` | Optional static `sourcetype` value stamped on every event. Empty → field omitted from the event body. |
| `splunk_source` | string | `""` | Optional static `source` value stamped on every event. Empty → field omitted. |
| `splunk_index` | string | `""` | Optional static `index` value stamped on every event. Empty → field omitted (HEC token defaulting / routing rules apply). |
| `splunk_host` | string | `""` | Optional static `host` value stamped on every event. Empty → field omitted. |
| `splunk_batch_size` | int | `100` | Max events per push request. `0` → default `100`; negative → error at arx-core's `parseConfig`. |
| `splunk_flush_interval` | string (duration) | `"5s"` | Max time between flushes. Parsed via `time.ParseDuration` (e.g. `"5s"`, `"250ms"`). Empty → default `5s`. |
| `splunk_gzip` | bool | `false` | When `true`, the request body is gzipped and `Content-Encoding: gzip` is set. HEC's JSON-mode endpoint supports this natively. |
| `splunk_tls_cert` | string | `""` | Path to client TLS certificate (PEM) for mTLS. **Must be set together with `splunk_tls_key`**. Independent of `splunk_ca_cert`. |
| `splunk_tls_key` | string | `""` | Path to client TLS private key (PEM) for mTLS. **Must be set together with `splunk_tls_cert`**. |
| `splunk_ca_cert` | string | `""` | Path to CA certificate (PEM) used to verify Splunk's certificate. **The field operators will reach for FIRST in practice** — Splunk's default install uses a self-signed certificate, and HEC is frequently deployed behind a self-signed-cert reverse proxy. Independent of the client-cert pair. |

arxsentinel's `validateSinks()` (in `internal/sys/config/config.go`)
fail-fast checks **only** that `splunk_url` and `splunk_token` are both
non-empty for `type: splunk`. Deeper validation (URL scheme, coupled-field
pair checks, batch-size bounds, duration parsing) lives in arx-core's
`parseConfig` — see arx-core's
[`pkg/sink/splunk/README.md`](https://github.com/mr-addams/arx-core)
§Configuration for the full list of arx-core-side validation rules.

## HEC API Mapping

The table below maps each arxsentinel-side YAML field to the corresponding
position in the actual HTTP request. Direction `→` means "the field is sent
in the request"; `←` means "the field is read from the response" (this
sink reads nothing from the response — non-2xx is treated as a hard error).

| Config Field | HEC API Field | Direction | Notes |
|--------------|--------------|-----------|-------|
| `splunk_url` | Base URL | `→` | `POST {splunk_url}/services/collector/event` |
| `splunk_token` | `Authorization` header | `→` | **Literal scheme `Splunk`**, not `Bearer` and not `Basic`. Format: `Authorization: Splunk <token>`. The literal keyword is the HEC wire convention. |
| `splunk_source_type` | `sourcetype` (per-event field) | `→` | Appended to the per-event JSON object when non-empty. |
| `splunk_source` | `source` (per-event field) | `→` | Appended to the per-event JSON object when non-empty. |
| `splunk_index` | `index` (per-event field) | `→` | Appended to the per-event JSON object when non-empty. |
| `splunk_host` | `host` (per-event field) | `→` | Appended to the per-event JSON object when non-empty. |
| `splunk_batch_size` + `splunk_flush_interval` | Batching policy | `→` | Applied internally; not visible on the wire. |
| `splunk_gzip` | `Content-Encoding` header + body transform | `→` | `Content-Encoding: gzip`; body is gzipped before POST. |
| `splunk_tls_cert` + `splunk_tls_key` | TLS client certificate | `→` | Loaded via `tls.LoadX509KeyPair`, installed in `tlsConfig.Certificates`. Presented during the TLS handshake. |
| `splunk_ca_cert` | TLS RootCAs pool | `→` | PEM loaded via `x509.NewCertPool().AppendCertsFromPEM`; replaces the system trust store on the connection's `*http.Transport`. |
| `format` | `event` (per-event field) | `→` | The sink calls the injected `format.Formatter` to render each event; the rendered bytes become the `event` field of the per-event JSON object. The sink never inspects `event.Payload` directly. |
| (event timestamp) | `time` (per-event field) | `→` | **JSON number, fractional seconds with 3-decimal precision** — encoded via `strconv.FormatFloat(tsSeconds, 'f', 3, 64)` wrapped in `json.Number`. Splunk HEC rejects events with a quoted-string `time`. |
| — | `Content-Type` header | `→` | Always `application/json`. |

### API Endpoints

| Operation | HTTP Method | Path |
|-----------|-------------|------|
| Push event batch | `POST` | `{splunk_url}/services/collector/event` |

A single batch is sent as **N concatenated JSON event objects
back-to-back, with no wrapping array, no commas, and no newlines between
them** — exactly:

```
{"time":1717777777.123,"event":"<line-1>"}{"time":1717777777.124,"event":"<line-2>"}{"time":1717777777.125,"event":"<line-3>"}
```

Per-event, the body is:

```json
{
  "time":       1717777777.123,
  "event":      "<formatter-output-line>",
  "sourcetype": "arxsentinel:json",
  "source":     "arx-core",
  "index":      "main",
  "host":       "arx-prod-01"
}
```

The four metadata fields (`sourcetype`, `source`, `index`, `host`) are
appended only when their corresponding `splunk_*` config values are
non-empty.

This framing is the second variant in the arx-core fleet's "three distinct
framings" trio (Loki envelope, Splunk concatenated objects, Datadog
top-level array) — see arx-core's `pkg/sink/splunk/README.md` §Behaviour
for the full contrast.

> The `/services/collector/raw` endpoint is **explicitly out of scope** for
> this sink (Flow 010, Decision 1). Only the JSON-mode
> `/services/collector/event` endpoint is supported.

## Response Handling

Any non-2xx status code is treated as an error. The response body is
discarded; the error returned to the pipeline is the status code. A typical
HEC failure response is JSON of the form `{"text":"Invalid token","code":4}`;
this sink does not decode it. The sink **does not retry or requeue** — a
failed batch is lost (`dropped` and `errors` counters are incremented in
the sink's `Stats()` output).

The most operationally important failure mode is `403 Forbidden`, which
HEC returns when the configured token is invalid.

## TLS Posture

Unlike `pkg/sink/mqtt` (where TLS wiring is intentionally not exposed), the
Splunk sink has real, working TLS support out of the box:

- **`https://` with no TLS material configured** — the Go stdlib
  `http.DefaultTransport` performs the TLS handshake and validates against
  the system trust store.
- **mTLS** — set `splunk_tls_cert` + `splunk_tls_key` together. The PEM
  pair is loaded and the resulting `tls.Certificate` is presented during
  the handshake.
- **Custom CA** — set `splunk_ca_cert` to point at a PEM CA bundle. **This
  is the configuration operators will reach for FIRST in practice**, because
  Splunk's default install uses a self-signed certificate and HEC is
  frequently deployed behind a self-signed-cert reverse proxy. The same
  config knob works without enabling mTLS.

What is **not** exposed (intentionally out of scope for this sink):
`InsecureSkipVerify`, minimum TLS version pin, custom verify-mode knobs.
These are deliberate omissions — see arx-core's `pkg/sink/splunk/README.md`
§TLS status for the rationale.

## Build Profile

The `splunk` sink is registered only in the `full` build profile (Flow 097
DECISIONS.md Decision 3). The `iot` and `minimal` profiles do not include
this sink. The blank-import lives in
`cmd/arxsentinel/plugins_full.go` and the registration entry in
`profiles/full.yaml`.

## See Also

- arx-core's [`pkg/sink/splunk/README.md`](https://github.com/mr-addams/arx-core)
  — the canonical reference for the sink package itself (batching, flush
  loop, buildHTTPClient, formatter injection, full YAML examples,
  behaviour contract, future work).
- [Splunk HEC — Set up and use HTTP Event Collector](https://help.splunk.com/en/splunk-enterprise/get-data-in/http-event-collector)
  — upstream setup guide for the HEC endpoint
  (`/services/collector/event`), token issuance, indexer
  acknowledgment, and the `Authorization: Splunk <token>` header
  convention.
- [Splunk HEC — Format events for HTTP Event Collector](https://help.splunk.com/en/splunk-enterprise/get-data-in/http-event-collector/format-events-for-http-event-collector)
  — the JSON event object schema, the numeric `time` field, and the
  concatenated-JSON event-stream body format this sink targets.
- `docs/providers/observability/splunk/cookbook.md` (Flow 097 Task 7.3b) —
  extended YAML examples: minimal, full with batching/gzip/metadata,
  mTLS, self-signed-CA behind a reverse proxy.
