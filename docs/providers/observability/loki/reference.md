# Loki Sink Reference

Egress sink that forwards pipeline events to a Grafana Loki instance via the
Loki HTTP push API. This document is the arxsentinel-side reference — it
documents the arxsentinel YAML configuration that wraps arx-core's
`pkg/sink/loki` package. For behaviour beyond the flat config (batching
internals, flush-loop details, buildHTTPClient wiring), see arx-core's own
[`pkg/sink/loki/README.md`](https://github.com/mr-addams/arx-core).

## Config Fields

All fields live at the top level of an `outputs[]` entry — there is no
nested `config:` block (sinks are not executors). Field names below are the
exact arxsentinel YAML keys (snake_case, mirroring arx-core's
`pkgsink.SinkConfig` Go struct fields 1:1).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | — | Must be `"loki"` (required). Selects the sink package at build time. |
| `format` | string | — | Product-side format hint — see `formatterForFormat()` in `internal/sys/config/config.go`. Use `json` for SIEM-style envelopes; `fail2ban` for line-based log streams. The sink package itself does not read this field; arxsentinel resolves it to a `format.Formatter` and injects it on `NewSink`. |
| `loki_url` | string | — | Base URL of the Loki push endpoint, e.g. `"https://loki.example.com:3100"`. **Required** for `type: loki`. |
| `loki_labels` | map[string]string | — | Static set of stream labels sent with every push, e.g. `{job: arxsentinel, level: info}`. **Required** (non-empty map) for `type: loki` — Loki's `/loki/api/v1/push` rejects streams with zero labels. |
| `loki_batch_size` | int | `100` | Max log lines per push request. `0` → default `100`; negative → error at arx-core's `parseConfig`. |
| `loki_flush_interval` | string (duration) | `"5s"` | Max time between flushes. Parsed via `time.ParseDuration` (e.g. `"5s"`, `"250ms"`). Empty → default `5s`. |
| `loki_tenant_id` | string | `""` | Optional value for the `X-Scope-OrgID` header (multi-tenant Loki deployments). |
| `loki_username` | string | `""` | Optional HTTP Basic Auth username. Grafana Cloud convention: instance ID. **Must be set together with `loki_password`** — arx-core's `parseConfig` rejects a half-configured credential pair. |
| `loki_password` | string | `""` | Optional HTTP Basic Auth password. Grafana Cloud convention: API key. **Must be set together with `loki_username`**. |
| `loki_gzip` | bool | `false` | When `true`, the request body is gzipped and `Content-Encoding: gzip` is set. |
| `loki_tls_cert` | string | `""` | Path to client TLS certificate (PEM) for mTLS. **Must be set together with `loki_tls_key`**. Independent of `loki_ca_cert` — pinning a private CA does not require enabling client-cert auth, and vice versa. |
| `loki_tls_key` | string | `""` | Path to client TLS private key (PEM) for mTLS. **Must be set together with `loki_tls_cert`**. |
| `loki_ca_cert` | string | `""` | Path to CA certificate (PEM) used to verify Loki's certificate. Most common reason to set this: Loki is behind a private CA. Independent of the client-cert pair. |

arxsentinel's `validateSinks()` (in `internal/sys/config/config.go`) fail-fast
checks **only** that `loki_url` is non-empty and `loki_labels` is non-empty
for `type: loki`. Deeper validation (URL scheme, label-map non-empty at the
HTTP layer, coupled-field pair checks, batch-size bounds, duration parsing)
lives in arx-core's `parseConfig` — see arx-core's
[`pkg/sink/loki/README.md`](https://github.com/mr-addams/arx-core) §Configuration
for the full list of arx-core-side validation rules.

## Loki HTTP API Mapping

The table below maps each arxsentinel-side YAML field to the corresponding
position in the actual HTTP request. Direction `→` means "the field is sent
in the request"; `←` means "the field is read from the response" (this sink
reads nothing from the response — non-2xx is treated as a hard error).

| Config Field | Loki API Field | Direction | Notes |
|--------------|---------------|-----------|-------|
| `loki_url` | Base URL | `→` | `POST {loki_url}/loki/api/v1/push` |
| `loki_labels` | `streams[].stream` | `→` | Becomes the `stream` object on the per-request envelope. |
| `loki_batch_size` + `loki_flush_interval` | Batching policy | `→` | Applied internally; not visible on the wire. |
| `loki_tenant_id` | `X-Scope-OrgID` header | `→` | Only set when non-empty. |
| `loki_username` + `loki_password` | `Authorization` header | `→` | `Authorization: Basic <base64(user:pass)>` via `http.Request.SetBasicAuth`. Only set when **both** fields are non-empty. |
| `loki_gzip` | `Content-Encoding` header + body transform | `→` | `Content-Encoding: gzip`; body is gzipped before POST. |
| `loki_tls_cert` + `loki_tls_key` | TLS client certificate | `→` | Loaded via `tls.LoadX509KeyPair`, installed in `tlsConfig.Certificates`. Presented during the TLS handshake. |
| `loki_ca_cert` | TLS RootCAs pool | `→` | PEM loaded via `x509.NewCertPool().AppendCertsFromPEM`; replaces the system trust store on the connection's `*http.Transport`. |
| `format` | Per-line payload bytes | `→` | The sink calls the injected `format.Formatter` to render each event; the rendered bytes are wrapped in a `[timestamp_string, line]` tuple on `streams[].values[]`. The sink never inspects `event.Payload` directly. |
| (event timestamp) | `streams[].values[].[0]` | `→` | **JSON string of nanoseconds since the epoch** — encoded via `strconv.FormatInt(event.Envelope.Timestamp.UnixNano(), 10)`. Loki returns `400 Bad Request` if the timestamp is a JSON number. |
| — | `Content-Type` header | `→` | Always `application/json`. |

### API Endpoints

| Operation | HTTP Method | Path |
|-----------|-------------|------|
| Push log batch | `POST` | `{loki_url}/loki/api/v1/push` |

A single batch is sent as a top-level envelope object:

```json
{
  "streams": [
    {
      "stream": { "job": "arxsentinel", "level": "info" },
      "values": [
        ["1717777777000000000", "<formatter-output-line-1>"],
        ["1717777777000000001", "<formatter-output-line-2>"]
      ]
    }
  ]
}
```

This framing is the third variant in the arx-core fleet's "three distinct
framings" trio (Loki envelope, Splunk concatenated objects, Datadog
top-level array) — see arx-core's `pkg/sink/loki/README.md` §Behaviour for
the full contrast.

## Response Handling

Any non-2xx status code is treated as an error. The response body is
discarded; the error returned to the pipeline is the status code. The sink
**does not retry or requeue** — a failed batch is lost (`dropped` and
`errors` counters are incremented in the sink's `Stats()` output).

## TLS Posture

Unlike `pkg/sink/mqtt` (where TLS wiring is intentionally not exposed), the
Loki sink has real, working TLS support out of the box:

- **`https://` with no TLS material configured** — the Go stdlib
  `http.DefaultTransport` performs the TLS handshake and validates against
  the system trust store. No `InsecureSkipVerify`, no downgrade to
  plaintext.
- **mTLS** — set `loki_tls_cert` + `loki_tls_key` together. The PEM pair
  is loaded and the resulting `tls.Certificate` is presented during the
  handshake.
- **Custom CA** — set `loki_ca_cert` to point at a PEM CA bundle. The PEM
  is parsed via `x509.NewCertPool().AppendCertsFromPEM`; if no valid cert
  is found, `NewSink` returns an error at construction time.

What is **not** exposed (intentionally out of scope for this sink):
`InsecureSkipVerify`, minimum TLS version pin, custom verify-mode knobs.
These are deliberate omissions — see arx-core's `pkg/sink/loki/README.md`
§TLS status for the rationale.

## Build Profile

The `loki` sink is registered only in the `full` build profile (Flow 097
DECISIONS.md Decision 3). The `iot` and `minimal` profiles do not include
this sink. The blank-import lives in
`cmd/arxsentinel/plugins_full.go` and the registration entry in
`profiles/full.yaml`.

## See Also

- arx-core's [`pkg/sink/loki/README.md`](https://github.com/mr-addams/arx-core)
  — the canonical reference for the sink package itself (batching, flush
  loop, buildHTTPClient, formatter injection, full YAML examples,
  behaviour contract, future work).
- [Grafana Loki HTTP API reference](https://grafana.com/docs/loki/latest/reference/loki-http-api/)
  — upstream spec for `POST /loki/api/v1/push` (body shape, headers,
  response codes, multi-tenant `X-Scope-OrgID`).
- `docs/providers/observability/loki/cookbook.md` (Flow 097 Task 7.3b) —
  extended YAML examples: minimal, full with batching/gzip/tenant/Basic
  Auth, mTLS, Grafana Cloud.
