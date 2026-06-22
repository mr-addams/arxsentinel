# `pkg/source/http` — HTTP Source

HTTP and HTTPS source plugin for ArxSentinel. Accepts log events from web servers,
cloud log delivery services, and observability tooling. Supports both push (webhook)
and pull (polling) modes, and ships with built-in adapters for nine common
cloud and observability protocols.

- **Plugin ID:** `http`
- **Plugin version:** `1.0.0`
- **Role:** `Source`
- **Input type:** `none`
- **Output type:** `structured`
- **Tags:** `http`, `https`, `push`, `pull`, `cloudflare`, `firehose`, `pubsub`, `loki`, `otlp`, `azure`, `splunk`, `cloud`

## Module Layout

```
pkg/source/http/
├── source.go          # Plugin registration, Run() entry point, adapters.Build dispatch
├── config.go          # Configuration parsing and validation
├── push.go            # Push-mode HTTP server, middleware chain
├── pull.go            # Pull-mode polling client
├── envelope.go        # Body reading, gzip decompression, timestamp normalization
└── adapters/
    ├── adapter.go         # Adapter interface, EnvelopeRecord
    ├── registry.go        # open adapter registry (Register/Build/Names/Has)
    ├── generic.go         # plain, ndjson (self-registered)
    ├── cloudflare.go      # cloudflare + ownership challenge middleware (self-registered)
    ├── firehose.go        # AWS Kinesis Firehose (self-registered)
    ├── pubsub.go          # GCP Pub/Sub push (self-registered)
    ├── pubsub_auth.go     # Pub/Sub OIDC JWT validation
    ├── loki.go            # Grafana Loki push API (self-registered)
    ├── otlp.go            # OpenTelemetry HTTP logs (self-registered)
    ├── azure.go           # Azure Monitor Data Collector (self-registered)
    ├── splunk.go          # Splunk HEC (self-registered)
    └── helpers.go         # normalizeTimestamp, copyMap
```

---

## Modes

The HTTP source runs in one of two modes, selected by the `mode` field
in the input configuration.

### Push Mode (`mode: push`, default)

The source runs an embedded HTTP/HTTPS server and accepts log events
incoming via webhook POST requests.

The handler is assembled as a middleware chain (outer to inner):

1. `bearerAuth` — Bearer token check on `Authorization` header.
   Active only when `token` is configured.
2. `CloudflareChallengeMiddleware` — answers `GET /?validate=true` with
   the value of the `Ownership-Challenge` request header. This allows
   Cloudflare Logpush to verify endpoint ownership.
3. `PubSubJWTMiddleware` — OIDC JWT validation. Active only when
   `protocol: pubsub` is selected.
4. Main handler:
   - `readLimited(r.Body, max_body_bytes)` — caps the request body
     to `max_body_bytes` (default 10 MB). Returns 413 on overflow.
   - `maybeGunzip(body, Content-Encoding, max_body_bytes)` —
     transparent gzip decompression, bounded by the same limit
     to prevent zip bombs.
   - Content-Type rejection for `application/x-protobuf` on
     `loki` and `otlp` (415) — these protocols accept JSON only.
   - Vendor request IDs (`X-Amz-Firehose-Request-Id`, `X-Request-ID`)
     are preserved in the per-record metadata map.
   - `adapter.Decode(body)` → `[]EnvelopeRecord`.
   - `par.Parse(record.RawLine)` → `*plugin.LogEntry`. Failed parses
     increment `parseErrors`; the record is dropped.
   - Non-blocking send on the `out` channel. If the channel is full,
     the entry is dropped and `dropped` is incremented.
   - `adapter.WriteAck(w, meta)` writes the protocol-specific
     acknowledgment.

Graceful shutdown is handled automatically — see [EOF and Cancellation](#eof-and-cancellation).

### Pull Mode (`mode: pull`)

The source polls a remote HTTP endpoint on a fixed interval and ingests
its response body as a batch of log events.

- Ticker at `pull_interval` (default 30 s).
- Issues a `GET` against the configured `url` (with optional Bearer token).
- Body processing matches push mode: `readLimited` → `maybeGunzip` →
  `adapter.Decode` → `par.Parse` → non-blocking send.
- Errors (network, decoding, transient HTTP failures) are logged but
  do not stop the loop; the next tick is honoured.
- The loop exits cleanly on `ctx.Done()`.

Pull mode does not run any middleware chain — the remote endpoint is
expected to be a trusted internal service or one protected by other means.

---

## Configuration Reference

Inputs are declared under `inputs[]` in the stream configuration. Only the
fields relevant to the HTTP source are listed below; see the project-level
documentation for the full input schema.

| Field            | Type      | Default                  | Required     | Description                                                                                      | Validation                                                                                            |
|------------------|-----------|--------------------------|--------------|--------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------|
| `type`           | `string`  | —                        | **yes**      | Must be `"http"`.                                                                                |                                                                                                       |
| `mode`           | `string`  | `"push"`                 | no           | `push` (server) or `pull` (client).                                                              |                                                                                                       |
| `addr`           | `string`  | —                        | **push only**| Listen address. Either `"host:port"` or a full URL: `"http://0.0.0.0:8888"`, `"https://..."`.     | Scheme defaults to `http` if omitted. Port defaults to `80` (http) or `443` (https).                 |
| `url`            | `string`  | —                        | **pull only**| Target URL to poll: `"http://log-aggregator:9000/export"`.                                       | Scheme, host, port, and path are parsed from the URL.                                                |
| `protocol`       | `string`  | —                        | **yes**      | Log format. One of: `plain`, `ndjson`, `cloudflare`, `firehose`, `pubsub`, `loki`, `otlp`, `azure`, `splunk`. | Must be one of the listed values.                                                                     |
| `http_path`      | `string`  | `"/"`                    | no           | HTTP path exposed by the push server or polled by the pull client.                               | Overrides the path component extracted from `addr` / `url`.                                           |
| `token`          | `string`  | —                        | no           | Bearer token for push-side authentication or pull-side `Authorization: Bearer ...` header.       | Compared in constant time.                                                                           |
| `envelope_field` | `string`  | —                        | no           | JSON key to extract from each NDJSON object (only for `protocol: ndjson`).                       | If the field is absent in a line, the adapter falls back to using the whole line.                    |
| `tls_cert`       | `string`  | —                        | **https**    | Path to TLS certificate (PEM).                                                                   | Required together with `tls_key` whenever the scheme is `https`.                                     |
| `tls_key`        | `string`  | —                        | **https**    | Path to TLS private key (PEM).                                                                   | Required together with `tls_cert` whenever the scheme is `https`.                                     |
| `pull_interval`  | `duration`| `"30s"`                  | no           | Polling interval in pull mode. Parsed by `time.ParseDuration`.                                   |                                                                                                       |
| `max_body_bytes` | `int`     | `10485760` (10 MB)       | no           | Maximum size of an HTTP request or pull response body.                                            | `0` or negative values reset to the 10 MB default.                                                    |

### Validation Rules

- `protocol` is mandatory; an empty or unknown value fails at startup.
- `mode: push` requires `addr`; `mode: pull` requires `url`.
- When the scheme is `https`, **both** `tls_cert` and `tls_key` must be set.
  Configuring only one is a configuration error.
- If the URL does not specify a port, the source substitutes `80` for `http`
  and `443` for `https`.
- `pull_interval` defaults to `30s` when omitted.
- `max_body_bytes` defaults to `10485760` (10 MB) when omitted or non-positive.

---

## Protocols and Adapters

Each adapter implements the same `Adapter` interface:

```go
type Adapter interface {
    Decode(body []byte) ([]EnvelopeRecord, error)
    WriteAck(w http.ResponseWriter, meta map[string]string)
}
```

`EnvelopeRecord` carries the raw line, a normalized Unix-nanosecond timestamp,
and an optional `map[string]string` of vendor-specific metadata.

### `plain` — Newline-delimited plain text

- **Adapter:** `GenericAdapter{isNDJSON: false}`
- **Input format:** one log line per `\n` separator. `\r` is trimmed.
  Blank lines are silently skipped.

  ```text
  192.0.2.10 - - [05/Jun/2026:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024
  192.0.2.11 - - [05/Jun/2026:12:00:01 +0000] "GET /api HTTP/1.1" 200 512
  ```

- **ACK response:** `200 OK` (no body).
- **Special behaviour:** timestamps are not extracted from the line —
  they are assigned by the downstream parser if any.

### `ndjson` — Newline-delimited JSON

- **Adapter:** `GenericAdapter{field: envelope_field, isNDJSON: true}`
- **Input format:** one JSON object per line. If `envelope_field` is set
  and the field exists in a line, its string value becomes `RawLine`.
  If `envelope_field` is set but the field is missing in a particular line,
  the entire JSON object is used as `RawLine` (fallback).

  ```json
  {"ts":"1717567200000000000","level":"info","message":"hello"}
  {"ts":"1717567201000000000","level":"warn","message":"slow query"}
  ```

- **ACK response:** `200 OK` (no body).
- **Special behaviour:** when `envelope_field` is omitted, the whole line
  is forwarded to the parser as `RawLine`. When `envelope_field` is set,
  a line that fails to parse as JSON aborts the request with a 400-level
  error.

### `cloudflare` — Cloudflare Logpush

- **Adapter:** `CloudflareAdapter`
- **Input format:** newline-delimited text in Logpush format. `\r` is
  trimmed; blank lines are skipped.

  ```text
  {"EdgeStartTimestamp":1717567200,"ClientIP":"203.0.113.5","Method":"GET","Path":"/"}
  {"EdgeStartTimestamp":1717567201,"ClientIP":"203.0.113.6","Method":"POST","Path":"/login"}
  ```

- **ACK response:** `200 OK` (no body).
- **Special behaviour:** the adapter also exposes a middleware that
  responds to `GET /?validate=true` with the value of the inbound
  `Ownership-Challenge` header, allowing Cloudflare to verify endpoint
  ownership. Cloudflare Logpush ships gzip-compressed NDJSON; the body
  pipeline decompresses it transparently.

### `firehose` — AWS Kinesis Firehose HTTP Endpoint Delivery

- **Adapter:** `FirehoseAdapter`
- **Input format:** JSON document containing a `records` array of
  base64-encoded payloads.

  ```json
  {
    "requestId": "...",
    "timestamp": 1717567200000,
    "records": [
      {"data": "eyJtc2ciOiJoZWxsbyJ9"},
      {"data": "eyJtc2ciOiJ3b3JsZCJ9"}
    ]
  }
  ```

- **ACK response:** `200 OK`, JSON body:

  ```json
  {"requestId":"<X-Amz-Firehose-Request-Id>","timestamp":<unix_ms>}
  ```

  with `Content-Type: application/json`.
- **Special behaviour:** the `X-Amz-Firehose-Request-Id` header on the
  inbound request is captured into the per-record metadata and echoed
  back in the ACK so Firehose can correlate retries.

### `pubsub` — GCP Pub/Sub Push

- **Adapter:** `PubSubAdapter`
- **Input format:** Pub/Sub push message envelope:

  ```json
  {
    "message": {
      "data": "SGVsbG8sIFdvcmxkIQ==",
      "messageId": "1234567890",
      "publishTime": "2026-06-05T12:00:00Z"
    },
    "subscription": "projects/.../subscriptions/..."
  }
  ```

  `message.data` is `base64.RawURLEncoding`; the adapter decodes it and
  populates `Metadata["messageId"]` for downstream tracing.

- **ACK response:** `204 No Content`.
- **Special behaviour:** requires `PubSubJWTMiddleware`. Requests are
  rejected with `401 Unauthorized` unless the `Authorization: Bearer ...`
  header carries a valid OIDC JWT signed by Google (RS256, JWKS fetched
  from `https://www.googleapis.com/oauth2/v3/certs`, audience matches the
  endpoint URL, `email_verified` is true). See [Security](#security).

### `loki` — Grafana Loki Push API

- **Adapter:** `LokiAdapter`
- **Input format:** Loki push body — one or more streams, each carrying
  labels and a list of `[timestamp, line]` pairs:

  ```json
  {
    "streams": [
      {
        "stream": {"job":"nginx","instance":"web-1"},
        "values": [
          ["1717567200000000000", "192.0.2.10 - - GET / 200"],
          ["1717567201000000000", "192.0.2.11 - - GET /api 200"]
        ]
      }
    ]
  }
  ```

- **ACK response:** `204 No Content`.
- **Special behaviour:** stream labels are copied into the record metadata.
  Requests with `Content-Type: application/x-protobuf` are rejected with
  `415 Unsupported Media Type` (this source accepts JSON only).
  Timestamps are stored as nanoseconds-as-string; malformed values
  default to `0`.

### `otlp` — OpenTelemetry HTTP Logs

- **Adapter:** `OTLPAdapter`
- **Input format:** OTLP/JSON logs payload (protobuf encoding is rejected
  with `415`):

  ```json
  {
    "resourceLogs": [
      {
        "scopeLogs": [
          {
            "logRecords": [
              {
                "timeUnixNano": "1717567200000000000",
                "body": {"stringValue": "user logged in"},
                "attributes": [
                  {"key": "user", "value": {"stringValue": "alice"}}
                ]
              }
            ]
          }
        ]
      }
    ]
  }
  ```

- **ACK response:** `200 OK`, JSON body:

  ```json
  {"partialSuccess":{}}
  ```

  with `Content-Type: application/json`.
- **Special behaviour:** the adapter walks
  `resourceLogs[].scopeLogs[].logRecords[]`. Supported body types are
  `stringValue`, `bytesValue` (base64-decoded), `intValue`, `doubleValue`,
  and `boolValue`. `timeUnixNano` is parsed as nanoseconds-as-string.
  Attributes are flattened into the record metadata.

### `azure` — Azure Monitor Data Collector

- **Adapter:** `AzureAdapter`
- **Input format:** top-level JSON array, one object per record. The
  `time` field, if present, must be RFC3339.

  ```json
  [
    {"time": "2026-06-05T12:00:00Z", "msg": "service started"},
    {"time": "2026-06-05T12:00:05Z", "msg": "service stopped"}
  ]
  ```

- **ACK response:** `204 No Content`.
- **Special behaviour:** the adapter preserves the raw JSON of each
  element as `RawLine` and normalizes `time` via RFC3339. The whole
  array is parsed in one pass; each element becomes one `EnvelopeRecord`.

### `splunk` — Splunk HTTP Event Collector (HEC)

- **Adapter:** `SplunkAdapter`
- **Input format:** newline-delimited JSON events. The `event` field may
  be a string or a nested object; the adapter stringifies objects.

  ```json
  {"time": 1717567200.123, "event": "user login"}
  {"time": 1717567201.456, "event": {"user":"alice","action":"logout"}}
  ```

- **ACK response:** `200 OK`, JSON body:

  ```json
  {"text":"Success","code":0}
  ```

  with `Content-Type: application/json`.
- **Special behaviour:** the adapter uses a streaming JSON decoder
  (`json.Decoder.More()`) to handle large payloads without buffering
  the entire body. `time` is parsed as a Unix float; non-parseable
  values default to `0`.

---

## Body Handling

Three utilities shape every incoming payload before it reaches an adapter.

### `readLimited(r io.Reader, maxBytes int64)`

Reads up to `maxBytes + 1` bytes from the reader. If the read length
exceeds `maxBytes`, the function returns an error and the source
increments the `dropped` counter. The push handler responds with
`413 Request Entity Too Large` in that case.

### `maybeGunzip(body []byte, contentEncoding string, maxBytes int64)`

If `Content-Encoding` is `gzip` or `x-gzip`, the body is decompressed
through a `gzip.Reader` bounded by `maxBytes + 1`. A decompression
result larger than `maxBytes` is rejected to defeat zip-bomb attacks.
Other `Content-Encoding` values yield an error response. Empty or
`identity` encoding is a no-op.

### Content-Type rejection (Loki and OTLP only)

For `protocol: loki` and `protocol: otlp`, requests with
`Content-Type: application/x-protobuf` are rejected with
`415 Unsupported Media Type`. Only JSON payloads are accepted by
this source — the wire-protocol negotiation is intentionally
deferred to a future change.

---

## Timestamp Normalization

The `normalizeTimestamp` helper (in `envelope.go` and re-exported by
`adapters/helpers.go`) converts a string timestamp into Unix nanoseconds
(int64). It is used by every adapter that ingests structured events.

| `kind`         | Input example             | Normalization                                                      |
|----------------|---------------------------|--------------------------------------------------------------------|
| `unix_ns`      | `1717567200000000000`     | `strconv.ParseInt` base 10 → int64                                 |
| `unix_ns_str`  | `1717567200000000000`     | `strconv.ParseInt` base 10 → int64                                 |
| `unix_ms`      | `1717567200000`           | `strconv.ParseInt` base 10 → multiplied by `1_000_000`             |
| `rfc3339`      | `2026-06-05T12:00:00Z`    | `time.Parse(time.RFC3339, val).UnixNano()`                         |
| `unix_float`   | `1717567200.123`          | `strconv.ParseFloat`, range check, multiplied by `1e9`             |

Adapter-to-kind mapping:

| Adapter  | Kind          | Notes                                                  |
|----------|---------------|--------------------------------------------------------|
| `plain`  | —             | Adapter does not extract timestamps.                   |
| `ndjson` | —             | Adapter does not extract timestamps.                   |
| `cloudflare` | —         | Adapter does not extract timestamps.                   |
| `firehose` | —           | Adapter does not extract timestamps.                   |
| `pubsub` | —             | Adapter does not extract timestamps.                   |
| `loki`   | `unix_ns_str` | `strconv.ParseInt`; per-record best-effort (defaults to `0` on error). |
| `otlp`   | `unix_ns_str` | `normalizeTimestamp`; per-record best-effort.          |
| `azure`  | `rfc3339`     | `normalizeTimestamp`; per-record best-effort.          |
| `splunk` | `unix_float`  | `normalizeTimestamp`; per-record best-effort.          |

---

## Security

The HTTP source applies a defence-in-depth model around inbound requests.

### Bearer token

When `token` is set, every push request must carry
`Authorization: Bearer <token>`. The comparison uses
`subtle.ConstantTimeCompare` to prevent timing attacks. Missing or
mismatched credentials return `401 Unauthorized` with a JSON error body.

In pull mode, the same `token` is sent as `Authorization: Bearer <token>`
on every outgoing request.

### Pub/Sub OIDC JWT

`PubSubJWTMiddleware` is mounted only when `protocol: pubsub` is selected.
A request is accepted only if all of the following hold:

- The `Authorization: Bearer <jwt>` header is present.
- The JWT header declares the `RS256` algorithm.
- The token signature is valid against the RSA public key whose `kid`
  matches the JWT header. The keys are fetched from
  `https://www.googleapis.com/oauth2/v3/certs` and cached for one hour.
- The `exp` claim is in the future.
- The `aud` claim equals the endpoint URL
  (`scheme://host:port/path`).
- The `email` claim is non-empty and `email_verified` is `true`.

Any failure returns `401 Unauthorized`.

### TLS

For `https`, both `tls_cert` and `tls_key` are required. The pair is
loaded with `tls.LoadX509KeyPair` at startup; missing or unreadable
files cause the source to fail before opening the listening socket.

### Body limit

`max_body_bytes` (default 10 MB) caps every request body. Exceeding the
limit returns `413 Request Entity Too Large` and the request is rejected
before any decoding.

### Gzip-bomb protection

`maybeGunzip` reads through a `gzip.Reader` bounded by `max_body_bytes`.
A decompressed body that exceeds the limit is rejected with a 400-level
error, regardless of how small the original gzipped payload was.

---

## Metrics and Stats

The source exposes three runtime counters via `Stats() plugin.SourceStats`:

| Counter       | Type   | Description                                              | Incremented when                                                                                                  |
|---------------|--------|----------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------|
| `linesRead`   | int64  | Log entries successfully forwarded to the pipeline.      | The non-blocking send on `out` succeeds (i.e., the parser returned `ok` and the channel accepted the entry).     |
| `parseErrors` | int64  | Records the line parser could not interpret.             | `par.Parse(record.RawLine)` returns `ok == false`. The record is dropped, the request still acknowledges.        |
| `dropped`     | int64  | Records dropped because downstream capacity was exceeded. | The non-blocking send on `out` falls into the `default` branch (the channel is full).                            |

All three counters are updated with `sync/atomic` and are safe to read
from the metrics endpoint without taking a lock.

---

## Constructors

A single constructor is exposed:

```go
// New creates an HTTPSource from configuration.
// cfg — validated input config (addr, protocol, mode, etc.).
// par — LineParser for raw log lines; must not be nil.
// logFn — structured logger; safe to pass nil (falls back to utils.Log).
func New(cfg pkgsource.InputConfig, par pkgsource.LineParser, logFn func(string, string, string)) (*HTTPSource, error)
```

The constructor parses the input configuration via `parseHTTPConfig()` and
returns an error if the protocol is unknown or the parser is nil. The caller
is expected to pass `BuildOptions.Parser` and `BuildOptions.LogFn` — these
are wired by the registry factory in `init()`.

Unlike `stdin`, there is no test-only constructor: the HTTP source creates
real network listeners and cannot be unit-tested with an injected reader.
Integration tests exercise the source through in-process HTTP clients against
a `httptest.Server` wrapper.

---

## Registration

The plugin is registered in `init()`:

```go
func init() {
	pkgsource.Register("http", func(cfg pkgsource.InputConfig, opts pkgsource.BuildOptions) (plugin.Source, error) {
		return New(cfg, opts.Parser, opts.LogFn)
	})
	pkgsource.RegisterManifest("http", (&HTTPSource{}).Manifest())
}
```

The factory delegates to `New()` with the stream-level `Parser` and `LogFn`
from `BuildOptions`. The manifest declares the plugin as a `Source` with
`InputType: none` and `OutputType: structured`.

---

## EOF and Cancellation

The source has three exit paths, all clean:

- **Push mode: context cancellation** — when `ctx.Done()` fires, a
  goroutine calls `server.Shutdown` with a 5-second timeout
  (`context.WithTimeout`). In-flight requests are allowed to drain before
  the server exits. `ListenAndServe` returns `http.ErrServerClosed`, which
  `runPush` converts to a `nil` return.
- **Pull mode: context cancellation** — the select loop observes
  `<-ctx.Done()` and returns `nil` immediately. No in-flight request is
  interrupted (the loop waits for the current tick/request to finish
  before the next `select` iteration; the context check gates the next
  iteration).
- **Startup error** — if the push server cannot bind to its address (port
  in use, TLS cert missing) or the pull client has a bad URL, the error
  is returned directly from `Run()` without starting any goroutine.

### Close()

`Close()` is a **no-op** on `HTTPSource`. The HTTP server/listener lifetime
is owned by the `Run()` context — cancellation of the context triggers
`server.Shutdown`, which is the only correct way to stop the server.

---

## Quick-Start Examples

The following snippets are self-contained, copy-pasteable fragments for
`inputs[]`. Each one assumes the rest of the ArxSentinel stream
configuration is in place.

### Plain text (newline-delimited)

```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8888"
    protocol: plain
```

### NDJSON with field extraction and Bearer auth

```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8896"
    protocol: ndjson
    envelope_field: message
    token: "your-secret-token"
```

### Cloudflare Logpush (gzip NDJSON, ownership challenge automatic)

```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8889"
    protocol: cloudflare
```

### AWS Kinesis Firehose

```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8890"
    protocol: firehose
```

### GCP Pub/Sub push

```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8891"
    protocol: pubsub
```

### Grafana Loki push API

```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8892"
    protocol: loki
```

### OpenTelemetry HTTP logs

```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8893"
    protocol: otlp
```

### Azure Monitor Data Collector

```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8894"
    protocol: azure
```

### Splunk HEC

```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8895"
    protocol: splunk
```

### Pull mode — poll an external endpoint every 30 seconds

```yaml
inputs:
  - type: http
    mode: pull
    url: "http://log-aggregator:9000/export"
    protocol: plain
    pull_interval: 30s
```

### HTTPS with TLS

```yaml
inputs:
  - type: http
    addr: "https://0.0.0.0:8443"
    protocol: plain
    tls_cert: /etc/arxsentinel/tls/server.crt
    tls_key: /etc/arxsentinel/tls/server.key
```

---

## Extending

Adding a new protocol adapter involves four localized steps. The pattern
is intentionally small so that new formats can be added without touching
the request pipeline.

1. **Implement the `Adapter` interface** in a new file under `adapters/`:

   ```go
   type MyAdapter struct{}

   func (a *MyAdapter) Decode(body []byte) ([]EnvelopeRecord, error) {
       // parse the vendor-specific payload here
   }

   func (a *MyAdapter) WriteAck(w http.ResponseWriter, meta map[string]string) {
       // write the protocol-specific acknowledgment
   }
   ```

2. **Self-register the adapter** by adding an `init()` to the same file
   that calls `adapters.Register("myproto", ...)`:

   ```go
   func init() {
       Register("myproto", func(cfg AdapterConfig) (Adapter, error) {
           return &MyAdapter{}, nil
       })
   }
   ```

   Registration is the open registry's only entry point — no switch in
   `source.go`, no iota in `config.go`. If the new protocol needs
   per-protocol context (such as `EnvelopeField` for NDJSON), add a
   field to `AdapterConfig`; the registry passes it through to every
   factory.
3. **(Optional) Add custom middleware** in `push.go` if the new protocol
   requires special authentication or handshake logic. Wire the
   middleware into the chain in `buildPushHandler`.
4. **Cover it with tests** by adding scenarios to
   `adapters/adapters_test.go` — at minimum, a happy-path decode and
   an ACK check. If the protocol is sensitive (auth, signed payloads),
   also extend `source_test.go` with a push-mode integration test.
5. **Document it** by adding a subsection under
   [Protocols and Adapters](#protocols-and-adapters) and a new
   quick-start example.

The interface and surrounding code paths are deliberately narrow so the
change set for a new adapter typically stays below 200 lines, including
tests.

---

## Dependencies

Standard library:

- `context` — cancellation propagation.
- `crypto/subtle` — constant-time token comparison (`bearerAuth`).
- `crypto/tls` — TLS certificate loading for HTTPS.
- `encoding/json` — JSON encoding for ACK/error responses.
- `fmt` — error and log message formatting.
- `net/http` — HTTP server (push) and client (pull).
- `sync/atomic` — counters (`linesRead`, `parseErrors`, `dropped`).
- `time` — 5-second shutdown timeout, pull interval ticker.

Project:

- `pkg/plugin` — `Source`, `Manifest`, `SourceStats`, `LogEntry`.
- `pkg/source` — registry (`Register`, `RegisterManifest`, `InputConfig`,
  `BuildOptions`, `LineParser`).
- `pkg/source/http/adapters` — `Adapter`, `EnvelopeRecord`, and all
  nine protocol adapters.
