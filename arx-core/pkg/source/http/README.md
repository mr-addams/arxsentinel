# `pkg/source/http`

HTTP/HTTPS source for `arx-core`. Accepts log events from webhooks
(push mode, the default) or polls a remote endpoint on a fixed interval
(pull mode). The wire format is selected by `protocol` and decoded by a
plugin-specific `Adapter` from `pkg/source/http/adapters/`: the
built-in protocols (`plain`, `ndjson`, `firehose`, `pubsub`, `loki`,
`otlp`, `azure`, `splunk`) cover the common cases; vendor logpush
protocols (e.g. CDN ownership-challenge flows) are registered
separately by their adapter package. The body is bounded by
`max_body_bytes` (default 10 MB) and decompressed transparently when
`Content-Encoding: gzip` is set, so the source is safe against both
oversize requests and zip bombs.

## Public API

```go
// HTTPSource — runs an HTTP server (push) or client (pull) and forwards
// decoded records to the pipeline. Implements plugin.Source.
type HTTPSource struct { /* unexported */ }

// New — cfg must already be parseable by parseHTTPConfig (addr or url,
// protocol, optional tls_cert/tls_key for https, optional token,
// envelope_field for ndjson, pull_interval for pull mode, etc.).
// parser must not be nil. logFn is nil-safe.
func New(cfg pkgsource.InputConfig, par pkgsource.LineParser, logFn func(tag, msg, level string)) (*HTTPSource, error)

// plugin.Source interface — implemented by HTTPSource.
func (s *HTTPSource) Name() string                       // returns "http"
func (s *HTTPSource) Run(ctx context.Context, out chan<- *plugin.Event) error
func (s *HTTPSource) Close() error                      // no-op: server/client lifetime is owned by the Run() context
func (s *HTTPSource) Stats() plugin.SourceStats         // LinesRead / ParseErrors / Dropped
func (s *HTTPSource) Manifest() plugin.Manifest         // PluginID "http", Tags include the built-in protocols

// Adapter — implemented by every protocol adapter under adapters/.
// Decode turns a request body into records; WriteAck writes the
// protocol-specific acknowledgement.
type Adapter interface {
    Decode(body []byte) ([]EnvelopeRecord, error)
    WriteAck(w http.ResponseWriter, meta map[string]string)
}
```

The source registers itself as `type: http` via `init()`. Push mode
adds middleware: optional Bearer-token check, the vendor-specific
ownership-challenge handler (when the protocol requires one), and
Pub/Sub OIDC JWT validation (activated only when `protocol: pubsub`).
Pull mode skips middleware and trusts the remote endpoint.

## Example

Receive a vendor logpush stream (gzip NDJSON) on port 8889 — the
ownership-challenge handshake is handled automatically when the
protocol declares it:

```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8889"
    protocol: cloudflare
```
