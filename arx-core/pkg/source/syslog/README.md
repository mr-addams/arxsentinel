# `pkg/source/syslog`

Syslog source for `arx-core`. Listens for syslog messages over UDP, TCP,
Unix domain stream, and Unix domain datagram sockets, strips the RFC 3164
or RFC 5424 envelope, and forwards the embedded log line to the configured
`LineParser`. Format is auto-detected by looking at the byte right after
the closing `>` of the priority bracket — `<PRI>1 ` triggers RFC 5424,
anything else falls back to RFC 3164. Each source is one `inputs[]`
entry with `type: syslog` and an `addr` URI that selects the transport
via its scheme (`udp://`, `tcp://`, `unix://`, `unixgram://`).

## Public API

```go
// SyslogSource — listener for syslog frames; implements plugin.Source.
// Streams run one goroutine per accepted connection; datagram transports
// run a single receive loop. Non-blocking send to `out` with the D3
// drop policy (full channel → Dropped++).
type SyslogSource struct { /* unexported */ }

// New — addr is a URI like "udp://:5514", "tcp://:514",
// "unix:///var/run/arx.sock", or "unixgram:///tmp/arx.sock". parser
// must not be nil. maxConnections limits concurrent TCP/Unix stream
// connections (≤0 defaults to 1000). logFn is nil-safe.
func New(addr string, parser pkgsource.LineParser, logFn func(tag, msg, level string), maxConnections int) (*SyslogSource, error)

// plugin.Source interface — implemented by SyslogSource.
func (s *SyslogSource) Name() string                       // returns "syslog:<addr>"
func (s *SyslogSource) Run(ctx context.Context, out chan<- *plugin.LogEntry) error
func (s *SyslogSource) Close() error                      // no-op: listener lifetime is owned by the Run() context
func (s *SyslogSource) Stats() plugin.SourceStats         // LinesRead / ParseErrors / Dropped
func (s *SyslogSource) Manifest() plugin.Manifest         // PluginID "syslog", Tags include the four schemes

// parseMessage (same package, used internally) strips the syslog
// envelope and returns the embedded log line.
func parseMessage(raw []byte) (string, error)
```

The source registers itself as `type: syslog` via `init()` and uses
`pkgsource.InputConfig.{Addr, MaxConnections}` plus
`pkgsource.BuildOptions.{Parser, LogFn}`. The parser slot is mandatory
— a nil parser fails in `New()`.

## Example

UDP syslog on port 5514 for a typical nginx access-log relay:

```yaml
inputs:
  - type: syslog
    addr: "udp://:5514"
    parser: combined
```
