# `pkg/source/syslog` — Syslog Source

Syslog source plugin for ArxSentinel. Listens for syslog messages over UDP,
TCP, Unix domain stream, and Unix domain datagram sockets. Strips RFC 3164
and RFC 5424 envelopes before forwarding the embedded log line to the
configured `LineParser`. Each syslog source is declared as one `inputs[]`
entry with `type: syslog` and an `addr` URI.

- **Plugin ID:** `syslog`
- **Plugin version:** `1.0.0`
- **Role:** `Source`
- **Input type:** `none`
- **Output type:** `structured`
- **Tags:** `syslog`, `udp`, `tcp`, `unix`, `rfc3164`, `rfc5424`, `network`

## Module Layout

```
pkg/source/syslog/
├── source.go          # Plugin registration, Run() entry point, transports, address parser
├── parser.go          # Syslog envelope stripping (RFC 3164 / RFC 5424)
├── source_test.go     # Integration tests (UDP, TCP, Unix, concurrent, drop counter, etc.)
└── parser_test.go     # Unit tests for envelope parser
```

There is no separate `config.go`, `udp.go`, `tcp.go`, or `unix.go` — all
transport logic and address parsing lives in `source.go`, and the envelope
parser is isolated in `parser.go`.

---

## How It Works

The data path is the same for every transport: receive a packet or line,
strip the syslog envelope, parse the remaining log line, and send a
`*plugin.LogEntry` downstream.

1. **Registration** — `init()` registers the factory under the plugin ID
   `"syslog"` in `pkg/source` and publishes the manifest.
2. **Build** — the input config is validated by the shared config
   validation entry point. When validation passes, the build step
   calls `New(addr, parser, logFn)`.
3. **Address parsing** — `parseAddr()` splits the URI into a Go
   `network` name and a `host` value (e.g. `udp://:5514` →
   `("udp", ":5514")`).
4. **Run dispatcher** — `Run()` picks the transport based on the scheme:
   - `udp`, `unixgram` → `runPacket()`
   - `tcp`, `unix`      → `runStream()`
5. **Envelope stripping** — every packet or scanned line flows through
   `parseMessage()`, which auto-detects RFC 3164 vs RFC 5424 and returns
   the embedded MSG portion. Anything that comes after the syslog header
   is handed to the configured `LineParser`.
6. **Delivery** — the resulting `*plugin.LogEntry` is delivered to the
   downstream pipeline via a non-blocking send on `out`. A full channel
   drops the entry and increments the `dropped` counter.

```
init → Register → (config validation) → Build → New → Run → runPacket / runStream → parseMessage → parser.Parse → out
```

---

## Source Interface

`SyslogSource` implements the shared `plugin.Source` contract:

```go
type SyslogSource struct { /* unexported fields */ }

func (s *SyslogSource) Name() string
//   Returns "syslog:" + addr (e.g. "syslog:udp://:5514").

func (s *SyslogSource) Close() error
//   No-op. Listener lifetime is owned by the Run() context.

func (s *SyslogSource) Stats() plugin.SourceStats
//   Returns LinesRead, ParseErrors, Dropped.

func (s *SyslogSource) Manifest() plugin.Manifest
//   Returns PluginID, Version, Role, InputType, OutputType, Tags.

func (s *SyslogSource) Run(ctx context.Context, out chan<- *plugin.LogEntry) error
//   Starts the appropriate transport dispatcher and blocks until ctx
//   is cancelled. Returns nil on graceful shutdown.
```

The factory wired in `init()` is:

```go
pkgsource.Register("syslog", func(cfg pkgsource.InputConfig, opts pkgsource.BuildOptions) (plugin.Source, error) {
    return New(cfg.Addr, opts.Parser, opts.LogFn)
})
```

---

## Transports

The transport is determined by the scheme in `addr`. Four schemes are
supported: `udp`, `tcp`, `unix`, and `unixgram`.

### UDP (`addr: "udp://host:port"`)

Datagram transport, connectionless.

- The source calls `net.ListenPacket("udp", hostport)`.
- Each UDP datagram contains exactly one syslog message.
- The receive buffer is 65536 bytes per read (the maximum practical
  size for a single IPv4 UDP datagram).
- No delivery guarantees — lost packets are not retransmitted.
- Typical use: receive nginx access logs forwarded by `rsyslog` or
  `syslog-ng` from many hosts.

Example:

```yaml
inputs:
  - type: syslog
    addr: "udp://:5514"
    parser: combined
```

### TCP (`addr: "tcp://host:port"`)

Stream transport, connection-oriented.

- The source calls `net.Listen("tcp", hostport)`, then runs an accept
  loop. Every accepted connection is handled in its own goroutine.
- Each goroutine reads the connection with a `bufio.Scanner` sized to
  65536 bytes; messages are separated by `\n` (LF).
- The connection is read until EOF (the client closed) or until the
  source context is cancelled.
- Many concurrent clients are supported transparently.

Example:

```yaml
inputs:
  - type: syslog
    addr: "tcp://:514"
    parser: combined
```

### Unix Stream (`addr: "unix:///path/to/sock"`)

Unix domain stream socket.

- The source calls `net.Listen("unix", path)`. Behaviour is identical
  to TCP: a `bufio.Scanner` per connection, LF-delimited messages.
- Bypasses the network stack entirely — useful when both the
  application (e.g. nginx) and ArxSentinel run on the same host.
- Requires write permission on the parent directory of the socket path.
- The socket file is not removed on shutdown; clean it up with
  `rm -f` if the previous run died uncleanly.

Example:

```yaml
inputs:
  - type: syslog
    addr: "unix:///var/run/arx.sock"
    parser: combined
```

### Unix Datagram (`addr: "unixgram:///path/to/sock"`)

Unix domain datagram socket.

- The source calls `net.ListenPacket("unixgram", path)`. Behaviour is
  identical to UDP: one message per datagram, 65536-byte buffer.
- Same host-only, no-network-stack property as `unix`.
- The source does not pre-remove stale socket files. Clean up with
  `rm -f` before starting ArxSentinel if a previous run left the
  socket behind.

Example:

```yaml
inputs:
  - type: syslog
    addr: "unixgram:///tmp/arx.sock"
    parser: combined
```

---

## Envelope Parsing

`parseMessage(raw []byte) (string, error)` extracts the embedded log
line from a raw syslog frame. The format is auto-detected by looking at
the characters immediately after the closing `>` of the priority
bracket:

- `<PRI>1 ` … → RFC 5424
- anything else → RFC 3164

If the `<…>` priority bracket is missing or appears past offset 6, the
function returns
`"syslog: malformed message: missing or invalid priority bracket"`.

### RFC 3164

Format: `<PRI>TIMESTAMP HOSTNAME TAG: MSG`

After `<PRI>`, the parser skips five space-separated tokens: the
three parts of TIMESTAMP, then HOSTNAME, then TAG (which must end with
`:`).

| # | Field        | Example             | Notes                                    |
|---|--------------|---------------------|------------------------------------------|
| 1 | TIMESTAMP    | `Jun  3 12:00:00`   | Three whitespace-separated parts.        |
| 2 | HOSTNAME     | `myhost`            | Single token.                            |
| 3 | TAG          | `nginx:`            | Single token, must end with `:`.         |

Anything after the TAG is returned as the message.

Raw input:

```text
<134>Jun  3 12:00:00 myhost nginx: 1.2.3.4 - - [03/Jun/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/7.68.0"
```

Stripped line (the value handed to the parser):

```text
1.2.3.4 - - [03/Jun/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/7.68.0"
```

Errors:

- Fewer than 5 fields after `<PRI>` →
  `"syslog: RFC 3164 message too short"`.
- No content after the TAG field →
  `"syslog: RFC 3164 message has no content after header"`.

### RFC 5424

Format: `<PRI>1 TIMESTAMP HOST APP PROCID MSGID [SD] MSG`

After `<PRI>1 `, the parser skips seven fields. The seventh field is the
STRUCTURED-DATA block: it is either the literal `-` (no structured data)
or a `[…]` block which is read as a single token up to and including
the closing `]`.

| # | Field            | Example                              | Notes                                    |
|---|------------------|--------------------------------------|------------------------------------------|
| 1 | VERSION          | `1`                                  | Always `1` for RFC 5424.                 |
| 2 | TIMESTAMP        | `2026-06-03T12:00:00Z`               | RFC3339-ish.                             |
| 3 | HOST             | `myhost`                             |                                          |
| 4 | APP              | `nginx`                              |                                          |
| 5 | PROCID           | `1234`                               |                                          |
| 6 | MSGID            | `-`                                  |                                          |
| 7 | STRUCTURED-DATA  | `-` or `[example@32473 iut="3" …]`   | `-` is nil; `[…]` is one token.          |

Anything after the STRUCTURED-DATA block is returned as the message.

Raw input with nil structured data:

```text
<134>1 2026-06-03T12:00:00Z myhost nginx 1234 - - 1.2.3.4 - - [03/Jun/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/7.68.0"
```

Raw input with structured data:

```text
<134>1 2026-06-03T12:00:00Z myhost nginx 1234 - [example@32473 iut="3" eventSource="Application"] 1.2.3.4 - - [03/Jun/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 612
```

Both produce the same stripped line:

```text
1.2.3.4 - - [03/Jun/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 612
```

Errors:

- Fewer than 7 fields after `<PRI>` →
  `"syslog: RFC 5424 message too short"`.
- No content after the STRUCTURED-DATA block →
  `"syslog: RFC 5424 message has no content after header"`.
- Nested `[…]` blocks are not supported; the parser reads up to the
  first `]` only.

### Empty and malformed input

- `[]byte{}` (empty input) → `"syslog: empty message"`.
- No `<…>` priority bracket, or `<` past offset 6 →
  `"syslog: malformed message: missing or invalid priority bracket"`.
- A line that parses successfully through the envelope but is rejected
  by the downstream `LineParser` is counted as a `parseError` and
  dropped; the next line is processed normally.

---

## Address Format

`parseAddr(addr string) (network, host string, err error)` splits the
URI into a Go network name and a host string. The scheme is the only
selector; the rest of the URI is passed through to the network package
as-is.

| Input                              | network     | host                | Error |
|------------------------------------|-------------|---------------------|-------|
| `"udp://0.0.0.0:5514"`            | `"udp"`     | `"0.0.0.0:5514"`    | none  |
| `"udp://:5514"`                   | `"udp"`     | `":5514"`           | none  |
| `"tcp://127.0.0.1:514"`          | `"tcp"`     | `"127.0.0.1:514"`   | none  |
| `"tcp://:514"`                   | `"tcp"`     | `":514"`            | none  |
| `"unix:///var/run/arx.sock"`     | `"unix"`    | `"/var/run/arx.sock"` | none |
| `"unixgram:///tmp/arx.sock"`     | `"unixgram"`| `"/tmp/arx.sock"`   | none  |
| `""`                              | —           | —                   | yes   |
| `"http://localhost:80"`          | —           | —                   | yes (`unknown scheme`) |
| `"udp://"`                       | —           | —                   | yes (empty host)       |

Any scheme outside `{udp, tcp, unix, unixgram}` fails at startup with
`"unknown syslog scheme %q in address %q"`.

---

## Configuration Reference

Inputs are declared under `inputs[]` in the stream configuration. Only
the fields relevant to the syslog source are listed below; see the
project-level documentation for the full input schema.

| Field    | Type     | Default | Required | Description                                                                                       | Validation                                                                                          |
|----------|----------|---------|----------|---------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| `type`   | `string` | —       | **yes**  | Must be `"syslog"`.                                                                               | `in.Type == "syslog"`.                                                                              |
| `addr`   | `string` | —       | **yes**  | Listen address. URI format: `"udp://:5514"`, `"tcp://:514"`, `"unix:///path"`, `"unixgram:///path"`. | `parseAddr()`; unknown scheme or empty host fails at startup.                                       |
| `parser`          | `string` | —      | **yes**  | Parser for log lines after envelope stripping: `combined`, `json`, `regex`, or a profile name.    | Not nil — checked in `New()`.                                                                        |
| `max_connections` | `int`    | `1000` | no       | Maximum simultaneous TCP/Unix stream connections. UDP/unixgram are connectionless and unaffected. | Env: `ARXSENTINEL_SYSLOG_MAX_CONNECTIONS`. Value ≤ 0 defaults to 1000.                              |

### Validation Rules

- `type: syslog` without `addr` fails with
  `"inputs[%d]: type=syslog requires addr (e.g. \"udp://:5514\")"`.
- `addr` must contain `://` and a scheme in `{udp, tcp, unix, unixgram}`.
- An empty host after `://` (e.g. `"udp://"`) is a configuration error.
- The configured parser must be resolvable; a nil parser fails in `New()`.

---

## Metrics and Stats

The source exposes three runtime counters via
`Stats() plugin.SourceStats`:

| Counter       | Type   | Description                                          | Incremented when                                                                            |
|---------------|--------|------------------------------------------------------|---------------------------------------------------------------------------------------------|
| `linesRead`   | int64  | Messages received from the network.                  | `conn.ReadFrom()` or `sc.Scan()` succeeds.                                                  |
| `parseErrors` | int64  | Envelope or line parse failures.                     | `parseMessage()` returns an error **or** `parser.Parse()` returns `ok == false`.            |
| `dropped`     | int64  | Entries dropped due to full channel buffer.          | The non-blocking send on `out` falls into the `default` branch (the channel is full).       |

All three counters are updated with `sync/atomic` and are safe to read
from the metrics endpoint without taking a lock.

> Note: `linesRead` is incremented immediately after a packet or line
> is read, before envelope stripping. Subtract `parseErrors` to get
> the count of messages that reached the parser output. This differs
> from sources that only count successfully delivered entries.

---

## Constructors

A single constructor is exposed:

```go
// New creates a SyslogSource that listens for syslog messages.
// addr — URI string: "udp://:5514", "tcp://:514",
//        "unix:///var/run/arx.sock", "unixgram:///tmp/arx.sock".
// parser — LineParser for log lines after envelope stripping; must not be nil.
// logFn — structured logger; nil-safe.
func New(addr string, parser pkgsource.LineParser, logFn func(string, string, string)) (*SyslogSource, error)
```

The constructor parses `addr` through `parseAddr()` to extract the Go
`network` name and `host` value. The following URIs succeed:

| Input                              | network     | host                |
|------------------------------------|-------------|---------------------|
| `"udp://:5514"`                    | `"udp"`     | `":5514"`           |
| `"tcp://127.0.0.1:514"`           | `"tcp"`     | `"127.0.0.1:514"`   |
| `"unix:///var/run/arx.sock"`      | `"unix"`    | `"/var/run/arx.sock"` |
| `"unixgram:///tmp/arx.sock"`      | `"unixgram"`| `"/tmp/arx.sock"`    |

Any scheme outside `{udp, tcp, unix, unixgram}` fails at startup with
`"unknown syslog scheme %q in address %q"`. An empty host (e.g.
`"udp://"`) is a configuration error.

The `parser` parameter is validated for nil — passing nil returns
`"syslog source %s: parser must not be nil"`. The constructor itself is
non-blocking and returns immediately.

> **Примечание:** Registration НЕ добавляем — она уже покрыта в секции
> How It Works (строки 38–39) и Source Interface (строки 87–93).

---

## Graceful Shutdown

`Run()` accepts a `context.Context`. When the context is cancelled:

- **Datagram transports** (`udp`, `unixgram`): the receive goroutine
  closes the `PacketConn` via the `<-ctx.Done()` signal, the next
  `ReadFrom` fails, the loop exits, and `Run()` returns `nil`.
- **Stream transports** (`tcp`, `unix`): the accept loop closes the
  `Listener`; each in-flight `handleConn` goroutine closes its
  connection on context cancel, which makes the `bufio.Scanner` exit.
  All `handleConn` goroutines are joined through a `sync.WaitGroup`
  before `Run()` returns.
- `Close()` is a no-op — listener lifetime is owned by the context.

This makes the source safe to embed in a supervisor that cancels the
context on process shutdown; in-flight connections are unblocked
promptly and the run loop exits cleanly.

---

## Quick-Start Examples

The following snippets are self-contained, copy-pasteable fragments for
`inputs[]`. Each one assumes the rest of the ArxSentinel stream
configuration is in place.

### UDP syslog on port 5514

```yaml
inputs:
  - type: syslog
    addr: "udp://:5514"
    parser: combined
```

### TCP syslog on port 514

```yaml
inputs:
  - type: syslog
    addr: "tcp://:514"
    parser: combined
```

### Unix domain stream socket

```yaml
inputs:
  - type: syslog
    addr: "unix:///var/run/arx.sock"
    parser: combined
```

### Unix domain datagram socket

```yaml
inputs:
  - type: syslog
    addr: "unixgram:///tmp/arx.sock"
    parser: combined
```

---

## Limitations

- **No TLS.** Syslog is plaintext on the wire. For secure transport,
  use TCP and front it with `stunnel` / `tailscale` / a VPN, or send
  to a local Unix socket.
- **Push only.** The source always listens — there is no pull mode for
  syslog.
- **Stream buffer cap.** `bufio.Scanner` is configured with a 65536
  byte buffer, which is the maximum line length accepted over TCP and
  Unix stream transports. Longer lines are truncated at the scanner
  boundary and counted as a parse error.
- **RFC 5424 structured data** is read as a single token from `[` to
  the first `]`. Nested `[…]` blocks are not supported.
- **Stale Unix sockets.** The source does not pre-`unlink()` the socket
  path. Remove a stale socket file with `rm -f` before starting
  ArxSentinel if a previous run died uncleanly.

---

## Dependencies

Standard library:

- `bufio` — line scanner for TCP/Unix stream connections.
- `context` — cancellation propagation.
- `fmt` — error and log message formatting.
- `net` — network listeners (`ListenPacket`, `Listen`, `Accept`, `Conn`).
- `strings` — address parsing (`strings.Cut`).
- `sync` — `WaitGroup` for joining in-flight `handleConn` goroutines.
- `sync/atomic` — counters (`linesRead`, `parseErrors`, `dropped`).

Project:

- `pkg/plugin` — `Source`, `Manifest`, `SourceStats`, `LogEntry`.
- `pkg/source` — registry (`Register`, `RegisterManifest`, `InputConfig`,
  `BuildOptions`, `LineParser`).
