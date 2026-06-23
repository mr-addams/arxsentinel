# arx-core LogAggregator example

A non-security telemetry pipeline built purely on `arx-core/pkg/*`. The example
proves that the arx-core runtime is domain-agnostic: there is no scoring step,
no detector registry, no threat level — just a syslog listener that filters and
serializes access-log lines into a JSON-lines file.

The example defines its own payload type (`*LogRecord`) and never imports
anything from `arxsentinel/...`. The arx-core engine reads only
`Envelope.Level` for metrics; the rest of `Event.Payload` is opaque to it.

## What it does

```
syslog source          FilterProcessor            file sink
(pkg/source/syslog)    (LineProcessor + Factory)  (pkg/sink/file +
                          *LogEntry -> *LogRecord    *JSONFormatter)
       |                                                  ^
       +-- *plugin.Event (Payload=*LogEntry) --> *plugin.Event (Payload=*LogRecord)
```

1. The syslog source listens on a UDP/TCP/Unix socket and parses each incoming
   RFC 3164/5424 message with the `parser.CombinedParser`.
2. `FilterProcessor.Process` type-asserts the inbound `Event.Payload` to
   `*parser.LogEntry`, builds a product-shaped `*LogRecord`, applies the
   severity and substring gates, and emits a new `*plugin.Event` with
   `Payload = *LogRecord` and `Envelope.Level = record.Severity`.
3. The file sink calls `JSONFormatter.Format(event)`, which type-asserts
   `Payload` back to `*LogRecord` and writes one JSON object per line.

## Run

Listen on UDP `:5514` and write everything to `./logaggregator-out.json`:

```
go run . -addr udp://:5514 -out /tmp/logaggregator.json
```

Apply a minimum-severity gate and a substring filter:

```
go run . -addr udp://:5514 -severity WARN -substring /admin
```

Send a syslog message (use the BSD `logger` utility or `nc`):

```
logger -n localhost -P 5514 --rfc3164 -t test '127.0.0.1 - - [02/Apr/2026:00:26:49 +0000] "GET /admin HTTP/1.1" 403 42 "-" "-" "-"'
```

## What it illustrates

- **Generic engine.** The arx-core runtime drives a non-security pipeline
  (no threat, no scoring, no detectors) — proves the engine is
  domain-agnostic.
- **Opaque payload.** `*plugin.Event` carries an envelope (transport
  metadata) plus an opaque payload. The example defines its own `*LogRecord`
  payload and the engine never inspects it — only `Envelope.Level`.
- **Plugin wiring via blank-import.** Sources and sinks are wired through
  the arx-core registries (`pkg/source`, `pkg/sink`) — the example imports
  them via blank import, no custom registration glue.
- **Produce-and-consume pattern.** A `LineProcessor` (the filter)
  type-asserts the inbound payload to `*parser.LogEntry`, builds a
  product-specific `*LogRecord`, and emits a new `*plugin.Event` with that
  payload — the canonical contract for product-shaped processors.
- **Formatter ownership.** A `format.Formatter` (the JSON formatter)
  type-asserts `*LogRecord` and renders bytes — product owns the byte
  shape, core owns the sink loop.

## Module layout

| File                | Purpose                                                        |
| ------------------- | -------------------------------------------------------------- |
| `go.mod`            | Module `arx-core/examples/logaggregator`, replace into `../../` |
| `logrecord.go`      | Product-shaped payload type `LogRecord` (example-owned)        |
| `filter.go`         | `FilterProcessor` — `LineProcessorFactory` + `LineProcessor`    |
| `json_formatter.go` | `JSONFormatter` — `format.Formatter` impl rendering `*LogRecord`|
| `main.go`           | Flag parsing, source/sink assembly, `runtime.Run` invocation   |
| `README.md`         | This document                                                  |

## Build

```
cd arx-core/examples/logaggregator
go build ./...
```

## Boundary verification

Confirm the example has zero `arxsentinel` product imports:

```
go list -deps ./... | grep -i arxsentinel
```

The command must produce no output. If it does, an upstream refactor has
leaked a product path into the example's dependency closure.