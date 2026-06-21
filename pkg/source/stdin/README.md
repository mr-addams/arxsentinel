# `pkg/source/stdin` — Stdin Source

Stdin source plugin for ArxSentinel. Reads newline-delimited log lines from
`os.Stdin`, parses each line through the configured `parser.Parser`, and
forwards the resulting log entry to the pipeline. Designed for the pipe mode
of the agent (`docker logs … | arxsentinel …`) and for container deployments
where an external orchestrator feeds logs in through the process standard input
(k8s sidecar, `docker run` with a stdin pipe, etc.).

- **Plugin ID:** `stdin`
- **Plugin version:** `1.0.0`
- **Role:** `Source`
- **Input type:** `none`
- **Output type:** `structured`
- **Tags:** `stdin`, `pipe`

## Module Layout

```
pkg/source/stdin/
├── manifest.go    # Plugin metadata
└── source.go      # StdinSource — main implementation
```

---

## Modes

The stdin source has a single code path. The distinction between **pipe
mode** and **container mode** is purely about who writes into the process
standard input — the source itself behaves identically in both cases.

### Pipe Mode (default)

The agent is launched as the right-hand side of a shell pipeline. The
upstream process produces log lines on its standard output and they are
streamed into the agent's standard input.

```bash
docker logs -f nginx | arxsentinel run --config config.yml
```

### Container Mode

The agent runs inside a container, and an external orchestrator
(kubernetes sidecar, a parent process in a `docker run` invocation with
a bind-mounted pipe, etc.) feeds log lines into the agent's standard
input. The data path is the same: `os.Stdin` → `bufio.Scanner` →
`parser.Parser` → pipeline.

---

## Configuration Reference

Inputs are declared under `inputs[]` in the stream configuration. The
stdin source has a single configurable field:

| Field  | Type     | Default | Required | Description        |
|--------|----------|---------|----------|--------------------|
| `type` | `string` | —       | **yes**  | Must be `"stdin"`. |

The `parser` is configured at the stream level under `parser.log_format`
and is inherited by the source — the stdin source itself has no parser
selector of its own.

### Validation Rules

- A non-`stdin` `type` produces a startup error:
  `inputs[%d]: unknown type %q (want file, stdin, exec, syslog, or http)`.

---

## Behaviour Details

### Run Loop

`Run(ctx context.Context, out chan<- *plugin.LogEntry) error` runs the
source until EOF or context cancellation:

1. A `bufio.Scanner` is created with a `64 KB` buffer
   (`stdinScanBufSize`).
2. A scanner goroutine is spawned: it reads lines from stdin into an
   internal `scanCh` (buffered, capacity `1000` = `defaultLinesBufSize`)
   and forwards scanner errors into a single-slot `errCh`.
3. The main select-loop reacts to three channels plus `ctx.Done()`:
   - **`ctx.Done()`** — calls `Close()` on the underlying `*os.File` to
     unblock the scanner goroutine, then returns `nil`.
   - **`line, ok := <-scanCh`** — `!ok` means the scanner reached EOF;
     the function returns `nil`. Otherwise the line is processed as
     below.
   - **`err := <-errCh`** — the error is logged and returned.

### Per-Line Processing

For every line received from `scanCh`:

- `par.Parse(line)` is invoked. On `ok == true`, the resulting log
  entry is offered to the downstream `out` channel via a
  **non-blocking send**. If the channel is full, the entry is dropped
  and the `dropped` counter is incremented.
- On `ok == false`, the line is malformed from the parser's point of
  view: `parseErrors` is incremented and a log entry
  (`"skipping malformed line: %.80s"`) is emitted, then the loop
  continues with the next line.

### Drop Policy

Sends to the `out` channel are non-blocking. When the channel is at
capacity (`1000`), the entry is discarded and the `dropped` counter
is incremented. There is no backpressure on the producer — stdin
throughput is decoupled from downstream consumption.

### Scanner Buffer

The `bufio.Scanner` is configured with a `64 KB` line buffer
(`stdinScanBufSize`). Lines longer than this trigger a `bufio.ErrTooLong`
that is forwarded through `errCh` and terminates `Run()` with an error.

### Internal Constants

| Constant               | Value | Purpose                                                                 |
|------------------------|-------|-------------------------------------------------------------------------|
| `stdinScanBufSize`     | 65536 | Maximum line length accepted by the `bufio.Scanner`.                    |
| `defaultLinesBufSize`  | 1000  | Capacity of the internal `scanCh` line channel and the `out` channel.  |

---

## EOF and Cancellation

The source has three exit paths, all clean:

- **EOF** — the scanner finishes reading stdin and closes `scanCh`. The
  main loop observes `ok == false` on the next receive and returns
  `nil`. EOF is treated as a normal exit, not an error.
- **Context cancellation** — `ctx.Done()` fires. The main loop calls
  `Close()` on the `*os.File` backing `os.Stdin`, which unblocks the
  scanner goroutine. The goroutine drains the rest of its buffer and
  exits, `Run()` returns `nil`. When the reader is not an `*os.File`
  (test scenarios using `NewStdinSourceWithReader`), `Close()` is a
  no-op and the scanner goroutine reads to the end of its input.
- **Scanner error** — a `bufio.ErrTooLong` or any other scanner error
  is forwarded through `errCh`, logged, and `Run()` returns the error.

### Close()

`Close()` is a **no-op** on the `StdinSource`. The process standard
input is owned by the process, not by the source, and must remain
open for the lifetime of the agent.

---

## Metrics and Stats

The source exposes three runtime counters via
`Stats() plugin.SourceStats`:

| Counter       | Type   | Description                                            | Incremented when                                                                                  |
|---------------|--------|--------------------------------------------------------|---------------------------------------------------------------------------------------------------|
| `linesRead`   | int64  | Lines successfully forwarded to the pipeline.          | The non-blocking send on `out` succeeds (parser returned `ok` and the channel accepted the entry).|
| `parseErrors` | int64  | Lines that the parser could not interpret.             | `par.Parse(line)` returns `ok == false`; the line is logged and skipped.                          |
| `dropped`     | int64  | Entries dropped because downstream capacity was exceeded. | The non-blocking send on `out` falls into the `default` branch (the channel is full).             |

All three counters are updated with `sync/atomic` and are safe to
read from the metrics endpoint without taking a lock.

---

## Constructors

Two constructors are exposed for the same `StdinSource` type:

```go
// Production: reads from os.Stdin.
func NewStdinSource(p parser.Parser, logFn func(tag, msg, level string)) *StdinSource

// Testable: injects any io.Reader. Used by unit tests.
func NewStdinSourceWithReader(r io.Reader, p parser.Parser, logFn func(tag, msg, level string)) *StdinSource
```

The production constructor wires `os.Stdin` as the reader; the testable
constructor lets callers pass an arbitrary `io.Reader` (typically a
`bytes.Buffer` or `strings.Reader`) without ever touching the real
process standard input.

Both constructors accept a nil-safe `logFn`. When `nil`, the source
becomes silent (`nil → no-op` per the
`pkg/source.registry.BuildOptions.LogFn` contract; previously `nil →
utils.Log` — see Flow 072 Task 1.2.5).

---

## Registration

The plugin is registered in `init()`:

```go
pkgsource.Register("stdin", func(cfg pkgsource.InputConfig, opts pkgsource.BuildOptions) (plugin.Source, error) {
    return NewStdinSource(opts.Parser, opts.LogFn), nil
})
pkgsource.RegisterManifest("stdin", (&StdinSource{}).Manifest())
```

The builder receives the stream-level `Parser` and `LogFn` from
`BuildOptions`; the input `cfg` is not consulted (the stdin source
has no per-input configuration).

---

## Quick-Start Examples

The following snippets are self-contained, copy-pasteable fragments
for `inputs[]`. Each one assumes the rest of the ArxSentinel stream
configuration is in place.

### Pipe — `docker logs`

```yaml
inputs:
  - type: stdin
```

```bash
docker logs -f nginx | arxsentinel run --config config.yml
```

### Container — k8s sidecar / `kubectl logs`

```yaml
inputs:
  - type: stdin
```

```bash
kubectl logs -f pod-name | arxsentinel run --config config.yml
```

### With an explicit parser

When the stream-level `parser.log_format` is not set, the parser can
be specified alongside the input:

```yaml
inputs:
  - type: stdin

parser:
  log_format: nginx
```

---

## Dependencies

Standard library:

- `bufio` — line scanner.
- `context` — cancellation propagation.
- `fmt` — log message formatting.
- `io` — `io.Reader` for the testable constructor.
- `os` — `os.Stdin` and `*os.File` for `Close()`-on-cancel.
- `sync/atomic` — counters.

Project:

- `internal/core/parser` — `parser.Parser` with
  `Parse(line) → (*plugin.LogEntry, bool)`.
- `pkg/plugin` — `Source`, `Manifest`, `SourceStats`, `LogEntry`.
- `pkg/source` — registry (`Register`, `RegisterManifest`).

Note: `internal/sys/utils` is no longer imported by this package as of
Flow 072 Task 1.2.5 — the legacy `utils.Log` fallback was replaced with
a local no-op per the `pkg/source.registry.BuildOptions.LogFn` contract.
