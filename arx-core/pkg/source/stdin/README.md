# `pkg/source/stdin`

Stdin source for `arx-core`. Reads newline-delimited log lines from an
`io.Reader` (production: `os.Stdin`), parses each line through the
configured `Parser`, and forwards the resulting `*parser.LogEntry` to
the pipeline via a non-blocking send. Designed for pipe mode
(`docker logs … | arx run --config …`) and for container deployments
where an external orchestrator feeds logs through the process standard
input (k8s sidecar, `docker run` with a stdin pipe). The scanner uses a
64 KB line buffer; lines longer than that are reported as a scanner
error and `Run()` returns it.

## Public API

```go
// StdinSource — bufio.Scanner over an injected reader; implements
// plugin.Source. Run completes on EOF or context cancellation;
// both are normal exits.
type StdinSource struct { /* unexported */ }

// NewStdinSource — production constructor. Wires os.Stdin as the reader.
// parser (arx-core/pkg/parser) must be configured at the stream level.
// logFn is nil-safe — nil falls back to an internal no-op.
func NewStdinSource(p parser.Parser, logFn func(tag, msg, level string)) *StdinSource

// NewStdinSourceWithReader — test constructor. Injects any io.Reader
// (typically bytes.Buffer / strings.Reader in unit tests) so unit tests
// never touch os.Stdin. Production code paths always go through
// NewStdinSource.
func NewStdinSourceWithReader(r io.Reader, p parser.Parser, logFn func(tag, msg, level string)) *StdinSource

// plugin.Source interface — implemented by StdinSource.
func (s *StdinSource) Name() string                       // returns "stdin"
func (s *StdinSource) Run(ctx context.Context, out chan<- *plugin.Event) error
func (s *StdinSource) Close() error                      // no-op: os.Stdin is owned by the process
func (s *StdinSource) Stats() plugin.SourceStats         // LinesRead / ParseErrors / Dropped
```

The source registers itself as `type: stdin` via `init()`; the input
`cfg` is not consulted — the stdin source has no per-input fields
beyond `type`. On context cancellation the main loop closes the
underlying `*os.File` (when the reader is one) to unblock the scanner
goroutine, then returns `nil`.

## Example

Pipe `docker logs` into `arx-core` for a streaming tail of a single
container's output:

```bash
docker logs -f nginx | arx run --config config.yml
```

```yaml
inputs:
  - type: stdin
parser:
  log_format: nginx
```
