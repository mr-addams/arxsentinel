# pkg/logger

Operational logger contract for libraries in the `arx-core` framework.
This is the single `Logger` interface that `pkg/` packages depend on,
so any `pkg/` library stays decoupled from the host application's
logging implementation and can be embedded in third-party products.

## Boundary

- **Stdlib only.** No product-internal imports, no product-specific
  vocabulary, no formatting, no colours — all of that is the host
  adapter's job.
- **Behaviour-preserving.** A host adapter forwards `Log` calls to the
  product's existing logger without translation or filtering.

## Interface

```go
type Logger interface {
    Log(tag, msg, level string)
}
```

## Level constants

```go
const (
    LevelDebug   = "debug"
    LevelInfo    = "info"
    LevelWarning = "warning"
    LevelError   = "error"
)
```

Values are plain strings so a host adapter can forward them unchanged
to whatever logging backend the host application uses.

## Default no-op

```go
type NopLogger struct{}
func (NopLogger) Log(string, string, string) {}
var Nop = NopLogger{}
```

`Nop` is the conventional zero-cost no-op. `pkg/` factory constructors
must accept a `Logger` and replace `nil` with `Nop` instead of falling
back to a host-application global logger. That contract keeps `pkg/`
independent of the host.

## Usage

```go
import "github.com/mr-addams/arx-core/pkg/logger"

if log == nil {
    log = logger.Nop
}
log.Log("EXECUTOR", "starting", logger.LevelInfo)
```

## Custom adapter example

```go
type StdLogger struct{ Out io.Writer }

func (l StdLogger) Log(tag, msg, level string) {
    fmt.Fprintf(l.Out, "%s [%s] %s: %s\n", level, tag, level, msg)
}

var _ logger.Logger = StdLogger{}
```

A product that wants structured logging or colour-coded output wraps
this interface with its own adapter; `pkg/` libraries remain agnostic.

## Tests

`logger_test.go` covers:

- Compile-time interface satisfaction.
- `Nop` does not panic and performs no observable work.
- `Level*` constants match the documented vocabulary.
- A recording implementation forwards arguments verbatim and in order.
