# pkg/logger

Operational logger contract for `pkg/` libraries of `arx-core`. Removes
the `pkg -> internal/sys/utils` dependency that blocks publishing `pkg/`
as a standalone library (Flow 072, Decision 1).

## Boundary

- **Stdlib only.** No `internal/` imports, no arxsentinel vocabulary, no
  formatting/colors — all of that is the adapter's job.
- **Behaviour-preserving.** The `internal/sys/utils` adapter (Task 1.2.6)
  forwards calls to `utils.Log` byte-for-byte.

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
Values match `utils.Log`'s documented vocabulary
(`internal/sys/utils/logging.go` line 282). Plain strings so the adapter
forwards them unchanged.

## Default no-op

```go
type NopLogger struct{}
func (NopLogger) Log(string, string, string) {}
var Nop = NopLogger{}
```
`Nop` is the conventional no-op. `pkg/` factories must accept a
`Logger` and replace `nil` with `Nop` — never fall back to `utils.Log`.
That contract keeps `pkg/` independent of `internal/`.

## Usage

```go
import "github.com/mr-addams/arx-core/pkg/logger"

if log == nil { log = logger.Nop }
log.Log("EXECUTOR", "starting", logger.LevelInfo)
```

## Tests

`logger_test.go`: compile-time interface satisfaction; `Nop` does not
panic; `Level*` constants equal `utils.Log`'s strings (text-only read);
a recording implementation forwards arguments verbatim and in order.