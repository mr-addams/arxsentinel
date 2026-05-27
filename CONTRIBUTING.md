# Contributing to ArxSentinel

Thank you for your interest in contributing!

## Ways to contribute

- **Bug reports** — open an issue using the Bug Report template
- **Feature requests** — open an issue using the Feature Request template
- **Pull requests** — fixes, new detectors, package support, documentation

## Before you start

- Check [open issues](https://github.com/mr-addams/arxsentinel/issues) to avoid duplicates
- For significant changes, open an issue first to discuss the approach

## Development setup

```bash
git clone https://github.com/mr-addams/arxsentinel
cd arxsentinel
go mod tidy
go build ./...
go test ./...
```

For end-to-end tests:

```bash
go test -tags e2e ./... -v
```

## Pull request guidelines

- One logical change per PR
- `go test ./...` must pass
- `go vet ./...` must be clean
- Follow existing code style — comments in English, no unnecessary abstractions
- Update `README.md` if the change affects user-facing behavior or config

## Adding a new detector

ArxSentinel uses a self-registration pattern via `init()` — no edits to `main.go` required.

### 1. Implement the `plugin.Detector` interface

Create `pkg/detector/yourdetector.go`:

```go
package detector

import (
    "github.com/mr-addams/arxsentinel/pkg/plugin"
)

type MyDetector struct {
    score int
}

func (d *MyDetector) Name() string { return "mydetector" }

func (d *MyDetector) Detect(sv plugin.IPView, entry *plugin.LogEntry) plugin.DetectResult {
    // sv gives read-only access to per-IP accumulated state
    // entry is the current log line
    if entry.Path == "/suspicious" {
        return plugin.DetectResult{Score: d.score, Module: "mydetector", Reason: "custom:1"}
    }
    return plugin.DetectResult{}
}
```

### 2. Register via `init()`

Add to the same file:

```go
import pkgdetector "github.com/mr-addams/arxsentinel/pkg/detector"

func init() {
    pkgdetector.Register("mydetector", func(cfg pkgdetector.DetectorConfig, shared pkgdetector.SharedResources) (plugin.Detector, error) {
        score := 25
        // YAML numbers are decoded as float64 via the inline map — cast accordingly.
        if v, ok := cfg.Params["score"].(float64); ok {
            score = int(v)
        }
        return &MyDetector{score: score}, nil
    })
}
```

### 3. Make the package importable

**Option A — separate package** (recommended for detectors you maintain separately):

Place code in `pkg/detector/mydetector/mydetector.go` (package `mydetector`), then
add a blank import to `cmd/arxsentinel/main.go` so `init()` runs at startup:

```go
import (
    _ "github.com/mr-addams/arxsentinel/pkg/detector/mydetector"
)
```

**Option B — same package** (for detectors kept in the main tree):

Place the file directly in `pkg/detector/yourdetector.go` (package `detector`).
The package is already imported by `main.go`, so `init()` runs automatically —
no extra import needed.

### 4. Add tests

Create `pkg/detector/yourdetector_test.go` with at minimum a happy-path test and one boundary case.

### 5. Document in README.md

Add a row to the **Detectors** table: name, description, key params.

### External detectors (no recompile)

For site-specific logic in any language, use the exec+JSON plugin protocol — see `docs/PLUGIN_DEV.md`.

## Coding style

- Go standard formatting (`gofmt`)
- Comments explain **why**, not what
- No unnecessary error wrapping for internal errors
- Prefer explicit over clever

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
