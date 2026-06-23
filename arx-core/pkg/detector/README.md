# pkg/detector — Detector plugin registry

Central registry, shared types, and parameter helpers for detector plugins
of the arx-core framework. Each detector self-registers via `init()` so the
pipeline can instantiate detectors by name from configuration without a
hard-coded factory list. Detectors are **stateless** — all per-IP state is
passed to each `Detect` call through `plugin.IPView` (see `pkg/plugin`).

The package depends only on `pkg/plugin`, `pkg/execplugin`, and
`pkg/pluginregistry`. It does **not** import anything from a product layer,
so it can be used as a standalone library.

## Package Layout

```
pkg/detector/
├── registry.go       # Registry (Register / Build / Names),
│                     # shared types (DetectorConfig, Matcher, SharedResources),
│                     # and Factory
├── params.go         # Exported helpers for parsing detector config:
│                     # GetInt / GetFloat64 / GetBool / GetDuration / GetStrings
└── registry_test.go  # Registry-infra tests: Names, Disabled, Unknown
```

## Sub-packages (detectors)

Each detector lives in its own sub-package so that build profiles can
exclude unused detectors from the resulting binary (tree-shaking).

The convention is:

- `<name>.go` — detector type, factory function, and `init()` calling
  `detector.Register("<name>", …)`.
- `manifest.go` — `Manifest()` method on the detector type, returning
  `plugin.Manifest`.
- `<name>_test.go` — unit tests for the detector plus registry smoke tests.

Build profiles wire selected sub-packages via blank-import in their
profile file. Detectors not imported by the profile are dropped by the
Go linker. The YAML `name:` field must match the registered name 1:1.

> Note: the example detector set shipped with the arx-core reference
> product (a security log aggregator) covers categories such as
> `probe`, `rate`, `bruteforce`, `crawler`, `noasset`, `badbot`,
> `overflow`, and `useragent`. Detector names and sub-package names
> are not required to follow this scheme in third-party projects.

## Wire-up (blank-import pattern)

```go
//go:build minimal
package main

import _ "example.com/myapp/pkg/detector/probe"
import _ "example.com/myapp/pkg/detector/rate"
```

If the build profile does not blank-import a detector sub-package, the
Go linker will not include that detector in the resulting binary.

## Core Types (`registry.go`)

```go
type DetectorConfig struct {
    Enabled bool
    Params  map[string]interface{}  // captures all YAML fields except enabled/exec
    Exec    string                  // path to an external exec-plugin binary
}

type Matcher interface {
    Match(list string, text string) bool
    MatchResult(list string, text string) (string, bool)
}

type SharedResources interface {
    Blocklist() Matcher
}

type Factory func(cfg DetectorConfig, shared SharedResources) (plugin.Detector, error)
```

- `Enabled == false` → `Build` returns `(nil, nil)`.
- `Params` holds every YAML key that is not `enabled` or `exec`. Detectors
  extract typed values via the helpers from `params.go`.
- `Matcher` is duck-typed — any concrete blocklist manager that exposes
  the two methods satisfies it implicitly, with no explicit import.
- `SharedResources` is used by detectors that need external runtime state.

### Registry API

```go
func Register(name string, f Factory)
func Build(ctx context.Context, name string, cfg DetectorConfig, shared SharedResources) (plugin.Detector, error)
func Names() []string
```

- `Register` panics on a duplicate name — duplication is a programmer
  error that must surface at startup.
- `Build` returns `(nil, nil)` for a disabled detector, a live detector
  for a registered name, an exec wrapper for an unknown name with
  `cfg.Exec != ""`, or an error otherwise.
- `Names` returns a sorted slice of all registered names.

### Exec fallback

If a name is not registered but `cfg.Exec` is set, `Build` delegates to
`pkg/execplugin` and returns a wrapper that invokes the external binary
on every `Detect` call. This lets operators ship arbitrary detectors
without recompiling the host process.

### Thread safety

The factory map is guarded by a `sync.RWMutex`. `Names()` and `Build()`
take the read lock; `Register()` takes the write lock. `Register` is
intended to be called from `init()`; the mutex also covers any future
dynamic-registration path and keeps the race detector quiet.

## Parameter helpers (`params.go`)

All helpers operate on `DetectorConfig.Params` and return `defaultVal`
when the key is absent or the value type cannot be converted. Silent
degradation is intentional: a misconfigured detector must not bring
down the whole host process.

### `GetInt`

```go
func GetInt(cfg DetectorConfig, key string, defaultVal int) int
```

Accepts `int`, `int64`, and `float64` (YAML sometimes produces
`float64` for whole numbers). Returns `defaultVal` when the key is
absent or the type does not match.

### `GetFloat64`

```go
func GetFloat64(cfg DetectorConfig, key string, defaultVal float64) float64
```

Accepts `float64`, `int`, and `int64`. Returns `defaultVal` on missing
key or wrong type.

### `GetBool`

```go
func GetBool(cfg DetectorConfig, key string, defaultVal bool) bool
```

Accepts `bool` only. Returns `defaultVal` on missing key or wrong type.

### `GetDuration`

```go
func GetDuration(cfg DetectorConfig, key string, defaultVal time.Duration) time.Duration
```

Accepts:

- `string` — parsed via `time.ParseDuration` (for example `"30s"`,
  `"1m"`, `"500ms"`).
- `int`, `int64`, `float64` — interpreted as a duration in nanoseconds.

Returns `defaultVal` on missing key, unknown type, or parse error.

### `GetStrings`

```go
func GetStrings(cfg DetectorConfig, key string, defaultVal []string) []string
```

Accepts:

- `[]string` — returned as-is.
- `[]interface{}` — each element cast to `string`; non-string items
  are skipped.

Returns `defaultVal` on missing key or wrong type.

## Usage example

```go
import (
    "github.com/mr-addams/arx-core/pkg/detector"
    "github.com/mr-addams/arx-core/pkg/plugin"
)

// In a custom detector's init():
func init() {
    detector.Register("rate", NewRateDetector)
}

func NewRateDetector(cfg detector.DetectorConfig, shared detector.SharedResources) (plugin.Detector, error) {
    window := detector.GetDuration(cfg, "window", time.Minute)
    threshold := detector.GetInt(cfg, "threshold", 100)
    return &rateDetector{window: window, threshold: threshold}, nil
}

// In the pipeline:
det, err := detector.Build(ctx, "rate", detector.DetectorConfig{
    Enabled: true,
    Params:  map[string]interface{}{"threshold": 250},
}, sharedResources)
if det == nil {
    // Disabled — skip silently.
}
```
