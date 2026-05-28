# Executors

## What is an Executor

An **Executor** is a stateful enforcement action triggered by a scored threat event.
Executors are the last step in the pipeline — they run after all Sinks have written the event.

### Executor vs Sink

| Aspect | Sink | Executor |
|---|---|---|
| Role | Passive — writes event data to a destination (file, syslog, Elastic) | Active — manages an external resource (API, firewall, blocklist) |
| State | Stateless — each event is written and forgotten | Stateful — holds a dedup map, TTL timers, current ban list |
| Lifecycle | Open → Write → Close | Init (sync state) → Execute (with dedup) → Close (cleanup) |
| Backpressure | None — returns immediately after write | May block the pipeline goroutine; implementations should budget latency or queue internally |
| Error handling | Write error is logged, pipeline continues | Error is logged, `Errors` counter incremented, pipeline continues |

An Executor is responsible for:

- **Startup sync** — loading the current remote state (e.g., existing ban list from Cloudflare API).
- **Deduplication** — skipping IPs already banned so the external API is not called twice.
- **TTL management** — scheduling auto-reverse actions such as automatic unban after a configured duration.
- **Retry / circuit-breaker** — handling transient failures when calling the external API.

Examples of Executor use-cases:

- Blocking an IP via Cloudflare IP List API.
- Adding an IP to an nginx deny configuration and reloading.
- Calling a third-party SOAR/EDR API to tag an indicator.

---

## Registry

All executor implementations self-register in a central registry so the pipeline can
instantiate them by name from YAML config without a hard-coded factory list.

### Package

```
pkg/executor/
└── registry.go       — Register, Build, Names, types
```

The registry lives in `pkg/executor` and imports **only** `pkg/plugin` and
`pkg/execplugin`. It does **not** import anything from `internal/` — external
developers can use the same registry for custom executors outside the main module.

### Register

Each executor implementation calls `Register` from its `init()`:

```go
func Register(name string, f Factory)
```

- `name` — the executor type name used in YAML config (`type: cloudflare`).
- `f` — a factory function with the signature `func(cfg ExecutorConfig) (plugin.Executor, error)`.

Duplicated registration panics at startup — this is a programmer error and must
be caught during development.

### Build

```go
func Build(cfg ExecutorConfig) (plugin.Executor, error)
```

`Build` looks up `cfg.Type` in the registry and calls its factory.
If the type is **not** found but `cfg.Exec` is non-empty, Build falls back to
`execplugin.NewExecutor` — this creates an `ExecExecutor` that runs an external
plugin binary. This allows users to add executors without recompiling the binary.

If the type is unknown **and** `cfg.Exec` is empty, Build returns an error.

### ExecutorConfig

```go
type ExecutorConfig struct {
    Name   string                 `yaml:"name"`
    Type   string                 `yaml:"type"`
    Exec   string                 `yaml:"exec"`    // binary path for ExecExecutor fallback
    Params map[string]interface{} `yaml:"params"`  // CLI flags for ExecExecutor
    Config map[string]interface{} `yaml:"config"`  // implementation-specific settings
}
```

`Config` is a raw `map[string]any` so `pkg/executor` has no import dependency on
any executor implementation. Each factory parses this map itself.

### Names

```go
func Names() []string
```

Returns a sorted list of all registered type names. Useful for diagnostics and
help text.

---

## Built-in Executors

| Name | Package | Description |
|---|---|---|
| `cloudflare` | `internal/core/executor/cloudflare` | Manages Cloudflare IP Lists — adds or removes IPs via the Cloudflare API. Supports dedup (skips already-banned IPs), TTL-based auto-unban, and configurable zone/account targets. |

---

## Adding a Custom Executor

Follow this checklist to add a new executor type:

### Step 1 — Implement the interface

Create a new package (recommended: `internal/core/executor/<name>/` for internal executors)
and implement `plugin.Executor`:

```go
type Executor interface {
    Name() string
    Execute(ctx context.Context, event plugin.ThreatEvent) error
    Close() error
    Stats() plugin.ExecutorStats
}
```

- `Name` — returns the executor instance name (from config, not the type).
- `Execute` — receives a fully scored `ThreatEvent`. Returns an error on failure.
- `Close` — clean up resources (close connections, cancel timers).
- `Stats` — returns `ExecutorStats{Executed, Skipped, Errors}` for pipeline-level metrics.

### Step 2 — Register via init()

In your package, add a `register.go` file that calls `executor.Register` from `init()`:

```go
package myexecutor

import (
    "github.com/mr-addams/arxsentinel/pkg/executor"
    "github.com/mr-addams/arxsentinel/pkg/plugin"
)

func init() {
    executor.Register("myexecutor", newFactory)
}

type MyConfig struct {
    APIKey  string `yaml:"api_key"`
    Timeout int    `yaml:"timeout"`
}

func newFactory(cfg executor.ExecutorConfig) (plugin.Executor, error) {
    // parse cfg.Config into MyConfig
    // return your executor instance
}
```

Registry panics on duplicate name — if two packages register the same type name,
the binary will not start. Choose a unique name.

### Step 3 — Add type to config

Add the executor to your YAML config under the `executors:` section:

```yaml
executors:
  - name: my-blocker
    type: myexecutor
    config:
      api_key: "${MY_API_KEY}"
      timeout: 30
```

### Step 4 — Blank import in main.go

Import the executor package with a blank identifier so its `init()` runs:

```go
package main

import (
    // ... other imports ...

    _ "github.com/mr-addams/arxsentinel/internal/core/executor/cloudflare"
    _ "github.com/mr-addams/arxsentinel/internal/core/executor/myexecutor"
)
```

Without the blank import, the `init()` function is never executed and the type
will not be registered, causing a runtime error `"unknown executor type"`.

### Alternative: ExecExecutor (no recompile)

If you cannot recompile the binary, configure an ExecExecutor by setting the
`exec` field instead of `type`:

```yaml
executors:
  - name: my-script
    exec: /usr/local/bin/my-blocker.sh
    params:
      --api-key: "${MY_API_KEY}"
```

The pipeline will run the binary as a subprocess, passing the event as stdin.
No Go code or recompilation needed.
