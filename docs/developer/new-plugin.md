# How to Write a New Plugin

This guide covers the **manifest-based plugin framework** introduced in v2. Every plugin — Source, Processor, Detector, Executor, Sink — follows the same five-file structure.

---

## Choose a Role

| Role | When to use |
|---|---|
| `source` | You need to read data from an external system (file, syslog, HTTP poll, cloud API) |
| `processor` | You need to transform, enrich, or filter events in the middle of the pipeline |
| `detector` | You need to analyse an event against IP history and compute a threat score |
| `executor` | You need to perform an action when a threat is detected (block IP, send alert) |
| `sink` | You need to persist or forward threat events to external storage |

---

## Five Required Files

Every plugin must provide these files inside its package directory:

```
internal/core/<role>/<plugin-name>/
├── manifest.go     — identity and data contract
├── config.go       — configuration struct and defaults
├── impl.go         — core logic (implements the role interface)
├── register.go     — init() registration with the role registry
└── impl_test.go    — unit tests
```

### manifest.go

```go
// ========================== manifest =====================================
//   Identity and data contract for the Manifest framework.
package myplugin

import "github.com/mr-addams/arxsentinel/pkg/plugin"

// Manifest returns the plugin's identity and data contract.
func (p *MyPlugin) Manifest() plugin.Manifest {
    return plugin.Manifest{
        PluginID:      "my-plugin",
        PluginVersion: "1.0.0",
        Role:          plugin.RoleProcessor,
        InputType:     plugin.TypeStructured,
        OutputType:    plugin.TypeStructured,
    }
}
```

Fields:

| Field | Description |
|---|---|
| `PluginID` | Unique identifier used in YAML config (lowercase, hyphen-separated) |
| `PluginVersion` | Semantic version of the plugin |
| `Role` | One of `RoleSource`, `RoleProcessor`, `RoleDetector`, `RoleExecutor`, `RoleSink` |
| `InputType` | `DataType` the plugin expects to receive |
| `OutputType` | `DataType` the plugin produces |

### config.go

```go
// ========================== config =======================================
package myplugin

// Config holds user-configurable parameters for MyPlugin.
type Config struct {
    Threshold int    `yaml:"threshold"`
    Endpoint  string `yaml:"endpoint"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
    return Config{
        Threshold: 50,
        Endpoint:  "http://localhost:8080",
    }
}
```

### impl.go

Source template:

```go
// ========================== impl =========================================
package myplugin

import (
    "context"
    "github.com/mr-addams/arxsentinel/pkg/plugin"
)

// MySource reads data from a custom external source.
type MySource struct {
    cfg    Config
    name   string
    stats  plugin.SourceStats
}

func (s *MySource) Name() string                                   { return s.name }
func (s *MySource) Run(ctx context.Context, out chan<- *plugin.LogEntry) error { return nil }
func (s *MySource) Close() error                                   { return nil }
func (s *MySource) Stats() plugin.SourceStats                      { return s.stats }

// NewMySource creates a new MySource instance.
func NewMySource(name string, cfg Config) plugin.Source {
    return &MySource{name: name, cfg: cfg}
}
```

Processor template:

```go
// ========================== impl =========================================
package myplugin

import "github.com/mr-addams/arxsentinel/pkg/plugin"

type MyProcessor struct {
    cfg Config
}

func (p *MyProcessor) Name() string { return "my-processor" }
func (p *MyProcessor) Process(entry *plugin.LogEntry) (*plugin.LogEntry, error) { return entry, nil }
```

Detector template:

```go
// ========================== impl =========================================
package myplugin

import "github.com/mr-addams/arxsentinel/pkg/plugin"

type MyDetector struct{}

func (d *MyDetector) Name() string { return "my-detector" }
func (d *MyDetector) Detect(sv plugin.IPView, entry *plugin.LogEntry) plugin.DetectResult {
    return plugin.DetectResult{Score: 0, Module: d.Name(), Reason: ""}
}
```

Sink template:

```go
// ========================== impl =========================================
package myplugin

import "github.com/mr-addams/arxsentinel/pkg/plugin"

type MySink struct {
    cfg   Config
    stats plugin.SinkStats
}

func (s *MySink) Name() string { return "my-sink" }
func (s *MySink) Write(event plugin.ThreatEvent) error {
    s.stats.EventsWritten++
    return nil
}
func (s *MySink) Close() error { return nil }
func (s *MySink) Stats() plugin.SinkStats { return s.stats }
```

Executor template:

```go
// ========================== impl =========================================
package myplugin

import (
    "context"
    "github.com/mr-addams/arxsentinel/pkg/executor/queue"
)

type MyExecutor struct{}

func (e *MyExecutor) Run(ctx context.Context, q queue.Queue) error {
    for {
        event, err := q.Pop(ctx)
        if err != nil { return err }
        _ = event // perform action
    }
}
```

### register.go

```go
// ========================== register ====================================
package myplugin

import (
    "github.com/mr-addams/arxsentinel/pkg/plugin"
    "github.com/mr-addams/arxsentinel/pkg/processor"  // change registry per role
)

func init() {
    processor.Register("my-plugin", func(cfg map[string]interface{}) plugin.ManifestProcessor {
        return NewMyProcessor(parseConfig(cfg))
    })
}

func parseConfig(cfg map[string]interface{}) Config {
    c := DefaultConfig()
    if v, ok := cfg["threshold"].(int); ok { c.Threshold = v }
    if v, ok := cfg["endpoint"].(string); ok { c.Endpoint = v }
    return c
}
```

Import the correct registry package:

| Role | Registry package |
|---|---|
| Source | `github.com/mr-addams/arxsentinel/pkg/source` |
| Processor | `github.com/mr-addams/arxsentinel/pkg/processor` |
| Detector | `github.com/mr-addams/arxsentinel/pkg/detector` |
| Executor | `github.com/mr-addams/arxsentinel/pkg/executor` |
| Sink | `github.com/mr-addams/arxsentinel/pkg/sink` |

### impl_test.go

```go
// ========================== impl_test ===================================
package myplugin

import (
    "testing"
    "github.com/mr-addams/arxsentinel/pkg/plugin"
)

func TestManifest(t *testing.T) {
    p := NewMyPlugin(DefaultConfig())
    m := p.Manifest()
    if m.PluginID != "my-plugin" {
        t.Fatalf("expected 'my-plugin', got %q", m.PluginID)
    }
    if m.Role != plugin.RoleProcessor {
        t.Fatalf("expected RoleProcessor, got %v", m.Role)
    }
}

func TestProcess(t *testing.T) {
    // role-specific test logic
}
```

---

## Example: MikroTik Executor

The MikroTik executor (`internal/core/executor/mikrotik/`) is the reference implementation for an executor plugin:

- **manifest.go** — declares `RoleExecutor`, `InputType: TypeNone`, `OutputType: TypeNone`
- **config.go** — host, username, password (from env), address-list, ttl
- **impl.go** — `Run(ctx, queue.Queue)` pops events and calls MikroTik REST API to add an IP to the blocklist
- **register.go** — `executor.Register("mikrotik", factory)`
- **impl_test.go** — mock HTTP server tests for API calls

---

## Checklist Before PR

- [ ] **Manifest** — `PluginID`, `PluginVersion`, `Role`, `InputType`, `OutputType` are filled
- [ ] **Config** — struct with `yaml` tags and `DefaultConfig()` function
- [ ] **Impl** — implements the correct interface (`plugin.Source`, `plugin.Processor`, `plugin.Detector`, `plugin.Sink`, or executor's `Run(ctx, queue.Queue)`)
- [ ] **Register** — `init()` registers the plugin in the appropriate role registry
- [ ] **Tests** — at minimum: Manifest contract + one happy-path test per exported method
- [ ] **Blank import** — `_ "github.com/mr-addams/arxsentinel/internal/core/<role>/<name>"` added to `cmd/arxsentinel/main.go`

---

## Verify

```bash
# Build the binary
go build ./cmd/arxsentinel

# Validate the pipeline sees the new plugin
arxsentinel validate --config=/etc/arxsentinel/pipeline.yaml

# Expected output:
# ✓ pipeline 'default' — valid (no semantic errors)
```

If the plugin is not found, check:

1. Blank import is present in `main.go`
2. `init()` in `register.go` calls the correct registry function
3. The build succeeded with `go build`
4. The YAML config uses the exact `PluginID` string