# How to Write a New Plugin (Product Layer)

> **Core five-file pattern, registry / init+blank-import wiring, and
> plugin role contracts live in
> [`arx-core/docs/plugin-development.md`](https://github.com/mr-addams/arx-core/blob/v0.1.0/docs/plugin-development.md).**
> Read the core contract first, then come back here for the **product-side
> checklist** and the **MikroTik / Sentinel-source / Sentinel-sink
> walkthroughs** that are specific to ArxSentinel.

---

## Product-side plugin checklist

Before opening a PR for a new product plugin:

- [ ] **Role** — one of `source` / `processor` / `detector` / `executor` / `sink`.
      See the core contract for the role's interface and lifecycle.
- [ ] **Manifest** — `PluginID`, `PluginVersion`, `Role`, `InputType`, `OutputType`
      populated. Add `Produces` / `Consumes` field declarations if your plugin
      has a non-trivial field contract.
- [ ] **Config** — struct with `yaml` tags and `DefaultConfig()`. `parseConfig`
      falls back safely on missing or wrongly-typed values.
- [ ] **Impl** — implements the correct interface from `github.com/mr-addams/arx-core/pkg/plugin/`.
      For detectors: `Detect(sv IPView, entry *plugin.Event) DetectResult`.
      For sinks: `Write(ctx, *plugin.Event) error`. For executors:
      `Run(ctx, EventSource) error` and type-asserts `event.Payload` to
      its product-owned type.
- [ ] **Register** — `init()` calls the role's `Register(name, factory)` (and
      optionally `RegisterManifest(name, manifest)`).
- [ ] **Blank import** — for `arx-core` plugins: included in the host's
      blank-import list. For product plugins: included in
      `cmd/arxsentinel/plugins_full.go` AND `profiles/full.yaml`.
- [ ] **Tests** — at minimum: Manifest contract + one happy-path test per
      exported method. Detectors should test against a mock `IPView`.
      Sinks/executors should test against a real `*plugin.Event` (Envelope +
      a product-owned payload, e.g. `&threat.ThreatEvent{...}`).
- [ ] **Boundary rule** — the package does NOT import `github.com/mr-addams/arx-core/pkg/plugin`
      types that are not in the published contract (e.g. `plugin.LogEntry` /
      `plugin.ThreatEvent` — those types do not exist; payload is opaque).
- [ ] **Build profile** — for any new source/sink/executor/processor, add
      an entry to `profiles/full.yaml` AND to `cmd/arxsentinel/plugins_full.go`,
      then run `bash scripts/check-build-profiles.sh`.

### Verify before commit

```bash
# Build the binary
go build ./cmd/arxsentinel

# Run the full test suite
go test ./...

# Validate profile ↔ plugin drift
bash scripts/check-build-profiles.sh

# Validate config (for any new executor/sink/source)
./arxsentinel validate --config=/etc/arxsentinel/config.yaml
# Expected:
# ✓ pipeline 'default' — valid (no semantic errors)
```

If a plugin is not found at runtime, check:

1. Blank import is present in `cmd/arxsentinel/plugins_full.go`.
2. `init()` in `register.go` calls the correct registry function.
3. The build succeeded with `go build`.
4. The YAML config uses the exact `PluginID` string from `Manifest.PluginID`.

---

## Walkthrough: MikroTik Executor (product example)

The MikroTik executor (`pkg/executorplugins/mikrotik/`) is the canonical
example of a product-side executor: it reads `*plugin.Event` from NCS,
type-asserts `event.Payload` to `*threat.ThreatEvent`, calls MikroTik
REST API to add the IP to a firewall address-list, and runs a TTL sweep
goroutine for auto-unban.

### manifest.go

```go
// pkg/executorplugins/mikrotik/manifest.go
package mikrotik

import "github.com/mr-addams/arx-core/pkg/plugin"

func (e *Executor) Manifest() plugin.Manifest {
    return plugin.Manifest{
        PluginID:      "mikrotik",
        PluginVersion: "1.0.0",
        Role:          plugin.RoleExecutor,
        InputType:     plugin.TypeScoredEvent,
        OutputType:    plugin.TypeNone,
        Tags:          []string{"firewall", "ban", "routeros"},
    }
}
```

### config.go (excerpt)

```go
type Config struct {
    Address   string        `yaml:"address"`     // 10.99.99.1
    Username  string        `yaml:"username"`
    Password  string        `yaml:"password"`    // "${MIKROTIK_PASSWORD}"
    List      string        `yaml:"address_list"`
    TTL       time.Duration `yaml:"ttl"`
    Timeout   time.Duration `yaml:"timeout"`
    MinLevel  string        `yaml:"min_level"`   // skip "" (no event) entries
}
```

### impl.go (excerpt — Run loop)

```go
func (e *Executor) Run(ctx context.Context, source plugin.EventSource) error {
    // Startup sync: load current address-list, prime dedup map.
    if err := e.syncRemoteState(ctx); err != nil {
        e.log("startup sync failed: %v", err)
        // continue anyway — better partial dedup than no enforcement
    }

    // TTL sweep goroutine: auto-unban after expiry.
    go e.ttlSweep(ctx)

    for {
        ev, err := source.Pop(ctx)
        if err != nil {
            if errors.Is(err, context.Canceled) { return nil }
            e.stats.Errors++
            continue
        }
        threat, ok := ev.Payload.(*threat.ThreatEvent)
        if !ok { continue }
        if !shouldAct(threat.Level, e.cfg.MinLevel) { e.stats.Skipped++; continue }

        if _, ok := e.dedup.LoadOrStore(threat.IP, time.Now()); ok {
            e.stats.Skipped++   // already banned
            continue
        }
        if err := e.addToAddressList(ctx, threat.IP); err != nil {
            e.dedup.Delete(threat.IP)
            e.stats.Errors++
            continue
        }
        e.stats.Executed++
    }
}
```

### register.go

```go
// pkg/executorplugins/mikrotik/register.go
package mikrotik

import (
    "github.com/mr-addams/arx-core/pkg/executor"
    "github.com/mr-addams/arx-core/pkg/plugin"
)

func init() {
    executor.Register("mikrotik", func(cfg executor.ExecutorConfig) (plugin.Executor, error) {
        return New(parseConfig(cfg.Params))
    })
    executor.RegisterManifest("mikrotik", (&Executor{}).Manifest())
}
```

### Blank import + profile entry

```go
// cmd/arxsentinel/plugins_full.go
import (
    _ "github.com/mr-addams/arxsentinel/pkg/executorplugins/mikrotik"
)
```

```yaml
# profiles/full.yaml
plugins:
  executors:
    - { name: mikrotik, module: arxsentinel }
```

### Tests (excerpt)

Place `impl_test.go` next to `impl.go`. Mock the HTTP client and assert
on RouterOS API call shape. See
`pkg/executorplugins/mikrotik/mikrotik_test.go` for a working example
that uses `httptest.NewServer`.

---

## Walkthrough: Sentinel source/sink (NCS bridge)

The sentinel source/sink pair (`github.com/mr-addams/arx-core/pkg/source/sentinel/`,
`github.com/mr-addams/arx-core/pkg/sink/sentinel/`) wire two ArxSentinel pipelines together
through NCS. The detector pipeline writes scored events into a named
queue via `sentinel-threat` sink; another pipeline reads them via
`sentinel` source and forwards to executors.

### Detector-side config (writes to NCS)

```yaml
streams:
  - name: detector
    pipelines:
      - name: p0
        inputs:  [{ type: file, path: /var/log/nginx/access.log }]
        detectors: { probe: {enabled: true} }
        outputs: [{ type: sentinel-threat, name: cf-threats }]   # NCS queue name
```

### Executor-side config (reads from NCS)

```yaml
streams:
  - name: executor
    pipelines:
      - name: p0
        inputs: [{ type: sentinel, addr: ncs://cf-threats }]     # same queue name
        outputs: []   # executors consume in-process via EventSource
executors:
  - name: cf-ban
    type: cloudflare
    sources: [{ name: cf-threats }]                              # same queue name
```

Both pipelines (or both processes) share the NCS queue (memory / bbolt /
redis backend). The `sentinel` source emits `*plugin.Event` with
`json.RawMessage` payload; the executor type-asserts to `*threat.ThreatEvent`.

---

## See also

- [`arx-core/docs/plugin-development.md`](https://github.com/mr-addams/arx-core/blob/v0.1.0/docs/plugin-development.md) — full plugin contract.
- [`docs/PLUGIN_DEV.md`](../PLUGIN_DEV.md) — Sink-vs-Executor, exec+JSON, product walkthroughs.
- [`docs/executors.md`](../executors.md) — executor framework overview.
- [`docs/developer/build-profiles.md`](build-profiles.md) — tree-shaking, `arx_tag` sentinel.
- [`pkg/executorplugins/`](../../pkg/executorplugins/) — reference implementations (cloudflare, mikrotik, nginx).
- [`arx-core/pkg/source/sentinel/README.md`](https://github.com/mr-addams/arx-core/blob/v0.1.0/pkg/source/sentinel/README.md),
  [`arx-core/pkg/sink/sentinel/README.md`](https://github.com/mr-addams/arx-core/blob/v0.1.0/pkg/sink/sentinel/README.md) — NCS bridge.
