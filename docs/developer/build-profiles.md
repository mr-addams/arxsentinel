# Build Profiles (Product Layer)

> **Generic build-profile mechanism (the `arx_tag` sentinel, schema, generator,
> verifier, tree-shaking semantics) lives in
> [`arx-core/docs/build-profiles.md`](https://github.com/mr-addams/arx-core/blob/v0.1.0/docs/build-profiles.md).**
> Read that document first if you are new to profiles.
>
> This document is the **product-layer companion**: the three profiles
> ArxSentinel ships (`full`, `minimal`, `iot`), how to author a custom
> product profile, and the ArxSentinel-specific always-linked components
> (detectors, Cloudflare executor, `pkg/sink/file`) that are outside
> the core tree-shaking contract.

## 1. Profiles shipped with ArxSentinel

Three profiles live in `profiles/`:

### `full` (default)

`profiles/full.yaml` — all 12 blank-import transports plus all 8 product
detectors, the Cloudflare/MikroTik/nginx executors, and the always-linked
components (blocklist, chaincheck, etc.). The build produced by plain
`go build ./...` with no tags. Use it when the binary runs on a normal
server with sufficient RAM and you want every integration available at
runtime via config alone.

Transports:

```yaml
# profiles/full.yaml (excerpt)
plugins:
  sources:
    - { name: exec,     module: arx-core }
    - { name: file,     module: arx-core }
    - { name: http,     module: arx-core }
    - { name: sentinel, module: arx-core }
    - { name: stdin,    module: arx-core }
    - { name: syslog,   module: arx-core }
  sinks:
    - { name: exec,            module: arx-core }
    - { name: sentinel-threat, module: arx-core }   # NCS bridge
    - { name: stdout,          module: arx-core }
  executors:
    - { name: mikrotik, module: arxsentinel }
    - { name: nginx,    module: arxsentinel }
  processors:
    - { module: arx-core }   # whitelist/chaincheck (always-linked, see below)
```

### `minimal`

`profiles/minimal.yaml` — log aggregation only: syslog + stdin sources
and a stdout sink, all from `arx-core`. No security detectors are removed
(they are always-linked, see [§3](#3-arxsentinel-specific-always-linked-components))
but no executors run either — nothing reacts to threats, the binary
only emits parsed log entries / threat events as JSON. Use it for a
forwarder sidecar that just re-shapes and forwards log streams.

### `iot`

`profiles/iot.yaml` — edge remediation: syslog + file sources, `exec`
sink (to trigger a local remediation script) plus `stdout` for visibility.
Use it on constrained devices where a full `full` build is too heavy
and you do want local remediation — the `exec` sink can call `iptables`
/ a MikroTik API client / an arbitrary remediation script.

## 2. How to create a custom product profile

A custom profile is created in four steps. The example below builds a
profile that only reads the HTTP push source and writes to stdout.

**Step 1 — declare the profile.** Create `profiles/custom-http.yaml`:

```yaml
name: custom-http
description: "HTTP push source only, stdout sink."
plugins:
  sources:
    - { name: http, module: arx-core }
  sinks:
    - { name: stdout, module: arx-core }
```

**Step 2 — run the generator.** The generator emits
`cmd/arxsentinel/plugins_custom_http.go` containing the blank-imports
for the profile under a `//go:build arx_tag && custom-http` constraint:

```bash
go generate ./cmd/arxsentinel/...
```

**Step 3 — run the verifier.** Catches declaration drift, missing
`Register` calls, and cookbook membership mismatches before you commit:

```bash
bash scripts/check-build-profiles.sh
```

**Step 4 — build with the sentinel tag.** See the core document for
**why `arx_tag` is mandatory**:

```bash
go build -tags "arx_tag custom-http" ./...
```

If everything is correct, the resulting binary contains only the
`http` source and the `stdout` sink (plus the always-linked detectors /
Cloudflare executor / `pkg/sink/file`, which profiles cannot remove —
see [§3](#3-arxsentinel-specific-always-linked-components)).

## 3. ArxSentinel-specific always-linked components

The core build-profile mechanism tree-shakes only the 12 transports
blank-imported in `cmd/arxsentinel/plugins_full.go`. Several ArxSentinel
components are outside its scope by design (see ADR-003 and Flow 075
DECISIONS.md Decisions 12–14):

- **Detectors (`pkg/detectorplugins/*`, 8 plugins)** — wired by named
  imports in `cmd/arxsentinel/{validate.go,builders.go}`. They are
  always-linked and all-or-nothing. Per-detector tree-shaking would
  require refactoring those files onto blank-import sub-packages plus a
  registry lookup — a future enhancement. The `detectors:` list in a
  profile YAML is documentation-only and is not verified.
- **Cloudflare executor (`pkg/executorplugins/cloudflare`)** — wired by
  a named import in `cmd/arxsentinel/cleanup.go` because the
  `arxsentinel cleanup` subcommand calls its API directly. Always-linked.
  Not part of build profiles.
- **`pkg/sink/file`** — wired by a named import in
  `internal/core/output/file.go` (the default fail2ban-format threat log).
  Always-linked. Not a profile transport.
- **`internal/core/processor/{chaincheck,whitelist}`** — not
  blank-imported in `cmd/arxsentinel/main.go`; called directly via
  `chaincheck.NewChecker()` from `securityState`. Pre-existing wiring
  choice, will be addressed by a separate fix task. They are NOT
  included in `profiles/full.yaml`.

For generic limitations and the `arx_tag` rationale, see
[`arx-core/docs/build-profiles.md` §5, §8](https://github.com/mr-addams/arx-core/blob/v0.1.0/docs/build-profiles.md).

## 4. Build commands

| Profile | Build | Test |
| --- | --- | --- |
| `full` (default) | `go build ./...` | `go test ./...` |
| `minimal` | `go build -tags "arx_tag minimal" ./...` | `go test -tags "arx_tag minimal" ./...` |
| `iot` | `go build -tags "arx_tag iot" ./...` | `go test -tags "arx_tag iot" ./...` |
| `<custom>` | `go build -tags "arx_tag <custom>" ./...` | `go test -tags "arx_tag <custom>" ./...` |

Always include `arx_tag`. Without it you silently get the full build
(`plugins_full.go` compiles because its constraint is `!arx_tag`).

## 5. Maintenance note — adding a new product plugin

When you add a new blank-import transport to ArxSentinel (a new
source / sink / executor / processor package that registers via
`init()` and is pulled in by `cmd/arxsentinel/main.go`), **two files
must be edited together**:

1. `cmd/arxsentinel/plugins_full.go` — add the blank import line.
2. `profiles/full.yaml` — add the corresponding entry under the right
   `plugins.<kind>`. Set `module: arxsentinel` for product plugins,
   `module: arx-core` for core ones.

The verifier's invariant (a) catches drift if only one is updated — the
build fails in pre-commit and in the `build-profiles-verify` CI job
with a clear "missing" / "extra" import message. If the new plugin
should also be available in `minimal` or `iot`, edit the corresponding
`profiles/<name>.yaml` and regenerate:

```bash
go generate ./cmd/arxsentinel/...
bash scripts/check-build-profiles.sh
```

## 6. Cross-references

- [`arx-core/docs/build-profiles.md`](https://github.com/mr-addams/arx-core/blob/v0.1.0/docs/build-profiles.md) — generic mechanism, schema, generator, verifier.
- [`arx-core/docs/plugin-development.md`](https://github.com/mr-addams/arx-core/blob/v0.1.0/docs/plugin-development.md) — plugin role interfaces, init+blank-import pattern.
- [ADR-003 — Build-time Modularity & Build Verifier](../architecture/adr/003-build-modularity.md)
- [ADR-002 — TelemetryCore boundary (Core/Product split)](../architecture/adr/002-telemetrycore-boundary.md)
- [Flow 075 decisions](../../../.opencode/flows/075_2026-06-22_build-modularity/DECISIONS.md)
