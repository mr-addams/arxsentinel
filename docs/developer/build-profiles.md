# Build Profiles

> Developer guide for ArxSentinel build-time modularity (Phase 1.5, ADR-003).
> Source of truth: [`docs/architecture/adr/003-build-modularity.md`](../architecture/adr/003-build-modularity.md).

## 1. What is a build profile and why

ArxSentinel ships every plugin in its default build — the **full** profile.
For many deployments that is the right answer, but two categories of integrators
need a smaller binary:

- **IoT / edge devices** — a router, a Raspberry Pi, an industrial gateway that
  only reacts to a local log stream and runs a remediation script. Pulling in the
  HTTP source, the MikroTik executor, or the Sentinel threat sink wastes flash
  and RAM for code that is never called.
- **Custom integrators** — teams building on `arx-core` who wire ArxSentinel into
  a larger product (see [ADR-002](../architecture/adr/002-telemetrycore-boundary.md))
  and want to ship only the transports they actually use.

A **build profile** is a named subset of the plugin transports (sources, sinks,
executors, processors) that the Go linker keeps in the binary. Plugins register
themselves via `init()` + `Register(name, factory)`, and `cmd/arxsentinel/main.go`
pulls them in through **blank-imports**. A plugin that is not blank-imported is
eliminated by the linker: no runtime overhead, no dead code, no registration
side-effects. A profile is the human-readable declaration of which blank-imports
end up in the binary.

The build profiles mechanism **only tree-shakes transports** — source/sink/
executor/processor packages registered via blank-import. Detectors, the
Cloudflare executor, and `pkg/sink/file` are wired by named imports elsewhere in
the binary and are always linked. See [Limitations & future work](#limitations--future-work).

## 2. Schema reference

Each profile lives in `profiles/<name>.yaml`:

```yaml
# profiles/minimal.yaml — example profile declaration
name: minimal
description: "Minimal arxsentinel build — syslog/stdin sources and stdout sink for log aggregation."
plugins:
  # Each list entry declares one plugin transport with two required fields.
  sources:
    - name: syslog          # Register name (matches Register("syslog", ...))
      module: arx-core      # Owning module per ADR-002
    - name: stdin
      module: arx-core
  sinks:
    - name: stdout
      module: arx-core
  # Optional kinds — omit when the profile needs none.
  executors: []
  processors: []
  detectors: []   # documentation-only; detectors are not tree-shakeable (Decision 12)
```

### Fields

| Field | Required | Description |
| --- | --- | --- |
| `name` (top-level) | yes | Profile name. Used as the Go build tag and in the generated file name `plugins_<name>.go`. |
| `description` | yes | Free-form one-liner, shown in tooling/CI summaries. |
| `plugins.<kind>[]` | optional | List of transports for `kind ∈ {sources, sinks, executors, processors, detectors}`. Absent / empty list means "none". |
| `plugins.<kind>[].name` | yes | **Register name** — the literal string passed to `Register(name, …)` in the plugin's `init()`. See [Register name vs package path](#register-name-vs-package-path-override) for the one special-case override. |
| `plugins.<kind>[].module` | yes | Owning module: `arx-core` or `arxsentinel`. See note below. |

### `module` field — Phase 1 vs Phase 2 semantics

In Phase 1.5 ArxSentinel is a single Go module (`github.com/mr-addams/arxsentinel`).
The generator **parses** the `module` field but **ignores** it when emitting import
paths — every plugin is imported from `github.com/mr-addams/arxsentinel/pkg/<kind>/<name>`.

The field is required in the schema so that **Phase 2.1.4** can activate it without
a schema migration: once the repository splits into `arx-core` and `arxsentinel`
modules (see [ADR-002](../architecture/adr/002-telemetrycore-boundary.md) and
[PLATFORM_ROADMAP §2.1.4](../../PLATFORM_ROADMAP.md)) the generator will start
mapping `module: arx-core` → `github.com/mr-addams/arx-core/pkg/…` and
`module: arxsentinel` → `github.com/mr-addams/arxsentinel/pkg/…`. No profile YAML
will need to change at that point.

## 3. Built-in profiles

Three profiles ship in the repository under `profiles/`:

### `full`

`profiles/full.yaml` — **all 12 blank-import transports** (the default). This is
the build produced by a plain `go build ./...` with no tags. Use it when the
binary will run on a normal server with sufficient RAM and you want every
integration available at runtime via config alone.

Transports: `source/{exec,file,http,sentinel,stdin,syslog}`,
`sink/{exec,sentinel-threat,stdout}`, `executor/{mikrotik,nginx}`,
`processor` (registry package).

### `minimal`

`profiles/minimal.yaml` — **log aggregation only**: syslog + stdin sources and a
stdout sink, all from `arx-core`. No security detectors are removed (they are
always-linked, see [Limitations](#limitations--future-work)) but no executors run
either — nothing reacts to threats, the binary only emits parsed log entries /
threat events as JSON. Use it for a forwarder sidecar that just re-shapes and
forwards log streams.

### `iot`

`profiles/iot.yaml` — **edge remediation**: syslog + file sources, `exec` sink
(to trigger a local remediation script) plus `stdout` for visibility. Use it on
constrained devices where a full `full` build is too heavy and you do want local
remediation — the `exec` sink can call `iptables` / a MikroTik API client / an
arbitrary remediation script.

## 4. How to create a custom profile

A custom profile is created in four steps. The example below builds a profile
that only reads the HTTP push source and writes to stdout.

**Step 1 — declare the profile.** Create `profiles/custom-http.yaml`:

```yaml
name: custom-http
description: "HTTP push source only, stdout sink."
plugins:
  sources:
    - name: http
      module: arx-core
  sinks:
    - name: stdout
      module: arx-core
```

**Step 2 — run the generator.** The generator emits a `plugins_custom_http.go`
file under `cmd/arxsentinel/` containing the blank-imports for the profile under
a `//go:build arx_tag && custom-http` constraint:

```bash
go generate ./cmd/arxsentinel/...
```

**Step 3 — run the verifier.** Catches declaration drift, missing `Register`
calls, and cookbook membership mismatches before you commit:

```bash
bash scripts/check-build-profiles.sh
```

**Step 4 — build with the sentinel tag.** See the next section for **why
`arx_tag` is mandatory**:

```bash
go build -tags "arx_tag custom-http" ./...
```

If everything is correct, the resulting binary contains only the `http` source
and the `stdout` sink (plus the always-linked detectors / Cloudflare executor /
`pkg/sink/file`, which profiles cannot remove).

## 5. The `arx_tag` sentinel — why `-tags custom` is not enough

> ⚠️ **Read this section.** A wrong build command silently produces a binary that
> panics on startup.

A profile is activated with **two** build tags: a fixed sentinel `arx_tag` and
the profile name. There is a reason the sentinel exists.

The hand-maintained `cmd/arxsentinel/plugins_full.go` carries the constraint
`//go:build !arx_tag`, and every generated `cmd/arxsentinel/plugins_<name>.go`
carries `//go:build arx_tag && <name>`. The sentinel **turns off `full` the
moment any profile tag is set**.

Without the sentinel, `plugins_full.go` would have to enumerate every known
profile to disable itself (something like `//go:build !(minimal || iot || …)`).
That scheme breaks the moment an integrator creates a profile the repository
does not know about: the integrator's `plugins_custom.go` and `plugins_full.go`
would both compile, both register the same plugins via `init()` → `Register()`,
and the binary would panic at startup with a double-registration error.

**Wrong — will panic at startup:**

```bash
go build -tags custom-http ./...
# plugins_full.go (!arx_tag) compiles because arx_tag is not set
# plugins_custom_http.go (arx_tag && custom-http) is skipped
# Result: full build — works, but you got the wrong binary.
#
# Now the inverse trap — using the sentinel only without the profile name:
go build -tags arx_tag ./...
# plugins_full.go skipped, but no plugins_<name>.go matches → no transports
# linked at all. Binary starts but every source/sink/executor is unknown.
```

**Correct — `arx_tag` plus the profile name:**

```bash
go build -tags "arx_tag custom-http" ./...
# plugins_full.go excluded (has !arx_tag)
# plugins_custom_http.go included (arx_tag && custom-http)
# Exactly the transports declared in profiles/custom-http.yaml are linked.
```

This is why every example in this document and every CI job passes
`-tags "arx_tag <name>"`, never `<name>` alone.

## 6. How to run the generator

The generator is `tools/gen-plugins/main.go`. It reads every `profiles/*.yaml`
(except `full`, which is hand-maintained) and emits one
`cmd/arxsentinel/plugins_<name>.go` per non-full profile. Run it via the
`go:generate` directive in `cmd/arxsentinel/main.go`:

```bash
go generate ./cmd/arxsentinel/...
```

Generated files **are committed to the repository** (ADR-003 OQ-5): they are
reviewable artefacts, not build-time output. A reviewer reading a PR that adds
or changes a profile sees the import diff directly. The verifier's invariant (a)
catches drift if a contributor forgets to regenerate, but does **not** replace
the review.

You can also invoke the generator directly with explicit paths:

```bash
go run ./tools/gen-plugins -profiles profiles -out cmd/arxsentinel
```

## 7. How to run the verifier

`scripts/check-build-profiles.sh` runs three static invariants over
`profiles/*.yaml`, `cmd/arxsentinel/plugins_*.go`, `pkg/{source,sink,executor,processor}/`,
and `cookbook/profiles/*.yaml`:

- **(a) Declaration ↔ generated-file drift** — for each profile, the plugin
  names in the YAML must match exactly the blank-imports in the corresponding
  `plugins_<name>.go` (for `full`: the hand-maintained `plugins_full.go`).
- **(b) Plugin name → `Register` existence** — every declared source/sink/
  executor name must have a matching `Register("<name>", …)` call in a non-test
  file under `pkg/<kind>/<name>/`. Catches typos and renamed-but-not-profile-
  updated plugins. Processor entries are checked for package existence only
  (registry package has no `Register` call by plugin name).
- **(c) Reference config ↔ profile membership** — when a `cookbook/profiles/
  <name>.yaml` exists, every `type:` value in that config must be a plugin
  declared in `profiles/<name>.yaml`.

Run it locally:

```bash
bash scripts/check-build-profiles.sh
```

It is wired into the project's pre-commit hook as well, so a drift is caught
before a commit lands. CI runs it in a dedicated `build-profiles-verify` job
before any profile build matrix.

## 8. Build commands

| Profile | Build | Test |
| --- | --- | --- |
| `full` (default) | `go build ./...` | `go test ./...` |
| `minimal` | `go build -tags "arx_tag minimal" ./...` | `go test -tags "arx_tag minimal" ./...` |
| `iot` | `go build -tags "arx_tag iot" ./...` | `go test -tags "arx_tag iot" ./...` |
| `<custom>` | `go build -tags "arx_tag <custom>" ./...` | `go test -tags "arx_tag <custom>" ./...` |

Always include `arx_tag`. See [§5](#5-the-arx_tag-sentinel--why--tags-custom-is-not-enough).

## 9. Cross-references

- [ADR-002 — TelemetryCore boundary (Core/Product split)](../architecture/adr/002-telemetrycore-boundary.md)
- [ADR-003 — Build-time Modularity & Build Verifier](../architecture/adr/003-build-modularity.md)
- [PLATFORM_ROADMAP §1.5 — Build Modularity](../../PLATFORM_ROADMAP.md)
- [PLATFORM_ROADMAP §2.1.4 — Profile schema cross-module activation](../../PLATFORM_ROADMAP.md)
- Flow 075 decisions: `.opencode/flows/075_2026-06-22_build-modularity/DECISIONS.md`

## 10. Maintenance note — adding a new plugin

When a new blank-import transport is added (a new source / sink / executor /
processor package that registers via `init()` and is pulled in by
`cmd/arxsentinel/main.go`), **two files must be edited together**:

1. `cmd/arxsentinel/plugins_full.go` — add the blank import line.
2. `profiles/full.yaml` — add the corresponding entry under the right `plugins.<kind>`.

The verifier's invariant (a) catches drift if only one of the two is updated —
the build will fail in pre-commit and in the `build-profiles-verify` CI job with
a clear "missing" / "extra" import message. If the new plugin should also be
available in `minimal` or `iot`, edit the corresponding `profiles/<name>.yaml`
and regenerate:

```bash
go generate ./cmd/arxsentinel/...
bash scripts/check-build-profiles.sh
```

## Limitations & future work

The build-profile mechanism tree-shakes **source / sink / executor / processor
transports only** — the 12 packages currently blank-imported in
`cmd/arxsentinel/plugins_full.go`. Several components are outside its scope by
design (see ADR-003 and Flow 075 DECISIONS.md Decisions 12–14):

- **Detectors (`pkg/detector`, 8 plugins)** — wired by named imports in
  `cmd/arxsentinel/{validate.go,builders.go}`. They are always-linked and
  all-or-nothing in Phase 1.5. Per-detector tree-shaking would require
  refactoring `validate.go` and `builders.go` onto blank-import sub-packages
  plus a registry lookup — a future enhancement, not in scope for Phase 1.5.
  The `detectors:` list in a profile YAML is documentation-only and is not
  verified.
- **Cloudflare executor (`pkg/executor/cloudflare`)** — wired by a named import
  in `cmd/arxsentinel/cleanup.go` because the `arxsentinel cleanup` subcommand
  calls its API directly. Always-linked. Not part of build profiles.
- **`pkg/sink/file`** — wired by a named import in `pkg/pipeline/pipeline.go`.
  Always-linked. Not a profile transport.
- **`pkg/processor/{chaincheck,whitelist}`** — not blank-imported in
  `cmd/arxsentinel/main.go`, so their `Register()` is never invoked. This is a
  pre-existing wiring ambiguity (the packages are called directly via
  `chaincheck.NewChecker()` rather than through the processor registry) and
  will be addressed by a separate fix task. They are **not** included in
  `profiles/full.yaml`.
- **Register name vs package path override** — the `name:` field in a profile
  entry is the **Register name**, not the package directory name. The one
  built-in override is `pkg/sink/sentinel`, whose `Register` call uses the name
  `sentinel-threat`. Profile declarations and the generator both apply this
  override; integrators writing a custom profile that references the Sentinel
  threat sink must use `name: sentinel-threat` in their YAML (not `sentinel`).