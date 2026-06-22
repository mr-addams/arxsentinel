# Build Profiles

How `arx-core` host applications select which plugin transports to compile into
a binary at build time. Covers the `arx_tag` sentinel-tag mechanism, the YAML
schema, the linker's tree-shaking, and how to author a custom profile.

> Scope: this document describes the contract between `arx-core` and any host
> application that links it. For the underlying plugin role interfaces and the
> `Register(name, factory)` registry convention, see
> [./plugin-development.md](./plugin-development.md). For the engine lifecycle
> that consumes the registered plugins, see [./architecture.md](./architecture.md).

A profile is a named subset of plugin transports (sources, sinks, executors,
processors). Each profile is a YAML declaration plus a generated Go file of
blank-imports; activating the profile at build time activates exactly that
subset of transports in the binary.

---

## 1. What is a build profile and why

By default, a host application built on `arx-core` links **every** registered
plugin transport into the binary. For many deployments that is the right
answer, but two categories of host applications need a smaller binary:

- **IoT / edge devices** — routers, gateways, industrial controllers that
  only react to a local log stream and run a remediation script. Pulling in a
  dozen HTTP adapters, a cloud-API executor, or a streaming source wastes
  flash and RAM for code that is never called.
- **Custom integrators** — teams that wire `arx-core` into a larger product
  and want to ship only the transports they actually use. A bespoke product
  rarely needs every source adapter that `arx-core` ships.

A **build profile** is a named subset of plugin transports that the Go linker
keeps in the binary. Plugins register themselves via `init()` →
`Register(name, factory)` (see
[./plugin-development.md](./plugin-development.md#4-registries-and-the-init--blank-import-pattern)),
and the host application's `main` package pulls them in through
**blank-imports**. A plugin that is not blank-imported is eliminated by the
linker: no runtime overhead, no dead code, no registration side-effects. A
profile is the human-readable declaration of which blank-imports end up in
the binary.

The mechanism only tree-shakes **transports** — source / sink / executor /
processor packages registered via blank-import. Components that the host
application wires by **named import** are always-linked regardless of
profile. See [§8 Limitations](#8-limitations--considerations).

---

## 2. Schema reference

Each profile lives in `profiles/<name>.yaml` under the host application's
repository root:

```yaml
# profiles/minimal.yaml — example profile declaration
name: minimal
description: "Minimal build — syslog/stdin sources and stdout sink for log aggregation."
plugins:
  # Each list entry declares one plugin transport with two required fields.
  sources:
    - name: syslog          # Register name (matches Register("syslog", …))
      module: arx-core      # Owning module
    - name: stdin
      module: arx-core
  sinks:
    - name: stdout
      module: arx-core
  # Optional kinds — omit when the profile needs none.
  executors: []
  processors: []
```

### 2.1 Fields

| Field | Required | Description |
| --- | --- | --- |
| `name` (top-level) | yes | Profile name. Used as the Go build tag and in the generated file name `plugins_<name>.go`. |
| `description` | yes | Free-form one-liner, surfaced in tooling and CI summaries. |
| `plugins.<kind>[]` | optional | List of transports for `kind ∈ {sources, sinks, executors, processors}`. Absent / empty list means "none". |
| `plugins.<kind>[].name` | yes | **Register name** — the literal string passed to `Register(name, …)` in the plugin's `init()`. Must match exactly. |
| `plugins.<kind>[].module` | yes | Owning module: `arx-core` for core-provided transports, or the host application's own module name. |

### 2.2 `module` field

The `module` field tells the generator where to import each transport from.
In a single-module layout (one Go module containing both `arx-core` and the
host product) the generator ignores the field and emits the in-repo import
path. In a multi-module layout (Core and Product separated, with `arx-core`
published as a Go module) the field maps directly to the import prefix:
`module: arx-core` → `arx-core/pkg/<kind>/<name>`, `module: <host-product>`
→ `<host-product>/pkg/<kind>/<name>`. No profile YAML needs to change when
the repository switches layout — only the generator learns the new prefix.

---

## 3. The `arx_tag` sentinel — why `-tags <name>` alone is not enough

> ⚠️ **Read this section.** A wrong build command silently produces a binary
> that panics on startup, or one that has every plugin but no profile applied.

A profile is activated with **two** build tags: a fixed sentinel `arx_tag`
and the profile name. There is a reason the sentinel exists.

The hand-maintained `cmd/<host>/plugins_full.go` carries the constraint
`//go:build !arx_tag`, and every generated `cmd/<host>/plugins_<name>.go`
carries `//go:build arx_tag && <name>`. The sentinel **turns off `full` the
moment any profile tag is set**.

Without the sentinel, `plugins_full.go` would have to enumerate every known
profile to disable itself (something like
`//go:build !(minimal || iot || …)`). That scheme breaks the moment an
integrator creates a profile the repository does not know about: the
integrator's `plugins_custom.go` and `plugins_full.go` would both compile,
both register the same plugins via `init()` → `Register()`, and the binary
would panic at startup with a double-registration error.

### 3.1 The three failure modes

**Wrong — `-tags <name>` without the sentinel (looks correct, gives full build):**

```bash
go build -tags custom-http ./...
# plugins_full.go (!arx_tag) compiles because arx_tag is not set
# plugins_custom_http.go (arx_tag && custom-http) is skipped
# Result: full build — works, but you got the wrong binary.
```

**Wrong — `-tags arx_tag` without a profile name (binary starts, nothing registered):**

```bash
go build -tags arx_tag ./...
# plugins_full.go skipped (because arx_tag is set)
# but no plugins_<name>.go matches → no transports linked at all
# Binary starts but every source/sink/executor name is unknown at runtime.
```

**Correct — both tags together:**

```bash
go build -tags "arx_tag custom-http" ./...
# plugins_full.go excluded (has !arx_tag)
# plugins_custom_http.go included (arx_tag && custom-http)
# Exactly the transports declared in profiles/custom-http.yaml are linked.
```

This is why every CI job and every example in this document passes
`-tags "arx_tag <name>"`, never `<name>` alone.

---

## 4. How plugins enter the binary

The linker's tree-shaking only removes a package when **nothing** in the
program imports it (named or blank). The blank-import is the bridge that
brings the package's `init()` into the build, and `init()` is where the
plugin announces itself to the registry.

```go
// pkg/source/<name>/source.go (in arx-core or in the host product)
package sourcename

import "arx-core/pkg/source"

func init() {
    source.Register("<name>", func(cfg source.InputConfig, opts source.BuildOptions) (plugin.Source, error) {
        // factory body
    })
}
```

Two layers of convention are at play:

1. **Plugin side** — each transport calls `Register(name, factory)` exactly
   once from `init()`. The registry is a package-level singleton; calling
   `Register` with the same name twice panics at startup (this is the
   property that the `arx_tag` sentinel protects — see §3).
2. **Host side** — `cmd/<host>/plugins_full.go` carries one blank import
   per transport under `//go:build !arx_tag`. The blank import forces the
   linker to retain the transport package, which forces its `init()` to
   run, which performs the registration.

Anything that is **not** blank-imported is invisible to the linker: the
package is dropped, its `init()` never runs, and no `Register()` call
happens. That is how a profile shrinks the binary — by reducing the set of
blank-imports that survive the build constraint.

### 4.1 The two file shapes

**Hand-maintained full profile:**

```go
//go:build !arx_tag

// cmd/<host>/plugins_full.go — blank-imports for every transport the host ships
// under the default build. Excluded as soon as arx_tag is set.
package main

import (
    _ "arx-core/pkg/source/syslog"
    _ "arx-core/pkg/source/stdin"
    _ "arx-core/pkg/sink/stdout"
    // … one blank import per transport in profiles/full.yaml
)
```

**Generated profile file:**

```go
// Code generated; DO NOT EDIT.

//go:build arx_tag && iot

// cmd/<host>/plugins_iot.go — blank-imports for the iot profile.
package main

import (
    _ "arx-core/pkg/source/syslog"
    _ "arx-core/pkg/source/file"
    _ "arx-core/pkg/sink/exec"
    _ "arx-core/pkg/sink/stdout"
)
```

Generated files are committed to the repository so that the import diff
is reviewable in PRs.

---

## 5. Built-in profiles

The reference product shipping `arx-core`-based binaries (`arxsentinel`)
provides `full`, `minimal`, and `iot` profiles out of the box. Other host
applications are free to ship different sets; the contract is the same.

### 5.1 `full`

`profiles/full.yaml` — **all blank-import transports** (the default). This is
the build produced by a plain `go build ./...` with no tags. Use it when the
binary runs on a normal server with sufficient RAM and you want every
available transport reachable at runtime through configuration alone.

### 5.2 `minimal`

`profiles/minimal.yaml` — **forwarder sidecar**: sources that read input
and a stdout sink, no executors. Nothing reacts to threats; the binary only
parses inputs and emits parsed log entries / threat events as JSON. Use it
for a sidecar that just re-shapes and forwards log streams.

### 5.3 `iot`

`profiles/iot.yaml` — **edge remediation**: a small set of sources plus an
exec sink that triggers a local remediation script and a stdout sink for
visibility. Use it on constrained devices where a full build is too heavy
and you do want local remediation actions to fire.

The names are illustrative — the contract is the schema in §2, not the
specific set of transports.

---

## 6. Creating a custom profile

A custom profile is created in four steps. The example below builds a
profile that only reads a single push source and writes to a stdout sink.

### 6.1 Declare the profile

Create `profiles/custom-http.yaml`:

```yaml
name: custom-http
description: "HTTP push source only, stdout sink — example custom profile."
plugins:
  sources:
    - name: plugin-A
      module: arx-core
  sinks:
    - name: sink-Y
      module: arx-core
```

The names `plugin-A` and `sink-Y` are placeholders; replace them with the
real Register names of the transports you want (see
[./plugin-development.md](./plugin-development.md#4-registries-and-the-init--blank-import-pattern)).

### 6.2 Generate the blank-import file

The generator reads `profiles/<name>.yaml` and emits
`cmd/<host>/plugins_<name>.go` containing the blank-imports for the profile
under a `//go:build arx_tag && <name>` constraint:

```bash
go generate ./cmd/<host>/...
```

The resulting file looks like the `plugins_iot.go` shape in §4.1, with one
blank import per declared plugin.

### 6.3 Verify declaration ↔ generated-file drift

A static check should enforce that the YAML declarations and the generated
blank-imports never drift apart — a contributor who updates one without the
other would silently ship a binary that does not match the profile. The
check walks every `profiles/*.yaml`, every `cmd/<host>/plugins_*.go`, and
every package under `pkg/<kind>/<name>/`, and fails the build if any
declared name has no `Register()` or any blank-imported package has no
declaration.

arx-core **does not ship the verifier itself** — it only defines the
contract the verifier must enforce. A consumer that embeds arx-core writes
its own drift-checking script (or CI step) against the contract above. The
reference product built on arx-core — ArxSentinel — ships one such
implementation at `scripts/check-build-profiles.sh` that downstream consumers
can use as a template:

```bash
# In the consumer's repository (ArxSentinel ships this script as a reference
# implementation; copy and adapt it for your own consumer product):
bash scripts/check-build-profiles.sh
```

### 6.4 Build with the sentinel tag

```bash
go build -tags "arx_tag custom-http" ./...
```

If everything is correct, the resulting binary contains only the transports
declared in `profiles/custom-http.yaml` (plus anything always-linked by
named import — see §8).

---

## 7. Build commands

| Profile | Build | Test |
| --- | --- | --- |
| `full` (default) | `go build ./...` | `go test ./...` |
| `minimal` | `go build -tags "arx_tag minimal" ./...` | `go test -tags "arx_tag minimal" ./...` |
| `iot` | `go build -tags "arx_tag iot" ./...` | `go test -tags "arx_tag iot" ./...` |
| `<custom>` | `go build -tags "arx_tag <custom>" ./...` | `go test -tags "arx_tag <custom>" ./...` |

Always include `arx_tag`. See [§3](#3-the-arx_tag-sentinel--why--tags-name-alone-is-not-enough).

---

## 8. Limitations & considerations

The build-profile mechanism tree-shakes **source / sink / executor /
processor transports only** — the packages registered via blank-import in
`cmd/<host>/plugins_full.go`. Several components are outside its scope by
design:

- **Named-import wiring** — any package the host application imports by name
  in non-blank-import code (engine wiring, subcommand handlers, helpers) is
  always-linked regardless of profile. Profiles cannot remove it. Examples
  that typically fall in this bucket: pipeline helpers, format encoders,
  parsers called directly from the host's bootstrap.
- **Components wired through named-import subpackages** — components that
  are loaded by name from a sibling subpackage (such as HTTP adapter
  families) require their parent to be named-imported, and so are
  always-linked as a group. Per-child tree-shaking is out of scope for the
  profile mechanism.
- **Detectors and other registry-only components without blank-import
  wiring** — if a role's transports are pulled in by named import from the
  engine startup code rather than from `cmd/<host>/plugins_full.go`, they
  are always-linked. Per-detector (or per-role) tree-shaking would require
  refactoring the engine wiring onto blank-import sub-packages — a future
  enhancement, not part of the profile contract.
- **Register-name vs package-directory override** — the `name:` field in a
  profile entry is the **Register name**, not the directory name. When a
  transport calls `Register("alias", …)` from a directory named differently
  (for historical or branding reasons), the YAML must declare the alias, not
  the directory. Profile declarations and the generator both apply this
  override; integrators writing a custom profile must use the alias the
  transport actually registers under. See
  [./plugin-development.md](./plugin-development.md#4-registries-and-the-init--blank-import-pattern)
  for the convention.

Profiles are a transport-level switch, not a fine-grained code-elimination
mechanism. Reach for them to remove whole transports; for finer control,
restructure the wiring onto blank-import sub-packages first.

---

## 9. Maintenance note — adding a new plugin

When a new blank-import transport is added (a new source / sink / executor /
processor package that registers via `init()` and is pulled in by the
host's `main`), **two files must be edited together**:

1. `cmd/<host>/plugins_full.go` — add the blank import line.
2. `profiles/full.yaml` — add the corresponding entry under the right
   `plugins.<kind>`.

The static check from §6.3 catches drift if only one of the two is updated
— the build fails in pre-commit and in CI with a clear "missing" or "extra"
import message. If the new transport should also be available in `minimal`
or `iot`, edit the corresponding `profiles/<name>.yaml` and regenerate:

```bash
go generate ./cmd/<host>/...
# Drift check — see §6.3: ship your own verifier (the reference product
# ArxSentinel ships scripts/check-build-profiles.sh as a template):
bash scripts/check-build-profiles.sh
```

When in doubt, prefer extending an existing profile over creating a new
one — every new profile is a new combination the verifier, the CI matrix,
and the documentation must keep in sync.
