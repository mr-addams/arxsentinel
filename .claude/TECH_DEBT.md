# Technical Debt

Tracked items of known technical debt. Each item includes origin flow,
severity, description, and proposed resolution.

---

## Format

```
### [ID] Short title
- **Flow:** #NNN — flow name
- **Severity:** low / medium / high
- **Area:** package or subsystem
- **Problem:** what is wrong and why it matters
- **Resolution:** proposed fix
- **Status:** open / in progress / resolved (Flow #NNN)
```

---

## Open

### [030-1] Alert Sinks with dedup/rate limit (Telegram, Slack, PagerDuty, Zapier)

- **Flow:** #030 — Universal I/O Phase 2
- **Severity:** medium
- **Area:** `internal/core/output/`, `pkg/plugin/sink.go`
- **Problem:** Phase 1 only implements file and stdout sinks. Teams often need real-time
  alert delivery to Telegram/Slack/PagerDuty. Without dedup and rate-limiting, a flood
  attack would generate thousands of alerts.
- **Resolution:** Add `AlertSink` wrapper with dedup cache (IP+level → last-sent timestamp)
  and token bucket rate limiter per-sink. Config: `min_level`, `dedup_window`, `rate_limit`.
  Implement alongside `HTTPSink` in Phase 2.
- **Status:** open

---

### [036-gRPC] gRPC/protobuf external plugin runtime (long-term)

- **Flow:** #036 — External Plugin Runtime (long-term evolution)
- **Severity:** low
- **Area:** `pkg/execplugin/`, `pkg/plugin/`
- **Problem:** The exec+JSON runtime (Flow #036) runs plugins as trusted local processes.
  Enterprise use cases need stronger isolation (sandboxed execution), better performance
  under high RPC rates, and cross-host plugin deployment. exec+JSON cannot provide these.
- **Resolution:** Implement gRPC sidecar protocol with protobuf schema:
  - `proto/plugin.proto` — LogEntry, ThreatEvent, DetectResult, IPView messages
  - `DetectorService.Detect`, `SinkService.Write`, `SourceService.Run` RPCs
  - Host-side adapters: `GrpcDetector`, `GrpcSink`, `GrpcSource` in `pkg/grpcplugin/`
  - Precedents: HashiCorp go-plugin, Terraform providers, Vault plugins
  - Requires: `google.golang.org/grpc` + `google.golang.org/protobuf` in go.mod
- **Status:** open long-term — blocked on deciding whether to add gRPC dependency to this
  minimalist-dependency codebase

---

## Resolved

### [001] BadBotDetector: bbolt file opened per-stream, not shared as singleton

- **Flow:** #024 — BadBot Community Blocklist Detector
- **Severity:** medium
- **Area:** `internal/core/detector/badbot.go`, `main.go`
- **Problem:** `buildDetectors()` is called once per log stream. Each call creates a new
  `BadBotDetector` instance via `newBadBotDetector()`, which in turn calls `newPatternStore()`.
  If `storage` is set to a bbolt path, every stream tries to open the same `.db` file.
  bbolt uses a file-level write lock — only the first opener succeeds; subsequent streams
  silently fall back to `MemoryStore` and fetch patterns independently over the network.
  This means: redundant HTTP fetches per stream, inconsistent memory usage, and silent
  degradation that is hard to diagnose.
- **Resolution:** Make `BadBotDetector` (or at minimum its `PatternStore` + automata pair)
  a package-level singleton, initialized once and shared across all streams via `sync.Once`.
  Alternatively, pass a shared detector instance through `buildDetectors()` instead of
  constructing it inside the factory.
- **Status:** resolved (Flow #025) — `blocklist.Manager` is created once in `main()` and
  passed to all streams via `SharedResources`. `BadBotDetector` is now a thin wrapper over
  `Manager.Match()`. A single bbolt file is opened by the Manager; no per-stream duplication.

---

### [002] main.go should move to cmd/arxsentinel/main.go

- **Flow:** #027 — Repo Cleanup & Structure
- **Severity:** low
- **Area:** project layout, goreleaser, CI, Dockerfiles
- **Problem:** main.go in root is non-standard for Go projects with tooling. Standard layout
  expects cmd/<binary>/main.go. Deferred due to high coordination cost (6+ files to update).
- **Resolution:** Dedicated flow — update goreleaser, Dockerfiles, install.sh, packaging,
  CI workflow, all documentation references in one atomic set of commits.
- **Status:** resolved (Flow #028)

---

### [030-2] Static Plugin Registry (name → factory function)

- **Flow:** #030 — Universal I/O Phase 2+
- **Severity:** low
- **Area:** `pkg/plugin/`, `cmd/arxsentinel/main.go`
- **Problem:** Source and Sink types are hardcoded in `buildSources()`/`buildSinks()`.
  Adding a new type requires editing main.go. After Phase 2 reaches ≥3 Source types and
  ≥3 Sink types, a registry pattern becomes worthwhile.
- **Resolution:** `plugin.RegisterSource(name, factory)` / `plugin.RegisterSink(name, factory)`
  called from `init()` in each implementation package. YAML `type:` maps to registry lookup.
  Implemented in Flow #035: `pkg/source/registry.go` and `pkg/sink/registry.go` follow
  the pattern established by `pkg/detector/registry.go`.
- **Status:** resolved (Flow #035)

---

### [030-3] Dynamic Plugin Runtime (exec+JSON)

- **Flow:** #030 — Universal I/O long-term
- **Severity:** low
- **Area:** `pkg/plugin/`, `pkg/execplugin/`
- **Problem:** External developers cannot add custom Sources/Sinks without forking and
  recompiling. Limits extensibility for enterprise use cases.
- **Resolution:** Implemented exec+JSON subprocess protocol in Flow #036:
  `pkg/execplugin/` with ExecDetector, ExecSink, ExecSource. Zero new Go dependencies.
  Any language can implement a plugin via stdin/stdout NDJSON.
  Full gRPC/WASM runtime tracked separately as [036-gRPC] (long-term).
- **Status:** resolved (Flow #036)

---

### [030-4] Slogan and hero section landing — dual audience positioning

- **Flow:** #030 — Universal I/O
- **Severity:** low
- **Area:** `docs/index.html`
- **Problem:** Slogan was nginx-centric ("watches every HTTP request and hands confirmed
  attackers straight to Fail2Ban"). After Universal I/O, ArxSentinel works with any web
  server and any output sink, but the hero copy did not reflect this.
- **Resolution:** Updated hero description in Flow #037: "analyse every HTTP access log" +
  "route confirmed attackers to any output — Fail2Ban, custom scripts, or your own sink".
  Full slogan redesign and A/B testing deferred indefinitely (low priority).
- **Status:** resolved (Flow #037)

---

### [034-1] Dynamic plugin runtime: external detectors via gRPC or WASM

- **Flow:** #034 — Pipeline Abstraction
- **Severity:** low
- **Area:** `pkg/detector/`, `cmd/arxsentinel/main.go`
- **Problem:** The detector registry (`pkg/detector`) supports only compiled-in (Go) detectors
  self-registered via `init()`. Users who want site-specific detection logic (custom ML
  classifiers, application-layer rules) must fork the project and recompile.
- **Resolution:** Implemented exec+JSON subprocess protocol in Flow #036.
  `pkg/detector/registry.go Build()` falls back to `execplugin.NewDetector()` when a detector
  name is not registered but `cfg.Exec` is set. Plugin binary path configured via `exec:` field.
  Full gRPC/WASM tracked as [036-gRPC] (long-term).
- **Status:** resolved (Flow #036)

---

### [046-1] Manifest reading requires constructing a live plugin instance

- **Flow:** #046 — Plugin Framework: Manifest, Validator, MikroTik
- **Severity:** medium
- **Area:** `cmd/arxsentinel/validate.go` (`collectManifests`), all plugin constructors
- **Problem:** `collectManifests()` builds a live plugin instance just to read its static
  `Manifest()`. For executors this means calling the constructor — e.g. `NewMikroTikExecutor`
  runs `syncExisting()` which makes a network call to RouterOS. Two consequences:
  1. `arxsentinel validate` against a config with an unreachable executor target would hang
     or fail, even though validation should be a static, offline check.
  2. Executors are silently skipped in pipeline validation because `collectManifests` passes
     no `Config` → `parseConfig` errors on empty host → Build fails → `continue`. So executor
     InputType compatibility is never actually validated.
- **Proposed resolution:** Expose manifests from the registry without constructing a live
  instance — e.g. register a `Manifest` alongside each factory, or split a side-effect-free
  `Manifest()` from the network-touching constructor. Reading a static contract must never
  require I/O.
- **Resolution (partial):** Constructors are now side-effect-free. `NewMikroTikExecutor` and
  `NewCloudflareExecutor` no longer do network I/O — `syncExisting` (and cloudflare's
  `FindOrCreateList`) moved into `Run()` start. Building an executor purely to read its
  Manifest is now safe and offline. Consequence (1) is resolved.
- **Status:** resolved (Flow #046). Consequence (1) fixed by the I/O-free constructors above;
  consequence (2) — executors actually validated — fixed by the topology-aware validator [046-2].

---

### [046-2] Pipeline validator uses a naive linear chain; can't model real topology

- **Flow:** #046 — Plugin Framework: Manifest, Validator, MikroTik
- **Severity:** medium
- **Area:** `cmd/arxsentinel/validate.go` (`collectManifests`), `pkg/pipeline/validator.go`
- **Problem:** `collectManifests()` builds one flat linear chain
  `Source → Detector → Sink → Executor` and `Validate()` checks adjacent
  `OutputType[i] == InputType[i+1]`. This does not match the real data flow:
  1. The core **Scorer** (not a plugin) transforms detector output `Structured` into
     `ScoredEvent`. It is invisible to the validator, so a `Detector(→Structured)` placed
     directly before a `Sink`/`Executor(ScoredEvent→)` is a false mismatch.
  2. Sinks and executors are **terminal fan-out** consumers of `ScoredEvent` (executors via
     the NamedChannelHub), not a linear sequence. Chaining `Sink(→None) → Sink(ScoredEvent→)`
     or `Sink → Executor` is also a false mismatch.
  The flaw was latent because executors were excluded (see [046-1]) and most configs put
  sinks under `streams[].pipelines[].outputs` (empty top-level `cfg.Outputs`), so the chain
  was effectively just `Source → Detector` and passed trivially. Including executors
  ([046-1] attempt) surfaced it: every executor config was rejected at fail-fast startup.
- **Proposed resolution:** Make the validator topology-aware:
  1. Build the linear **producing spine**: `Source → Processor → Detector → synthetic Scorer
     (Structured→ScoredEvent)`.
  2. Validate each **terminal consumer** (every sink, every executor) independently against
     the spine's final output type (`ScoredEvent`, or `TypeAny`), instead of chaining them
     to each other.
  Then re-enable executor inclusion in `collectManifests` (the `Config: ex.Config` line that
  was reverted) to close [046-1] consequence (2).
- **Resolution:** Implemented the topology-aware validator in Flow #046:
  - Registries expose static manifests without construction: `ManifestByName` added to the
    executor, sink, and source registries (the latter avoids building file/exec sources that
    need a path+parser at validation time).
  - `pkg/pipeline`: `ValidateSpine` builds the producing spine and appends a synthetic Scorer
    manifest only when the pipeline has detectors (ETL stays Structured); `ValidateTerminals`
    checks each sink independently (fan-out, no chaining); `ValidatePipelines` runs both per
    pipeline and returns the produced type; `ValidateExecutorWiring` matches each executor to
    its sentinel-threat sink by NCH channel name. `SemanticError` carries stream/pipeline/
    consumer context.
  - `cmd/arxsentinel/validate.go`: assembles `PipelineContext`s from `streams[].pipelines[]`,
    computes the produced type once per pipeline (reused for channel-type mapping), and flags
    unknown executor types. `arxsentinel validate` runs fully offline; daemon startup fail-fast
    uses the same path.
  - Verified: all example configs (incl. config.example.yaml after fixing its commented-sink
    executor inconsistency that the validator surfaced) pass; deliberate mismatches (unknown
    channel, type mismatch, unknown executor type, ETL→ScoredEvent sink) are rejected with
    contextual messages. 112/112 integration tests pass.
- **Status:** resolved (Flow #046). Closes [046-1] consequence (2): executors are now validated.
