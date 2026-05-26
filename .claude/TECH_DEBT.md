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

### [030-2] Static Plugin Registry (name → factory function)

- **Flow:** #030 — Universal I/O Phase 2+
- **Severity:** low
- **Area:** `pkg/plugin/`, `cmd/arxsentinel/main.go`
- **Problem:** Source and Sink types are hardcoded in `buildSources()`/`buildSinks()`.
  Adding a new type requires editing main.go. After Phase 2 reaches ≥3 Source types and
  ≥3 Sink types, a registry pattern becomes worthwhile.
- **Resolution:** `plugin.RegisterSource(name, factory)` / `plugin.RegisterSink(name, factory)`
  called from `init()` in each implementation package. YAML `type:` maps to registry lookup.
- **Status:** open

### [030-3] Dynamic Plugin Runtime (gRPC sidecar or WASM)

- **Flow:** #030 — Universal I/O long-term
- **Severity:** low
- **Area:** `pkg/plugin/`
- **Problem:** External developers cannot add custom Sources/Sinks without forking and
  recompiling. Limits extensibility for enterprise use cases.
- **Resolution:** Implement a gRPC sidecar protocol or WASM plugin runtime.
  Precedents: Terraform providers, Vault plugins, Packer builders.
- **Status:** open

### [030-4] Slogan and hero section landing — dual audience positioning

- **Flow:** #030 — Universal I/O
- **Severity:** low
- **Area:** `docs/index.html`
- **Problem:** Current slogan is nginx-centric ("watches every HTTP request and hands
  confirmed attackers straight to Fail2Ban"). After Universal I/O, ArxSentinel works
  with any web server and any output sink, but the slogan does not reflect this.
  Changing the hero copy requires copywriter input and A/B testing considerations.
- **Resolution:** Separate flow for slogan/hero redesign. Interim: add "Works with your
  stack" section below the hero (done in Flow #030).
- **Status:** open (hero section deferred)
