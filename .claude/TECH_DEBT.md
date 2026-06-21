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
- **Status:** open long-term / in progress / resolved (Flow #NNN)
```

---

## Open

### [068-1] Тесты реестров не идемпотентны к `go test -count>1`
- **Flow:** #068 — Baseline & Dependency Map (Phase 0.2/0.3)
- **Severity:** low
- **Area:** `pkg/executor`, `pkg/sink`, `pkg/source` (registry-тесты), `pkg/source/http/adapters`
- **Problem:** при `go test -count=3 ./...` пакеты падают с `panic: duplicate registration`
  (executor/sink/source) и PubSub JWT → 401 (http/adapters). Причина — тесты регистрируют
  плагины в глобальный singleton-реестр без cleanup/reset между прогонами; на 2-м прогоне
  в том же бинаре — дубликат. С `-count=1` всё зелёное (`go test -race -count=1 ./...` →
  30 ok, 0 FAIL, 0 DATA RACE). Код реестра исправен — дефект только в тестах.
- **Resolution:** добавить `t.Cleanup`/reset глобального реестра между прогонами (или
  изолированный экземпляр реестра в тестах вместо singleton). Естественно чинить в Phase 1.1
  при переводе реестров на generic `Registry[T,CFG]` — заодно сделать тесты идемпотентными.
- **Status:** open long-term (чинить в Phase 1.1)

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
- **Status:** open long-term

---

### [049-WS] Dedicated WebSocket abuse detector plugin

- **Flow:** #049 — HTTP source plugin (surfaced during integration testing)
- **Severity:** medium
- **Area:** `pkg/detector/` (new `websocket.go`), `internal/sys/config/config.go`
- **Problem:** A single IP can flood WebSocket upgrade endpoints (`GET /ws` → repeated
  `101 Switching Protocols`, then `444`), exhausting connection slots. Legitimate clients
  open ONE socket; dozens of `101` from one IP in a short window is the abuse signal.
  No current detector inspects HTTP status code semantically: `probe` is path-based,
  `bruteforce` keys on 404 ratio, `rate` counts requests blind to status. A smart attacker
  sending a real User-Agent evades the empty-UA branch of the `useragent` detector — so
  the only robust signal (repeated `101`) is currently unused.
- **Resolution:** New `websocket` detector that counts `status == 101` (optionally `444`/`499`)
  per IP per window and scores when the count crosses a configurable threshold. Config under
  `detectors.websocket`: `enabled`, `score`, `max_upgrades`, `window`, optional `status_codes`.
  Consider a more general `status-anomaly` detector (configurable suspicious codes) if other
  status-based patterns emerge. Must go through `/architect` as its own flow — it is a new
  detection subsystem, not part of the HTTP source work.
- **Interim mitigation (Flow #049):** ✅ DONE — `whitelist.custom.paths` added; operators
  can exclude legitimate WS traffic (`/ws`) from scoring via YAML or `ARXSENTINEL_WHITELIST_CUSTOM_PATHS`.
- **Status:** open (detector itself pending; interim mitigation shipped in v2.0.3-dev.4)

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

### [064-AC] ahocorasick contains-wrapper (FindAllString аллокация)

- **Flow:** #064 — Consolidated Review & Hardening
- **Severity:** low
- **Area:** `internal/core/blocklist/`
- **Problem:** Обёртка `Match(s string) bool` вызывает `ac.FindAllString(s)` (из `github.com/rrethy/ahocorasick`), который аллоцирует свежий слайс на каждое совпадение, даже когда нужен только булев ответ «есть хоть одно совпадение». Для каждого запроса на каждом IP это лишняя аллокация.
- **Resolution:** Если ahocorasick не предоставляет `MatchBool`, заменить на однопроходный поиск с ранним выходом: написать тонкую обёртку, которая использует `FindAllString` с лимитом 1 или перейти на `Contains` из другой библиотеки Aho-Corasick.
- **Status:** open

---

### [064-RP] RecentPaths cache reuse (backing array)

- **Flow:** #064 — Consolidated Review & Hardening
- **Severity:** low
- **Area:** `internal/core/state/` (tracker, IPState)
- **Problem:** `RecentPaths()` возвращает новый слайс через `append([]string(nil), ...)`. При высокой частоте запросов (десятки тысяч IP/сек) это создаёт избыточное давление на GC. Можно переиспользовать backing array и возвращать `pathCache[:n]`.
- **Resolution:** Добавить `pool` (sync.Pool) для слайсов RecentPaths или вернуть срез поверх существующего массива с копированием только при одновременном чтении/записи. Требует осторожной синхронизации — см. ring-buf под rwlock.
- **Status:** open

---

### [064-APIV] PluginAPIVersion в Manifest

- **Flow:** #064 — Consolidated Review & Hardening
- **Severity:** low
- **Area:** `pkg/plugin/` (Manifest)
- **Problem:** `Manifest` содержит `PluginVersion` (версия реализации), но не `APIVersion` (версия контракта plugin/host). При изменении ExecJSON протокола (например, новые поля в ThreatEvent) старый плагин с `PluginVersion="1.0.0"` не может сообщить, что он несовместим. Валидатор не может отличить несовместимость от простого «старый».
- **Resolution:** Добавить `APIVersion string` в Manifest. Плагины и хост декларируют поддерживаемую версию API. Валидатор (pkg/pipeline) проверяет совместимость при старте.
- **Status:** open

---

### [064-PW] Processors wiring: appCtx вместо context.Background(), Close на shutdown

- **Flow:** #064 — Consolidated Review & Hardening
- **Severity:** medium
- **Area:** `internal/core/whitelist/`, `internal/core/chaincheck/`, `cmd/arxsentinel/pipeline.go`
- **Problem:** ChainChecker и Verifier в `SharedResources` создаются с `context.Background()`, а не с `appCtx`. При SIGHUP/graceful shutdown эти компоненты не получают сигнал отмены и могут зависнуть на сетевых вызовах (DNS verify, ChainGuard API). Кроме того, у Verifier и ChainChecker нет метода `Close()`, поэтому drain в `runPipeline` не может дождаться их завершения.
- **Resolution:** Пробросить `appCtx` при создании Verifier и ChainChecker. Добавить интерфейс `io.Closer` или канал `Done()`. В `runPipeline` вызывать `Close()` (или ожидать `Done()`) в фазе drain.
- **Status:** open

---

### [064-DB] Optional drain budget: runPipeline без общего таймаута

- **Flow:** #064 — Consolidated Review & Hardening
- **Severity:** low
- **Area:** `cmd/arxsentinel/pipeline.go` (`runPipeline`)
- **Problem:** Drain-цикл в `runPipeline` использует `context.Background()` для финальной записи буферов. Если flush зависает (NFS stall, сетевой executor), shutdown блокируется бесконечно — процесс не завершается. Нет общего таймаута на drain.
- **Resolution:** Рассмотреть ~30s drain контекст, производный от `appCtx`: `drainCtx, cancel := context.WithTimeout(appCtx, 30*time.Second)`. Использовать `drainCtx` для финального flush вместо `context.Background()`. После таймаута логировать предупреждение и завершать процесс.
- **Status:** open

---

## Resolved

### [051-stdin] Unit tests for pkg/source/stdin

- **Flow:** #057 — stdin unit tests
- **Severity:** medium
- **Area:** `pkg/source/stdin/`
- **Problem:** Пакет не имел unit-тестов. `NewStdinSourceWithReader(io.Reader)` создан специально для тестируемости — без тестов.
- **Resolution:** Добавлен `source_test.go` с 7 unit-тестами (strings.NewReader, без os.Stdin).
- **Status:** resolved (Flow #057)

---

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
     the NamedChannelSwitch), not a linear sequence. Chaining `Sink(→None) → Sink(ScoredEvent→)`
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
    its sentinel-threat sink by NCS channel name. `SemanticError` carries stream/pipeline/
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
