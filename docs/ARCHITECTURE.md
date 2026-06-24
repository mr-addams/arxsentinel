# ArxSentinel — Architecture

Архитектура ArxSentinel в её текущей форме (post-081 / post-083): разделение core/product,
product-security-слой поверх generic runtime, что приходит из arx-core, что остаётся
в ArxSentinel как product-specific код.

> **Движок** (`runtime.Run`, `LineProcessor`, `Action`, fan-in, NCS wiring) — в
> [`arx-core/docs/architecture.md`](https://github.com/mr-addams/arx-core/blob/v0.1.0/docs/architecture.md). Этот документ
> описывает **только** product-security-слой ArxSentinel, который сидит поверх движка.

---

## 1. Где проходит граница core/product

ArxSentinel построен на [arx-core](https://github.com/mr-addams/arx-core/blob/v0.1.0/README.md) — generic line-oriented
telemetry pipeline. Граница зафиксирована в [ADR-002](architecture/adr/002-telemetrycore-boundary.md)
и пересмотрена после flows 081/083:

- **arx-core** владеет: runtime (`pkg/runtime`), plugin-интерфейсами
  (`pkg/plugin` — `Source`, `Sink`, `Detector`, `Processor`, `Executor`),
  generic `*plugin.Event` (Envelope + opaque Payload), парсером HTTP-форматов
  (`pkg/parser` с `LogEntry`), стандартными Source/Sink-имплементациями
  (`pkg/source/{file,stdin,syslog,http,exec,sentinel}`, `pkg/sink/{file,stdout,exec,sentinel}`),
  NCS-bridge и queue-backends (`pkg/ncs`, `pkg/executor/queue`),
  exec+JSON protocol (`pkg/execplugin`).
- **ArxSentinel (product)** владеет: `*ThreatEvent` (в `internal/threat/`),
  `*securityProcessor` (реализация `runtime.LineProcessor` в `cmd/arxsentinel/processor_security.go`),
  product-форматтерами для sentinel-bridge, product-детекторами
  (`pkg/detectorplugins/*` — probe, rate, useragent, bruteforce, crawler,
  noasset, overflow, badbot), whitelist/chaincheck/blocklist, всеми
  product-исполнителями (executors: cloudflare, mikrotik, nginx).

`pkg/runtime` импортирует **только** stdlib + `github.com/mr-addams/arx-core/pkg/{plugin,input}`.
Никаких `arxsentinel/...` импортов внутри `github.com/mr-addams/arx-core/pkg/runtime/` — это
инвариант ADR-002. Score / detectors / threat-intel живут в product и
достигают движка через opaque closures внутри `LineProcessorFactory.Build`.

---

## 2. Запуск продукта — `cmd/arxsentinel/main.go`

Top-level стартовая последовательность (порядок менять нельзя — нарушение
порядка ведёт к nil-pointer panic или пропущенным событиям):

```
main()
├─ config.LoadConfig()              [load YAML, apply migrations]
├─ utils.Init()                     [initialize logger]
├─ writePID()                       [write daemon PID]
├─ signal.NotifyContext()           [bind SIGTERM/SIGINT]
├─ metrics.Init()                   [register Prometheus vectors]
├─ HTTP metrics server              [goroutine, port 9999]
├─ blocklist.NewManager()           [load UA/referer blocklist]
├─ chaincheck.NewChecker()          [init proxy chain validator]
└─ runtime.Run(ctx, streamSpec, factory, shared, reloadCh, logFn)
       └─ движок arx-core пишет в sinks, считает eventCount,
          дёргает MetricsCallbacks — продукт только поставляет
          factory + shared.
```

Долгое время шаги `for each stream: runStream()` → `for each pipeline:
runPipeline()` → `main loop: processLine(entry)` жили в продуктовом коде.
В flow 081 это целиком переехало в `github.com/mr-addams/arx-core/pkg/runtime/engine.go` —
теперь продукт только собирает `StreamSpec`/`PipelineSpec` и передаёт
в `runtime.Run` свой `LineProcessorFactory` (см. §3). Подробности
lifecycle (Build / Reload / Process / dispatchEntry / fan-in) — в
[`arx-core/docs/architecture.md`](https://github.com/mr-addams/arx-core/blob/v0.1.0/docs/architecture.md#3-pipeline-lifecycle-runpipeline).

---

## 3. Product pipeline — `securityProcessor`

`securityProcessor` — реализация `runtime.LineProcessor` из arx-core.
Один `securityProcessor` per pipeline; его opaque-state (`securityState`)
живёт между вызовами `Process()` и обновляется через `factory.Reload`
на SIGHUP. Полный исходник — `cmd/arxsentinel/processor_security.go`.

```go
// cmd/arxsentinel/processor_security.go
type securityState struct {
    StreamName, PipelineName string
    PipelineIdx              int
    Tracker                  *state.Tracker
    Scorer                   *scorer.Scorer
    Matcher                  *whitelist.Matcher
    Verifier                 *whitelist.Verifier
    FakeBotScore             int
    DNSVerifyTimeout         time.Duration
}

type securityProcessor struct {
    shared coreruntime.SharedResources
}

func (p *securityProcessor) Process(
    ctx context.Context,
    entry *plugin.Event,
    state coreruntime.ProcessorState,
    evctx coreruntime.EventContext,
) coreruntime.Action {
    ss := state.(*securityState)
    le, _ := pluginparser.UnwrapLogEntry(entry.Payload) // *parser.LogEntry

    // 1) Whitelist (IP / CIDR / UA / bot)
    if ss.Matcher.IsWhitelisted(le) { return coreruntime.Action{Skip: true} }

    // 2) Chain-check (proxy chain integrity)
    if chainIssue := ss.Verifier.CheckChain(le); chainIssue != "" {
        ss.Tracker.RecordChainIssue(le.RealIP, chainIssue)
    }

    // 3) Bot UA → DNS verify
    if bot, ok := ss.Matcher.MatchBot(le.UserAgent); ok {
        if !ss.Verifier.Verify(ctx, le.RealIP, bot) {
            ss.Tracker.ApplyFakeBotPenalty(le.RealIP, ss.FakeBotScore)
        }
    }

    // 4) Tracker update (per-IP state)
    ss.Tracker.Update(le.RealIP, le)

    // 5) Score via product detectors
    threat := ss.Scorer.Evaluate(ss.Tracker.View(le.RealIP), le)
    if threat == nil { return coreruntime.Action{} } // no event

    // 6) Wrap into product-owned *threat.ThreatEvent,
    //    attach to *plugin.Event, return Action with payload.
    return coreruntime.Action{
        Payload: &plugin.Event{
            Envelope: plugin.Envelope{
                Timestamp: le.Time, Stream: ss.StreamName,
                Source: evctx.SourceName, SourceType: evctx.SourceType,
                Level: threat.Level,
            },
            Payload: threat, // *threat.ThreatEvent
        },
    }
}
```

Движок после `Process()`:
- читает `Action.Payload.Envelope.Level` для metrics (`THREAT` инкрементит `eventCount`),
- фан-аутит `Action.Payload` во все `Sink`s из `PipelineSpec.Sinks`,
- вызывает `RecordOutputEvent` callback per sink.

Sink-имплементации получают `*plugin.Event` с opaque Payload и сами решают,
как его сериализовать. `SentinelThreatSink` (NCS-bridge) использует
product-side `Formatter` (`internal/threat/format`) для JSON-сериализации
`*threat.ThreatEvent` в wire-байты, которые ложатся в queue.

---

## 4. Per-entry flow (security-логика внутри `Process`)

```
*plugin.Event (Payload: *parser.LogEntry)
    │
    ├─ UnwrapLogEntry → *parser.LogEntry
    │
    ├─ Whitelist.Matcher.IsWhitelisted(IP/UA)?
    │   └─ yes → Action{Skip: true}, row out
    │
    ├─ ChainChecker.Check(RealIP)
    │   ├─ Cloudflare / Akamai IP? → validate trusted proxies
    │   └─ Bogon IP? → flag and drop
    │
    ├─ Whitelist.Matcher.MatchBot(UA)
    │   ├─ Known bot? → Verifier.Verify(IP, botName)
    │   │   ├─ DNS verify: rDNS/fDNS → pass? → mark verified (no penalty)
    │   │   └─ fail? → mark as fake bot (apply fake_bot_score in tracker)
    │   └─ Unknown UA → treat as potential threat
    │
    ├─ Tracker.Update(RealIP, entry)
    │   ├─ total requests
    │   ├─ status codes (404s, 403s)
    │   ├─ recent paths (ring buffer, last 64)
    │   └─ sliding-window rate counters
    │
    ├─ Scorer.Evaluate(Tracker.View(IP), entry)
    │   ├─ run 8 product detectors (probe, rate, ua, bruteforce, ...)
    │   │   каждый возвращает DetectResult{Score, Module, Reason}
    │   ├─ aggregate score (linear decay за observation_window)
    │   └─ verdict: empty | WARN (≥alert_threshold) | THREAT (≥ban_threshold)
    │
    └─ if verdict != "":
         └─ *threat.ThreatEvent {Level, Score, Modules, Reason, ...}
            wrapped in *plugin.Event{Envelope{Level: "WARN"|"THREAT"}, Payload: ...}
                 │
                 ▼  engine: фан-аут во все Sinks
         ┌───────────────┬─────────────────┬──────────────────────────┐
         ▼               ▼                 ▼                          ▼
   FileSink         StdoutSink    SentinelThreatSink            exec+JSON sink
   (fail2ban)       (JSON line)   (NCS queue: ncs://threats)   (subprocess)
                                            │
                                            ▼ Executor-impl
                                    ┌───────────────┬──────────────┐
                                    ▼               ▼              ▼
                              Cloudflare     MikroTik         nginx
                              IP Lists API   firewall add     blocklist file
                              (TTL sweep)    (TTL sweep)      (atomic write)
```

### Whitelist Matching (early exit)

Четыре слоя whitelist (config keys: `whitelist.cidrs`, `whitelist.ips`,
`whitelist.user_agents`, `whitelist.bots[]`):

1. **CIDR-блоки** — `192.168.0.0/16`, `10.0.0.0/8` (внутренние сети).
2. **Exact IP list** — `127.0.0.1`, monitoring tools.
3. **User-Agent substrings** — `curl/*`, `wget/*`.
4. **Bot UA + DNS verification** — `Googlebot/.*` + reverse_dns_suffix `.google.com`.
   Verifier делает двустороннюю DNS-проверку: rDNS(IP) заканчивается на
   `bot.domain` И fDNS(hostname) резолвится обратно в IP. Если оба
   pass — бот настоящий, событий нет. Иначе — fake_bot_score пенальти
   накапливается в tracker, scorer использует его при скоринге.

### Tracker: per-IP state

Каждый `TrackerGroup` (per stream, может быть shared через `tracker_group`)
держит `map[IP]*IPState`:

```go
type IPState struct {
    TotalRequests    int
    Recent404Count   int
    Recent403Count   int
    RecentPaths      []*RecentPath // ring buffer, last 64
    RatePerSecond    float64
    LastActivity     time.Time
    FakeBotPenalty   bool   // failed DNS verify
    IsSuspicious     bool   // cached from last scorer evaluate
}
```

GC запускается раз в `state.gc_interval` (default 5m), удаляет IP
с `time.Since(LastActivity) > state.max_age` (default 24h).

### Scorer: threat evaluation

`Scorer.Evaluate(ipView, entry)` запускает все включённые product-детекторы,
агрегирует scores (linear decay за `scoring.observation_window`) и
выдаёт `ThreatResult`:

```go
type ThreatResult struct {
    Level   string   // "", "WARN", "THREAT"
    Score   int      // 0..100 (с учётом decay)
    Modules []string // ["probe", "rate", "bruteforce"]
    Reason  string   // human-readable
}
```

Если `Score >= ban_threshold` → `Level = "THREAT"` (Fail2Ban ban).
Если `alert_threshold ≤ Score < ban_threshold` → `Level = "WARN"`.
Иначе → `Level = ""` (нет события).

### Detectors (built-in)

| Detector | Триггер | Default score |
|----------|---------|---------------|
| probe | запросы на `/.env`, `/.git`, `/wp-config.php` и т.п. | 25 / request |
| rate | > N запросов за window | 25 |
| useragent | scanner / grabber / automation / empty UA | 15–40 |
| bruteforce | >60% ответов 4xx при ≥10 запросов | 30 |
| crawler | ≥5 последовательных `/page/N` | 20 |
| noasset | <10% запросов к static assets при ≥3 page requests | 20 |
| overflow | URL >2048 chars или WAF bypass keywords | 30 |
| badbot | UA/Referer матчит community blocklist (~685 patterns) | 60 |

Score-конфиг: `detectors.<name>.score` (per-detector override).
Threshold-конфиг: `scoring.alert_threshold` (default 50), `scoring.ban_threshold` (default 80).
Window-конфиг: `scoring.observation_window` (default 300s).

---

## 5. NCS (Named Channel Switch) — меж-pipeline маршрутизация

NCS — generic queue-fanout primitive в `github.com/mr-addams/arx-core/pkg/ncs/`. **Не дёргается
из `pkg/runtime`** — это product-infrastructure. ArxSentinel использует
NCS, чтобы отделить детектор-pipeline (читает access.log, скоры) от
executor-pipeline (Cloudflare API call, MikroTik block, nginx blocklist).
Один pipeline пишет, другой читает; они могут жить в разных процессах
и даже в разных k8s-replicas (с `bbolt` или `redis` backend).

```
Detector-pipeline
  └─ SentinelThreatSink (formatter = product JSON)
       └─ executor.AttachWriter("ncs://cf-threats")
              │ queue.Queue (memory | bbolt | redis)
              ▼
Executor-pipeline (Cloudflare)
  └─ SentinelSource (cfg.Addr = "ncs://cf-threats")
       └─ Executor.Run(ctx, source) → CF API call → TTL sweep
```

> **⚠️ NCS — Work Queue, не Pub/Sub.** Если подключить два executor к
> одному `ncs://threats`, они получат события round-robin (~50% each).
> Для fan-out на несколько executor-ов — отдельный channel per executor
> (валидатор `ValidateExecutorWiring` ловит writer без reader, но
> не ловит два reader на одном channel):
>
> ```yaml
> streams:
>   - outputs:
>       - type: sentinel-threat, name: cf-threats
>       - type: sentinel-threat, name: mtk-threats
> executors:
>   - name: cf-ban,  sources: [{name: cf-threats}]
>   - name: mtk-ban, sources: [{name: mtk-threats}]
> ```

Backend-выбор: `memory` (single-process), `bbolt` (file-persisted),
`redis` (multi-replica). См. [arx-core/pkg/ncs/README.md](https://github.com/mr-addams/arx-core/blob/v0.1.0/pkg/ncs/README.md).

---

## 6. Executors — stateful action plugins

Executors читают `*plugin.Event` из NCS-очереди (`EventSource.Pop`) и
выполняют side-effect (block IP, send alert). В отличие от sink-ов
(passive log writers), executors активны и хранят состояние:

| Executor | Действие | TTL |
|----------|----------|-----|
| **cloudflare** | `POST /accounts/{id}/rules/lists` — IP в IP List | config `ttl` (auto sweep) |
| **mikrotik** | RouterOS v7 REST `/rest/ip/firewall/address-list/add` | config `ttl` (auto unban) |
| **nginx** | atomic write в blocklist файл, опционально reload команда | config `ttl` |

Каждый executor реализует `plugin.Executor` из arx-core, держит:
- **Dedup map** (пропускает уже-known IP — избегает повторных API calls).
- **TTL scheduler** (auto-unban после expiry).
- **Startup sync** (загружает remote state, например, текущий CF IP List).
- **Retry / circuit-breaker** на внешние API errors.

Полные API детали каждого — в:
- `pkg/executorplugins/cloudflare/README.md` + `docs/executor-cloudflare.md`
- `pkg/executorplugins/mikrotik/README.md` + `docs/providers/mikrotik/`
- `pkg/executorplugins/nginx/README.md` + `docs/executor-nginx.md`

### Executor data flow

```
detector-pipeline ──→ SentinelThreatSink ──→ NCS queue "threats"
                                                    │
                                                    ▼
executor-pipeline:
  SentinelSource.Run() ──→ *plugin.Event (Payload: *threat.ThreatEvent)
       └─ Executor.Run(ctx, eventSource) {
            ├─ for event := range eventSource.Pop(ctx) {
            │    ├─ Dedup check (skip if known)
            │    ├─ External API call (e.g., CF IP List add)
            │    ├─ Mark in dedup map
            │    └─ Schedule TTL expiry
            │  }
            └─ TTL sweep goroutine: auto-unban after expiry
       }
```

---

## 7. ThreatEvent — product-owned DTO

`ThreatEvent` живёт в `internal/threat/threatevent.go` (НЕ в arx-core
`pkg/plugin` — это post-083 изменение, см. ADR-002 boundary rule). Поля:

```go
// internal/threat/threatevent.go
type ThreatEvent struct {
    Timestamp  time.Time
    Level      string   // "WARN" | "THREAT"
    Stream     string
    Source     string
    SourceType string
    IP         string
    Score      int
    Modules    []string
    Reason     string
    RawLine    string
}
```

Wire-format (JSON) сериализуется через `internal/threat/format` —
product-owned `Formatter` имплементация. `SentinelThreatSink`
(github.com/mr-addams/arx-core/pkg/sink/sentinel) вызывает `formatter.Format(event)`,
получает bytes, кладёт в NCS queue. На принимающей стороне
`SentinelSource` достаёт bytes, оборачивает в `json.RawMessage` в
`Event.Payload`, дальше `queue_event_source.Pop` делает JSON-decode
в `*threat.ThreatEvent` для executor-а.

`github.com/mr-addams/arx-core/pkg/runtime/` НЕ импортирует `internal/threat/`. Это
граница — runtime знает только `*plugin.Event{Envelope, Payload}`,
Payload type-assert происходит в product-имплементациях
(`securityProcessor`, `SentinelSource`, executors).

---

## 8. Plugin registry & multi-stream

Plugins регистрируются через `init()` + `Register(name, factory)`.
Всегда подключённые транспорты:
- **Sources**: `file`, `stdin`, `syslog`, `http`, `exec`, `sentinel` (`ncs://`)
- **Sinks**: `file`, `stdout`, `exec`, `sentinel-threat`
- **Executors**: `cloudflare`, `mikrotik`, `nginx`
- **Detectors** (always-linked, per build profile design): 8 built-in
- **Processors**: `whitelist`, `chaincheck` (direct call, not registry)

Tree-shaking управляется через `profiles/<name>.yaml` (build-time,
`arx_tag` sentinel). Подробности — в
[`docs/developer/build-profiles.md`](developer/build-profiles.md) и
[`arx-core/docs/build-profiles.md`](https://github.com/mr-addams/arx-core/blob/v0.1.0/docs/build-profiles.md).

### Multi-stream / multi-pipeline

Один ArxSentinel процесс держит несколько streams, каждый со своими
pipelines. Streams полностью изолированы (no shared tracker/scoring).
Pipelines внутри stream могут делиться IP-state через `tracker_group`:

```yaml
streams:
  - name: nginx-monitoring
    pipelines:
      - name: api-scanner
        tracker_group: web              # pipelines с одним group делят IP state
        inputs: [{type: file, path: /var/log/nginx/api.log}]
        detectors: { probe: {enabled: true}, rate: {enabled: true} }
        outputs: [{type: file, path: /var/log/arxsentinel/api-threats.log}]
      - name: admin-watcher
        tracker_group: web              # ← shared с api-scanner
        inputs: [{type: file, path: /var/log/nginx/admin.log}]
        detectors: { bruteforce: {enabled: true}, badbot: {enabled: true} }
        outputs: [{type: file, path: /var/log/arxsentinel/admin-threats.log}]
```

Метрики получают label `pipeline` — `arx_sentinel_lines_processed_total{stream, pipeline}`.
Legacy pipelines (auto-wrapped из single-pipeline config) — `pipeline=""`.

---

## 9. Startup sequence (product-side)

Порядок инициализации (нарушение → nil-pointer или пропущенные события):

1. **`config.LoadConfig()`** — read YAML, apply migrations, validate
   required fields (parsers, sinks). Return `*config.Config`.
2. **`utils.Init()`** — initialize logger (stdout, file, syslog).
   После этого любой `Log()` работает.
3. **`writePID()`** — write daemon PID (e.g. `/var/run/arxsentinel.pid`).
   Логгирует через `utils.Log` (требует step 2).
4. **`signal.NotifyContext()`** — bind SIGTERM/SIGINT к `appCtx.Done()`.
   После этого горутины могут проверять `ctx.Done()`.
5. **`metrics.Init()` + `http.Server.ListenAndServe()`** — register
   Prometheus vectors, start HTTP server в background. Scraper видит
   continuous series.
6. **`blocklist.NewManager()`** — load UA/referer blocklist, open bbolt
   storage. Нужен для `Detector.Detect()` (badbot-детектор) и whitelist.
7. **`chaincheck.NewChecker()`** — load trusted proxies list, compile
   Cloudflare / bogon ranges. Готов к `ChainChecker.Check()` в Process.
8. **`runtime.Run(...)`** — построить `StreamSpec`/`PipelineSpec`/factory,
   вызвать `runtime.Run`. Движок arx-core стартует pipelines (см.
   [`arx-core/docs/architecture.md` §3](https://github.com/mr-addams/arx-core/blob/v0.1.0/docs/architecture.md#3-pipeline-lifecycle-runpipeline)).

---

## 10. Configuration

Top-level YAML (`/etc/arxsentinel/config.yaml`):

```yaml
general:
  version: 1
  log_file: /var/log/nginx/access.log
  stats_interval: 60s

parser:
  profile: nginx                    # nginx | apache | traefik | haproxy-http | caddy | litespeed

scoring:
  alert_threshold: 50               # WARN threshold
  ban_threshold: 80                 # THREAT threshold
  observation_window: 300s

state:
  gc_interval: 5m
  max_age: 24h

detectors:
  probe:    { enabled: true, score: 25, paths: [...] }
  rate:     { enabled: true, score: 25, threshold: 100, window: 60s }
  useragent:{ enabled: true, scanner_score: 40, grabber_score: 20, automation_score: 15, empty_ua_score: 30 }
  bruteforce:{ enabled: true, score: 30, ratio_threshold: 0.6, min_requests: 10 }
  crawler:  { enabled: true, score: 20, min_sequential: 5 }
  noasset:  { enabled: true, score: 20, asset_ratio_threshold: 0.1, min_page_requests: 3 }
  overflow: { enabled: true, score: 30, max_url_length: 2048, suspicious_params: [...] }
  badbot:   { enabled: true, score: 60, check_ua: true, check_referrer: false }

blocklist:
  storage: ""                       # in-memory; "path" = bbolt
  lists:
    - { name: badbot-ua, refresh_interval: 24h, sources: [...] }

whitelist:
  fake_bot_score: 35
  dns_verify_timeout: 2s
  ips: [127.0.0.1]
  cidrs: [10.0.0.0/8]
  ua_substrings: [internal-monitor]
  bots:
    - { name: Googlebot, ua_pattern: Googlebot/.*, reverse_dns_suffix: .google.com }

chaincheck:
  enabled: false
  trusted_proxies_file: /etc/arxsentinel/trusted-proxies.txt
  bogon_protection: false

streams:
  - name: nginx
    pipelines:
      - name: default
        tracker_group: web
        inputs:  [{ type: file, path: /var/log/nginx/access.log }]
        detectors: { probe: {enabled: true}, rate: {enabled: true} }
        outputs: [
          { type: file, path: /var/log/arxsentinel/threats.log, format: fail2ban },
          { type: sentinel-threat, name: cf-threats },
        ]
executors:
  - name: cf-ban
    type: cloudflare
    sources: [{name: cf-threats}]
    ttl: 24h
    api_token: "${CF_API_TOKEN}"
    list_id: "${CF_LIST_ID}"

metrics:
  enabled: true
  addr: ":9999"
```

> `yaml.v3 limitation:` если секция присутствует в config.yaml (e.g.
> `scoring:`), она должна включать **все** поля — пропущенные обнулятся.
> Секции отсутствующие целиком — Go defaults.

### Config migration

Legacy configs (< v1) с top-level `inputs/outputs/log_file` —
auto-wrapped в один unnamed stream (`stream=""` label на метриках):

```yaml
# old format
log_file: /var/log/app.log
inputs:  [{ type: file, path: /var/log/app.log }]
outputs: [{ type: file, path: /var/log/threats.log }]

# auto-migrated to
streams:
  - name: ""
    pipelines:
      - name: default
        tracker_group: default
        inputs:  [{ type: file, path: /var/log/app.log }]
        outputs: [{ type: file, path: /var/log/threats.log }]
```

Backward-compatible: legacy metrics с `pipeline=""` продолжают работать.

---

## 11. Plugin system — arx-core

Все Source/Sink/Detector/Processor/Executor интерфейсы живут в
`github.com/mr-addams/arx-core/pkg/plugin/`. Контракт, лайфцикл, init+blank-import pattern —
в [`arx-core/docs/plugin-development.md`](https://github.com/mr-addams/arx-core/blob/v0.1.0/docs/plugin-development.md).
Product-специфика (sentinel source/sink, security-детекторы, cloudflare/mikrotik
executors) — в `docs/PLUGIN_DEV.md` (этот документ) и `docs/executors.md`.

Продуктовые регистрации:
- `pkg/detectorplugins/{probe,rate,useragent,bruteforce,crawler,noasset,overflow,badbot}`
- `pkg/processorplugins/{whitelist,chaincheck}` (direct call, not registry)
- `pkg/executorplugins/{cloudflare,mikrotik,nginx}`
- Built-in sources/sinks — в `github.com/mr-addams/arx-core/pkg/source/`, `github.com/mr-addams/arx-core/pkg/sink/`.

---

## 12. Metrics

Все метрики помечены `stream` и `pipeline` (legacy — `stream=""`, `pipeline=""`).

### Request counters

```
arx_sentinel_lines_processed_total{stream, pipeline}
  Counter. Всего строк прочитано из sources.

arx_sentinel_threats_total{stream, pipeline, level}
  Counter. Угрозы записанные (level = "WARN" | "THREAT").
  Инкрементится движком когда Action.Payload.Envelope.Level != "" и Sink.Write OK.
```

### Threat analysis

```
arx_sentinel_detector_hits_total{stream, pipeline, detector}
  Counter. Per-detector hit count. Инкрементится когда DetectResult.Score > 0.

arx_sentinel_tracked_ips{stream, pipeline}
  Gauge. Текущее число tracked IPs в памяти.

arx_sentinel_suspicious_ips{stream, pipeline}
  Gauge. IPs с IsSuspicious = true.
```

### Source / sink activity

```
arx_sentinel_input_lines_total{stream, pipeline, source, source_type}
  Counter. Прочитано строк per source.

arx_sentinel_output_events_total{stream, pipeline, sink}
  Counter. Событий записанных per sink.

arx_sentinel_output_dropped_total{stream, pipeline, sink}
  Counter. Событий отброшенных per sink (write error).
```

### Blocklist freshness

```
arx_sentinel_blocklist_last_refresh_timestamp_seconds{list}
  Gauge. Unix timestamp последнего успешного refresh per list.
  list = имя blocklist из config (e.g. "badbot-ua").
```

**Scrape endpoint:** `http://<addr>/metrics` (default `:9999`).
**Auth (optional):** `metrics.auth: "user:pass"` — HTTP Basic Auth,
constant-time compare.

---

## 13. Error handling и resilience

### Source failure

`Source.Run()` возвращает error (file deleted, command crashed):

1. Log error with source name.
2. Backoff: sleep `general.tail_retry_interval` (default 5s).
3. Retry: reconnect and resume reading.
4. Max retries: infinite (configurable).

Если все sources fail, pipeline блокируется до восстановления — это by design
(data integrity > availability).

### Sink failure

`Sink.Write()` возвращает error:

1. Log error with sink name and event summary.
2. Increment `arx_sentinel_output_dropped_total` counter.
3. **Продолжить** к следующему sink — broken sink не должен стопить pipeline.
4. Engine-уровень: один failed sink в fan-out не убивает остальные sinks
   (см. [`arx-core/docs/architecture.md` §4](https://github.com/mr-addams/arx-core/blob/v0.1.0/docs/architecture.md#4-dispatchentry-one-row-processing)).

### Executor failure

`Executor.Execute()` returns error:

1. Increment `Executor.Stats().Errors`.
2. Event остаётся в queue (bbolt/redis) → может быть повторно popped
   после рестарта executor-pipeline.
3. Circuit-breaker (если настроен) открывается на N ошибок подряд,
   pause приём на M seconds.

### Graceful shutdown (SIGTERM/SIGINT)

```
SIGTERM
  ↓
  appCtx.Done()
  ↓
  runtime.Run видит ctx.Done() → для каждого pipeline:
    ├─ drain remaining entries (context.Background() — не cancelled)
    ├─ close sinks (SentinelThreatSink → flush queue)
    └─ close sources
  ↓
  tracker GC goroutines exit
  ↓
  runtime.Run() returns
  ↓
  main() reaches wg.Wait() → defers
  ↓
  cancel() → removePID() → utils.Close()
  ↓
  daemon exits (code 0)
```

Timeout: если shutdown > 30s, daemon hard-exits.

---

## 14. SIGHUP reload

`factory.Reload(old ProcessorState, ctx) → (new ProcessorState, error)` —
обязательный метод `LineProcessorFactory` (см. [arx-core/docs/contract.md](https://github.com/mr-addams/arx-core/blob/v0.1.0/docs/contract.md)).
На SIGHUP:

1. `appCtx` НЕ отменяется.
2. Engine отправляет event в `reloadCh` (per-stream).
3. `runPipeline` (внутри arx-core engine) вызывает `factory.Reload(ps, ctx)`.
4. Product `Reload()` перечитывает config, пересоздаёт `Scorer` и
   `Matcher`, **сохраняет** `Tracker` (IP state переживает reload),
   **сохраняет** `Verifier` (DNS cache не сбрасывается).
5. Engine атомарно подменяет `ps` в pipeline loop. Последующие строки
   идут через новый `scorer`/`matcher`.
6. Для каждого sink если он implements `Reloader` → `sink.Reload()`
   (например `FileSink` ротирует log file).

**Thread-safety:** `Build`/`Reload` могут вызываться параллельно для
sibling pipelines. Product implementations обязаны быть thread-safe.

**Что обновляется:** scorer (детекторы + thresholds), whitelist matcher,
debug/color flags, log paths.
**Что НЕ обновляется:** tracker (IP state), DNS cache, source paths
(требует restart).

---

## 15. Design rationale

### Почему NCS + отдельные executor-pipelines

Sink-и passive — write event to file/stdout. External API calls
(Cloudflare block, MikroTik firewall rule) требуют state: dedup,
TTL expiry, retry, circuit-breaker. Если впихнуть это в Sink,
каждый Sink должен реализовать всё это. NCS + Executor разделяет
ответственности:

- Detector-pipeline: stateless, fast, не блокируется на API latency.
- Executor-pipeline: stateful, async, не блокирует detection.

Multi-replica deployment: detector-pipeline в 10 pods, executor —
в 2 (через Redis NCS backend) — независимое масштабирование.

### Почему product-owned ThreatEvent

Generic `*plugin.Event` отделяет engine от domain. Если ThreatEvent
живёт в `github.com/mr-addams/arx-core/pkg/plugin`, то любое изменение ThreatEvent полей
меняет core, что противоречит ADR-002. Теперь:

- `github.com/mr-addams/arx-core/pkg/plugin` знает только `Event{Envelope, Payload any}`.
- `internal/threat/threatevent.go` — product-owned. Поменял поля —
  движок не заметил. Можно заменить ThreatEvent на другую структуру
  (e.g. в graph-aggregation), engine остался generic.

### Почему linear score decay

Без decay: IP делает 100 запросов на `/admin` за час → score=2500
вечно. Через 24 часа этот IP делает 1 GET `/` — всё ещё THREAT.
С decay: score спадает линейно за `observation_window` (default 5min
накапливается, 30min полностью спадает). Recurrent bad behavior
продолжает скор, но старая активность не держит IP в бане вечно.

### Почему whitelist имеет четыре слоя

Простое "ignore trusted IPs" не работает: бот может прикинуться
Googlebot (UA spoofing). Четвёртый слой — DNS-верификация — закрывает
это через rDNS+fDNS. Без DNS-верификации `whitelist.bots` —
это просто строка-фильтр, который тривиально спуфится.

### Почему два DNS queries (rDNS + fDNS)

Один rDNS недостаточен: атакующий может контролировать PTR-запись
своего IP (reverse zone). fDNS (forward resolve hostname → IP) должен
дать обратно тот же IP. Только обе проверки вместе = бот настоящий.
Cache 1h на per-(IP, bot) pair для производительности.

### Почему TrackerGroup

Без sharing: nginx pipeline видит 3 запроса от IP, apache — 2, итого
5 → score 45. С sharing: оба pipeline пишут в один tracker, итог 5
запросов, alert один раз. Trade-off: требует согласованного group
naming внутри stream; typo → silent isolation.

### Почему exec+JSON

ML-модели, third-party tools, vendor-specific детекторы часто не на Go.
Exec+JSON — language-agnostic протокол: `Plugin → Process → stdin/stdout NDJSON`.
Iterative development: rebuild plugin без пересборки ArxSentinel.
Resource isolation: можно запускать в контейнере / с cgroup limits /
под другим user. Compile-in для latency-critical кода, exec — для
всего остального.

---

## 16. Testing

### Unit tests

Каждый пакет имеет `_test.go`:
- `pkg/detectorplugins/*_test.go` — поведение детекторов.
- `internal/core/{scorer,state,whitelist,chaincheck,blocklist}/*_test.go`.
- `internal/threat/*_test.go` — ThreatEvent, Formatter.
- `cmd/arxsentinel/processor_security_test.go` — securityProcessor (mock tracker/scorer).
- `github.com/mr-addams/arx-core/pkg/runtime/engine_test.go` — engine lifecycle (Build, Reload, dispatchEntry).

Table-driven, focus on behavior, not implementation details.

### Integration tests

`cmd/arxsentinel/*_test.go` — full pipeline:

1. Создать config с mock sources/sinks.
2. Подать log lines.
3. Проверить что threat events записаны правильно в sink-и.

Также есть [`github.com/mr-addams/arx-core/examples/logaggregator/`](https://github.com/mr-addams/arx-core/tree/v0.1.0/examples/logaggregator) — минимальный standalone
пример (syslog source → filter detector → JSON sink), собирается
отдельно, доказывает что arx-core self-contained (`go list -deps
| grep arxsentinel` = пусто).

### Manual testing

```bash
# Dev mode
go build ./cmd/arxsentinel
./arxsentinel -c test.yaml

# Watch logs
tail -f /var/log/arxsentinel/sentinel.log

# Metrics
curl http://localhost:9999/metrics

# Reload without restart
kill -HUP $(cat /var/run/arxsentinel.pid)
```

---

## 17. Cross-references

- [`arx-core/docs/architecture.md`](https://github.com/mr-addams/arx-core/blob/v0.1.0/docs/architecture.md) — engine lifecycle, NCS wiring, fan-in, runtime.Run.
- [`arx-core/docs/contract.md`](https://github.com/mr-addams/arx-core/blob/v0.1.0/docs/contract.md) — symbol-level contract (`Run`, `LineProcessor`, `Action`, `EventContext`, `SharedResources`, `MetricsCallbacks`).
- [`arx-core/docs/plugin-development.md`](https://github.com/mr-addams/arx-core/blob/v0.1.0/docs/plugin-development.md) — как писать plugin (Source/Sink/Detector/Processor/Executor).
- [`docs/PLUGIN_DEV.md`](PLUGIN_DEV.md) — product plugin examples (sentinel-source/sink, exec+JSON, full sink-vs-executor comparison).
- [`docs/executors.md`](executors.md) — executor framework overview.
- [`docs/developer/build-profiles.md`](developer/build-profiles.md) — build-time tree-shaking, arx_tag sentinel.
- [`docs/architecture/adr/002-telemetrycore-boundary.md`](architecture/adr/002-telemetrycore-boundary.md) — Core/Product boundary (ADR-002, history).
- [`docs/architecture/pipeline.md`](architecture/pipeline.md) — product-pipeline specifics (securityProcessor wiring).
- [`docs/executor-cloudflare.md`](executor-cloudflare.md), [`docs/executor-nginx.md`](executor-nginx.md), [`docs/providers/mikrotik/`](providers/mikrotik/) — per-executor config & troubleshooting.

---

## 18. License

ArxSentinel is licensed under the [Elastic License 2.0](../LICENSE). Free use
for your own infrastructure. Commercial use as a managed security or telemetry
service, or as part of a managed service, requires a separate agreement.
