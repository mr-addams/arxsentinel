# ArxSentinel — Architecture

## Overview

ArxSentinel is a real-time web server log analyzer and threat detection daemon. It reads log entries from multiple sources (file tailing, stdin, exec plugins), detects attack patterns (probing, brute force, suspicious user agents, rate anomalies), and emits threat events to configurable sinks (files, stdout, external tools).

**Core design principle:** decouple data sources, detection logic, and output channels through pluggable registries. A single daemon can monitor multiple log streams and pipelines with independent threat scoring and output strategies.

---

## Component Hierarchy

### Top Level: Main Entry Point (cmd/arxsentinel/main.go)

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
└─ for each stream: runStream()     [goroutine per stream]
    └─ main event loop until ctx.Done()
```

**Startup sequence is strictly ordered.** Violating the order causes nil pointer panics or missed log lines. See [Startup Sequence](#startup-sequence) for details.

### Streaming Level: runStream()

```
runStream(streamName, streamCfg)
├─ buildTrackerGroups()             [map: groupName → *state.Tracker]
├─ for each tracker: RunGC()        [goroutine per group; prunes old IPs]
└─ for each pipeline: runPipeline() [goroutine per pipeline]
    └─ main processing loop until ctx.Done()
```

Each stream has its own set of TrackerGroups. Trackers within a group share IP state across pipelines in that stream; different streams are always isolated.

### Pipeline Level: runPipeline()

The core processing unit. One pipeline per input+detector+output combination.

```
runPipeline(pipelineName, pipelineCfg)
├─ whitelist.NewMatcher()                  [IP/CIDR/UA whitelist]
├─ whitelist.NewVerifier(matcher, shared)  [DNS bot verification]
├─ buildSources()                          [plugin.Source × N]
├─ buildSinks()                            [plugin.Sink × N]
├─ buildPipelineDetectors()                [plugin.Detector × N]
├─ coreinput.Merge(sources)                [multiplex source channels]
└─ main loop: processLine(entry)           [until sources close]
    ├─ metrics.RecordLine()
    ├─ ChainChecker.Check()                [proxy chain validation]
    ├─ Matcher.IsWhitelisted*()             [early return if matched]
    ├─ Matcher.MatchBot()                  [identify bot UA]
    ├─ Verifier.Verify()                   [DNS verify or mark fake]
    ├─ Tracker.Update()                    [update IP state]
    ├─ Scorer.Evaluate()                   [threat score via detectors]
    └─ if threat: Sink.Write()              [emit threat event]
```

---

## Data Flow

### Per-Entry Pipeline

```
Log Entry (file tail / stdin / exec)
    ↓
    Parser.Parse()  [regex | json | combined]
    ↓ LogEntry{IP, UA, Path, StatusCode, Size, ...}
    ↓
    ChainChecker.Check(IP)
    ├─ Cloudflare/Akamai IP? → validate trusted proxies
    └─ Bogon IP? → optionally flag and drop
    ↓
    Matcher.IsWhitelistedIP(IP)  →  drop if matched
    ↓
    Matcher.IsWhitelistedUA(UA)  →  drop if matched
    ↓
    Matcher.MatchBot(UA)
    ├─ Known bot? → Verifier.Verify(IP, botName)
    │   ├─ DNS verify: rDNS/fDNS → pass? → mark as verified
    │   └─ fail? → mark as fake bot (apply penalty in scorer)
    └─ Unknown UA → treat as potential threat
    ↓
    Tracker.Update(IP, entry)
    ├─ increment total requests
    ├─ track status codes (404s, 403s)
    ├─ record recent request paths
    └─ compute current request rate
    ↓
    IPState{
        TotalRequests: 42,
        Recent404Count: 12,
        RecentPaths: ["GET /admin", "GET /config"],
        RatePerSecond: 3.2,
        LastActivity: now,
        ...
    }
    ↓
    Scorer.Evaluate(ipState, entry)
    ├─ for each Detector.Detect(ipView, entry) → DetectResult
    │   ├─ Probe: check for path enumeration (/admin, /.env, etc.)
    │   ├─ Rate: check if requests/sec exceeds threshold
    │   ├─ UA: check UA blocklist + regex patterns
    │   ├─ Bruteforce: check 4xx spike
    │   ├─ Crawler: check if User-Agent implies crawler
    │   ├─ NoAsset: check GET to /path without .ext
    │   ├─ Overflow: check request size anomalies
    │   └─ BadBot: custom detector logic + exec-plugin support
    ├─ aggregate scores: threat level, confidence, module list
    └─ return (ThreatEvent | empty)
    ↓
    if ThreatLevel ≠ "": for each Sink.Write(threatEvent)
    ├─ FileSink: append to threat log
    ├─ StdoutSink: print to stderr
    ├─ ExecSink: pass JSON to subprocess
    └─ SentinelThreatSink: push to NCS queue
       │ executor.AttachWriter("ncs://threats")
       ↓
    ╔══════════════════════════════════════════╗
    ║  Named Channel Switch (Work Queue)       ║
    ║  backend: memory │ bbolt │ redis         ║
    ╚═══════════════════╤══════════════════════╝
                        │ executor.AttachReader("ncs://threats")
                        ↓
    Executor source: Pop(ctx) loop
    ├─ Dedup Map check  → skip if IP already acted on
    ├─ Executor.Execute(ctx, event)
    │  ├─ Cloudflare:  API call → add IP to IP List
    │  ├─ MikroTik:    REST API → add to address-list
    │  └─ nginx:       atomic file write + reload command
    ├─ Mark in dedup map
    └─ TTL Scheduler: goroutine → auto-unban after expiry
    ↓
    metrics.RecordThreat(level, detector, ...)
```

### State Management

**Per-IP state survives across log lines:**

```
IP → Tracker → IPState {
    TotalRequests: int
    Recent404Count, Recent403Count: int
    RecentPaths: []*RecentPath     [time + method + path]
    RatePerSecond: float64
    LastActivity: time.Time
    FakeBotPenalty: bool           [failed DNS verify]
    IsSuspicious: bool             [cached from last evaluate]
}
```

When tracker's GC runs (every `state.gc_interval`), it prunes entries where `time.Now() - LastActivity > state.max_age`.

---

## Startup Sequence

**Order is mandatory.** Violations cause nil panics or missed events.

1. **config.LoadConfig()**
   - Read YAML file
   - Run migration (legacy fields → pipelines)
   - Validate required fields (parsers, sinks)
   - Return *config.Config

2. **utils.Init()**
   - Initialize logger (stdout, file, syslog)
   - Parse color settings
   - Now any Log() call works

3. **writePID()**
   - Write daemon PID to file (e.g., /var/run/arxsentinel.pid)
   - Logged via utils.Log (requires step 2)

4. **signal.NotifyContext()**
   - Bind SIGTERM/SIGINT to appCtx.Done()
   - Now goroutines can check ctx.Done()

5. **metrics.Init() + http.Server.ListenAndServe()**
   - Register Prometheus vectors (lines_processed_total, threats_total, etc.)
   - Start HTTP server in background goroutine
   - Scraper sees continuous series

6. **blocklist.NewManager()**
   - Load UA/referer blocklist from sources (file or HTTP)
   - Open bbolt database for in-memory storage
   - Essential for Detector.Detect() calls (step 8)

7. **chaincheck.NewChecker()**
   - Load trusted proxies list (optional)
   - Compile Cloudflare IP ranges, bogon ranges
   - Ready for ChainChecker.Check() in processLine

8. **for each stream: runStream()**
   - Last step: all shared resources exist
   - Each stream launches TrackerGroup GC and runPipeline goroutines
   - Main loop begins

---

## Event Routing: Direct Channels vs Named Channel Switch

ArxSentinel uses two distinct event routing mechanisms with different semantics,
performance characteristics, and use-cases. Choosing the wrong one is the single
most common configuration mistake — see the warning below.

### Two routing mechanisms

```
Intra-pipeline (Direct Go Channels):
  Source → entries chan → processLine() → Detectors → Sink.Write()
  Latency: 1–5 ms · Synchronous · Single process

Inter-pipeline (Named Channel Switch):
  Pipeline A → sentinel-threat sink → NCS queue → Pipeline B source → Executor
  Latency: queue-dependent · Async · Cross-process capable
```

### 1. Direct Go Channels (intra-pipeline routing)

**Used by:** Source, Detector, and Sink plugins within a single pipeline.

**How it works:**
- Sources push `*plugin.LogEntry` into an `entries chan`
- Detectors are called synchronously via `Scorer.Evaluate(entry)`
- Sinks receive `plugin.ThreatEvent` via direct `Sink.Write(ctx, event)` calls

**Properties:**
- Minimal latency (1–5 ms per event, no serialization)
- Synchronous processing within a single pipeline goroutine
- No deduplication, no persistence, no queue
- Each pipeline is fully isolated — no shared mutable state between pipelines

**When to use:** log parsing, in-process detection, passive logging,
writing to files / stdout / syslog.

### 2. Named Channel Switch — NCS (inter-pipeline routing)

**Used by:** Executor plugins (Cloudflare, MikroTik, nginx blocklist).

**How it works:**
- A `sentinel-threat` sink pushes `plugin.ThreatEvent` into a named NCS queue via `executor.AttachWriter(name, bufSize)`
- An executor source reads the queue via `executor.AttachReader(name)` using the `ncs://<name>` address scheme
- Three queue backends are supported: `memory` (in-process), `bbolt` (on-disk file), `redis` (cross-process)

**Properties:**
- Asynchronous, buffered; producers do not block on consumer speed
- Supports multi-replica deployment (bbolt/redis backends)
- Queue persistence survives process restarts (bbolt/redis)
- **Point-to-Point semantics (Work Queue):** each event is delivered to exactly one reader

**When to use:** IP blocking via external APIs, firewall management, any
stateful enforcement that needs deduplication, TTL expiry, or
cross-process / multi-replica routing.

> ⚠️ **CRITICAL: NCS is a Work Queue, not Pub/Sub.**
>
> Connecting two executors to the same `ncs://threats` channel does
> **not** broadcast events to both. The NCS distributes events between
> attached readers in round-robin fashion — each reader sees roughly
> half the events. If you want two executors to receive every event,
> declare two separate output channels:
>
> ```yaml
> # ❌ WRONG: round-robin between the two executors
> streams:
>   - name: main
>     outputs:
>       - type: sentinel-threat
>         name: threats
> executors:
>   - name: cf-ban
>     type: cloudflare
>     sources:
>       - name: threats     # receives ~50% of events
>   - name: mtk-ban
>     type: mikrotik
>     sources:
>       - name: threats     # receives the other ~50%
> ```
>
> ```yaml
> # ✅ CORRECT: one dedicated channel per executor
> streams:
>   - name: main
>     outputs:
>       - type: sentinel-threat
>         name: cf-threats
>       - type: sentinel-threat
>         name: mtk-threats
> executors:
>   - name: cf-ban
>     type: cloudflare
>     sources:
>       - name: cf-threats
>   - name: mtk-ban
>     type: mikrotik
>     sources:
>       - name: mtk-threats
> ```
>
> The same rule applies to any number of executors. The validator
> (`ValidateExecutorWiring`) catches a writer without a reader at
> startup, but it cannot catch two readers sharing a channel — that
> only shows up as missing events in production.

### When to use which mechanism

| Use-case | Mechanism | Reason |
|---|---|---|
| Log parsing and enrichment | Direct channels | Zero overhead, synchronous |
| In-process threat scoring | Direct channels | `Scorer.Evaluate()` is synchronous |
| Writing to file / stdout / syslog | Direct Sink | No inter-process communication needed |
| Blocking IPs via external API | NCS + Executor | Stateful, dedup, TTL, queue persistence |
| Multi-pipeline fan-out | NCS (multiple outputs) | One output per executor, each gets full stream |
| Multi-replica K8s deployment | NCS + Redis/bbolt | Shared queue across replicas |

### See also

- [`pkg/executor/README.md`](../pkg/executor/README.md) — NCS API reference and startup ordering
- [`pkg/executor/queue/README.md`](../pkg/executor/queue/README.md) — queue backend selection guide
- [`docs/executors.md`](executors.md) — executor framework overview

---

## Pipeline Processing

### Whitelist Matching (Early Exit)

Whitelist has four layers:

1. **IP CIDR blocks** (e.g., internal network)
   ```yaml
   whitelist:
     cidrs: ["192.168.0.0/16", "10.0.0.0/8"]
   ```

2. **Exact IP list** (e.g., monitoring tools)
   ```yaml
   whitelist:
     ips: ["1.2.3.4", "5.6.7.8"]
   ```

3. **User-Agent patterns** (e.g., known crawlers)
   ```yaml
   whitelist:
     user_agents: ["curl/*", "wget/*"]
   ```

4. **Bot UA + DNS verification** (e.g., real Googlebot)
   ```yaml
   whitelist:
     bots:
       - name: "Googlebot"
         ua_pattern: "Googlebot/.*"
         reverse_dns_suffix: ".google.com"
   ```
   The verifier performs bidirectional DNS check:
   - rDNS(IP) → must end with `.google.com`
   - fDNS(hostname) → must resolve back to IP
   - If both pass: bot is real; return (no threat)
   - If fail: apply fake-bot penalty in scorer

### Tracker: IP State Accumulation

Each TrackerGroup maintains `map[IP]*IPState`. When a new log line arrives:

1. Look up IP in tracker
2. If not found, create fresh IPState
3. Increment TotalRequests
4. If status 404, increment Recent404Count (with time window)
5. Append {Method, Path} to RecentPaths (keep last 50)
6. Recompute RatePerSecond: requests / time since last reset
7. Update LastActivity = now

Example:
```
IP 203.0.113.42 makes 5 requests in 2 seconds
├─ req1: GET /index.html → 200
├─ req2: GET /nonexist → 404
├─ req3: GET /admin → 404
├─ req4: GET /.env → 404
└─ req5: POST /api → 200

IPState.TotalRequests = 5
IPState.Recent404Count = 3
IPState.RatePerSecond = 5 / 2s = 2.5 req/s
IPState.RecentPaths = [
  {GET, /index.html},
  {GET, /nonexist},
  {GET, /admin},
  {GET, /.env},
  {POST, /api}
]
```

Garbage collection runs periodically: if IP's LastActivity is older than `state.max_age`, remove the entry.

### Scorer: Threat Evaluation

The Scorer aggregates threat signals from multiple detectors.

```go
type ThreatResult struct {
    Level      string    // "", "WARN", "THREAT"
    Score      float32   // 0-100
    Modules    []string  // ["probe", "rate", "bruteforce"]
    Reason     string    // human-readable explanation
}
```

Each detector contributes a score (0-100) and a reason:

- **Probe**: Check if IP is requesting sensitive paths (/admin, /.env, /config, etc.)
  - Score += 30 per suspicious path
  - Max 100

- **Rate**: Check if requests/sec exceeds threshold
  - Threshold configurable (default 10 req/s)
  - Score = (actual_rate / threshold) * 100
  - Capped at 100

- **UA (User-Agent)**: Check against blocklist and regex patterns
  - Score += 20 if in blocklist
  - Score += 50 if matches malicious regex (sql-injection probes, etc.)

- **Bruteforce**: Check for spike in 4xx status codes
  - Threshold: default 20 (percent of requests in window)
  - Score += 40 if breached

- **Crawler**: Check if UA identifies as crawler but not in whitelist
  - Score += 15

- **NoAsset**: Check GET requests without file extension
  - Suggests enumeration
  - Score += 20 per request (capped)

- **Overflow**: Check request size > threshold
  - Score += 50

- **BadBot**: Custom detector (exec plugin support)
  - Returns arbitrary score

**Aggregation:**
```
total_score = sum(all detector scores)
if total_score > alert_threshold (default 70):
    level = "THREAT"
elif total_score > warn_threshold (default 40):
    level = "WARN"
else:
    level = ""  (no event)

if level != "":
    emit ThreatEvent with level, score, modules, reason
```

---

## TrackerGroup: Shared IP Memory

By default, each pipeline has its own isolated tracker. However, you can share trackers across pipelines:

```yaml
streams:
  - name: webservers
    pipelines:
      - name: nginx
        tracker_group: web      # ← group name
        inputs: [...]
      - name: apache
        tracker_group: web      # ← same group
        inputs: [...]
```

Result: nginx pipeline and apache pipeline share the same IP state. When analyzing combined logs:
- IP 1.2.3.4 makes 3 requests to nginx
- Same IP makes 2 requests to apache
- Total tracked: 5 requests (score reflects combined activity)

**Per-stream isolation:** streams never share trackers, even with the same group name. Each stream has its own `map[groupName]*state.Tracker`.

---

## Configuration System

### Config Structure (YAML → Go struct)

```yaml
# Top-level config file (default: /etc/arxsentinel.yaml)

general:
  version: 1                             # config version
  log_file: /var/log/arxsentinel.log    # daemon operational log
  pid_file: /var/run/arxsentinel.pid    # PID marker for systemd
  tail_retry_interval: 5s                # retry on source error
  stats_interval: 60s                    # metrics flush interval

logging:
  debug: false                           # verbose per-component logs
  operational_log: /var/log/arxsentinel/ops.log  # structured events
  raw_line_logging: false                # dump each log line (verbose)

parser:
  profile: nginx                         # or apache, traefik, haproxy-http, caddy
  log_format: default                    # or custom
  regex_pattern: |
    ^(?P<ip>\S+).*?"(?P<method>\S+) (?P<path>\S+).*?" (?P<status>\d+)
  json_fields: {}                        # for JSON logs

scoring:
  alert_threshold: 70                    # THREAT if score > this
  warn_threshold: 40                     # WARN if score > this

state:
  gc_interval: 5m                        # run garbage collection
  max_age: 24h                           # prune IPs older than this

detectors:
  probe:
    enabled: true
    sensitive_paths: ["/admin", "/.env", "/config", ...]
  rate:
    enabled: true
    threshold_req_per_sec: 10
  ua:
    enabled: true
  bruteforce:
    enabled: true
    threshold_4xx_percent: 20
  crawler:
    enabled: true
  noasset:
    enabled: true
  overflow:
    enabled: true
    threshold_bytes: 1048576
  badbot:
    enabled: false
    exec: /usr/local/bin/badbot-detector  # optional

whitelist:
  ips: ["127.0.0.1", "::1"]
  cidrs: ["192.168.0.0/16"]
  user_agents: ["curl/*", "wget/*"]
  bots:
    - name: "Googlebot"
      ua_pattern: "Googlebot/.*"
      reverse_dns_suffix: ".google.com"

metrics:
  enabled: true
  addr: ":9999"
  auth: ""                               # or "user:pass"

blocklist:
  sources:
    - url: "https://blocklist.example.com/ua.json"
      refresh: 6h
  storage: /var/lib/arxsentinel/blocklist.db
  refresh_interval: 6h

chaincheck:
  enabled: false
  trusted_proxies_file: /etc/arxsentinel/trusted-proxies.txt
  bogon_protection: false

streams:
  - name: webservers
    pipelines:
      - name: nginx
        tracker_group: web               # optional: default = pipeline name
        inputs:
          - type: file
            path: /var/log/nginx/access.log
          - type: exec
            exec: journalctl -u nginx -f
        outputs:
          - type: file
            path: /var/log/arxsentinel/threats.log
            format: json
          - type: exec
            exec: /usr/local/bin/alert.sh
        detectors:
          probe:
            sensitive_paths: ["/admin", "/wp-admin"]
          rate:
            threshold_req_per_sec: 15
```

### Config Migration

Legacy configs (< v1) have top-level `inputs`, `outputs`, `log_file` fields. The loader auto-wraps them:

```yaml
# Old format
log_file: /var/log/app.log
inputs:
  - type: file
    path: /var/log/nginx.log
outputs:
  - type: file
    path: /var/log/threats.log

# Auto-migrated to
streams:
  - name: ""                             # unnamed stream
    pipelines:
      - name: default
        tracker_group: default
        inputs: [...]
        outputs: [...]
```

This preserves backward compatibility while internally using the new pipeline model.

---

## Plugin Registries

Three plugin systems allow extensibility without code changes.

### Source Registry (pkg/source/registry.go)

**Interface:**
```go
type Source interface {
    Read(ctx context.Context) (<-chan *LogEntry, error)
    Close() error
}
```

**Built-in sources:**
- `file` — tail file (via internal/core/input/file.go)
- `stdin` — read from standard input
- `exec` — spawn subprocess, capture JSON lines (internal/core/input/exec.go)

**Registration:**
```go
func init() {
    source.Register("file", newFileSource)
    source.Register("stdin", newStdinSource)
    source.Register("exec", newExecSource)
}
```

**Usage in config:**
```yaml
inputs:
  - type: file
    path: /var/log/nginx.log
  - type: exec
    exec: "journalctl -u nginx -f"
```

### Sink Registry (pkg/sink/registry.go)

**Interface:**
```go
type Sink interface {
    Write(ctx context.Context, event *ThreatEvent) error
    Close() error
}
```

**Built-in sinks:**
- `file` — append to threat log
- `stdout` — print to stderr
- `exec` — pass JSON to subprocess (internal/core/output/exec.go)

**Usage in config:**
```yaml
outputs:
  - type: file
    path: /var/log/threats.json
    format: json
  - type: exec
    exec: "jq . | mail -s 'Threat' admin@example.com"
```

### Detector Registry (pkg/detector/registry.go)

**Interface:**
```go
type Detector interface {
    Detect(ipView IPView, entry *LogEntry) DetectResult
}
```

**Built-in detectors:**
- `probe` — path enumeration
- `rate` — request rate anomalies
- `ua` — user-agent analysis
- `bruteforce` — 4xx spike
- `crawler` — crawler classification
- `noasset` — requests without file extension
- `overflow` — request size anomalies
- `badbot` — custom detector (exec plugin)

**Custom detector example (in external tool):**
```go
// my-detector.go
func init() {
    detector.Register("custom-signature", func(cfg *config.DetectorConfig, shared *BuildShared) (plugin.Detector, error) {
        return &customDetector{threshold: cfg.Params["threshold"].(float64)}, nil
    })
}

type customDetector struct {
    threshold float64
}

func (d *customDetector) Detect(ipView plugin.IPView, entry *plugin.LogEntry) plugin.DetectResult {
    // custom logic
    if entry.Size > d.threshold {
        return plugin.DetectResult{Score: 50, Reason: "oversized request"}
    }
    return plugin.DetectResult{Score: 0}
}
```

Then register and build via the registry in buildPipelineDetectors().

---

## Dependency Graph

```
stdlib
├─ log, net, http, time, os, sync, context, crypto, etc.
│
└─ pkg/plugin                [interfaces: Source, Sink, Detector, LogEntry, ThreatEvent]
   ├─ exposes core abstractions (no implementations)
   ├─ implements registries
   └─ used by all components
       │
       ├─ pkg/detector          [Detector implementations + registry]
       │  ├─ probe.go
       │  ├─ rate.go
       │  ├─ ua.go
       │  ├─ bruteforce.go
       │  ├─ crawler.go
       │  ├─ noasset.go
       │  ├─ overflow.go
       │  ├─ badbot.go
       │  └─ registry.go         [Build(name, cfg, shared)]
       │
       ├─ pkg/source            [Source registry; implementations are internal]
       │  └─ registry.go         [Build(cfg, opts)]
       │
       ├─ pkg/sink              [Sink registry; implementations are internal]
       │  └─ registry.go         [Build(cfg)]
       │
       ├─ pkg/execplugin        [Subprocess runtime: exec Source, Sink, Detector]
       │  └─ exec runner
       │
       └─ internal/core/
          ├─ input/             [Source implementations]
          │  ├─ file.go         [tail via fsnotify]
          │  ├─ stdin.go        [buffered stdin reader]
          │  └─ exec.go         [JSON subprocess]
          │
          ├─ output/            [Sink implementations]
          │  ├─ file.go         [buffered file writer]
          │  ├─ stdout.go       [stderr output]
          │  └─ exec.go         [JSON subprocess]
          │
          ├─ parser/            [Parser implementations: regex, json, combined]
          │  ├─ regex.go
          │  ├─ json.go
          │  └─ combined.go
          │
          ├─ scorer/            [Threat scoring: aggregates detector results]
          │  └─ scorer.go
          │
          ├─ state/             [IP state tracking + GC]
          │  └─ tracker.go
          │
          ├─ blocklist/         [UA/referer blocklist + bbolt storage]
          │  └─ manager.go
          │
          ├─ whitelist/         [IP/CIDR/UA/bot whitelist + DNS verifier]
          │  ├─ matcher.go
          │  └─ verifier.go
          │
          ├─ chaincheck/        [Proxy chain integrity: Cloudflare/Akamai/bogon validation]
          │  └─ checker.go
          │
          └─ sys/
             ├─ config/         [YAML loader + migration]
             │  └─ config.go
             │
             ├─ metrics/        [Prometheus vectors]
             │  └─ metrics.go
             │
             └─ utils/          [Logging, PID file, etc.]
                └─ logger.go
```

**Key dependency rule:** internal components do not import each other horizontally (input/ imports nothing from output/, scorer/ imports nothing from detector/). All coordination happens in main.go's runPipeline().

---

## Metrics

All metrics are labeled by `stream` and `pipeline` (except global counters).

### Request Counters

```
arxsentinel_lines_processed_total{stream, pipeline}
  Counter. Total log lines read from sources.

arxsentinel_threats_total{stream, pipeline, level}
  Counter. Threat events written (level = "WARN" | "THREAT").
```

### Threat Analysis

```
arxsentinel_detector_hits_total{stream, pipeline, detector}
  Counter. Per-detector hit count (detector = "probe", "rate", "ua", etc.).
  Incremented when Detector.Detect() returns score > 0.

arxsentinel_tracked_ips{stream, pipeline}
  Gauge. Current count of tracked IPs in memory.

arxsentinel_suspicious_ips{stream, pipeline}
  Gauge. Current count of IPs marked as suspicious (IsSuspicious = true).
```

### Source and Sink Activity

```
arxsentinel_input_lines_total{stream, pipeline, source, source_type}
  Counter. Lines read per source (source_type = "file", "stdin", "exec").

arxsentinel_output_events_total{stream, pipeline, sink}
  Counter. Events written to sink.

arxsentinel_output_dropped_total{stream, pipeline, sink}
  Counter. Events dropped by sink (e.g., write error).
```

**Scrape endpoint:** `http://localhost:9999/metrics` (default).

**Authentication (optional):**
```yaml
metrics:
  auth: "user:pass"
```
Uses HTTP Basic Auth; credentials checked via constant-time comparison.

---

## Error Handling and Resilience

### Source Failure

When a Source.Read() returns an error (e.g., file deleted, command crashed):

1. Log the error with source name
2. Backoff: sleep `tail_retry_interval` (configurable, default 5s)
3. Retry: reconnect and resume reading
4. Max retries: configurable (default: infinite)

If all sources fail, the pipeline blocks until one recovers.

### Sink Failure

When a Sink.Write() returns an error:

1. Log the error with sink name and entry summary
2. Increment `arxsentinel_output_dropped_total` counter
3. Continue to next line (do not block pipeline)

Reason: a slow sink should not starve log processing. Critical sinks (e.g., alerts) should implement their own retry logic.

### Graceful Shutdown (SIGTERM/SIGINT)

```
SIGTERM
  ↓
  appCtx.Done()
  ↓
  all goroutines check ctx.Done() and exit
  ↓
  Source.Close(), Sink.Close()
  ↓
  Tracker GC goroutines exit
  ↓
  runStream exits → wg.Done()
  ↓
  main() reaches wg.Wait() → proceeds to defers
  ↓
  cancel() → removePID() → utils.Close()
  ↓
  daemon exits (code 0)
```

Timeout: if shutdown takes > 30s, daemon hard-exits.

---

## Design Rationale

### Why Separate Sources, Detectors, Sinks?

**Single Responsibility:** Each component does one thing.
- Source: how to read logs (file, exec, stdin — doesn't matter)
- Detector: what makes a log line suspicious (8 pluggable strategies)
- Sink: where to send threats (file, webhook, alert tool — doesn't matter)

**Result:** you can mix and match. Monitor nginx + apache together, apply same detectors, split alerts by severity to different sinks — all in YAML.

### Why TrackerGroups?

Without groups, every pipeline re-analyzes the same IP independently:
```
nginx pipeline: IP 1.2.3.4 makes 3 requests → score 30
apache pipeline: same IP makes 2 requests → score 15
alert sent twice
```

With groups:
```
tracker_group: web
  nginx: 3 requests
  apache: 2 requests
  total: 5 requests → score 45
alert sent once, based on combined activity
```

Trade-off: requires careful naming (group names shared within a stream). Typos cause silent isolation.

### Why DNS Verification for Bots?

A bot UA like "Googlebot/2.1" can be spoofed by malicious clients. Verification:
- rDNS: IP's reverse DNS must end with bot's domain (e.g., `.google.com`)
- fDNS: that hostname must resolve back to the IP

Requires two DNS queries. Cached for performance. If either check fails, IP is marked as "fake bot" and score is penalized.

### Why Exec Plugins?

Some detection logic is hard to express in Go (complex regex, ML models, third-party tools). Exec plugins allow spawning a subprocess:

```yaml
detectors:
  badbot:
    enabled: true
    exec: /usr/local/bin/ml-threat-scorer
```

The subprocess reads JSON on stdin, writes score + reason on stdout. Simple, language-agnostic, testable in isolation.

### Why Multiple Streams?

A single ArxSentinel daemon can monitor multiple, completely independent log sources:
```yaml
streams:
  - name: production
    pipelines: [...]
  - name: staging
    pipelines: [...]
```

Each stream has its own metrics labels, its own tracker groups, its own GC. Isolates risks: a misconfiguration in staging won't affect production metrics.

---

## Testing Strategy

### Unit Tests

Each package has `_test.go` files:
- `pkg/detector/*_test.go` — detector behavior
- `internal/core/state/*_test.go` — tracker GC, state updates
- `internal/core/parser/*_test.go` — log parsing
- etc.

Tests use table-driven style and focus on behavior, not implementation details.

### Integration Tests

`cmd/arxsentinel/*_test.go` — full pipeline tests:
1. Create config with mock sources/sinks
2. Feed log lines
3. Assert threat events were written correctly

### Manual Testing

1. **Dev mode:** build with `go build ./cmd/arxsentinel`, run `./arxsentinel -c test.yaml`
2. **Watch logs:** `tail -f /var/log/arxsentinel.log`
3. **Metrics:** `curl http://localhost:9999/metrics`
4. **SIGHUP reload:** `kill -HUP $(cat arxsentinel.pid)`

---

## Contributing Guide

### Adding a New Detector

1. Create `pkg/detector/newdetector.go`
   ```go
   type newDetector struct { ... }
   
   func (d *newDetector) Detect(ipView plugin.IPView, entry *plugin.LogEntry) plugin.DetectResult {
       // logic here
       return plugin.DetectResult{Score: 50, Reason: "..."}
   }
   ```

2. Register in `init()`
   ```go
   func init() {
       detector.Register("newdetector", newDetectorFactory)
   }
   ```

3. Add config struct to `internal/sys/config/detectors.go`

4. Reference in YAML
   ```yaml
   detectors:
     newdetector:
       enabled: true
       param1: value
   ```

5. Write tests in `pkg/detector/newdetector_test.go`

### Adding a New Sink

1. Create `internal/core/output/newsink.go` or external package
2. Implement `plugin.Sink` interface
3. Register in `pkg/sink/registry.go`
4. Update config
5. Test

### Modifying Startup Sequence

**Do not** change the startup order without deep understanding. If you must:
1. Document the new order in the comment block in main.go
2. Add a test that verifies the order (e.g., `TestStartupOrder`)
3. Update this ARCHITECTURE.md
4. Get review

---

## Debugging

### Enable Debug Logs

```yaml
logging:
  debug: true
```

Outputs verbose logs for each component (tracker updates, verifier checks, scorer results, etc.).

### Raw Line Logging

```yaml
logging:
  raw_line_logging: true
```

Prints every parsed log line. **Use sparingly** — can spam logs on high-traffic systems.

### Metrics Inspection

```bash
curl http://localhost:9999/metrics | grep arxsentinel_
```

Shows current state (tracked IPs, threat counts, detector hits, etc.).

### Reload Configuration

```bash
kill -HUP $(cat /var/run/arxsentinel.pid)
```

Reloads YAML without restart. Tracker and Verifier survive reload; Scorer and Matcher are rebuilt. Sinks are kept (FileSink handles log rotation in-place).

---

## Performance Considerations

### Memory

- **Per-tracked-IP:** ~500 bytes (IPState with recent paths)
- **Per-detector:** negligible
- **Blocklist:** depends on size; typical 10–100 MB (bbolt overhead)
- **Worst case:** 1M tracked IPs = 500 MB + overhead

Mitigation: `state.max_age` and `state.gc_interval` prune old entries.

### CPU

- **Per-entry:** 1–5ms (parsing + detectors + sink writes)
- **Bottleneck:** DNS verification (if enabled; cached 1h per bot)
- **Regex detectors:** slow on malformed logs; use compiled regex

### Throughput

- **Single pipeline:** 10k–100k lines/sec (depends on detector complexity)
- **Multiple pipelines:** near-linear scaling (independent goroutines)

---

## License

ArxSentinel is licensed under the [project-specific license]. See LICENSE file.

