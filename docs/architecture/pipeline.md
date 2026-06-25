# ArxSentinel Pipeline (Product Layer)

> **Core pipeline architecture (the five plugin roles, the DataType chain,
> the engine dispatch model, the NCS fan-in) lives in
> [`arx-core/docs/architecture.md`](https://github.com/mr-addams/arx-core/blob/v0.1.0/docs/architecture.md).**
> Read that document first for the generic pipeline engine.
>
> This document is the **product-layer companion**: the **ArxSentinel
> security pipeline** — how the `securityProcessor` wraps the generic
> `LineProcessor` contract with whitelist → chaincheck → bot-verify →
> tracker → scorer → `*threat.ThreatEvent` flow, and how the resulting
> events fan out to the product's sinks and executors.

---

## 1. Pipeline vision (product-specific)

The ArxSentinel pipeline takes raw access logs (nginx / Apache / Caddy /
Traefik / HAProxy / LiteSpeed), runs them through 8 product detectors,
and produces:

1. **WARN / THREAT** events → `*threat.ThreatEvent` (product-owned DTO)
   wrapped in `*plugin.Event{Envelope{Level: ...}, Payload: ...}` and
   fanned out to the pipeline's sinks.
2. **TTL-managed bans** via the executor layer (Cloudflare / MikroTik /
   nginx), decoupled through NCS.
3. **Operational metrics** via Prometheus on `:9999` (per-stream,
   per-pipeline labels).
4. **Warnings** on infrastructure issues (broken proxy chain, bogon
   IPs as client) — distinct from threats; these mean ArxSentinel
   cannot reliably identify the real attacker IP.

The pipeline is:

- **Fail-fast on topology** — `arxsentinel validate` checks the wiring
  before the daemon starts.
- **Stateful on IP history** — per-IP `Tracker` accumulates activity
  across requests (total, 404 ratio, recent paths, rate, fake-bot
  penalty). State is per-stream; pipelines within a stream may share
  a tracker via `tracker_group`.
- **Pluggable on every stage** — sources (file/stdin/syslog/http/exec/sentinel),
  detectors (8 built-in + exec+JSON), sinks (file/stdout/exec/sentinel-threat),
  executors (cloudflare/mikrotik/nginx). All wired through the
  `plugin.*` interfaces from `arx-core`.
- **Decoupled on enforcement** — detector pipeline returns immediately
  after scoring; executor pipeline reads from NCS, holds dedup/TTL
  state, survives restarts (`bbolt`/`redis` NCS backends).

---

## 2. ArxSentinel security pipeline (securityProcessor)

The pipeline is wired by `securityProcessor` (in
`cmd/arxsentinel/processor_security.go`), which implements
`runtime.LineProcessor` from arx-core. One `securityProcessor` per
pipeline; its opaque `securityState` lives between `Process()` calls
and is rebuilt by `factory.Reload` on SIGHUP.

### 2.1 Stage chain

```
*plugin.Event (Envelope + Payload: *parser.LogEntry)
    │
    │  engine dispatchEntry → securityProcessor.Process(ctx, entry, state, evctx)
    ▼
[Stage 1] Whitelist.Matcher.IsWhitelisted(IP / CIDR / UA / bot DNS-verified)
    │  ─ hit → return Action{Skip: true}, row out
    │  ─ miss → continue
    ▼
[Stage 2] ChainChecker.Check(RealIP)
    │  ─ Cloudflare / Akamai edge IP as client? → warnings.log
    │  ─ Bogon / RFC 1918 / CGNAT IP?            → warnings.log
    │  ─ OK → continue
    ▼
[Stage 3] Whitelist.Matcher.MatchBot(UA)
    │  ─ known bot? → Verifier.Verify(IP, botName) via rDNS+fDNS
    │     ─ pass → mark verified (no penalty)
    │     ─ fail → tracker.ApplyFakeBotPenalty(IP, fake_bot_score)
    │  ─ unknown UA → treat as potential threat
    ▼
[Stage 4] Tracker.Update(RealIP, entry)
    │  total requests, 404/403 counters, recent paths (ring, last 64),
    │  sliding-window rate counters, last_activity
    ▼
[Stage 5] Scorer.Evaluate(Tracker.View(IP), entry)
    │  run 8 product detectors (probe, rate, useragent, bruteforce,
    │  crawler, noasset, overflow, badbot)
    │  aggregate score with linear decay over observation_window
    │  verdict: "" | "WARN" (≥alert_threshold) | "THREAT" (≥ban_threshold)
    │  ─ empty → return Action{}, no event
    │  ─ WARN/THREAT → continue
    ▼
[Stage 6] Build *threat.ThreatEvent {Level, Score, Modules, Reason, ...}
    wrap in *plugin.Event{Envelope{Level: "WARN"|"THREAT"}, Payload: ThreatEvent}
    return Action{Payload: *plugin.Event}
    │
    │  engine dispatches Action.Payload to all PipelineSpec.Sinks
    ▼
[Sinks] FileSink | StdoutSink | SentinelThreatSink | exec+JSON sink
    │  ─ SentinelThreatSink pushes to NCS via product Formatter
    ▼
[Executors] Cloudflare | MikroTik | nginx
       (read from NCS via SentinelSource, type-assert Payload → ThreatEvent)
```

### 2.2 securityState (opaque ProcessorState)

```go
// cmd/arxsentinel/processor_security.go
type securityState struct {
    StreamName, PipelineName string
    PipelineIdx              int
    Tracker                  *state.Tracker     // per-IP map[IP]*IPState
    Scorer                   *scorer.Scorer     // 8 detectors + thresholds
    Matcher                  *whitelist.Matcher // CIDR/IP/UA/bot whitelist
    Verifier                 *whitelist.Verifier // DNS bot verification
    FakeBotScore             int
    DNSVerifyTimeout         time.Duration
}
```

`state.Tracker` and `state.Verifier` are **shared across pipelines** within
a tracker group (kept alive across SIGHUP reloads).
`scorer.Scorer` and `whitelist.Matcher` are **rebuilt on reload** (new
config may change thresholds / whitelist entries).

### 2.3 Reload contract

```go
// cmd/arxsentinel/processor_factory.go (excerpt)
func (f *ProcessorFactory) Reload(old coreruntime.ProcessorState, ctx context.Context) (coreruntime.ProcessorState, error) {
    oldState := old.(*securityState)
    newCfg := f.config.Load()    // re-read YAML
    return &securityState{
        StreamName:       oldState.StreamName,
        PipelineName:     oldState.PipelineName,
        PipelineIdx:      oldState.PipelineIdx,
        Tracker:          oldState.Tracker,   // survives reload
        Verifier:         oldState.Verifier,  // survives reload (DNS cache)
        Scorer:           scorer.New(newCfg.Detectors, newCfg.Scoring),  // rebuilt
        Matcher:          whitelist.NewMatcher(newCfg.Whitelist),         // rebuilt
        FakeBotScore:     newCfg.Whitelist.FakeBotScore,
        DNSVerifyTimeout: newCfg.Whitelist.DNSVerifyTimeout,
    }, nil
}
```

Thread-safety: `Build` and `Reload` may run concurrently for sibling
pipelines; the product factory must serialise shared-resource access.

---

## 3. Config example (product pipeline)

```yaml
streams:
  - name: nginx
    pipelines:
      - name: default
        tracker_group: web
        inputs:
          - type: file
            path: /var/log/nginx/access.log
        detectors:
          probe:     { enabled: true, score: 25, paths: [...] }
          rate:      { enabled: true, score: 25, threshold: 100, window: 60s }
          useragent: { enabled: true, scanner_score: 40, grabber_score: 20, automation_score: 15, empty_ua_score: 30 }
          bruteforce:{ enabled: true, score: 30, ratio_threshold: 0.6, min_requests: 10 }
          crawler:   { enabled: true, score: 20, min_sequential: 5 }
          noasset:   { enabled: true, score: 20, asset_ratio_threshold: 0.1, min_page_requests: 3 }
          overflow:  { enabled: true, score: 30, max_url_length: 2048, suspicious_params: [...] }
          badbot:    { enabled: true, score: 60, check_ua: true, check_referrer: false }
        outputs:
          - type: file
            path: /var/log/arxsentinel/threats.log
            format: fail2ban
          - type: stdout
            format: json
          - type: sentinel-threat
            name: cf-threats    # NCS queue name; downstream executor reads this

executors:
  - name: cf-ban
    type: cloudflare
    sources: [{ name: cf-threats }]    # matches the sentinel-threat sink.name above
    ttl: 24h
    min_level: WARN
    api_token: "${CF_API_TOKEN}"
    account_id: "${CF_ACCOUNT_ID}"
    list_id: "${CF_LIST_ID}"

metrics:
  enabled: true
  addr: ":9999"
```

`arxsentinel validate --config=/etc/arxsentinel/config.yaml` runs the
topology validator before the daemon starts. It catches:

- Unknown source/sink/executor names (typos).
- Missing `Register` call for declared plugin.
- Incompatible `InputType` ↔ `OutputType` adjacencies.
- Writer-without-reader for NCS channels.
- A single stream with conflicting `tracker_group` semantics.

---

## 4. TrackerGroup — shared IP state within a stream

By default each pipeline has its own isolated tracker. Set
`tracker_group: <name>` to share `*state.Tracker` across pipelines
within the same stream:

```yaml
streams:
  - name: web
    pipelines:
      - name: nginx
        tracker_group: web
        inputs:  [{ type: file, path: /var/log/nginx/access.log }]
        detectors: { probe: {enabled: true} }
        outputs: [{ type: file, path: /var/log/arxsentinel/nginx-threats.log }]
      - name: apache
        tracker_group: web            # ← shared tracker
        inputs:  [{ type: file, path: /var/log/apache2/access.log }]
        detectors: { probe: {enabled: true} }
        outputs: [{ type: file, path: /var/log/arxsentinel/apache-threats.log }]
```

IP 1.2.3.4 hitting nginx (3 reqs) and apache (2 reqs) → combined tracker
sees 5 reqs, scorer evaluates 5-req history. Without sharing, each
pipeline independently scores 3 and 2 and emits separate events.

**Per-stream isolation:** streams never share trackers, even with the
same group name. Each stream has its own `map[groupName]*state.Tracker`.

---

## 5. Cross-references

- [`arx-core/docs/architecture.md`](https://github.com/mr-addams/arx-core/blob/v0.1.0/docs/architecture.md) — generic pipeline engine, NCS fan-in, lifecycle.
- [`arx-core/docs/contract.md`](https://github.com/mr-addams/arx-core/blob/v0.1.0/docs/contract.md) — `Run`, `LineProcessor`, `Action`, `EventContext`, `SharedResources`, `MetricsCallbacks`.
- [`arx-core/docs/plugin-development.md`](https://github.com/mr-addams/arx-core/blob/v0.1.0/docs/plugin-development.md) — plugin role interfaces, init+blank-import.
- [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md) — full product-security architecture (top-level, includes executor / metrics / error handling).
- [`docs/PLUGIN_DEV.md`](../PLUGIN_DEV.md) — Sink-vs-Executor, sentinel source/sink, Cloudflare/MikroTik executor walkthroughs.
- [`docs/executors.md`](../executors.md) — executor framework overview.
- [`docs/developer/build-profiles.md`](../developer/build-profiles.md) — product-layer build profiles.
