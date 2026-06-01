# Event-Driven Telemetry Pipeline — Architecture

## Vision

A universal telemetry pipeline framework decoupled from any specific protocol or data source (nginx, HTTP, syslog, cloud logs). The pipeline processes events through a chain of typed stages, each transforming data in place. The same framework handles access logs, DNS queries, firewall events, and application telemetry — the only difference is which plugins are wired in.

The pipeline is:

- **Typed** — every plugin declares input/output `DataType`; the validator rejects mismatched adjacencies at startup
- **Composable** — Source → Processor chain → Detectors → Sinks → Executor runs can be assembled from independent plugins
- **Unidirectional** — data flows forward; no reverse edges, no cycles
- **Fail-fast** — topology is validated before any event is processed; a miswired pipeline never starts

---

## Roles

Five plugin roles define position and responsibility in the pipeline:

| Role | Tag | Responsibility | Example |
|---|---|---|---|
| Source | `source` | Acquires raw data from an external system and emits `LogEntry` events | File tailer, syslog listener, CloudWatch reader, HTTP poller |
| Processor | `processor` | Transforms, enriches, or filters events in-place. May drop events (return `nil`) | Geo-IP enricher, log normalizer, regex masker, rate-limiter gate |
| Detector | `detector` | Analyses an event against IP history and returns a threat score (0–100) | SQLi probe detector, brute-force detector, ML classifier |
| Executor | `executor` | Reads scored events from a named queue and runs an action (block, rate-limit, notify) | Cloudflare IP block, MikroTik firewall rule, Telegram alert |
| Sink | `sink` | Persists or forwards a `ThreatEvent` to external storage or service | File appender, Elasticsearch indexer, HTTP webhook, stdout |

---

## DataType Constants

Every plugin declares `InputType` and `OutputType` in its Manifest. These types define the data contract between pipeline stages.

| Constant | Value | Meaning |
|---|---|---|
| `TypeNone` | `none` | No data flows. Used for Sources that emit externally (side effect) and Sinks that only consume. |
| `TypeRawLog` | `raw_log` | A raw, unparsed log line (string) before any parsing. |
| `TypeStructured` | `structured` | A parsed `LogEntry` with all HTTP fields (IP, method, path, status, UA, etc.). |
| `TypeScoredEvent` | `scored_event` | A `LogEntry` enriched with a threat score (0–100). |
| `TypeAny` | `any` | Universal bridge — compatible with any type on either side of the adjacency. |

**Evolution chain:**
```
TypeNone → TypeRawLog → TypeStructured → TypeScoredEvent → TypeNone
```

---

## Data Flow Diagram

```
                         ┌───────────────────┐
                         │   NamedChannelHub  │
                         │  (pkg/executor)    │
                         └──────┬─────▲──────┘
                                │     │
                    Push(event) │     │ Pop(event)
                                │     │
                    ┌───────────▼─────┴───────────┐
                    │        Executor(s)           │
                    │  (read queue → run action)   │
                    └─────────────────────────────┘
                                    ▲
                                    │ scored_event
                                    │
┌────────┐   raw_log    ┌────────────────────┐   structured   ┌────────────┐   scored_event   ┌────────┐
│ Source │─────────────▶│ Processor Chain(s) │───────────────▶│ Detectors  │────────────────▶│  Sink  │
│ (emit) │              │ (transform/filter) │                │ (score)    │                 │ (store)│
└────────┘              └────────────────────┘                └────────────┘                 └────────┘
     │                                                                                          │
     │ TypeNone (side-effect source)                                                             │ TypeNone
     ▼                                                                                          ▼
(external system)                                                                     (external storage)
```

**Flow rules:**

1. A Source emits `TypeRawLog` or `TypeStructured` (or `TypeNone` if it has side effects only)
2. Zero or more Processors transform and optionally drop events
3. Detectors receive `TypeStructured` and produce `TypeScoredEvent`
4. Sinks receive `TypeScoredEvent` and persist/forward it
5. Sinks may also push events into `NamedChannelHub` for Executor consumption
6. Executors read from `NamedChannelHub` and perform actions (block, notify, etc.)

There is always exactly one Source at the start. Processors, Detectors, Sinks, and Executors can be chained in any number.

---

## Config Examples

### Source (file tail + exec plugin)

```yaml
pipelines:
  - name: nginx
    sources:
      - type: file
        path: /var/log/nginx/access.log
      - type: exec
        exec: /opt/plugins/cloudwatch_reader.py
        params:
          region: us-east-1
          log_group: /aws/nginx/access-logs
```

### Processor (geo-IP enricher)

```yaml
processors:
  - type: geoip
    params:
      database: /opt/data/GeoLite2-City.mmdb
```

### Detector (ML classifier)

```yaml
detectors:
  ml-threat:
    enabled: true
    exec: /opt/plugins/ml_detector.py
    params:
      threshold: 0.75
      model_path: /opt/models/threat-classifier.pkl
```

### Sink (file + Elasticsearch)

```yaml
outputs:
  - type: file
    path: /var/log/arxsentinel/threats.log
    format: json
  - type: elasticsearch
    params:
      urls: ["http://localhost:9200"]
      index: arxsentinel-threats-%Y-%m-%d
```

### Executor (MikroTik block)

```yaml
executors:
  mikrotik-block:
    enabled: true
    queue: threats
    action: block
    params:
      address: 10.99.99.1
      username: api-user
      password: "${MIKROTIK_PASSWORD}"
      address_list: arxsentinel-blocked
      ttl: 1h
```