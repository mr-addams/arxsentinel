# Plugin Development Guide (Product Layer)

> **Core contract (Source / Sink / Detector / Processor / Executor interfaces,
> lifecycle, init+blank-import pattern, exec+JSON protocol) lives in
> [`arx-core/docs/plugin-development.md`](../arx-core/docs/plugin-development.md).**
> This document is the **product-layer companion**: ArxSentinel-specific
> examples and the things only an ArxSentinel contributor needs to know.
> If you're writing a new plugin, read the core contract first, then come
> back here for the product-side wiring.

## Table of Contents

1. [Sink Plugins vs Executor Plugins](#sink-plugins-vs-executor-plugins)
2. [Sentinel source/sink — NCS bridge](#sentinel-sourcesink--ncs-bridge)
3. [Cloudflare executor (compiled-in)](#cloudflare-executor)
4. [MikroTik executor (compiled-in)](#mikrotik-executor)
5. [Nginx blocklist executor](#nginx-blocklist-executor)
6. [exec+JSON — product examples](#execjson--product-examples)
7. [Security model](#security-model)
8. [Testing your plugin](#testing-your-plugin)
9. [Troubleshooting](#troubleshooting)

---

## Sink Plugins vs Executor Plugins

ArxSentinel exposes two ways to react to a scored threat event:
**Sinks** (passive log writers) and **Executors** (stateful action managers).
Picking the wrong one leads to subtle bugs — duplicate API calls, lost
events, race conditions on dedup state, or an entire pipeline that does
nothing.

### Key difference in one line

**Sinks** are stateless log writers. **Executors** are stateful action
managers that enforce policy via external APIs.

| Aspect | Sink | Executor |
|---|---|---|
| Role | Passive — writes event data | Active — enforces policy via external resource |
| Input | `Sink.Write(ctx, *plugin.Event)` direct call | `ncs://<name>` queue via NCS (EventSource.Pop) |
| State | Stateless | Holds dedup map, TTL timers, ban list |
| Deduplication | None | Built-in (prevents duplicate API calls) |
| TTL expiry | None | Automatic unban / cleanup after configured duration |
| Persistence | None | Optional (bbolt/redis queue backend) |
| Routing | Direct Go channel | Named Channel Switch (Work Queue) |
| Backpressure | None | Queue buffer (configurable backend) |
| Startup sync | Not applicable | Loads remote state on Init (e.g. existing ban list) |
| Failure handling | Log error, continue | Retry / circuit-breaker, increment `Errors` counter |

### When to create an Executor (not a Sink)

Create an **Executor** when your integration:

- **Modifies external state** — firewall rules, IP lists, databases, CDN configs.
- **Needs deduplication** — you must not call the external API twice for the same IP.
- **Requires TTL-based cleanup** — automatic reversal (auto-unban after 24h).
- **Must survive restarts** — queue persistence means no event loss on crash.
- **Targets distributed environments** — multi-replica K8s with shared Redis queue.
- **Needs startup state sync** — load the current remote state (existing ban list).

Create a **Sink** when your integration:

- Only writes/forwards event data (files, syslog, webhooks, Kafka, Slack, Telegram).
- Is stateless and idempotent at the I/O level.
- Does not need deduplication, TTL, or cross-process delivery.

### Sink vs Executor data flow

```
Detector-pipeline
  └─ SentinelThreatSink (formatter = product JSON)
       └─ executor.AttachWriter("ncs://threats") → NCS queue
                                                    │
                                            executor.AttachReader("ncs://threats")
                                                    │
                                            SentinelSource.Run()  →  Executor.Run()
                                                    │                       │
                                              *plugin.Event            ├─ Startup sync
                                              (Payload: ThreatEvent)   ├─ Dedup check
                                                                         ├─ External API call
                                                                         ├─ Mark in dedup map
                                                                         └─ Schedule TTL expiry
```

### Quick reference: which interface to implement

- **Sink** → `plugin.Sink` from `arx-core/pkg/plugin/sink.go`. The sink receives
  `*plugin.Event`; concrete byte-level serialisation goes through a
  product-side `Formatter` (interface in `arx-core/pkg/sink/format`).
- **Executor** → `plugin.Executor` from `arx-core/pkg/plugin/executor.go`. The
  executor reads `*plugin.Event` from `EventSource.Pop` and type-asserts
  `event.Payload` to its product-owned type (typically `*threat.ThreatEvent`).

### See also

- [`arx-core/docs/plugin-development.md`](../arx-core/docs/plugin-development.md) — interfaces, lifecycle, init+blank-import pattern.
- [`docs/executors.md`](executors.md) — full executor framework overview.
- [`pkg/executorplugins/`](../pkg/executorplugins/) — reference implementations.

---

## Sentinel source/sink — NCS bridge

The **sentinel** Source/Sink pair wires two ArxSentinel pipelines together
through NCS. The sink serialises scored `*plugin.Event` (with
`*threat.ThreatEvent` payload) into NCS queue bytes via a product-side
`Formatter`; the source reads those bytes back from the queue and emits
`*plugin.Event` (with `json.RawMessage` payload) into another pipeline.
This is the mechanism that decouples detection from enforcement.

### Source — `pkg/source/sentinel` (in arx-core)

```yaml
streams:
  - name: executor-side
    pipelines:
      - name: cf-exec
        inputs:
          - type: sentinel
            addr: ncs://cf-threats    # queue name registered by sink
        outputs: []                    # executors consume in-process via EventSource
```

The source `Run` loop: `queue.Pop(ctx)` → JSON-decoded bytes → `json.RawMessage`
wrapped in `Event.Payload` → sent to `out` chan. The downstream
executor (in same process or another process reading the same NCS queue)
type-asserts to its product-owned type.

### Sink — `pkg/sink/sentinel` (in arx-core, type=`sentinel-threat`)

```yaml
streams:
  - name: detector-side
    pipelines:
      - name: detector
        inputs:
          - type: file
            path: /var/log/nginx/access.log
        outputs:
          - type: sentinel-threat
            name: cf-threats           # arbitrary channel name, matches source.addr
```

The sink `Write(ctx, *plugin.Event)` is called per surviving event.
It calls the injected product-side `Formatter.Format(event)` to get
bytes, then pushes bytes onto the NCS queue. Back-pressure is
non-blocking send: when queue is full, the event is dropped and
`Stats().Dropped` is incremented.

### Why this split exists

A `Sink` alone is synchronous — it runs in the same goroutine as the
detector. If it makes a slow API call (Cloudflare), the detector blocks.
By pushing events into NCS via `sentinel-threat` sink, the detector
returns immediately; the executor reads from NCS at its own pace,
holds dedup/TTL state, and survives restarts (with `bbolt`/`redis` backend).

> **Work-queue warning:** NCS is a Work Queue, not a Pub/Sub. If two
> executors share `ncs://threats`, they get round-robin distribution
> (~50% each). One channel per executor.

### See also

- [`arx-core/pkg/source/sentinel/README.md`](../arx-core/pkg/source/sentinel/README.md)
- [`arx-core/pkg/sink/sentinel/README.md`](../arx-core/pkg/sink/sentinel/README.md)
- [`internal/threat/format/`](../internal/threat/format/) — `Formatter` impls.

---

## Cloudflare executor

Reference: `pkg/executorplugins/cloudflare/`. Adds threat IPs to a
Cloudflare IP List via the `/accounts/{id}/rules/lists` API; auto-removes
expired entries via TTL sweep.

```yaml
executors:
  - name: cf-ban
    type: cloudflare
    sources: [{ name: cf-threats }]    # NCS queue name (matches sentinel-threat sink)
    api_token: "${CF_API_TOKEN}"       # env-var ref, do NOT hardcode
    account_id: "${CF_ACCOUNT_ID}"
    list_id: "${CF_LIST_ID}"
    ttl: 24h
    min_level: WARN                    # default — skip "" (no event) entries
```

Behaviour:

- **Dedup:** IPs already in the CF list are skipped (no second API call).
- **TTL sweep:** every `ttl`, IPs added by this executor with `added_at < now-ttl`
  are removed. The executor only removes its own entries (filtered by
  `comment` metadata).
- **Startup sync:** loads current CF list and primes the dedup map so
  already-banned IPs don't trigger duplicate adds after restart.
- **Retry / circuit-breaker:** 5xx / network errors retry with backoff;
  persistent failures open the circuit for 30s.

See [`docs/executor-cloudflare.md`](executor-cloudflare.md) for full
config reference, troubleshooting, and `arxsentinel cleanup --cf` usage.

---

## MikroTik executor

Reference: `pkg/executorplugins/mikrotik/`. Manages a RouterOS v7
firewall address-list over the REST API. TTL-based auto-unban, removes
only ArxSentinel-owned entries (filtered by `comment` field).

```yaml
executors:
  - name: mtk-ban
    type: mikrotik
    sources: [{ name: mtk-threats }]
    address: 10.99.99.1
    username: api-user
    password: "${MIKROTIK_PASSWORD}"
    address_list: arxsentinel-blocked
    ttl: 24h
    insecure_skip_verify: false       # set true only for self-signed test certs
```

Behaviour:

- **REST API:** `/rest/ip/firewall/address-list/add` with
  `address=<ip>`, `list=arxsentinel-blocked`, `comment=arxsentinel:<timestamp>`.
- **TTL sweep:** every `ttl`, removes entries whose comment starts with
  `arxsentinel:` and whose timestamp is older than `ttl`. Other entries
  in the same address-list are untouched.
- **CHR / ARM compatible:** uses stdlib HTTP client, no RouterOS-specific
  binary libraries.

See [`docs/providers/mikrotik/`](providers/mikrotik/) for full config
reference, troubleshooting, and CHR setup notes.

---

## Nginx blocklist executor

Reference: `pkg/executorplugins/nginx/`. Atomic file write of banned IPs
to a plain blocklist file; you include the file in nginx however suits
your setup. Optional reload command after each write.

```yaml
executors:
  - name: nginx-ban
    type: nginx
    sources: [{ name: nginx-threats }]
    path: /etc/nginx/conf.d/arxsentinel-blocklist.conf
    reload_command: "nginx -s reload"   # optional
    ttl: 24h
```

The file format is `deny <ip>;` per line. Atomic writes via
`rename(tmp, path)`. The executor only manages IPs whose line
includes the `arxsentinel:` marker, so manual `allow` / `deny` lines
in the file are preserved.

---

## exec+JSON — product examples

The exec+JSON protocol lets you write plugins in any language. The
host binary spawns the plugin as a subprocess and pipes NDJSON through
`arx-core/pkg/execplugin/`. Protocol spec and message shapes are in
`arx-core/docs/plugin-development.md#8-external-execjson-plugins`.

### Detector example: Python ML classifier

```python
#!/usr/bin/env python3
# /opt/plugins/ml_detector.py — receives detect request, returns score
import json, os, sys

params = json.loads(os.environ.get('ARXSENTINEL_PLUGIN_PARAMS', '{}'))
THRESHOLD = float(params.get('threshold', 0.7))

for line in sys.stdin:
    msg = json.loads(line.strip())
    if msg.get('action') != 'detect':
        continue
    entry = msg.get('entry', {})
    state = msg.get('state', {})

    # ... feature extraction + model.predict_proba ...
    score = int(prob * 100) if prob >= THRESHOLD else 0

    print(json.dumps({
        'score': max(0, min(100, score)),
        'module': 'ml-classifier',
        'reason': f'ML prediction: {prob:.2%} threat probability',
    }))
    sys.stdout.flush()
```

```yaml
detectors:
  ml-classifier:
    enabled: true
    exec: /opt/plugins/ml_detector.py
    score: 45
    params:
      threshold: 0.75
      model_path: /opt/models/threat-classifier.pkl
```

### Sink example: bash Telegram notifier

```bash
#!/bin/bash
# /opt/plugins/telegram_notifier.sh
BOT_TOKEN=$(echo "$ARXSENTINEL_PLUGIN_PARAMS" | python3 -c "import json,sys;print(json.load(sys.stdin).get('bot_token',''))")
CHAT_ID=$(echo "$ARXSENTINEL_PLUGIN_PARAMS"   | python3 -c "import json,sys;print(json.load(sys.stdin).get('chat_id',''))")
API_URL="https://api.telegram.org/bot${BOT_TOKEN}/sendMessage"

while read -r line; do
  ip=$(echo "$line" | jq -r '.event.ip // empty')
  [ -z "$ip" ] && continue
  msg="⚠️ Threat detected
IP: $ip
Score: $(echo "$line" | jq -r '.event.score // 0')
Reason: $(echo "$line" | jq -r '.event.reason // "unknown"')"
  curl -s -X POST "$API_URL" \
    -d "chat_id=${CHAT_ID}" -d "text=${msg}" -d "parse_mode=Markdown" > /dev/null
done
```

```yaml
outputs:
  - type: exec
    exec: /opt/plugins/telegram_notifier.sh
    params:
      bot_token: "${TELEGRAM_BOT_TOKEN}"
      chat_id: "-1001234567890"
```

### Source example: Python CloudWatch reader

See `arx-core/docs/plugin-development.md` §8 for a full CloudWatch
example using `boto3` and the `start`/`stop` reverse-stream protocol.

### Environment variables

When ArxSentinel spawns a plugin, it sets:

| Variable | Value |
|---|---|
| `ARXSENTINEL_PLUGIN_PARAMS` | JSON-encoded map of YAML `params:` block |

Plugin decodes this in `main()` and uses parameters during init.

---

## Security model

### Trust boundaries

- **Compiled-in plugins** (`pkg/detectorplugins/*`, `pkg/executorplugins/*`):
  run in same process and memory space as ArxSentinel. Assume they are
  trusted (reviewed product code).
- **External exec+JSON plugins**: run as separate processes. Consider
  untrusted (user-supplied, third-party). Sandbox them as needed.

### Input validation

- `*plugin.Event` envelope: validated by the engine before reaching any
  plugin (well-formed transport metadata).
- `*plugin.Event.Payload` (e.g. `*threat.ThreatEvent`): trusted only if
  the producer is trusted. Bad values from untrusted plugin should
  be clamped in the plugin receiver.

### Process isolation

For security-critical plugins (ML models, third-party detectors):

```bash
# Container
exec: docker run --rm -i --net none my-plugin:latest

# cgroup limits via systemd-run
exec: systemd-run --scope -p MemoryLimit=256M /opt/plugins/ml_detector.py

# Run as dedicated user
useradd -r arxsentinel-plugins
chmod -R o-rwx /opt/plugins
```

Do NOT run plugins as root.

### Secrets management

Do NOT embed secrets in `config.yaml`. Use env-var refs:

```yaml
outputs:
  - type: exec
    exec: /opt/plugins/slack_notifier.sh
    params:
      webhook_url_env: SLACK_WEBHOOK_URL    # plugin reads from process env
```

Plugin reads via `os.environ.get('SLACK_WEBHOOK_URL')` (Python) or
`$SLACK_WEBHOOK_URL` (bash).

---

## Testing your plugin

### Unit tests (compiled-in)

For product-side compiled-in plugins, use a mock `IPView` for detectors
and a mock `tracker.Tracker` for stateful plugins:

```go
type mockView struct {
    ip string; total int; fourOhFour int
    paths []string; rate float64
}
func (m *mockView) GetIP() string                           { return m.ip }
func (m *mockView) GetTotalRequests() int                   { return m.total }
func (m *mockView) GetRequests404() int                     { return m.fourOhFour }
func (m *mockView) RecentPaths() []string                   { return m.paths }
func (m *mockView) ApproxRate(time.Duration) float64        { return m.rate }
```

Place `impl_test.go` next to `impl.go`. Use table-driven tests focused
on behaviour, not implementation.

### Integration tests (exec+JSON)

Pipe NDJSON into the plugin binary and assert on its stdout:

```bash
echo '{"v":"1","action":"detect","entry":{...},"state":{...}}' \
  | /opt/plugins/my_detector.py
```

Wrap in a Go integration test that uses `os/exec` to spawn the binary
and `bufio.Scanner` to read the response. Test against a real
`*plugin.Event` shape (Envelope + Payload).

### Full pipeline test

For sink/executor plugins that read from NCS:

```go
// 1. Build a memory queue.Queue, write sample *plugin.Event into it
// 2. Build your plugin against the queue
// 3. Run plugin.Run(ctx, queue) in a goroutine
// 4. Assert on side effects (file write, API mock call, etc.)
// 5. Cancel ctx, assert on clean shutdown
```

See `pkg/executorplugins/*/*_test.go` for working examples.

---

## Troubleshooting

### Plugin fails to load

**Compiled-in:** ensure the import is added to `cmd/arxsentinel/plugins_full.go`
(blank import) — for always-linked plugins. For tree-shakeable plugins,
also update `profiles/full.yaml`. Run `bash scripts/check-build-profiles.sh`
to catch drift.

**External:** verify the binary exists, is executable, has correct shebang.
`ls -la /opt/plugins/`, `chmod +x` if needed.

### Plugin receives no requests

- **Detector:** verify `enabled: true` in config. Check ArxSentinel operational
  log for `[DETECTOR]` lines (enable `logging.debug: true`).
- **Source:** verify the source is registered and appears in the config under
  `inputs:`. `arxsentinel validate` catches misconfigured names.
- **Sink:** ensure threat events are being generated (detectors must trigger).
  Use `sentinel-threat` sink with `name: <queue>` to see events flow.

### Plugin times out or crashes

- **Compiled-in:** add `defer recover()` and log the stack trace. Profile with
  `pprof` if hot path is slow.
- **External:** add `stderr` logging — visible in ArxSentinel operational log.
  Test locally: `echo '...' | ./plugin.py`.

### Performance degradation

- **Compiled-in:** profile with `pprof`. Expensive detectors should move to
  external.
- **External:** add latency metrics to your plugin output. Consider batching
  (multiple events per request) in a future protocol version.

### See also

- [`arx-core/docs/plugin-development.md`](../arx-core/docs/plugin-development.md) — full plugin contract.
- [`docs/developer/build-profiles.md`](developer/build-profiles.md) — tree-shaking, build tags.
- [`docs/executors.md`](executors.md) — executor framework overview.
