# Plugin Development Guide

ArxSentinel provides two complementary plugin extension mechanisms:
- **Compiled-in plugins** — Go packages registered via `init()` and linked at compile time
- **External exec+JSON plugins** — Any-language subprocesses communicating via stdin/stdout

Both types implement the same interfaces and are configured the same way in YAML.

---

## Table of Contents

1. [Overview](#overview)
2. [Sink Plugins vs Executor Plugins: Choosing the Right Abstraction](#sink-plugins-vs-executor-plugins-choosing-the-right-abstraction)
3. [Plugin Interfaces](#plugin-interfaces)
4. [Compiled-in Detector](#compiled-in-detector)
5. [Compiled-in Source](#compiled-in-source)
6. [Compiled-in Sink](#compiled-in-sink)
7. [exec+JSON Protocol](#execjson-protocol)
8. [exec+JSON Detector](#execjson-detector)
9. [exec+JSON Sink](#execjson-sink)
10. [exec+JSON Source](#execjson-source)
11. [Testing Your Plugin](#testing-your-plugin)
12. [Security Model](#security-model)

---

## Overview

### Compiled-in Plugins

Go packages that implement a plugin interface and register themselves via `init()`.
Linked directly into the `arxsentinel` binary. No subprocess overhead.

**When to use:**
- High-performance detectors (microsecond latency critical)
- Tight integration with ArxSentinel state
- Security-sensitive logic you want in-process
- Deployment via single static binary

**Example:** BadBot community blocklist detector, built-in geo-IP detector.

### External exec+JSON Plugins

Standalone executables that implement the exec+JSON protocol. ArxSentinel spawns them
as subprocesses and communicate via stdin/stdout NDJSON (newline-delimited JSON).

**When to use:**
- Written in languages other than Go (Python, Rust, Node.js, bash, etc.)
- Iterative development (rebuild plugin, not ArxSentinel)
- Separate versioning/deployment cycle
- Resource isolation (sandbox, container, separate machine via HTTP proxy)
- Third-party services (ML model inference, Slack API, custom webhooks)

**Example:** Python ML detector, bash Telegram notifier, Node.js webhook sink.

---

## Sink Plugins vs Executor Plugins: Choosing the Right Abstraction

ArxSentinel exposes two different ways to react to a scored threat event:
**Sinks** and **Executors**. They look similar at a glance, but they solve
fundamentally different problems. Picking the wrong one leads to subtle bugs
— duplicate API calls, lost events, race conditions on dedup state, or an
entire pipeline that does nothing.

### Key difference in one line

**Sinks** are stateless log writers. **Executors** are stateful action
managers that enforce policy via external APIs.

### Sink vs Executor — full comparison

| Aspect | Sink | Executor |
|---|---|---|
| Role | Passive — writes event data | Active — enforces policy via external resource |
| Input | `Sink.Write(ctx, event)` direct call | `ncs://<name>` queue via NCS |
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

- **Modifies external state** — firewall rules, IP lists, databases, CDN configs
- **Needs deduplication** — you must not call the external API twice for the same IP / event
- **Requires TTL-based cleanup** — automatic reversal of actions (e.g. auto-unban after 24h)
- **Must survive restarts** — queue persistence means no event loss if the process crashes
- **Targets distributed environments** — multi-replica K8s with shared Redis queue
- **Needs startup state sync** — load the current remote state (existing ban list) before processing the first event

Create a **Sink** when your integration:

- Only writes / forwards event data (files, syslog, webhooks, Kafka, Slack, Telegram)
- Is stateless and idempotent at the I/O level
- Does not need deduplication, TTL, or cross-process delivery
- Has no concept of "current state" beyond the event itself

### Executor data flow

```
Pipeline (detector)
  └─ sentinel-threat sink
       └─ executor.AttachWriter("threats") → NCS queue "threats"
                                                    │
                                             executor.AttachReader("threats")
                                                    │
                                            Executor source (Pop loop)
                                                    │
                                            Run(ctx, source)
                                              ├─ Startup sync (load remote state)
                                              ├─ for event := range source.Pop(ctx):
                                              │    ├─ Dedup check (skip if known)
                                              │    ├─ External API call
                                              │    ├─ Mark in dedup map
                                              │    └─ Schedule TTL expiry
                                              └─ Close (cancel timers, drain)
```

Note that the executor does **not** receive events via a direct call — it
runs its own `Run` goroutine and pulls events from the NCS queue
asynchronously. This is what allows it to apply stateful logic (dedup,
TTL) without blocking the pipeline.

### Quick reference: which interface to implement

If you are implementing a **Sink**, implement `plugin.Sink` from
[`pkg/plugin/sink.go`](../pkg/plugin/sink.go):

```go
type Sink interface {
    Name() string
    Write(ctx context.Context, event ThreatEvent) error
    Close() error
    Manifest() Manifest
    Stats() SinkStats
}
```

Register it via `pkgsink.Register(typeName, factory)` in `init()`.

If you are implementing an **Executor**, implement `plugin.Executor` from
[`pkg/plugin/executor.go`](../pkg/plugin/executor.go):

```go
type Executor interface {
    Name() string
    Type() string
    Run(ctx context.Context, source EventSource) error
    Manifest() Manifest
    Stats() ExecutorStats
}
```

Register it via `executor.Register(typeName, factory)` in `init()`,
and expose a source side that reads from `ncs://<name>` — see
[`pkg/source/sentinel/`](../pkg/source/sentinel/) for the canonical
source plugin and [`pkg/executor/registry.go`](../pkg/executor/registry.go)
for the registration helper.

### See also

- [`docs/executors.md`](executors.md) — full executor framework overview (registry, `ExecutorConfig`, exec+JSON)
- [`pkg/executor/README.md`](../pkg/executor/README.md) — NCS API used by executor sources
- [`pkg/executor/cloudflare/`](../pkg/executor/cloudflare/) and [`pkg/executor/mikrotik/`](../pkg/executor/mikrotik/) — reference implementations

---

## Plugin Interfaces

All plugins implement one of three core interfaces defined in `pkg/plugin/`:

### Detector Interface

```go
// Detector analyzes a log entry against an IP's history and returns a threat score.
type Detector interface {
    Name() string                                           // Unique identifier
    Detect(sv IPView, entry *LogEntry) DetectResult
}

// DetectResult is returned by a detector.
type DetectResult struct {
    Score  int    // 0–100: threat confidence
    Module string // Detector name (same as Name())
    Reason string // Human-readable explanation
}

// IPView provides context about an IP's request history.
type IPView interface {
    GetIP() string
    GetTotalRequests() int
    GetRequests404() int
    RecentPaths() []string
    ApproxRate(window time.Duration) float64 // Requests per second over window
}
```

**Contracts:**
- `Score` must be 0–100; silently clamped otherwise
- `Module` must equal `Name()` for consistency
- `Reason` is logged and sent to output sinks
- Detector must not panic; panic is treated as score 0

### Source Interface

```go
// Source generates LogEntry items from any backend (file, syslog, HTTP, database, etc.)
// and sends them to the provided channel. Run() blocks until ctx is cancelled.
type Source interface {
    Name() string
    Run(ctx context.Context, out chan<- *LogEntry) error
    Close() error
    Stats() SourceStats
}

// SourceStats reports performance metrics.
type SourceStats struct {
    EntriesRead int64
    BytesRead   int64
    Errors      int64
    LastEntry   time.Time
}

// LogEntry is a parsed HTTP log line.
type LogEntry struct {
    RemoteAddr string    // Client IP
    RemoteUser string    // HTTP Basic Auth username (if present)
    Time       time.Time // Request timestamp
    Method     string    // GET, POST, etc.
    RawURI     string    // Full URI from log
    Path       string    // URL path component
    Query      string    // URL query string
    Protocol   string    // HTTP/1.1, HTTP/2, etc.
    Status     int       // Response status code
    BytesSent  int64     // Response body size
    Referer    string    // Referer header
    UserAgent  string    // User-Agent header
    RealIP     string    // X-Real-IP or X-Forwarded-For (if configured)
}
```

**Contracts:**
- `Run()` must respect `ctx.Done()` and unblock within 5 seconds of cancellation
- Closing the `out` channel is ArxSentinel's responsibility, not the plugin's
- `Close()` is called after `Run()` exits; use for cleanup (file handles, DB connections)
- Plugin must not panic in `Run()`

### Sink Interface

```go
// Sink consumes ThreatEvent items and delivers them (to file, HTTP, database, etc.)
type Sink interface {
    Name() string
    Write(event ThreatEvent) error
    Close() error
    Stats() SinkStats
}

// SinkStats reports performance metrics.
type SinkStats struct {
    EventsWritten int64
    EventsDropped int64
    Errors        int64
    LastEvent     time.Time
}

// ThreatEvent is sent to sinks when a threat is detected.
type ThreatEvent struct {
    Timestamp  time.Time // When the threat was detected
    Level      string    // "WARN" or "THREAT"
    Stream     string    // Config stream name
    Source     string    // Config source name
    SourceType string    // "file", "syslog", "exec", etc.
    IP         string    // Offending IP
    Score      int       // Aggregate threat score
    Modules    []string  // Detectors that triggered
    Reason     string    // Concatenated reasons
    RawLine    string    // Original log line (for archival)
}
```

**Contracts:**
- `Write()` must not block for more than 5 seconds
- Network errors (HTTP 5xx, database unavailable) should be retried by caller
- `Close()` is called once during shutdown; use for flushing and cleanup
- All sinks receive all events; filtering is upstream

---

## Compiled-in Detector

### Step 1: Create the Plugin Package

Create `internal/core/detector/mydetector/mydetector.go`:

```go
// Package mydetector detects threats using custom heuristics.
package mydetector

import (
    "github.com/mr-addams/arxsentinel/pkg/plugin"
    "strings"
    "time"
)

// MyDetector implements plugin.Detector.
type MyDetector struct{}

// Name returns the unique identifier for this detector.
func (d *MyDetector) Name() string {
    return "my-custom"
}

// Detect analyzes the IP and log entry, returning a threat score.
func (d *MyDetector) Detect(sv plugin.IPView, entry *plugin.LogEntry) plugin.DetectResult {
    score := 0
    reason := ""

    // Heuristic 1: Multiple 404s indicate directory scanning
    if sv.GetRequests404() > 10 {
        score += 30
        reason += "many 404s; "
    }

    // Heuristic 2: SQL injection keywords in query string
    if isSuspiciousQuery(entry.Query) {
        score += 50
        reason += "SQL keywords detected; "
    }

    // Heuristic 3: High request rate
    rate := sv.ApproxRate(1 * time.Second)
    if rate > 100 {
        score += 20
        reason += "high request rate; "
    }

    // Clamp score to 0–100
    if score > 100 {
        score = 100
    }

    return plugin.DetectResult{
        Score:  score,
        Module: d.Name(),
        Reason: strings.TrimSuffix(reason, "; "),
    }
}

func isSuspiciousQuery(query string) bool {
    keywords := []string{"union", "select", "drop", "insert", "delete"}
    lower := strings.ToLower(query)
    for _, kw := range keywords {
        if strings.Contains(lower, kw) {
            return true
        }
    }
    return false
}

// NewMyDetector creates a new instance.
func NewMyDetector() plugin.Detector {
    return &MyDetector{}
}
```

### Step 2: Register the Plugin

Create `internal/core/detector/mydetector/init.go`:

```go
package mydetector

import (
    "github.com/mr-addams/arxsentinel/pkg/detector"
)

func init() {
    detector.Register("my-custom", func() plugin.Detector {
        return NewMyDetector()
    })
}
```

### Step 3: Import in main

Edit `cmd/arxsentinel/main.go` and add the import:

```go
import (
    // ... other imports
    _ "github.com/mr-addams/arxsentinel/internal/core/detector/mydetector"
)
```

### Step 4: Use in Config

```yaml
detectors:
  my-custom:
    enabled: true
```

---

## Compiled-in Source

### Step 1: Create the Plugin Package

Create `internal/core/source/mysource/mysource.go`:

```go
package mysource

import (
    "bufio"
    "context"
    "github.com/mr-addams/arxsentinel/pkg/plugin"
    "os"
    "time"
)

// MySource reads log entries from a file.
type MySource struct {
    filePath string
    stats    plugin.SourceStats
}

func (s *MySource) Name() string {
    return "my-source"
}

func (s *MySource) Run(ctx context.Context, out chan<- *plugin.LogEntry) error {
    file, err := os.Open(s.filePath)
    if err != nil {
        return err
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        select {
        case <-ctx.Done():
            return ctx.Err()
        default:
        }

        line := scanner.Text()
        entry := parseLine(line) // Your parsing logic here
        if entry != nil {
            out <- entry
            s.stats.EntriesRead++
        }
    }

    return scanner.Err()
}

func (s *MySource) Close() error {
    return nil
}

func (s *MySource) Stats() plugin.SourceStats {
    return s.stats
}

func NewMySource(filePath string) plugin.Source {
    return &MySource{filePath: filePath}
}

func parseLine(line string) *plugin.LogEntry {
    // Parse and return a LogEntry, or nil if unparseable
    return &plugin.LogEntry{
        RemoteAddr: "127.0.0.1",
        Method:     "GET",
        Path:       "/",
        Status:     200,
        Time:       time.Now(),
    }
}
```

### Step 2: Register

Create `internal/core/source/mysource/init.go`:

```go
package mysource

import (
    "github.com/mr-addams/arxsentinel/pkg/source"
)

func init() {
    source.Register("my-source", func(cfg map[string]interface{}) (plugin.Source, error) {
        path, _ := cfg["path"].(string)
        return NewMySource(path), nil
    })
}
```

### Step 3: Import and Use

Add to `cmd/arxsentinel/main.go`:

```go
import (
    _ "github.com/mr-addams/arxsentinel/internal/core/source/mysource"
)
```

In `config.yaml`:

```yaml
inputs:
  - type: my-source
    path: /var/log/app.log
```

---

## Compiled-in Sink

### Step 1: Create the Plugin Package

Create `internal/core/sink/mysink/mysink.go`:

```go
package mysink

import (
    "github.com/mr-addams/arxsentinel/pkg/plugin"
    "os"
    "fmt"
)

// MySink writes threat events to a file.
type MySink struct {
    filePath string
    file     *os.File
    stats    plugin.SinkStats
}

func (s *MySink) Name() string {
    return "my-sink"
}

func (s *MySink) Write(event plugin.ThreatEvent) error {
    line := fmt.Sprintf("[%s] %s:%d IP=%s modules=%v reason=%s\n",
        event.Timestamp.Format("2006-01-02 15:04:05"),
        event.Level,
        event.Score,
        event.IP,
        event.Modules,
        event.Reason,
    )
    _, err := s.file.WriteString(line)
    if err == nil {
        s.stats.EventsWritten++
        s.stats.LastEvent = event.Timestamp
    } else {
        s.stats.EventsDropped++
    }
    return err
}

func (s *MySink) Close() error {
    return s.file.Close()
}

func (s *MySink) Stats() plugin.SinkStats {
    return s.stats
}

func NewMySink(filePath string) (plugin.Sink, error) {
    f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        return nil, err
    }
    return &MySink{filePath: filePath, file: f}, nil
}
```

### Step 2: Register and Import

Create `internal/core/sink/mysink/init.go`:

```go
package mysink

import (
    "github.com/mr-addams/arxsentinel/pkg/sink"
)

func init() {
    sink.Register("my-sink", func(cfg map[string]interface{}) (plugin.Sink, error) {
        path, _ := cfg["path"].(string)
        return NewMySink(path)
    })
}
```

Add to `cmd/arxsentinel/main.go`:

```go
import (
    _ "github.com/mr-addams/arxsentinel/internal/core/sink/mysink"
)
```

In `config.yaml`:

```yaml
outputs:
  - type: my-sink
    path: /var/log/threats.log
```

---

## exec+JSON Protocol

External plugins communicate with ArxSentinel via stdin/stdout, exchanging newline-delimited JSON.
Each message is a complete JSON object on a single line (no multiline JSON).

### Protocol Version

All messages include `"v":"1"` (protocol version).

### Environment Variables

When ArxSentinel spawns a plugin, the following env variables are provided:

- `ARXSENTINEL_PLUGIN_PARAMS` — JSON-encoded map of plugin config parameters
  - For YAML `params: {threshold: 0.7, model: "/path"}`, env contains:
    ```
    {"threshold":0.7,"model":"/path"}
    ```
  - Plugin decodes this in main() and uses parameters during initialization

### Detector Protocol (Request/Response)

**ArxSentinel sends (stdin):**

```json
{
  "v": "1",
  "action": "detect",
  "entry": {
    "remote_addr": "1.2.3.4",
    "remote_user": "",
    "time": "2026-01-01T12:00:00Z",
    "method": "GET",
    "raw_uri": "/admin",
    "path": "/admin",
    "query": "",
    "protocol": "HTTP/1.1",
    "status": 401,
    "bytes_sent": 512,
    "referer": "http://example.com",
    "user_agent": "Mozilla/5.0",
    "real_ip": ""
  },
  "state": {
    "ip": "1.2.3.4",
    "total_requests": 42,
    "requests_404": 5,
    "approx_rate_1m": 2.5,
    "recent_paths": ["/admin", "/.env", "/wp-admin"]
  }
}
```

**Plugin responds (stdout):**

```json
{
  "score": 45,
  "module": "ml-detector",
  "reason": "suspicious pattern: 3 failed admin attempts"
}
```

### Sink Protocol (One-Way Push)

**ArxSentinel sends (stdin):**

```json
{
  "v": "1",
  "action": "write",
  "event": {
    "timestamp": "2026-01-01T12:00:00Z",
    "level": "THREAT",
    "stream": "nginx-default",
    "source": "file-nginx",
    "source_type": "file",
    "ip": "1.2.3.4",
    "score": 150,
    "modules": ["probe-detector", "rate-detector"],
    "reason": "directory scan + high rate",
    "raw_line": "1.2.3.4 - - [01/Jan/2026:12:00:00 +0000] \"GET /admin HTTP/1.1\" 401 512"
  }
}
```

**Plugin responds (stdout):** optional, ignored

```json
{"ok": true}
```

### Source Protocol (Reverse Stream)

**ArxSentinel sends (stdin) to start:**

```json
{"v": "1", "action": "start"}
```

**Plugin streams continuously (stdout):**

```json
{
  "entry": {
    "remote_addr": "1.2.3.4",
    "remote_user": "",
    "time": "2026-01-01T12:00:00Z",
    "method": "GET",
    "raw_uri": "/",
    "path": "/",
    "query": "",
    "protocol": "HTTP/1.1",
    "status": 200,
    "bytes_sent": 1024,
    "referer": "",
    "user_agent": "curl/7.64.1",
    "real_ip": ""
  }
}
```

**ArxSentinel sends on shutdown (stdin):**

```json
{"v": "1", "action": "stop"}
```

---

## exec+JSON Detector

### Example: Python ML Detector

```yaml
# config.yaml
detectors:
  ml-classifier:
    enabled: true
    exec: /opt/plugins/ml_detector.py
    params:
      threshold: 0.75
      model_path: /opt/models/threat-classifier.pkl
```

**File: `/opt/plugins/ml_detector.py`**

```python
#!/usr/bin/env python3

import json
import sys
import os
import logging

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s', stream=sys.stderr)
logger = logging.getLogger(__name__)

# Load config from environment
params = json.loads(os.environ.get('ARXSENTINEL_PLUGIN_PARAMS', '{}'))
THRESHOLD = float(params.get('threshold', 0.7))
MODEL_PATH = params.get('model_path', './model.pkl')

# Load ML model. For production, use joblib or ONNX instead of pickle.
# Pickle is used here only for brevity; prefer safe serialization formats.
try:
    # NOTE: Only load models from trusted sources. Untrusted pickle files can execute code.
    import pickle
    with open(MODEL_PATH, 'rb') as f:
        model = pickle.load(f)
    logger.info(f'Loaded model from {MODEL_PATH}')
except Exception as e:
    logger.error(f'Failed to load model: {e}')
    sys.exit(1)

def detect_from_request(entry, state):
    """
    Extract features from log entry and IP state,
    run through ML model, return threat score.
    """
    # Example features: path length, query length, status code, rate, 404 ratio
    features = [
        len(entry['path']),
        len(entry['query']),
        entry['status'],
        state['approx_rate_1m'],
        state['requests_404'] / max(state['total_requests'], 1),
    ]
    
    # Predict threat probability
    prob = model.predict_proba([features])[0][1]  # Probability of class 1 (threat)
    
    score = int(prob * 100)
    reason = f"ML prediction: {prob:.2%} threat probability"
    
    return score, reason

def main():
    for line in sys.stdin:
        try:
            msg = json.loads(line.strip())
        except json.JSONDecodeError as e:
            logger.error(f'Invalid JSON: {e}')
            continue
        
        if msg.get('action') != 'detect':
            logger.warning(f"Unexpected action: {msg.get('action')}")
            continue
        
        entry = msg.get('entry', {})
        state = msg.get('state', {})
        
        try:
            score, reason = detect_from_request(entry, state)
            
            # Clamp score to 0–100
            score = max(0, min(100, score))
            
            result = {
                'score': score,
                'module': 'ml-classifier',
                'reason': reason,
            }
            print(json.dumps(result))
            sys.stdout.flush()
        except Exception as e:
            logger.error(f'Detection failed: {e}')
            # Return score 0 on error (no threat assumed)
            result = {'score': 0, 'module': 'ml-classifier', 'reason': f'Error: {e}'}
            print(json.dumps(result))
            sys.stdout.flush()

if __name__ == '__main__':
    main()
```

**Make it executable:**
```bash
chmod +x /opt/plugins/ml_detector.py
```

---

## exec+JSON Sink

### Example: Bash Telegram Notifier

```yaml
# config.yaml
outputs:
  - type: exec
    exec: /opt/plugins/telegram_notifier.sh
    params:
      bot_token: "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
      chat_id: "-1001234567890"
```

**File: `/opt/plugins/telegram_notifier.sh`**

```bash
#!/bin/bash

# Load params from environment (JSON)
BOT_TOKEN=$(echo "$ARXSENTINEL_PLUGIN_PARAMS" | python3 -c "import json, sys; p = json.load(sys.stdin); print(p.get('bot_token', ''))")
CHAT_ID=$(echo "$ARXSENTINEL_PLUGIN_PARAMS" | python3 -c "import json, sys; p = json.load(sys.stdin); print(p.get('chat_id', ''))")

API_URL="https://api.telegram.org/bot${BOT_TOKEN}/sendMessage"

while read -r line; do
    # Parse JSON event
    ip=$(echo "$line" | jq -r '.event.ip // empty')
    score=$(echo "$line" | jq -r '.event.score // 0')
    reason=$(echo "$line" | jq -r '.event.reason // "unknown"')
    
    if [ -z "$ip" ]; then
        continue
    fi
    
    # Format message
    msg="⚠️ Threat detected
IP: $ip
Score: $score
Reason: $reason"
    
    # Send via Telegram API
    curl -s -X POST "$API_URL" \
        -d "chat_id=${CHAT_ID}" \
        -d "text=${msg}" \
        -d "parse_mode=Markdown" > /dev/null 2>&1
done
```

**Make it executable:**
```bash
chmod +x /opt/plugins/telegram_notifier.sh
```

---

## exec+JSON Source

### Example: Python CloudWatch Reader

```yaml
# config.yaml
inputs:
  - type: exec
    exec: /opt/plugins/cloudwatch_reader.py
    params:
      region: us-east-1
      log_group: /aws/cloudfront/access-logs
      log_stream_prefix: ABCDEF.2026-01-01-12
```

**File: `/opt/plugins/cloudwatch_reader.py`**

```python
#!/usr/bin/env python3

import json
import sys
import os
import logging
import boto3
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s', stream=sys.stderr)
logger = logging.getLogger(__name__)

# Load params from environment
params = json.loads(os.environ.get('ARXSENTINEL_PLUGIN_PARAMS', '{}'))
REGION = params.get('region', 'us-east-1')
LOG_GROUP = params.get('log_group', '/aws/cloudfront/access-logs')
LOG_STREAM_PREFIX = params.get('log_stream_prefix', '')

def parse_cloudfront_log(line):
    """Parse CloudFront access log format into LogEntry."""
    parts = line.split('\t')
    if len(parts) < 16:
        return None
    
    # CloudFront format: date, time, bytes, ip, method, host, uri, status, referer, user-agent, ...
    try:
        return {
            'remote_addr': parts[4],
            'remote_user': '',
            'time': datetime.fromisoformat(f"{parts[0]}T{parts[1]}").isoformat() + 'Z',
            'method': parts[5],
            'raw_uri': f"{parts[6]}{('?' + parts[11]) if parts[11] != '-' else ''}",
            'path': parts[6],
            'query': parts[11] if parts[11] != '-' else '',
            'protocol': 'HTTP/1.1',
            'status': int(parts[8]),
            'bytes_sent': int(parts[3]) if parts[3] != '-' else 0,
            'referer': parts[9] if parts[9] != '-' else '',
            'user_agent': parts[10] if parts[10] != '-' else '',
            'real_ip': parts[4],
        }
    except (ValueError, IndexError) as e:
        logger.debug(f'Failed to parse line: {e}')
        return None

def main():
    # Initialize CloudWatch Logs client
    client = boto3.client('logs', region_name=REGION)
    
    try:
        # Find log streams matching prefix
        response = client.describe_log_streams(
            logGroupName=LOG_GROUP,
            logStreamNamePrefix=LOG_STREAM_PREFIX
        )
        
        for stream in response.get('logStreams', []):
            stream_name = stream['name']
            logger.info(f'Reading stream: {stream_name}')
            
            # Get log events
            events = client.get_log_events(
                logGroupName=LOG_GROUP,
                logStreamName=stream_name,
                startFromHead=True
            )
            
            for event in events.get('events', []):
                message = event.get('message', '')
                entry = parse_cloudfront_log(message)
                if entry:
                    result = {'entry': entry}
                    print(json.dumps(result))
                    sys.stdout.flush()
    
    except Exception as e:
        logger.error(f'CloudWatch read failed: {e}')
        sys.exit(1)

if __name__ == '__main__':
    main()
```

---

## Testing Your Plugin

### Unit Tests (Compiled-in)

For compiled-in detectors, create a test file alongside the detector:

**File: `internal/core/detector/mydetector/mydetector_test.go`**

```go
package mydetector

import (
    "testing"
    "time"
    "github.com/mr-addams/arxsentinel/pkg/plugin"
)

// MockIPView is a test double for IPView.
type MockIPView struct {
    ip             string
    totalRequests  int
    requests404    int
    recentPaths    []string
    approxRateVal  float64
}

func (m *MockIPView) GetIP() string                            { return m.ip }
func (m *MockIPView) GetTotalRequests() int                    { return m.totalRequests }
func (m *MockIPView) GetRequests404() int                      { return m.requests404 }
func (m *MockIPView) RecentPaths() []string                    { return m.recentPaths }
func (m *MockIPView) ApproxRate(window time.Duration) float64  { return m.approxRateVal }

func TestDetectHighRateAndMany404s(t *testing.T) {
    d := &MyDetector{}
    
    sv := &MockIPView{
        ip:             "1.2.3.4",
        totalRequests:  100,
        requests404:    20,
        approxRateVal:  150.0,
        recentPaths:    []string{"/.env", "/.git", "/admin"},
    }
    
    entry := &plugin.LogEntry{
        RemoteAddr: "1.2.3.4",
        Path:       "/admin",
        Query:      "id=1",
        Status:     401,
    }
    
    result := d.Detect(sv, entry)
    
    if result.Score < 50 {
        t.Fatalf("Expected score >= 50, got %d", result.Score)
    }
    if result.Module != d.Name() {
        t.Fatalf("Expected module %q, got %q", d.Name(), result.Module)
    }
}
```

### Integration Tests (exec+JSON)

For external plugins, test via stdin/stdout:

**File: `test_detector.sh`**

```bash
#!/bin/bash

# Start plugin in background
/opt/plugins/ml_detector.py &
PLUGIN_PID=$!

# Create test request
cat > /tmp/detect_req.json << 'EOF'
{
  "v": "1",
  "action": "detect",
  "entry": {
    "remote_addr": "1.2.3.4",
    "method": "GET",
    "path": "/.env",
    "query": "",
    "status": 404,
    "bytes_sent": 512,
    "referer": "",
    "user_agent": "curl"
  },
  "state": {
    "ip": "1.2.3.4",
    "total_requests": 42,
    "requests_404": 5,
    "approx_rate_1m": 2.5,
    "recent_paths": ["/.env", "/.git"]
  }
}
EOF

# Send request and capture response
response=$(cat /tmp/detect_req.json | /opt/plugins/ml_detector.py)

# Verify response structure
echo "$response" | python3 -c "
import json, sys
r = json.load(sys.stdin)
assert 'score' in r, 'Missing score'
assert 'module' in r, 'Missing module'
assert 'reason' in r, 'Missing reason'
assert 0 <= r['score'] <= 100, f'Score out of range: {r[\"score\"]}'
print('✓ All assertions passed')
"

kill $PLUGIN_PID
```

---

## Security Model

### Trust Boundaries

- **Compiled-in plugins:** Run in the same process and memory space as ArxSentinel.
  Assume they are trusted (developer-written, reviewed code).

- **External exec+JSON plugins:** Run as separate processes. Consider untrusted
  (user-supplied, third-party, externally maintained). Sandbox them as needed.

### Input Validation

- **LogEntry validation:** The core pipeline validates all LogEntry fields before
  passing to plugins. Plugin receives pre-validated data.

- **Detection results:** Plugin output (score, reason) is untrusted.
  ArxSentinel clamps scores to 0–100 and truncates long reasons.

- **Environment injection:** `ARXSENTINEL_PLUGIN_PARAMS` is provided by ArxSentinel
  and sourced from the config file. Plugins must parse it safely (use standard
  JSON libraries, validate types and ranges).

### Process Isolation

For security-critical plugins (ML models, third-party detectors):

1. **Run in a container:**
   ```bash
   exec: docker run --rm -i --net none my-plugin:latest
   ```
   This isolates the filesystem and network.

2. **Resource limits (cgroups/systemd):**
   ```bash
   exec: systemd-run --scope -p MemoryLimit=256M /opt/plugins/ml_detector.py
   ```

3. **Separate user account:**
   Create a dedicated user (e.g., `arxsentinel-plugins`) and run plugins as that user.
   Do NOT run plugins as root.

### Secrets Management

**Do NOT embed secrets in config.yaml.**

Instead, use environment variables:
```yaml
outputs:
  - type: exec
    exec: /opt/plugins/slack_notifier.sh
    params:
      webhook_url_env: SLACK_WEBHOOK_URL
```

Plugin reads from:
```python
webhook_url = os.environ.get('SLACK_WEBHOOK_URL')
```

---

## Troubleshooting

### Plugin fails to load

**Compiled-in:** Ensure the import statement is added to `cmd/arxsentinel/main.go`.
Run `go build` to verify no compilation errors.

**External:** Verify the binary exists, is executable, and has the correct shebang.
Check permissions: `ls -la /opt/plugins/`

### Plugin receives no requests

**Detector:** Verify `enabled: true` in config.yaml. Check ArxSentinel logs for errors.

**Source:** Verify the source is registered and appears in the config under `inputs:`.

**Sink:** Ensure threat events are being generated (detectors must trigger).

### Plugin times out or crashes

**Compiled-in:** Add panic recovery via `defer recover()` and log the stack trace.
Optimize algorithm or offload to external plugin.

**External:** Add logging to stderr (visible in ArxSentinel logs).
Test locally: `echo '...' | ./plugin.py`

### Performance degradation

**Compiled-in:** Profile with `pprof`. Expensive detectors should move to external.

**External:** Add latency metrics. Consider batching (multiple LogEntry per request)
in a future protocol version.
