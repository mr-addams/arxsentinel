# `pkg/source/sentinel`

Sentinel source for `arx-core`. Reads `plugin.ThreatEvent` records from the
in-process **Named Channel Switch** (`pkg/ncs/channelswitch.go`) and
forwards them to the pipeline as `*plugin.LogEntry`. The source is the
reverse direction of `pkg/sink/sentinel/`: the sink pushes ThreatEvents
into the NCS, this source pulls them back out so another pipeline (or a
second chain in the same process) can run them through the normal
parser → whitelist → scorer → executor chain. Wire format on both sides
is `plugin.ThreatEvent`, which makes the NCS act as a typed in-process
message bus between pipeline components.

## Public API

```go
// SentinelSource — reads ThreatEvent from a single named NCS queue
// and forwards each as a *plugin.LogEntry. Implements plugin.Source.
type SentinelSource struct { /* unexported */ }

// New — production constructor. addr is "ncs://<queue-name>" and must
// reference a queue that an executor writer (or pkg/sink/sentinel) has
// already registered via ncs.AttachWriter; otherwise New fails with the
// error from AttachReader and the pipeline does not start. logFn is
// nil-safe — nil means "stay quiet".
func New(addr string, logFn func(tag, msg, level string)) (*SentinelSource, error)

// NewWithQueue — test constructor. Skips addr parsing and AttachReader;
// the queue handle is injected directly. Used by source_test.go to avoid
// the global NCS singleton. Production code paths always go through New.
func NewWithQueue(name string, q queue.Queue, logFn func(tag, msg, level string)) *SentinelSource

// plugin.Source interface — implemented by SentinelSource.
func (s *SentinelSource) Name() string                       // returns "sentinel:<queue-name>"
func (s *SentinelSource) Run(ctx context.Context, out chan<- *plugin.LogEntry) error
func (s *SentinelSource) Close() error                      // no-op: queue lifecycle is owned by the writer
func (s *SentinelSource) Stats() plugin.SourceStats         // LinesRead / ParseErrors / Dropped
func (s *SentinelSource) Manifest() plugin.Manifest         // PluginID "sentinel", Role=Source
```

Address scheme: only `ncs://<queue-name>` is accepted; anything else is
rejected at `New()`. Empty queue name is rejected with `queue name is
empty`. The queue's `IP` field on `ThreatEvent` is mandatory — an event
with an empty IP is logged and dropped (counted as `parseErrors`) so the
downstream pipeline never sees an unmatchable entry.

## Example

Two pipelines sharing one NCS queue name. Pipeline A writes ThreatEvents
through a sentinel sink into `shared-events`; Pipeline B pulls them back
through this source.

```yaml
# pipeline-a.yaml — writes
inputs:
  - type: file
    path: /var/log/nginx/access.log
outputs:
  - type: sentinel-threat
    name: shared-events

# pipeline-b.yaml — reads
inputs:
  - type: sentinel
    addr: ncs://shared-events
executors:
  - name: cf-block
    type: cloudflare
```
