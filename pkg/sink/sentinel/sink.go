// ====== Module: pkg/sink/sentinel — Sentinel Threat Sink ======
//   Writes ThreatEvent records to the Sentinel Hub bridge via executor queue.
//   Acts as a bridge: receives events from the pipeline and enqueues them
//   for asynchronous processing by the SentinelHub executor.
//   Implements back-pressure: drops events silently when the queue is full.

package sentinel

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/mr-addams/arx-core/pkg/executor/queue"
	"github.com/mr-addams/arx-core/pkg/ncs"
	"github.com/mr-addams/arx-core/pkg/plugin"
)

// SentinelThreatSink enqueues threat events for the Sentinel Hub executor.
// YAML: sink.sentinel-threat.name.
// Fields:
//   - name: queue name passed to executor.AttachWriter. Consumer: executor
//   - q: shared queue handle for Push/DetachWriter. Consumer: Write, Close
//   - dropped: atomic counter for events dropped due to full queue. Consumer: Stats
type SentinelThreatSink struct {
	name    string
	q       queue.Queue
	dropped atomic.Int64
}

// NewSentinelThreatSink creates a sink that enqueues events to the Sentinel Hub bridge.
// Called from: sink/sentinel/register.go (plugin factory).
// Returns: configured SentinelThreatSink, or error if name is empty or queue registration fails.
func NewSentinelThreatSink(name string, bufferSize int) (*SentinelThreatSink, error) {
	if name == "" {
		return nil, fmt.Errorf("sentinel-threat sink: name is required")
	}
	q, err := ncs.AttachWriter(name, bufferSize)
	if err != nil {
		return nil, fmt.Errorf("sentinel-threat sink %q: %w", name, err)
	}
	return &SentinelThreatSink{name: name, q: q}, nil
}

// Name returns the sink identifier.
// Called from: pipeline/executor.go (logging, error messages).
func (s *SentinelThreatSink) Name() string {
	return "sentinel-threat:" + s.name
}

// Write enqueues a single threat event for the Sentinel Hub executor.
// Called from: pipeline/executor.go (per-event).
// Non-blocking: Push() uses a bounded channel; blocks only if channel is full.
// Silent drop: events are dropped without returning error when the queue is full
// (implements back-pressure without propagating errors up the pipeline).
//
// ctx is forwarded to the queue Push so that an in-flight enqueue can be
// cancelled by the pipeline during shutdown.
func (s *SentinelThreatSink) Write(ctx context.Context, event plugin.ThreatEvent) error {
	if err := s.q.Push(ctx, event); err != nil {
		if errors.Is(err, queue.ErrQueueFull) {
			s.dropped.Add(1)
			return nil
		}
		return err
	}
	return nil
}

// Close unregisters the queue from the executor.
// Called from: pipeline/executor.go during shutdown.
// The Sentinel Hub executor drains the queue asynchronously after unregister.
func (s *SentinelThreatSink) Close() error {
	ncs.DetachWriter(s.name)
	return nil
}

// Stats returns counters for dropped events.
// Called from: pipeline/executor.go (metrics reporting).
func (s *SentinelThreatSink) Stats() plugin.SinkStats {
	return plugin.SinkStats{
		Dropped: s.dropped.Load(),
	}
}
