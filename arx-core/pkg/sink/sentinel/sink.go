// ====== Module: pkg/sink/sentinel — Sentinel Threat Sink ======
//   Writes pipeline events to the NCS bridge via executor queue.
//   Acts as a bridge: receives events from the pipeline and enqueues them
//   for asynchronous processing by a downstream executor that reads from
//   the same named queue.
//   Implements back-pressure: drops events silently when the queue is full.
//
//   Gate B (Flow 083 / Task 3.3 / RESOLVED-D):
//   - The sink consumes the generic *plugin.Event. It serializes via an
//     injected Formatter (interface from pkg/sink/format) and pushes the
//     resulting bytes onto the NCS queue. Core owns the bridge, the
//     transport, and the lifecycle; product owns the wire format.
//   - Gate A type-assert on Event.Payload was removed; the Formatter impl
//     (a product-side formatter) owns the type-assertion.

package sentinel

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/mr-addams/arx-core/pkg/executor/queue"
	"github.com/mr-addams/arx-core/pkg/ncs"
	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/mr-addams/arx-core/pkg/sink/format"
)

// SentinelThreatSink enqueues pipeline events for downstream executor consumption.
// YAML: sink.sentinel-threat.name.
type SentinelThreatSink struct {
	name      string
	formatter format.Formatter
	q         queue.Queue
	dropped   atomic.Int64
}

// NewSentinelThreatSink creates a sink that enqueues events to the NCS bridge.
// formatter is required — the sink serializes events through it before pushing bytes
// onto the queue. The product owns the wire format (e.g. a sentinel-specific formatter).
//
// Returns: configured SentinelThreatSink, or error if name/formatter is empty
// or queue registration fails.
func NewSentinelThreatSink(name string, formatter format.Formatter, bufferSize int) (*SentinelThreatSink, error) {
	if name == "" {
		return nil, fmt.Errorf("sentinel-threat sink: name is required")
	}
	if formatter == nil {
		return nil, fmt.Errorf("sentinel-threat sink %q: formatter must not be nil", name)
	}
	q, err := ncs.AttachWriter(name, bufferSize)
	if err != nil {
		return nil, fmt.Errorf("sentinel-threat sink %q: %w", name, err)
	}
	return &SentinelThreatSink{name: name, formatter: formatter, q: q}, nil
}

// Name returns the sink identifier.
func (s *SentinelThreatSink) Name() string {
	return "sentinel-threat:" + s.name
}

// Write serializes event via the injected Formatter and enqueues the resulting
// bytes for the downstream executor that reads from the same named queue.
// Non-blocking: Push() uses a bounded channel; blocks only if channel is full.
// Silent drop on ErrQueueFull.
//
// Gate B (Flow 083 / Task 3.3 / RESOLVED-D): the sink no longer inspects
// Event.Payload. The injected Formatter takes the generic *plugin.Event
// and renders the byte sequence; the Formatter impl owns the type-assertion.
func (s *SentinelThreatSink) Write(ctx context.Context, event *plugin.Event) error {
	if event == nil {
		return fmt.Errorf("sentinel-threat sink %s: nil event", s.name)
	}
	line, err := s.formatter.Format(event)
	if err != nil {
		return fmt.Errorf("sentinel-threat sink %s: format: %w", s.name, err)
	}
	if err := s.q.Push(ctx, line); err != nil {
		if errors.Is(err, queue.ErrQueueFull) {
			s.dropped.Add(1)
			return nil
		}
		return err
	}
	return nil
}

// Close unregisters the queue from the executor.
// Called from: pipeline during shutdown.
func (s *SentinelThreatSink) Close() error {
	ncs.DetachWriter(s.name)
	return nil
}

// Stats returns counters for dropped events.
func (s *SentinelThreatSink) Stats() plugin.SinkStats {
	return plugin.SinkStats{
		Dropped: s.dropped.Load(),
	}
}