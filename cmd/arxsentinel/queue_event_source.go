// ========================== Queue→EventSource adapter (Gate A) ============================
//   Phase 2.2 (Flow 083 / Gate A / RESOLVED-D strategy II / OPEN-Q3b gray zone):
//
//   pkg/executor/queue.Queue still operates on opaque []byte payloads (see
//   pkg/executor/queue/queue.go — deliberate, so persistent backends serialize
//   via JSON cleanly across process restarts). The Sink side (Formatter) owns
//   the wire schema: today it produces Fail2Ban-line or JSON-serialized
//   *plugin.ThreatEvent bytes.
//
//   plugin.EventSource wants *plugin.Event from Pop. Until the proper
//   adapter lands in Task 3.3 (Flow 083), this file provides a minimal
//   bytes→Event adapter used only by the executor goroutine dispatcher
//   in cmd/arxsentinel/executors.go. The wire format expected here is a
//   JSON-encoded *plugin.ThreatEvent (matching what the sentinel-threat
//   sink pushes onto the queue today).
//
//   Replaced with a richer adapter in Task 3.3 — the long-term shape
//   accepts arbitrary formatter-driven payloads, not just ThreatEvent JSON.

package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/mr-addams/arx-core/pkg/executor/queue"
	"github.com/mr-addams/arx-core/pkg/plugin"
)

// queueEventSource wraps a queue.Queue (bytes-oriented) into a
// plugin.EventSource (Event-oriented). Gate A scope: decodes JSON
// *plugin.ThreatEvent payloads; a wrong payload type is a programmer
// error and is logged-and-skipped (the executor's own Gate A guard
// handles type-assertion of Event.Payload).
type queueEventSource struct {
	q queue.Queue
}

func newQueueEventSource(q queue.Queue) *queueEventSource {
	return &queueEventSource{q: q}
}

// Pop implements plugin.EventSource by reading bytes from the underlying
// queue and JSON-decoding them into a *plugin.Event whose Payload is the
// recovered *plugin.ThreatEvent. Wire format is JSON *plugin.ThreatEvent.
func (s *queueEventSource) Pop(ctx context.Context) (*plugin.Event, error) {
	data, err := s.q.Pop(ctx)
	if err != nil {
		return nil, err
	}
	var te plugin.ThreatEvent
	if jerr := json.Unmarshal(data, &te); jerr != nil {
		return nil, fmt.Errorf("queueEventSource: decode ThreatEvent JSON: %w", jerr)
	}
	return &plugin.Event{Payload: &te}, nil
}
