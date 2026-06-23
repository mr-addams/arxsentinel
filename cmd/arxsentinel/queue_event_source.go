// ========================== Queue→EventSource adapter (Gate B) ============================
//   Gate B (Flow 083 / Task 3.3 / RESOLVED-D):
//
//   pkg/executor/queue.Queue still operates on opaque []byte payloads (see
//   pkg/executor/queue/queue.go — deliberate, so persistent backends serialize
//   via JSON cleanly across process restarts). The Sink side (Formatter) owns
//   the wire schema: today it produces Fail2Ban-line or JSON-serialized
//   *threat.ThreatEvent bytes.
//
//   plugin.EventSource wants *plugin.Event from Pop. This file provides a
//   bytes→Event adapter used only by the executor goroutine dispatcher in
//   cmd/arxsentinel/executors.go. The wire format expected here is a
//   JSON-encoded *threat.ThreatEvent (matching what the sentinel-threat
//   sink pushes onto the queue today).

package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/mr-addams/arx-core/pkg/executor/queue"
	"github.com/mr-addams/arx-core/pkg/plugin"

	"github.com/mr-addams/arxsentinel/internal/threat"
)

// queueEventSource wraps a queue.Queue (bytes-oriented) into a
// plugin.EventSource (Event-oriented). Gate B scope: decodes JSON
// *threat.ThreatEvent payloads; a wrong payload type is a programmer
// error and is logged-and-skipped (the executor's own Gate B guard
// handles type-assertion of Event.Payload).
type queueEventSource struct {
	q queue.Queue
}

func newQueueEventSource(q queue.Queue) *queueEventSource {
	return &queueEventSource{q: q}
}

// Pop implements plugin.EventSource by reading bytes from the underlying
// queue and JSON-decoding them into a *plugin.Event whose Payload is the
// recovered *threat.ThreatEvent. Wire format is JSON *threat.ThreatEvent.
func (s *queueEventSource) Pop(ctx context.Context) (*plugin.Event, error) {
	data, err := s.q.Pop(ctx)
	if err != nil {
		return nil, err
	}
	var te threat.ThreatEvent
	if jerr := json.Unmarshal(data, &te); jerr != nil {
		return nil, fmt.Errorf("queueEventSource: decode ThreatEvent JSON: %w", jerr)
	}
	return &plugin.Event{Payload: &te}, nil
}
