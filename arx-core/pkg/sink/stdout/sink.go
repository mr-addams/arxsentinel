// ====== Module: pkg/sink/stdout — Stdout Sink ======
//   Writes pipeline events to stdout. Serialization is delegated to an
//   injected Formatter (pkg/sink/format.Formatter); the sink owns only the
//   I/O loop and lifecycle.
//
//   Phase 2.2 (Flow 083 / RESOLVED-Q9 / RESOLVED-Z12): the sink no longer
//   switches on a format string. Product code picks a Formatter at pipeline
//   assembly time.

package stdout

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/mr-addams/arx-core/pkg/sink/format"
)

// StdoutSink writes pipeline events to stdout using an injected Formatter.
// YAML: sink.stdout.format (used at wiring time to pick a Formatter).
type StdoutSink struct {
	name      string
	formatter format.Formatter
	w         *os.File

	mu sync.Mutex

	eventsWritten atomic.Int64
	dropped       atomic.Int64
	errors        atomic.Int64
}

// NewStdoutSink creates a StdoutSink writing to os.Stdout using formatter.
func NewStdoutSink(formatter format.Formatter) (*StdoutSink, error) {
	return NewStdoutSinkWithWriter(os.Stdout, formatter)
}

// NewStdoutSinkWithWriter creates a StdoutSink with a custom writer (for testing)
// and an injected formatter.
//
// Called from: NewStdoutSink, sink_test.go.
// Returns: configured StdoutSink on success, or error if formatter is nil.
func NewStdoutSinkWithWriter(w *os.File, formatter format.Formatter) (*StdoutSink, error) {
	if formatter == nil {
		return nil, fmt.Errorf("stdout sink: formatter must not be nil")
	}
	return &StdoutSink{
		name:      "stdout",
		formatter: formatter,
		w:         w,
	}, nil
}

// Name returns the sink identifier.
func (s *StdoutSink) Name() string { return s.name }

// Close is a no-op for stdout (no file handle to close).
func (s *StdoutSink) Close() error { return nil }

// Stats returns counters for events written, dropped, and errors.
func (s *StdoutSink) Stats() plugin.SinkStats {
	return plugin.SinkStats{
		EventsWritten: s.eventsWritten.Load(),
		Dropped:       s.dropped.Load(),
		Errors:        s.errors.Load(),
	}
}

// Write serializes event via the injected Formatter and writes the bytes to
// the underlying writer.
//
// ctx is accepted to satisfy the plugin.Sink interface but is intentionally
// unused: stdout writes are short syscalls bounded by the mutex, so
// cancellation is not meaningful.
//
// Gate A (Flow 083 / Task 2.2 / RESOLVED-D strategy II): the Sink contract
// carries generic *plugin.Event; the Formatter still wants a concrete
// *plugin.ThreatEvent. We type-assert here and surface a programmer error on
// a wrong payload type. Replaced with Formatter-injection in Task 3.3.
func (s *StdoutSink) Write(ctx context.Context, event *plugin.Event) error {
	if event == nil {
		s.errors.Add(1)
		return fmt.Errorf("stdout sink: nil event")
	}
	te, ok := event.Payload.(*plugin.ThreatEvent)
	if !ok {
		s.errors.Add(1)
		return fmt.Errorf("stdout sink: Phase 2.2 Gate A: expected *plugin.ThreatEvent payload, got %T", event.Payload)
	}
	line, err := s.formatter.Format(te)
	if err != nil {
		s.errors.Add(1)
		return fmt.Errorf("stdout sink: format: %w", err)
	}
	line = append(line, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.w.Write(line); err != nil {
		s.errors.Add(1)
		return fmt.Errorf("stdout sink: write: %w", err)
	}
	s.eventsWritten.Add(1)
	return nil
}