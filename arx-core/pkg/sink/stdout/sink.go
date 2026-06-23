// ====== Module: pkg/sink/stdout — Stdout Sink ======
//   Writes pipeline events to stdout. Serialization is delegated to an
//   injected Formatter (pkg/sink/format.Formatter); the sink owns only the
//   I/O loop and lifecycle.
//
//   Gate B (Flow 083 / Task 3.3 / RESOLVED-D): the Gate A type-assert on
//   Event.Payload was removed. The injected Formatter (product-side impl
//   from cmd/arxsentinel/internal/threat/format) owns the type-assertion.

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
// Gate B (Flow 083 / Task 3.3 / RESOLVED-D): the sink no longer inspects
// Event.Payload. The injected Formatter takes the generic *plugin.Event
// and renders the byte sequence; the Formatter impl owns the type-assertion.
func (s *StdoutSink) Write(ctx context.Context, event *plugin.Event) error {
	if event == nil {
		s.errors.Add(1)
		return fmt.Errorf("stdout sink: nil event")
	}
	line, err := s.formatter.Format(event)
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