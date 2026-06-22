// ====== Module: pkg/sink/stdout — Stdout Sink ======
//   Writes ThreatEvent records to stdout.
//   Supports three output formats: fail2ban, json, sentinel-threat.
//   Uses mutex + atomic counters for thread-safe writes and statistics.

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

// StdoutSink writes threat events to stdout in the configured output format.
// YAML: sink.stdout.format.
// Fields:
//   - name: fixed identifier "stdout". Consumer: pipeline/executor.go
//   - format: output format ("fail2ban" | "json" | "sentinel-threat"). Consumer: Write
//   - w: output file (default stdout, injectable for testing). Consumer: Write
//   - mu: serializes stdout writes. Consumer: Write
//   - eventsWritten, dropped, errors: atomic counters. Consumer: Stats
type StdoutSink struct {
	name   string
	format string
	w      *os.File

	mu sync.Mutex

	eventsWritten atomic.Int64
	dropped       atomic.Int64
	errors        atomic.Int64
}

// NewStdoutSink creates a StdoutSink writing to os.Stdout.
// Called from: sink/stdout/register.go (plugin factory).
func NewStdoutSink(format string) (*StdoutSink, error) {
	return NewStdoutSinkWithWriter(os.Stdout, format)
}

// NewStdoutSinkWithWriter creates a StdoutSink with a custom writer (for testing).
// Called from: NewStdoutSink, sink_test.go.
// Returns: configured StdoutSink on success, or error if format is unknown.
func NewStdoutSinkWithWriter(w *os.File, format string) (*StdoutSink, error) {
	// Reject unknown formats early to prevent silent misconfiguration.
	if format != "fail2ban" && format != "json" && format != "sentinel-threat" {
		return nil, fmt.Errorf("stdout sink: unknown format %q (want fail2ban, json, or sentinel-threat)", format)
	}
	return &StdoutSink{
		name:   "stdout",
		format: format,
		w:      w,
	}, nil
}

// Name returns the sink identifier.
// Called from: pipeline/executor.go (logging, error messages).
func (s *StdoutSink) Name() string { return s.name }

// Close is a no-op for stdout (no file handle to close).
// Called from: pipeline/executor.go during shutdown.
func (s *StdoutSink) Close() error { return nil }

// Stats returns counters for events written, dropped, and errors.
// Called from: pipeline/executor.go (metrics reporting).
func (s *StdoutSink) Stats() plugin.SinkStats {
	return plugin.SinkStats{
		EventsWritten: s.eventsWritten.Load(),
		Dropped:       s.dropped.Load(),
		Errors:        s.errors.Load(),
	}
}

// Write formats and writes a single threat event to stdout.
// Called from: pipeline/executor.go (per-event).
// Non-blocking: mutex-protected write.
//
// ctx is accepted to satisfy the plugin.Sink interface but is intentionally
// unused: stdout writes are short syscalls bounded by the mutex, so
// cancellation is not meaningful.
func (s *StdoutSink) Write(ctx context.Context, event plugin.ThreatEvent) error {
	// Serialize event to bytes according to configured format.
	var line []byte
	switch s.format {
	case "json":
		b, err := format.FormatJSON(event)
		if err != nil {
			s.errors.Add(1)
			return fmt.Errorf("stdout sink: json marshal: %w", err)
		}
		line = append(b, '\n')
	case "sentinel-threat":
		b, err := format.FormatSentinelThreat(event, "")
		if err != nil {
			s.errors.Add(1)
			return fmt.Errorf("stdout sink: sentinel-threat marshal: %w", err)
		}
		line = append(b, '\n')
	default:
		// "fail2ban" — default format.
		line = []byte(format.FormatFailban(event) + "\n")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.w.Write(line); err != nil {
		s.errors.Add(1)
		return fmt.Errorf("stdout sink: write: %w", err)
	}
	s.eventsWritten.Add(1)
	return nil
}
