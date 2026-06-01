// ========================== Module output/stdout =======================================
//   StdoutSink — writes threat events to os.Stdout in fail2ban or json format.
//   Intended for container / pipe mode where logs are collected by the orchestrator.
//
//   WHAT IS HERE:
//     - StdoutSink — implements plugin.Sink, writes to os.Stdout
//
//   WHAT IS NOT HERE:
//     - FileSink (file.go)
//     - Format functions (format.go)

package output

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/mr-addams/arxsentinel/pkg/plugin"
	pkgsink "github.com/mr-addams/arxsentinel/pkg/sink"
)

// StdoutSink writes threat events to os.Stdout.
//
// Supported formats: "fail2ban" (text line) or "json" (JSON envelope + newline).
// mu serialises concurrent Write calls — os.Stdout is shared across goroutines.
type StdoutSink struct {
	plugin.NopManifest
	name   string
	format string // "fail2ban" | "json"
	w      *os.File // injectable for tests; os.Stdout in production

	mu sync.Mutex

	eventsWritten atomic.Int64
	dropped       atomic.Int64
	errors        atomic.Int64
}

// NewStdoutSink creates a StdoutSink writing to os.Stdout.
// format must be "fail2ban" or "json".
func NewStdoutSink(format string) (*StdoutSink, error) {
	return NewStdoutSinkWithWriter(os.Stdout, format)
}

// NewStdoutSinkWithWriter creates a StdoutSink writing to w.
// Used in tests to inject a pipe without touching os.Stdout.
func NewStdoutSinkWithWriter(w *os.File, format string) (*StdoutSink, error) {
	if format != "fail2ban" && format != "json" && format != "sentinel-threat" {
		return nil, fmt.Errorf("stdout sink: unknown format %q (want fail2ban, json, or sentinel-threat)", format)
	}
	return &StdoutSink{
		name:   "stdout",
		format: format,
		w:      w,
	}, nil
}

func (s *StdoutSink) Name() string { return s.name }

// Close is a no-op — os.Stdout is not owned by StdoutSink.
func (s *StdoutSink) Close() error { return nil }

// Stats returns a point-in-time snapshot of operational counters.
func (s *StdoutSink) Stats() plugin.SinkStats {
	return plugin.SinkStats{
		EventsWritten: s.eventsWritten.Load(),
		Dropped:       s.dropped.Load(),
		Errors:        s.errors.Load(),
	}
}

// Write formats and writes a ThreatEvent to stdout.
// Safe for concurrent calls — protected by mu.
func (s *StdoutSink) Write(event plugin.ThreatEvent) error {
	var line []byte
	switch s.format {
	case "json":
		b, err := FormatJSON(event)
		if err != nil {
			s.errors.Add(1)
			return fmt.Errorf("stdout sink: json marshal: %w", err)
		}
		line = append(b, '\n')
	case "sentinel-threat":
		b, err := FormatSentinelThreat(event, "")
		if err != nil {
			s.errors.Add(1)
			return fmt.Errorf("stdout sink: sentinel-threat marshal: %w", err)
		}
		line = append(b, '\n')
	default: // "fail2ban"
		line = []byte(FormatFailban(event) + "\n")
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

// init registers StdoutSink with the global registry.
// Called at module init time, making "stdout" available as a sink type in YAML config.
func init() {
	pkgsink.Register("stdout", func(cfg pkgsink.SinkConfig) (plugin.Sink, error) {
		return NewStdoutSink(cfg.Format)
	})
}
