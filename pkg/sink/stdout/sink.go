package stdout

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/mr-addams/arxsentinel/internal/core/output"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

type StdoutSink struct {
	name   string
	format string
	w      *os.File

	mu sync.Mutex

	eventsWritten atomic.Int64
	dropped       atomic.Int64
	errors        atomic.Int64
}

func NewStdoutSink(format string) (*StdoutSink, error) {
	return NewStdoutSinkWithWriter(os.Stdout, format)
}

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

func (s *StdoutSink) Close() error { return nil }

func (s *StdoutSink) Stats() plugin.SinkStats {
	return plugin.SinkStats{
		EventsWritten: s.eventsWritten.Load(),
		Dropped:       s.dropped.Load(),
		Errors:        s.errors.Load(),
	}
}

func (s *StdoutSink) Write(event plugin.ThreatEvent) error {
	var line []byte
	switch s.format {
	case "json":
		b, err := output.FormatJSON(event)
		if err != nil {
			s.errors.Add(1)
			return fmt.Errorf("stdout sink: json marshal: %w", err)
		}
		line = append(b, '\n')
	case "sentinel-threat":
		b, err := output.FormatSentinelThreat(event, "")
		if err != nil {
			s.errors.Add(1)
			return fmt.Errorf("stdout sink: sentinel-threat marshal: %w", err)
		}
		line = append(b, '\n')
	default:
		line = []byte(output.FormatFailban(event) + "\n")
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

