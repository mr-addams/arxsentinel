// ========================== Module output/file =========================================
//   FileSink — writes threat events to a file in fail2ban or json format.
//   Supports SIGHUP log rotation via Reload().
//
//   WHAT IS HERE:
//     - FileSink — implements plugin.Sink, writes to a local file
//     - Reload() — reopens the file after logrotate (mv + copytruncate)
//
//   WHAT IS NOT HERE:
//     - StdoutSink (stdout.go)
//     - Format functions (format.go)
//     - ThreatLogger backward-compat wrapper (logger.go)
//
//   SIGHUP RELOAD:
//     main.go calls Reload() from the fan-out goroutine on SIGHUP.
//     mu protects the file descriptor swap — Write() and Reload() are serialised.

package output

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

// FileSink writes threat events to a file.
//
// Supported formats: "fail2ban" (text line) or "json" (JSON envelope + newline).
// The file is created if it does not exist; directories must already exist.
type FileSink struct {
	name   string
	path   string
	format string // "fail2ban" | "json"

	mu sync.Mutex
	f  *os.File

	eventsWritten atomic.Int64
	dropped       atomic.Int64
	errors        atomic.Int64
}

// NewFileSink creates a FileSink and opens the output file.
// format must be "fail2ban" or "json"; an error is returned for unknown formats.
func NewFileSink(path, format string) (*FileSink, error) {
	if path == "" {
		return nil, fmt.Errorf("file sink: path must not be empty")
	}
	if format != "fail2ban" && format != "json" {
		return nil, fmt.Errorf("file sink %s: unknown format %q (want fail2ban or json)", path, format)
	}
	f, err := openSinkFile(path)
	if err != nil {
		return nil, fmt.Errorf("file sink %s: %w", path, err)
	}
	return &FileSink{
		name:   "file:" + path,
		path:   path,
		format: format,
		f:      f,
	}, nil
}

func (s *FileSink) Name() string { return s.name }

// Close flushes and closes the underlying file.
func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	_ = s.f.Sync()
	err := s.f.Close()
	s.f = nil
	return err
}

// Stats returns a point-in-time snapshot of operational counters.
func (s *FileSink) Stats() plugin.SinkStats {
	return plugin.SinkStats{
		EventsWritten: s.eventsWritten.Load(),
		Dropped:       s.dropped.Load(),
		Errors:        s.errors.Load(),
	}
}

// Write formats and writes a ThreatEvent to the file.
// Safe for concurrent calls — protected by mu.
func (s *FileSink) Write(event plugin.ThreatEvent) error {
	var line []byte
	switch s.format {
	case "json":
		b, err := FormatJSON(event)
		if err != nil {
			s.errors.Add(1)
			return fmt.Errorf("file sink %s: json marshal: %w", s.path, err)
		}
		line = append(b, '\n')
	default: // "fail2ban"
		line = []byte(FormatFailban(event) + "\n")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.f == nil {
		s.dropped.Add(1)
		return fmt.Errorf("file sink %s: file is closed", s.path)
	}
	if _, err := s.f.Write(line); err != nil {
		s.errors.Add(1)
		return fmt.Errorf("file sink %s: write: %w", s.path, err)
	}
	s.eventsWritten.Add(1)
	return nil
}

// Reload reopens the underlying file after logrotate.
// Called from the SIGHUP fan-out goroutine in main.go.
// Flushes and closes the old file descriptor before opening the new one.
func (s *FileSink) Reload() error {
	newF, err := openSinkFile(s.path)
	if err != nil {
		return fmt.Errorf("file sink %s reload: %w", s.path, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f != nil {
		_ = s.f.Sync()
		_ = s.f.Close()
	}
	s.f = newF
	return nil
}

// openSinkFile opens path for appending, creating it and its parent directory if needed.
func openSinkFile(path string) (*os.File, error) {
	if err := ensureSinkDir(path); err != nil {
		return nil, err
	}
	return os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
}

// ensureSinkDir creates the parent directory of path if it does not exist.
func ensureSinkDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "" || dir == "." {
		return nil
	}
	return os.MkdirAll(dir, 0755)
}
