// ====== Module: pkg/sink/file — File Sink ======
//   Writes ThreatEvent records to a local file.
//   Supports three output formats: fail2ban, json, sentinel-threat.
//   Uses mutex + atomic counters for thread-safe writes and statistics.

package file

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/mr-addams/arx-core/pkg/sink/format"
)

// FileSink writes threat events to a file in the configured output format.
// YAML: sink.file.path, sink.file.format.
// Fields:
//   - name: human-readable identifier "file:<path>". Consumer: pipeline/executor.go
//   - path: target file path. Consumer: openSinkFile
//   - format: output format ("fail2ban" | "json" | "sentinel-threat"). Consumer: Write
//   - mu: serializes file writes. Consumer: Write, Close, Reload
//   - f: open file handle. Consumer: Write, Close, Reload
//   - eventsWritten, dropped, errors: atomic counters for statistics. Consumer: Stats
type FileSink struct {
	name   string
	path   string
	format string

	mu sync.Mutex
	f  *os.File

	eventsWritten atomic.Int64
	dropped       atomic.Int64
	errors        atomic.Int64
}

// NewFileSink creates a new FileSink instance and opens the target file.
// Called from: sink/file/register.go (plugin factory).
// Returns: configured FileSink on success, or error if path empty or file cannot be opened.
// Blocking: opens and locks the file.
func NewFileSink(path, format string) (*FileSink, error) {
	if path == "" {
		return nil, fmt.Errorf("file sink: path must not be empty")
	}
	// Reject unknown formats early to prevent silent misconfiguration.
	if format != "fail2ban" && format != "json" && format != "sentinel-threat" {
		return nil, fmt.Errorf("file sink %s: unknown format %q (want fail2ban, json, or sentinel-threat)", path, format)
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

// Name returns the sink identifier.
// Called from: pipeline/executor.go (logging, error messages).
func (s *FileSink) Name() string { return s.name }

// Close closes the file handle and syncs pending writes.
// Called from: pipeline/executor.go during shutdown.
// Blocking: acquires mutex, syncs and closes file descriptor.
func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// No-op if file was already closed (e.g., after Reload error).
	if s.f == nil {
		return nil
	}
	_ = s.f.Sync()
	err := s.f.Close()
	s.f = nil
	return err
}

// Stats returns counters for events written, dropped, and errors.
// Called from: pipeline/executor.go (metrics reporting).
func (s *FileSink) Stats() plugin.SinkStats {
	return plugin.SinkStats{
		EventsWritten: s.eventsWritten.Load(),
		Dropped:       s.dropped.Load(),
		Errors:        s.errors.Load(),
	}
}

// Write formats and writes a single threat event to the file.
// Called from: pipeline/executor.go (per-event).
// Non-blocking: mutex-protected file write.
//
// ctx is accepted to satisfy the plugin.Sink interface but is intentionally
// unused: file I/O here is a single short syscall that is bounded by the
// mutex, so cancellation is not meaningful.
func (s *FileSink) Write(ctx context.Context, event plugin.ThreatEvent) error {
	// Serialize event to bytes according to configured format.
	var line []byte
	switch s.format {
	case "json":
		b, err := format.FormatJSON(event)
		if err != nil {
			s.errors.Add(1)
			return fmt.Errorf("file sink %s: json marshal: %w", s.path, err)
		}
		line = append(b, '\n')
	case "sentinel-threat":
		b, err := format.FormatSentinelThreat(event, "")
		if err != nil {
			s.errors.Add(1)
			return fmt.Errorf("file sink %s: sentinel-threat marshal: %w", s.path, err)
		}
		line = append(b, '\n')
	default:
		// "fail2ban" — default format.
		line = []byte(format.FormatFailban(event) + "\n")
	}

	// Serialize access to the shared file handle.
	s.mu.Lock()
	defer s.mu.Unlock()

	// Drop if file was closed between FormatJSON call and mutex acquisition (e.g., Reload race).
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

// Reload closes and reopens the file, enabling log rotation.
// Called from: pipeline/executor.go (SIGHUP handler).
// Blocking: acquires mutex, closes and reopens file descriptor.
func (s *FileSink) Reload() error {
	newF, err := openSinkFile(s.path)
	if err != nil {
		return fmt.Errorf("file sink %s reload: %w", s.path, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Sync and close old handle before replacing with new one.
	if s.f != nil {
		_ = s.f.Sync()
		_ = s.f.Close()
	}
	s.f = newF
	return nil
}

// openSinkFile opens (or creates) the sink file for append-only writes.
// Ensures parent directory exists before opening.
func openSinkFile(path string) (*os.File, error) {
	if err := ensureSinkDir(path); err != nil {
		return nil, err
	}
	return os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
}

// ensureSinkDir creates the parent directory of the sink path if it does not exist.
// Silently succeeds if the directory already exists.
func ensureSinkDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "" || dir == "." {
		return nil
	}
	return os.MkdirAll(dir, 0755)
}
