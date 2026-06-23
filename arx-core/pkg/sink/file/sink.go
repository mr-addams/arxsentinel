// ====== Module: pkg/sink/file — File Sink ======
//   Writes pipeline events to a local file. Serialization is delegated to
//   an injected Formatter (pkg/sink/format.Formatter); the file sink owns
//   only the I/O loop and the lifecycle (open / write / sync / close / reload).
//
//   Phase 2.2 (Flow 083 / RESOLVED-Q9 / RESOLVED-Z12): the sink no longer
//   switches on a format string. The caller injects a Formatter that knows
//   how to render Event bytes (typically a product-owned impl from
//   cmd/arxsentinel/internal/threat/format). The sink itself is
//   generic — it never inspects Event.Payload.

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

// FileSink writes pipeline events to a file using an injected Formatter.
//
// YAML: sink.file.path, sink.file.format (used at wiring time to pick a Formatter).
// Fields:
//   - name: human-readable identifier "file:<path>". Consumer: pipeline / metrics.
//   - path: target file path. Consumer: openSinkFile.
//   - formatter: serializer from Event → bytes. Consumer: Write.
//   - mu: serializes file writes. Consumer: Write, Close, Reload.
//   - f: open file handle. Consumer: Write, Close, Reload.
//   - eventsWritten, dropped, errors: atomic counters for statistics. Consumer: Stats.
type FileSink struct {
	name      string
	path      string
	formatter format.Formatter

	mu sync.Mutex
	f  *os.File

	eventsWritten atomic.Int64
	dropped       atomic.Int64
	errors        atomic.Int64
}

// NewFileSink creates a new FileSink instance and opens the target file.
// formatter is required — the sink has no built-in default. Product code
// injects a concrete Formatter (FailbanFormatter / JSONFormatter /
// SentinelFormatter) at pipeline assembly time.
//
// Called from: sink/file/register.go (plugin factory), tests.
// Returns: configured FileSink on success, or error if path/formatter invalid
// or the file cannot be opened.
// Blocking: opens and locks the file.
func NewFileSink(path string, formatter format.Formatter) (*FileSink, error) {
	if path == "" {
		return nil, fmt.Errorf("file sink: path must not be empty")
	}
	if formatter == nil {
		return nil, fmt.Errorf("file sink %s: formatter must not be nil", path)
	}
	f, err := openSinkFile(path)
	if err != nil {
		return nil, fmt.Errorf("file sink %s: %w", path, err)
	}
	return &FileSink{
		name:      "file:" + path,
		path:      path,
		formatter: formatter,
		f:         f,
	}, nil
}

// Name returns the sink identifier.
// Called from: pipeline (logging, error messages).
func (s *FileSink) Name() string { return s.name }

// Close closes the file handle and syncs pending writes.
// Called from: pipeline during shutdown.
// Blocking: acquires mutex, syncs and closes file descriptor.
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

// Stats returns counters for events written, dropped, and errors.
// Called from: pipeline (metrics reporting).
func (s *FileSink) Stats() plugin.SinkStats {
	return plugin.SinkStats{
		EventsWritten: s.eventsWritten.Load(),
		Dropped:       s.dropped.Load(),
		Errors:        s.errors.Load(),
	}
}

// Write serializes event via the injected Formatter and writes the bytes to
// the file.
//
// ctx is accepted to satisfy the plugin.Sink interface but is intentionally
// unused: file I/O here is a single short syscall that is bounded by the
// mutex, so cancellation is not meaningful.
//
// Gate A (Flow 083 / Task 2.2 / RESOLVED-D strategy II): the Sink contract
// carries generic *plugin.Event; the Formatter still wants a concrete
// *plugin.ThreatEvent because the byte format is ThreatEvent-shaped. We
// type-assert here and surface a programmer error on a wrong payload type.
// Replaced with Formatter-injection in Task 3.3 (Flow 083 RESOLVED-D).
func (s *FileSink) Write(ctx context.Context, event *plugin.Event) error {
	if event == nil {
		s.errors.Add(1)
		return fmt.Errorf("file sink %s: nil event", s.path)
	}
	te, ok := event.Payload.(*plugin.ThreatEvent)
	if !ok {
		s.errors.Add(1)
		return fmt.Errorf("file sink %s: Phase 2.2 Gate A: expected *plugin.ThreatEvent payload, got %T", s.path, event.Payload)
	}
	line, err := s.formatter.Format(te)
	if err != nil {
		s.errors.Add(1)
		return fmt.Errorf("file sink %s: format: %w", s.path, err)
	}
	// Sinks do not append newlines — that is the formatter's responsibility
	// for line-oriented formats.
	line = append(line, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()

	// Drop if file was closed between Format call and mutex acquisition (e.g., Reload race).
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
// Called from: pipeline (SIGHUP handler).
// Blocking: acquires mutex, closes and reopens file descriptor.
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