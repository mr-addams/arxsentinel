package file

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/mr-addams/arxsentinel/internal/core/output"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

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

func NewFileSink(path, format string) (*FileSink, error) {
	if path == "" {
		return nil, fmt.Errorf("file sink: path must not be empty")
	}
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

func (s *FileSink) Name() string { return s.name }

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

func (s *FileSink) Stats() plugin.SinkStats {
	return plugin.SinkStats{
		EventsWritten: s.eventsWritten.Load(),
		Dropped:       s.dropped.Load(),
		Errors:        s.errors.Load(),
	}
}

func (s *FileSink) Write(event plugin.ThreatEvent) error {
	var line []byte
	switch s.format {
	case "json":
		b, err := output.FormatJSON(event)
		if err != nil {
			s.errors.Add(1)
			return fmt.Errorf("file sink %s: json marshal: %w", s.path, err)
		}
		line = append(b, '\n')
	case "sentinel-threat":
		b, err := output.FormatSentinelThreat(event, "")
		if err != nil {
			s.errors.Add(1)
			return fmt.Errorf("file sink %s: sentinel-threat marshal: %w", s.path, err)
		}
		line = append(b, '\n')
	default:
		line = []byte(output.FormatFailban(event) + "\n")
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

func openSinkFile(path string) (*os.File, error) {
	if err := ensureSinkDir(path); err != nil {
		return nil, err
	}
	return os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
}

func ensureSinkDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "" || dir == "." {
		return nil
	}
	return os.MkdirAll(dir, 0755)
}