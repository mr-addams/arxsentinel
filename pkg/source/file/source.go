// ========================== pkg/source/file — FileSource =====================================
//   Reads access log lines from a file using tail-like following.
//   Parses each line with a Parser, sends *plugin.LogEntry to the pipeline.
//   Supports log rotation via inotify (TailReader).
//
//   WHAT IS HERE:
//     FileSource — plugin.Source implementation that tails a file
//     NewFileSource — constructor
//
//   WHAT IS NOT HERE:
//     manifest.go — PluginID, Role, DataType declarations
//     internal/sys/utils/tail.go — platform-specific file tailing (inotify/FSEvents)
//
//   NOTE: pkg/source/file still imports internal/sys/utils for utils.NewTailReader
//   (Run(), line below). Removing this import is deferred to Phase 1.3 (Tail
//   Abstraction) — see Flow 072 DECISIONS.md Scope.

package file

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/mr-addams/arxsentinel/pkg/parser"
	// TODO(Phase 1.3 — Tail Abstraction): pkg/source/file still imports
	// internal/sys/utils for utils.NewTailReader (see Run()). Dropping this
	// import is the subject of a separate flow (Phase 1.3). Flow 072 only
	// removes the utils.Log fallback; it does not touch this import.
	"github.com/mr-addams/arxsentinel/internal/sys/utils"
	"github.com/mr-addams/arx-core/pkg/plugin"
	pkgsource "github.com/mr-addams/arxsentinel/pkg/source"
)

// nopLogFn is a no-op logFn implementation per the
// pkg/source.registry.BuildOptions.LogFn contract: nil → no-op.
// Replaces the legacy implicit fallback to internal/sys/utils.Log
// (Flow 072 Task 1.2.5). The BuildOptions.LogFn type itself stays
// `func(tag, msg, level string)` until Phase 1.4 — see
// .opencode/flows/072/DECISIONS.md Decision 7.
func nopLogFn(tag, msg, level string) {}

// defaultLinesBufSize is the channel buffer between tail goroutine and parser.
// Non-blocking send with drop policy: if buffer is full, entries are dropped
// and Dropped counter is incremented. Larger buffer = less drops, more memory.
const defaultLinesBufSize = 1000

// FileSource tails a log file and delivers parsed LogEntry records.
type FileSource struct {
	name          string
	path          string
	parser        parser.Parser // parses raw log lines into *plugin.LogEntry
	retryInterval time.Duration // delay between retry attempts on file errors
	logFn         func(tag, msg, level string)

	linesRead   atomic.Int64 // total lines received from the file
	parseErrors atomic.Int64 // lines that failed to parse
	dropped     atomic.Int64 // lines dropped due to full channel buffer
}

// NewFileSource creates a new file source.
// Called from: pkg/source registry (init() → Build).
// Non-blocking — returns immediately with a configured instance or error.
func NewFileSource(path string, p parser.Parser, retryInterval time.Duration, logFn func(tag, msg, level string)) (*FileSource, error) {
	if path == "" {
		return nil, fmt.Errorf("file source: path must not be empty")
	}
	if p == nil {
		return nil, fmt.Errorf("file source %s: parser must not be nil", path)
	}
	if retryInterval <= 0 {
		retryInterval = 5 * time.Second
	}
	lf := logFn
	if lf == nil {
		lf = nopLogFn
	}
	return &FileSource{
		name:          "file:" + path,
		path:          path,
		parser:        p,
		retryInterval: retryInterval,
		logFn:         lf,
	}, nil
}

// Name returns the source identifier.
// Called from: pipeline (logging, metrics).
func (s *FileSource) Name() string { return s.name }

// Close releases resources.
// Called from: pipeline shutdown. FileSource is stateless — nothing to close.
func (s *FileSource) Close() error { return nil }

// Stats returns operational counters.
// Called from: pipeline (STATS log, Prometheus metrics).
func (s *FileSource) Stats() plugin.SourceStats {
	return plugin.SourceStats{
		LinesRead:   s.linesRead.Load(),
		ParseErrors: s.parseErrors.Load(),
		Dropped:     s.dropped.Load(),
	}
}

// Run starts tailing the file and sends parsed entries to out.
// Called from: pipeline goroutine.
// Blocking — runs until ctx is cancelled.
func (s *FileSource) Run(ctx context.Context, out chan<- *plugin.LogEntry) error {
	lines := make(chan string, defaultLinesBufSize)
	tail := utils.NewTailReader(s.path, lines, s.retryInterval)
	go tail.Run(ctx)

	for line := range lines {
		s.linesRead.Add(1)
		entry, ok := s.parser.Parse(line)
		if !ok {
			s.parseErrors.Add(1)
			s.logFn("PARSER", fmt.Sprintf("file source %s: skipping malformed line: %.80s", s.path, line), "debug")
			continue
		}
		// Non-blocking send: drop if pipeline is slow. D3 threshold protects memory.
		select {
		case out <- entry:
		default:
			s.dropped.Add(1)
		}
	}
	return nil
}

func init() {
	pkgsource.Register("file", func(cfg pkgsource.InputConfig, opts pkgsource.BuildOptions) (plugin.Source, error) {
		return NewFileSource(cfg.Path, opts.Parser, opts.RetryInterval, opts.LogFn)
	})
	pkgsource.RegisterManifest("file", (&FileSource{}).Manifest())
}
