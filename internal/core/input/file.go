// ========================== Module input/file ==========================================
//   FileSource — reads a log file via inotify (TailReader) and delivers
//   parsed *plugin.LogEntry values to the pipeline.
//
//   WHAT IS HERE:
//     - FileSource — wraps TailReader + Parser; implements plugin.Source
//
//   WHAT IS NOT HERE:
//     - Low-level file watching and logrotate handling (internal/sys/utils.TailReader)
//     - Parsing logic (internal/core/parser/)
//     - Merge fan-in (merge.go)
//
//   DEPENDENCY NOTE:
//     FileSource imports internal/sys/utils for TailReader — the file-watching
//     component lives there for backward compat until Task 5 wires the new pipeline.
//     There is no import cycle: utils does not import any internal/core package.

package input

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/mr-addams/arxsentinel/internal/core/parser"
	"github.com/mr-addams/arxsentinel/internal/sys/utils"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
	pkgsource "github.com/mr-addams/arxsentinel/pkg/source"
)

// defaultLinesBufSize — internal TailReader channel buffer.
// Sized to absorb short bursts between TailReader and FileSource.Run().
const defaultLinesBufSize = 1000

// FileSource reads a log file via TailReader and delivers parsed *LogEntry values.
// Supports logrotate (both mv and copytruncate) transparently via TailReader.
//
// Each FileSource owns its parser — different files in a stream can use different
// formats (D1 in DECISIONS.md).
type FileSource struct {
	name          string // "file:/path/to/access.log"
	path          string
	par           parser.Parser
	retryInterval time.Duration
	logFn         func(tag, msg, level string) // nil-safe; defaults to utils.Log

	// stats counters — updated atomically during Run().
	linesRead   atomic.Int64
	parseErrors atomic.Int64
	dropped     atomic.Int64
}

// NewFileSource creates a FileSource for the given path.
// retryInterval — how long to wait between retries when the file is unavailable
// (pass cfg.General.TailRetryInterval or use 5 * time.Second as default).
// logFn — log function; pass nil to use utils.Log.
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
		lf = utils.Log
	}
	return &FileSource{
		name:          "file:" + path,
		path:          path,
		par:           p,
		retryInterval: retryInterval,
		logFn:         lf,
	}, nil
}

func (s *FileSource) Name() string { return s.name }

// Close is a no-op for FileSource — TailReader is lifecycle-bound to Run().
// Present to satisfy plugin.Source interface; future versions may hold external resources.
func (s *FileSource) Close() error { return nil }

// Stats returns a point-in-time snapshot of operational counters.
func (s *FileSource) Stats() plugin.SourceStats {
	return plugin.SourceStats{
		LinesRead:   s.linesRead.Load(),
		ParseErrors: s.parseErrors.Load(),
		Dropped:     s.dropped.Load(),
	}
}

// Run starts the TailReader and delivers parsed entries to out.
// Blocks until ctx is cancelled. Does not close out — Merge() owns the channel.
// Drop policy (D3): non-blocking send; full buffer increments Dropped counter.
func (s *FileSource) Run(ctx context.Context, out chan<- *plugin.LogEntry) error {
	lines := make(chan string, defaultLinesBufSize)
	tail := utils.NewTailReader(s.path, lines, s.retryInterval)
	go tail.Run(ctx)

	for line := range lines {
		s.linesRead.Add(1)
		entry, ok := s.par.Parse(line)
		if !ok {
			s.parseErrors.Add(1)
			s.logFn("PARSER", fmt.Sprintf("file source %s: skipping malformed line: %.80s", s.path, line), "debug")
			continue
		}
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
}
