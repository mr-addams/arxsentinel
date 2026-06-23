// ========================== pkg/source/file — FileSource =====================================
//   Reads access log lines from a file using tail-like following.
//   Parses each line with a Parser and sends *plugin.Event to the pipeline.
//   Supports log rotation via inotify (TailReader).
//
//   WHAT IS HERE:
//     FileSource — plugin.Source implementation that tails a file
//     NewFileSource — constructor
//
//   WHAT IS NOT HERE:
//     manifest.go — PluginID, Role, DataType declarations
//     arx-core/pkg/tail — platform-specific file tailing (inotify/FSEvents)
//
//   Phase 2.2 (Flow 083 / RESOLVED-Q9): the source emits *plugin.Event with
//   the parser-owned LogEntry as Payload (built via WrapLogEntry). Envelope
//   fields Source / SourceType / Stream / Timestamp are filled by the source;
//   Level is left empty (scorer fills later).

package file

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/mr-addams/arx-core/pkg/parser"
	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/mr-addams/arx-core/pkg/tail"
	pkgsource "github.com/mr-addams/arx-core/pkg/source"
)

// nopLogFn is a no-op logFn implementation per the
// pkg/source.registry.BuildOptions.LogFn contract: nil → no-op.
func nopLogFn(tag, msg, level string) {}

// defaultLinesBufSize is the channel buffer between tail goroutine and parser.
const defaultLinesBufSize = 1000

// FileSource tails a log file and delivers parsed *plugin.Event values
// (carrying parser.LogEntry as Payload).
type FileSource struct {
	name          string
	path          string
	parser        parser.Parser
	retryInterval time.Duration
	logFn         func(tag, msg, level string)

	linesRead   atomic.Int64
	parseErrors atomic.Int64
	dropped     atomic.Int64
}

// NewFileSource creates a new file source.
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
func (s *FileSource) Name() string { return s.name }

// Close releases resources.
func (s *FileSource) Close() error { return nil }

// Stats returns operational counters.
func (s *FileSource) Stats() plugin.SourceStats {
	return plugin.SourceStats{
		LinesRead:   s.linesRead.Load(),
		ParseErrors: s.parseErrors.Load(),
		Dropped:     s.dropped.Load(),
	}
}

// Run starts tailing the file and sends parsed events to out.
// Blocking — runs until ctx is cancelled.
func (s *FileSource) Run(ctx context.Context, out chan<- *plugin.Event) error {
	lines := make(chan string, defaultLinesBufSize)
	reader := tail.NewTailReader(s.path, lines, s.retryInterval, s.logFn)
	go reader.Run(ctx)

	for line := range lines {
		s.linesRead.Add(1)
		entry, ok := s.parser.Parse(line)
		if !ok {
			s.parseErrors.Add(1)
			s.logFn("PARSER", fmt.Sprintf("file source %s: skipping malformed line: %.80s", s.path, line), "debug")
			continue
		}
		ev := parser.WrapLogEntry(entry, plugin.Envelope{
			Source:     s.name,
			SourceType: "file",
			Stream:     "", // engine fills Stream from EventContext
			Timestamp:  entry.Time,
			Level:      "", // scorer fills later
		})
		select {
		case out <- ev:
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