package file

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

const defaultLinesBufSize = 1000

type FileSource struct {
	name          string
	path          string
	par           parser.Parser
	retryInterval time.Duration
	logFn         func(tag, msg, level string)

	linesRead   atomic.Int64
	parseErrors atomic.Int64
	dropped     atomic.Int64
}

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

func (s *FileSource) Close() error { return nil }

func (s *FileSource) Stats() plugin.SourceStats {
	return plugin.SourceStats{
		LinesRead:   s.linesRead.Load(),
		ParseErrors: s.parseErrors.Load(),
		Dropped:     s.dropped.Load(),
	}
}

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