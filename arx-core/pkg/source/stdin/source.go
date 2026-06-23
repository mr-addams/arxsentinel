// ========================== Module pkg/source/stdin =======================================
//   StdinSource — reads log lines from os.Stdin and delivers parsed *plugin.Event
//   values to the pipeline. Designed for container / pipe mode:
//     docker logs nginx | arxsentinel --input=stdin
//
//   Phase 2.2 (Flow 083 / RESOLVED-Q9): emits *plugin.Event with the parser-
//   owned LogEntry as Payload (built via WrapLogEntry).

package stdin

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"sync/atomic"

	"github.com/mr-addams/arx-core/pkg/parser"
	"github.com/mr-addams/arx-core/pkg/plugin"
	pkgsource "github.com/mr-addams/arx-core/pkg/source"
)

func nopLogFn(tag, msg, level string) {}

const stdinScanBufSize = 64 * 1024 // 64 KB

const defaultLinesBufSize = 1000

// StdinSource reads log lines from os.Stdin (or any io.Reader) and delivers
// parsed *plugin.Event values to the pipeline.
//
// Run completes on EOF or ctx cancellation — whichever comes first.
type StdinSource struct {
	name   string
	parser parser.Parser
	logFn  func(tag, msg, level string)
	r      io.Reader

	linesRead   atomic.Int64
	parseErrors atomic.Int64
	dropped     atomic.Int64
}

// NewStdinSource creates a StdinSource reading from os.Stdin.
func NewStdinSource(p parser.Parser, logFn func(tag, msg, level string)) *StdinSource {
	return NewStdinSourceWithReader(os.Stdin, p, logFn)
}

// NewStdinSourceWithReader creates a StdinSource reading from r.
// Used in tests to inject a custom reader without touching os.Stdin.
func NewStdinSourceWithReader(r io.Reader, p parser.Parser, logFn func(tag, msg, level string)) *StdinSource {
	lf := logFn
	if lf == nil {
		lf = nopLogFn
	}
	return &StdinSource{
		name:   "stdin",
		parser: p,
		logFn:  lf,
		r:      r,
	}
}

func (s *StdinSource) Name() string { return s.name }

func (s *StdinSource) Close() error { return nil }

func (s *StdinSource) Stats() plugin.SourceStats {
	return plugin.SourceStats{
		LinesRead:   s.linesRead.Load(),
		ParseErrors: s.parseErrors.Load(),
		Dropped:     s.dropped.Load(),
	}
}

// Run reads lines from stdin until EOF or ctx is cancelled.
func (s *StdinSource) Run(ctx context.Context, out chan<- *plugin.Event) error {
	scanner := bufio.NewScanner(s.r)
	scanner.Buffer(make([]byte, stdinScanBufSize), stdinScanBufSize)

	scanCh := make(chan string, defaultLinesBufSize)
	errCh := make(chan error, 1)

	go func() {
		for scanner.Scan() {
			scanCh <- scanner.Text()
		}
		if err := scanner.Err(); err != nil {
			errCh <- err
		}
		close(scanCh)
	}()

	for {
		select {
		case <-ctx.Done():
			if f, ok := s.r.(*os.File); ok {
				_ = f.Close()
			}
			return nil

		case line, ok := <-scanCh:
			if !ok {
				return nil
			}
			s.linesRead.Add(1)
			entry, parsed := s.parser.Parse(line)
			if !parsed {
				s.parseErrors.Add(1)
				s.logFn("PARSER", fmt.Sprintf("stdin source: skipping malformed line: %.80s", line), "debug")
				continue
			}
			ev := parser.WrapLogEntry(entry, plugin.Envelope{
				Source:     "stdin",
				SourceType: "stdin",
				Stream:     "",
				Timestamp:  entry.Time,
				Level:      "",
			})
			select {
			case out <- ev:
			default:
				s.dropped.Add(1)
			}

		case err := <-errCh:
			s.logFn("STDIN", fmt.Sprintf("stdin source: scanner error: %v", err), "error")
			return err
		}
	}
}

func init() {
	pkgsource.Register("stdin", func(cfg pkgsource.InputConfig, opts pkgsource.BuildOptions) (plugin.Source, error) {
		return NewStdinSource(opts.Parser, opts.LogFn), nil
	})
	pkgsource.RegisterManifest("stdin", (&StdinSource{}).Manifest())
}