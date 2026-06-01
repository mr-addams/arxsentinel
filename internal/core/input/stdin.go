// ========================== Module input/stdin =========================================
//   StdinSource — reads log lines from os.Stdin and delivers parsed *plugin.LogEntry
//   values to the pipeline. Designed for container / pipe mode:
//     docker logs nginx | arxsentinel --input=stdin
//
//   WHAT IS HERE:
//     - StdinSource — bufio.Scanner over os.Stdin; implements plugin.Source
//
//   WHAT IS NOT HERE:
//     - File input (file.go)
//     - Parsing logic (internal/core/parser/)

package input

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"sync/atomic"

	"github.com/mr-addams/arxsentinel/internal/core/parser"
	"github.com/mr-addams/arxsentinel/internal/sys/utils"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
	pkgsource "github.com/mr-addams/arxsentinel/pkg/source"
)

// stdinScanBufSize — scanner buffer for stdin lines.
// Matches maxLineSize in TailReader — both must handle the same maximum line length.
const stdinScanBufSize = 64 * 1024 // 64 KB

// StdinSource reads log lines from os.Stdin (or any io.Reader) and delivers
// parsed *LogEntry values to the pipeline.
//
// Run completes on EOF or ctx cancellation — whichever comes first.
// In container / pipe mode EOF is the normal termination signal.
type StdinSource struct {
	plugin.NopManifest
	name  string
	par   parser.Parser
	logFn func(tag, msg, level string) // nil-safe; defaults to utils.Log
	r     io.Reader                    // injectable for tests; os.Stdin in production

	linesRead   atomic.Int64
	parseErrors atomic.Int64
	dropped     atomic.Int64
}

// NewStdinSource creates a StdinSource reading from os.Stdin.
// logFn — log function; pass nil to use utils.Log.
func NewStdinSource(p parser.Parser, logFn func(tag, msg, level string)) *StdinSource {
	return NewStdinSourceWithReader(os.Stdin, p, logFn)
}

// NewStdinSourceWithReader creates a StdinSource reading from r.
// Used in tests to inject a custom reader without touching os.Stdin.
func NewStdinSourceWithReader(r io.Reader, p parser.Parser, logFn func(tag, msg, level string)) *StdinSource {
	lf := logFn
	if lf == nil {
		lf = utils.Log
	}
	return &StdinSource{
		name:  "stdin",
		par:   p,
		logFn: lf,
		r:     r,
	}
}

func (s *StdinSource) Name() string { return s.name }

// Close is a no-op — os.Stdin is not owned by StdinSource.
func (s *StdinSource) Close() error { return nil }

// Stats returns a point-in-time snapshot of operational counters.
func (s *StdinSource) Stats() plugin.SourceStats {
	return plugin.SourceStats{
		LinesRead:   s.linesRead.Load(),
		ParseErrors: s.parseErrors.Load(),
		Dropped:     s.dropped.Load(),
	}
}

// Run reads lines from stdin until EOF or ctx is cancelled.
// EOF is a normal exit condition (pipe closed by the upstream producer).
// Drop policy (D3): non-blocking send; full buffer increments Dropped counter.
func (s *StdinSource) Run(ctx context.Context, out chan<- *plugin.LogEntry) error {
	scanner := bufio.NewScanner(s.r)
	scanner.Buffer(make([]byte, stdinScanBufSize), stdinScanBufSize)

	scanCh := make(chan string, defaultLinesBufSize)
	errCh := make(chan error, 1)

	// Scanner is blocking — run it in a goroutine so we can also select on ctx.Done().
	// On ctx cancellation we close os.Stdin to unblock the scanner goroutine.
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
			// Unblock the scanner goroutine by closing stdin.
			// Safe to call even if the goroutine already exited.
			if f, ok := s.r.(*os.File); ok {
				_ = f.Close()
			}
			return nil

		case line, ok := <-scanCh:
			if !ok {
				// EOF — drain complete, normal exit.
				return nil
			}
			s.linesRead.Add(1)
			entry, parsed := s.par.Parse(line)
			if !parsed {
				s.parseErrors.Add(1)
				s.logFn("PARSER", fmt.Sprintf("stdin source: skipping malformed line: %.80s", line), "debug")
				continue
			}
			select {
			case out <- entry:
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
}
