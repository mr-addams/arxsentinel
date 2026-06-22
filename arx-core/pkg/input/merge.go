// ========================== Module pkg/input/merge ==========================================
//   Fan-in merger: runs multiple Sources concurrently and multiplexes their
//   output into a single bounded channel consumed by the pipeline.
//
//   WHAT IS HERE:
//     - Merge — starts each Source in its own goroutine, closes out when all done
//
//   WHAT IS NOT HERE:
//     - Source implementations (file.go, stdin.go)
//     - Pipeline processing (cmd/arxsentinel/main.go)
//
//   DROP POLICY (D3):
//     Non-blocking send — full buffer drops the newest entry and increments
//     the Source's Dropped counter. Already-buffered entries are preserved.
//     Use pipeline.buffer_size to tune; monitor arxsentinel_input_dropped_total.

package input

import (
	"context"
	"fmt"
	"sync"

	"github.com/mr-addams/arx-core/pkg/plugin"
)

// LogFn is a callback for structured logging from Merge.
// tag identifies the component, msg is the log message, level is one of
// "error", "warn", "info", "debug".
type LogFn func(tag, msg, level string)

// Merge fans-in multiple Sources into a single output channel.
// Runs each Source in its own goroutine, closes out when all done.
// Non-blocking — drops newest entry if buffer is full.
//
//   Called from: arx-core/pkg/runtime (engine.go), cmd/arxsentinel/pipeline.go.
// Blocking: waits for all sources to finish before closing the channel.
func Merge(ctx context.Context, sources []plugin.Source, bufSize int, logFn LogFn) <-chan *plugin.LogEntry {
	out := make(chan *plugin.LogEntry, bufSize)

	var wg sync.WaitGroup
	for _, src := range sources {
		src := src
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Panic recovery (C4): if a Source panics, recover and log instead of
			// crashing the entire pipeline.
			defer func() {
				if r := recover(); r != nil {
					if logFn != nil {
						logFn("merge", fmt.Sprintf("source panic recovered: %v", r), "error")
					}
				}
			}()
			// Run blocks until ctx is Done or unrecoverable error.
			// Log errors that the Source itself did not handle (M2).
			if err := src.Run(ctx, out); err != nil && logFn != nil {
				logFn("merge", fmt.Sprintf("source Run error: %v", err), "error")
			}
		}()
	}

	// Close out only after all Sources have stopped writing.
	// The pipeline's drain loop reads until !ok — this guarantees no entries are lost.
	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}
