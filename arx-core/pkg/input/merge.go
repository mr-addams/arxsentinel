// ========================== Module pkg/input/merge ==========================================
//   Fan-in merger: runs multiple Sources concurrently and multiplexes their
//   output into a single bounded channel consumed by the pipeline.
//
//   WHAT IS HERE:
//     - Merge — starts each Source in its own goroutine, closes out when all done
//
//   WHAT IS NOT HERE:
//     - Source implementations (file.go, stdin.go)
//     - Pipeline processing (engine in pkg/runtime)
//
//   DROP POLICY (D3):
//     Non-blocking send — full buffer drops the newest entry and increments
//     the Source's Dropped counter. Already-buffered entries are preserved.
//     Use pipeline.buffer_size to tune; monitor arxsentinel_input_dropped_total.
//
//   Phase 2.2 (Flow 083 / RESOLVED-Q9): merge fan-in carries the generic
//   *plugin.Event. Concrete payload-shape concerns live with each Source.

package input

import (
	"context"
	"fmt"
	"sync"

	"github.com/mr-addams/arx-core/pkg/plugin"
)

// LogFn is a callback for structured logging from Merge.
type LogFn func(tag, msg, level string)

// Merge fans-in multiple Sources into a single output channel.
// Runs each Source in its own goroutine, closes out when all done.
// Non-blocking — drops newest entry if buffer is full.
//
//   Called from: arx-core/pkg/runtime (engine.go), cmd/arxsentinel/pipeline.go.
// Blocking: waits for all sources to finish before closing the channel.
func Merge(ctx context.Context, sources []plugin.Source, bufSize int, logFn LogFn) <-chan *plugin.Event {
	out := make(chan *plugin.Event, bufSize)

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
			if err := src.Run(ctx, out); err != nil && logFn != nil {
				logFn("merge", fmt.Sprintf("source Run error: %v", err), "error")
			}
		}()
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}