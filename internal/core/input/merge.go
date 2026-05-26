// ========================== Module input/merge ==========================================
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
	"sync"

	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

// Merge runs each Source in its own goroutine and fan-ins their output into
// a single bounded channel. The channel is closed when all Sources have
// returned (either ctx cancelled or unrecoverable error in a Source).
//
// bufSize must be > 0; callers should use pipeline.buffer_size from config (D4).
// Sources that fill the buffer have their entries dropped — see DROP POLICY above.
func Merge(ctx context.Context, sources []plugin.Source, bufSize int) <-chan *plugin.LogEntry {
	out := make(chan *plugin.LogEntry, bufSize)

	var wg sync.WaitGroup
	for _, src := range sources {
		src := src
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Run blocks until ctx is Done or unrecoverable error.
			// Errors are logged by the Source itself; Merge does not surface them.
			_ = src.Run(ctx, out)
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
