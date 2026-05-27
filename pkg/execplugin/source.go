// ========================== pkg/execplugin — ExecSource ===============================
//   Source that streams log entries from an external plugin process.
//
//   WHAT IS HERE:
//     - ExecSource — implements plugin.Source using subprocess communication
//     - Start/stop control signals, line-by-line SourceEntry reading
//
//   WHAT IS NOT HERE:
//     - ManagedProcess lifecycle (process.go)
//     - Protocol message types (protocol.go)
//
//   DESIGN NOTE:
//     ExecSource does NOT own a persistent ManagedProcess. Instead, it creates
//     one each time Run() is called. This allows the source to be stopped and
//     restarted cleanly. ManagedProcess lifetime = Run() lifetime.

package execplugin

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

// ExecSource implements plugin.Source by streaming log entries from an external
// plugin process via NDJSON over stdin/stdout.
//
// The subprocess is NOT started until Run() is called. This defers process startup
// to the pipeline startup sequence, allowing clean restart semantics.
//
// Run() sends {"v":"1","action":"start"} to the plugin stdin, then reads SourceEntry
// lines from stdout in a loop. When ctx is cancelled, it sends {"v":"1","action":"stop"}
// and exits gracefully.
type ExecSource struct {
	execPath  string
	linesRead atomic.Int64
	parseErrs atomic.Int64
}

// NewSource creates an ExecSource.
// The subprocess is NOT started until Run() is called.
// This defers process startup to the pipeline startup sequence.
func NewSource(execPath string) (*ExecSource, error) {
	// Validate that execPath is non-empty
	if execPath == "" {
		return nil, fmt.Errorf("exec source: execPath cannot be empty")
	}

	return &ExecSource{
		execPath: execPath,
	}, nil
}

// Name returns "exec:<execPath>".
func (s *ExecSource) Name() string {
	return fmt.Sprintf("exec:%s", s.execPath)
}

// Run starts the subprocess, sends {"v":"1","action":"start"} to stdin,
// then reads SourceEntry JSON lines from stdout in a loop.
// Each parsed LogEntry is sent to out channel (non-blocking).
// When ctx is cancelled, sends {"v":"1","action":"stop"} to stdin and exits.
// Closes the subprocess via proc.Close() on return.
// Does NOT close the out channel (contract: Source must not close out).
func (s *ExecSource) Run(ctx context.Context, out chan<- *plugin.LogEntry) error {
	// Create the ManagedProcess for this Run() session
	proc, err := NewManagedProcess(context.Background(), s.execPath)
	if err != nil {
		return fmt.Errorf("exec source %q: start plugin: %w", s.execPath, err)
	}
	defer proc.Close()

	// Send start signal
	startMsg, _ := json.Marshal(StartRequest{V: ProtoVersion, Action: "start"})
	if err := proc.Send(startMsg); err != nil {
		return fmt.Errorf("exec source %q: send start: %w", s.execPath, err)
	}

	// Channel for forwarding entries from read goroutine.
	// Larger buffer to ensure entries are delivered even if main loop is slow.
	entries := make(chan *plugin.LogEntry, 256)
	readErr := make(chan error, 1)

	// Goroutine reads stdout and sends entries to internal channel
	go func() {
		defer close(entries)
		for {
			line, err := proc.Recv()
			if err != nil {
				// EOF is normal — just return without error.
				// Other errors (broken pipe, scanner error) should be reported.
				if !strings.Contains(err.Error(), "EOF") {
					readErr <- err
				}
				return
			}

			var se SourceEntry
			if jerr := json.Unmarshal(line, &se); jerr != nil {
				s.parseErrs.Add(1)
				continue
			}

			entry := logEntryFromJSON(se.Entry)
			s.linesRead.Add(1)
			entries <- entry
		}
	}()

	// Main loop: forward entries and handle context cancellation
	for {
		select {
		case <-ctx.Done():
			// Context cancelled — send stop signal (best-effort)
			stopMsg, _ := json.Marshal(StopRequest{V: ProtoVersion, Action: "stop"})
			_ = proc.Send(stopMsg)
			return nil

		case entry, ok := <-entries:
			if !ok {
				// Plugin exited cleanly (read goroutine closed entries channel)
				return nil
			}

			// Non-blocking send to out channel
			select {
			case out <- entry:
				// Successfully sent

			case <-ctx.Done():
				// Context cancelled during send — send stop signal and exit
				stopMsg, _ := json.Marshal(StopRequest{V: ProtoVersion, Action: "stop"})
				_ = proc.Send(stopMsg)
				return nil

			default:
				// out channel is full — drop entry (non-blocking send policy)
				// Note: dropped counter is not incremented in Phase 1
			}

		case err := <-readErr:
			// Plugin read error
			if ctx.Err() != nil {
				// Context was already cancelled — clean shutdown
				return nil
			}
			return err
		}
	}
}

// Close stops the subprocess if it's running.
// Since ExecSource creates the subprocess in Run(), Close() is a no-op
// (subprocess is already cleaned up in Run's defer).
func (s *ExecSource) Close() error {
	// No persistent process to close — cleanup happens in Run()'s defer
	return nil
}

// Stats returns cumulative counters.
func (s *ExecSource) Stats() plugin.SourceStats {
	return plugin.SourceStats{
		LinesRead:   s.linesRead.Load(),
		ParseErrors: s.parseErrs.Load(),
		Dropped:     0, // Phase 1 doesn't track drops
	}
}
