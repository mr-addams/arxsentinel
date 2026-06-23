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
	"time"

	"github.com/mr-addams/arx-core/pkg/parser"
	"github.com/mr-addams/arx-core/pkg/plugin"
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
// ExecSource creates a fresh ManagedProcess on each Run() — allows clean restart.
type ExecSource struct {
	execPath  string       // Internal — plugin binary path. Consumer: Run
	linesRead atomic.Int64 // Internal — lines successfully parsed. Consumer: Stats
	parseErrs atomic.Int64 // Internal — JSON parse failures. Consumer: Stats
	dropped   atomic.Int64 // Internal — entries dropped due to full output channel. Consumer: Stats (H2)
}

// NewSource creates an ExecSource.
// The subprocess is NOT started until Run() is called.
// This defers process startup to the pipeline startup sequence.
// Called from: pipeline.newSource. Non-blocking.
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
// Called from: pipeline.runSource (logging). Non-blocking.
func (s *ExecSource) Name() string {
	return fmt.Sprintf("exec:%s", s.execPath)
}

// Run starts the subprocess, sends {"v":"1","action":"start"} to stdin,
// then reads SourceEntry JSON lines from stdout in a loop.
// Each parsed LogEntry is sent to out channel (non-blocking).
// When ctx is cancelled, sends {"v":"1","action":"stop"} to stdin and exits.
// Closes the subprocess via proc.Close() on return.
// Does NOT close the out channel (contract: Source must not close out).
// Called from: pipeline.runSource.
//
// Blocking — runs until ctx cancellation or plugin error.
//
// Phase 2.2 (Flow 083): the source-emitter channel now carries generic
// *plugin.Event. We wrap each LogEntry into an Event with a transport
// Envelope before forwarding. Source is the remote peer (as parsed by the
// plugin); SourceType identifies the exec-plugin transport; Stream is empty
// (pipeline stream is assigned downstream); Timestamp is the parsed request
// time.
func (s *ExecSource) Run(ctx context.Context, out chan<- *plugin.Event) error {
	// Create the ManagedProcess for this Run() session
	proc, err := NewManagedProcess(ctx, s.execPath)
	if err != nil {
		return fmt.Errorf("exec source %q: start plugin: %w", s.execPath, err)
	}
	defer proc.Close()

	// Устанавливаем таймаут на чтение строк из stdout плагина (H2, L1).
	// Если плагин завис и не отправляет данные дольше 30s, Recv() вернёт
	// timeout error, что приведёт к пересозданию процесса при следующем Run().
	proc.SetReadTimeout(30 * time.Second)

	// Send start signal
	startMsg, _ := json.Marshal(StartRequest{V: ProtoVersion, Action: "start"})
	if err := proc.Send(startMsg); err != nil {
		return fmt.Errorf("exec source %q: send start: %w", s.execPath, err)
	}

	// Channel for forwarding entries from read goroutine.
	// Larger buffer to ensure entries are delivered even if main loop is slow.
	// WHY 256: accommodates burst parsing during initial sync while staying bounded.
	entries := make(chan *plugin.Event, 256)
	readErr := make(chan error, 2)

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
			// Wrap into a generic *plugin.Event for the runtime contract.
			event := parser.WrapLogEntry(entry, plugin.Envelope{
				Source:     entry.RemoteAddr,
				SourceType: "exec",
				Timestamp:  entry.Time,
			})
			// Non-blocking send: if entries buffer is full (slow main loop),
			// drop entry instead of blocking. Blocking send would stall proc.Recv()
			// → plugin blocks on stdout write → whole pipeline deadlock.
			// Monitor drop rate: Stats().Dropped / Stats().LinesRead ratio.
			select {
			case entries <- event:
			default:
				s.dropped.Add(1)
			}
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

		case event, ok := <-entries:
			if !ok {
				// Plugin exited cleanly (read goroutine closed entries channel)
				return nil
			}

			// Non-blocking send to out channel
			select {
			case out <- event:
				// Successfully sent

			case <-ctx.Done():
				// Context cancelled during send — send stop signal and exit
				stopMsg, _ := json.Marshal(StopRequest{V: ProtoVersion, Action: "stop"})
				_ = proc.Send(stopMsg)
				return nil

			default:
				// out channel is full — drop entry (non-blocking send policy)
				s.dropped.Add(1)
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
		Dropped:     s.dropped.Load(),
	}
}

// Manifest returns the plugin identity and data contract.
func (s *ExecSource) Manifest() plugin.Manifest {
	return plugin.Manifest{
		PluginID:      "exec",
		PluginVersion: "1.0.0",
		Role:          plugin.RoleSource,
		InputType:     plugin.TypeNone,
		OutputType:    plugin.TypeStructured,
		Tags:          []string{"exec", "external-plugin", "ndjson"},
	}
}
