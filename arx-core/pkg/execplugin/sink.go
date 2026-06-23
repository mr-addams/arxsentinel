// ========================== pkg/execplugin — ExecSink ================================
//   Sink that delegates threat event delivery to an external plugin process.
//
//   WHAT IS HERE:
//     - ExecSink — implements plugin.Sink using subprocess communication
//     - Fire-and-forget Write (ack optional, not validated)
//
//   WHAT IS NOT HERE:
//     - ManagedProcess lifecycle (process.go)
//     - Protocol message types (protocol.go)

package execplugin

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"

	"github.com/mr-addams/arx-core/pkg/plugin"
)

// ExecSink implements plugin.Sink by communicating with an external
// plugin process via NDJSON over stdin/stdout.
//
// Write() sends a WriteRequest to the plugin's stdin and does NOT wait
// for WriteAck (fire-and-forget). This simplifies the protocol and allows
// the plugin to process events asynchronously.
//
// Concurrent Write() calls are protected by a mutex on the ManagedProcess.
//
// ExecSink holds a persistent ManagedProcess — recreated only on Close+reopen.
type ExecSink struct {
	name          string          // Internal — sink identifier. Consumer: Name
	proc          *ManagedProcess // Internal — plugin subprocess. Consumer: Write, Close
	eventsWritten atomic.Int64    // Internal — successful writes. Consumer: Stats
	errors        atomic.Int64    // Internal — write failures. Consumer: Stats
}

// NewSink spawns the plugin binary at execPath and returns an ExecSink.
// The subprocess is started immediately and kept alive for all Write() calls.
//
// ctx is passed to NewManagedProcess — если ctx отменён (SIGHUP/SIGTERM) ДО
// того, как subprocess стартовал, спавн прерывается. Это устраняет класс
// багов, когда exec-бинарник висит в init-фазе и блокирует весь pipeline
// на старте, пока daemon не убьёт его по таймауту.
//
// execPath is the path to the plugin binary.
// Returns an error if the binary is not executable or cannot be started.
// Called from: pkg/sink/exec/register.go (factory) → Build(ctx, cfg).
//
// Blocking — NewManagedProcess is called synchronously.
func NewSink(ctx context.Context, execPath string) (*ExecSink, error) {
	proc, err := NewManagedProcess(ctx, execPath)
	if err != nil {
		return nil, fmt.Errorf("failed to spawn sink plugin at %s: %w", execPath, err)
	}

	return &ExecSink{
		name: fmt.Sprintf("exec:%s", execPath),
		proc: proc,
	}, nil
}

// Name returns the sink name, prefixed with "exec:".
// Called from: pipeline.runSink (logging). Non-blocking.
func (s *ExecSink) Name() string {
	return s.name
}

// Write serializes the threat event as a WriteRequest and sends it to the plugin stdin.
// The write is fire-and-forget: no ReadAck is expected (ack is optional in the protocol).
//
// If the write fails, the error counter is incremented and an error is returned.
// If the write succeeds, the events counter is incremented.
// Called from: pipeline.runSink.
//
// Non-blocking.
//
// ctx is accepted to satisfy the plugin.Sink interface but is intentionally
// not propagated: ManagedProcess.Send is a non-blocking stdin write and does
// not accept a context today. Plumbed through the interface for forward
// compatibility (cancellable in-flight send).
//
// Gate B (Flow 083 / Task 3.3 / RESOLVED-D): the Sink contract now carries
// generic *plugin.Event. Core no longer type-asserts Event.Payload — wire
// conversion goes through threatEventToJSON which round-trips the opaque
// payload (encoding/json field-name parity preserves byte-identical output
// when the payload is a *threat.ThreatEvent).
func (s *ExecSink) Write(ctx context.Context, event *plugin.Event) error {
	s.proc.Lock()
	defer s.proc.Unlock()

	threatJSON, err := threatEventToJSON(event)
	if err != nil {
		s.errors.Add(1)
		return fmt.Errorf("%w", err)
	}

	// Build the request
	req := WriteRequest{
		V:      ProtoVersion,
		Action: "write",
		Event:  threatJSON,
	}

	// Marshal to JSON
	reqData, err := json.Marshal(req)
	if err != nil {
		s.errors.Add(1)
		return fmt.Errorf("failed to marshal WriteRequest: %w", err)
	}

	// Send the request (fire-and-forget, no ack wait)
	if err := s.proc.Send(reqData); err != nil {
		s.errors.Add(1)
		return fmt.Errorf("failed to send WriteRequest: %w", err)
	}

	// Increment success counter
	s.eventsWritten.Add(1)
	return nil
}

// Close shuts down the plugin subprocess gracefully.
func (s *ExecSink) Close() error {
	return s.proc.Close()
}

// Stats returns operational counters for this sink.
func (s *ExecSink) Stats() plugin.SinkStats {
	return plugin.SinkStats{
		EventsWritten: s.eventsWritten.Load(),
		Dropped:       0, // Phase 1 doesn't have async buffering
		Errors:        s.errors.Load(),
	}
}

func (s *ExecSink) Manifest() plugin.Manifest {
	return plugin.Manifest{
		PluginID:      "exec",
		PluginVersion: "1.0.0",
		Role:          plugin.RoleSink,
		InputType:     plugin.TypeScoredEvent,
		OutputType:    plugin.TypeNone,
		Tags:          []string{"exec", "external", "plugin"},
	}
}
