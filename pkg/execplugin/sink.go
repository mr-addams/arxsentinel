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

	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

// ExecSink implements plugin.Sink by communicating with an external
// plugin process via NDJSON over stdin/stdout.
//
// Write() sends a WriteRequest to the plugin's stdin and does NOT wait
// for WriteAck (fire-and-forget). This simplifies the protocol and allows
// the plugin to process events asynchronously.
//
// Concurrent Write() calls are protected by a mutex on the ManagedProcess.
	// ExecSink holds a persistent ManagedProcess — recreated only on Close+reopen.
	type ExecSink struct {
		name          string            // Internal — sink identifier. Consumer: Name
		proc          *ManagedProcess  // Internal — plugin subprocess. Consumer: Write, Close
		eventsWritten atomic.Int64     // Internal — successful writes. Consumer: Stats
		errors        atomic.Int64     // Internal — write failures. Consumer: Stats
	}

// NewSink spawns the plugin binary at execPath and returns an ExecSink.
// The subprocess is started immediately and kept alive for all Write() calls.
//
// name is the sink identifier returned by Name().
// params is passed to the plugin as ARXSENTINEL_PLUGIN_PARAMS environment variable
// (JSON-encoded). If params is empty or nil, the environment variable is not set.
//
// Returns an error if the binary is not executable or cannot be started.
// Called from: pipeline.newSink.
//
// Blocking — NewManagedProcess is called synchronously.
func NewSink(execPath string) (*ExecSink, error) {
	proc, err := NewManagedProcess(context.Background(), execPath)
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
func (s *ExecSink) Write(event plugin.ThreatEvent) error {
	s.proc.Lock()
	defer s.proc.Unlock()

	// Build the request
	req := WriteRequest{
		V:      ProtoVersion,
		Action: "write",
		Event:  threatEventToJSON(event),
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
