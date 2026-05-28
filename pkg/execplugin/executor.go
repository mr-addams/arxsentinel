// ========================== pkg/execplugin — ExecExecutor ================================
//   Executor that delegates enforcement actions to an external plugin process.
//
//   WHAT IS HERE:
//     - ExecExecutor — implements plugin.Executor using subprocess communication
//     - Serialization of ExecuteRequest and deserialization of ExecuteResponse
//
//   WHAT IS NOT HERE:
//     - ManagedProcess lifecycle (process.go)
//     - Protocol message types (protocol.go)

package execplugin

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

// ExecExecutor implements plugin.Executor by communicating with an external
// plugin process via NDJSON over stdin/stdout.
//
// Each Execute() call is mutex-serialized to ensure correct request/response
// ordering. Multiple goroutines calling Execute() on the same instance will
// be serialized (one at a time).
//
// If the plugin crashes or stdout closes unexpectedly, Execute() returns an error
// and increments the Errors counter.
type ExecExecutor struct {
	name     string
	proc     *ManagedProcess
	mu       sync.Mutex
	executed atomic.Int64
	errors   atomic.Int64
}

// NewExecutor spawns the plugin binary at execPath and returns an ExecExecutor.
// The subprocess is started immediately and kept alive for all Execute() calls.
//
// name is the executor identifier returned by Name().
// params is passed to the plugin as ARXSENTINEL_PLUGIN_PARAMS environment variable
// (JSON-encoded). If params is empty or nil, the environment variable is not set.
//
// Returns an error if the binary is not executable or cannot be started.
func NewExecutor(name, execPath string, params map[string]interface{}) (*ExecExecutor, error) {
	proc, err := NewManagedProcess(context.Background(), execPath)
	if err != nil {
		return nil, fmt.Errorf("failed to spawn executor plugin %q at %s: %w", name, execPath, err)
	}
	return &ExecExecutor{
		name: name,
		proc: proc,
	}, nil
}

// Name returns the executor name as registered in the plugin registry.
func (e *ExecExecutor) Name() string {
	return e.name
}

// Execute sends an ExecuteRequest to the plugin and reads back an ExecuteResponse.
// The request/response cycle is mutex-serialized for thread safety.
//
// Returns an error if:
//   - JSON marshaling fails
//   - Send/Recv fails (plugin crash, stdin/stdout closed)
//   - Response parsing fails
//   - Response has non-empty Error field
//
// On success, increments the Executed counter. On any error, increments Errors.
// Skipped events (e.g., below min_level) are not counted here — the pipeline
// handles that logic; Execute is only called for events that should be acted upon.
func (e *ExecExecutor) Execute(ctx context.Context, event plugin.ThreatEvent) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Build the request
	req := ExecuteRequest{
		V:      ProtoVersion,
		Action: "execute",
		Event:  threatEventToJSON(event),
	}

	// Marshal to JSON
	reqData, err := json.Marshal(req)
	if err != nil {
		e.errors.Add(1)
		return fmt.Errorf("[%s] Failed to marshal ExecuteRequest: %w", e.name, err)
	}

	// Send the request
	if err := e.proc.Send(reqData); err != nil {
		e.errors.Add(1)
		fmt.Fprintf(os.Stderr, "[%s] Failed to send request: %v\n", e.name, err)
		return fmt.Errorf("[%s] Failed to send request: %w", e.name, err)
	}

	// Receive the response
	respData, err := e.proc.Recv()
	if err != nil {
		e.errors.Add(1)
		fmt.Fprintf(os.Stderr, "[%s] Failed to receive response: %v\n", e.name, err)
		return fmt.Errorf("[%s] Failed to receive response: %w", e.name, err)
	}

	// Parse the response
	resp, err := ParseExecuteResponse(respData)
	if err != nil {
		e.errors.Add(1)
		fmt.Fprintf(os.Stderr, "[%s] Failed to parse ExecuteResponse: %v\n", e.name, err)
		return fmt.Errorf("[%s] Failed to parse ExecuteResponse: %w", e.name, err)
	}

	// Check for explicit plugin error — non-empty Error field means the action failed.
	if resp.Error != "" {
		e.errors.Add(1)
		return fmt.Errorf("[%s] Plugin returned error: %s", e.name, resp.Error)
	}

	// Success
	e.executed.Add(1)
	return nil
}

// Close shuts down the plugin subprocess gracefully.
func (e *ExecExecutor) Close() error {
	return e.proc.Close()
}

// Stats returns operational counters for this executor.
func (e *ExecExecutor) Stats() plugin.ExecutorStats {
	return plugin.ExecutorStats{
		Executed: e.executed.Load(),
		Skipped:  0, // Skipped is pipeline-level; Execute is only called for actionable events.
		Errors:   e.errors.Load(),
	}
}
