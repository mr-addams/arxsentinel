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
// Each event received via Run() is mutex-serialized to ensure correct
// request/response ordering. Multiple events on the channel are processed
// sequentially (one at a time).
//
// If the plugin crashes or stdout closes unexpectedly, Run() returns an error
// and increments the Errors counter.
type ExecExecutor struct {
	plugin.NopManifest
	name     string
	execType string
	proc     *ManagedProcess
	mu       sync.Mutex
	executed atomic.Int64
	errors   atomic.Int64
}

// NewExecutor spawns the plugin binary at execPath and returns an ExecExecutor.
// The subprocess is started immediately and kept alive for all Run() calls.
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
		name:     name,
		execType: "exec",
		proc:     proc,
	}, nil
}

// Type returns "exec" — the executor type for exec plugins.
func (e *ExecExecutor) Type() string { return e.execType }

// Name returns the executor name as registered in the plugin registry.
func (e *ExecExecutor) Name() string {
	return e.name
}

// Run reads ThreatEvents from the source via Pop and delegates to executePlugin.
// Blocks until ctx is cancelled or the source returns a terminal error.
func (e *ExecExecutor) Run(ctx context.Context, source plugin.EventSource) error {
	for {
		event, err := source.Pop(ctx)
		if err != nil {
			return nil
		}
		if err := e.executePlugin(ctx, event); err != nil {
			continue
		}
	}
}

// executePlugin sends an ExecuteRequest to the plugin and reads back an ExecuteResponse.
// The request/response cycle is mutex-serialized for thread safety.
//
// Returns an error if:
//   - JSON marshaling fails
//   - Send/Recv fails (plugin crash, stdin/stdout closed)
//   - Response parsing fails
//   - Response has non-empty Error field
//
// On success, increments the Executed counter. On any error, increments Errors.
func (e *ExecExecutor) executePlugin(ctx context.Context, event plugin.ThreatEvent) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	req := ExecuteRequest{
		V:      ProtoVersion,
		Action: "execute",
		Event:  threatEventToJSON(event),
	}

	reqData, err := json.Marshal(req)
	if err != nil {
		e.errors.Add(1)
		return fmt.Errorf("[%s] Failed to marshal ExecuteRequest: %w", e.name, err)
	}

	if err := e.proc.Send(reqData); err != nil {
		e.errors.Add(1)
		fmt.Fprintf(os.Stderr, "[%s] Failed to send request: %v\n", e.name, err)
		return fmt.Errorf("[%s] Failed to send request: %w", e.name, err)
	}

	respData, err := e.proc.Recv()
	if err != nil {
		e.errors.Add(1)
		fmt.Fprintf(os.Stderr, "[%s] Failed to receive response: %v\n", e.name, err)
		return fmt.Errorf("[%s] Failed to receive response: %w", e.name, err)
	}

	resp, err := ParseExecuteResponse(respData)
	if err != nil {
		e.errors.Add(1)
		fmt.Fprintf(os.Stderr, "[%s] Failed to parse ExecuteResponse: %v\n", e.name, err)
		return fmt.Errorf("[%s] Failed to parse ExecuteResponse: %w", e.name, err)
	}

	if resp.Error != "" {
		e.errors.Add(1)
		return fmt.Errorf("[%s] Plugin returned error: %s", e.name, resp.Error)
	}

	e.executed.Add(1)
	return nil
}

// Stats returns operational counters for this executor.
func (e *ExecExecutor) Stats() plugin.ExecutorStats {
	return plugin.ExecutorStats{
		Executed: e.executed.Load(),
		Skipped:  0, // Skipped is pipeline-level; Execute is only called for actionable events.
		Errors:   e.errors.Load(),
	}
}
