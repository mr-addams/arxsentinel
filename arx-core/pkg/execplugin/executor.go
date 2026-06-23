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

	"github.com/mr-addams/arx-core/pkg/plugin"
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
// ExecExecutor holds a persistent ManagedProcess — recreated only on Close+reopen.
type ExecExecutor struct {
	name     string          // YAML: executors[i].name — executor identifier. Consumer: Name, executePlugin
	execType string          // YAML: — executor type, always "exec". Consumer: Type
	proc     *ManagedProcess // Internal — plugin subprocess. Consumer: executePlugin
	mu       sync.Mutex      // Internal — serializes request/response. Consumer: executePlugin
	executed atomic.Int64    // Internal — successful executions. Consumer: Stats
	errors   atomic.Int64    // Internal — failures. Consumer: Stats
}

// NewExecutor spawns the plugin binary at execPath and returns an ExecExecutor.
// The subprocess is started immediately and kept alive for all Run() calls.
// Called from: pipeline.newExecutor. Blocking — NewManagedProcess is called synchronously.
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
// Called from: pipeline.newExecutor. Non-blocking.
func (e *ExecExecutor) Type() string { return e.execType }

// Name returns the executor name as registered in the plugin registry.
// Called from: pipeline (logging). Non-blocking.
func (e *ExecExecutor) Name() string {
	return e.name
}

// Manifest returns the plugin's identity and data contract.
// Called from: pipeline (debug logging). Non-blocking.
func (e *ExecExecutor) Manifest() plugin.Manifest {
	return plugin.Manifest{
		Role:       plugin.RoleExecutor,
		InputType:  plugin.TypeScoredEvent,
		OutputType: plugin.TypeNone,
		Tags:       []string{"exec", "external-plugin", "ndjson"},
	}
}

// Run reads Events from the source via Pop and delegates to executePlugin.
// Blocks until ctx is cancelled or the source returns a terminal error.
// Called from: pipeline.runExecutor.
//
// Blocking — runs until ctx cancellation or source error.
//
// Gate B (Flow 083 / Task 3.3 / RESOLVED-D): the source delivers generic
// *plugin.Event. The executor forwards the event directly to executePlugin
// which round-trips it through threatEventToJSON to the wire-format. Core
// no longer type-asserts Event.Payload — the executor treats the payload
// as opaque and the wire-format conversion is owned by threatEventToJSON
// (encoding/json field-name parity preserves byte-identical output).
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
//   - threatEventToJSON fails (marshal/unmarshal into ThreatEventJSON)
//   - JSON marshaling fails
//   - Send/Recv fails (plugin crash, stdin/stdout closed)
//   - Response parsing fails
//   - Response has non-empty Error field
//
// On success, increments the Executed counter. On any error, increments Errors.
// Called from: Run.
//
// Non-blocking.
//
// Gate B (Flow 083 / Task 3.3 / RESOLVED-D): executePlugin now takes the
// generic *plugin.Event (not a concrete ThreatEvent). Wire conversion goes
// through threatEventToJSON which round-trips the opaque payload — core
// has no type-assert and no knowledge of the product ThreatEvent.
func (e *ExecExecutor) executePlugin(ctx context.Context, event *plugin.Event) error {
	if event == nil {
		e.errors.Add(1)
		return fmt.Errorf("[%s] executePlugin: nil event", e.name)
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	threatJSON, err := threatEventToJSON(event)
	if err != nil {
		e.errors.Add(1)
		return fmt.Errorf("[%s] %w", e.name, err)
	}

	req := ExecuteRequest{
		V:      ProtoVersion,
		Action: "execute",
		Event:  threatJSON,
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
