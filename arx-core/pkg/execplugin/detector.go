// ========================== pkg/execplugin — ExecDetector ===============================
//   Detector that delegates detection logic to an external plugin process.
//
//   WHAT IS HERE:
//     - ExecDetector — implements plugin.Detector using subprocess communication
//     - Serialization of DetectRequest and deserialization of DetectResponse
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

	"github.com/mr-addams/arx-core/pkg/parser"
	"github.com/mr-addams/arx-core/pkg/plugin"
)

// ExecDetector implements plugin.Detector by communicating with an external
// plugin process via NDJSON over stdin/stdout.
//
// Each Detect() call is mutex-serialized to ensure correct request/response
// ordering. Multiple goroutines calling Detect() on the same instance will
// be serialized (one at a time).
//
// If the plugin crashes or stdout closes unexpectedly, Detect() returns a
// zero DetectResult without panicking. The error is logged to stderr.
type ExecDetector struct {
	name string
	proc *ManagedProcess
	mu   sync.Mutex // serializes Detect() calls
}

// NewDetector spawns the plugin binary at execPath and returns an ExecDetector.
// The subprocess is started immediately and kept alive for all Detect() calls.
//
// name is the detector identifier returned by Name().
// params is passed to the plugin as ARXSENTINEL_PLUGIN_PARAMS environment variable
// (JSON-encoded). If params is empty or nil, the environment variable is not set.
// ctx controls the subprocess lifecycle: when ctx is cancelled, the process is killed.
//
// Returns an error if the binary is not executable or cannot be started.
// Called from: pipeline.newDetector.
//
// Blocking — NewManagedProcess is called synchronously.
func NewDetector(name, execPath string, params map[string]interface{}, ctx context.Context) (*ExecDetector, error) {
	proc, err := NewManagedProcess(ctx, execPath)
	if err != nil {
		return nil, fmt.Errorf("failed to spawn detector plugin %q at %s: %w", name, execPath, err)
	}

	return &ExecDetector{
		name: name,
		proc: proc,
	}, nil
}

// Name returns the detector name as registered in the plugin registry.
// Called from: pipeline.processEntries (logging). Non-blocking.
func (d *ExecDetector) Name() string {
	return d.name
}

// Manifest returns the plugin's identity and data contract.
// Called from: pipeline (debug logging). Non-blocking.
func (d *ExecDetector) Manifest() plugin.Manifest {
	return plugin.Manifest{
		Role:       plugin.RoleDetector,
		InputType:  plugin.TypeStructured,
		OutputType: plugin.TypeStructured,
		Tags:       []string{"exec", "external-plugin", "ndjson"},
	}
}

// Detect sends a DetectRequest to the plugin and reads back a DetectResponse.
// The request/response cycle is mutex-serialized for thread safety.
//
// Returns a zero DetectResult on transport or parse error. Errors are logged
// to stderr but do not cause a panic.
// Called from: pipeline.processEntries.
//
// Non-blocking.
//
// Phase 2.2 (Flow 083): the Detector contract now takes *plugin.Event.
// We unwrap the *parser.LogEntry payload here before sending it to the
// external plugin (wire format is unchanged — still LogEntryJSON).
func (d *ExecDetector) Detect(sv plugin.IPView, event *plugin.Event) plugin.DetectResult {
	d.mu.Lock()
	defer d.mu.Unlock()

	entry := parser.UnwrapLogEntry(event)

	// Build the request
	req := DetectRequest{
		V:      ProtoVersion,
		Action: "detect",
		Entry:  logEntryToJSON(entry),
		State:  ipViewToJSON(sv),
	}

	// Marshal to JSON
	reqData, err := json.Marshal(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] Failed to marshal DetectRequest: %v\n", d.name, err)
		return plugin.DetectResult{}
	}

	// Send the request
	if err := d.proc.Send(reqData); err != nil {
		fmt.Fprintf(os.Stderr, "[%s] Failed to send request: %v\n", d.name, err)
		return plugin.DetectResult{}
	}

	// Receive the response
	respData, err := d.proc.Recv()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] Failed to receive response: %v\n", d.name, err)
		return plugin.DetectResult{}
	}

	// Parse the response
	resp, err := ParseDetectResponse(respData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] Failed to parse DetectResponse: %v\n", d.name, err)
		return plugin.DetectResult{}
	}

	// Convert to plugin.DetectResult
	return plugin.DetectResult{
		Score:  resp.Score,
		Module: resp.Module,
		Reason: resp.Reason,
	}
}

// Close shuts down the plugin subprocess gracefully.
func (d *ExecDetector) Close() error {
	return d.proc.Close()
}
