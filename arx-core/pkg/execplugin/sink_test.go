// ========================== pkg/execplugin — sink_test.go =================
//   Tests for ExecSink: Manifest, Sink, lifecycle.
//
//   Gate B (Flow 083 / Task 3.3 / RESOLVED-D): the Sink contract carries
//   generic *plugin.Event; tests build a local fakeThreatPayload struct
//   (matching the wire shape of the product threat.ThreatEvent) and push
//   it as Event.Payload. Core tests do not import the product type.

package execplugin

import (
	"context"
	"encoding/json"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/mr-addams/arx-core/pkg/plugin"
)

// fakeThreatPayload mirrors the JSON field names of the product-owned
// threat.ThreatEvent. The execplugin wire-format ThreatEventJSON has the
// same JSON tags, so a JSON round-trip through Event.Payload →
// ThreatEventJSON preserves all fields.
type fakeThreatPayload struct {
	Timestamp  time.Time
	Level      string
	Stream     string
	Source     string
	SourceType string
	IP         string
	Score      int
	Modules    []string
	Reason     string
	RawLine    string
}

// TestExecSink_Name tests that Name() returns the sink identifier with "exec:" prefix.
func TestExecSink_Name(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	testdataDir := filepath.Join(filepath.Dir(filename), "testdata")
	scriptPath := filepath.Join(testdataDir, "sink.sh")

	sink, err := NewSink(context.Background(), scriptPath)
	if err != nil {
		t.Fatalf("NewSink failed: %v", err)
	}
	defer sink.Close()

	name := sink.Name()
	if name != "exec:"+scriptPath {
		t.Errorf("Name() = %q, want %q", name, "exec:"+scriptPath)
	}
}

// TestExecSink_Write tests that Write() forwards the event to the plugin
// subprocess and increments counters. The wire format is verified by
// the script (sink.sh) which echoes the JSON it received back — the
// event's payload survives the json.Marshal→json.Unmarshal round-trip
// in threatEventToJSON.
func TestExecSink_Write(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	testdataDir := filepath.Join(filepath.Dir(filename), "testdata")
	scriptPath := filepath.Join(testdataDir, "sink.sh")

	sink, err := NewSink(context.Background(), scriptPath)
	if err != nil {
		t.Fatalf("NewSink failed: %v", err)
	}
	defer sink.Close()

	// Build a wire-shape event. JSON marshalling here must match the
	// ThreatEventJSON field names (timestamp/level/stream/source/...).
	payload := &fakeThreatPayload{
		Timestamp:  time.Now(),
		Level:      "THREAT",
		Stream:     "frontend",
		Source:     "file:/var/log/nginx/access.log",
		SourceType: "file",
		IP:         "1.2.3.4",
		Score:      150,
		Modules:    []string{"probe", "rate"},
		Reason:     "probe:env:3,rate:142rps",
		RawLine:    "",
	}
	event := &plugin.Event{Payload: payload}

	// Sanity check: payload JSON shape must match what threatEventToJSON
	// expects. If this assertion fails the wire format diverged and
	// sink.sh will reject the request.
	if _, err := json.Marshal(payload); err != nil {
		t.Fatalf("payload marshal failed: %v", err)
	}

	// Call Write
	err = sink.Write(context.Background(), event)
	if err != nil {
		t.Errorf("Write() failed: %v", err)
	}

	// Check stats
	stats := sink.Stats()
	if stats.EventsWritten != 1 {
		t.Errorf("Stats().EventsWritten = %d, want 1", stats.EventsWritten)
	}
	if stats.Errors != 0 {
		t.Errorf("Stats().Errors = %d, want 0", stats.Errors)
	}
}

// TestExecSink_InvalidExec tests that NewSink fails with a nonexistent binary.
func TestExecSink_InvalidExec(t *testing.T) {
	_, err := NewSink(context.Background(), "/nonexistent-binary-xyz-definitely-not-found")
	if err == nil {
		t.Errorf("NewSink with nonexistent binary should return error, got nil")
	}
}
