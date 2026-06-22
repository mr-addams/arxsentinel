// ========================== pkg/execplugin — sink_test.go =================
//   Tests for ExecSink: Manifest, Sink, lifecycle.

package execplugin

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/mr-addams/arx-core/pkg/plugin"
)

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

// TestExecSink_Write tests that Write() sends a ThreatEvent to the plugin and increments counters.
func TestExecSink_Write(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	testdataDir := filepath.Join(filepath.Dir(filename), "testdata")
	scriptPath := filepath.Join(testdataDir, "sink.sh")

	sink, err := NewSink(context.Background(), scriptPath)
	if err != nil {
		t.Fatalf("NewSink failed: %v", err)
	}
	defer sink.Close()

	// Create a test ThreatEvent
	event := plugin.ThreatEvent{
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
