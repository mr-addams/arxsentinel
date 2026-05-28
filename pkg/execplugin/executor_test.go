package execplugin

import (
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

// TestExecExecutor_Name tests that Name() returns the executor's registered name.
func TestExecExecutor_Name(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	testdataDir := filepath.Join(filepath.Dir(filename), "testdata")
	scriptPath := filepath.Join(testdataDir, "executor.sh")

	executor, err := NewExecutor("my-executor", scriptPath, nil)
	if err != nil {
		t.Fatalf("NewExecutor failed: %v", err)
	}
	defer executor.Close()

	if name := executor.Name(); name != "my-executor" {
		t.Errorf("Name() = %q, want %q", name, "my-executor")
	}
}

// TestExecExecutor_Execute_success tests the happy path: sending a ThreatEvent
// to the executor plugin and receiving an ok response.
func TestExecExecutor_Execute_success(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	testdataDir := filepath.Join(filepath.Dir(filename), "testdata")
	scriptPath := filepath.Join(testdataDir, "executor.sh")

	executor, err := NewExecutor("test-executor", scriptPath, nil)
	if err != nil {
		t.Fatalf("NewExecutor failed: %v", err)
	}
	defer executor.Close()

	// Create a test ThreatEvent
	event := plugin.ThreatEvent{
		Timestamp:  time.Now(),
		Level:      "THREAT",
		Stream:     "main",
		Source:     "file:/var/log/nginx/access.log",
		SourceType: "file",
		IP:         "10.0.0.1",
		Score:      200,
		Modules:    []string{"probe", "rate"},
		Reason:     "probe:admin:5,rate:300rps",
		RawLine:    "",
	}

	// Call Execute
	err = executor.Execute(nil, event)
	if err != nil {
		t.Errorf("Execute() failed: %v", err)
	}

	// Check stats
	stats := executor.Stats()
	if stats.Executed != 1 {
		t.Errorf("Stats().Executed = %d, want 1", stats.Executed)
	}
	if stats.Errors != 0 {
		t.Errorf("Stats().Errors = %d, want 0", stats.Errors)
	}
}

// TestExecExecutor_InvalidExec tests that NewExecutor fails with a nonexistent binary.
func TestExecExecutor_InvalidExec(t *testing.T) {
	_, err := NewExecutor("broken", "/nonexistent-binary-xyz-definitely-not-found", nil)
	if err == nil {
		t.Errorf("NewExecutor with nonexistent binary should return error, got nil")
	}
}
