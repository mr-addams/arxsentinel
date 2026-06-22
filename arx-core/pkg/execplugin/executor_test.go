// ========================== pkg/execplugin — executor_test.go ==============
//   Tests for ExecExecutor: Execute, ExecuteAsync, lifecycle.

package execplugin

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/mr-addams/arx-core/pkg/executor/queue"
	"github.com/mr-addams/arx-core/pkg/plugin"
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
	if name := executor.Name(); name != "my-executor" {
		t.Errorf("Name() = %q, want %q", name, "my-executor")
	}
}

// TestExecExecutor_Run_success tests the happy path: sending a ThreatEvent via Run()
// and verifying the stats counter increments.
func TestExecExecutor_Run_success(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	testdataDir := filepath.Join(filepath.Dir(filename), "testdata")
	scriptPath := filepath.Join(testdataDir, "executor.sh")

	executor, err := NewExecutor("test-executor", scriptPath, nil)
	if err != nil {
		t.Fatalf("NewExecutor failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	q := queue.NewMemoryQueue(10)

	done := make(chan error, 1)
	go func() {
		done <- executor.Run(ctx, q)
	}()

	_ = q.Push(ctx, plugin.ThreatEvent{
		Timestamp:  time.Now(),
		Level:      "THREAT",
		Stream:     "main",
		Source:     "file:/var/log/nginx/access.log",
		SourceType: "file",
		IP:         "10.0.0.1",
		Score:      200,
		Modules:    []string{"probe", "rate"},
		Reason:     "probe:admin:5,rate:300rps",
	})

	// Give Run() time to process the event before checking stats.
	time.Sleep(100 * time.Millisecond)

	stats := executor.Stats()
	if stats.Executed != 1 {
		t.Errorf("Stats().Executed = %d, want 1", stats.Executed)
	}
	if stats.Errors != 0 {
		t.Errorf("Stats().Errors = %d, want 0", stats.Errors)
	}

	cancel()
	<-done
}

// TestExecExecutor_InvalidExec tests that NewExecutor fails with a nonexistent binary.
func TestExecExecutor_InvalidExec(t *testing.T) {
	_, err := NewExecutor("broken", "/nonexistent-binary-xyz-definitely-not-found", nil)
	if err == nil {
		t.Errorf("NewExecutor with nonexistent binary should return error, got nil")
	}
}
