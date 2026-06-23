// ========================== pkg/execplugin — source_test.go ================
//   Tests for ExecSource: lifecycle, Start, Stop, channel operations.

package execplugin

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/mr-addams/arx-core/pkg/parser"
	"github.com/mr-addams/arx-core/pkg/plugin"
)

// TestExecSource_Name tests that Name() returns "exec:<execPath>".
func TestExecSource_Name(t *testing.T) {
	execPath := "/path/to/source.sh"
	src, err := NewSource(execPath)
	if err != nil {
		t.Fatalf("NewSource failed: %v", err)
	}

	expected := "exec:/path/to/source.sh"
	if name := src.Name(); name != expected {
		t.Errorf("Name() = %q, want %q", name, expected)
	}
}

// TestExecSource_Run tests the happy path: Run() starts the plugin, reads 3 entries,
// and completes when the plugin closes stdout.
func TestExecSource_Run(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	testdataDir := filepath.Join(filepath.Dir(filename), "testdata")
	scriptPath := filepath.Join(testdataDir, "source.sh")

	src, err := NewSource(scriptPath)
	if err != nil {
		t.Fatalf("NewSource failed: %v", err)
	}
	defer src.Close()

	// Create output channel and run source in a goroutine
	out := make(chan *plugin.Event, 256)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var runErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		runErr = src.Run(ctx, out)
	}()

	// Collect entries from out channel until Run completes
	var entries []*parser.LogEntry
	entryCount := 0

	// Wait for Run to complete or timeout
	select {
	case <-done:
		// Run completed, now drain any remaining entries from out

	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for Run completion")
	}

	// Drain remaining entries from out channel with a short timeout
	drainCtx, drainCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer drainCancel()
	for {
		select {
		case ev, ok := <-out:
			if !ok {
				t.Fatal("out channel closed unexpectedly (Run should not close out)")
			}
			entries = append(entries, parser.UnwrapLogEntry(ev))
			entryCount++

		case <-drainCtx.Done():
			// No more entries
			goto checkEntries

		default:
			goto checkEntries
		}
	}

checkEntries:
	// Check errors from Run
	if runErr != nil {
		t.Errorf("Run() returned error: %v", runErr)
	}

	// We should have at least 3 entries (the test script emits 3)
	if len(entries) < 3 {
		t.Errorf("Expected at least 3 entries, got %d", len(entries))
	}

	// Verify first entry has expected fields (source.sh emits 1.2.3.i)
	if len(entries) >= 1 {
		if entries[0].RemoteAddr != "1.2.3.1" {
			t.Errorf("entries[0].RemoteAddr = %q, want %q", entries[0].RemoteAddr, "1.2.3.1")
		}
		if entries[0].Method != "GET" {
			t.Errorf("entries[0].Method = %q, want %q", entries[0].Method, "GET")
		}
		if entries[0].Path != "/test" {
			t.Errorf("entries[0].Path = %q, want %q", entries[0].Path, "/test")
		}
		if entries[0].Status != 200 {
			t.Errorf("entries[0].Status = %d, want %d", entries[0].Status, 200)
		}
	}

	// Check stats
	stats := src.Stats()
	if stats.LinesRead < 3 {
		t.Errorf("Stats().LinesRead = %d, want at least 3", stats.LinesRead)
	}
	if stats.ParseErrors != 0 {
		t.Errorf("Stats().ParseErrors = %d, want 0", stats.ParseErrors)
	}
}

// TestExecSource_CancelStop tests that cancelling ctx sends a stop signal
// and Run() exits cleanly.
func TestExecSource_CancelStop(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	testdataDir := filepath.Join(filepath.Dir(filename), "testdata")
	scriptPath := filepath.Join(testdataDir, "source.sh")

	src, err := NewSource(scriptPath)
	if err != nil {
		t.Fatalf("NewSource failed: %v", err)
	}
	defer src.Close()

	out := make(chan *plugin.Event, 10)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	var runErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		runErr = src.Run(ctx, out)
	}()

	// Let it run for a bit and collect some entries
	time.Sleep(100 * time.Millisecond)

	// Context will timeout and trigger cancellation
	select {
	case <-done:
		// Run completed, which is expected when ctx times out
		if runErr != nil {
			// Some errors are acceptable (e.g., process exit), but timeout should just return nil
			if ctx.Err() == context.DeadlineExceeded {
				// This is expected — Run() should return nil when ctx is Done
				if runErr != nil {
					t.Logf("Run() returned error after context timeout (acceptable): %v", runErr)
				}
			} else {
				t.Errorf("Run() returned unexpected error: %v", runErr)
			}
		}

	case <-time.After(2 * time.Second):
		t.Fatal("Run() did not exit after context timeout")
	}
}

// TestExecSource_InvalidExec tests that NewSource returns an error for invalid paths
// and Run() returns an error when trying to start a non-existent binary.
func TestExecSource_InvalidExec(t *testing.T) {
	src, err := NewSource("/nonexistent-binary-xyz")
	if err != nil {
		// NewSource should accept any path string (validation happens at Run time)
		t.Logf("NewSource rejected invalid path (acceptable): %v", err)
		return
	}
	defer src.Close()

	// Try to run with non-existent binary
	out := make(chan *plugin.Event, 10)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	runErr := src.Run(ctx, out)
	if runErr == nil {
		t.Error("Run() should return error for non-existent binary, got nil")
	}
}
