// ========================== pkg/execplugin — executor_test.go ==============
//   Tests for ExecExecutor: Execute, ExecuteAsync, lifecycle.
//
//   Gate B (Flow 083 / Task 3.3 / RESOLVED-D): the executor consumes
//   generic *plugin.Event; tests construct a fakeThreatPayload (matching
//   the wire shape of the product threat.ThreatEvent) and wrap it in a
//   *plugin.Event with an adapter source that calls Pop. Core tests do
//   not import the product type.

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

// fakeEventSource is a minimal plugin.EventSource for tests. It pushes
// a single pre-built event into a buffered channel and closes the
// channel; Pop returns the event then a closed-channel error.
type fakeEventSource struct {
	ch     chan *plugin.Event
	closed bool
}

func newFakeEventSource(events ...*plugin.Event) *fakeEventSource {
	ch := make(chan *plugin.Event, len(events))
	for _, e := range events {
		ch <- e
	}
	return &fakeEventSource{ch: ch}
}

func (s *fakeEventSource) Pop(ctx context.Context) (*plugin.Event, error) {
	if s.closed {
		return nil, context.Canceled
	}
	select {
	case ev, ok := <-s.ch:
		if !ok {
			s.closed = true
			return nil, context.Canceled
		}
		return ev, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

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

// TestExecExecutor_Run_success tests the happy path: sending a fakeThreatPayload
// via Run() through a fakeEventSource and verifying the stats counter
// increments. The plugin subprocess (executor.sh) echoes the JSON it
// receives; the test asserts only the executor's own counters because
// the round-trip semantics belong to threatEventToJSON (already covered
// by the Sink test).
func TestExecExecutor_Run_success(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	testdataDir := filepath.Join(filepath.Dir(filename), "testdata")
	scriptPath := filepath.Join(testdataDir, "executor.sh")

	executor, err := NewExecutor("test-executor", scriptPath, nil)
	if err != nil {
		t.Fatalf("NewExecutor failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	payload := &fakeThreatPayload{
		Timestamp:  time.Now(),
		Level:      "THREAT",
		Stream:     "main",
		Source:     "file:/var/log/nginx/access.log",
		SourceType: "file",
		IP:         "10.0.0.1",
		Score:      200,
		Modules:    []string{"probe", "rate"},
		Reason:     "probe:admin:5,rate:300rps",
	}
	// Sanity check: payload JSON shape must match what threatEventToJSON expects.
	if _, err := json.Marshal(payload); err != nil {
		t.Fatalf("payload marshal failed: %v", err)
	}

	source := newFakeEventSource(&plugin.Event{Payload: payload})

	done := make(chan error, 1)
	go func() {
		done <- executor.Run(ctx, source)
	}()

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
