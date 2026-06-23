// ========================== pkg/executor/queue — queue_test.go ============
//   Tests for Queue: buffering, ordering, worker pool, shutdown.
//
//   Gate B (Flow 083 / Task 3.3 / RESOLVED-D): queue payloads are opaque
//   bytes; tests construct a local fixture struct (jsonFields) and marshal
//   it to []byte before Push, mirroring what product-side Formatters do.
//   Core tests do not import the product threat.ThreatEvent (boundary
//   invariant).

package queue_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/mr-addams/arx-core/pkg/executor/queue"
)

// jsonFields is a local test fixture that JSON-round-trips into the same
// shape product-side Formatter impls emit. The queue does not inspect the
// bytes; tests only assert that Push/Pop preserve the payload verbatim.
type jsonFields struct {
	IP    string `json:"ip"`
	Level string `json:"level"`
	Score int    `json:"score"`
}

// mustMarshal is a test helper that fatals on JSON errors — production code
// never panics on JSON but tests can rely on deterministic fixtures.
func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("test fixture marshal: %v", err)
	}
	return b
}

func TestMemoryQueue_PushPop(t *testing.T) {
	q := queue.NewMemoryQueue(10)
	ctx := context.Background()
	payload := mustMarshal(t, jsonFields{IP: "1.2.3.4", Level: "THREAT"})

	if err := q.Push(ctx, payload); err != nil {
		t.Fatalf("Push error = %v, want nil", err)
	}
	if q.Len() != 1 {
		t.Fatalf("Len = %d, want 1", q.Len())
	}

	got, err := q.Pop(ctx)
	if err != nil {
		t.Fatalf("Pop error = %v, want nil", err)
	}
	// Round-trip back into the fixture to assert payload preservation.
	var decoded jsonFields
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("Pop returned non-JSON payload: %v (bytes: %q)", err, got)
	}
	if decoded.IP != "1.2.3.4" || decoded.Level != "THREAT" {
		t.Errorf("Pop got %+v, want IP=1.2.3.4 Level=THREAT", decoded)
	}
	if q.Len() != 0 {
		t.Errorf("Len after Pop = %d, want 0", q.Len())
	}
}

func TestMemoryQueue_PopBlocks(t *testing.T) {
	q := queue.NewMemoryQueue(1)
	ctx := context.Background()

	done := make(chan struct{})
	go func() {
		_, err := q.Pop(ctx)
		if err != nil {
			t.Errorf("Pop error = %v", err)
		}
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("Pop returned before Push")
	case <-time.After(500 * time.Millisecond):
	}

	payload := mustMarshal(t, jsonFields{IP: "1.2.3.4", Level: "THREAT"})
	q.Push(ctx, payload)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Pop did not return after Push")
	}
}

func TestMemoryQueue_PopCancelled(t *testing.T) {
	q := queue.NewMemoryQueue(1)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		_, err := q.Pop(ctx)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Pop error = %v, want context.Canceled", err)
		}
		close(done)
	}()

	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Pop did not return after cancel")
	}
}

func TestMemoryQueue_QueueFull(t *testing.T) {
	q := queue.NewMemoryQueue(1)
	ctx := context.Background()

	q.Push(ctx, mustMarshal(t, jsonFields{IP: "1.2.3.4", Level: "THREAT"}))
	err := q.Push(ctx, mustMarshal(t, jsonFields{IP: "5.6.7.8", Level: "THREAT"}))
	if err != queue.ErrQueueFull {
		t.Errorf("Push error = %v, want ErrQueueFull", err)
	}
}

func TestMemoryQueue_Close(t *testing.T) {
	q := queue.NewMemoryQueue(1)
	q.Close()
	if err := q.Close(); err != nil {
		t.Errorf("second Close error = %v, want nil", err)
	}
}

func TestMemoryQueue_PopAfterClose(t *testing.T) {
	q := queue.NewMemoryQueue(1)
	ctx := context.Background()
	q.Close()

	_, err := q.Pop(ctx)
	if err != queue.ErrQueueClosed {
		t.Errorf("Pop after Close error = %v, want ErrQueueClosed", err)
	}
}

func TestMemoryQueue_Len(t *testing.T) {
	q := queue.NewMemoryQueue(5)
	ctx := context.Background()

	if q.Len() != 0 {
		t.Errorf("empty Len = %d, want 0", q.Len())
	}
	q.Push(ctx, mustMarshal(t, jsonFields{IP: "1.2.3.4", Level: "THREAT"}))
	if q.Len() != 1 {
		t.Errorf("Len after Push = %d, want 1", q.Len())
	}
	q.Pop(ctx)
	if q.Len() != 0 {
		t.Errorf("Len after Pop = %d, want 0", q.Len())
	}
}
