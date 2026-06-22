// ========================== pkg/executor/queue — queue_test.go ============
//   Tests for Queue: buffering, ordering, worker pool, shutdown.

package queue_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mr-addams/arx-core/pkg/executor/queue"
	"github.com/mr-addams/arx-core/pkg/plugin"
)

func TestMemoryQueue_PushPop(t *testing.T) {
	q := queue.NewMemoryQueue(10)
	ctx := context.Background()
	event := plugin.ThreatEvent{IP: "1.2.3.4", Level: "THREAT"}

	if err := q.Push(ctx, event); err != nil {
		t.Fatalf("Push error = %v, want nil", err)
	}
	if q.Len() != 1 {
		t.Fatalf("Len = %d, want 1", q.Len())
	}

	got, err := q.Pop(ctx)
	if err != nil {
		t.Fatalf("Pop error = %v, want nil", err)
	}
	if got.IP != event.IP {
		t.Errorf("Pop IP = %q, want %q", got.IP, event.IP)
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

	q.Push(ctx, plugin.ThreatEvent{IP: "1.2.3.4", Level: "THREAT"})

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

	q.Push(ctx, plugin.ThreatEvent{IP: "1.2.3.4", Level: "THREAT"})
	err := q.Push(ctx, plugin.ThreatEvent{IP: "5.6.7.8", Level: "THREAT"})
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
	q.Push(ctx, plugin.ThreatEvent{IP: "1.2.3.4", Level: "THREAT"})
	if q.Len() != 1 {
		t.Errorf("Len after Push = %d, want 1", q.Len())
	}
	q.Pop(ctx)
	if q.Len() != 0 {
		t.Errorf("Len after Pop = %d, want 0", q.Len())
	}
}
