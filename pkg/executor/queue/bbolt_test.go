// ========================== Module: queue/bbolt — tests ===================================
//   Tests for BboltQueue covering push, pop, blocking, persistence, Len, and Close.
//   All tests use t.TempDir() for temporary .db files — no external dependencies.
// ==========================================================================================

package queue

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/mr-addams/arx-core/pkg/logger"
	"github.com/mr-addams/arx-core/pkg/plugin"
)

func testEvent(ip string) plugin.ThreatEvent {
	return plugin.ThreatEvent{
		IP: ip,
	}
}

func newTestBbolt(t *testing.T) *BboltQueue {
	t.Helper()
	path := filepath.Join(t.TempDir(), "queue.db")
	q, err := NewBboltQueue(path, "q", logger.Nop)
	if err != nil {
		t.Fatalf("NewBboltQueue: %v", err)
	}
	return q
}

func TestBboltQueue_PushPop(t *testing.T) {
	q := newTestBbolt(t)
	defer q.Close()

	ctx := context.Background()
	err := q.Push(ctx, testEvent("192.168.1.1"))
	if err != nil {
		t.Fatalf("Push: %v", err)
	}

	event, err := q.Pop(ctx)
	if err != nil {
		t.Fatalf("Pop: %v", err)
	}
	if event.IP != "192.168.1.1" {
		t.Fatalf("expected IP 192.168.1.1, got %s", event.IP)
	}
}

func TestBboltQueue_PopBlocks(t *testing.T) {
	q := newTestBbolt(t)
	defer q.Close()

	ctx := context.Background()
	done := make(chan struct{})

	go func() {
		_, err := q.Pop(ctx)
		if err != nil {
			t.Errorf("Pop: %v", err)
		}
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)

	select {
	case <-done:
		t.Fatal("Pop returned before Push")
	default:
	}

	err := q.Push(ctx, testEvent("10.0.0.1"))
	if err != nil {
		t.Fatalf("Push: %v", err)
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Pop did not return after Push")
	}
}

func TestBboltQueue_PopCancelled(t *testing.T) {
	q := newTestBbolt(t)
	defer q.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := q.Pop(ctx)
	if err == nil {
		t.Fatal("expected error on cancelled context")
	}
}

func TestBboltQueue_Persistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "persist.db")

	q1, err := NewBboltQueue(path, "q", logger.Nop)
	if err != nil {
		t.Fatalf("NewBboltQueue: %v", err)
	}

	ctx := context.Background()
	err = q1.Push(ctx, testEvent("10.0.0.1"))
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	err = q1.Push(ctx, testEvent("10.0.0.2"))
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	q1.Close()

	q2, err := NewBboltQueue(path, "q", logger.Nop)
	if err != nil {
		t.Fatalf("NewBboltQueue (reopen): %v", err)
	}
	defer q2.Close()

	event, err := q2.Pop(ctx)
	if err != nil {
		t.Fatalf("Pop: %v", err)
	}
	if event.IP != "10.0.0.1" {
		t.Fatalf("expected IP 10.0.0.1, got %s", event.IP)
	}

	event, err = q2.Pop(ctx)
	if err != nil {
		t.Fatalf("Pop: %v", err)
	}
	if event.IP != "10.0.0.2" {
		t.Fatalf("expected IP 10.0.0.2, got %s", event.IP)
	}
}

func TestBboltQueue_Len(t *testing.T) {
	q := newTestBbolt(t)
	defer q.Close()

	ctx := context.Background()
	if l := q.Len(); l != 0 {
		t.Fatalf("expected Len 0, got %d", l)
	}

	q.Push(ctx, testEvent("10.0.0.1"))
	q.Push(ctx, testEvent("10.0.0.2"))
	q.Push(ctx, testEvent("10.0.0.3"))

	if l := q.Len(); l != 3 {
		t.Fatalf("expected Len 3, got %d", l)
	}

	q.Pop(ctx)
	if l := q.Len(); l != 2 {
		t.Fatalf("expected Len 2, got %d", l)
	}
}

func TestBboltQueue_Close(t *testing.T) {
	q := newTestBbolt(t)

	err := q.Close()
	if err != nil {
		t.Fatalf("first Close: %v", err)
	}

	// Second close must be idempotent.
	err = q.Close()
	if err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestBboltQueue_ConcurrentCloseAndPush(t *testing.T) {
	dir := t.TempDir()
	q, err := NewBboltQueue(filepath.Join(dir, "test.db"), "q", logger.Nop)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	event := plugin.ThreatEvent{IP: "1.2.3.4", Level: "THREAT"}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = q.Push(ctx, event)
		}()
	}
	// Close concurrently with pushes — must not panic
	go q.Close()
	wg.Wait()
}
