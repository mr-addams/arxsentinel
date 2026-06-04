package executor_test

import (
	"context"
	"testing"

	"github.com/mr-addams/arxsentinel/pkg/executor"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

func TestNamedHub_SendReceive(t *testing.T) {
	ctx := context.Background()
	q, err := executor.RegisterSink("test-sr", 10)
	if err != nil {
		t.Fatalf("RegisterSink error = %v, want nil", err)
	}

	src, err := executor.GetSource("test-sr")
	if err != nil {
		t.Fatalf("GetSource error = %v, want nil", err)
	}

	event := plugin.ThreatEvent{IP: "1.2.3.4", Level: "THREAT"}
	if err := q.Push(ctx, event); err != nil {
		t.Fatalf("Push error = %v, want nil", err)
	}

	got, err := src.Pop(ctx)
	if err != nil {
		t.Fatalf("Pop error = %v, want nil", err)
	}
	if got.IP != event.IP {
		t.Errorf("received IP = %q, want %q", got.IP, event.IP)
	}
	if got.Level != event.Level {
		t.Errorf("received Level = %q, want %q", got.Level, event.Level)
	}

	executor.Unregister("test-sr")
}

func TestNamedHub_DuplicateName(t *testing.T) {
	ctx := context.Background()

	// Fan-in: two streams register the same name and get the same queue.
	q1, err := executor.RegisterSink("test-dup", 5)
	if err != nil {
		t.Fatalf("first RegisterSink error = %v, want nil", err)
	}
	q2, err := executor.RegisterSink("test-dup", 5)
	if err != nil {
		t.Fatalf("second RegisterSink error = %v, want nil", err)
	}
	if q1 != q2 {
		t.Error("both RegisterSink calls must return the same queue")
	}

	// Both push through different handles; consumer sees all events.
	src, _ := executor.GetSource("test-dup")
	_ = q1.Push(ctx, plugin.ThreatEvent{IP: "1.1.1.1", Level: "THREAT"})
	_ = q2.Push(ctx, plugin.ThreatEvent{IP: "2.2.2.2", Level: "THREAT"})

	got1, _ := src.Pop(ctx)
	got2, _ := src.Pop(ctx)
	ips := map[string]bool{got1.IP: true, got2.IP: true}
	if !ips["1.1.1.1"] || !ips["2.2.2.2"] {
		t.Errorf("expected both IPs from fan-in, got %q and %q", got1.IP, got2.IP)
	}

	// Ref count: first Unregister keeps queue alive.
	executor.Unregister("test-dup") // ref: 2 → 1, queue must stay open
	if _, err := executor.GetSource("test-dup"); err != nil {
		t.Error("queue should still be open after first Unregister")
	}
	executor.Unregister("test-dup") // ref: 1 → 0, queue closed
	if _, err := executor.GetSource("test-dup"); err == nil {
		t.Error("queue should be gone after last Unregister")
	}
}

func TestNamedHub_Unregister(t *testing.T) {
	ctx := context.Background()
	q, err := executor.RegisterSink("test-unreg", 3)
	if err != nil {
		t.Fatalf("RegisterSink error = %v, want nil", err)
	}

	src, err := executor.GetSource("test-unreg")
	if err != nil {
		t.Fatalf("GetSource error = %v, want nil", err)
	}

	_ = q.Push(ctx, plugin.ThreatEvent{IP: "1.2.3.4", Level: "THREAT"})
	executor.Unregister("test-unreg")

	// After close, Pop returns ErrQueueClosed.
	got, err := src.Pop(ctx)
	if err == nil {
		t.Logf("received value after close: %+v", got)
	}
}

func TestNamedHub_GetSourceNotFound(t *testing.T) {
	_, err := executor.GetSource("nonexistent")
	if err == nil {
		t.Fatal("GetSource(nonexistent) expected error, got nil")
	}
}
