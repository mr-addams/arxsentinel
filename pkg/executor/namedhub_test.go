package executor_test

import (
	"testing"

	"github.com/mr-addams/arxsentinel/pkg/executor"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

func TestNamedHub_SendReceive(t *testing.T) {
	ch, err := executor.RegisterSink("test-sr", 10)
	if err != nil {
		t.Fatalf("RegisterSink error = %v, want nil", err)
	}

	src, err := executor.GetSource("test-sr")
	if err != nil {
		t.Fatalf("GetSource error = %v, want nil", err)
	}

	event := plugin.ThreatEvent{IP: "1.2.3.4", Level: "THREAT"}
	ch <- event

	got := <-src
	if got.IP != event.IP {
		t.Errorf("received IP = %q, want %q", got.IP, event.IP)
	}
	if got.Level != event.Level {
		t.Errorf("received Level = %q, want %q", got.Level, event.Level)
	}

	executor.Unregister("test-sr")
}

func TestNamedHub_DuplicateName(t *testing.T) {
	_, err := executor.RegisterSink("test-dup", 5)
	if err != nil {
		t.Fatalf("first RegisterSink error = %v, want nil", err)
	}

	_, err = executor.RegisterSink("test-dup", 5)
	if err == nil {
		t.Fatal("second RegisterSink expected error, got nil")
	}

	executor.Unregister("test-dup")
}

func TestNamedHub_Unregister(t *testing.T) {
	ch, err := executor.RegisterSink("test-unreg", 3)
	if err != nil {
		t.Fatalf("RegisterSink error = %v, want nil", err)
	}

	src, err := executor.GetSource("test-unreg")
	if err != nil {
		t.Fatalf("GetSource error = %v, want nil", err)
	}

	ch <- plugin.ThreatEvent{IP: "1.2.3.4", Level: "THREAT"}
	executor.Unregister("test-unreg")

	// After close, the channel yields zero values then blocks.
	got, ok := <-src
	if ok {
		t.Logf("received value after close: %+v", got)
	}
}

func TestNamedHub_GetSourceNotFound(t *testing.T) {
	_, err := executor.GetSource("nonexistent")
	if err == nil {
		t.Fatal("GetSource(nonexistent) expected error, got nil")
	}
}
