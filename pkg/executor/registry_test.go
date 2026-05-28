package executor_test

import (
	"context"
	"testing"

	"github.com/mr-addams/arxsentinel/pkg/executor"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

func TestRegistry_TypedFactory(t *testing.T) {
	executor.Register("test-typed", func(cfg executor.ExecutorConfig) (plugin.Executor, error) {
		return &mockExecutor{name: cfg.Name}, nil
	})

	exe, err := executor.Build(executor.ExecutorConfig{
		Name: "my-executor",
		Type: "test-typed",
	})
	if err != nil {
		t.Fatalf("Build(test-typed) error = %v, want nil", err)
	}
	if exe == nil {
		t.Fatal("Build(test-typed) returned nil executor")
	}
	if exe.Name() != "my-executor" {
		t.Errorf("Name() = %q, want %q", exe.Name(), "my-executor")
	}
}

func TestRegistry_UnknownType(t *testing.T) {
	_, err := executor.Build(executor.ExecutorConfig{
		Name: "unknown",
		Type: "nonexistent_type_xyz",
	})
	if err == nil {
		t.Fatal("Build(unknown) expected error, got nil")
	}
}

func TestRegistry_ExecFallback(t *testing.T) {
	exe, err := executor.Build(executor.ExecutorConfig{
		Name: "exec-fallback",
		Type: "unregistered_type",
		Exec: "../execplugin/testdata/executor.sh",
	})
	if err != nil {
		t.Fatalf("Build(exec-fallback) error = %v, want nil", err)
	}
	if exe == nil {
		t.Fatal("Build(exec-fallback) returned nil executor")
	}
	if exe.Name() != "exec-fallback" {
		t.Errorf("Name() = %q, want %q", exe.Name(), "exec-fallback")
	}
}

type mockExecutor struct {
	name string
}

func (m *mockExecutor) Name() string                                     { return m.name }
func (m *mockExecutor) Execute(_ context.Context, _ plugin.ThreatEvent) error { return nil }
func (m *mockExecutor) Close() error                                     { return nil }
func (m *mockExecutor) Stats() plugin.ExecutorStats                      { return plugin.ExecutorStats{} }
