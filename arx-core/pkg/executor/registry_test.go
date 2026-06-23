// ========================== pkg/executor — registry_test.go ==============
//   Tests for ExecutorRegistry: registration, lookup, error handling.
//
//   Тесты объявлены в `package executor` (а не `executor_test`) чтобы получить
//   доступ к пакетному `unregister()` helper и иметь возможность снимать
//   регистрацию в t.Cleanup. Без этого на 2-м прогоне `go test -count>1`
//   в том же бинаре Register() паникует на дубликате (см. дефект [068-1]).
//   Это test-only изменение package declaration — production-код реестра не трогаем.

package executor

import (
	"context"
	"testing"

	"github.com/mr-addams/arx-core/pkg/logger"
	"github.com/mr-addams/arx-core/pkg/plugin"
)

// unregisterForTest удаляет name из singleton-реестра.
// Тестовая обёртка для идемпотентности к `go test -count>1`: на 2-м прогоне
// имя уже занято. Делегирует в unregister() — пакетный helper, обёрнутый
// вокруг generic-ядра (Flow 070 / Task 1.1.4). Семантика идентична оригиналу:
// cleanup глобального singleton между прогонами через Delete().
func unregisterForTest(names ...string) {
	for _, n := range names {
		unregister(n)
	}
}

func TestRegistry_TypedFactory(t *testing.T) {
	Register("test-typed", func(cfg ExecutorConfig, _ logger.Logger) (plugin.Executor, error) {
		return &mockExecutor{name: cfg.Name}, nil
	})
	t.Cleanup(func() { unregisterForTest("test-typed") })

	exe, err := Build(ExecutorConfig{
		Name: "my-executor",
		Type: "test-typed",
	}, logger.Nop)
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
	_, err := Build(ExecutorConfig{
		Name: "unknown",
		Type: "nonexistent_type_xyz",
	}, logger.Nop)
	if err == nil {
		t.Fatal("Build(unknown) expected error, got nil")
	}
}

func TestRegistry_ExecFallback(t *testing.T) {
	exe, err := Build(ExecutorConfig{
		Name: "exec-fallback",
		Type: "unregistered_type",
		// execplugin перенесён в arx-core/pkg/execplugin (Flow 079 W4.2).
		// После Phase 3 registry переехал в arx-core/pkg/executor — путь
		// относительно текущей директории пакета: ../execplugin/testdata/.
		Exec: "../execplugin/testdata/executor.sh",
	}, logger.Nop)
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

func (m *mockExecutor) Manifest() plugin.Manifest { return plugin.Manifest{} }

func (m *mockExecutor) Name() string                { return m.name }
func (m *mockExecutor) Type() string                { return "mock" }
func (m *mockExecutor) Stats() plugin.ExecutorStats { return plugin.ExecutorStats{} }
func (m *mockExecutor) Run(_ context.Context, source plugin.EventSource) error {
	for {
		_, err := source.Pop(context.Background())
		if err != nil {
			return nil
		}
	}
}
