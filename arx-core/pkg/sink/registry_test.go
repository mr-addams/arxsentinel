// ========================== pkg/sink — registry tests ===================================
//   Tests: Register, Build (by name and unknown), Names, duplicate-panic.

package sink

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/mr-addams/arx-core/pkg/plugin"
)

// ── Mock Sink for testing ──────────────────────────────────────────────────────────────

type mockSink struct {
	name  string
	stats plugin.SinkStats
}

func (m *mockSink) Name() string {
	return m.name
}

func (m *mockSink) Manifest() plugin.Manifest { return plugin.Manifest{} }

func (m *mockSink) Write(ctx context.Context, event plugin.ThreatEvent) error {
	return nil
}

func (m *mockSink) Close() error {
	return nil
}

func (m *mockSink) Stats() plugin.SinkStats {
	return m.stats
}

// ── Test helpers ───────────────────────────────────────────────────────────────────────

// unregisterForTest удаляет name из singleton-реестра.
// Тестовая обёртка для идемпотентности к `go test -count>1`: production Register()
// паникует на дубликате, а на 2-м прогоне в том же бинаре имя уже занято.
// t.Cleanup гарантирует удаление после теста даже при panic внутри.
// Делегирует в unregister() — пакетный хелпер, обёрнутый вокруг generic-ядра
// (Flow 070 / Task 1.1.3). Семантика идентична оригиналу: cleanup глобального
// singleton между прогонами.
func unregisterForTest(names ...string) {
	for _, n := range names {
		unregister(n)
	}
}

// ── Tests ──────────────────────────────────────────────────────────────────────────────

func TestRegistry_Register(t *testing.T) {
	testName := "test-register-sink-" + t.Name()
	factory := func(ctx context.Context, cfg SinkConfig) (plugin.Sink, error) {
		return &mockSink{name: cfg.Type}, nil
	}

	Register(testName, factory)
	t.Cleanup(func() { unregisterForTest(testName) })

	// Verify the factory was registered by building with it.
	cfg := SinkConfig{Type: testName, Path: "/tmp/test.log", Format: "fail2ban"}

	sink, err := Build(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Build() failed: %v", err)
	}
	if sink == nil {
		t.Fatal("Build() returned nil sink")
	}
}

func TestRegistry_Build_Unknown(t *testing.T) {
	unknownName := "this-sink-does-not-exist-" + t.Name()
	cfg := SinkConfig{Type: unknownName, Path: "/tmp/test.log", Format: "json"}

	sink, err := Build(context.Background(), cfg)
	if err == nil {
		t.Fatal("Build() should return error for unknown sink")
	}
	if sink != nil {
		t.Fatal("Build() returned non-nil sink on error")
	}

	// Error message should mention the unknown name.
	if !strings.Contains(err.Error(), unknownName) {
		t.Errorf("error message does not mention unknown name: %v", err)
	}
}

func TestRegistry_Names(t *testing.T) {
	// Register a few unique test sinks.
	names := []string{
		"test-names-zebra-" + t.Name(),
		"test-names-apple-" + t.Name(),
		"test-names-cherry-" + t.Name(),
	}

	factory := func(ctx context.Context, cfg SinkConfig) (plugin.Sink, error) {
		return &mockSink{name: cfg.Type}, nil
	}

	for _, name := range names {
		Register(name, factory)
	}
	t.Cleanup(func() { unregisterForTest(names...) })

	// Call Names() and verify all registered names are present and sorted.
	allNames := Names()

	for _, name := range names {
		if !slices.Contains(allNames, name) {
			t.Errorf("Names() missing registered name: %s", name)
		}
	}

	// Verify sorted order.
	sortedAllNames := make([]string, len(allNames))
	copy(sortedAllNames, allNames)
	slices.Sort(sortedAllNames)
	if !slices.Equal(allNames, sortedAllNames) {
		t.Errorf("Names() not sorted. Got: %v", allNames)
	}
}

func TestRegistry_Register_Duplicate(t *testing.T) {
	duplicateName := "test-dup-" + t.Name()
	factory := func(ctx context.Context, cfg SinkConfig) (plugin.Sink, error) {
		return &mockSink{name: cfg.Type}, nil
	}

	Register(duplicateName, factory)
	t.Cleanup(func() { unregisterForTest(duplicateName) })

	// Attempting to register the same name again should panic.
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("Register() should panic on duplicate")
		}
	}()

	Register(duplicateName, factory)
}
