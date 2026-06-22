// ========================== pkg/source — registry tests =================================
//   Tests: Register, Build (by name and unknown), Names, duplicate-panic.

package source

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mr-addams/arx-core/pkg/plugin"
)

// ── Mock Source for testing ────────────────────────────────────────────────────────────

type mockSource struct {
	name  string
	stats plugin.SourceStats
}

func (m *mockSource) Name() string {
	return m.name
}

func (m *mockSource) Manifest() plugin.Manifest { return plugin.Manifest{} }

func (m *mockSource) Run(ctx context.Context, out chan<- *plugin.LogEntry) error {
	<-ctx.Done()
	return ctx.Err()
}

func (m *mockSource) Close() error {
	return nil
}

func (m *mockSource) Stats() plugin.SourceStats {
	return m.stats
}

// ── Mock Parser for testing ────────────────────────────────────────────────────────────

type mockParser struct{}

func (m *mockParser) Parse(line string) (*plugin.LogEntry, bool) {
	return &plugin.LogEntry{
		RemoteAddr: "192.0.2.1",
		Method:     "GET",
		Path:       "/test",
		Status:     200,
	}, true
}

// ── Test helpers ───────────────────────────────────────────────────────────────────────

// unregisterForTest удаляет name из singleton-реестра.
// Тестовая обёртка для идемпотентности к `go test -count>1`: production Register()
// паникует на дубликате, а на 2-м прогоне в том же бинаре имя уже занято.
// t.Cleanup гарантирует удаление после теста даже при panic внутри.
// Делегирует в unregister() — пакетный хелпер, обёрнутый вокруг generic-ядра
// (Flow 070 / Task 1.1.2). Семантика идентична оригиналу: cleanup глобального
// singleton между прогонами.
func unregisterForTest(names ...string) {
	for _, n := range names {
		unregister(n)
	}
}

// ── Tests ──────────────────────────────────────────────────────────────────────────────

func TestRegistry_Register(t *testing.T) {
	testName := "test-register-source-" + t.Name()
	factory := func(cfg InputConfig, opts BuildOptions) (plugin.Source, error) {
		return &mockSource{name: cfg.Type}, nil
	}

	Register(testName, factory)
	t.Cleanup(func() { unregisterForTest(testName) })

	// Verify the factory was registered by building with it.
	cfg := InputConfig{Type: "file", Path: "/tmp/test.log"}
	opts := BuildOptions{
		Parser:        &mockParser{},
		RetryInterval: time.Second,
	}

	src, err := Build(testName, cfg, opts)
	if err != nil {
		t.Fatalf("Build() failed: %v", err)
	}
	if src == nil {
		t.Fatal("Build() returned nil source")
	}
}

func TestRegistry_Build_Unknown(t *testing.T) {
	unknownName := "this-source-does-not-exist-" + t.Name()
	cfg := InputConfig{Type: "file", Path: "/tmp/test.log"}
	opts := BuildOptions{
		Parser:        &mockParser{},
		RetryInterval: time.Second,
	}

	src, err := Build(unknownName, cfg, opts)
	if err == nil {
		t.Fatal("Build() should return error for unknown source")
	}
	if src != nil {
		t.Fatal("Build() returned non-nil source on error")
	}

	// Error message should mention the unknown name.
	if !strings.Contains(err.Error(), unknownName) {
		t.Errorf("error message does not mention unknown name: %v", err)
	}
}

func TestRegistry_Names(t *testing.T) {
	// Register a few unique test sources.
	names := []string{
		"test-names-zebra-" + t.Name(),
		"test-names-apple-" + t.Name(),
		"test-names-cherry-" + t.Name(),
	}

	factory := func(cfg InputConfig, opts BuildOptions) (plugin.Source, error) {
		return &mockSource{name: cfg.Type}, nil
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
	factory := func(cfg InputConfig, opts BuildOptions) (plugin.Source, error) {
		return &mockSource{name: cfg.Type}, nil
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
