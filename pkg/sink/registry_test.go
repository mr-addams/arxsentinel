// ========================== pkg/sink — registry tests ===================================
//   Tests: Register, Build (by name and unknown), Names, duplicate-panic.

package sink

import (
	"slices"
	"strings"
	"testing"

	"github.com/mr-addams/arxsentinel/pkg/plugin"
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

func (m *mockSink) Write(event plugin.ThreatEvent) error {
	return nil
}

func (m *mockSink) Close() error {
	return nil
}

func (m *mockSink) Stats() plugin.SinkStats {
	return m.stats
}

// ── Tests ──────────────────────────────────────────────────────────────────────────────

func TestRegistry_Register(t *testing.T) {
	// Fresh registry for this test.
	// In real code, Registry would be instantiated per test to avoid pollution.
	// For now, we use global and rely on unique names per test.

	testName := "test-register-sink-" + t.Name()
	factory := func(cfg SinkConfig) (plugin.Sink, error) {
		return &mockSink{name: cfg.Type}, nil
	}

	Register(testName, factory)

	// Verify the factory was registered by building with it.
	cfg := SinkConfig{Type: testName, Path: "/tmp/test.log", Format: "fail2ban"}

	sink, err := Build(cfg)
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

	sink, err := Build(cfg)
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

	factory := func(cfg SinkConfig) (plugin.Sink, error) {
		return &mockSink{name: cfg.Type}, nil
	}

	for _, name := range names {
		Register(name, factory)
	}

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
	factory := func(cfg SinkConfig) (plugin.Sink, error) {
		return &mockSink{name: cfg.Type}, nil
	}

	Register(duplicateName, factory)

	// Attempting to register the same name again should panic.
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("Register() should panic on duplicate")
		}
	}()

	Register(duplicateName, factory)
}
