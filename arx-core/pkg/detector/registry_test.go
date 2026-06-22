// ========================== Registry tests ==============================================
//   Infrastructure tests for the pkg/detector registry: Register, Build, Names.
//   Individual detectors are tested in their own sub-packages; this file intentionally
//   does not assert any particular detector behaviour.

package detector

import (
	"context"
	"testing"

	"github.com/mr-addams/arx-core/pkg/plugin"
)

// dummyFactory returns a no-op detector; used only for temporary registration.
func dummyFactory(_ DetectorConfig, _ SharedResources) (plugin.Detector, error) {
	return nil, nil
}

// ── Registry unit tests ───────────────────────────────────────────────────────────────

// TestRegistry_Names verifies Names() returns a sorted, duplicate-free list.
// It registers a temporary factory so the test does not depend on any concrete
// detector package being blank-imported, then unregisters it afterwards.
func TestRegistry_Names(t *testing.T) {
	testName := "test_registry_dummy_detector"
	Register(testName, dummyFactory)
	defer unregister(testName)

	names := Names()

	if len(names) == 0 {
		t.Fatal("Names() returned empty slice, expected at least one registered detector")
	}

	seen := make(map[string]struct{}, len(names))
	for i, n := range names {
		if n == "" {
			t.Errorf("Names()[%d] is empty string", i)
			continue
		}
		if _, ok := seen[n]; ok {
			t.Errorf("Names() contains duplicate %q at index %d", n, i)
		}
		seen[n] = struct{}{}
	}

	// Verify sorted order.
	for i := 1; i < len(names); i++ {
		if names[i] < names[i-1] {
			t.Errorf("Names() not sorted: %q < %q at index %d", names[i], names[i-1], i)
		}
	}
}

// TestRegistry_Build_Disabled verifies that Build returns (nil, nil) for a disabled detector.
func TestRegistry_Build_Disabled(t *testing.T) {
	cfg := DetectorConfig{Enabled: false}
	d, err := Build(context.Background(), "probe", cfg, nil)
	if err != nil {
		t.Fatalf("Build(disabled) error = %v, want nil", err)
	}
	if d != nil {
		t.Fatalf("Build(disabled) detector = %v, want nil", d)
	}
}

// TestRegistry_Build_Unknown verifies that Build returns an error for an unregistered name.
func TestRegistry_Build_Unknown(t *testing.T) {
	cfg := DetectorConfig{Enabled: true}
	d, err := Build(context.Background(), "nonexistent_detector_xyz", cfg, nil)
	if err == nil {
		t.Fatal("Build(unknown) expected error, got nil")
	}
	if d != nil {
		t.Fatalf("Build(unknown) returned non-nil detector: %v", d)
	}
}
