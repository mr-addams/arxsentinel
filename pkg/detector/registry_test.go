// ========================== Registry tests ==============================================
//   Tests for the pkg/detector registry: Register, Build, Names.
//   Also tests that built-in detectors (registered via init()) produce working instances.

package detector_test

import (
	"context"
	"testing"
	"time"

	"github.com/mr-addams/arxsentinel/pkg/detector"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

// ── Registry unit tests ───────────────────────────────────────────────────────────────

// TestRegistry_Names verifies the registry is populated and that Names()
// returns a sorted, duplicate-free, non-empty list.
// It intentionally does not assert the full set of detector names, because
// individual detectors are registered via blank imports in cmd/arxsentinel
// plugins files; pkg/detector tests only check registry infrastructure.
func TestRegistry_Names(t *testing.T) {
	names := detector.Names()

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
	cfg := detector.DetectorConfig{Enabled: false}
	d, err := detector.Build(context.Background(), "probe", cfg, nil)
	if err != nil {
		t.Fatalf("Build(disabled) error = %v, want nil", err)
	}
	if d != nil {
		t.Fatalf("Build(disabled) detector = %v, want nil", d)
	}
}

// TestRegistry_Build_Unknown verifies that Build returns an error for an unregistered name.
func TestRegistry_Build_Unknown(t *testing.T) {
	cfg := detector.DetectorConfig{Enabled: true}
	d, err := detector.Build(context.Background(), "nonexistent_detector_xyz", cfg, nil)
	if err == nil {
		t.Fatal("Build(unknown) expected error, got nil")
	}
	if d != nil {
		t.Fatalf("Build(unknown) returned non-nil detector: %v", d)
	}
}

// ── Built-in detector smoke tests ─────────────────────────────────────────────────────

// TestUADetector_ViaRegistry verifies scanner and empty UA detection.
func TestUADetector_ViaRegistry(t *testing.T) {
	cfg := detector.DetectorConfig{Enabled: true}
	d, err := detector.Build(context.Background(), "ua", cfg, nil)
	if err != nil {
		t.Fatalf("Build(ua) error: %v", err)
	}
	if d.Name() != "ua" {
		t.Errorf("Name() = %q, want %q", d.Name(), "ua")
	}

	sv := newStubView(0, 0, nil, 0)
	cases := []struct {
		ua        string
		wantScore bool
	}{
		{"", true},             // empty UA
		{"-", true},            // nginx empty placeholder
		{"Nuclei/2.9.4", true}, // scanner
		{"Mozilla/5.0", false}, // legitimate browser
	}
	for _, tc := range cases {
		entry := &plugin.LogEntry{UserAgent: tc.ua}
		result := d.Detect(sv, entry)
		if tc.wantScore && result.Score == 0 {
			t.Errorf("ua detector: UA=%q should score, got 0", tc.ua)
		}
		if !tc.wantScore && result.Score != 0 {
			t.Errorf("ua detector: UA=%q should not score, got %d", tc.ua, result.Score)
		}
	}
}

// ── Stubs and mocks ───────────────────────────────────────────────────────────────────

// stubView implements plugin.IPView for test use.
type stubView struct {
	total    int
	count404 int
	paths    []string
	rate     float64
}

// newStubView creates a stubView with the given field values.
func newStubView(total, count404 int, paths []string, rate float64) plugin.IPView {
	return &stubView{total: total, count404: count404, paths: paths, rate: rate}
}

func (s *stubView) GetIP() string                      { return "1.2.3.4" }
func (s *stubView) GetTotalRequests() int              { return s.total }
func (s *stubView) GetRequests404() int                { return s.count404 }
func (s *stubView) RecentPaths() []string              { return s.paths }
func (s *stubView) ApproxRate(_ time.Duration) float64 { return s.rate }

// stubShared wraps a Matcher into a SharedResources implementation.
type stubShared struct{ matcher detector.Matcher }

func (s *stubShared) Blocklist() detector.Matcher { return s.matcher }
