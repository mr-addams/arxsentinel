// ========================== Probe detector smoke tests ================================
//   Internal smoke tests for the probe detector. Tests package probe directly
//   without blank-import; registry path is exercised by calling detector.Build.
//
//   Moved from pkg/detector/registry_test.go as part of Flow 076 sub-package migration.

package probe

import (
	"context"
	"testing"
	"time"

	"github.com/mr-addams/arxsentinel/pkg/detector"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

// TestProbeDetector_ViaRegistry builds a probe detector and verifies it matches
// a known sensitive path.
func TestProbeDetector_ViaRegistry(t *testing.T) {
	cfg := detector.DetectorConfig{
		Enabled: true,
		Params:  map[string]interface{}{"score": 25},
	}
	d, err := detector.Build(context.Background(), "probe", cfg, nil)
	if err != nil {
		t.Fatalf("Build(probe) error: %v", err)
	}
	if d == nil {
		t.Fatal("Build(probe) returned nil")
	}
	if d.Name() != "probe" {
		t.Errorf("Name() = %q, want %q", d.Name(), "probe")
	}

	// Sensitive path should trigger.
	result := d.Detect(newStubView(0, 0, nil, 0), &plugin.LogEntry{Path: "/.env"})
	if result.Score == 0 {
		t.Error("probe should score on /.env, got 0")
	}

	// Normal path should not trigger.
	result2 := d.Detect(newStubView(0, 0, nil, 0), &plugin.LogEntry{Path: "/index.html"})
	if result2.Score != 0 {
		t.Errorf("probe should not score on /index.html, got %d", result2.Score)
	}
}

// ── Stubs and mocks for internal use ──────────────────────────────────────────────────

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
