// ========================== NoAsset detector tests ======================================
//   Unit and registry smoke tests for the noasset detector.

package noasset_test

import (
	"context"
	"testing"
	"time"

	"github.com/mr-addams/arxsentinel/pkg/detector"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

// TestNoAssetDetector_ViaRegistry verifies detection of page-only traffic.
func TestNoAssetDetector_ViaRegistry(t *testing.T) {
	cfg := detector.DetectorConfig{
		Enabled: true,
		Params: map[string]interface{}{
			"min_page_requests":     3,
			"asset_ratio_threshold": 0.1,
			"score":                 20,
		},
	}
	d, err := detector.Build(context.Background(), "noasset", cfg, nil)
	if err != nil {
		t.Fatalf("Build(noasset) error: %v", err)
	}
	if d.Name() != "noasset" {
		t.Errorf("Name() = %q, want %q", d.Name(), "noasset")
	}

	// Only page requests (no assets) → should trigger.
	sv := newStubView(0, 0, []string{"/", "/about", "/blog"}, 0)
	result := d.Detect(sv, &plugin.LogEntry{})
	if result.Score == 0 {
		t.Error("noasset should trigger when no assets loaded, got score=0")
	}

	// Mix of pages and assets (ratio above threshold) → should not trigger.
	sv2 := newStubView(0, 0, []string{"/", "/style.css", "/app.js"}, 0)
	result2 := d.Detect(sv2, &plugin.LogEntry{})
	if result2.Score != 0 {
		t.Errorf("noasset should not trigger with adequate asset ratio, got score=%d", result2.Score)
	}

	// Below min_page_requests → should not trigger.
	sv3 := newStubView(0, 0, []string{"/only-one-page"}, 0)
	result3 := d.Detect(sv3, &plugin.LogEntry{})
	if result3.Score != 0 {
		t.Errorf("noasset should not trigger below min_page_requests, got score=%d", result3.Score)
	}
}

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
