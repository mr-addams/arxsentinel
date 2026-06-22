// ========================== Bruteforce detector tests ===================================
//   Unit and registry smoke tests for the bruteforce detector.

package bruteforce_test

import (
	"context"
	"testing"
	"time"

	"github.com/mr-addams/arxsentinel/pkg/detector"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

// TestBruteforceDetector_ViaRegistry verifies triggering on a high 404 ratio.
func TestBruteforceDetector_ViaRegistry(t *testing.T) {
	cfg := detector.DetectorConfig{
		Enabled: true,
		Params: map[string]interface{}{
			"min_requests":    10,
			"ratio_threshold": 0.6,
			"score":           30,
		},
	}
	d, err := detector.Build(context.Background(), "bruteforce", cfg, nil)
	if err != nil {
		t.Fatalf("Build(bruteforce) error: %v", err)
	}
	if d.Name() != "bruteforce" {
		t.Errorf("Name() = %q, want %q", d.Name(), "bruteforce")
	}

	// 9 of 10 requests are 404 → 90% → should trigger.
	sv := newStubView(10, 9, nil, 0)
	result := d.Detect(sv, &plugin.LogEntry{})
	if result.Score == 0 {
		t.Error("bruteforce should trigger on 90% 404 ratio, got score=0")
	}

	// Below min_requests — should not trigger.
	sv2 := newStubView(5, 4, nil, 0)
	result2 := d.Detect(sv2, &plugin.LogEntry{})
	if result2.Score != 0 {
		t.Errorf("bruteforce should not trigger below min_requests, got score=%d", result2.Score)
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
