// ========================== Crawler smoke tests ===========================================
//   Smoke test for the crawler detector registered via its sub-package.

package crawler_test

import (
	"context"
	"testing"
	"time"

	detector "github.com/mr-addams/arxsentinel/pkg/detector"
	_ "github.com/mr-addams/arxsentinel/pkg/detector/crawler"
	"github.com/mr-addams/arx-core/pkg/plugin"
)

// TestCrawlerDetector_ViaRegistry verifies sequential numeric path detection.
func TestCrawlerDetector_ViaRegistry(t *testing.T) {
	cfg := detector.DetectorConfig{
		Enabled: true,
		Params:  map[string]interface{}{"min_sequential": 3, "score": 20},
	}
	d, err := detector.Build(context.Background(), "crawler", cfg, nil)
	if err != nil {
		t.Fatalf("Build(crawler) error: %v", err)
	}
	if d.Name() != "crawler" {
		t.Errorf("Name() = %q, want %q", d.Name(), "crawler")
	}

	// 3 consecutive pages → should trigger.
	sv := newStubView(0, 0, []string{"/page/1", "/page/2", "/page/3"}, 0)
	result := d.Detect(sv, &plugin.LogEntry{})
	if result.Score == 0 {
		t.Error("crawler should trigger on 3 sequential pages, got score=0")
	}

	// Non-sequential paths → should not trigger.
	sv2 := newStubView(0, 0, []string{"/about", "/contact", "/blog"}, 0)
	result2 := d.Detect(sv2, &plugin.LogEntry{})
	if result2.Score != 0 {
		t.Errorf("crawler should not trigger on non-sequential paths, got score=%d", result2.Score)
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
