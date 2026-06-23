// ========================== Overflow detector tests =====================================
//   Unit and registry smoke tests for the overflow detector.

package overflow_test

import (
	"context"
	"testing"
	"time"

	"github.com/mr-addams/arx-core/pkg/detector"
	"github.com/mr-addams/arx-core/pkg/plugin"
)

// TestOverflowDetector_ViaRegistry verifies URL length and WAF bypass detection.
func TestOverflowDetector_ViaRegistry(t *testing.T) {
	cfg := detector.DetectorConfig{
		Enabled: true,
		Params: map[string]interface{}{
			"max_url_length":    20,
			"suspicious_params": []interface{}{"exec", "eval"},
			"score":             30,
		},
	}
	d, err := detector.Build(context.Background(), "overflow", cfg, nil)
	if err != nil {
		t.Fatalf("Build(overflow) error: %v", err)
	}
	if d.Name() != "overflow" {
		t.Errorf("Name() = %q, want %q", d.Name(), "overflow")
	}

	sv := newStubView(0, 0, nil, 0)

	// URL longer than max_url_length → should trigger.
	longURL := "/" + string(make([]byte, 30)) // 31 bytes > 20
	result := d.Detect(sv, &plugin.Event{Payload: &plugin.LogEntry{Path: longURL}})
	if result.Score == 0 {
		t.Error("overflow should trigger on long URL, got score=0")
	}

	// WAF bypass keyword → should trigger.
	result2 := d.Detect(sv, &plugin.Event{Payload: &plugin.LogEntry{Path: "/api", Query: "cmd=exec+bash"}})
	if result2.Score == 0 {
		t.Error("overflow should trigger on suspicious param, got score=0")
	}

	// Normal short URL without keywords → should not trigger.
	result3 := d.Detect(sv, &plugin.Event{Payload: &plugin.LogEntry{Path: "/index.html"}})
	if result3.Score != 0 {
		t.Errorf("overflow should not trigger on clean URL, got score=%d", result3.Score)
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
