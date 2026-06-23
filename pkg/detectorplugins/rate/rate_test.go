// ========================== Rate detector smoke tests ===================================
//   Internal smoke tests for the rate detector. Tests package rate directly
//   without blank-import; registry path is exercised by calling detector.Build.
//
//   Moved from pkg/detector/registry_test.go as part of Flow 076 sub-package migration.

package rate

import (
	"context"
	"testing"
	"time"

	"github.com/mr-addams/arx-core/pkg/detector"
	"github.com/mr-addams/arx-core/pkg/plugin"
)

// TestRateDetector_ViaRegistry builds a rate detector and verifies it triggers
// on a simulated high request rate.
func TestRateDetector_ViaRegistry(t *testing.T) {
	cfg := detector.DetectorConfig{
		Enabled: true,
		Params: map[string]interface{}{
			"threshold": 10,
			"window":    "60s",
			"score":     25,
		},
	}
	d, err := detector.Build(context.Background(), "rate", cfg, nil)
	if err != nil {
		t.Fatalf("Build(rate) error: %v", err)
	}
	if d.Name() != "rate" {
		t.Errorf("Name() = %q, want %q", d.Name(), "rate")
	}

	// 20 req/60s ≈ 0.333 rps — exceeds threshold of 10/60 ≈ 0.167 rps.
	highRate := newStubView(0, 0, nil, 20.0/60.0)
	result := d.Detect(highRate, &plugin.Event{Payload: &plugin.LogEntry{}})
	if result.Score == 0 {
		t.Error("rate detector should trigger on high rate, got score=0")
	}

	// Low rate should not trigger.
	lowRate := newStubView(0, 0, nil, 1.0/60.0)
	result2 := d.Detect(lowRate, &plugin.Event{Payload: &plugin.LogEntry{}})
	if result2.Score != 0 {
		t.Errorf("rate detector should not trigger on low rate, got score=%d", result2.Score)
	}
}

// TestRateDetector_InvalidParams verifies that invalid rate detector params
// (window=0 or threshold=0) return an error from Build, not a disabled detector.
func TestRateDetector_InvalidParams(t *testing.T) {
	for _, tc := range []struct {
		name   string
		params map[string]interface{}
	}{
		{"zero_window", map[string]interface{}{"window": "0s", "threshold": 100}},
		{"zero_threshold", map[string]interface{}{"window": "60s", "threshold": 0}},
		{"negative_window", map[string]interface{}{"window": "-10s", "threshold": 100}},
		{"negative_threshold", map[string]interface{}{"window": "60s", "threshold": -1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := detector.DetectorConfig{Enabled: true, Params: tc.params}
			_, err := detector.Build(context.Background(), "rate", cfg, nil)
			if err == nil {
				t.Fatalf("Build(rate, %s) expected error, got nil", tc.name)
			}
		})
	}
}

// TestRateDetector_ValidParams verifies that a valid rate detector is created and scores correctly.
func TestRateDetector_ValidParams(t *testing.T) {
	cfg := detector.DetectorConfig{
		Enabled: true,
		Params: map[string]interface{}{
			"window":    "60s",
			"threshold": 100,
			"score":     25,
		},
	}
	d, err := detector.Build(context.Background(), "rate", cfg, nil)
	if err != nil {
		t.Fatalf("Build(rate, valid) error: %v", err)
	}
	if d == nil {
		t.Fatal("Build(rate, valid) returned nil")
	}

	// Rate 0.5 req/s → no score
	svLow := newStubView(0, 0, nil, 0.5)
	result := d.Detect(svLow, &plugin.Event{Payload: &plugin.LogEntry{}})
	if result.Score != 0 {
		t.Errorf("low rate should not score, got %d", result.Score)
	}

	// Rate 100 req/s → score 25
	svHigh := newStubView(0, 0, nil, 100)
	result = d.Detect(svHigh, &plugin.Event{Payload: &plugin.LogEntry{}})
	if result.Score != 25 {
		t.Errorf("high rate should score 25, got %d", result.Score)
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
