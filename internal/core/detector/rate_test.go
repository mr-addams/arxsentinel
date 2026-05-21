// ========================== RateDetector tests ========================================
//   Table-driven tests: above/below threshold, window=0, enabled=false.
//
//   mockIPView — local mock IPView for all tests in the detector package.
//   Implements the IPView interface via plain fields — no complex dependencies on state/.

package detector

import (
	"testing"
	"time"

	"github.com/mr-addams/arxsentinel/internal/core/parser"
	"github.com/mr-addams/arxsentinel/internal/sys/config"
)

// ========================== Mock IPView ===============================================

// mockIPView implements IPView for detector tests.
// Fields directly control returned values — no state logic.
type mockIPView struct {
	ip            string
	totalRequests int
	requests404   int
	recentPaths   []string
	approxRate    float64 // value returned by ApproxRate for any window
}

func (m *mockIPView) GetIP() string               { return m.ip }
func (m *mockIPView) GetTotalRequests() int        { return m.totalRequests }
func (m *mockIPView) GetRequests404() int          { return m.requests404 }
func (m *mockIPView) RecentPaths() []string        { return m.recentPaths }
func (m *mockIPView) ApproxRate(_ time.Duration) float64 { return m.approxRate }

// ========================== TestRateDetector ==========================================

func TestRateDetector(t *testing.T) {
	// Base config: 60s window, threshold 100 req → thresholdRPS = 100/60 ≈ 1.67 rps
	baseCfg := config.RateConfig{
		Enabled:   true,
		Window:    config.Duration(60 * time.Second),
		Threshold: 100,
		Score:     25,
	}

	tests := []struct {
		name      string
		cfg       config.RateConfig
		rate      float64 // mockIPView.approxRate
		wantScore bool
	}{
		// ── Above threshold ───────────────────────────────────────────────────────────────
		{
			name:      "rate above threshold: triggers",
			cfg:       baseCfg,
			rate:      3.0, // 3 rps > 1.67 rps (threshold 100 req/60s)
			wantScore: true,
		},
		{
			name:      "rate equals threshold: triggers (>= threshold)",
			cfg:       baseCfg,
			rate:      100.0 / 60.0, // exactly the threshold
			wantScore: true,
		},
		// ── Below threshold ───────────────────────────────────────────────────────────────
		{
			name:      "rate below threshold: no trigger",
			cfg:       baseCfg,
			rate:      1.0, // 1 rps < 1.67 rps
			wantScore: false,
		},
		{
			name:      "rate=0: no trigger",
			cfg:       baseCfg,
			rate:      0,
			wantScore: false,
		},
		// ── window=0 → detector disabled ──────────────────────────────────────────────────
		// Guard in NewRateDetector: zero window → enabled=false, avoids division by zero.
		{
			name: "window=0: always Score=0",
			cfg: config.RateConfig{
				Enabled:   true,
				Window:    config.Duration(0),
				Threshold: 100,
				Score:     25,
			},
			rate:      1000.0, // high rate — but detector must be disabled
			wantScore: false,
		},
		// ── enabled=false ─────────────────────────────────────────────────────────────────
		{
			name: "disabled: high rate does not trigger when enabled=false",
			cfg: config.RateConfig{
				Enabled:   false,
				Window:    config.Duration(60 * time.Second),
				Threshold: 100,
				Score:     25,
			},
			rate:      999.0,
			wantScore: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewRateDetector(tt.cfg)
			mv := &mockIPView{approxRate: tt.rate}
			entry := &parser.LogEntry{}

			result := d.Detect(mv, entry)

			if tt.wantScore && result.Score == 0 {
				t.Errorf("expected Score > 0, got 0 (rate=%.2f)", tt.rate)
			}
			if !tt.wantScore && result.Score != 0 {
				t.Errorf("expected Score = 0, got %d (rate=%.2f)", result.Score, tt.rate)
			}
			// When triggered, Module and Reason must be populated
			if result.Score > 0 {
				if result.Module != "rate" {
					t.Errorf("Module = %q, expected %q", result.Module, "rate")
				}
				if result.Reason == "" {
					t.Error("Reason is empty when Score > 0")
				}
			}
		})
	}
}
