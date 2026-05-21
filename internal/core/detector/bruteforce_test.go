// ========================== BruteforceDetector tests ==================================
//   Table-driven tests: ratio above/below threshold, insufficient requests, enabled=false,
//   boundary values (exactly at threshold, zero 404 counter).
//
//   mockIPView is defined in rate_test.go — shared across all package tests.

package detector

import (
	"testing"

	"github.com/mr-addams/arxsentinel/internal/core/parser"
	"github.com/mr-addams/arxsentinel/internal/sys/config"
)

func TestBruteforceDetector(t *testing.T) {
	baseCfg := config.BruteforceConfig{
		Enabled:        true,
		MinRequests:    10,
		RatioThreshold: 0.6, // 60%
		Score:          30,
	}

	tests := []struct {
		name          string
		cfg           config.BruteforceConfig
		totalRequests int
		requests404   int
		wantScore     bool
	}{
		// ── Above threshold ───────────────────────────────────────────────────────────────
		{
			name:          "70% 404 out of 20 requests → triggers",
			cfg:           baseCfg,
			totalRequests: 20,
			requests404:   14, // 70% > 60%
			wantScore:     true,
		},
		{
			name:          "100% 404 out of 10 requests → triggers",
			cfg:           baseCfg,
			totalRequests: 10,
			requests404:   10,
			wantScore:     true,
		},
		// ── Exactly at threshold ──────────────────────────────────────────────────────────
		{
			name:          "exactly 60% 404 out of 100 requests → triggers (>= threshold)",
			cfg:           baseCfg,
			totalRequests: 100,
			requests404:   60,
			wantScore:     true,
		},
		// ── Below threshold ───────────────────────────────────────────────────────────────
		{
			name:          "50% 404 out of 20 requests → no trigger",
			cfg:           baseCfg,
			totalRequests: 20,
			requests404:   10, // 50% < 60%
			wantScore:     false,
		},
		{
			name:          "0% 404 out of 50 requests → no trigger",
			cfg:           baseCfg,
			totalRequests: 50,
			requests404:   0,
			wantScore:     false,
		},
		// ── Insufficient requests ─────────────────────────────────────────────────────────
		// Guard against false positives on low request counts.
		{
			name:          "9 requests (< min_requests=10) → no trigger",
			cfg:           baseCfg,
			totalRequests: 9,
			requests404:   9, // 100%, but below MinRequests
			wantScore:     false,
		},
		{
			name:          "0 requests → no trigger",
			cfg:           baseCfg,
			totalRequests: 0,
			requests404:   0,
			wantScore:     false,
		},
		// ── enabled=false ─────────────────────────────────────────────────────────────────
		{
			name: "disabled: 80% 404 does not trigger when enabled=false",
			cfg: config.BruteforceConfig{
				Enabled:        false,
				MinRequests:    10,
				RatioThreshold: 0.6,
				Score:          30,
			},
			totalRequests: 50,
			requests404:   40, // 80%
			wantScore:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewBruteforceDetector(tt.cfg)
			mv := &mockIPView{
				totalRequests: tt.totalRequests,
				requests404:   tt.requests404,
			}
			result := d.Detect(mv, &parser.LogEntry{})

			if tt.wantScore && result.Score == 0 {
				t.Errorf("expected Score > 0, got 0 (total=%d 404=%d)",
					tt.totalRequests, tt.requests404)
			}
			if !tt.wantScore && result.Score != 0 {
				t.Errorf("expected Score = 0, got %d (total=%d 404=%d)",
					result.Score, tt.totalRequests, tt.requests404)
			}
			if result.Score > 0 {
				if result.Module != "bruteforce" {
					t.Errorf("Module = %q, expected %q", result.Module, "bruteforce")
				}
				if result.Reason == "" {
					t.Error("Reason is empty when Score > 0")
				}
			}
		})
	}
}
