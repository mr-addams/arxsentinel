// ========================== UADetector tests ==========================================
//   Table-driven tests: scanner/grabber/automation/empty UA, normal browser, enabled=false.
//
//   mockIPView is defined in rate_test.go — shared across all package tests.

package detector

import (
	"strings"
	"testing"

	"github.com/mr-addams/arxsentinel/internal/core/parser"
	"github.com/mr-addams/arxsentinel/internal/sys/config"
)

func TestUADetector(t *testing.T) {
	// Base config with non-zero scores for each category.
	baseCfg := config.UserAgentConfig{
		Enabled:         true,
		ScannerScore:    40,
		GrabberScore:    20,
		AutomationScore: 15,
		EmptyUAScore:    30,
	}

	tests := []struct {
		name          string
		cfg           config.UserAgentConfig
		ua            string
		wantScore     bool
		wantMinScore  int    // minimum expected Score (0 if wantScore=false)
		wantReasonPfx string // Reason prefix (empty = not checked)
	}{
		// ── Scanners ──────────────────────────────────────────────────────────────────────
		{
			name:          "scanner: Nuclei/2.9.4 → ScannerScore",
			cfg:           baseCfg,
			ua:            "Nuclei/2.9.4",
			wantScore:     true,
			wantMinScore:  40,
			wantReasonPfx: "ua:scanner:",
		},
		{
			name:          "scanner: sqlmap/1.7.2 → ScannerScore",
			cfg:           baseCfg,
			ua:            "sqlmap/1.7.2#stable (https://sqlmap.org)",
			wantScore:     true,
			wantMinScore:  40,
			wantReasonPfx: "ua:scanner:",
		},
		{
			name:          "scanner: nikto/2.1 → ScannerScore",
			cfg:           baseCfg,
			ua:            "Mozilla/5.0 (Nikto/2.1.6)",
			wantScore:     true,
			wantMinScore:  40,
			wantReasonPfx: "ua:scanner:",
		},
		// ── Grabbers ──────────────────────────────────────────────────────────────────────
		{
			name:          "grabber: python-requests/2.28 → GrabberScore",
			cfg:           baseCfg,
			ua:            "python-requests/2.28.0",
			wantScore:     true,
			wantMinScore:  20,
			wantReasonPfx: "ua:grabber:",
		},
		{
			name:          "grabber: wget/1.21 → GrabberScore",
			cfg:           baseCfg,
			ua:            "Wget/1.21.3",
			wantScore:     true,
			wantMinScore:  20,
			wantReasonPfx: "ua:grabber:",
		},
		{
			name:          "grabber: Scrapy/2.6 → GrabberScore",
			cfg:           baseCfg,
			ua:            "Scrapy/2.6.1 (+https://scrapy.org)",
			wantScore:     true,
			wantMinScore:  20,
			wantReasonPfx: "ua:grabber:",
		},
		// ── Automation ────────────────────────────────────────────────────────────────────
		{
			name:          "automation: Go-http-client/1.1 → AutomationScore",
			cfg:           baseCfg,
			ua:            "Go-http-client/1.1",
			wantScore:     true,
			wantMinScore:  15,
			wantReasonPfx: "ua:automation:",
		},
		{
			name:          "automation: aiohttp/3.8 → AutomationScore",
			cfg:           baseCfg,
			ua:            "Python/3.10 aiohttp/3.8.1",
			wantScore:     true,
			wantMinScore:  15,
			wantReasonPfx: "ua:automation:",
		},
		// ── Empty UA ──────────────────────────────────────────────────────────────────────
		{
			name:          `empty: "" → EmptyUAScore`,
			cfg:           baseCfg,
			ua:            "",
			wantScore:     true,
			wantMinScore:  30,
			wantReasonPfx: "ua:empty",
		},
		{
			name:          `empty: "-" → EmptyUAScore`,
			cfg:           baseCfg,
			ua:            "-",
			wantScore:     true,
			wantMinScore:  30,
			wantReasonPfx: "ua:empty",
		},
		// ── Normal browser → Score=0 ──────────────────────────────────────────────────────
		{
			name:      "browser: Chrome does not trigger",
			cfg:       baseCfg,
			ua:        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			wantScore: false,
		},
		{
			name:      "browser: Firefox does not trigger",
			cfg:       baseCfg,
			ua:        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
			wantScore: false,
		},
		{
			name:      "browser: Safari does not trigger",
			cfg:       baseCfg,
			ua:        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
			wantScore: false,
		},
		// ── enabled=false ─────────────────────────────────────────────────────────────────
		{
			name: "disabled: Nuclei does not trigger when enabled=false",
			cfg: config.UserAgentConfig{
				Enabled:      false,
				ScannerScore: 40,
			},
			ua:        "Nuclei/2.9.4",
			wantScore: false,
		},
		{
			name: `disabled: "-" does not trigger when enabled=false`,
			cfg: config.UserAgentConfig{
				Enabled:      false,
				EmptyUAScore: 30,
			},
			ua:        "-",
			wantScore: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewUADetector(tt.cfg)
			entry := &parser.LogEntry{UserAgent: tt.ua}
			mv := &mockIPView{}

			result := d.Detect(mv, entry)

			if tt.wantScore && result.Score == 0 {
				t.Errorf("expected Score > 0, got 0 (ua=%q)", tt.ua)
			}
			if !tt.wantScore && result.Score != 0 {
				t.Errorf("expected Score = 0, got %d (ua=%q)", result.Score, tt.ua)
			}
			// Guard: wantMinScore=0 with wantScore=true — likely forgot to set it.
			if tt.wantScore && tt.wantMinScore == 0 {
				t.Fatalf("wantMinScore not set for case %q", tt.name)
			}
			if tt.wantScore && result.Score < tt.wantMinScore {
				t.Errorf("Score = %d, expected >= %d (ua=%q)", result.Score, tt.wantMinScore, tt.ua)
			}
			// Check Module and Reason only when triggered
			if result.Score > 0 {
				if result.Module != "ua" {
					t.Errorf("Module = %q, expected %q", result.Module, "ua")
				}
				if tt.wantReasonPfx != "" && !strings.HasPrefix(result.Reason, tt.wantReasonPfx) {
					t.Errorf("Reason = %q, expected prefix %q", result.Reason, tt.wantReasonPfx)
				}
			}
		})
	}
}
