// ========================== OverflowDetector tests ====================================
//   Table-driven tests: URL above/below limit, WAF bypass keywords,
//   case-insensitive, length + suspicious (length priority), enabled=false.
//
//   mockIPView is defined in rate_test.go — shared across all package tests.

package detector

import (
	"strings"
	"testing"

	"github.com/mr-addams/nginx-sentinel/internal/core/parser"
	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
)

func TestOverflowDetector(t *testing.T) {
	baseCfg := config.OverflowConfig{
		Enabled:          true,
		MaxURLLength:     100,
		SuspiciousParams: []string{"bypass", "shell", "cmd", "exec"},
		Score:            30,
	}

	tests := []struct {
		name      string
		cfg       config.OverflowConfig
		path      string
		query     string
		wantScore bool
		wantMsg   string // substring expected in Reason when triggered
	}{
		// ── Buffer overflow: URL length ───────────────────────────────────────────────────
		{
			name:      "URL 101 chars (> max=100) → triggers",
			cfg:       baseCfg,
			path:      "/" + strings.Repeat("a", 100),
			wantScore: true,
			wantMsg:   "overflow:url_len=",
		},
		{
			name:      "path=50 + query=60 → total=111 > 100 → triggers",
			cfg:       baseCfg,
			path:      "/" + strings.Repeat("p", 49),
			query:     strings.Repeat("q", 60),
			wantScore: true,
			wantMsg:   "overflow:url_len=",
		},
		{
			name:      "URL exactly 100 chars → no trigger (not exceeded)",
			cfg:       baseCfg,
			path:      "/" + strings.Repeat("a", 99),
			wantScore: false,
		},
		{
			name:      "short URL → no trigger",
			cfg:       baseCfg,
			path:      "/index.html",
			wantScore: false,
		},
		// ── WAF bypass: suspicious keywords ──────────────────────────────────────────────
		{
			name:      "/?cmd=whoami → triggers",
			cfg:       baseCfg,
			path:      "/",
			query:     "cmd=whoami",
			wantScore: true,
			wantMsg:   "overflow:waf_bypass=cmd",
		},
		{
			name:      "/exec in path → triggers",
			cfg:       baseCfg,
			path:      "/api/exec/run",
			wantScore: true,
			wantMsg:   "overflow:waf_bypass=exec",
		},
		{
			name:      "/?bypass=1 → triggers",
			cfg:       baseCfg,
			path:      "/login",
			query:     "bypass=1",
			wantScore: true,
			wantMsg:   "overflow:waf_bypass=bypass",
		},
		// ── Case-insensitive ──────────────────────────────────────────────────────────────
		{
			name:      "CMD in uppercase → triggers",
			cfg:       baseCfg,
			path:      "/",
			query:     "CMD=ls",
			wantScore: true,
			wantMsg:   "overflow:waf_bypass=cmd",
		},
		{
			name:      "SHELL in mixed case → triggers",
			cfg:       baseCfg,
			path:      "/",
			query:     "Shell=/bin/bash",
			wantScore: true,
			wantMsg:   "overflow:waf_bypass=shell",
		},
		// ── Priority: length is checked first ────────────────────────────────────────────
		{
			// URL is long AND contains a suspicious param — returns overflow:url_len
			name:      "long URL with suspicious param → overflow:url_len (length priority)",
			cfg:       baseCfg,
			path:      "/" + strings.Repeat("x", 99),
			query:     "cmd=test",
			wantScore: true,
			wantMsg:   "overflow:url_len=",
		},
		// ── Normal URL ────────────────────────────────────────────────────────────────────
		{
			name:      "normal request → no trigger",
			cfg:       baseCfg,
			path:      "/products",
			query:     "page=1&sort=name",
			wantScore: false,
		},
		{
			name:      "empty path → no trigger",
			cfg:       baseCfg,
			path:      "/",
			wantScore: false,
		},
		// ── enabled=false ─────────────────────────────────────────────────────────────────
		{
			name: "disabled: long URL does not trigger",
			cfg: config.OverflowConfig{
				Enabled:          false,
				MaxURLLength:     100,
				SuspiciousParams: []string{"cmd"},
				Score:            30,
			},
			path:      "/" + strings.Repeat("a", 200),
			wantScore: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewOverflowDetector(tt.cfg)
			mv := &mockIPView{}
			entry := &parser.LogEntry{Path: tt.path, Query: tt.query}
			result := d.Detect(mv, entry)

			if tt.wantScore && result.Score == 0 {
				t.Errorf("expected Score > 0, got 0 (path=%q query=%q)", tt.path, tt.query)
			}
			if !tt.wantScore && result.Score != 0 {
				t.Errorf("expected Score = 0, got %d (path=%q query=%q)",
					result.Score, tt.path, tt.query)
			}
			if result.Score > 0 {
				if result.Module != "overflow" {
					t.Errorf("Module = %q, expected %q", result.Module, "overflow")
				}
				if tt.wantMsg != "" && !strings.Contains(result.Reason, tt.wantMsg) {
					t.Errorf("Reason = %q, expected substring %q", result.Reason, tt.wantMsg)
				}
			}
		})
	}
}
