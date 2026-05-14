// ========================== ProbeDetector tests =======================================
//   Table-driven tests: exact-match, prefix-match, harmless paths, enabled=false, empty pathSet.
//
//   mockIPView is defined in rate_test.go — shared across all package tests.

package detector

import (
	"testing"

	"github.com/mr-addams/nginx-sentinel/internal/core/parser"
	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
)

func TestProbeDetector(t *testing.T) {
	// Base config for most tests: exact-paths + prefix-paths, enabled.
	baseCfg := config.ProbeConfig{
		Enabled: true,
		Score:   25,
		Paths: []string{
			"/.env",
			"/wp-config.php",
			"/.git/config",
			"/wp-admin/", // prefix: catches /wp-admin/anything
			"/actuator/", // prefix: Spring Boot actuator endpoints
		},
	}

	tests := []struct {
		name      string
		cfg       config.ProbeConfig
		path      string
		wantScore bool // true = Score > 0
	}{
		// ── Exact-match ───────────────────────────────────────────────────────────────────
		{
			name:      "exact: /.env triggers",
			cfg:       baseCfg,
			path:      "/.env",
			wantScore: true,
		},
		{
			name:      "exact: /wp-config.php triggers",
			cfg:       baseCfg,
			path:      "/wp-config.php",
			wantScore: true,
		},
		{
			name:      "exact: /.git/config triggers",
			cfg:       baseCfg,
			path:      "/.git/config",
			wantScore: true,
		},
		// ── Prefix-match ──────────────────────────────────────────────────────────────────
		{
			name:      "prefix: /wp-admin/options.php triggers (prefix /wp-admin/)",
			cfg:       baseCfg,
			path:      "/wp-admin/options.php",
			wantScore: true,
		},
		{
			name:      "prefix: /wp-admin/ triggers (exact prefix path)",
			cfg:       baseCfg,
			path:      "/wp-admin/",
			wantScore: true,
		},
		{
			name:      "prefix: /actuator/env triggers (prefix /actuator/)",
			cfg:       baseCfg,
			path:      "/actuator/env",
			wantScore: true,
		},
		// ── Harmless paths ────────────────────────────────────────────────────────────────
		{
			name:      "harmless: /index.html does not trigger",
			cfg:       baseCfg,
			path:      "/index.html",
			wantScore: false,
		},
		{
			name:      "harmless: /api/users does not trigger",
			cfg:       baseCfg,
			path:      "/api/users",
			wantScore: false,
		},
		{
			name:      "harmless: / does not trigger",
			cfg:       baseCfg,
			path:      "/",
			wantScore: false,
		},
		{
			name:      "harmless: /wp-config.php.bak does not trigger (no exact match)",
			cfg:       baseCfg,
			path:      "/wp-config.php.bak",
			wantScore: false,
		},
		// ── enabled=false ─────────────────────────────────────────────────────────────────
		// Detector is disabled — must not trigger on any path.
		{
			name: "disabled: /.env does not trigger when enabled=false",
			cfg: config.ProbeConfig{
				Enabled: false,
				Score:   25,
				Paths:   []string{"/.env"},
			},
			path:      "/.env",
			wantScore: false,
		},
		{
			name: "disabled: /wp-admin/login.php does not trigger when enabled=false",
			cfg: config.ProbeConfig{
				Enabled: false,
				Score:   25,
				Paths:   []string{"/wp-admin/"},
			},
			path:      "/wp-admin/login.php",
			wantScore: false,
		},
		// ── Empty pathSet ─────────────────────────────────────────────────────────────────
		// Empty path list — no request should trigger.
		{
			name: "empty pathSet: /.env does not trigger",
			cfg: config.ProbeConfig{
				Enabled: true,
				Score:   25,
				Paths:   []string{},
			},
			path:      "/.env",
			wantScore: false,
		},
		{
			name: "empty pathSet: /api/data does not trigger",
			cfg: config.ProbeConfig{
				Enabled: true,
				Score:   25,
				Paths:   nil,
			},
			path:      "/api/data",
			wantScore: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewProbeDetector(tt.cfg)
			entry := &parser.LogEntry{Path: tt.path}
			mv := &mockIPView{}

			result := d.Detect(mv, entry)

			if tt.wantScore && result.Score == 0 {
				t.Errorf("expected Score > 0, got 0 (path=%q)", tt.path)
			}
			if !tt.wantScore && result.Score != 0 {
				t.Errorf("expected Score = 0, got %d (path=%q)", result.Score, tt.path)
			}
			// When triggered, Module and Reason must be populated
			if result.Score > 0 {
				if result.Module != "probe" {
					t.Errorf("Module = %q, expected %q", result.Module, "probe")
				}
				if result.Reason == "" {
					t.Error("Reason is empty when Score > 0")
				}
			}
		})
	}
}
