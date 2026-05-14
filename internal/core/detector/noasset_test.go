// ========================== NoAssetDetector tests =====================================
//   Table-driven tests: pages only (no assets), mix of pages and assets,
//   many assets (legitimate browser), insufficient pages, enabled=false.
//
//   mockIPView is defined in rate_test.go — shared across all package tests.

package detector

import (
	"testing"

	"github.com/mr-addams/nginx-sentinel/internal/core/parser"
	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
)

var baseNoAssetCfg = config.NoAssetConfig{
	Enabled:             true,
	MinPageRequests:     3,
	AssetRatioThreshold: 0.1, // < 10% assets → bot
	AssetExtensions:     []string{".css", ".js", ".png", ".jpg", ".ico", ".woff"},
	Score:               20,
}

func TestNoAssetDetector(t *testing.T) {
	tests := []struct {
		name        string
		cfg         config.NoAssetConfig
		recentPaths []string
		wantScore   bool
	}{
		// ── Pages only (bot without browser rendering) ────────────────────────────────────
		{
			name: "5 HTML pages, 0 assets → triggers",
			cfg:  baseNoAssetCfg,
			recentPaths: []string{
				"/", "/about", "/products", "/faq", "/contact",
			},
			wantScore: true,
		},
		{
			name: "pages with .html extension, 0 assets → triggers",
			cfg:  baseNoAssetCfg,
			recentPaths: []string{
				"/index.html", "/about.html", "/terms.html",
			},
			wantScore: true,
		},
		{
			name: "PHP pages without assets → triggers",
			cfg:  baseNoAssetCfg,
			recentPaths: []string{
				"/index.php", "/login.php", "/dashboard.php", "/profile.php",
			},
			wantScore: true,
		},
		// ── Legitimate browser — has assets ───────────────────────────────────────────────
		{
			name: "pages + CSS/JS → no trigger (browser loads resources)",
			cfg:  baseNoAssetCfg,
			recentPaths: []string{
				"/", "/style.css", "/app.js", "/logo.png",
				"/about", "/favicon.ico",
			},
			wantScore: false,
		},
		{
			name: "exactly at 10% asset threshold → no trigger (>= threshold)",
			cfg:  baseNoAssetCfg,
			recentPaths: []string{
				// 9 pages + 1 asset = 10% assets = threshold, no trigger
				"/", "/a", "/b", "/c", "/d", "/e", "/f", "/g", "/h", "/style.css",
			},
			wantScore: false,
		},
		// ── Insufficient pages ────────────────────────────────────────────────────────────
		{
			name: "only 2 pages (< min=3) → no trigger",
			cfg:  baseNoAssetCfg,
			recentPaths: []string{
				"/", "/about",
			},
			wantScore: false,
		},
		{
			name:        "empty list → no trigger",
			cfg:         baseNoAssetCfg,
			recentPaths: []string{},
			wantScore:   false,
		},
		// ── enabled=false ─────────────────────────────────────────────────────────────────
		{
			name: "disabled: pages only do not trigger when enabled=false",
			cfg: config.NoAssetConfig{
				Enabled:             false,
				MinPageRequests:     3,
				AssetRatioThreshold: 0.1,
				AssetExtensions:     []string{".css", ".js"},
				Score:               20,
			},
			recentPaths: []string{"/", "/about", "/contact", "/products"},
			wantScore:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewNoAssetDetector(tt.cfg)
			mv := &mockIPView{recentPaths: tt.recentPaths}
			result := d.Detect(mv, &parser.LogEntry{})

			if tt.wantScore && result.Score == 0 {
				t.Errorf("expected Score > 0, got 0 (paths=%v)", tt.recentPaths)
			}
			if !tt.wantScore && result.Score != 0 {
				t.Errorf("expected Score = 0, got %d (paths=%v)", result.Score, tt.recentPaths)
			}
			if result.Score > 0 {
				if result.Module != "noasset" {
					t.Errorf("Module = %q, expected %q", result.Module, "noasset")
				}
				if result.Reason == "" {
					t.Error("Reason is empty when Score > 0")
				}
			}
		})
	}
}

// ========================== isAsset tests =============================================

func TestIsAsset(t *testing.T) {
	d := NewNoAssetDetector(baseNoAssetCfg)

	tests := []struct {
		path string
		want bool
	}{
		{"/style.css", true},
		{"/app.js", true},
		{"/logo.png", true},
		{"/image.jpg", true},
		{"/favicon.ico", true},
		{"/font.woff", true},
		{"/", false},
		{"/about", false},
		{"/index.html", false},
		{"/login.php", false},
		{"/api/data.json", false}, // .json is not in AssetExtensions
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := d.isAsset(tt.path)
			if got != tt.want {
				t.Errorf("isAsset(%q) = %v, expected %v", tt.path, got, tt.want)
			}
		})
	}
}
