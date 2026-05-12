// ========================== Тесты NoAssetDetector =====================================
//   Табличные тесты: только страницы (нет ассетов), смесь страниц и ассетов,
//   много ассетов (легитимный браузер), недостаточно страниц, enabled=false.
//
//   mockIPView определён в rate_test.go — общий для всех тестов пакета.

package detector

import (
	"testing"

	"github.com/mr-addams/nginx-sentinel/internal/core/parser"
	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
)

var baseNoAssetCfg = config.NoAssetConfig{
	Enabled:             true,
	MinPageRequests:     3,
	AssetRatioThreshold: 0.1, // < 10% ассетов → бот
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
		// ── Только страницы (бот без браузерного рендеринга) ─────────────────────────────
		{
			name: "5 HTML-страниц, 0 ассетов → срабатывает",
			cfg:  baseNoAssetCfg,
			recentPaths: []string{
				"/", "/about", "/products", "/faq", "/contact",
			},
			wantScore: true,
		},
		{
			name: "страницы с .html расширением, 0 ассетов → срабатывает",
			cfg:  baseNoAssetCfg,
			recentPaths: []string{
				"/index.html", "/about.html", "/terms.html",
			},
			wantScore: true,
		},
		{
			name: "PHP-страницы без ассетов → срабатывает",
			cfg:  baseNoAssetCfg,
			recentPaths: []string{
				"/index.php", "/login.php", "/dashboard.php", "/profile.php",
			},
			wantScore: true,
		},
		// ── Легитимный браузер — есть ассеты ─────────────────────────────────────────────
		{
			name: "страницы + CSS/JS → не срабатывает (браузер загружает ресурсы)",
			cfg:  baseNoAssetCfg,
			recentPaths: []string{
				"/", "/style.css", "/app.js", "/logo.png",
				"/about", "/favicon.ico",
			},
			wantScore: false,
		},
		{
			name: "ровно на пороге 10% ассетов → не срабатывает (>= threshold)",
			cfg:  baseNoAssetCfg,
			recentPaths: []string{
				// 9 страниц + 1 ассет = 10% ассетов = порог, не срабатывает
				"/", "/a", "/b", "/c", "/d", "/e", "/f", "/g", "/h", "/style.css",
			},
			wantScore: false,
		},
		// ── Недостаточно страниц ─────────────────────────────────────────────────────────
		{
			name: "только 2 страницы (< min=3) → не срабатывает",
			cfg:  baseNoAssetCfg,
			recentPaths: []string{
				"/", "/about",
			},
			wantScore: false,
		},
		{
			name:        "пустой список → не срабатывает",
			cfg:         baseNoAssetCfg,
			recentPaths: []string{},
			wantScore:   false,
		},
		// ── enabled=false ─────────────────────────────────────────────────────────────────
		{
			name: "disabled: только страницы не срабатывают при enabled=false",
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
				t.Errorf("ожидали Score > 0, получили 0 (paths=%v)", tt.recentPaths)
			}
			if !tt.wantScore && result.Score != 0 {
				t.Errorf("ожидали Score = 0, получили %d (paths=%v)", result.Score, tt.recentPaths)
			}
			if result.Score > 0 {
				if result.Module != "noasset" {
					t.Errorf("Module = %q, ожидали %q", result.Module, "noasset")
				}
				if result.Reason == "" {
					t.Error("Reason пустой при Score > 0")
				}
			}
		})
	}
}

// ========================== Тесты isAsset =============================================

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
		{"/api/data.json", false}, // .json не в AssetExtensions
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := d.isAsset(tt.path)
			if got != tt.want {
				t.Errorf("isAsset(%q) = %v, ожидали %v", tt.path, got, tt.want)
			}
		})
	}
}
