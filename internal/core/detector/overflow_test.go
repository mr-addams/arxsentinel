// ========================== Тесты OverflowDetector ====================================
//   Табличные тесты: URL выше/ниже лимита, WAF bypass ключевые слова,
//   case-insensitive, длина + suspicious (приоритет длины), enabled=false.
//
//   mockIPView определён в rate_test.go — общий для всех тестов пакета.

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
		wantMsg   string // подстрока в Reason, если срабатывает
	}{
		// ── Buffer overflow: длина URL ────────────────────────────────────────────────────
		{
			name:      "URL 101 символ (> max=100) → срабатывает",
			cfg:       baseCfg,
			path:      "/" + strings.Repeat("a", 100),
			wantScore: true,
			wantMsg:   "overflow:url_len=",
		},
		{
			name:      "path=50 + query=60 → total=111 > 100 → срабатывает",
			cfg:       baseCfg,
			path:      "/" + strings.Repeat("p", 49),
			query:     strings.Repeat("q", 60),
			wantScore: true,
			wantMsg:   "overflow:url_len=",
		},
		{
			name:      "URL ровно 100 символов → не срабатывает (не превышение)",
			cfg:       baseCfg,
			path:      "/" + strings.Repeat("a", 99),
			wantScore: false,
		},
		{
			name:      "короткий URL → не срабатывает",
			cfg:       baseCfg,
			path:      "/index.html",
			wantScore: false,
		},
		// ── WAF bypass: подозрительные ключевые слова ────────────────────────────────────
		{
			name:      "/?cmd=whoami → срабатывает",
			cfg:       baseCfg,
			path:      "/",
			query:     "cmd=whoami",
			wantScore: true,
			wantMsg:   "overflow:waf_bypass=cmd",
		},
		{
			name:      "/exec в пути → срабатывает",
			cfg:       baseCfg,
			path:      "/api/exec/run",
			wantScore: true,
			wantMsg:   "overflow:waf_bypass=exec",
		},
		{
			name:      "/?bypass=1 → срабатывает",
			cfg:       baseCfg,
			path:      "/login",
			query:     "bypass=1",
			wantScore: true,
			wantMsg:   "overflow:waf_bypass=bypass",
		},
		// ── Case-insensitive ──────────────────────────────────────────────────────────────
		{
			name:      "CMD в верхнем регистре → срабатывает",
			cfg:       baseCfg,
			path:      "/",
			query:     "CMD=ls",
			wantScore: true,
			wantMsg:   "overflow:waf_bypass=cmd",
		},
		{
			name:      "SHELL в смешанном регистре → срабатывает",
			cfg:       baseCfg,
			path:      "/",
			query:     "Shell=/bin/bash",
			wantScore: true,
			wantMsg:   "overflow:waf_bypass=shell",
		},
		// ── Приоритет: длина проверяется первой ──────────────────────────────────────────
		{
			// URL длинный И содержит suspicious param — возвращаем overflow:url_len
			name:      "длинный URL с suspicious param → overflow:url_len (приоритет длины)",
			cfg:       baseCfg,
			path:      "/" + strings.Repeat("x", 99),
			query:     "cmd=test",
			wantScore: true,
			wantMsg:   "overflow:url_len=",
		},
		// ── Нормальный URL ────────────────────────────────────────────────────────────────
		{
			name:      "нормальный запрос → не срабатывает",
			cfg:       baseCfg,
			path:      "/products",
			query:     "page=1&sort=name",
			wantScore: false,
		},
		{
			name:      "пустой путь → не срабатывает",
			cfg:       baseCfg,
			path:      "/",
			wantScore: false,
		},
		// ── enabled=false ─────────────────────────────────────────────────────────────────
		{
			name: "disabled: длинный URL не срабатывает",
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
				t.Errorf("ожидали Score > 0, получили 0 (path=%q query=%q)", tt.path, tt.query)
			}
			if !tt.wantScore && result.Score != 0 {
				t.Errorf("ожидали Score = 0, получили %d (path=%q query=%q)",
					result.Score, tt.path, tt.query)
			}
			if result.Score > 0 {
				if result.Module != "overflow" {
					t.Errorf("Module = %q, ожидали %q", result.Module, "overflow")
				}
				if tt.wantMsg != "" && !strings.Contains(result.Reason, tt.wantMsg) {
					t.Errorf("Reason = %q, ожидали подстроку %q", result.Reason, tt.wantMsg)
				}
			}
		})
	}
}
