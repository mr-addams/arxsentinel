// ========================== Тесты ProbeDetector =======================================
//   Табличные тесты: exact-match, prefix-match, безобидные пути, enabled=false, пустой pathSet.
//
//   mockIPView определён в rate_test.go — общий для всех тестов пакета.

package detector

import (
	"testing"

	"github.com/mr-addams/nginx-sentinel/internal/core/parser"
	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
)

func TestProbeDetector(t *testing.T) {
	// Базовый конфиг для большинства тестов: exact-paths + prefix-paths, enabled.
	baseCfg := config.ProbeConfig{
		Enabled: true,
		Score:   25,
		Paths: []string{
			"/.env",
			"/wp-config.php",
			"/.git/config",
			"/wp-admin/", // prefix: ловит /wp-admin/anything
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
			name:      "exact: /.env срабатывает",
			cfg:       baseCfg,
			path:      "/.env",
			wantScore: true,
		},
		{
			name:      "exact: /wp-config.php срабатывает",
			cfg:       baseCfg,
			path:      "/wp-config.php",
			wantScore: true,
		},
		{
			name:      "exact: /.git/config срабатывает",
			cfg:       baseCfg,
			path:      "/.git/config",
			wantScore: true,
		},
		// ── Prefix-match ──────────────────────────────────────────────────────────────────
		{
			name:      "prefix: /wp-admin/options.php срабатывает (prefix /wp-admin/)",
			cfg:       baseCfg,
			path:      "/wp-admin/options.php",
			wantScore: true,
		},
		{
			name:      "prefix: /wp-admin/ срабатывает (точный prefix-путь)",
			cfg:       baseCfg,
			path:      "/wp-admin/",
			wantScore: true,
		},
		{
			name:      "prefix: /actuator/env срабатывает (prefix /actuator/)",
			cfg:       baseCfg,
			path:      "/actuator/env",
			wantScore: true,
		},
		// ── Безобидные пути ───────────────────────────────────────────────────────────────
		{
			name:      "безобидный: /index.html не срабатывает",
			cfg:       baseCfg,
			path:      "/index.html",
			wantScore: false,
		},
		{
			name:      "безобидный: /api/users не срабатывает",
			cfg:       baseCfg,
			path:      "/api/users",
			wantScore: false,
		},
		{
			name:      "безобидный: / не срабатывает",
			cfg:       baseCfg,
			path:      "/",
			wantScore: false,
		},
		{
			name:      "безобидный: /wp-config.php.bak не срабатывает (нет точного совпадения)",
			cfg:       baseCfg,
			path:      "/wp-config.php.bak",
			wantScore: false,
		},
		// ── enabled=false ─────────────────────────────────────────────────────────────────
		// Детектор отключён — не должен срабатывать ни на какой путь.
		{
			name: "disabled: /.env не срабатывает при enabled=false",
			cfg: config.ProbeConfig{
				Enabled: false,
				Score:   25,
				Paths:   []string{"/.env"},
			},
			path:      "/.env",
			wantScore: false,
		},
		{
			name: "disabled: /wp-admin/login.php не срабатывает при enabled=false",
			cfg: config.ProbeConfig{
				Enabled: false,
				Score:   25,
				Paths:   []string{"/wp-admin/"},
			},
			path:      "/wp-admin/login.php",
			wantScore: false,
		},
		// ── Пустой pathSet ────────────────────────────────────────────────────────────────
		// Пустой список путей — ни один запрос не должен срабатывать.
		{
			name: "пустой pathSet: /.env не срабатывает",
			cfg: config.ProbeConfig{
				Enabled: true,
				Score:   25,
				Paths:   []string{},
			},
			path:      "/.env",
			wantScore: false,
		},
		{
			name: "пустой pathSet: /api/data не срабатывает",
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
				t.Errorf("ожидали Score > 0, получили 0 (path=%q)", tt.path)
			}
			if !tt.wantScore && result.Score != 0 {
				t.Errorf("ожидали Score = 0, получили %d (path=%q)", result.Score, tt.path)
			}
			// При срабатывании Module и Reason должны быть заполнены
			if result.Score > 0 {
				if result.Module != "probe" {
					t.Errorf("Module = %q, ожидали %q", result.Module, "probe")
				}
				if result.Reason == "" {
					t.Error("Reason пустой при Score > 0")
				}
			}
		})
	}
}
