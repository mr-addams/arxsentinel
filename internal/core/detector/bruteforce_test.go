// ========================== Тесты BruteforceDetector ==================================
//   Табличные тесты: ratio выше/ниже порога, недостаточно запросов, enabled=false,
//   граничные значения (ровно на пороге, нулевой счётчик 404).
//
//   mockIPView определён в rate_test.go — общий для всех тестов пакета.

package detector

import (
	"testing"

	"github.com/mr-addams/nginx-sentinel/internal/core/parser"
	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
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
		// ── Выше порога ───────────────────────────────────────────────────────────────────
		{
			name:          "70% 404 из 20 запросов → срабатывает",
			cfg:           baseCfg,
			totalRequests: 20,
			requests404:   14, // 70% > 60%
			wantScore:     true,
		},
		{
			name:          "100% 404 из 10 запросов → срабатывает",
			cfg:           baseCfg,
			totalRequests: 10,
			requests404:   10,
			wantScore:     true,
		},
		// ── Ровно на пороге ───────────────────────────────────────────────────────────────
		{
			name:          "ровно 60% 404 из 100 запросов → срабатывает (>= threshold)",
			cfg:           baseCfg,
			totalRequests: 100,
			requests404:   60,
			wantScore:     true,
		},
		// ── Ниже порога ───────────────────────────────────────────────────────────────────
		{
			name:          "50% 404 из 20 запросов → не срабатывает",
			cfg:           baseCfg,
			totalRequests: 20,
			requests404:   10, // 50% < 60%
			wantScore:     false,
		},
		{
			name:          "0% 404 из 50 запросов → не срабатывает",
			cfg:           baseCfg,
			totalRequests: 50,
			requests404:   0,
			wantScore:     false,
		},
		// ── Недостаточно запросов ────────────────────────────────────────────────────────
		// Guard против ложных срабатываний на малом количестве запросов.
		{
			name:          "9 запросов (< min_requests=10) → не срабатывает",
			cfg:           baseCfg,
			totalRequests: 9,
			requests404:   9, // 100%, но меньше MinRequests
			wantScore:     false,
		},
		{
			name:          "0 запросов → не срабатывает",
			cfg:           baseCfg,
			totalRequests: 0,
			requests404:   0,
			wantScore:     false,
		},
		// ── enabled=false ─────────────────────────────────────────────────────────────────
		{
			name: "disabled: 80% 404 не срабатывает при enabled=false",
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
				t.Errorf("ожидали Score > 0, получили 0 (total=%d 404=%d)",
					tt.totalRequests, tt.requests404)
			}
			if !tt.wantScore && result.Score != 0 {
				t.Errorf("ожидали Score = 0, получили %d (total=%d 404=%d)",
					result.Score, tt.totalRequests, tt.requests404)
			}
			if result.Score > 0 {
				if result.Module != "bruteforce" {
					t.Errorf("Module = %q, ожидали %q", result.Module, "bruteforce")
				}
				if result.Reason == "" {
					t.Error("Reason пустой при Score > 0")
				}
			}
		})
	}
}
