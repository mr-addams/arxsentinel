// ========================== Тесты RateDetector ========================================
//   Табличные тесты: выше/ниже порога, window=0, enabled=false.
//
//   mockIPView — локальный мок IPView для всех тестов пакета detector.
//   Реализует интерфейс IPView через набор полей — без сложных зависимостей от state/.

package detector

import (
	"testing"
	"time"

	"github.com/mr-addams/nginx-sentinel/internal/core/parser"
	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
)

// ========================== Mock IPView ===============================================

// mockIPView реализует IPView для тестов детекторов.
// Поля напрямую управляют возвращаемыми значениями — без логики state.
type mockIPView struct {
	ip            string
	totalRequests int
	requests404   int
	recentPaths   []string
	approxRate    float64 // значение, которое вернёт ApproxRate при любом window
}

func (m *mockIPView) GetIP() string               { return m.ip }
func (m *mockIPView) GetTotalRequests() int        { return m.totalRequests }
func (m *mockIPView) GetRequests404() int          { return m.requests404 }
func (m *mockIPView) RecentPaths() []string        { return m.recentPaths }
func (m *mockIPView) ApproxRate(_ time.Duration) float64 { return m.approxRate }

// ========================== TestRateDetector ==========================================

func TestRateDetector(t *testing.T) {
	// Базовый конфиг: окно 60s, порог 100 req → thresholdRPS = 100/60 ≈ 1.67 rps
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
		// ── Выше порога ───────────────────────────────────────────────────────────────────
		{
			name:      "rate выше порога: срабатывает",
			cfg:       baseCfg,
			rate:      3.0, // 3 rps > 1.67 rps (порог 100 req/60s)
			wantScore: true,
		},
		{
			name:      "rate равен порогу: срабатывает (≥ threshold)",
			cfg:       baseCfg,
			rate:      100.0 / 60.0, // ровно порог
			wantScore: true,
		},
		// ── Ниже порога ───────────────────────────────────────────────────────────────────
		{
			name:      "rate ниже порога: не срабатывает",
			cfg:       baseCfg,
			rate:      1.0, // 1 rps < 1.67 rps
			wantScore: false,
		},
		{
			name:      "rate=0: не срабатывает",
			cfg:       baseCfg,
			rate:      0,
			wantScore: false,
		},
		// ── window=0 → детектор отключён ──────────────────────────────────────────────────
		// Guard в NewRateDetector: нулевое окно → enabled=false, избегаем деления на 0.
		{
			name: "window=0: всегда Score=0",
			cfg: config.RateConfig{
				Enabled:   true,
				Window:    config.Duration(0),
				Threshold: 100,
				Score:     25,
			},
			rate:      1000.0, // высокий rate — но детектор должен быть отключён
			wantScore: false,
		},
		// ── enabled=false ─────────────────────────────────────────────────────────────────
		{
			name: "disabled: высокий rate не срабатывает при enabled=false",
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
				t.Errorf("ожидали Score > 0, получили 0 (rate=%.2f)", tt.rate)
			}
			if !tt.wantScore && result.Score != 0 {
				t.Errorf("ожидали Score = 0, получили %d (rate=%.2f)", result.Score, tt.rate)
			}
			// При срабатывании Module и Reason должны быть заполнены
			if result.Score > 0 {
				if result.Module != "rate" {
					t.Errorf("Module = %q, ожидали %q", result.Module, "rate")
				}
				if result.Reason == "" {
					t.Error("Reason пустой при Score > 0")
				}
			}
		})
	}
}
