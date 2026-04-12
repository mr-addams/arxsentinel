// ========================== Детектор rate ===============================================
//   Детекция аномального всплеска запросов: N запросов за скользящее окно.
//   Алгоритм ApproxRate (two-counter sliding window) реализован в state.IPState.
//
//   ЧТО ЗДЕСЬ:
//     - RateDetector — структура с порогами из конфига
//     - NewRateDetector(cfg) — инициализация, преобразование порога
//     - Detect() — сравнивает sv.ApproxRate(window) с thresholdRPS
//
//   ПОРОГ В RPS:
//     cfg.Threshold задан в запросах за окно (например: 100 req / 60s).
//     ApproxRate возвращает запросов/сек за окно.
//     Преобразование: thresholdRPS = Threshold / window.Seconds() — один раз в NewRateDetector.
//     На hot path — только float64 сравнение.
//
//   СОГЛАСОВАННОСТЬ С TRACKER:
//     window должен совпадать с detectors.rate.window из конфига —
//     оба (Tracker.rateWindow и RateDetector.window) читают из cfg.Detectors.Rate.Window.
//
//   Реализовано: Task 4.2.

package detector

import (
	"fmt"
	"time"

	"github.com/mr-addams/nginx-sentinel/internal/core/parser"
	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
)

// ========================== RateDetector ==============================================

// RateDetector детектирует аномальный rate запросов за скользящее окно.
//
// Жизненный цикл:
//   nil            → до вызова NewRateDetector
//   *RateDetector  → после NewRateDetector, используется всё время жизни демона
//   перестройка    → при SIGHUP (Task 7.1) — создаётся новый экземпляр
type RateDetector struct {
	thresholdRPS float64       // порог в req/s: cfg.Threshold / window.Seconds()
	window       time.Duration // окно ApproxRate — должно совпадать с state.Tracker.rateWindow
	score        int
	enabled      bool
}

// NewRateDetector создаёт RateDetector из конфига.
// Преобразует Threshold (req/window) → thresholdRPS (req/s) один раз при старте.
// При нулевом или отрицательном window — отключает детектор: деление на 0 даёт +Inf/NaN,
// что приводит к тому что детектор либо никогда не срабатывает, либо срабатывает всегда.
// Вызывается из main.go при старте и SIGHUP.
func NewRateDetector(cfg config.RateConfig) *RateDetector {
	window := time.Duration(cfg.Window)

	// Guard: нулевое окно делает thresholdRPS = +Inf (Threshold>0) или NaN (Threshold=0).
	// Оба варианта — silent misconfiguration: детектор или не срабатывает никогда,
	// или срабатывает всегда. Отключаем явно, чтобы не пропустить атаку без предупреждения.
	if window <= 0 {
		return &RateDetector{enabled: false}
	}

	// Порог в req/s: выносим деление из hot path — Detect вызывается на каждой строке лога
	thresholdRPS := float64(cfg.Threshold) / window.Seconds()
	return &RateDetector{
		thresholdRPS: thresholdRPS,
		window:       window,
		score:        cfg.Score,
		enabled:      cfg.Enabled,
	}
}

// Name возвращает идентификатор детектора.
func (d *RateDetector) Name() string { return "rate" }

// Detect сравнивает ApproxRate IP с порогом.
//
// ApproxRate(window) — приближённый rate за последнее window (±10% относительно точного).
// Погрешность приемлема: лучше редкий ложный WARN чем пропущенная DDoS-атака.
// Reason содержит фактический rate для диагностики в threat-логе.
func (d *RateDetector) Detect(sv IPView, entry *parser.LogEntry) DetectResult {
	if !d.enabled {
		return DetectResult{}
	}

	rate := sv.ApproxRate(d.window)
	if rate < d.thresholdRPS {
		return DetectResult{}
	}

	return DetectResult{
		Score:  d.score,
		Module: "rate",
		Reason: fmt.Sprintf("rate:%.0frps", rate),
	}
}
