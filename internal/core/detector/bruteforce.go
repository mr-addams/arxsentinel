// ========================== Детектор bruteforce =========================================
//   Детекция аномального процента 404-ответов с одного IP (404 ratio).
//   Симптом сканирования несуществующих путей / перебора директорий.
//
//   ЧТО ЗДЕСЬ:
//     - BruteforceDetector — структура с параметрами из конфига
//     - NewBruteforceDetector(cfg) — инициализация
//     - Detect() — проверяет отношение Requests404 / TotalRequests
//
//   АЛГОРИТМ:
//     ratio = Requests404 / TotalRequests
//     Если TotalRequests >= MinRequests && ratio >= RatioThreshold → score += Score.
//
//     Порог MinRequests защищает от ложных срабатываний при малом числе запросов:
//     один 404 у нового IP не означает brute-force.
//
//   ПОЧЕМУ RATIO, А НЕ АБСОЛЮТНОЕ ЧИСЛО 404:
//     Абсолютный счётчик не учитывает интенсивность трафика — IP с 60 запросами
//     и 40 404 (67%) опаснее IP с 200 запросами и 40 404 (20%).
//
//   ДАННЫЕ ИЗ IPVIEW:
//     GetTotalRequests() — суммарно запросов к IP, реализуется *state.IPState.TotalRequests.
//     GetRequests404()   — счётчик 404-ответов, реализуется *state.IPState.Requests404.
//
//   Реализовано: Task 6.1.

package detector

import (
	"fmt"

	"github.com/mr-addams/nginx-sentinel/internal/core/parser"
	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
)

// ========================== BruteforceDetector ========================================

// BruteforceDetector детектирует аномальный процент 404-ответов с одного IP.
type BruteforceDetector struct {
	enabled        bool
	minRequests    int
	ratioThreshold float64
	score          int
}

// NewBruteforceDetector создаёт BruteforceDetector из конфига.
// Вызывается из main.go при старте и SIGHUP.
func NewBruteforceDetector(cfg config.BruteforceConfig) *BruteforceDetector {
	return &BruteforceDetector{
		enabled:        cfg.Enabled,
		minRequests:    cfg.MinRequests,
		ratioThreshold: cfg.RatioThreshold,
		score:          cfg.Score,
	}
}

// Name возвращает идентификатор детектора.
func (d *BruteforceDetector) Name() string { return "bruteforce" }

// Detect проверяет долю 404 ответов в суммарных запросах IP.
//
// MinRequests снижает чувствительность на начальном накоплении данных:
// первые несколько запросов IP с 100% 404 — не аномалия, а шум.
func (d *BruteforceDetector) Detect(sv IPView, entry *parser.LogEntry) DetectResult {
	if !d.enabled {
		return DetectResult{}
	}

	total := sv.GetTotalRequests()
	if total < d.minRequests {
		return DetectResult{}
	}

	ratio := float64(sv.GetRequests404()) / float64(total)
	if ratio < d.ratioThreshold {
		return DetectResult{}
	}

	return DetectResult{
		Score:  d.score,
		Module: "bruteforce",
		Reason: fmt.Sprintf("bruteforce:404=%.0f%%(%d/%d)", ratio*100, sv.GetRequests404(), total),
	}
}
