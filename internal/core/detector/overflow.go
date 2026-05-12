// ========================== Детектор overflow ============================================
//   Детекция попыток buffer overflow и WAF bypass:
//   аномальная длина URL, подозрительные ключевые слова в пути/параметрах.
//
//   ЧТО ЗДЕСЬ:
//     - OverflowDetector — структура с параметрами и нормализованным списком ключевых слов
//     - NewOverflowDetector(cfg) — инициализация, lowercase нормализация suspicious_params
//     - Detect() — проверяет длину URL и наличие ключевых слов
//
//   АЛГОРИТМ:
//     1. Собрать полный URL: Path + "?" + Query (если Query не пустой).
//     2. Если len(fullURL) > MaxURLLength → buffer overflow attempt, score.
//     3. Иначе: если fullURL содержит любой suspicious_params (case-insensitive) → WAF bypass, score.
//
//   ПОЧЕМУ ОДИН Score ДЛЯ ОБОИХ УСЛОВИЙ:
//     Оба индикатора (длина и suspicious params) предполагают один и тот же класс угрозы —
//     попытку обойти защиту или вызвать уязвимость. Разделять score нецелесообразно:
//     один детектор — одно решение. Разные scores → два детектора.
//
//   ИЗВЕСТНОЕ ОГРАНИЧЕНИЕ:
//     strings.Contains по всему URL может дать ложные срабатывания для коротких слов ("cmd").
//     Пример: /api/cmd/results срабатывает на "cmd". Score=30 и ban_threshold=80 означает,
//     что нужны 3+ независимых попадания прежде чем IP получит THREAT. Приемлемый компромисс
//     для обнаружения vs точности.
//
//   Реализовано: Task 6.4.

package detector

import (
	"fmt"
	"strings"

	"github.com/mr-addams/nginx-sentinel/internal/core/parser"
	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
)

// ========================== OverflowDetector ==========================================

// OverflowDetector детектирует попытки buffer overflow и WAF bypass через URL.
type OverflowDetector struct {
	enabled          bool
	maxURLLength     int
	suspiciousParams []string // lowercase-нормализованные
	score            int
}

// NewOverflowDetector создаёт OverflowDetector из конфига.
// Нормализует suspicious_params в lowercase один раз — на hot path только ToLower(URL).
// Вызывается из main.go при старте и SIGHUP.
func NewOverflowDetector(cfg config.OverflowConfig) *OverflowDetector {
	params := make([]string, len(cfg.SuspiciousParams))
	for i, p := range cfg.SuspiciousParams {
		params[i] = strings.ToLower(p)
	}
	return &OverflowDetector{
		enabled:          cfg.Enabled,
		maxURLLength:     cfg.MaxURLLength,
		suspiciousParams: params,
		score:            cfg.Score,
	}
}

// Name возвращает идентификатор детектора.
func (d *OverflowDetector) Name() string { return "overflow" }

// Detect проверяет текущий запрос на overflow и WAF bypass.
//
// Проверяется entry.Path + entry.Query — текущий запрос, не история IP.
// Первое совпадение возвращает результат: длина имеет приоритет (вероятнее целенаправленная атака).
func (d *OverflowDetector) Detect(sv IPView, entry *parser.LogEntry) DetectResult {
	if !d.enabled {
		return DetectResult{}
	}

	fullURL := entry.Path
	if entry.Query != "" {
		fullURL = entry.Path + "?" + entry.Query
	}

	// ── Buffer overflow: аномальная длина URL ─────────────────────────────────────────
	if len(fullURL) > d.maxURLLength {
		return DetectResult{
			Score:  d.score,
			Module: "overflow",
			Reason: fmt.Sprintf("overflow:url_len=%d", len(fullURL)),
		}
	}

	// ── WAF bypass: подозрительные ключевые слова ────────────────────────────────────
	lowerURL := strings.ToLower(fullURL)
	for _, param := range d.suspiciousParams {
		if strings.Contains(lowerURL, param) {
			return DetectResult{
				Score:  d.score,
				Module: "overflow",
				Reason: fmt.Sprintf("overflow:waf_bypass=%s", param),
			}
		}
	}

	return DetectResult{}
}
