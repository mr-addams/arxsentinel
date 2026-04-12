// ========================== Детектор probe ==============================================
//   Детекция запросов к чувствительным путям: .env, .git, wp-config, aws-exports и т.д.
//   Один совпавший путь = фиксированный штраф к score IP.
//
//   ЧТО ЗДЕСЬ:
//     - ProbeDetector — структура с предкомпилированным set путей
//     - NewProbeDetector(cfg) — инициализация из конфига
//     - Detect() — O(1) exact-match + linear prefix-match
//
//   АЛГОРИТМ:
//     1. Exact match в map[string]struct{} — O(1), покрывает статичные пути (.env, wp-config.php)
//     2. Prefix match — ловит /wp-admin/page.php, /actuator/env и т.д.
//     Пути с "/" на конце в конфиге → prefix-проверка.
//     Все остальные → exact-match map.
//
//   ПОЧЕМУ MAP, А НЕ SLICE:
//     map[string]struct{} для exact-match: O(1) lookup, легко расширять —
//     добавление нового пути в конфиг не требует правки кода.
//
//   Реализовано: Task 4.1.

package detector

import (
	"strings"

	"github.com/mr-addams/nginx-sentinel/internal/core/parser"
	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
)

// ========================== ProbeDetector =============================================

// ProbeDetector детектирует запросы к чувствительным путям.
//
// Жизненный цикл:
//   nil              → до вызова NewProbeDetector
//   *ProbeDetector   → после NewProbeDetector, используется всё время жизни демона
//   перестройка      → при SIGHUP (Task 7.1) — создаётся новый экземпляр из нового конфига
type ProbeDetector struct {
	score    int
	pathSet  map[string]struct{} // exact-match paths: O(1) lookup
	prefixes []string            // prefix paths (с "/" на конце): ловит любой подпуть
	enabled  bool
}

// NewProbeDetector создаёт ProbeDetector из конфига.
// Разбивает пути: с "/" на конце → prefixes (prefix-match), остальные → pathSet (exact-match).
// Вызывается из main.go при старте и SIGHUP.
func NewProbeDetector(cfg config.ProbeConfig) *ProbeDetector {
	pathSet := make(map[string]struct{}, len(cfg.Paths))
	var prefixes []string

	for _, p := range cfg.Paths {
		if strings.HasSuffix(p, "/") {
			// /wp-admin/, /actuator/ — prefix-проверка ловит любой подпуть
			prefixes = append(prefixes, p)
		} else {
			pathSet[p] = struct{}{}
		}
	}

	return &ProbeDetector{
		score:    cfg.Score,
		pathSet:  pathSet,
		prefixes: prefixes,
		enabled:  cfg.Enabled,
	}
}

// Name возвращает идентификатор детектора для логов и threat-записей.
func (d *ProbeDetector) Name() string { return "probe" }

// Detect проверяет путь запроса на совпадение с чувствительными путями.
//
// Порядок: exact match → prefix match.
// Exact match первым: O(1) и покрывает большинство статичных чувствительных путей.
// Prefix match вторым: O(n) по числу prefix-путей, ловит подпути (/wp-admin/login.php).
//
// entry.Path уже без query string — парсер разделил на Path + Query.
func (d *ProbeDetector) Detect(sv IPView, entry *parser.LogEntry) DetectResult {
	if !d.enabled {
		return DetectResult{}
	}

	path := entry.Path

	// ── Exact match ───────────────────────────────────────────────────────────────────
	if _, ok := d.pathSet[path]; ok {
		return DetectResult{
			Score:  d.score,
			Module: "probe",
			Reason: "probe:" + path,
		}
	}

	// ── Prefix match ──────────────────────────────────────────────────────────────────
	// /wp-admin/ в конфиге → срабатывает на /wp-admin/options-general.php, /wp-admin/ и т.д.
	for _, prefix := range d.prefixes {
		if strings.HasPrefix(path, prefix) {
			return DetectResult{
				Score:  d.score,
				Module: "probe",
				Reason: "probe:" + path,
			}
		}
	}

	return DetectResult{}
}
