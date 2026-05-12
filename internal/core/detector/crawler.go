// ========================== Детектор crawler ============================================
//   Детекция последовательного обхода URL по числовому паттерну.
//   Признак автоматического сканера контента.
//
//   ЧТО ЗДЕСЬ:
//     - CrawlerDetector — структура с параметрами из конфига
//     - NewCrawlerDetector(cfg) — инициализация
//     - Detect() — ищет числовые последовательности в RecentPaths
//
//   АЛГОРИТМ:
//     1. Для каждого пути из RecentPaths извлечь (prefix, num) через numericSuffixRE:
//        /page/5       → prefix="/page/",  num=5
//        /product/42   → prefix="/product/", num=42
//        /archive/2024 → prefix="/archive/", num=2024
//     2. Сгруппировать числа по prefix.
//     3. Если в группе найдена последовательность из MinSequential подряд идущих
//        целых чисел (после дедупликации и сортировки) → score += Score.
//
//   ПОЧЕМУ ЧИСЛОВАЯ ПОСЛЕДОВАТЕЛЬНОСТЬ:
//     Легитимные пользователи в отличие от краулеров не обходят страницы строго
//     последовательно. /page/1 → /page/2 → /page/3 → /page/4 → /page/5 за короткое
//     время — это паттерн автоматизации, а не органического просмотра.
//     MinSequential=5 снижает ложные срабатывания: пользователь редко пролистывает
//     5+ страниц подряд в одном числовом диапазоне.
//
//   ОГРАНИЧЕНИЕ:
//     Анализируется только последние 64 пути (кольцевой буфер pathBuf в IPState).
//     Краулер с окном > 64 уникальных URL не детектируется — приемлемо,
//     т.к. такой трафик поймает RateDetector.
//
//   Реализовано: Task 6.2.

package detector

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"

	"github.com/mr-addams/nginx-sentinel/internal/core/parser"
	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
)

// numericSuffixRE извлекает (prefix, digits) из URL-пути где ПОСЛЕДНИЙ сегмент — чистое число.
//
// Паттерн: `(.*/|/)` требует разделитель `/` непосредственно перед числом,
// что исключает slug-числа вида `/api/v2` или `/item5`.
// Примеры совпадений:
//
//	/page/5    → prefix="/page/",    num="5"
//	/items/12  → prefix="/items/",   num="12"
//	/5         → prefix="/",         num="5"
//
// Примеры несовпадений (slug-числа — не отдельный сегмент):
//
//	/api/v2    → нет (v2 — не отдельный числовой сегмент)
//	/item5     → нет (5 — суффикс slug, не отдельный сегмент)
//	/foo       → нет (нет числовых сегментов)
var numericSuffixRE = regexp.MustCompile(`^(.*/|/)(\d+)/?$`)

// ========================== CrawlerDetector ===========================================

// CrawlerDetector детектирует последовательный числовой обход URL.
type CrawlerDetector struct {
	enabled       bool
	minSequential int
	score         int
}

// NewCrawlerDetector создаёт CrawlerDetector из конфига.
// Вызывается из main.go при старте и SIGHUP.
func NewCrawlerDetector(cfg config.CrawlerConfig) *CrawlerDetector {
	return &CrawlerDetector{
		enabled:       cfg.Enabled,
		minSequential: cfg.MinSequential,
		score:         cfg.Score,
	}
}

// Name возвращает идентификатор детектора.
func (d *CrawlerDetector) Name() string { return "crawler" }

// Detect ищет числовые последовательности в истории путей IP.
//
// Вызывается на каждой строке лога — только при наличии достаточного
// числа путей в RecentPaths (>= MinSequential) запускает поиск паттерна.
func (d *CrawlerDetector) Detect(sv IPView, entry *parser.LogEntry) DetectResult {
	if !d.enabled {
		return DetectResult{}
	}

	paths := sv.RecentPaths()
	if len(paths) < d.minSequential {
		return DetectResult{}
	}

	// Группируем числовые суффиксы по prefix.
	// map[prefix][]int — списки чисел для каждого URL-шаблона.
	groups := make(map[string][]int, len(paths))
	for _, p := range paths {
		prefix, num, ok := parseNumericPath(p)
		if !ok {
			continue
		}
		groups[prefix] = append(groups[prefix], num)
	}

	for prefix, nums := range groups {
		if hasConsecutiveSequence(nums, d.minSequential) {
			return DetectResult{
				Score:  d.score,
				Module: "crawler",
				Reason: fmt.Sprintf("crawler:seq=%s*%d", prefix, d.minSequential),
			}
		}
	}

	return DetectResult{}
}

// ========================== Вспомогательные функции ===================================

// parseNumericPath извлекает (prefix, num) из URL-пути с числовым суффиксом.
// Возвращает ok=false если путь не содержит числового суффикса.
func parseNumericPath(path string) (prefix string, num int, ok bool) {
	m := numericSuffixRE.FindStringSubmatch(path)
	if m == nil {
		return "", 0, false
	}
	n, err := strconv.Atoi(m[2])
	if err != nil {
		return "", 0, false
	}
	return m[1], n, true
}

// hasConsecutiveSequence проверяет наличие последовательности minLen подряд идущих
// целых чисел в срезе (с дедупликацией перед проверкой).
func hasConsecutiveSequence(nums []int, minLen int) bool {
	// minLen <= 0 технически невалиден; guard защищает от паники ниже (nums[:1] на пустом срезе).
	if len(nums) == 0 || minLen <= 0 {
		return false
	}
	if len(nums) < minLen {
		return false
	}

	sort.Ints(nums)

	// Дедупликация: одинаковые числа (повторные запросы к одному URL) не считаются
	// отдельными шагами последовательности.
	uniq := nums[:1]
	for _, n := range nums[1:] {
		if n != uniq[len(uniq)-1] {
			uniq = append(uniq, n)
		}
	}
	if len(uniq) < minLen {
		return false
	}

	consec := 1
	for i := 1; i < len(uniq); i++ {
		if uniq[i] == uniq[i-1]+1 {
			consec++
			if consec >= minLen {
				return true
			}
		} else {
			consec = 1
		}
	}

	// Последний прогон мог не набрать minLen в цикле (в т.ч. единственный элемент при minLen=1).
	return consec >= minLen
}
