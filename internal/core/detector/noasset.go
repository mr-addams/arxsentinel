// ========================== Детектор noasset ============================================
//   Детекция ботов, запрашивающих HTML-страницы без загрузки статики (CSS/JS/images).
//   Легитимный браузер всегда загружает ресурсы страницы — бот нет.
//
//   ЧТО ЗДЕСЬ:
//     - NoAssetDetector — структура с параметрами и предкомпилированным set расширений
//     - NewNoAssetDetector(cfg) — инициализация, построение assetExts map
//     - Detect() — считает страницы и ассеты в RecentPaths, проверяет ratio
//
//   АЛГОРИТМ:
//     Для каждого пути из RecentPaths определить тип:
//       - asset: расширение входит в AssetExtensions (.css, .js, .png, ...)
//       - page:  всё остальное (без расширения, .html, .php, .asp, ...)
//     Если pageCount >= MinPageRequests && assetCount/total < AssetRatioThreshold → score.
//
//   ПОЧЕМУ РАСШИРЕНИЕ, А НЕ CONTENT-TYPE:
//     LogEntry не содержит Content-Type ответа — nginx пишет только строки запроса.
//     Расширение пути — надёжный прокси: браузер загружает href=".css" → путь имеет .css.
//     Исключение: SPA (React/Vue) — всё через /api/ без расширений. Детектор может дать
//     ложный WARN для SPA-ботов. Снижение порога AssetRatioThreshold уменьшает ложный шум.
//
//   ЗАВИСИМОСТЬ ОТ ДАННЫХ:
//     RecentPaths — кольцевой буфер последних 64 путей (state.pathBuf).
//     При minPageRequests=3 и bufer=64 первые страницы IP уже накоплены к моменту срабатывания.
//
//   Реализовано: Task 6.3.

package detector

import (
	"fmt"
	"path"
	"strings"

	"github.com/mr-addams/nginx-sentinel/internal/core/parser"
	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
)

// ========================== NoAssetDetector ===========================================

// NoAssetDetector детектирует ботов, не загружающих статические ресурсы страниц.
type NoAssetDetector struct {
	enabled             bool
	minPageRequests     int
	assetRatioThreshold float64
	score               int
	assetExts           map[string]struct{} // set расширений статических ресурсов
}

// NewNoAssetDetector создаёт NoAssetDetector из конфига.
// Строит assetExts map один раз — на hot path O(1) lookup вместо O(n) по slice.
// Вызывается из main.go при старте и SIGHUP.
func NewNoAssetDetector(cfg config.NoAssetConfig) *NoAssetDetector {
	exts := make(map[string]struct{}, len(cfg.AssetExtensions))
	for _, ext := range cfg.AssetExtensions {
		exts[strings.ToLower(ext)] = struct{}{}
	}
	return &NoAssetDetector{
		enabled:             cfg.Enabled,
		minPageRequests:     cfg.MinPageRequests,
		assetRatioThreshold: cfg.AssetRatioThreshold,
		score:               cfg.Score,
		assetExts:           exts,
	}
}

// Name возвращает идентификатор детектора.
func (d *NoAssetDetector) Name() string { return "noasset" }

// Detect анализирует соотношение страниц и ассетов в истории запросов IP.
//
// Не срабатывает если pageCount < minPageRequests — IP мог только начать обход,
// статистика нерепрезентативна.
func (d *NoAssetDetector) Detect(sv IPView, entry *parser.LogEntry) DetectResult {
	if !d.enabled {
		return DetectResult{}
	}

	paths := sv.RecentPaths()

	var pageCount, assetCount int
	for _, p := range paths {
		if d.isAsset(p) {
			assetCount++
		} else {
			pageCount++
		}
	}

	if pageCount < d.minPageRequests {
		return DetectResult{}
	}

	total := pageCount + assetCount
	// total > 0 гарантирован: pageCount >= minPageRequests > 0.
	assetRatio := float64(assetCount) / float64(total)
	if assetRatio >= d.assetRatioThreshold {
		return DetectResult{}
	}

	return DetectResult{
		Score:  d.score,
		Module: "noasset",
		Reason: fmt.Sprintf("noasset:pages=%d,assets=%d,ratio=%.0f%%",
			pageCount, assetCount, assetRatio*100),
	}
}

// isAsset возвращает true если путь заканчивается расширением статического ресурса.
// Использует path.Ext (forward-slash семантика, не filepath.Ext) для URL-путей.
func (d *NoAssetDetector) isAsset(urlPath string) bool {
	// Отрезаем query string если каким-то образом попал в путь (defensive)
	if idx := strings.IndexByte(urlPath, '?'); idx >= 0 {
		urlPath = urlPath[:idx]
	}
	ext := strings.ToLower(path.Ext(urlPath))
	_, ok := d.assetExts[ext]
	return ok
}
