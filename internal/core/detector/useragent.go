// ========================== Детектор useragent ==========================================
//   Детекция подозрительных User-Agent: сканеры (Nuclei, sqlmap), грабберы (wget, scrapy),
//   автоматизация (python-requests, aiohttp), пустой UA.
//
//   ЧТО ЗДЕСЬ:
//     - UADetector — структура с очками из конфига
//     - Предкомпилированные паттерны в package-level vars (три категории)
//     - Detect() — проверка по категориям от наибольшего штрафа к наименьшему
//
//   КАТЕГОРИИ (порядок проверки):
//     empty UA     → "" или "-"                                    (EmptyUAScore, default 30)
//     scanner      → Nuclei, sqlmap, nikto, nmap, masscan, ...     (ScannerScore, default 40)
//     grabber      → wget, scrapy, python-requests, libwww, ...    (GrabberScore, default 20)
//     automation   → aiohttp, Go-http-client, okhttp, ...          (AutomationScore, default 15)
//
//   ПЕРВОЕ СОВПАДЕНИЕ ПОБЕЖДАЕТ:
//     Detect возвращает при первом match — двойного начисления нет.
//     Порядок категорий: более опасные проверяются первыми.
//
//   ПОЧЕМУ ПАТТЕРНЫ HARDCODED, А НЕ В КОНФИГЕ:
//     Список инструментов-сканеров стабилен и специфичен — выносить в YAML создаёт
//     риск неполного списка (оператор может случайно удалить критичные паттерны).
//     При появлении нового инструмента — правим код, а не конфиг (SRE workflow).
//     Очки (ScannerScore и т.д.) остаются в конфиге — поведение тюнингуется без деплоя.
//
//   Реализовано: Task 4.3.

package detector

import (
	"strings"

	"github.com/mr-addams/nginx-sentinel/internal/core/parser"
	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
)

// ========================== UA паттерны ==============================================

// scannerPatterns — инструменты активного сканирования и эксплуатации.
// strings.Contains: UA часто содержит версию ("Nuclei/2.9.4") — точное совпадение не подходит.
var scannerPatterns = []string{
	"Nuclei", "sqlmap", "nikto", "Nikto",
	"nmap", "masscan", "zgrab", "ZGrab",
	"dirbuster", "DirBuster", "gobuster", "feroxbuster",
	"wfuzz", "WFuzz", "ffuf", "FFUF",
	"hydra", "Hydra", "medusa", "Medusa",
	"nessus", "openvas", "acunetix", "w3af",
	"havij", "burpsuite", "BurpSuite",
}

// grabberPatterns — краулеры и загрузчики контента.
// curl/ и wget/ с "/" чтобы не блокировать UA вида "Recursive wget protection".
var grabberPatterns = []string{
	"Wget/", "curl/", "python-requests", "libwww-perl",
	"scrapy", "Scrapy", "HTTrack", "WebCopier",
	"SiteSnagger", "WebReaper", "Teleport Pro",
}

// automationPatterns — HTTP-клиенты и фреймворки автоматизации.
// "Go-http-client" специфично: не блокирует браузерные расширения со словом "Go".
// "Java/" с "/" чтобы не блокировать UA вида "JavaScript/...".
var automationPatterns = []string{
	"python-urllib", "aiohttp", "Go-http-client",
	"Java/", "okhttp", "axios/", "node-fetch",
	"got (", "superagent", "RestSharp", "HttpClient",
}

// ========================== UADetector ===============================================

// UADetector детектирует подозрительные User-Agent по предопределённым паттернам.
//
// Жизненный цикл:
//   nil          → до вызова NewUADetector
//   *UADetector  → после NewUADetector, используется всё время жизни демона
//   перестройка  → при SIGHUP (Task 7.1) — создаётся новый экземпляр
type UADetector struct {
	scannerScore    int
	grabberScore    int
	automationScore int
	emptyUAScore    int
	enabled         bool
}

// NewUADetector создаёт UADetector из конфига.
// Вызывается из main.go при старте и SIGHUP.
func NewUADetector(cfg config.UserAgentConfig) *UADetector {
	return &UADetector{
		scannerScore:    cfg.ScannerScore,
		grabberScore:    cfg.GrabberScore,
		automationScore: cfg.AutomationScore,
		emptyUAScore:    cfg.EmptyUAScore,
		enabled:         cfg.Enabled,
	}
}

// Name возвращает идентификатор детектора.
func (d *UADetector) Name() string { return "ua" }

// Detect проверяет User-Agent по категориям угроз.
//
// Порядок: пустой UA → сканеры → грабберы → автоматизация.
// Пустой UA первым: короткий путь без перебора паттернов.
// Первое совпадение возвращает результат — исключает двойное начисление.
func (d *UADetector) Detect(sv IPView, entry *parser.LogEntry) DetectResult {
	if !d.enabled {
		return DetectResult{}
	}

	ua := entry.UserAgent

	// ── Пустой UA ─────────────────────────────────────────────────────────────────────
	// "-" — стандартный placeholder nginx для отсутствующего заголовка User-Agent
	if ua == "" || ua == "-" {
		return DetectResult{
			Score:  d.emptyUAScore,
			Module: "ua",
			Reason: "ua:empty",
		}
	}

	// ── Сканеры ───────────────────────────────────────────────────────────────────────
	for _, p := range scannerPatterns {
		if strings.Contains(ua, p) {
			return DetectResult{
				Score:  d.scannerScore,
				Module: "ua",
				Reason: "ua:scanner:" + p,
			}
		}
	}

	// ── Грабберы ──────────────────────────────────────────────────────────────────────
	for _, p := range grabberPatterns {
		if strings.Contains(ua, p) {
			return DetectResult{
				Score:  d.grabberScore,
				Module: "ua",
				Reason: "ua:grabber:" + p,
			}
		}
	}

	// ── Автоматизация ─────────────────────────────────────────────────────────────────
	for _, p := range automationPatterns {
		if strings.Contains(ua, p) {
			return DetectResult{
				Score:  d.automationScore,
				Module: "ua",
				Reason: "ua:automation:" + p,
			}
		}
	}

	return DetectResult{}
}
