// ========================== UserAgent detector ==========================================
//   Detects suspicious User-Agent strings: scanners (Nuclei, sqlmap), grabbers (wget, scrapy),
//   automation (python-requests, aiohttp), empty UA.
//
//   WHAT IS HERE:
//     - UADetector — struct with scores from config
//     - Package-level pre-compiled patterns in three categories
//     - Detect() — category checks from highest penalty to lowest
//
//   CATEGORIES (check order):
//     empty UA     → "" or "-"                                    (EmptyUAScore, default 30)
//     scanner      → Nuclei, sqlmap, nikto, nmap, masscan, ...   (ScannerScore, default 40)
//     grabber      → wget, scrapy, python-requests, libwww, ...  (GrabberScore, default 20)
//     automation   → aiohttp, Go-http-client, okhttp, ...        (AutomationScore, default 15)
//
//   FIRST MATCH WINS:
//     Detect returns on the first match — no double scoring.
//     Category order: more dangerous categories are checked first.
//
//   WHY PATTERNS ARE HARDCODED AND NOT IN CONFIG:
//     The scanner tool list is stable and specific — externalizing to YAML creates
//     a risk of an incomplete list (an operator may accidentally remove critical patterns).
//     When a new tool appears — change code, not config (SRE workflow).
//     Scores (ScannerScore etc.) remain in config — behavior is tunable without deploy.
//
//   Implemented: Task 4.3.

package detector

import (
	"strings"

	"github.com/mr-addams/nginx-sentinel/internal/core/parser"
	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
)

// ========================== UA patterns ===============================================

// scannerPatterns — active scanning and exploitation tools.
// strings.Contains: UA often includes version ("Nuclei/2.9.4") — exact match is insufficient.
var scannerPatterns = []string{
	"Nuclei", "sqlmap", "nikto", "Nikto",
	"nmap", "masscan", "zgrab", "ZGrab",
	"dirbuster", "DirBuster", "gobuster", "feroxbuster",
	"wfuzz", "WFuzz", "ffuf", "FFUF",
	"hydra", "Hydra", "medusa", "Medusa",
	"nessus", "openvas", "acunetix", "w3af",
	"havij", "burpsuite", "BurpSuite",
}

// grabberPatterns — content crawlers and downloaders.
// curl/ and wget/ with "/" to avoid blocking UAs like "Recursive wget protection".
var grabberPatterns = []string{
	"Wget/", "curl/", "python-requests", "libwww-perl",
	"scrapy", "Scrapy", "HTTrack", "WebCopier",
	"SiteSnagger", "WebReaper", "Teleport Pro",
}

// automationPatterns — HTTP clients and automation frameworks.
// "Go-http-client" is specific: does not block browser extensions containing "Go".
// "Java/" with "/" to avoid blocking UAs like "JavaScript/...".
var automationPatterns = []string{
	"python-urllib", "aiohttp", "Go-http-client",
	"Java/", "okhttp", "axios/", "node-fetch",
	"got (", "superagent", "RestSharp", "HttpClient",
}

// ========================== UADetector ===============================================

// UADetector detects suspicious User-Agent strings by predefined patterns.
//
// Lifecycle:
//   nil          → before NewUADetector is called
//   *UADetector  → after NewUADetector, used for the daemon's entire lifetime
//   rebuild      → on SIGHUP (Task 7.1) — a new instance is created
type UADetector struct {
	scannerPatterns    []string
	grabberPatterns    []string
	automationPatterns []string
	scannerScore       int
	grabberScore       int
	automationScore    int
	emptyUAScore       int
	enabled            bool
}

// NewUADetector creates a UADetector from config.
// Extra patterns from config are appended to built-in lists — built-ins cannot be removed.
// Called from main.go on startup and SIGHUP.
func NewUADetector(cfg config.UserAgentConfig) *UADetector {
	return &UADetector{
		scannerPatterns:    append(scannerPatterns, cfg.ExtraScannerPatterns...),
		grabberPatterns:    append(grabberPatterns, cfg.ExtraGrabberPatterns...),
		automationPatterns: append(automationPatterns, cfg.ExtraAutomationPatterns...),
		scannerScore:       cfg.ScannerScore,
		grabberScore:       cfg.GrabberScore,
		automationScore:    cfg.AutomationScore,
		emptyUAScore:       cfg.EmptyUAScore,
		enabled:            cfg.Enabled,
	}
}

// Name returns the detector identifier.
func (d *UADetector) Name() string { return "ua" }

// Detect checks User-Agent against threat categories.
//
// Order: empty UA → scanners → grabbers → automation.
// Empty UA first: short-circuit without iterating patterns.
// First match returns a result — prevents double scoring.
func (d *UADetector) Detect(sv IPView, entry *parser.LogEntry) DetectResult {
	if !d.enabled {
		return DetectResult{}
	}

	ua := entry.UserAgent

	// ── Empty UA ──────────────────────────────────────────────────────────────────────
	// "-" is nginx's standard placeholder for a missing User-Agent header
	if ua == "" || ua == "-" {
		return DetectResult{
			Score:  d.emptyUAScore,
			Module: "ua",
			Reason: "ua:empty",
		}
	}

	// Normalize UA once — catches CURL/8.7.1, WGET/1.x and other case variants.
	// Reason still uses the original pattern for readability in logs.
	uaLower := strings.ToLower(ua)

	// ── Scanners ──────────────────────────────────────────────────────────────────────
	for _, p := range d.scannerPatterns {
		if strings.Contains(uaLower, strings.ToLower(p)) {
			return DetectResult{
				Score:  d.scannerScore,
				Module: "ua",
				Reason: "ua:scanner:" + p,
			}
		}
	}

	// ── Grabbers ──────────────────────────────────────────────────────────────────────
	for _, p := range d.grabberPatterns {
		if strings.Contains(uaLower, strings.ToLower(p)) {
			return DetectResult{
				Score:  d.grabberScore,
				Module: "ua",
				Reason: "ua:grabber:" + p,
			}
		}
	}

	// ── Automation ────────────────────────────────────────────────────────────────────
	for _, p := range d.automationPatterns {
		if strings.Contains(uaLower, strings.ToLower(p)) {
			return DetectResult{
				Score:  d.automationScore,
				Module: "ua",
				Reason: "ua:automation:" + p,
			}
		}
	}

	return DetectResult{}
}
