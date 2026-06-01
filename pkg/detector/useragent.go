// ========================== UserAgent detector ==========================================
//   Detects suspicious User-Agent strings: scanners (Nuclei, sqlmap), grabbers (wget,
//   scrapy), automation (python-requests, aiohttp), empty UA.
//
//   CATEGORIES (check order — most dangerous first):
//     empty UA     → "" or "-"                                    (default score: 30)
//     scanner      → Nuclei, sqlmap, nikto, nmap, masscan, ...   (default score: 40)
//     grabber      → wget, scrapy, python-requests, libwww, ...  (default score: 20)
//     automation   → aiohttp, Go-http-client, okhttp, ...        (default score: 15)
//
//   WHY PATTERNS ARE HARDCODED AND NOT IN CONFIG:
//     The scanner tool list is stable and specific — externalizing to YAML creates risk
//     of an incomplete list. Scores remain in config and are tunable without deploy.
//
//   Params (DetectorConfig.Params):
//     scanner_score              int      — score for scanner UA (default: 40)
//     grabber_score              int      — score for grabber UA (default: 20)
//     automation_score           int      — score for automation UA (default: 15)
//     empty_ua_score             int      — score for empty UA (default: 30)
//     extra_scanner_patterns     []string — appended to built-in scanners
//     extra_grabber_patterns     []string — appended to built-in grabbers
//     extra_automation_patterns  []string — appended to built-in automation
//
//   Registered as "ua" via init().

package detector

import (
	"strings"

	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

func init() {
	Register("ua", newUAFactory)
}

// Built-in pattern lists. All lowercase — Detect normalizes input to lowercase.

// builtinScannerPatterns — active scanning and exploitation tools.
var builtinScannerPatterns = []string{
	"nuclei", "sqlmap", "nikto",
	"nmap", "masscan", "zgrab",
	"dirbuster", "gobuster", "feroxbuster",
	"wfuzz", "ffuf",
	"hydra", "medusa",
	"nessus", "openvas", "acunetix", "w3af",
	"havij", "burpsuite",
}

// builtinGrabberPatterns — content crawlers and downloaders.
// Wget/ and curl/ with "/" to avoid blocking UAs like "Recursive wget protection".
var builtinGrabberPatterns = []string{
	"Wget/", "curl/", "python-requests", "libwww-perl",
	"scrapy", "HTTrack", "WebCopier",
	"SiteSnagger", "WebReaper", "Teleport Pro",
}

// builtinAutomationPatterns — HTTP clients and automation frameworks.
var builtinAutomationPatterns = []string{
	"python-urllib", "aiohttp", "Go-http-client",
	"Java/", "okhttp", "axios/", "node-fetch",
	"got (", "superagent", "RestSharp", "HttpClient",
}

// uaDetector detects suspicious User-Agent strings.
type uaDetector struct {
	plugin.NopManifest
	scannerPatterns    []string
	grabberPatterns    []string
	automationPatterns []string
	scannerScore       int
	grabberScore       int
	automationScore    int
	emptyUAScore       int
}

// newUAFactory creates a uaDetector from DetectorConfig.
func newUAFactory(cfg DetectorConfig, _ SharedResources) (plugin.Detector, error) {
	scannerScore := getInt(cfg.Params, "scanner_score", 40)
	grabberScore := getInt(cfg.Params, "grabber_score", 20)
	automationScore := getInt(cfg.Params, "automation_score", 15)
	emptyUAScore := getInt(cfg.Params, "empty_ua_score", 30)

	extraScanners := getStrings(cfg.Params, "extra_scanner_patterns", nil)
	extraGrabbers := getStrings(cfg.Params, "extra_grabber_patterns", nil)
	extraAutomation := getStrings(cfg.Params, "extra_automation_patterns", nil)

	return &uaDetector{
		scannerPatterns:    append(builtinScannerPatterns, extraScanners...),
		grabberPatterns:    append(builtinGrabberPatterns, extraGrabbers...),
		automationPatterns: append(builtinAutomationPatterns, extraAutomation...),
		scannerScore:       scannerScore,
		grabberScore:       grabberScore,
		automationScore:    automationScore,
		emptyUAScore:       emptyUAScore,
	}, nil
}

// Name returns the detector identifier.
func (d *uaDetector) Name() string { return "ua" }

// Detect checks User-Agent against threat categories.
//
// Order: empty UA → scanners → grabbers → automation.
// First match returns a result — prevents double scoring.
func (d *uaDetector) Detect(_ plugin.IPView, entry *plugin.LogEntry) plugin.DetectResult {
	ua := entry.UserAgent

	// ── Empty UA ──────────────────────────────────────────────────────────────────────
	// "-" is nginx's standard placeholder for a missing User-Agent header.
	if ua == "" || ua == "-" {
		return plugin.DetectResult{
			Score:  d.emptyUAScore,
			Module: "ua",
			Reason: "ua:empty",
		}
	}

	// Normalize once — catches CURL/8.7.1, WGET/1.x and other case variants.
	uaLower := strings.ToLower(ua)

	// ── Scanners ──────────────────────────────────────────────────────────────────────
	for _, p := range d.scannerPatterns {
		if strings.Contains(uaLower, strings.ToLower(p)) {
			return plugin.DetectResult{
				Score:  d.scannerScore,
				Module: "ua",
				Reason: "ua:scanner:" + p,
			}
		}
	}

	// ── Grabbers ──────────────────────────────────────────────────────────────────────
	for _, p := range d.grabberPatterns {
		if strings.Contains(uaLower, strings.ToLower(p)) {
			return plugin.DetectResult{
				Score:  d.grabberScore,
				Module: "ua",
				Reason: "ua:grabber:" + p,
			}
		}
	}

	// ── Automation ────────────────────────────────────────────────────────────────────
	for _, p := range d.automationPatterns {
		if strings.Contains(uaLower, strings.ToLower(p)) {
			return plugin.DetectResult{
				Score:  d.automationScore,
				Module: "ua",
				Reason: "ua:automation:" + p,
			}
		}
	}

	return plugin.DetectResult{}
}
