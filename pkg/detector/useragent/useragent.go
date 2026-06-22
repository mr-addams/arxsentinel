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

package useragent

import (
	"strings"

	detector "github.com/mr-addams/arxsentinel/pkg/detector"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

func init() {
	detector.Register("ua", newUAFactory)
}

// Built-in pattern lists. Normalized to lowercase in newUAFactory — Detect
// already lowercases the input, so patterns must match in lowercase.

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
// All lowercase — normalized in newUAFactory.
// wget/ and curl/ with "/" to avoid blocking UAs like "Recursive wget protection".
var builtinGrabberPatterns = []string{
	"wget/", "curl/", "python-requests", "libwww-perl",
	"scrapy", "httrack", "webcopier",
	"sitesnagger", "webreaper", "teleport pro",
}

// builtinAutomationPatterns — HTTP clients and automation frameworks.
// All lowercase — normalized in newUAFactory.
var builtinAutomationPatterns = []string{
	"python-urllib", "aiohttp", "go-http-client",
	"java/", "okhttp", "axios/", "node-fetch",
	"got (", "superagent", "restsharp", "httpclient",
}

// uaDetector detects suspicious User-Agent strings.
type uaDetector struct {
	scannerPatterns    []string
	grabberPatterns    []string
	automationPatterns []string
	scannerScore       int
	grabberScore       int
	automationScore    int
	emptyUAScore       int
}

// newUAFactory creates a uaDetector from DetectorConfig.
// Normalizes all patterns to lowercase once — avoids per-call ToLower on hot path.
func newUAFactory(cfg detector.DetectorConfig, _ detector.SharedResources) (plugin.Detector, error) {
	scannerScore := detector.GetInt(cfg, "scanner_score", 40)
	grabberScore := detector.GetInt(cfg, "grabber_score", 20)
	automationScore := detector.GetInt(cfg, "automation_score", 15)
	emptyUAScore := detector.GetInt(cfg, "empty_ua_score", 30)

	extraScanners := detector.GetStrings(cfg, "extra_scanner_patterns", nil)
	extraGrabbers := detector.GetStrings(cfg, "extra_grabber_patterns", nil)
	extraAutomation := detector.GetStrings(cfg, "extra_automation_patterns", nil)

	// Normalize all patterns to lowercase once.
	scannerPatterns := normalizePatterns(builtinScannerPatterns, extraScanners)
	grabberPatterns := normalizePatterns(builtinGrabberPatterns, extraGrabbers)
	automationPatterns := normalizePatterns(builtinAutomationPatterns, extraAutomation)

	return &uaDetector{
		scannerPatterns:    scannerPatterns,
		grabberPatterns:    grabberPatterns,
		automationPatterns: automationPatterns,
		scannerScore:       scannerScore,
		grabberScore:       grabberScore,
		automationScore:    automationScore,
		emptyUAScore:       emptyUAScore,
	}, nil
}

// normalizePatterns merges builtin and extra patterns, lowercasing all of them.
func normalizePatterns(builtin, extra []string) []string {
	total := len(builtin) + len(extra)
	result := make([]string, 0, total)
	for _, p := range builtin {
		result = append(result, strings.ToLower(p))
	}
	for _, p := range extra {
		result = append(result, strings.ToLower(p))
	}
	return result
}

// Name returns the detector identifier.
func (d *uaDetector) Name() string { return "ua" }

// Detect checks User-Agent against threat categories.
//
// Order: empty UA → scanners → grabbers → automation.
// First match returns a result — prevents double scoring.
// Called from: pipeline.processEntries.
//
// Non-blocking.
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
	// Patterns are pre-normalized to lowercase in newUAFactory.
	for _, p := range d.scannerPatterns {
		if strings.Contains(uaLower, p) {
			return plugin.DetectResult{
				Score:  d.scannerScore,
				Module: "ua",
				Reason: "ua:scanner:" + p,
			}
		}
	}

	// ── Grabbers ──────────────────────────────────────────────────────────────────────
	for _, p := range d.grabberPatterns {
		if strings.Contains(uaLower, p) {
			return plugin.DetectResult{
				Score:  d.grabberScore,
				Module: "ua",
				Reason: "ua:grabber:" + p,
			}
		}
	}

	// ── Automation ────────────────────────────────────────────────────────────────────
	for _, p := range d.automationPatterns {
		if strings.Contains(uaLower, p) {
			return plugin.DetectResult{
				Score:  d.automationScore,
				Module: "ua",
				Reason: "ua:automation:" + p,
			}
		}
	}

	return plugin.DetectResult{}
}
