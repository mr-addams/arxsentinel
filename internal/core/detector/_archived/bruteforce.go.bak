// ========================== Bruteforce detector =======================================
//   Detects anomalous 404-response ratio from a single IP (404 ratio).
//   Symptom of scanning non-existent paths / directory brute-forcing.
//
//   WHAT IS HERE:
//     - BruteforceDetector — struct with parameters from config
//     - NewBruteforceDetector(cfg) — initialization
//     - Detect() — checks the ratio Requests404 / TotalRequests
//
//   ALGORITHM:
//     ratio = Requests404 / TotalRequests
//     If TotalRequests >= MinRequests && ratio >= RatioThreshold → score += Score.
//
//     MinRequests threshold guards against false positives on low request counts:
//     a single 404 from a new IP is not a brute-force indicator.
//
//   WHY RATIO INSTEAD OF ABSOLUTE 404 COUNT:
//     An absolute counter ignores traffic intensity — an IP with 60 requests
//     and 40 404s (67%) is more suspicious than one with 200 requests and 40 404s (20%).
//
//   DATA FROM IPVIEW:
//     GetTotalRequests() — total requests to the IP, implemented by *state.IPState.TotalRequests.
//     GetRequests404()   — 404-response counter, implemented by *state.IPState.Requests404.
//
//   Implemented: Task 6.1.

package detector

import (
	"fmt"

	"github.com/mr-addams/arxsentinel/internal/core/parser"
	"github.com/mr-addams/arxsentinel/internal/sys/config"
)

// ========================== BruteforceDetector ========================================

// BruteforceDetector detects anomalous 404-response ratio from a single IP.
type BruteforceDetector struct {
	enabled        bool
	minRequests    int
	ratioThreshold float64
	score          int
}

// NewBruteforceDetector creates a BruteforceDetector from config.
// Called from main.go on startup and SIGHUP.
func NewBruteforceDetector(cfg config.BruteforceConfig) *BruteforceDetector {
	return &BruteforceDetector{
		enabled:        cfg.Enabled,
		minRequests:    cfg.MinRequests,
		ratioThreshold: cfg.RatioThreshold,
		score:          cfg.Score,
	}
}

// Name returns the detector identifier.
func (d *BruteforceDetector) Name() string { return "bruteforce" }

// Detect checks the share of 404 responses among total IP requests.
//
// MinRequests reduces sensitivity during the initial data accumulation phase:
// the first few requests from an IP with 100% 404s are noise, not an anomaly.
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
