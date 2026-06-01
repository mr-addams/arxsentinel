// ========================== Bruteforce detector =======================================
//   Detects anomalous 404-response ratio from a single IP.
//   Symptom of scanning non-existent paths / directory brute-forcing.
//
//   ALGORITHM:
//     ratio = Requests404 / TotalRequests
//     If TotalRequests >= min_requests && ratio >= ratio_threshold → score.
//     min_requests guards against false positives on low request counts.
//
//   WHY RATIO INSTEAD OF ABSOLUTE 404 COUNT:
//     Absolute counter ignores traffic intensity — 40/60 (67%) is more suspicious
//     than 40/200 (20%). Ratio gives a normalized signal.
//
//   Params (DetectorConfig.Params):
//     min_requests     int     — minimum requests before triggering (default: 10)
//     ratio_threshold  float64 — 404 ratio threshold, 0.0–1.0 (default: 0.6)
//     score            int     — threat score on trigger (default: 30)
//
//   Registered as "bruteforce" via init().

package detector

import (
	"fmt"

	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

func init() {
	Register("bruteforce", newBruteforceFactory)
}

// bruteforceDetector detects anomalous 404 ratio.
type bruteforceDetector struct {
	plugin.NopManifest
	minRequests    int
	ratioThreshold float64
	score          int
}

// newBruteforceFactory creates a bruteforceDetector from DetectorConfig.
func newBruteforceFactory(cfg DetectorConfig, _ SharedResources) (plugin.Detector, error) {
	return &bruteforceDetector{
		minRequests:    getInt(cfg.Params, "min_requests", 10),
		ratioThreshold: getFloat64(cfg.Params, "ratio_threshold", 0.6),
		score:          getInt(cfg.Params, "score", 30),
	}, nil
}

// Name returns the detector identifier.
func (d *bruteforceDetector) Name() string { return "bruteforce" }

// Detect checks the share of 404 responses among total IP requests.
//
// min_requests reduces sensitivity during the initial data accumulation phase:
// the first few requests from an IP with 100% 404s are noise, not an anomaly.
func (d *bruteforceDetector) Detect(sv plugin.IPView, _ *plugin.LogEntry) plugin.DetectResult {
	total := sv.GetTotalRequests()
	if total < d.minRequests {
		return plugin.DetectResult{}
	}

	ratio := float64(sv.GetRequests404()) / float64(total)
	if ratio < d.ratioThreshold {
		return plugin.DetectResult{}
	}

	return plugin.DetectResult{
		Score:  d.score,
		Module: "bruteforce",
		Reason: fmt.Sprintf("bruteforce:404=%.0f%%(%d/%d)", ratio*100, sv.GetRequests404(), total),
	}
}
