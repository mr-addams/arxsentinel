// ========================== Overflow detector ============================================
//   Detects buffer overflow attempts and WAF bypass:
//   anomalous URL length, suspicious keywords in path/parameters.
//
//   ALGORITHM:
//     1. Build full URL: Path + "?" + Query (if Query is not empty).
//     2. If len(fullURL) > max_url_length → buffer overflow attempt, score.
//     3. Otherwise: if fullURL contains any suspicious_params (case-insensitive) → WAF bypass, score.
//
//   WHY ONE SCORE FOR BOTH CONDITIONS:
//     Both indicators imply the same threat class — an attempt to bypass protection
//     or trigger a vulnerability. Splitting score would require two separate detectors.
//
//   Params (DetectorConfig.Params):
//     max_url_length     int      — max URL byte length before trigger (default: 2048)
//     suspicious_params  []string — keywords triggering WAF bypass detection
//                                   (default: bypass, shell, cmd, exec, eval, system, passthru)
//     score              int      — threat score on trigger (default: 30)
//
//   Registered as "overflow" via init().

package detector

import (
	"fmt"
	"strings"

	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

func init() {
	Register("overflow", newOverflowFactory)
}

// defaultSuspiciousParams is the built-in list of WAF bypass keywords.
var defaultSuspiciousParams = []string{
	"bypass", "shell", "cmd", "exec", "eval", "system", "passthru",
}

// overflowDetector detects buffer overflow and WAF bypass attempts via URL.
type overflowDetector struct {
	maxURLLength     int
	suspiciousParams []string // lowercase-normalized for case-insensitive matching
	score            int
}

// newOverflowFactory creates an overflowDetector from DetectorConfig.
func newOverflowFactory(cfg DetectorConfig, _ SharedResources) (plugin.Detector, error) {
	maxURLLength := getInt(cfg.Params, "max_url_length", 2048)
	rawParams := getStrings(cfg.Params, "suspicious_params", defaultSuspiciousParams)
	score := getInt(cfg.Params, "score", 30)

	// Normalize to lowercase once — hot path only needs ToLower(URL).
	params := make([]string, len(rawParams))
	for i, p := range rawParams {
		params[i] = strings.ToLower(p)
	}

	return &overflowDetector{
		maxURLLength:     maxURLLength,
		suspiciousParams: params,
		score:            score,
	}, nil
}

// Name returns the detector identifier.
func (d *overflowDetector) Name() string { return "overflow" }

// Detect checks the current request for overflow and WAF bypass.
//
// Checks the full URL (Path + Query) — current request, not IP history.
// Length check first: more likely a deliberate overflow attempt.
// Called from: pipeline.processEntries.
//
// Non-blocking.
func (d *overflowDetector) Detect(_ plugin.IPView, entry *plugin.LogEntry) plugin.DetectResult {
	fullURL := entry.Path
	if entry.Query != "" {
		fullURL = entry.Path + "?" + entry.Query
	}

	// ── Buffer overflow: anomalous URL length ─────────────────────────────────────────
	// len() counts bytes — correct for ASCII URLs (RFC 3986).
	// Percent-encoding increases byte length without decoding, so an attacker cannot
	// shrink below the threshold by encoding.
	if len(fullURL) > d.maxURLLength {
		return plugin.DetectResult{
			Score:  d.score,
			Module: "overflow",
			Reason: fmt.Sprintf("overflow:url_len=%d", len(fullURL)),
		}
	}

	// ── WAF bypass: suspicious keywords ──────────────────────────────────────────────
	lowerURL := strings.ToLower(fullURL)
	for _, param := range d.suspiciousParams {
		if strings.Contains(lowerURL, param) {
			return plugin.DetectResult{
				Score:  d.score,
				Module: "overflow",
				Reason: fmt.Sprintf("overflow:waf_bypass=%s", param),
			}
		}
	}

	return plugin.DetectResult{}
}
