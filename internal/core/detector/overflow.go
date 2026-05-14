// ========================== Overflow detector ============================================
//   Detects buffer overflow attempts and WAF bypass:
//   anomalous URL length, suspicious keywords in path/parameters.
//
//   WHAT IS HERE:
//     - OverflowDetector — struct with parameters and normalized keyword list
//     - NewOverflowDetector(cfg) — initialization, lowercase normalization of suspicious_params
//     - Detect() — checks URL length and keyword presence
//
//   ALGORITHM:
//     1. Build the full URL: Path + "?" + Query (if Query is not empty).
//     2. If len(fullURL) > MaxURLLength → buffer overflow attempt, score.
//     3. Otherwise: if fullURL contains any suspicious_params (case-insensitive) → WAF bypass, score.
//
//   WHY ONE Score FOR BOTH CONDITIONS:
//     Both indicators (length and suspicious params) imply the same threat class —
//     an attempt to bypass protection or trigger a vulnerability. Splitting score is not useful:
//     one detector — one decision. Different scores → two detectors.
//
//   KNOWN LIMITATION:
//     strings.Contains over the entire URL may produce false positives for short words ("cmd").
//     Example: /api/cmd/results triggers on "cmd". Score=30 and ban_threshold=80 means
//     3+ independent hits are needed before an IP receives THREAT. Acceptable trade-off
//     between detection recall and precision.
//
//   Implemented: Task 6.4.

package detector

import (
	"fmt"
	"strings"

	"github.com/mr-addams/nginx-sentinel/internal/core/parser"
	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
)

// ========================== OverflowDetector ==========================================

// OverflowDetector detects buffer overflow and WAF bypass attempts via URL.
type OverflowDetector struct {
	enabled          bool
	maxURLLength     int
	suspiciousParams []string // lowercase-normalized
	score            int
}

// NewOverflowDetector creates an OverflowDetector from config.
// Normalizes suspicious_params to lowercase once — hot path only needs ToLower(URL).
// Called from main.go on startup and SIGHUP.
func NewOverflowDetector(cfg config.OverflowConfig) *OverflowDetector {
	params := make([]string, len(cfg.SuspiciousParams))
	for i, p := range cfg.SuspiciousParams {
		params[i] = strings.ToLower(p)
	}
	return &OverflowDetector{
		enabled:          cfg.Enabled,
		maxURLLength:     cfg.MaxURLLength,
		suspiciousParams: params,
		score:            cfg.Score,
	}
}

// Name returns the detector identifier.
func (d *OverflowDetector) Name() string { return "overflow" }

// Detect checks the current request for overflow and WAF bypass.
//
// Checks entry.Path + entry.Query — the current request, not the IP history.
// First match returns a result: length takes priority (more likely a deliberate attack).
func (d *OverflowDetector) Detect(sv IPView, entry *parser.LogEntry) DetectResult {
	if !d.enabled {
		return DetectResult{}
	}

	fullURL := entry.Path
	if entry.Query != "" {
		fullURL = entry.Path + "?" + entry.Query
	}

	// ── Buffer overflow: anomalous URL length ─────────────────────────────────────────
	// len() counts bytes, not Unicode code points — correct for ASCII URLs (RFC 3986).
	// Percent-encoded characters (%XX) increase len without decoding — an attacker
	// cannot shrink the byte length via encoding.
	if len(fullURL) > d.maxURLLength {
		return DetectResult{
			Score:  d.score,
			Module: "overflow",
			Reason: fmt.Sprintf("overflow:url_len=%d", len(fullURL)),
		}
	}

	// ── WAF bypass: suspicious keywords ──────────────────────────────────────────────
	lowerURL := strings.ToLower(fullURL)
	for _, param := range d.suspiciousParams {
		if strings.Contains(lowerURL, param) {
			return DetectResult{
				Score:  d.score,
				Module: "overflow",
				Reason: fmt.Sprintf("overflow:waf_bypass=%s", param),
			}
		}
	}

	return DetectResult{}
}
