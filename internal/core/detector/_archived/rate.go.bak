// ========================== Rate detector ===============================================
//   Detects anomalous request rate spikes: N requests over a sliding window.
//   The ApproxRate algorithm (two-counter sliding window) is implemented in state.IPState.
//
//   WHAT IS HERE:
//     - RateDetector — struct with thresholds from config
//     - NewRateDetector(cfg) — initialization, threshold conversion
//     - Detect() — compares sv.ApproxRate(window) with thresholdRPS
//
//   THRESHOLD IN RPS:
//     cfg.Threshold is given in requests per window (e.g. 100 req / 60s).
//     ApproxRate returns requests/sec over the window.
//     Conversion: thresholdRPS = Threshold / window.Seconds() — done once in NewRateDetector.
//     On the hot path — only a float64 comparison.
//
//   CONSISTENCY WITH TRACKER:
//     window must match detectors.rate.window from config —
//     both (Tracker.rateWindow and RateDetector.window) read from cfg.Detectors.Rate.Window.
//
//   Implemented: Task 4.2.

package detector

import (
	"fmt"
	"time"

	"github.com/mr-addams/arxsentinel/internal/core/parser"
	"github.com/mr-addams/arxsentinel/internal/sys/config"
)

// ========================== RateDetector ==============================================

// RateDetector detects anomalous request rate over a sliding window.
//
// Lifecycle:
//   nil            → before NewRateDetector is called
//   *RateDetector  → after NewRateDetector, used for the daemon's entire lifetime
//   rebuild        → on SIGHUP (Task 7.1) — a new instance is created
type RateDetector struct {
	thresholdRPS float64       // threshold in req/s: cfg.Threshold / window.Seconds()
	window       time.Duration // ApproxRate window — must match state.Tracker.rateWindow
	score        int
	enabled      bool
}

// NewRateDetector creates a RateDetector from config.
// Converts Threshold (req/window) → thresholdRPS (req/s) once at startup.
// On zero or negative window — disables the detector: dividing by 0 yields +Inf/NaN,
// causing the detector to either never fire or always fire.
// Called from main.go on startup and SIGHUP.
func NewRateDetector(cfg config.RateConfig) *RateDetector {
	window := time.Duration(cfg.Window)

	// Guard: zero window makes thresholdRPS = +Inf (Threshold>0) or NaN (Threshold=0).
	// Both are silent misconfiguration: the detector either never fires
	// or always fires. Disable explicitly to avoid silently missing an attack.
	if window <= 0 {
		return &RateDetector{enabled: false}
	}

	// Threshold in req/s: move the division off the hot path — Detect is called on every log line
	thresholdRPS := float64(cfg.Threshold) / window.Seconds()
	return &RateDetector{
		thresholdRPS: thresholdRPS,
		window:       window,
		score:        cfg.Score,
		enabled:      cfg.Enabled,
	}
}

// Name returns the detector identifier.
func (d *RateDetector) Name() string { return "rate" }

// Detect compares the IP's ApproxRate with the threshold.
//
// ApproxRate(window) — approximate rate over the last window (±10% relative to exact).
// The margin is acceptable: a rare false WARN is better than a missed DDoS attack.
// Reason includes the actual rate for diagnostics in the threat log.
func (d *RateDetector) Detect(sv IPView, entry *parser.LogEntry) DetectResult {
	if !d.enabled {
		return DetectResult{}
	}

	rate := sv.ApproxRate(d.window)
	// Strict <: rate == thresholdRPS is already considered exceeded — detector fires.
	// Intentional: rate "exactly at threshold" is already an anomaly; better WARN than miss the start of an attack.
	if rate < d.thresholdRPS {
		return DetectResult{}
	}

	return DetectResult{
		Score:  d.score,
		Module: "rate",
		Reason: fmt.Sprintf("rate:%.0frps", rate),
	}
}
