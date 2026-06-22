// ========================== Rate detector ===============================================
//   Detects anomalous request rate spikes: N requests over a sliding window.
//   The ApproxRate algorithm (two-counter sliding window) is implemented in state.IPState.
//
//   ALGORITHM:
//     thresholdRPS = Threshold / window.Seconds()
//     If IP.ApproxRate(window) > thresholdRPS → score.
//     Conversion done once in factory — hot path is a single float64 comparison.
//
//   Params (DetectorConfig.Params):
//     threshold  int    — max requests per window (default: 100)
//     window     string — sliding window duration, e.g. "60s" (default: "60s")
//     score      int    — threat score on trigger (default: 25)
//
//   Registered as "rate" via init() in sub-package rate.

package rate

import (
	"fmt"
	"time"

	detector "github.com/mr-addams/arx-core/pkg/detector"
	"github.com/mr-addams/arx-core/pkg/plugin"
)

func init() {
	detector.Register("rate", newRateFactory)
}

// rateDetector detects anomalous request rate over a sliding window.
type rateDetector struct {
	thresholdRPS float64       // threshold in req/s: Threshold / window.Seconds()
	window       time.Duration // ApproxRate window
	score        int
}

// newRateFactory creates a rateDetector from DetectorConfig.
// Returns error when window <= 0 or threshold <= 0 — these produce a broken
// thresholdRPS (NaN, +Inf, or zero) that would silently block-or-allow all traffic.
// The caller (config validation or Build) must handle the error.
func newRateFactory(cfg detector.DetectorConfig, _ detector.SharedResources) (plugin.Detector, error) {
	threshold := detector.GetInt(cfg, "threshold", 100)
	window := detector.GetDuration(cfg, "window", 60*time.Second)
	score := detector.GetInt(cfg, "score", 25)

	if window <= 0 {
		return nil, fmt.Errorf("rate: window=%v must be positive", window)
	}
	if threshold <= 0 {
		return nil, fmt.Errorf("rate: threshold=%d must be positive", threshold)
	}

	return &rateDetector{
		thresholdRPS: float64(threshold) / window.Seconds(),
		window:       window,
		score:        score,
	}, nil
}

// Name returns the detector identifier.
func (d *rateDetector) Name() string { return "rate" }

// Detect checks whether the IP's request rate exceeds the configured threshold.
// Called from: pipeline.processEntries.
//
// Non-blocking.
func (d *rateDetector) Detect(sv plugin.IPView, _ *plugin.LogEntry) plugin.DetectResult {
	if sv.ApproxRate(d.window) <= d.thresholdRPS {
		return plugin.DetectResult{}
	}
	return plugin.DetectResult{
		Score:  d.score,
		Module: "rate",
		Reason: "rate:threshold_exceeded",
	}
}
