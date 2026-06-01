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
//   Registered as "rate" via init().

package detector

import (
	"time"

	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

func init() {
	Register("rate", newRateFactory)
}

// rateDetector detects anomalous request rate over a sliding window.
type rateDetector struct {
	plugin.NopManifest
	thresholdRPS float64       // threshold in req/s: Threshold / window.Seconds()
	window       time.Duration // ApproxRate window
	score        int
}

// newRateFactory creates a rateDetector from DetectorConfig.
func newRateFactory(cfg DetectorConfig, _ SharedResources) (plugin.Detector, error) {
	threshold := getInt(cfg.Params, "threshold", 100)
	window := getDuration(cfg.Params, "window", 60*time.Second)
	score := getInt(cfg.Params, "score", 25)

	// Guard: invalid window or threshold — both produce a broken thresholdRPS:
	//   window<=0  → thresholdRPS = +Inf (never fires) or NaN (threshold=0)
	//   threshold<=0 → thresholdRPS = 0, fires on *every* request, banning all traffic
	// Return a permanently disabled detector in both cases to surface the misconfiguration
	// rather than silently degrading into "block everyone" or "block nobody" mode.
	if window <= 0 || threshold <= 0 {
		return &disabledRateDetector{}, nil
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

// disabledRateDetector is returned when window <= 0 (misconfiguration).
// Never fires; Name() still returns "rate" so it appears in detector lists.
type disabledRateDetector struct {
	plugin.NopManifest
}

func (d *disabledRateDetector) Name() string { return "rate" }
func (d *disabledRateDetector) Detect(plugin.IPView, *plugin.LogEntry) plugin.DetectResult {
	return plugin.DetectResult{}
}
