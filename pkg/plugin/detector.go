// ========================== pkg/plugin — Detector interface ==============================
//   Public contract for threat detection logic.
//   Moved from internal/core/detector so external developers can implement
//   custom detectors without importing internal packages.
//
//   WHAT IS HERE:
//     - IPView      — read-only IP state interface used by Detector implementations
//     - DetectResult — result of a single detector invocation
//     - Detector     — public interface for any threat detector
//
//   WHAT IS NOT HERE:
//     - ScoreAccess (internal/core/detector) — extends IPView with score mutation;
//       not public because it exposes scorer internals irrelevant to detector authors
//     - Detector implementations (internal/core/detector/*.go)
//
//   DEPENDENCY RULE:
//     pkg/plugin → stdlib only.

package plugin

import "time"

// IPView — read-only view of per-IP accumulated state.
// Implemented by *state.IPState (duck typing — no explicit declaration required).
//
// Purpose of each method:
//
//	GetTotalRequests → rate, bruteforce (404 ratio), noasset
//	GetRequests404   → bruteforce (404 ratio threshold)
//	RecentPaths      → probe (sensitive path patterns), crawler (sequential traversal)
//	ApproxRate       → rate anomaly (requests/sec over window)
type IPView interface {
	GetIP() string
	GetTotalRequests() int
	GetRequests404() int
	RecentPaths() []string
	ApproxRate(window time.Duration) float64
}

// DetectResult — outcome of a single detector run for one IP + request.
//
// Score == 0 means the detector did not trigger; Module and Reason are
// populated only when Score > 0.
type DetectResult struct {
	Score  int    // threat points contributed by this detector (0 = clean)
	Module string // detector identifier: "probe", "rate", "ua", ...
	Reason string // trigger detail: "env_probe:3", "rate:142rps", "ua:Nuclei"
}

// Detector — public interface for threat detection logic.
//
// Each implementation analyzes a single (IP state + current request) pair
// and returns a score contribution. Detectors are stateless — all per-IP
// state lives in IPView (provided by the pipeline via state.Tracker).
//
// Implement this interface to add a custom detector to arxsentinel.
type Detector interface {
	Name() string
	Detect(sv IPView, entry *LogEntry) DetectResult
	Manifest() Manifest
}
