// ========================== detector module =============================================
//   Detector interface, result types, and IP state access interfaces.
//   Defines the contract between scorer, state, and concrete detectors.
//
//   WHAT IS HERE:
//     - IPView — IP state read interface (implemented by *state.IPState)
//     - ScoreAccess — IPView extension for reading and updating accumulated score
//     - DetectResult — result of a single detector run
//     - Detector — threat detector interface
//
//   WHAT IS NOT HERE:
//     - Detector implementations (probe.go, rate.go, useragent.go, ...) — Flow #4
//     - Score aggregation (scorer/)
//
//   LAYER ISOLATION:
//     IPView and ScoreAccess are defined here, not in state/ — so that scorer
//     depends only on detector/, without importing core/state directly.
//     *state.IPState implements both interfaces implicitly (Go duck typing).
//
//   core/ IMPORTS:
//     detector/ → parser/ (LogEntry as the shared pipeline DTO).
//     Unidirectional dependency, no cycles.

package detector

import (
	"time"

	"github.com/mr-addams/arxsentinel/internal/core/parser"
)

// ========================== IP state access interface =================================

// IPView — IP state read interface for detectors (read-only).
//
// Implemented by *state.IPState without importing the detector package from state/:
// Go does not require explicit declaration — matching signatures are sufficient.
//
// Purpose of each method:
//   GetTotalRequests  → bruteforce (404 ratio), rate, noasset
//   GetRequests404    → bruteforce (404 ratio)
//   RecentPaths       → probe (sensitive paths), crawler (sequential patterns)
//   ApproxRate        → rate anomaly (requests/sec over window)
type IPView interface {
	GetIP() string
	GetTotalRequests() int
	GetRequests404() int
	RecentPaths() []string
	ApproxRate(window time.Duration) float64
}

// ScoreAccess extends IPView with the ability to read and update accumulated score.
//
// Scorer calls SetScore after each evaluation — decay + new points are stored
// in the IP state for accumulation between requests.
type ScoreAccess interface {
	IPView
	GetScore() int
	GetScoreUpdatedAt() time.Time
	SetScore(score int, at time.Time)
}

// ========================== Detection result ==========================================

// DetectResult — result of a single detector run for a single IP.
//
// Score=0 means no threat — the detector adds no points.
// Module and Reason are populated only if Score > 0.
type DetectResult struct {
	Score  int    // threat points (0 = did not trigger)
	Module string // detector identifier: "probe", "rate", "ua", "bruteforce", ...
	Reason string // trigger details: "env_probe:3", "rate:142rps", "ua:Nuclei"
}

// ========================== Detector interface ========================================

// Detector — threat detector interface.
//
// Each detector analyzes a single (IP state + current request) combination
// and returns a threat score. Detectors do not store state themselves —
// all state lives in IPView (implemented by state.Tracker).
//
// Implementations — in Flow #4:
//   probe.go      — requests to .env, .git, wp-config, etc.
//   rate.go       — request rate spike over a window
//   useragent.go  — scanners, curl, empty UA
//   bruteforce.go — anomalous 404 percentage
//   crawler.go    — sequential URL traversal
//   noasset.go    — requests without loading CSS/JS/images
//   overflow.go   — anomalous URL length, WAF bypass parameters
type Detector interface {
	Name() string
	Detect(sv IPView, entry *parser.LogEntry) DetectResult
}
