// ========================== detector module =============================================
//   Type aliases and ScoreAccess for the detector layer.
//   Public contracts (IPView, DetectResult, Detector) are defined in pkg/plugin/detector.go
//   and re-exported here as type aliases so all internal packages compile unchanged.
//
//   WHAT IS HERE:
//     - IPView, DetectResult, Detector — type aliases for pkg/plugin equivalents
//     - ScoreAccess — extends plugin.IPView with score mutation (internal only)
//
//   WHAT IS NOT HERE:
//     - Detector implementations (probe.go, rate.go, useragent.go, ...)
//     - Score aggregation (scorer/)
//
//   LAYER ISOLATION:
//     ScoreAccess stays in internal — it exposes scorer internals not relevant
//     to external detector authors.
//     *state.IPState implements ScoreAccess implicitly (Go duck typing).

package detector

import (
	"time"

	"github.com/mr-addams/arx-core/pkg/plugin"
)

// IPView is a type alias for plugin.IPView.
// Canonical definition and method docs live in pkg/plugin/detector.go.
type IPView = plugin.IPView

// DetectResult is a type alias for plugin.DetectResult.
type DetectResult = plugin.DetectResult

// Detector is a type alias for plugin.Detector.
type Detector = plugin.Detector

// ScoreAccess extends IPView with score read/write used by the scorer.
//
// Not exported via pkg/plugin — score mutation is an internal scorer concern,
// not part of the public detector contract.
// *state.IPState satisfies this interface without explicit declaration.
type ScoreAccess interface {
	plugin.IPView
	GetScore() int
	GetScoreUpdatedAt() time.Time
	SetScore(score int, at time.Time)
}
