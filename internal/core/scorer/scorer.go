// ========================== Module scorer ===============================================
//   Aggregation of scores from detectors, verdict determination, linear decay.
//
//   WHAT IS HERE:
//     - Scorer — aggregator of all detector results per IP
//     - Evaluate() — run detectors + decay + issue verdict
//     - applyDecay() — linear decay of accumulated score over the window
//
//   VERDICT:
//     ""      → score < alert_threshold   (normal activity)
//     "WARN"  → score ∈ [alert, ban)      (suspicious activity)
//     "THREAT"→ score ≥ ban_threshold     (Fail2Ban should block)
//
//   DECAY (linear):
//     decayed = currentScore × max(0, 1 − elapsed/window)
//     When elapsed = 0       → score unchanged
//     When elapsed = window/2 → score halved
//     When elapsed ≥ window  → score zeroed
//
//   ISOLATION:
//     Scorer does not import core/state — works through detector.ScoreAccess.
//     *state.IPState implements this interface implicitly (Go duck typing).
//
//   core/ IMPORTS:
//     scorer/ → detector/ (ScoreAccess, Detector, DetectResult)
//     scorer/ → parser/ (LogEntry as DTO)

package scorer

import (
	"fmt"
	"strings"
	"time"

	"github.com/mr-addams/arxsentinel/internal/core/detector"
	"github.com/mr-addams/arxsentinel/internal/core/parser"
	"github.com/mr-addams/arxsentinel/internal/sys/config"
)

// ========================== Scorer ====================================================

// Scorer aggregates detector results and issues a verdict per IP.
//
// Evaluate call lifecycle:
//   1. Apply decay to the accumulated IP score
//   2. Run each detector, collect DetectResult
//   3. Sum scores, update score in IPState via ScoreAccess
//   4. Compare against thresholds → return threat level
type Scorer struct {
	alertThreshold int
	banThreshold   int
	window         time.Duration
	detectors      []detector.Detector

	logFn func(tag, msg, level string) // injected from main.go
}

// NewScorer creates a Scorer from config.
// detectors is passed empty in Flow #2 — first real detectors will be added in Flow #4.
// logFn is passed from main.go — core/ does not import sys/utils directly.
func NewScorer(cfg config.ScoringConfig, detectors []detector.Detector, logFn func(tag, msg, level string)) *Scorer {
	return &Scorer{
		alertThreshold: cfg.AlertThreshold,
		banThreshold:   cfg.BanThreshold,
		window:         time.Duration(cfg.ObservationWindow),
		detectors:      detectors,
		logFn:          logFn,
	}
}

// ========================== Evaluate ==================================================

// Evaluate runs all detectors, updates the accumulated IP score with decay applied,
// and returns the threat level.
//
//   Parameters:
//     sv        — IP state (implements detector.ScoreAccess; typically *state.IPState)
//     entry     — current log line
//     exemptSet — detector names to skip (nil or empty = all detectors run)
//
// Returns:
//   level   — "" / "WARN" / "THREAT"
//   score   — final score after decay + new detector contributions
//   modules — list of triggered detectors (only Score > 0)
//   reason  — string "module1:reason1,module2:reason2"
//
// Called from the main pipeline for each log line after Tracker.Update.
// Non-blocking — all operations are synchronous in a single goroutine.
func (s *Scorer) Evaluate(sv detector.ScoreAccess, entry *parser.LogEntry, exemptSet map[string]struct{}) (level string, score int, modules []string, reason string) {
	// ── Step 1: decay of accumulated score ───────────────────────────────────────────────
	// now is fixed once: decay and SetScore use the same point in time.
	// Two time.Now() calls create a systematic drift: decay computed at t0,
	// score stored at t0+Δ — on the next Evaluate elapsed is underestimated → score inflated.
	now := time.Now()
	existing := sv.GetScore()
	lastUpdate := sv.GetScoreUpdatedAt()
	decayed := applyDecay(existing, lastUpdate, s.window, now)

	// ── Step 2: collect detector results ─────────────────────────────────────────
	var delta int
	var modulesHit []string
	var reasons []string

	for _, d := range s.detectors {
		// exemptSet filter: skip detectors in the exempt list.
		if exemptSet != nil {
			if _, ok := exemptSet[d.Name()]; ok {
				continue
			}
		}
		res := d.Detect(sv, entry)
		if res.Score <= 0 {
			continue
		}
		delta += res.Score
		modulesHit = append(modulesHit, res.Module)
		// Empty Reason is valid per DetectResult type — do not add "module:" without a body.
		if res.Reason != "" {
			reasons = append(reasons, fmt.Sprintf("%s:%s", res.Module, res.Reason))
		}

		if s.logFn != nil {
			s.logFn("DETECTOR", fmt.Sprintf("[%s] %s +%d (reason: %s)",
				strings.ToUpper(res.Module), sv.GetIP(), res.Score, res.Reason), "debug")
		}
	}

	// ── Step 3: update score in IP state ────────────────────────────────────────────────
	// decayed ≥ 0 (guaranteed by applyDecay), delta ≥ 0 (only Score > 0 are summed)
	newScore := decayed + delta
	sv.SetScore(newScore, now)

	// ── Step 4: determine verdict against thresholds ──────────────────────────────────────
	level = s.levelFor(newScore)

	if s.logFn != nil && (level != "" || delta > 0) {
		s.logFn("SCORER", fmt.Sprintf("%s score=%d (decay %d→%d + delta=%d) level=%q",
			sv.GetIP(), newScore, existing, decayed, delta, level), "debug")
	}

	return level, newScore, modulesHit, strings.Join(reasons, ",")
}

// levelFor returns the threat level for the given score.
// Check order: high threshold first (THREAT), then low (WARN).
func (s *Scorer) levelFor(score int) string {
	switch {
	case score >= s.banThreshold:
		return "THREAT"
	case score >= s.alertThreshold:
		return "WARN"
	default:
		return ""
	}
}

// ========================== Decay =====================================================

// applyDecay computes the score after linear decay.
//
// Formula: decayed = current × max(0, 1 − elapsed/window)
//   elapsed = now − lastUpdate  (now is passed from Evaluate — single point in time)
//   window  = scoring.observation_window from config
//
// When lastUpdate.IsZero() (first request from IP) — returns 0.
// When elapsed ≥ window — returns 0 (score fully dissipated).
func applyDecay(current int, lastUpdate time.Time, window time.Duration, now time.Time) int {
	if current <= 0 || lastUpdate.IsZero() || window <= 0 {
		return 0
	}
	elapsed := now.Sub(lastUpdate)
	if elapsed >= window {
		return 0
	}
	// Multiply via float64, truncate down (ceil not needed — partial score is acceptable)
	fraction := float64(elapsed) / float64(window)
	decayed := float64(current) * (1 - fraction)
	return int(decayed)
}
