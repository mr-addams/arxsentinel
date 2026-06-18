// ========================== Tests scorer ================================================

package scorer

import (
	"testing"
	"time"

	"github.com/mr-addams/arxsentinel/internal/core/detector"
	"github.com/mr-addams/arxsentinel/internal/core/parser"
	"github.com/mr-addams/arxsentinel/internal/sys/config"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

// ========================== Mock implementations ===========================================

// mockScoreState — minimal implementation of detector.ScoreAccess for scorer tests.
// Does not depend on core/state — full test isolation.
type mockScoreState struct {
	ip          string
	score       int
	scoreAt     time.Time
	total       int
	requests404 int
	paths       []string
	rate        float64
}

func (m *mockScoreState) GetIP() string                    { return m.ip }
func (m *mockScoreState) GetTotalRequests() int            { return m.total }
func (m *mockScoreState) GetRequests404() int              { return m.requests404 }
func (m *mockScoreState) RecentPaths() []string            { return m.paths }
func (m *mockScoreState) ApproxRate(_ time.Duration) float64 { return m.rate }
func (m *mockScoreState) GetScore() int                    { return m.score }
func (m *mockScoreState) GetScoreUpdatedAt() time.Time     { return m.scoreAt }
func (m *mockScoreState) SetScore(score int, at time.Time) { m.score = score; m.scoreAt = at }

// fixedDetector returns a fixed DetectResult regardless of input.
// Allows precise control over score contribution when testing scorer.
type fixedDetector struct {
	name   string
	result detector.DetectResult
}

func (d *fixedDetector) Name() string { return d.name }

func (d *fixedDetector) Manifest() plugin.Manifest { return plugin.Manifest{} }
func (d *fixedDetector) Detect(_ detector.IPView, _ *parser.LogEntry) detector.DetectResult {
	return d.result
}

// makeDetector creates a mock detector with specified score and reason.
func makeDetector(name string, score int, reason string) detector.Detector {
	return &fixedDetector{
		name: name,
		result: detector.DetectResult{Score: score, Module: name, Reason: reason},
	}
}

// makeScorer creates a Scorer with test thresholds (alert=50, ban=80, window=300s).
func makeScorer(detectors ...detector.Detector) *Scorer {
	cfg := config.ScoringConfig{
		AlertThreshold:    50,
		BanThreshold:      80,
		ObservationWindow: config.Duration(300 * time.Second),
	}
	return NewScorer(cfg, detectors, nil)
}

// freshState creates a mockScoreState without accumulated score.
func freshState() *mockScoreState {
	return &mockScoreState{ip: "1.2.3.4"}
}

// makeEntry creates a minimal LogEntry for passing to Evaluate.
func makeEntry() *parser.LogEntry {
	return &parser.LogEntry{
		RealIP: "1.2.3.4",
		Method: "GET",
		Path:   "/",
		Status: 200,
		Time:   time.Now(),
	}
}

// ========================== Verdict tests ===========================================

// TestEvaluateNoDetectors verifies that without detectors score stays 0 and level is "".
func TestEvaluateNoDetectors(t *testing.T) {
	sc := makeScorer() // no detectors
	sv := freshState()

	level, score, modules, _ := sc.Evaluate(sv, makeEntry(), nil)

	if level != "" {
		t.Errorf("level: expected %q, got %q", "", level)
	}
	if score != 0 {
		t.Errorf("score: expected 0, got %d", score)
	}
	if len(modules) != 0 {
		t.Errorf("modules: expected empty, got %v", modules)
	}
}

// TestEvaluateBelowAlert verifies that score < alert gives level "".
func TestEvaluateBelowAlert(t *testing.T) {
	sc := makeScorer(makeDetector("probe", 30, "env_probe"))
	sv := freshState()

	level, score, _, _ := sc.Evaluate(sv, makeEntry(), nil)

	if level != "" {
		t.Errorf("level: expected %q, got %q", "", level)
	}
	if score != 30 {
		t.Errorf("score: expected 30, got %d", score)
	}
}

// TestEvaluateWarnLevel verifies WARN level triggers when score ∈ [alert, ban).
func TestEvaluateWarnLevel(t *testing.T) {
	// 30 + 25 = 55 ≥ alert(50), < ban(80)
	sc := makeScorer(
		makeDetector("probe", 30, "env_probe"),
		makeDetector("ua", 25, "curl"),
	)
	sv := freshState()

	level, score, modules, reason := sc.Evaluate(sv, makeEntry(), nil)

	if level != "WARN" {
		t.Errorf("level: expected WARN, got %q", level)
	}
	if score != 55 {
		t.Errorf("score: expected 55, got %d", score)
	}
	if len(modules) != 2 {
		t.Errorf("modules: expected 2, got %d", len(modules))
	}
	if reason == "" {
		t.Error("reason must not be empty when detectors trigger")
	}
}

// TestEvaluateThreatLevel verifies THREAT level triggers when score ≥ ban.
func TestEvaluateThreatLevel(t *testing.T) {
	// 40 + 25 + 20 = 85 ≥ ban(80)
	sc := makeScorer(
		makeDetector("ua", 40, "Nuclei"),
		makeDetector("probe", 25, "wp-config"),
		makeDetector("rate", 20, "rate:120rps"),
	)
	sv := freshState()

	level, score, modules, _ := sc.Evaluate(sv, makeEntry(), nil)

	if level != "THREAT" {
		t.Errorf("level: expected THREAT, got %q", level)
	}
	if score != 85 {
		t.Errorf("score: expected 85, got %d", score)
	}
	if len(modules) != 3 {
		t.Errorf("modules: expected 3, got %d", len(modules))
	}
}

// TestEvaluateZeroScoreDetectorIgnored verifies that a detector with Score=0 is not counted.
func TestEvaluateZeroScoreDetectorIgnored(t *testing.T) {
	sc := makeScorer(
		makeDetector("probe", 0, ""), // did not trigger
		makeDetector("ua", 60, "sqlmap"),
	)
	sv := freshState()

	level, score, modules, _ := sc.Evaluate(sv, makeEntry(), nil)

	if level != "WARN" {
		t.Errorf("level: expected WARN, got %q", level)
	}
	if score != 60 {
		t.Errorf("score: expected 60, got %d", score)
	}
	if len(modules) != 1 || modules[0] != "ua" {
		t.Errorf("modules: expected [ua], got %v", modules)
	}
}

// TestEvaluateScoreAccumulation verifies score accumulation between requests.
func TestEvaluateScoreAccumulation(t *testing.T) {
	sc := makeScorer(makeDetector("probe", 30, "env"))
	sv := freshState()

	// First request → score = 0 + 30 = 30
	_, score1, _, _ := sc.Evaluate(sv, makeEntry(), nil)
	if score1 != 30 {
		t.Fatalf("after 1st request score: expected 30, got %d", score1)
	}

	// Second request immediately — decay nearly zero → score ≈ 30 + 30 = ~60
	_, score2, _, _ := sc.Evaluate(sv, makeEntry(), nil)
	if score2 < 55 || score2 > 60 {
		// Small tolerance for test execution time
		t.Errorf("after 2nd request score: expected ~60, got %d", score2)
	}
}

// ========================== Decay tests ==============================================

// TestApplyDecayNoTime verifies that when lastUpdate.IsZero() decay returns 0.
func TestApplyDecayNoTime(t *testing.T) {
	result := applyDecay(100, time.Time{}, 300*time.Second, time.Now())
	if result != 0 {
		t.Errorf("decay with zero time: expected 0, got %d", result)
	}
}

// TestApplyDecayFreshScore verifies that a score updated just now barely changes.
func TestApplyDecayFreshScore(t *testing.T) {
	now := time.Now()
	result := applyDecay(100, now, 300*time.Second, now)
	// elapsed = 0 → decay = 0 → result = 100 (deterministic)
	if result < 99 {
		t.Errorf("fresh score: expected ≥99, got %d", result)
	}
}

// TestApplyDecayHalfWindow verifies score halves when elapsed = window/2.
func TestApplyDecayHalfWindow(t *testing.T) {
	window := 300 * time.Second
	now := time.Now()
	halfAgo := now.Add(-window / 2)
	result := applyDecay(100, halfAgo, window, now)
	// elapsed = 150s exactly (now is deterministic) → fraction = 0.5 → result = 50
	if result < 45 || result > 55 {
		t.Errorf("decay at half-window: expected ~50, got %d", result)
	}
}

// TestApplyDecayExpired verifies that score fully dissipates after the window expires.
func TestApplyDecayExpired(t *testing.T) {
	window := 300 * time.Second
	now := time.Now()
	longAgo := now.Add(-window - time.Second)
	result := applyDecay(100, longAgo, window, now)
	if result != 0 {
		t.Errorf("expired score: expected 0, got %d", result)
	}
}

// TestApplyDecayZeroScore verifies that decay of a zero score returns 0.
func TestApplyDecayZeroScore(t *testing.T) {
	result := applyDecay(0, time.Now().Add(-10*time.Second), 300*time.Second, time.Now())
	if result != 0 {
		t.Errorf("decay of zero score: expected 0, got %d", result)
	}
}

// ========================== Benchmarks =================================================

// BenchmarkScorerEvaluate measures the throughput of Scorer.Evaluate with multiple detectors.
// Simulates a realistic scoring path: 5 detectors, each contributing score.
func BenchmarkScorerEvaluate(b *testing.B) {
	detectors := []detector.Detector{
		makeDetector("probe", 30, "env_probe"),
		makeDetector("ua", 25, "curl"),
		makeDetector("rate", 20, "rate:120rps"),
		makeDetector("badbot", 15, "fake_bot"),
		makeDetector("overflow", 10, "long_url"),
	}
	sc := makeScorer(detectors...)
	sv := freshState()
	entry := makeEntry()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sc.Evaluate(sv, entry, nil)
	}
}

// ========================== ExemptSet filter tests ======================================

func TestScorer_ExemptDetectorFilter(t *testing.T) {
	// Two detectors: noasset (score=20) and rate (score=25).
	// exemptSet excludes "noasset" → only rate contributes.
	sc := makeScorer(
		makeDetector("noasset", 20, "no_assets"),
		makeDetector("rate", 25, "rate:150rps"),
	)
	sv := freshState()

	// Without exemptSet — both detectors fire
	level1, score1, modules1, _ := sc.Evaluate(sv, makeEntry(), nil)
	if score1 != 45 {
		t.Errorf("without exemptSet: expected score=45, got %d", score1)
	}
	if len(modules1) != 2 {
		t.Errorf("without exemptSet: expected 2 modules, got %d", len(modules1))
	}
	_ = level1

	// With exemptSet excluding "noasset" — only rate fires
	sv2 := freshState()
	exempt := map[string]struct{}{"noasset": {}}
	level2, score2, modules2, _ := sc.Evaluate(sv2, makeEntry(), exempt)

	if score2 != 25 {
		t.Errorf("with exemptSet: expected score=25, got %d", score2)
	}
	if len(modules2) != 1 || modules2[0] != "rate" {
		t.Errorf("with exemptSet: expected [rate], got %v", modules2)
	}
	_ = level2
}
