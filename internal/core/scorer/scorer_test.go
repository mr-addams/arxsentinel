// ========================== Тесты scorer ================================================

package scorer

import (
	"testing"
	"time"

	"github.com/mr-addams/nginx-sentinel/internal/core/detector"
	"github.com/mr-addams/nginx-sentinel/internal/core/parser"
	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
)

// ========================== Mock-реализации ===========================================

// mockScoreState — минимальная реализация detector.ScoreAccess для тестов scorer.
// Не зависит от core/state — полная изоляция теста.
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

// fixedDetector возвращает фиксированный DetectResult независимо от входных данных.
// Позволяет точно контролировать вклад в score при тестировании scorer.
type fixedDetector struct {
	name   string
	result detector.DetectResult
}

func (d *fixedDetector) Name() string { return d.name }
func (d *fixedDetector) Detect(_ detector.IPView, _ *parser.LogEntry) detector.DetectResult {
	return d.result
}

// makeDetector создаёт мок-детектор с заданными очками и причиной.
func makeDetector(name string, score int, reason string) detector.Detector {
	return &fixedDetector{
		name: name,
		result: detector.DetectResult{Score: score, Module: name, Reason: reason},
	}
}

// makeScorer создаёт Scorer с тестовыми порогами (alert=50, ban=80, window=300s).
func makeScorer(detectors ...detector.Detector) *Scorer {
	cfg := config.ScoringConfig{
		AlertThreshold:    50,
		BanThreshold:      80,
		ObservationWindow: config.Duration(300 * time.Second),
	}
	return NewScorer(cfg, detectors, nil)
}

// freshState создаёт mockScoreState без накопленного score.
func freshState() *mockScoreState {
	return &mockScoreState{ip: "1.2.3.4"}
}

// makeEntry создаёт минимальный LogEntry для передачи в Evaluate.
func makeEntry() *parser.LogEntry {
	return &parser.LogEntry{
		RealIP: "1.2.3.4",
		Method: "GET",
		Path:   "/",
		Status: 200,
		Time:   time.Now(),
	}
}

// ========================== Тесты вердикта ===========================================

// TestEvaluateNoDetectors проверяет что без детекторов score остаётся 0 и уровень "".
func TestEvaluateNoDetectors(t *testing.T) {
	sc := makeScorer() // без детекторов
	sv := freshState()

	level, score, modules, _ := sc.Evaluate(sv, makeEntry())

	if level != "" {
		t.Errorf("уровень: ожидал %q, получил %q", "", level)
	}
	if score != 0 {
		t.Errorf("score: ожидал 0, получил %d", score)
	}
	if len(modules) != 0 {
		t.Errorf("modules: ожидал пустой, получил %v", modules)
	}
}

// TestEvaluateBelowAlert проверяет что score < alert дают уровень "".
func TestEvaluateBelowAlert(t *testing.T) {
	sc := makeScorer(makeDetector("probe", 30, "env_probe"))
	sv := freshState()

	level, score, _, _ := sc.Evaluate(sv, makeEntry())

	if level != "" {
		t.Errorf("уровень: ожидал %q, получил %q", "", level)
	}
	if score != 30 {
		t.Errorf("score: ожидал 30, получил %d", score)
	}
}

// TestEvaluateWarnLevel проверяет срабатывание уровня WARN при score ∈ [alert, ban).
func TestEvaluateWarnLevel(t *testing.T) {
	// 30 + 25 = 55 ≥ alert(50), < ban(80)
	sc := makeScorer(
		makeDetector("probe", 30, "env_probe"),
		makeDetector("ua", 25, "curl"),
	)
	sv := freshState()

	level, score, modules, reason := sc.Evaluate(sv, makeEntry())

	if level != "WARN" {
		t.Errorf("уровень: ожидал WARN, получил %q", level)
	}
	if score != 55 {
		t.Errorf("score: ожидал 55, получил %d", score)
	}
	if len(modules) != 2 {
		t.Errorf("modules: ожидал 2, получил %d", len(modules))
	}
	if reason == "" {
		t.Error("reason не должен быть пустым при срабатывании детекторов")
	}
}

// TestEvaluateThreatLevel проверяет срабатывание уровня THREAT при score ≥ ban.
func TestEvaluateThreatLevel(t *testing.T) {
	// 40 + 25 + 20 = 85 ≥ ban(80)
	sc := makeScorer(
		makeDetector("ua", 40, "Nuclei"),
		makeDetector("probe", 25, "wp-config"),
		makeDetector("rate", 20, "rate:120rps"),
	)
	sv := freshState()

	level, score, modules, _ := sc.Evaluate(sv, makeEntry())

	if level != "THREAT" {
		t.Errorf("уровень: ожидал THREAT, получил %q", level)
	}
	if score != 85 {
		t.Errorf("score: ожидал 85, получил %d", score)
	}
	if len(modules) != 3 {
		t.Errorf("modules: ожидал 3, получил %d", len(modules))
	}
}

// TestEvaluateZeroScoreDetectorIgnored проверяет что детектор с Score=0 не учитывается.
func TestEvaluateZeroScoreDetectorIgnored(t *testing.T) {
	sc := makeScorer(
		makeDetector("probe", 0, ""), // не сработал
		makeDetector("ua", 60, "sqlmap"),
	)
	sv := freshState()

	level, score, modules, _ := sc.Evaluate(sv, makeEntry())

	if level != "WARN" {
		t.Errorf("уровень: ожидал WARN, получил %q", level)
	}
	if score != 60 {
		t.Errorf("score: ожидал 60, получил %d", score)
	}
	if len(modules) != 1 || modules[0] != "ua" {
		t.Errorf("modules: ожидал [ua], получил %v", modules)
	}
}

// TestEvaluateScoreAccumulation проверяет накопление score между запросами.
func TestEvaluateScoreAccumulation(t *testing.T) {
	sc := makeScorer(makeDetector("probe", 30, "env"))
	sv := freshState()

	// Первый запрос → score = 0 + 30 = 30
	_, score1, _, _ := sc.Evaluate(sv, makeEntry())
	if score1 != 30 {
		t.Fatalf("после 1-го запроса score: ожидал 30, получил %d", score1)
	}

	// Второй запрос сразу — decay почти нулевой → score ≈ 30 + 30 = ~60
	_, score2, _, _ := sc.Evaluate(sv, makeEntry())
	if score2 < 55 || score2 > 60 {
		// Небольшой допуск на время выполнения теста
		t.Errorf("после 2-го запроса score: ожидал ~60, получил %d", score2)
	}
}

// ========================== Тесты decay ==============================================

// TestApplyDecayNoTime проверяет что при lastUpdate.IsZero() decay возвращает 0.
func TestApplyDecayNoTime(t *testing.T) {
	result := applyDecay(100, time.Time{}, 300*time.Second)
	if result != 0 {
		t.Errorf("decay с zero time: ожидал 0, получил %d", result)
	}
}

// TestApplyDecayFreshScore проверяет что score, обновлённый только что, почти не меняется.
func TestApplyDecayFreshScore(t *testing.T) {
	now := time.Now()
	result := applyDecay(100, now, 300*time.Second)
	// elapsed ≈ 0 → decay ≈ 0 → result ≈ 100
	if result < 99 {
		t.Errorf("свежий score: ожидал ≥99, получил %d", result)
	}
}

// TestApplyDecayHalfWindow проверяет уменьшение score вдвое при elapsed = window/2.
func TestApplyDecayHalfWindow(t *testing.T) {
	window := 300 * time.Second
	halfAgo := time.Now().Add(-window / 2)
	result := applyDecay(100, halfAgo, window)
	// elapsed = 150s, fraction = 0.5 → result = 100 * 0.5 = 50
	if result < 45 || result > 55 {
		t.Errorf("decay на пол-окна: ожидал ~50, получил %d", result)
	}
}

// TestApplyDecayExpired проверяет что score полностью рассеивается по истечении окна.
func TestApplyDecayExpired(t *testing.T) {
	window := 300 * time.Second
	longAgo := time.Now().Add(-window - time.Second)
	result := applyDecay(100, longAgo, window)
	if result != 0 {
		t.Errorf("истёкший score: ожидал 0, получил %d", result)
	}
}

// TestApplyDecayZeroScore проверяет что decay нулевого score возвращает 0.
func TestApplyDecayZeroScore(t *testing.T) {
	result := applyDecay(0, time.Now().Add(-10*time.Second), 300*time.Second)
	if result != 0 {
		t.Errorf("decay нулевого score: ожидал 0, получил %d", result)
	}
}
