// ========================== Модуль scorer ===============================================
//   Агрегация очков от детекторов, вынесение вердикта, линейный decay.
//
//   ЧТО ЗДЕСЬ:
//     - Scorer — агрегатор результатов всех детекторов по одному IP
//     - Evaluate() — запуск детекторов + decay + вынесение вердикта
//     - applyDecay() — линейное убывание накопленного score за окно
//
//   ВЕРДИКТ:
//     ""      → score < alert_threshold   (нормальная активность)
//     "WARN"  → score ∈ [alert, ban)      (подозрительная активность)
//     "THREAT"→ score ≥ ban_threshold     (Fail2Ban должен заблокировать)
//
//   DECAY (линейный):
//     decayed = currentScore × max(0, 1 − elapsed/window)
//     При elapsed = 0     → score не меняется
//     При elapsed = window/2 → score уменьшается вдвое
//     При elapsed ≥ window   → score обнуляется
//
//   ИЗОЛЯЦИЯ:
//     Scorer не импортирует core/state — работает через detector.ScoreAccess.
//     *state.IPState реализует этот интерфейс неявно (Go duck typing).
//
//   ИМПОРТЫ core/:
//     scorer/ → detector/ (ScoreAccess, Detector, DetectResult)
//     scorer/ → parser/ (LogEntry как DTO)

package scorer

import (
	"fmt"
	"strings"
	"time"

	"github.com/mr-addams/nginx-sentinel/internal/core/detector"
	"github.com/mr-addams/nginx-sentinel/internal/core/parser"
	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
)

// ========================== Scorer ====================================================

// Scorer агрегирует результаты детекторов и выносит вердикт по IP.
//
// Жизненный цикл вызова Evaluate:
//   1. Применить decay к накопленному score IP
//   2. Запустить каждый детектор, собрать DetectResult
//   3. Сложить очки, обновить score в IPState через ScoreAccess
//   4. Сравнить с порогами → вернуть уровень угрозы
type Scorer struct {
	alertThreshold int
	banThreshold   int
	window         time.Duration
	detectors      []detector.Detector

	logFn func(tag, msg, level string) // инъекция из main.go
}

// NewScorer создаёт Scorer из конфига.
// detectors передаётся пустым в Flow #2 — первые реальные детекторы добавятся в Flow #4.
// logFn передаётся из main.go — core/ не импортирует sys/utils напрямую.
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

// Evaluate запускает все детекторы, обновляет накопленный score IP с учётом decay
// и возвращает уровень угрозы.
//
// Параметры:
//   sv    — состояние IP (реализует detector.ScoreAccess; обычно *state.IPState)
//   entry — текущая строка лога
//
// Возвращает:
//   level   — "" / "WARN" / "THREAT"
//   score   — итоговый score после decay + нового вклада детекторов
//   modules — список сработавших детекторов (только Score > 0)
//   reason  — строка "module1:reason1,module2:reason2"
//
// Вызывается из main pipeline для каждой строки лога после Tracker.Update.
// Не блокирует — все операции синхронные в одной горутине.
func (s *Scorer) Evaluate(sv detector.ScoreAccess, entry *parser.LogEntry) (level string, score int, modules []string, reason string) {
	// ── Шаг 1: decay накопленного score ───────────────────────────────────────────────
	// now фиксируется один раз: decay и SetScore используют один момент времени.
	// Два вызова time.Now() создают систематический сдвиг: decay вычислен на t0,
	// score сохранён с t0+Δ — при следующем Evaluate elapsed занижен → score завышен.
	now := time.Now()
	existing := sv.GetScore()
	lastUpdate := sv.GetScoreUpdatedAt()
	decayed := applyDecay(existing, lastUpdate, s.window, now)

	// ── Шаг 2: сбор результатов от детекторов ─────────────────────────────────────────
	var delta int
	var modulesHit []string
	var reasons []string

	for _, d := range s.detectors {
		res := d.Detect(sv, entry)
		if res.Score <= 0 {
			continue
		}
		delta += res.Score
		modulesHit = append(modulesHit, res.Module)
		// Пустой Reason допустим по типу DetectResult — не добавляем "module:" без тела.
		if res.Reason != "" {
			reasons = append(reasons, fmt.Sprintf("%s:%s", res.Module, res.Reason))
		}

		if s.logFn != nil {
			s.logFn("DETECTOR", fmt.Sprintf("[%s] %s +%d (reason: %s)",
				strings.ToUpper(res.Module), sv.GetIP(), res.Score, res.Reason), "debug")
		}
	}

	// ── Шаг 3: обновление score в состоянии IP ────────────────────────────────────────
	// decayed ≥ 0 (гарантия applyDecay), delta ≥ 0 (суммируются только Score > 0)
	newScore := decayed + delta
	sv.SetScore(newScore, now)

	// ── Шаг 4: вынесение вердикта по порогам ──────────────────────────────────────────
	level = s.levelFor(newScore)

	if s.logFn != nil && (level != "" || delta > 0) {
		s.logFn("SCORER", fmt.Sprintf("%s score=%d (decay %d→%d + delta=%d) level=%q",
			sv.GetIP(), newScore, existing, decayed, delta, level), "debug")
	}

	return level, newScore, modulesHit, strings.Join(reasons, ",")
}

// levelFor возвращает уровень угрозы по score.
// Порядок проверок: сначала высокий порог (THREAT), потом низкий (WARN).
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

// applyDecay вычисляет score после линейного decay.
//
// Формула: decayed = current × max(0, 1 − elapsed/window)
//   elapsed = now − lastUpdate  (now передаётся из Evaluate — единый момент времени)
//   window  = scoring.observation_window из конфига
//
// При lastUpdate.IsZero() (первый запрос от IP) — возвращает 0.
// При elapsed ≥ window — возвращает 0 (score полностью рассеялся).
func applyDecay(current int, lastUpdate time.Time, window time.Duration, now time.Time) int {
	if current <= 0 || lastUpdate.IsZero() || window <= 0 {
		return 0
	}
	elapsed := now.Sub(lastUpdate)
	if elapsed >= window {
		return 0
	}
	// Умножаем через float64, округляем вниз (ceil не нужен — частичный score допустим)
	fraction := float64(elapsed) / float64(window)
	decayed := float64(current) * (1 - fraction)
	return int(decayed)
}
