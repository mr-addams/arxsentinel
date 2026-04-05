// ========================== Модуль detector =============================================
//   Интерфейс Detector, типы результатов и интерфейсы доступа к состоянию IP.
//   Определяет контракт между scorer, state и конкретными детекторами.
//
//   ЧТО ЗДЕСЬ:
//     - IPView — интерфейс чтения состояния IP (реализуется *state.IPState)
//     - ScoreAccess — расширение IPView для управления накопленным score
//     - DetectResult — результат работы одного детектора
//     - Detector — интерфейс детектора угроз
//
//   ЧТО НЕ ЗДЕСЬ:
//     - Реализации детекторов (probe.go, rate.go, useragent.go, ...) — Flow #4
//     - Агрегация очков (scorer/)
//
//   ИЗОЛЯЦИЯ ОТ СЛОЁВ:
//     IPView и ScoreAccess определены здесь, а не в state/ — чтобы scorer
//     зависел только от detector/, не импортируя core/state напрямую.
//     *state.IPState реализует оба интерфейса неявно (Go duck typing).
//
//   ИМПОРТЫ core/:
//     detector/ → parser/ (LogEntry как общий DTO пайплайна).
//     Однонаправленная зависимость, циклов нет.

package detector

import (
	"time"

	"github.com/mr-addams/nginx-sentinel/internal/core/parser"
)

// ========================== Интерфейс доступа к состоянию IP ==========================

// IPView — интерфейс чтения состояния IP для детекторов (только чтение).
//
// Реализуется *state.IPState без импорта пакета detector в state/:
// Go не требует явного объявления — достаточно совпадения сигнатур.
//
// Назначение каждого метода:
//   GetTotalRequests  → bruteforce (404 ratio), rate, noasset
//   GetRequests404    → bruteforce (404 ratio)
//   RecentPaths       → probe (чувствительные пути), crawler (последовательные паттерны)
//   ApproxRate        → rate anomaly (запросов/сек за окно)
type IPView interface {
	GetIP() string
	GetTotalRequests() int
	GetRequests404() int
	RecentPaths() []string
	ApproxRate(window time.Duration) float64
}

// ScoreAccess расширяет IPView возможностью чтения и обновления накопленного score.
//
// Scorer вызывает SetScore после каждой оценки — decay + новые очки сохраняются
// в состоянии IP для накопления между запросами.
type ScoreAccess interface {
	IPView
	GetScore() int
	GetScoreUpdatedAt() time.Time
	SetScore(score int, at time.Time)
}

// ========================== Результат детекции ========================================

// DetectResult — результат работы одного детектора по одному IP.
//
// Score=0 означает отсутствие угрозы — детектор не добавляет очков.
// Module и Reason заполняются только если Score > 0.
type DetectResult struct {
	Score  int    // очки угрозы (0 = не сработал)
	Module string // идентификатор детектора: "probe", "rate", "ua", "bruteforce", ...
	Reason string // детали срабатывания: "env_probe:3", "rate:142rps", "ua:Nuclei"
}

// ========================== Интерфейс детектора =======================================

// Detector — интерфейс детектора угроз.
//
// Каждый детектор анализирует одну комбинацию (состояние IP + текущий запрос)
// и возвращает количество очков угрозы. Детекторы не хранят состояние сами —
// всё состояние находится в IPView (реализуется state.Tracker).
//
// Реализации — в Flow #4:
//   probe.go      — запросы к .env, .git, wp-config и т.д.
//   rate.go       — всплеск запросов за окно
//   useragent.go  — сканеры, curl, пустой UA
//   bruteforce.go — аномальный % 404
//   crawler.go    — последовательный обход URL
//   noasset.go    — запросы без загрузки CSS/JS/images
//   overflow.go   — аномальная длина URL, WAF bypass параметры
type Detector interface {
	Name() string
	Detect(sv IPView, entry *parser.LogEntry) DetectResult
}
