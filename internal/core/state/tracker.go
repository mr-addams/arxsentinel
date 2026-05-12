// ========================== Модуль state/tracker ========================================
//   In-memory хранилище состояния по IP-адресам.
//   Основа для всех детекторов — они читают состояние через интерфейс detector.IPView.
//
//   ЧТО ЗДЕСЬ:
//     - IPState — состояние одного IP: счётчики, кольцевой буфер путей,
//       sliding-window rate, накопленный score
//     - Tracker — потокобезопасное хранилище с LRU eviction при max_tracked_ips
//     - GC — фоновая горутина очистки неактивных IP по таймеру (Task 2.2)
//
//   ЧТО НЕ ЗДЕСЬ:
//     - Классификация путей (page/asset) — делают детекторы сами (Flow #4)
//     - Логика детекции и scoring — core/detector, core/scorer
//
//   РЕАЛИЗУЕТ ИНТЕРФЕЙСЫ:
//     *IPState → detector.IPView (чтение состояния детекторами)
//     *IPState → detector.ScoreAccess (чтение/запись score scorer'ом)
//     Явный импорт detector/ не нужен — Go duck typing.
//
//   ПОТОКОБЕЗОПАСНОСТЬ:
//     Update() и gc() защищены write lock.
//     RunGC() запускается в отдельной горутине, работает через ticker.
//     Caller после Update() держит *IPState — GC не удалит активный IP
//     (LastSeen обновлён, порог не пройден).
//
//   ПАМЯТЬ (оценка для max_tracked_ips=100k):
//     IPState ≈ 1.2 KB (struct) + пути ≈ 64×20B = 1.3 KB → ~260 MB на 100k IP.
//     Приемлемо для security-демона. При нехватке — уменьшить pathBufSize.

package state

import (
	"container/list"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/mr-addams/nginx-sentinel/internal/core/parser"
	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
)

// pathBufSize — глубина кольцевого буфера путей на один IP.
// hardcoded: внутреннее ограничение памяти, не поведенческий параметр.
// 64 путей достаточно для probe-детектора (срабатывает сразу) и
// crawler-детектора (паттерн виден за 5–10 запросов).
const pathBufSize = 64

// ========================== IPState =================================================

// IPState — состояние одного IP-адреса.
//
// Поля читаются детекторами через detector.IPView / detector.ScoreAccess —
// оба интерфейса реализованы методами ниже без явного импорта пакета detector.
//
// Жизненный цикл:
//   создан  → первый Update(entry) для этого IP
//   активен → LastSeen обновляется при каждом Update
//   удалён  → GC при LastSeen < now-retention ИЛИ LRU eviction при max_tracked_ips
type IPState struct {
	IP        string
	FirstSeen time.Time
	LastSeen  time.Time

	TotalRequests int
	Requests404   int // для bruteforce ratio (Flow #6.1)

	// ── Кольцевой буфер путей ──────────────────────────────────────────────────────────
	// Хранит последние pathBufSize путей запросов в хронологическом порядке.
	// pathPos = следующая позиция записи; pathFull = буфер заполнен хотя бы раз.
	pathBuf  [pathBufSize]string
	pathPos  int
	pathFull bool

	// ── Sliding window rate counters ──────────────────────────────────────────────────
	// Два счётчика для скользящего окна: избегает хранения N тысяч временных меток.
	// Формула: approxRate = (prevCount*(1-elapsed/window) + currCount) / window.
	// Источник: standard sliding window log counter algorithm.
	rateWindowStart time.Time
	rateCurrCount   int
	ratePrevCount   int

	// ── Score ─────────────────────────────────────────────────────────────────────────
	// Накопленный score с линейным decay. Обновляется scorer'ом через SetScore.
	// Приватные поля: внешний доступ только через GetScore/GetScoreUpdatedAt/SetScore.
	score          int
	scoreUpdatedAt time.Time

	// Элемент LRU-списка — только для Tracker. Не трогать вручную.
	lruElem *list.Element
}

// ++++++++++++++++++++++++++ Реализация detector.IPView ++++++++++++++++++++++++++++++

func (s *IPState) GetIP() string           { return s.IP }
func (s *IPState) GetTotalRequests() int   { return s.TotalRequests }
func (s *IPState) GetRequests404() int     { return s.Requests404 }

// RecentPaths возвращает последние пути в хронологическом порядке (старые → новые).
// Возвращает копию — безопасно читать после получения из Tracker без блокировки.
func (s *IPState) RecentPaths() []string {
	if !s.pathFull {
		// Буфер не заполнен — только первые pathPos элементов актуальны
		result := make([]string, s.pathPos)
		copy(result, s.pathBuf[:s.pathPos])
		return result
	}
	// Буфер заполнен: pathPos указывает на самый старый элемент (след. для перезаписи)
	result := make([]string, pathBufSize)
	n := copy(result, s.pathBuf[s.pathPos:])
	copy(result[n:], s.pathBuf[:s.pathPos])
	return result
}

// ApproxRate возвращает приближённый rate запросов в секунду за окно window.
//
// Алгоритм скользящего окна через два счётчика:
//   approx = prevCount*(1-elapsed/window) + currCount
//   rate = approx / window.Seconds()
//
// Точность ±10% по сравнению с точным sliding window log.
// Не блокирует — вызывается из scoring pipeline без захвата мьютекса.
func (s *IPState) ApproxRate(window time.Duration) float64 {
	if window <= 0 || s.rateWindowStart.IsZero() {
		return 0
	}
	now := time.Now()
	elapsed := now.Sub(s.rateWindowStart)
	windowSec := window.Seconds()

	if elapsed >= 2*window {
		// Оба счётных окна полностью устарели
		return 0
	}
	if elapsed >= window {
		// Текущее окно завершилось; prevCount — данные прошлого окна
		overshot := elapsed - window
		fraction := float64(overshot) / float64(window)
		approx := float64(s.rateCurrCount) * (1 - fraction)
		return approx / windowSec
	}
	// Стандартный случай: внутри текущего окна
	fraction := float64(elapsed) / float64(window)
	approx := float64(s.ratePrevCount)*(1-fraction) + float64(s.rateCurrCount)
	return approx / windowSec
}

// ++++++++++++++++++++++++++ Реализация detector.ScoreAccess +++++++++++++++++++++++++

func (s *IPState) GetScore() int               { return s.score }
func (s *IPState) GetScoreUpdatedAt() time.Time { return s.scoreUpdatedAt }
func (s *IPState) SetScore(score int, at time.Time) {
	s.score = score
	s.scoreUpdatedAt = at
}

// ========================== Tracker =================================================

// Tracker — потокобезопасное хранилище состояний по IP.
//
// LRU eviction: при превышении maxIPs удаляем наименее используемый IP.
// GC eviction: по таймеру удаляем IP с LastSeen > retention.
//
// Конкурентный доступ:
//   - Основной pipeline: Update + scorer.Evaluate в одной горутине
//   - GC горутина: RunGC в отдельной горутине
//   - Оба пути захватывают write lock → сериализованы
type Tracker struct {
	mu     sync.RWMutex
	states map[string]*IPState
	lru    *list.List // Front = most recently used, Back = LRU candidate

	maxIPs     int
	rateWindow time.Duration // из config.Detectors.Rate.Window — для sliding window
	retention  time.Duration // из config.Scoring.ObservationWindow — для GC

	logFn func(tag, msg, level string) // инъекция из main.go
}

// NewTracker создаёт Tracker из конфига.
// logFn передаётся из main.go — core/ не импортирует sys/utils напрямую.
func NewTracker(cfg config.Config, logFn func(tag, msg, level string)) *Tracker {
	rw := time.Duration(cfg.Detectors.Rate.Window)
	if rw <= 0 {
		// Fallback здесь, а не в updateRateLocked — не засорять hot path под write lock
		rw = 60 * time.Second
	}
	return &Tracker{
		states:     make(map[string]*IPState),
		lru:        list.New(),
		maxIPs:     cfg.State.MaxTrackedIPs,
		rateWindow: rw,
		retention:  time.Duration(cfg.Scoring.ObservationWindow),
		logFn:      logFn,
	}
}

// Update обновляет состояние IP из записи лога и возвращает указатель на IPState.
//
// Потокобезопасно. Вызывается из main pipeline для каждой строки.
// Возвращаемый *IPState реализует detector.IPView и detector.ScoreAccess —
// можно передавать напрямую в scorer.Evaluate без приведения типа в main.go.
//
// ПОТОКОБЕЗОПАСНОСТЬ ВОЗВРАЩАЕМОГО *IPState:
//   Методы IPState (GetScore, SetScore, RecentPaths и т.д.) вызываются caller'ом
//   БЕЗ захвата мьютекса Tracker — это безопасно, поскольку:
//     1. Pipeline однопоточный: Update + scorer.Evaluate выполняются последовательно
//        в одной горутине main.
//     2. GC (RunGC) удаляет записи из map, но не модифицирует поля *IPState —
//        локальный указатель caller'а остаётся валидным (Go GC не соберёт объект,
//        пока есть живая ссылка).
//     3. GC не удалит активный IP: LastSeen обновлён в Update, порог retention
//        ещё не пройден.
//   Это допущение должно оставаться верным в Flow #4 когда детекторы начнут
//   активно читать *IPState. Если понадобится запись из нескольких горутин —
//   добавить отдельный мьютекс в IPState.
func (t *Tracker) Update(entry *parser.LogEntry) *IPState {
	t.mu.Lock()
	defer t.mu.Unlock()

	st, exists := t.states[entry.RealIP]
	if !exists {
		// Eviction до добавления: иначе в map кратковременно maxIPs+1 записей.
		// При maxIPs=1 предыдущий код держал в памяти 2 IP вместо 1.
		if len(t.states) >= t.maxIPs {
			t.evictLRULocked()
		}
		st = &IPState{
			IP:        entry.RealIP,
			FirstSeen: entry.Time,
		}
		t.states[entry.RealIP] = st
		st.lruElem = t.lru.PushFront(st)
	} else {
		// IP активен — перемещаем в голову LRU
		t.lru.MoveToFront(st.lruElem)
	}

	// ── Обновление счётчиков ───────────────────────────────────────────────────────────
	st.LastSeen = entry.Time
	st.TotalRequests++

	if entry.Status == 404 {
		st.Requests404++
	}

	// ── Кольцевой буфер путей ─────────────────────────────────────────────────────────
	st.pathBuf[st.pathPos] = entry.Path
	st.pathPos = (st.pathPos + 1) % pathBufSize
	if !st.pathFull && st.pathPos == 0 {
		// pathPos обернулся на 0 — буфер заполнен первый раз
		st.pathFull = true
	}

	// ── Sliding window rate counter ───────────────────────────────────────────────────
	t.updateRateLocked(st, entry.Time)

	return st
}

// updateRateLocked обновляет sliding window rate counters.
// Вызывается только под write lock из Update.
//
// Алгоритм: two-counter sliding window.
// ИЗВЕСТНОЕ ОГРАНИЧЕНИЕ: при gap ∈ (w, 2w) prevCount содержит данные из
// предыдущего окна (до gap). ApproxRate предполагает их равномерное
// распределение — при бурстовом трафике возможен false positive (~1–1.5x).
// Это приемлемо для rate-детектора: лучше ложный WARN чем пропущенная атака.
// Алгоритм применяется в production rate limiters (Cloudflare, nginx).
func (t *Tracker) updateRateLocked(st *IPState, reqTime time.Time) {
	w := t.rateWindow // всегда > 0 — fallback установлен в NewTracker

	if st.rateWindowStart.IsZero() {
		// Первый запрос от этого IP — инициализируем окно
		st.rateWindowStart = reqTime
		st.rateCurrCount = 1
		return
	}

	elapsed := reqTime.Sub(st.rateWindowStart)
	switch {
	case elapsed >= 2*w:
		// Оба окна устарели — начинаем с чистого листа
		st.rateWindowStart = reqTime
		st.rateCurrCount = 1
		st.ratePrevCount = 0
	case elapsed >= w:
		// Текущее окно завершилось — сдвигаем.
		// rateWindowStart.Add(w): новое окно начинается ровно через w от предыдущего,
		// не от reqTime — иначе потеряем часть elapsed для следующего запроса.
		st.ratePrevCount = st.rateCurrCount
		st.rateCurrCount = 1
		st.rateWindowStart = st.rateWindowStart.Add(w)
	default:
		st.rateCurrCount++
	}
}

// evictLRULocked удаляет наименее используемый IP (хвост LRU-списка).
// Вызывается только под write lock из Update.
func (t *Tracker) evictLRULocked() {
	oldest := t.lru.Back()
	if oldest == nil {
		return
	}
	st := oldest.Value.(*IPState)
	delete(t.states, st.IP)
	t.lru.Remove(oldest)
	if t.logFn != nil {
		t.logFn("GC", fmt.Sprintf("[GC] LRU eviction: %s (requests=%d)", st.IP, st.TotalRequests), "debug")
	}
}

// ========================== Статистика ==================================================

// Stats — снапшот состояния трекера для периодического логирования.
type Stats struct {
	TrackedIPs    int   // текущее число отслеживаемых IP
	TotalRequests int64 // сумма TotalRequests по всем IP
	Suspicious    int   // IP со Score > 0 (накопили хотя бы одно очко)
}

// GetStats возвращает снапшот статистики под read lock.
// Не вызывать из hot path — итерация по всем IP под RLock.
func (t *Tracker) GetStats() Stats {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var s Stats
	s.TrackedIPs = len(t.states)
	for _, st := range t.states {
		s.TotalRequests += int64(st.TotalRequests)
		if st.score > 0 {
			s.Suspicious++
		}
	}
	return s
}

// Reconfigure применяет новые параметры конфига после SIGHUP.
// Вызывается из main.go в блоке case <-reloadCh — между строками pipeline,
// поэтому нет concurrent access с Update (однопоточный pipeline).
// GC-горутина может читать retention/rateWindow → нужен write lock.
func (t *Tracker) Reconfigure(cfg config.Config) {
	rw := time.Duration(cfg.Detectors.Rate.Window)
	if rw <= 0 {
		rw = 60 * time.Second
	}
	t.mu.Lock()
	t.retention = time.Duration(cfg.Scoring.ObservationWindow)
	t.rateWindow = rw
	t.mu.Unlock()
}

// Len возвращает количество отслеживаемых IP (потокобезопасно).
func (t *Tracker) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.states)
}

// Has возвращает true если IP отслеживается (потокобезопасно).
// Используется в тестах вместо прямого доступа к tr.states — безопасно при t.Parallel().
func (t *Tracker) Has(ip string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	_, ok := t.states[ip]
	return ok
}

// ========================== GC ======================================================

// RunGC запускает фоновую горутину сборки мусора неактивных IP.
//
// Удаляет IP с LastSeen старше retention (= scoring.observation_window).
// interval из config.State.GCInterval — передаётся из main.go.
//
// Паттерн из telegram-бота (patterns.md §2 GC):
//   ticker + ctx.Done() + логгер через колбэк.
//
// Вызывать: go tracker.RunGC(ctx, time.Duration(cfg.State.GCInterval))
func (t *Tracker) RunGC(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	if t.logFn != nil {
		t.logFn("GC", fmt.Sprintf("сборщик мусора запущен (интервал=%v, retention=%v)", interval, t.retention), "info")
	}

	for {
		select {
		case <-ctx.Done():
			if t.logFn != nil {
				t.logFn("GC", "сборщик мусора остановлен", "info")
			}
			return
		case <-ticker.C:
			deleted, remaining := t.runGC()
			if t.logFn != nil && deleted > 0 {
				t.logFn("GC", fmt.Sprintf("удалено %d неактивных IP, осталось %d", deleted, remaining), "info")
			}
		}
	}
}

// runGC выполняет один цикл сборки мусора.
// Удаляет IP, неактивные дольше retention.
// Возвращает (deleted, remaining) — оба числа захвачены под одним write lock,
// поэтому лог "удалено N, осталось M" точно описывает состояние после этого цикла.
//
// threshold вычисляется внутри лока: Reconfigure() может обновить t.retention
// из main-горутины пока GC-горутина ещё не захватила мьютекс.
func (t *Tracker) runGC() (int, int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	threshold := time.Now().Add(-t.retention)

	deleted := 0
	for ip, st := range t.states {
		if st.LastSeen.Before(threshold) {
			t.lru.Remove(st.lruElem)
			delete(t.states, ip)
			deleted++
		}
	}
	return deleted, len(t.states)
}
