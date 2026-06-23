// Unit-тесты для пакета dedup. Покрывают:
//   - базовый сценарий: повтор → true
//   - TTL expiry: после истечения → false
//   - ttl=0: dedup выключен, всегда false
//   - concurrency: гонка горутин, отсутствие data race
//   - edge cases: nil receiver, пустая строка, разные ключи
//   - cleanup: истёкшие записи вычищаются
//   - разделение API: Contains (pure lookup) vs Mark (side-effect)
//   - IsDuplicate как convenience-обёртку
//
// Для контроля времени используем fake clock (через setNow) — иначе тесты
// становятся flaky из-за реальных задержек.
package dedup

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// setNow подменяет nowFn в Window. Через замыкание меняем "текущее время"
// в тесте, не блокируя тестовые горутины на time.Sleep.
func setNow(w *Window, fn func() time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.nowFn = fn
}

// fakeClock — минимальный часовой механизм для тестов: переменная-время,
// которую тест двигает вручную.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func TestWindow_BasicDuplicate(t *testing.T) {
	w := NewWindow(5 * time.Minute)

	// Первый вызов — не duplicate.
	assert.False(t, w.IsDuplicate("1.2.3.4"), "first call must not be duplicate")
	// Повтор в пределах TTL — duplicate.
	assert.True(t, w.IsDuplicate("1.2.3.4"), "second call within TTL must be duplicate")
	// Другой ключ — не duplicate.
	assert.False(t, w.IsDuplicate("5.6.7.8"), "different key must not be duplicate")
	// И ещё раз тот же — duplicate.
	assert.True(t, w.IsDuplicate("1.2.3.4"), "subsequent call must remain duplicate")
}

func TestWindow_TTLExpiry(t *testing.T) {
	clk := newFakeClock()
	w := NewWindow(5 * time.Minute)
	setNow(w, clk.Now)

	// В момент T=0 — не duplicate.
	assert.False(t, w.IsDuplicate("1.2.3.4"))

	// T=4m59s — всё ещё в окне.
	clk.Advance(4*time.Minute + 59*time.Second)
	assert.True(t, w.IsDuplicate("1.2.3.4"), "within TTL")

	// T=5m01s — за пределами окна, IsDuplicate (как convenience) обновит
	// запись на новый срок (sliding window).
	clk.Advance(2 * time.Second)
	assert.False(t, w.IsDuplicate("1.2.3.4"), "after TTL expiry, sliding window resets")

	// Сразу после — снова duplicate.
	assert.True(t, w.IsDuplicate("1.2.3.4"))
}

func TestWindow_DisabledOnZeroTTL(t *testing.T) {
	w := NewWindow(0)

	// ttl=0 — dedup выключен, всегда false.
	for i := 0; i < 10; i++ {
		assert.False(t, w.IsDuplicate("1.2.3.4"), "ttl=0 must always return false")
	}

	// Size() должен вернуть 0 — map не инициализируется.
	assert.Equal(t, 0, w.Size(), "ttl=0 must not allocate map")
}

func TestWindow_NegativeTTLIsTreatedAsZero(t *testing.T) {
	w := NewWindow(-5 * time.Minute)

	// Защита от опечаток в конфиге: ttl < 0 → 0 → выключено.
	assert.False(t, w.IsDuplicate("1.2.3.4"))
	assert.False(t, w.IsDuplicate("1.2.3.4"))
	assert.Equal(t, 0, w.Size(), "negative TTL must behave like disabled")
}

func TestWindow_NilReceiver(t *testing.T) {
	var w *Window // nil

	// nil receiver не паникует, всегда false.
	assert.NotPanics(t, func() {
		assert.False(t, w.IsDuplicate("1.2.3.4"))
	})

	// Size на nil receiver тоже безопасен.
	assert.NotPanics(t, func() {
		assert.Equal(t, 0, w.Size())
	})

	// Contains и Mark на nil receiver тоже безопасны.
	assert.NotPanics(t, func() {
		assert.False(t, w.Contains("1.2.3.4"))
	})
	assert.NotPanics(t, func() {
		w.Mark("1.2.3.4")
	})
}

func TestWindow_EmptyStringKey(t *testing.T) {
	w := NewWindow(5 * time.Minute)

	// Пустая строка — валидный ключ, обрабатывается одинаково.
	assert.False(t, w.IsDuplicate(""))
	assert.True(t, w.IsDuplicate(""))
}

func TestWindow_CleanupExpiresOldEntries(t *testing.T) {
	clk := newFakeClock()
	w := NewWindow(10 * time.Minute)
	setNow(w, clk.Now)

	// Набиваем 3 ключа.
	assert.False(t, w.IsDuplicate("a"))
	assert.False(t, w.IsDuplicate("b"))
	assert.False(t, w.IsDuplicate("c"))
	assert.Equal(t, 3, w.Size(), "3 entries expected")

	// Сдвигаем время за пределы TTL.
	clk.Advance(11 * time.Minute)

	// Запрашиваем ключ "a" — IsDuplicate (convenience) обновит свою запись,
	// попутно почистив "b" и "c" (они истекли в окрестности).
	assert.False(t, w.IsDuplicate("a"))
	assert.Equal(t, 1, w.Size(), "only 'a' should remain after cleanup of expired")
}

func TestWindow_ConcurrentAccess(t *testing.T) {
	// Запускаем много горутин, каждая пишет/читает в один Window.
	// Цель: убедиться, что нет data race (запустить с -race)
	// и что дедупликация работает согласованно.
	clk := newFakeClock()
	w := NewWindow(5 * time.Minute)
	setNow(w, clk.Now)

	const goroutines = 50
	const perGoroutine = 1000

	var totalDup atomic.Int64
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(gid int) {
			defer wg.Done()
			// Каждая горутина работает со своим набором ключей,
			// но часть ключей пересекается с соседями.
			for i := 0; i < perGoroutine; i++ {
				key := "ip-" + string(rune('a'+(gid%5))) + "-" + string(rune('0'+(i%3)))
				if w.IsDuplicate(key) {
					totalDup.Add(1)
				}
			}
		}(g)
	}
	wg.Wait()

	// Не проверяем точное число — гонка недетерминирована.
	// Главное: не упали, не было паники, totalDup > 0 (часть вызовов попала в дубликаты).
	assert.Greater(t, totalDup.Load(), int64(0), "expected some duplicates under concurrent load")
}

func TestWindow_Size(t *testing.T) {
	clk := newFakeClock()
	w := NewWindow(5 * time.Minute)
	setNow(w, clk.Now)

	assert.Equal(t, 0, w.Size())

	w.IsDuplicate("a")
	assert.Equal(t, 1, w.Size())

	w.IsDuplicate("b")
	assert.Equal(t, 2, w.Size())

	// Повтор того же ключа — Size не растёт.
	w.IsDuplicate("a")
	assert.Equal(t, 2, w.Size())
}

// ── Разделённый API: Contains (pure lookup) и Mark (side-effect) ────────────
// Семантическое разделение — главное изменение Task 4. Эти тесты фиксируют
// контракт: Contains не модифицирует state, Mark всегда модифицирует.

func TestWindow_ContainsIsPureLookup(t *testing.T) {
	clk := newFakeClock()
	w := NewWindow(5 * time.Minute)
	setNow(w, clk.Now)

	// До Mark: Contains возвращает false.
	assert.False(t, w.Contains("1.2.3.4"), "Contains on empty window is false")
	assert.Equal(t, 0, w.Size(), "Contains must not allocate map or store entries")

	// Повторные Contains — идемпотентны, Size не растёт.
	for i := 0; i < 100; i++ {
		assert.False(t, w.Contains("1.2.3.4"), "Contains must remain pure")
	}
	assert.Equal(t, 0, w.Size(), "repeated Contains must not create entries")
}

func TestWindow_ContainsReflectsMark(t *testing.T) {
	clk := newFakeClock()
	w := NewWindow(5 * time.Minute)
	setNow(w, clk.Now)

	// До Mark — false.
	assert.False(t, w.Contains("1.2.3.4"))

	// Mark фиксирует ключ в окне.
	w.Mark("1.2.3.4")
	assert.True(t, w.Contains("1.2.3.4"), "after Mark, Contains must return true")
	assert.Equal(t, 1, w.Size())
}

func TestWindow_ContainsDoesNotExtendTTL(t *testing.T) {
	// Ключевой flaky-safe контракт: Contains НЕ продлевает TTL.
	// Иначе фоновый health-check (или просто частый polling) "обнулил" бы
	// sliding window и IP не банился бы никогда.
	clk := newFakeClock()
	w := NewWindow(5 * time.Minute)
	setNow(w, clk.Now)

	w.Mark("1.2.3.4")

	// T=4m59s — внутри окна.
	clk.Advance(4*time.Minute + 59*time.Second)
	assert.True(t, w.Contains("1.2.3.4"), "within TTL")

	// T=4m59s + 5s = 5m04s — за пределами. Contains возвращает false,
	// но запись физически остаётся (cleanup делает Mark, а не Contains).
	clk.Advance(5 * time.Second)
	assert.False(t, w.Contains("1.2.3.4"), "after TTL expiry, Contains is false")
}

func TestWindow_MarkSlidingWindow(t *testing.T) {
	clk := newFakeClock()
	w := NewWindow(5 * time.Minute)
	setNow(w, clk.Now)

	// T=0: Mark.
	w.Mark("1.2.3.4")
	assert.True(t, w.Contains("1.2.3.4"))

	// T=4m: повторный Mark — дедлайн сдвигается к T=9m.
	clk.Advance(4 * time.Minute)
	w.Mark("1.2.3.4")
	assert.True(t, w.Contains("1.2.3.4"), "still within window after re-mark")

	// T=8m59s: всё ещё в окне.
	clk.Advance(4*time.Minute + 59*time.Second)
	assert.True(t, w.Contains("1.2.3.4"), "sliding window extended TTL")

	// T=9m01s: за пределами.
	clk.Advance(2 * time.Second)
	assert.False(t, w.Contains("1.2.3.4"), "after sliding TTL expiry, Contains is false")
}

func TestWindow_MarkCleansExpiredEntries(t *testing.T) {
	// Mark обязан чистить истёкшие записи — иначе Size() неограниченно
	// растёт. Это поведение было у старого IsDuplicate, сохраняем в Mark.
	clk := newFakeClock()
	w := NewWindow(10 * time.Minute)
	setNow(w, clk.Now)

	w.Mark("a")
	w.Mark("b")
	w.Mark("c")
	assert.Equal(t, 3, w.Size())

	clk.Advance(11 * time.Minute)

	// Mark на "d" должен попутно почистить "a", "b", "c" (они истекли).
	w.Mark("d")
	assert.Equal(t, 1, w.Size(), "Mark must clean expired entries opportunistically")
	assert.True(t, w.Contains("d"))
}

func TestWindow_MarkNoOpOnZeroTTL(t *testing.T) {
	w := NewWindow(0)

	// ttl=0: Mark — no-op, Size не растёт.
	w.Mark("1.2.3.4")
	w.Mark("1.2.3.4")
	assert.Equal(t, 0, w.Size(), "Mark on ttl=0 must not store entries")

	// Contains всегда false.
	assert.False(t, w.Contains("1.2.3.4"))
}

func TestWindow_MarkNoOpOnNilReceiver(t *testing.T) {
	var w *Window
	assert.NotPanics(t, func() { w.Mark("1.2.3.4") })
}

func TestWindow_ContainsNoOpOnZeroTTL(t *testing.T) {
	w := NewWindow(0)
	// ttl=0: Contains всегда false, не дёргает map.
	for i := 0; i < 10; i++ {
		assert.False(t, w.Contains("1.2.3.4"))
	}
	assert.Equal(t, 0, w.Size())
}

func TestWindow_IsDuplicateIsConvenience(t *testing.T) {
	// Контракт: IsDuplicate(k) ⇔ (Contains(k) || (Mark(k), false)).
	// Это удобная обёртка для сценариев, где side-effect ошибки не критичен.
	clk := newFakeClock()
	w := NewWindow(5 * time.Minute)
	setNow(w, clk.Now)

	// Первый вызов: false + Mark.
	assert.False(t, w.IsDuplicate("1.2.3.4"))
	assert.Equal(t, 1, w.Size(), "IsDuplicate must call Mark on first call")
	assert.True(t, w.Contains("1.2.3.4"), "subsequent Contains must see the mark")

	// Второй вызов: true (через Contains внутри IsDuplicate).
	assert.True(t, w.IsDuplicate("1.2.3.4"))
	assert.Equal(t, 1, w.Size(), "duplicate call must not grow Size")

	// Разные ключи — изолированы.
	assert.False(t, w.IsDuplicate("5.6.7.8"))
	assert.Equal(t, 2, w.Size())
}

// ── Flaky-safe сценарий: симуляция, в которой Mark не должен быть
// вызван при ошибке upstream. Это тест-документация паттерна из Task 4.

func TestWindow_FlakySafePattern(t *testing.T) {
	clk := newFakeClock()
	w := NewWindow(5 * time.Minute)
	setNow(w, clk.Now)

	ip := "1.2.3.4"

	// 1) Первый event: Contains=false, выполняем действие.
	assert.False(t, w.Contains(ip), "pre-action: not in window")
	// ... doAction() возвращает ошибку (flaky upstream) ...
	// Mark НЕ вызывается: это и есть flaky-safe.

	// 2) Второй event: Contains по-прежнему false, повторяем попытку.
	assert.False(t, w.Contains(ip), "after failed action, IP must NOT be in window")

	// 3) Третий event: действие успешно, теперь Mark.
	w.Mark(ip)

	// 4) Четвёртый event: Contains=true, пропускаем.
	assert.True(t, w.Contains(ip), "after successful action + Mark, skip duplicates")
}

// ── MarkBatch: одна mutex-блокировка для группы ключей. ──────────────────
// Используется executor flush — после успешного batch Add помечаем
// все ключи одним вызовом вместо N отдельных Mark.

func TestWindow_MarkBatchBasic(t *testing.T) {
	w := NewWindow(5 * time.Minute)

	w.MarkBatch([]string{"1.1.1.1", "2.2.2.2", "3.3.3.3"})

	assert.Equal(t, 3, w.Size())
	assert.True(t, w.Contains("1.1.1.1"))
	assert.True(t, w.Contains("2.2.2.2"))
	assert.True(t, w.Contains("3.3.3.3"))
}

func TestWindow_MarkBatchEmptyIsNoOp(t *testing.T) {
	clk := newFakeClock()
	w := NewWindow(5 * time.Minute)
	setNow(w, clk.Now)

	// Пустой slice: MarkBatch не должен даже инициализировать map
	// (важно для случая, когда flush вернул ноль успешных IP).
	w.MarkBatch(nil)
	w.MarkBatch([]string{})
	assert.Equal(t, 0, w.Size(), "empty MarkBatch must not allocate map")
}

func TestWindow_MarkBatchNoOpOnZeroTTL(t *testing.T) {
	w := NewWindow(0)
	w.MarkBatch([]string{"1.1.1.1", "2.2.2.2"})
	assert.Equal(t, 0, w.Size(), "MarkBatch on ttl=0 must be no-op")
}

func TestWindow_MarkBatchNoOpOnNilReceiver(t *testing.T) {
	var w *Window
	assert.NotPanics(t, func() { w.MarkBatch([]string{"1.1.1.1"}) })
}

func TestWindow_MarkBatchCleansExpired(t *testing.T) {
	// Как и Mark, MarkBatch должен попутно чистить истёкшие.
	clk := newFakeClock()
	w := NewWindow(10 * time.Minute)
	setNow(w, clk.Now)

	w.MarkBatch([]string{"a", "b", "c"})
	assert.Equal(t, 3, w.Size())

	clk.Advance(11 * time.Minute)

	w.MarkBatch([]string{"d"})
	assert.Equal(t, 1, w.Size(), "expired entries cleaned during MarkBatch")
	assert.True(t, w.Contains("d"))
}

func TestWindow_MarkBatchDedupWithinInput(t *testing.T) {
	// Дубликаты внутри keys — идемпотентны: map[ip] = deadline.
	// Size не должен расти сверх уникальных ключей.
	clk := newFakeClock()
	w := NewWindow(5 * time.Minute)
	setNow(w, clk.Now)

	w.MarkBatch([]string{"1.1.1.1", "1.1.1.1", "1.1.1.1"})
	assert.Equal(t, 1, w.Size(), "duplicate keys in batch collapse to one entry")
}

// TestWindow_CleanupAllExpired verifies that Mark and MarkBatch clean up ALL
// expired entries, leaving Size() == 0 when all keys have expired (C6 regression).
func TestWindow_CleanupAllExpired(t *testing.T) {
	clk := newFakeClock()
	w := NewWindow(10 * time.Minute)
	setNow(w, clk.Now)

	// Insert 1000 keys using MarkBatch.
	keys := make([]string, 1000)
	for i := range keys {
		keys[i] = fmt.Sprintf("ip-10.0.0.%d", i)
	}
	w.MarkBatch(keys)
	assert.Equal(t, 1000, w.Size())

	// Advance past TTL — all keys expired.
	clk.Advance(11 * time.Minute)

	// Mark a new key triggers cleanup of all expired.
	w.Mark("new-key")
	assert.Equal(t, 1, w.Size(), "all expired keys must be cleaned; only new-key remains")

	// Mark all keys again, then advance, then MarkBatch — all should be cleaned.
	w.MarkBatch(keys)
	assert.Equal(t, 1001, w.Size())

	clk.Advance(11 * time.Minute)

	w.MarkBatch([]string{"another-key"})
	assert.Equal(t, 1, w.Size(), "MarkBatch must also clean all expired")
	assert.True(t, w.Contains("another-key"))
}
