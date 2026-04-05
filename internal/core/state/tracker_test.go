// ========================== Тесты state/tracker =========================================

package state

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/mr-addams/nginx-sentinel/internal/core/parser"
	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
)

// ========================== Вспомогательные функции ===================================

// makeConfig возвращает минимальный конфиг для тестов.
func makeConfig(maxIPs int) config.Config {
	cfg := config.Config{}
	cfg.State.MaxTrackedIPs = maxIPs
	cfg.State.GCInterval = config.Duration(60 * time.Second)
	cfg.Scoring.ObservationWindow = config.Duration(300 * time.Second)
	cfg.Detectors.Rate.Window = config.Duration(60 * time.Second)
	return cfg
}

// makeEntry создаёт LogEntry с заданным IP, методом, путём и статусом.
func makeEntry(ip, method, path string, status int) *parser.LogEntry {
	return &parser.LogEntry{
		RealIP: ip,
		Method: method,
		Path:   path,
		Status: status,
		Time:   time.Now(),
	}
}

// ========================== Тесты Update ==============================================

// TestTrackerUpdateNewIP проверяет что новый IP создаётся с корректными начальными счётчиками.
func TestTrackerUpdateNewIP(t *testing.T) {
	tr := NewTracker(makeConfig(1000), nil)

	st := tr.Update(makeEntry("1.2.3.4", "GET", "/index.html", 200))

	if st == nil {
		t.Fatal("Update вернул nil")
	}
	if st.IP != "1.2.3.4" {
		t.Errorf("IP: ожидал 1.2.3.4, получил %s", st.IP)
	}
	if st.TotalRequests != 1 {
		t.Errorf("TotalRequests: ожидал 1, получил %d", st.TotalRequests)
	}
	if tr.Len() != 1 {
		t.Errorf("Len: ожидал 1, получил %d", tr.Len())
	}
}

// TestTrackerUpdateSameIP проверяет накопление счётчиков при повторных запросах.
func TestTrackerUpdateSameIP(t *testing.T) {
	tr := NewTracker(makeConfig(1000), nil)
	ip := "1.2.3.4"

	tr.Update(makeEntry(ip, "GET", "/page1", 200))
	tr.Update(makeEntry(ip, "GET", "/page2", 404))
	tr.Update(makeEntry(ip, "GET", "/page3", 404))

	st := tr.Update(makeEntry(ip, "GET", "/page4", 200))

	if st.TotalRequests != 4 {
		t.Errorf("TotalRequests: ожидал 4, получил %d", st.TotalRequests)
	}
	if st.Requests404 != 2 {
		t.Errorf("Requests404: ожидал 2, получил %d", st.Requests404)
	}
	if tr.Len() != 1 {
		t.Errorf("Len: должен оставаться 1, получил %d", tr.Len())
	}
}

// TestTrackerMultipleIPs проверяет независимость состояний разных IP.
func TestTrackerMultipleIPs(t *testing.T) {
	tr := NewTracker(makeConfig(1000), nil)

	tr.Update(makeEntry("1.1.1.1", "GET", "/", 200))
	tr.Update(makeEntry("2.2.2.2", "GET", "/", 404))
	tr.Update(makeEntry("1.1.1.1", "GET", "/about", 200))

	if tr.Len() != 2 {
		t.Errorf("Len: ожидал 2, получил %d", tr.Len())
	}
	st1 := tr.Update(makeEntry("1.1.1.1", "GET", "/contact", 200))
	if st1.TotalRequests != 3 {
		t.Errorf("1.1.1.1 TotalRequests: ожидал 3, получил %d", st1.TotalRequests)
	}
	st2 := tr.Update(makeEntry("2.2.2.2", "GET", "/login", 200))
	if st2.TotalRequests != 2 {
		t.Errorf("2.2.2.2 TotalRequests: ожидал 2, получил %d", st2.TotalRequests)
	}
	if st2.Requests404 != 1 {
		t.Errorf("2.2.2.2 Requests404: ожидал 1, получил %d", st2.Requests404)
	}
}

// ========================== Тесты кольцевого буфера путей ============================

// TestRingBufferOrder проверяет хронологический порядок путей до заполнения буфера.
func TestRingBufferOrder(t *testing.T) {
	tr := NewTracker(makeConfig(1000), nil)
	ip := "1.2.3.4"

	paths := []string{"/a", "/b", "/c", "/d", "/e"}
	for _, p := range paths {
		tr.Update(makeEntry(ip, "GET", p, 200))
	}

	st := tr.Update(makeEntry(ip, "GET", "/f", 200))
	recent := st.RecentPaths()

	// Последние 6 путей должны быть в правильном порядке
	expected := append(paths, "/f")
	if len(recent) != len(expected) {
		t.Fatalf("RecentPaths длина: ожидал %d, получил %d", len(expected), len(recent))
	}
	for i, p := range expected {
		if recent[i] != p {
			t.Errorf("RecentPaths[%d]: ожидал %q, получил %q", i, p, recent[i])
		}
	}
}

// TestRingBufferWrap проверяет корректную работу кольцевого буфера после заполнения.
func TestRingBufferWrap(t *testing.T) {
	tr := NewTracker(makeConfig(1000), nil)
	ip := "1.2.3.4"

	// Заполняем буфер + ещё несколько путей сверху
	overCount := 5
	total := pathBufSize + overCount

	for i := 0; i < total; i++ {
		tr.Update(makeEntry(ip, "GET", fmt.Sprintf("/path/%d", i), 200))
	}

	st := tr.Update(makeEntry(ip, "GET", "/final", 200))
	recent := st.RecentPaths()

	// Буфер должен содержать ровно pathBufSize элементов
	if len(recent) != pathBufSize {
		t.Fatalf("RecentPaths длина после wrap: ожидал %d, получил %d", pathBufSize, len(recent))
	}

	// Последний элемент — самый свежий путь
	if recent[pathBufSize-1] != "/final" {
		t.Errorf("последний элемент: ожидал /final, получил %q", recent[pathBufSize-1])
	}

	// Вытеснены первые overCount+1 путей (0..overCount); первый актуальный — /path/(overCount+1).
	// Итого записей: pathBufSize+overCount (цикл) + 1 (/final) = pathBufSize+overCount+1.
	// pathPos = (pathBufSize+overCount+1) % pathBufSize = overCount+1.
	expectedFirst := fmt.Sprintf("/path/%d", overCount+1)
	if recent[0] != expectedFirst {
		t.Errorf("первый элемент: ожидал %q, получил %q", expectedFirst, recent[0])
	}
}

// ========================== Тесты GC eviction =========================================

// TestGCEviction проверяет что GC удаляет неактивные IP по retention.
func TestGCEviction(t *testing.T) {
	tr := NewTracker(makeConfig(1000), nil)

	// Добавляем IP с LastSeen в прошлом (старше retention)
	tr.Update(makeEntry("old.ip", "GET", "/", 200))
	old := tr.states["old.ip"]
	old.LastSeen = time.Now().Add(-400 * time.Second) // старше ObservationWindow(300s)

	// Добавляем свежий IP
	tr.Update(makeEntry("new.ip", "GET", "/", 200))

	deleted := tr.runGC()

	if deleted != 1 {
		t.Errorf("GC: ожидал удаление 1 записи, удалено %d", deleted)
	}
	if tr.Len() != 1 {
		t.Errorf("после GC Len: ожидал 1, получил %d", tr.Len())
	}
	// Убеждаемся что удалён именно old.ip
	if _, exists := tr.states["old.ip"]; exists {
		t.Error("old.ip должен быть удалён GC")
	}
	if _, exists := tr.states["new.ip"]; !exists {
		t.Error("new.ip должен остаться после GC")
	}
}

// TestGCNoEviction проверяет что GC не трогает активные IP.
func TestGCNoEviction(t *testing.T) {
	tr := NewTracker(makeConfig(1000), nil)

	tr.Update(makeEntry("1.1.1.1", "GET", "/", 200))
	tr.Update(makeEntry("2.2.2.2", "GET", "/", 200))

	deleted := tr.runGC()

	if deleted != 0 {
		t.Errorf("GC: ожидал 0 удалений, удалено %d", deleted)
	}
	if tr.Len() != 2 {
		t.Errorf("Len после GC: ожидал 2, получил %d", tr.Len())
	}
}

// TestRunGCContext проверяет что RunGC корректно завершается по контексту.
func TestRunGCContext(t *testing.T) {
	tr := NewTracker(makeConfig(1000), nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		tr.RunGC(ctx, 10*time.Millisecond)
		close(done)
	}()

	cancel()

	select {
	case <-done:
		// успех
	case <-time.After(500 * time.Millisecond):
		t.Fatal("RunGC не завершился после отмены контекста")
	}
}

// ========================== Тесты LRU eviction ========================================

// TestLRUEviction проверяет что при превышении maxIPs удаляется наименее используемый IP.
func TestLRUEviction(t *testing.T) {
	maxIPs := 3
	tr := NewTracker(makeConfig(maxIPs), nil)

	// Добавляем maxIPs+1 различных IP
	tr.Update(makeEntry("a.a.a.a", "GET", "/", 200)) // LRU-кандидат (самый старый)
	tr.Update(makeEntry("b.b.b.b", "GET", "/", 200))
	tr.Update(makeEntry("c.c.c.c", "GET", "/", 200))
	tr.Update(makeEntry("d.d.d.d", "GET", "/", 200)) // 4-й — должен вытеснить a.a.a.a

	if tr.Len() != maxIPs {
		t.Errorf("Len после eviction: ожидал %d, получил %d", maxIPs, tr.Len())
	}
	if _, exists := tr.states["a.a.a.a"]; exists {
		t.Error("a.a.a.a должен быть вытеснен как LRU")
	}
}

// TestLRURecentAccessProtection проверяет что обращение к IP защищает его от вытеснения.
func TestLRURecentAccessProtection(t *testing.T) {
	maxIPs := 2
	tr := NewTracker(makeConfig(maxIPs), nil)

	tr.Update(makeEntry("a.a.a.a", "GET", "/", 200)) // первый
	tr.Update(makeEntry("b.b.b.b", "GET", "/", 200)) // второй

	// Обращаемся к a.a.a.a — перемещаем в голову LRU
	tr.Update(makeEntry("a.a.a.a", "GET", "/page", 200))

	// Добавляем третий — должен вытеснить b.b.b.b (LRU)
	tr.Update(makeEntry("c.c.c.c", "GET", "/", 200))

	if tr.Len() != maxIPs {
		t.Errorf("Len: ожидал %d, получил %d", maxIPs, tr.Len())
	}
	if _, exists := tr.states["b.b.b.b"]; exists {
		t.Error("b.b.b.b должен быть вытеснен как LRU")
	}
	if _, exists := tr.states["a.a.a.a"]; !exists {
		t.Error("a.a.a.a должен остаться — был обновлён недавно")
	}
}

// ========================== Тесты sliding window rate =================================

// TestRateCounterGapInOneToTwoWindows проверяет корректный сдвиг окна при gap ∈ (w, 2w).
// Это граничный случай алгоритма two-counter: prevCount переносится из предыдущего окна.
// Тест документирует known limitation (возможный false positive при burst + тишина + burst).
func TestRateCounterGapInOneToTwoWindows(t *testing.T) {
	cfg := makeConfig(1000)
	tr := NewTracker(cfg, nil)
	ip := "1.2.3.4"

	w := time.Duration(cfg.Detectors.Rate.Window)

	// Первый запрос — инициализируем окно
	e1 := makeEntry(ip, "GET", "/", 200)
	e1.Time = time.Now()
	tr.mu.Lock()
	st := &IPState{IP: ip, FirstSeen: e1.Time}
	tr.states[ip] = st
	st.lruElem = tr.lru.PushFront(st)
	tr.updateRateLocked(st, e1.Time)
	tr.mu.Unlock()

	if st.rateCurrCount != 1 {
		t.Fatalf("после первого запроса currCount=%d, ожидал 1", st.rateCurrCount)
	}

	// Gap = 1.5*w — попадает в ветку elapsed ∈ (w, 2w)
	t1 := e1.Time.Add(w + w/2)
	tr.mu.Lock()
	tr.updateRateLocked(st, t1)
	tr.mu.Unlock()

	// После сдвига: prevCount=1 (старый currCount), currCount=1, rateWindowStart сдвинулся
	if st.ratePrevCount != 1 {
		t.Errorf("после gap=1.5w: prevCount=%d, ожидал 1", st.ratePrevCount)
	}
	if st.rateCurrCount != 1 {
		t.Errorf("после gap=1.5w: currCount=%d, ожидал 1", st.rateCurrCount)
	}
	if st.rateWindowStart.IsZero() {
		t.Error("rateWindowStart не должен быть zero после сдвига")
	}

	// Следующий запрос сразу после — должен попасть в default (elapsed < w)
	t2 := t1.Add(time.Second)
	tr.mu.Lock()
	tr.updateRateLocked(st, t2)
	tr.mu.Unlock()

	if st.rateCurrCount != 2 {
		t.Errorf("после запроса через 1s: currCount=%d, ожидал 2", st.rateCurrCount)
	}
}

// ========================== Тесты ScoreAccess =========================================

// TestScoreAccess проверяет реализацию detector.ScoreAccess через IPState.
func TestScoreAccess(t *testing.T) {
	tr := NewTracker(makeConfig(1000), nil)
	st := tr.Update(makeEntry("1.2.3.4", "GET", "/", 200))

	if st.GetScore() != 0 {
		t.Errorf("начальный score: ожидал 0, получил %d", st.GetScore())
	}
	if !st.GetScoreUpdatedAt().IsZero() {
		t.Error("ScoreUpdatedAt должен быть zero при инициализации")
	}

	now := time.Now()
	st.SetScore(42, now)

	if st.GetScore() != 42 {
		t.Errorf("score после SetScore: ожидал 42, получил %d", st.GetScore())
	}
	if !st.GetScoreUpdatedAt().Equal(now) {
		t.Error("ScoreUpdatedAt не обновился")
	}
}
