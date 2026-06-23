// ========================== Tests: pkg/source/sentinel ===================================
//   Unit tests for SentinelSource — покрывают: чтение ThreatEvent из NCS-очереди,
//   конверсию ThreatEvent → LogEntry, обработку ctx-cancel и закрытия очереди,
//   drop-policy при полном downstream-канале, обработку ThreatEvent без IP.
//
//   Тесты не зависят от глобального NCS singleton — канал инжектится через NewWithQueue
//   и реальный queue.MemoryQueue, создаваемый в test setup.

package sentinel_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mr-addams/arx-core/pkg/executor/queue"
	"github.com/mr-addams/arx-core/pkg/parser"
	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/mr-addams/arx-core/pkg/source/sentinel"
)

// validThreat — стандартный ThreatEvent с заполненным IP и Reason.
var validThreat = plugin.ThreatEvent{
	Timestamp: time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC),
	Level:     "THREAT",
	Stream:    "main",
	Source:    "sentinel:other-pipeline",
	IP:        "203.0.113.42",
	Score:     85,
	Modules:   []string{"probe", "rate"},
	Reason:    "probe:env:3,rate:142rps",
}

// nopLog — no-op logger для тестов, не проверяющих log output.
func nopLog(_, _, _ string) {}

// runAndCollect запускает src.Run в горутине и собирает ровно wantCount entries из out
// с таймаутом 2s. Возвращает собранные entries и финальную ошибку Run.
//
// Используется в большинстве тестов — единая обёртка для читаемости.
func runAndCollect(t *testing.T, src plugin.Source, wantCount int) ([]*parser.LogEntry, error) {
	t.Helper()
	out := make(chan *plugin.Event, wantCount+2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- src.Run(ctx, out) }()

	got := make([]*parser.LogEntry, 0, wantCount)
	for i := 0; i < wantCount; i++ {
		select {
		case ev := <-out:
			got = append(got, parser.UnwrapLogEntry(ev))
		case <-time.After(2 * time.Second):
			cancel()
			t.Fatalf("timeout waiting for entry %d", i)
		}
	}
	// cancel() must be called explicitly before blocking on errCh —
	// Run() loops on Pop(ctx) and will never return unless ctx is cancelled.
	// defer cancel() would only run after this function returns, causing a deadlock.
	cancel()
	select {
	case err := <-errCh:
		return got, err
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit within 2s after cancel")
		return got, nil
	}
}

// ----------------------------------------------------------------------------------------
// Test 1: ThreatEvent из очереди конвертируется в LogEntry с правильными полями.
// ----------------------------------------------------------------------------------------
func TestSentinelSource_ReadsThreats(t *testing.T) {
	q := queue.NewMemoryQueue(8)
	if err := q.Push(context.Background(), validThreat); err != nil {
		t.Fatalf("Push: %v", err)
	}

	src := sentinel.NewWithQueue("test-stream", q, nopLog)
	got, err := runAndCollect(t, src, 1)
	if err != nil {
		t.Fatalf("Run returned %v, want nil", err)
	}

	if len(got) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(got))
	}
	e := got[0]
	if e.RealIP != "203.0.113.42" {
		t.Errorf("RealIP = %q, want %q", e.RealIP, "203.0.113.42")
	}
	if e.RemoteAddr != "203.0.113.42" {
		t.Errorf("RemoteAddr = %q, want %q", e.RemoteAddr, "203.0.113.42")
	}
	if e.ChainIssue != "sentinel:event" {
		t.Errorf("ChainIssue = %q, want %q", e.ChainIssue, "sentinel:event")
	}
	if e.UserAgent != "probe:env:3,rate:142rps" {
		t.Errorf("UserAgent = %q, want %q", e.UserAgent, "probe:env:3,rate:142rps")
	}
	if e.Time.IsZero() {
		t.Error("Time is zero, want non-zero")
	}

	if stats := src.Stats(); stats.LinesRead != 1 {
		t.Errorf("LinesRead = %d, want 1", stats.LinesRead)
	}
}

// ----------------------------------------------------------------------------------------
// Test 2: ctx cancellation завершает Run с nil и не приводит к panic.
// ----------------------------------------------------------------------------------------
func TestSentinelSource_StopOnCtxCancel(t *testing.T) {
	q := queue.NewMemoryQueue(8)
	src := sentinel.NewWithQueue("test-stream", q, nopLog)
	out := make(chan *plugin.Event, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- src.Run(ctx, out) }()

	// Run крутит Pop-цикл, который блокируется в ожидании события или ctx.Done.
	// Через 50ms отменяем — Run должен вернуться nil.
	time.AfterFunc(50*time.Millisecond, cancel)

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run returned %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s after ctx cancel")
	}
}

// ----------------------------------------------------------------------------------------
// Test 3: ThreatEvent с пустым IP считается parse-error и не доставляется в out.
// ----------------------------------------------------------------------------------------
func TestSentinelSource_ParseErrorOnEmptyIP(t *testing.T) {
	q := queue.NewMemoryQueue(8)
	emptyIP := validThreat
	emptyIP.IP = "" // pipeline не сможет сматчить — отбрасываем
	if err := q.Push(context.Background(), emptyIP); err != nil {
		t.Fatalf("Push: %v", err)
	}

	src := sentinel.NewWithQueue("test-stream", q, nopLog)
	out := make(chan *plugin.Event, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- src.Run(ctx, out) }()

	// Ждём немного — Run должен инкрементировать parseErrors и продолжить цикл.
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run returned %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s after cancel")
	}

	// out должен остаться пустым — пустой IP → parse error → нет LogEntry.
	select {
	case e := <-out:
		t.Fatalf("out received entry with empty IP: %+v", e)
	default:
	}

	stats := src.Stats()
	if stats.ParseErrors != 1 {
		t.Errorf("ParseErrors = %d, want 1", stats.ParseErrors)
	}
	if stats.LinesRead != 1 {
		t.Errorf("LinesRead = %d, want 1 (Push succeeded, Run read it)", stats.LinesRead)
	}
}

// ----------------------------------------------------------------------------------------
// Test 4: закрытие очереди (ErrQueueClosed) приводит к штатному завершению Run.
// ----------------------------------------------------------------------------------------
func TestSentinelSource_QueueClosed(t *testing.T) {
	q := queue.NewMemoryQueue(8)
	src := sentinel.NewWithQueue("test-stream", q, nopLog)
	out := make(chan *plugin.Event, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- src.Run(ctx, out) }()

	// Закрываем очередь через 50ms — Run должен получить ErrQueueClosed и выйти.
	time.AfterFunc(50*time.Millisecond, func() { _ = q.Close() })

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run returned %v, want nil on queue close", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s after queue close")
	}
}

// ----------------------------------------------------------------------------------------
// Test 5: при полном downstream-канале entries отбрасываются и инкрементируется Dropped.
// ----------------------------------------------------------------------------------------
func TestSentinelSource_DropCounter(t *testing.T) {
	q := queue.NewMemoryQueue(8)
	// Кладём 3 события — Run попытается отправить каждое в unbuffered `out`.
	for i := 0; i < 3; i++ {
		if err := q.Push(context.Background(), validThreat); err != nil {
			t.Fatalf("Push %d: %v", i, err)
		}
	}

	src := sentinel.NewWithQueue("test-stream", q, nopLog)
	out := make(chan *plugin.Event, 0) // unbuffered — каждое сообщение отбрасывается
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Run заблокируется на Pop-цикле — отменяем через 100ms.
	// К моменту отмены все 3 Push уже прошли, но unbuffered send падает в default → Dropped++.
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	if err := src.Run(ctx, out); err != nil {
		t.Fatalf("Run returned %v, want nil", err)
	}

	stats := src.Stats()
	if stats.LinesRead != 3 {
		t.Errorf("LinesRead = %d, want 3", stats.LinesRead)
	}
	if stats.Dropped < 2 {
		t.Errorf("Dropped = %d, want >= 2", stats.Dropped)
	}
	if stats.ParseErrors != 0 {
		t.Errorf("ParseErrors = %d, want 0", stats.ParseErrors)
	}
}

// ----------------------------------------------------------------------------------------
// Test 6: logFn вызывается с тегом "SENTINEL" при parse-error (пустой IP).
// ----------------------------------------------------------------------------------------
func TestSentinelSource_LogFnCalledOnParseError(t *testing.T) {
	q := queue.NewMemoryQueue(8)
	emptyIP := validThreat
	emptyIP.IP = ""
	_ = q.Push(context.Background(), emptyIP)

	var calls atomic.Int32
	var loggedTag atomic.Value
	logFn := func(tag, _, _ string) {
		calls.Add(1)
		loggedTag.Store(tag)
	}

	src := sentinel.NewWithQueue("test-stream", q, logFn)
	out := make(chan *plugin.Event, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- src.Run(ctx, out) }()

	time.Sleep(100 * time.Millisecond)
	cancel()

	if err := <-errCh; err != nil {
		t.Fatalf("Run returned %v, want nil", err)
	}

	if calls.Load() == 0 {
		t.Fatal("logFn was not called")
	}
	if got := loggedTag.Load(); got != "SENTINEL" {
		t.Errorf("logged tag = %q, want %q", got, "SENTINEL")
	}
}

// ----------------------------------------------------------------------------------------
// Test 7: New() с пустым или невалидным адресом возвращает ошибку (fail-fast на старте).
// ----------------------------------------------------------------------------------------
func TestSentinelSource_NewRejectsBadAddr(t *testing.T) {
	cases := []struct {
		name string
		addr string
	}{
		{"empty", ""},
		{"wrong scheme", "http://foo"},
		{"scheme without name", "ncs://"},
		{"only scheme", "ncs:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := sentinel.New(tc.addr, nopLog)
			if err == nil {
				t.Fatalf("New(%q) = nil, want error", tc.addr)
			}
		})
	}
}

// ----------------------------------------------------------------------------------------
// Test 8: Name() возвращает ожидаемый формат "sentinel:<queue-name>".
// ----------------------------------------------------------------------------------------
func TestSentinelSource_Name(t *testing.T) {
	q := queue.NewMemoryQueue(8)
	src := sentinel.NewWithQueue("my-stream", q, nopLog)
	if got := src.Name(); got != "sentinel:my-stream" {
		t.Errorf("Name() = %q, want %q", got, "sentinel:my-stream")
	}
}

// ----------------------------------------------------------------------------------------
// Test 9: Close() — no-op; повторный вызов не паникует.
// ----------------------------------------------------------------------------------------
func TestSentinelSource_CloseIsIdempotent(t *testing.T) {
	q := queue.NewMemoryQueue(8)
	src := sentinel.NewWithQueue("test-stream", q, nopLog)

	if err := src.Close(); err != nil {
		t.Errorf("first Close() = %v, want nil", err)
	}
	if err := src.Close(); err != nil {
		t.Errorf("second Close() = %v, want nil", err)
	}
}

// guard — гарантирует, что errors.Is импортирован (нужен в одном из тестов при
// потенциальной будущей проверке контекстной ошибки). Не выполняется, только
// защищает от неиспользуемого-импорта при рефакторинге.
var _ = errors.Is
