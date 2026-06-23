// ========================== Tests: pkg/source/sentinel ===================================
//   Unit tests for SentinelSource — NCS queue reader that wraps each JSON
//   payload as an opaque *plugin.Event and forwards it to the pipeline.
//
//   Gate B (Flow 083 / Task 3.3 / RESOLVED-D): the source no longer
//   type-asserts the payload to the product-owned ThreatEvent (which
//   migrated out of arx-core). It validates that the queue payload is
//   valid JSON and
//   wraps it as json.RawMessage in Event.Payload. Tests assert on
//   Envelope fields and on payload byte-preservation — the product
//   consumer (cmd/arxsentinel/queue_event_source) is responsible for
//   JSON-decoding the payload into threat.ThreatEvent.
//
//   Тесты не зависят от глобального NCS singleton — канал инжектится через NewWithQueue
//   и реальный queue.MemoryQueue, создаваемый в test setup.

package sentinel_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mr-addams/arx-core/pkg/executor/queue"
	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/mr-addams/arx-core/pkg/source/sentinel"
)

// validThreatJSON is a wire-format fixture — bytes matching the
// FormatSentinelThreat output. Tests push these bytes into the queue
// and assert that the source forwards them verbatim in the
// Event.Payload (json.RawMessage round-trip preserves the original
// bytes).
var validThreatJSON = []byte(`{"ts":"2026-06-05T12:00:00Z","ip":"203.0.113.42","score":85,"level":"THREAT","modules":["probe","rate"],"reason":"probe:env:3,rate:142rps","source":"sentinel:other-pipeline"}`)

// nopLog — no-op logger для тестов, не проверяющих log output.
func nopLog(_, _, _ string) {}

// runAndCollect запускает src.Run в горутине и собирает ровно wantCount entries из out
// с таймаутом 2s. Возвращает собранные entries и финальную ошибку Run.
//
// Используется в большинстве тестов — единая обёртка для читаемости.
func runAndCollect(t *testing.T, src plugin.Source, wantCount int) ([]*plugin.Event, error) {
	t.Helper()
	out := make(chan *plugin.Event, wantCount+2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- src.Run(ctx, out) }()

	got := make([]*plugin.Event, 0, wantCount)
	for i := 0; i < wantCount; i++ {
		select {
		case ev := <-out:
			got = append(got, ev)
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
// Test 1: ThreatEvent bytes из очереди конвертируются в *plugin.Event с envelope-метаданными.
// Payload остаётся json.RawMessage (opaque to core, decoded by product consumer).
// ----------------------------------------------------------------------------------------
func TestSentinelSource_ReadsThreats(t *testing.T) {
	q := queue.NewMemoryQueue(8)
	if err := q.Push(context.Background(), validThreatJSON); err != nil {
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

	// Envelope metadata is filled by the source.
	if e.Source != "sentinel:test-stream" {
		t.Errorf("Envelope.Source = %q, want %q", e.Source, "sentinel:test-stream")
	}
	if e.SourceType != "sentinel" {
		t.Errorf("Envelope.SourceType = %q, want %q", e.SourceType, "sentinel")
	}
	if e.Level != "" {
		t.Errorf("Envelope.Level = %q, want empty (downstream scoring fills later)", e.Level)
	}

	// Payload is json.RawMessage containing the original bytes verbatim.
	raw, ok := e.Payload.(json.RawMessage)
	if !ok {
		t.Fatalf("Payload type = %T, want json.RawMessage", e.Payload)
	}
	if !bytes.Equal(raw, validThreatJSON) {
		t.Errorf("Payload bytes mismatch:\n got: %s\nwant: %s", raw, validThreatJSON)
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
// Test 3: невалидный JSON считается parse-error и не доставляется в out.
// ----------------------------------------------------------------------------------------
func TestSentinelSource_ParseErrorOnInvalidJSON(t *testing.T) {
	q := queue.NewMemoryQueue(8)
	if err := q.Push(context.Background(), []byte("not-valid-json{")); err != nil {
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
		t.Fatal("Run did not return within 2s after ctx cancel")
	}

	// out должен остаться пустым — invalid JSON → parse error → нет Event.
	select {
	case e := <-out:
		t.Fatalf("out received entry with invalid JSON: %+v", e)
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
		if err := q.Push(context.Background(), validThreatJSON); err != nil {
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
// Test 6: logFn вызывается с тегом "SENTINEL" при parse-error (invalid JSON).
// ----------------------------------------------------------------------------------------
func TestSentinelSource_LogFnCalledOnParseError(t *testing.T) {
	q := queue.NewMemoryQueue(8)
	_ = q.Push(context.Background(), []byte("not-valid-json{"))

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
