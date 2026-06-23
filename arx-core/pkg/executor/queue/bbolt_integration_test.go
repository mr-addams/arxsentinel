//go:build integration

// ========================== Module: queue/bbolt — integration tests =============================
//   Heavyweight integration tests for BboltQueue. Run with: go test -tags integration ./...
//
//   WHAT IS DIFFERENT FROM bbolt_test.go:
//     Unit tests cover the basic happy paths. These tests verify real-file behaviour
//     under load, persistence across many close/reopen cycles, FIFO ordering under
//     concurrent pushers, and graceful rejection of corrupted .db files.
//
//   ISOLATION:
//     Each test uses t.TempDir() for an isolated .db file. No port allocation,
//     no Docker — only the local filesystem and bbolt itself.
//
//   Gate B (Flow 083 / Task 3.3 / RESOLVED-D): payloads are opaque []byte;
//   tests marshal a local jsonFields fixture before Push. Core tests do
//   not import the product threat.ThreatEvent (boundary invariant).
// ================================================================================================

package queue

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mr-addams/arx-core/pkg/logger"
	"go.etcd.io/bbolt"
)

// jsonFields переиспользуется из bbolt_test.go (компилируется без build-тега,
// доступен всему пакету queue). С -tags integration этот файл компилируется
// вместе с bbolt_test.go, поэтому дублировать декларацию здесь нельзя —
// компилятор падает с "redeclared in this block". Содержательно тип
// идентичен — IP/Level/Score/Reason/Modules.

// bboltIntegrationEvent returns a JSON payload mirroring what the
// product-side SentinelFormatter would emit — unique IP per idx so the
// test can verify FIFO delivery of each event exactly once.
func bboltIntegrationEvent(ip string, idx int) []byte {
	b, _ := json.Marshal(jsonFields{
		IP:      ip,
		Level:   "THREAT",
		Score:   idx,
		Reason:  "stress:" + ip,
		Modules: []string{"integration"},
	})
	return b
}

// TestBboltIntegration_PersistenceAcrossManyReopens проверяет, что данные
// переживают множественные циклы close/reopen. Unit-тест проверяет один
// цикл — здесь симулируется сценарий рестарта сервиса, при котором
// pipeline накапливает события в одну сессию, останавливается, и
// возобновляется позже, повторяя этот цикл.
func TestBboltIntegration_PersistenceAcrossManyReopens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "persist-many.db")
	ctx := context.Background()

	const cycles = 5
	const eventsPerCycle = 20

	expected := make([]string, 0, cycles*eventsPerCycle)
	for c := 0; c < cycles; c++ {
		q, err := NewBboltQueue(path, "q", logger.Nop)
		if err != nil {
			t.Fatalf("cycle %d: open: %v", c, err)
		}
		for i := 0; i < eventsPerCycle; i++ {
			ip := "10.0.0." + strconv.Itoa(c*eventsPerCycle+i+1)
			if err := q.Push(ctx, bboltIntegrationEvent(ip, c*eventsPerCycle+i)); err != nil {
				t.Fatalf("cycle %d push %d: %v", c, i, err)
			}
			expected = append(expected, ip)
		}
		if err := q.Close(); err != nil {
			t.Fatalf("cycle %d close: %v", c, err)
		}
	}

	// Финальная сессия: читаем все события и проверяем FIFO порядок.
	q, err := NewBboltQueue(path, "q", logger.Nop)
	if err != nil {
		t.Fatalf("final open: %v", err)
	}
	defer q.Close()

	for i, want := range expected {
		payload, err := q.Pop(ctx)
		if err != nil {
			t.Fatalf("pop %d: %v", i, err)
		}
		var f jsonFields
		if err := json.Unmarshal(payload, &f); err != nil {
			t.Fatalf("pop %d decode: %v", i, err)
		}
		if f.IP != want {
			t.Fatalf("pop %d: got IP %s, want %s", i, f.IP, want)
		}
	}
}

// TestBboltIntegration_FIFOUnderConcurrentPushers проверяет, что
// BboltQueue сохраняет полноту набора при конкурентных Push'ах из
// множества горутин. Background write goroutine сериализует записи,
// поэтому каждое событие доходит до reader'а ровно один раз —
// итоговое множество IP должно совпасть с ожидаемым диапазоном.
func TestBboltIntegration_FIFOUnderConcurrentPushers(t *testing.T) {
	q := newTestBbolt(t)
	defer q.Close()

	const pusherCount = 8
	const eventsPerPusher = 50
	const total = pusherCount * eventsPerPusher

	// seen[i] — true, если IP с суффиксом i был прочитан.
	seen := make([]bool, total+1) // индекс 0 не используем
	var pusherWg sync.WaitGroup
	for p := 0; p < pusherCount; p++ {
		pusherWg.Add(1)
		go func(start int) {
			defer pusherWg.Done()
			ctx := context.Background()
			for i := 0; i < eventsPerPusher; i++ {
				idx := start + i + 1
				ip := "10.1.0." + strconv.Itoa(idx)
				if err := q.Push(ctx, bboltIntegrationEvent(ip, idx)); err != nil {
					t.Errorf("push idx=%d: %v", idx, err)
					return
				}
			}
		}(p * eventsPerPusher)
	}
	pusherWg.Wait()

	if got := q.Len(); got != total {
		t.Fatalf("Len after concurrent push: got %d, want %d", got, total)
	}

	ctx := context.Background()
	for i := 0; i < total; i++ {
		payload, err := q.Pop(ctx)
		if err != nil {
			t.Fatalf("pop %d: %v", i, err)
		}
		var f jsonFields
		if err := json.Unmarshal(payload, &f); err != nil {
			t.Fatalf("pop %d decode: %v", i, err)
		}
		// IP формата "10.1.0.<N>" — извлекаем N как int.
		idx := extractIPOctet(f.IP)
		if idx < 1 || idx > total {
			t.Fatalf("pop %d: out-of-range idx %d from IP %s", i, idx, f.IP)
		}
		if seen[idx] {
			t.Fatalf("pop %d: duplicate IP %s (idx %d)", i, f.IP, idx)
		}
		seen[idx] = true
	}
	for i := 1; i <= total; i++ {
		if !seen[i] {
			t.Fatalf("missing idx %d after %d pops", i, total)
		}
	}
}

// TestBboltIntegration_LenAccuracyUnderMixedReadWrite проверяет, что
// Len() остаётся точным при одновременных Push и Pop. Это критично
// для executor'ов, которые полагаются на Len для backpressure /
// метрик. Используем атомарный счётчик, чтобы валидировать
// инвариант: pushes == totalWrites, pops == totalWrites, final len == 0.
func TestBboltIntegration_LenAccuracyUnderMixedReadWrite(t *testing.T) {
	q := newTestBbolt(t)
	defer q.Close()

	const writers = 4
	const readers = 4
	const eventsPerWriter = 100
	const totalWrites = writers * eventsPerWriter

	var pushed atomic.Int64
	var popped atomic.Int64
	var producerWg, consumerWg sync.WaitGroup

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Producers
	for w := 0; w < writers; w++ {
		producerWg.Add(1)
		go func(w int) {
			defer producerWg.Done()
			for i := 0; i < eventsPerWriter; i++ {
				ip := "10.2.0." + strconv.Itoa(w*eventsPerWriter+i+1)
				if err := q.Push(ctx, bboltIntegrationEvent(ip, w*eventsPerWriter+i)); err != nil {
					if ctx.Err() != nil {
						return
					}
					t.Errorf("push: %v", err)
					return
				}
				pushed.Add(1)
			}
		}(w)
	}

	// Consumers: каждый крутится, пока не вычерпает totalWrites событий.
	for r := 0; r < readers; r++ {
		consumerWg.Add(1)
		go func() {
			defer consumerWg.Done()
			for popped.Load() < int64(totalWrites) {
				popCtx, popCancel := context.WithTimeout(ctx, 100*time.Millisecond)
				if _, err := q.Pop(popCtx); err != nil {
					popCancel()
					if ctx.Err() != nil {
						return
					}
					// timeout ожидаем, пока producers не догнали.
					continue
				}
				popCancel()
				popped.Add(1)
			}
		}()
	}

	producerWg.Wait()
	consumerWg.Wait()
	cancel() // страховка: гасим всех

	if p := pushed.Load(); p != int64(totalWrites) {
		t.Errorf("pushed counter: got %d, want %d", p, totalWrites)
	}
	if p := popped.Load(); p != int64(totalWrites) {
		t.Errorf("popped counter: got %d, want %d", p, totalWrites)
	}
	if l := q.Len(); l != 0 {
		t.Errorf("Len after drain: got %d, want 0", l)
	}
}

// TestBboltIntegration_PopBlocksOnEmptyQueue проверяет, что Pop
// действительно блокируется на пустой очереди и не возвращает
// «no error, empty event» — критично для executor'ов, которые
// крутятся в Run() и не должны ловить spurious wakeups.
func TestBboltIntegration_PopBlocksOnEmptyQueue(t *testing.T) {
	q := newTestBbolt(t)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := q.Pop(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Pop on empty queue with timed context: expected error, got nil")
	}
	if elapsed < 100*time.Millisecond {
		t.Fatalf("Pop returned too early (%v) — should block until ctx deadline", elapsed)
	}
}

// TestBboltIntegration_PushAfterCloseIsRejected проверяет, что Push
// после Close возвращает ErrQueueClosed немедленно, не пытаясь
// записать в закрытую БД.
func TestBboltIntegration_PushAfterCloseIsRejected(t *testing.T) {
	q := newTestBbolt(t)

	if err := q.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if err := q.Push(context.Background(), bboltIntegrationEvent("10.3.0.1", 1)); err != ErrQueueClosed {
		t.Errorf("Push after Close: got %v, want ErrQueueClosed", err)
	}
}

// TestBboltIntegration_CorruptedBucketDetected проверяет, что Len
// и writePush корректно отрабатывают на «битой» БД (бакет есть, но
// счётчик \x00seq повреждён). Len должен вернуть 0 (graceful),
// writePush — ErrQueueCorrupted.
func TestBboltIntegration_CorruptedBucketDetected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corrupt.db")
	ctx := context.Background()

	// Создаём нормальную очередь и пушим одно событие — это создаёт
	// корректные счётчики seq/read в бакете.
	q, err := NewBboltQueue(path, "q", logger.Nop)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := q.Push(ctx, bboltIntegrationEvent("10.4.0.1", 1)); err != nil {
		t.Fatalf("push: %v", err)
	}
	if err := q.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Вручную портим счётчик \x00seq: заменяем на 2 байта вместо 8 —
	// это валидный bucket key, но bboltQueue ожидает 8 байт big-endian uint64.
	corruptBboltCounter(t, path, "q", "\x00seq", []byte{0xFF, 0xFF})

	// Reopen — open проходит (bbolt не валидирует формат значений),
	// но Push и Len должны устоять: Len возвращает 0, Push возвращает ErrQueueCorrupted.
	q2, err := NewBboltQueue(path, "q", logger.Nop)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer q2.Close()

	if l := q2.Len(); l != 0 {
		t.Errorf("Len on corrupted seq: got %d, want 0", l)
	}

	if err := q2.Push(ctx, bboltIntegrationEvent("10.4.0.2", 2)); err == nil {
		t.Error("Push on corrupted seq: expected error, got nil")
	}
}

// extractIPOctet возвращает последний октет IP-адреса как int. Используется
// для проверки, что все индексы 1..N были записаны и прочитаны.
func extractIPOctet(ip string) int {
	dot := strings.LastIndex(ip, ".")
	if dot < 0 || dot+1 >= len(ip) {
		return 0
	}
	n, _ := strconv.Atoi(ip[dot+1:])
	return n
}

// corruptBboltCounter открывает .db напрямую и заменяет значение счётчика
// на повреждённые данные (другая длина / мусор). Тест проверяет, что Len и
// writePush устойчивы к corruption, а не паникуют.
func corruptBboltCounter(t *testing.T, path, bucket, key string, badValue []byte) {
	t.Helper()
	db, err := bbolt.Open(path, 0600, nil)
	if err != nil {
		t.Fatalf("direct open: %v", err)
	}
	defer db.Close()
	if err := db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return bbolt.ErrBucketNotFound
		}
		return b.Put([]byte(key), badValue)
	}); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
}