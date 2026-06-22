//go:build integration

// ========================== Module: queue/redis — integration tests ============================
//   Heavyweight integration tests for RedisQueue. Run with: go test -tags integration ./...
//
//   WHAT IS DIFFERENT FROM redis_test.go:
//     Unit tests cover the basic happy paths against localhost:6379. These tests
//     verify cross-process behaviour under load: shared state between multiple
//     queue instances (simulating multiple executor replicas), graceful rejection
//     of operations after Close, and concurrent Push/Pop without races.
//
//   ENVIRONMENT:
//     Tests read REDIS_URL (default "redis://localhost:6379/0") and skip when
//     Redis is unreachable. This matches the production deployment model where
//     each executor replica gets its own RedisQueue client pointed at the
//     shared Redis instance.
//
//   ISOLATION:
//     Each test uses a unique key (random hex suffix) to avoid cross-test pollution
//     when go test runs tests in parallel or sequentially. Cleanup deletes the key.
// ================================================================================================

package queue

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/mr-addams/arx-core/pkg/plugin"
)

// redisIntegrationURL возвращает Redis URL для интеграционных тестов:
// берёт REDIS_URL из окружения, иначе localhost:6379/0. Возвращает URL и
// флаг «доступен ли Redis» — если парсинг URL падает, тесты должны Skip,
// а не падать с cryptic error.
func redisIntegrationURL(t *testing.T) (string, bool) {
	t.Helper()
	raw := os.Getenv("REDIS_URL")
	if raw == "" {
		raw = "redis://localhost:6379/0"
	}
	// Проверяем, что URL парсится стандартным пакетом — иначе
	// fail-fast понятной ошибкой.
	if _, err := url.Parse(raw); err != nil {
		t.Skipf("REDIS_URL %q is malformed: %v", raw, err)
		return "", false
	}
	// Проверяем, что go-redis принимает URL.
	opts, err := redis.ParseURL(raw)
	if err != nil {
		t.Skipf("REDIS_URL %q cannot be parsed by go-redis: %v", raw, err)
		return "", false
	}
	// Проверяем, что Redis реально отвечает на PING.
	c := redis.NewClient(opts)
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.Ping(ctx).Err(); err != nil {
		t.Skipf("Redis at %q not reachable: %v", raw, err)
		return "", false
	}
	return raw, true
}

// uniqueIntegrationKey возвращает случайный hex-суффикс для Redis-ключа.
// 8 hex chars (4 байта энтропии) — достаточно для изоляции в CI, где
// параллельные прогонки тестов не создают коллизий.
func uniqueIntegrationKey() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand.Read в тестах не должен падать, но если — fallback
		// на timestamp даёт хоть какую-то уникальность.
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b[:])
}

// newRedisIntegrationQueue создаёт RedisQueue с уникальным ключом для
// каждого теста — это гарантирует изоляцию при параллельном запуске
// (go test -p) и при последовательных прогонах. Cleanup удаляет ключ
// и закрывает клиент.
func newRedisIntegrationQueue(t *testing.T) *RedisQueue {
	t.Helper()
	raw, ok := redisIntegrationURL(t)
	if !ok {
		t.SkipNow()
	}
	key := "arxsentinel:queue:integration:" + uniqueIntegrationKey()
	q, err := NewRedisQueue(raw, key)
	if err != nil {
		t.Fatalf("NewRedisQueue: %v", err)
	}
	t.Cleanup(func() {
		// Удаляем ключ ДО закрытия клиента — иначе Del может бросить
		// ошибку «client is closed» если Close() вызван первым.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = q.client.Del(ctx, q.key).Err()
		_ = q.Close()
	})
	return q
}

// redisIntegrationEvent возвращает ThreatEvent с уникальным IP для каждого
// индекса — последний октет содержит idx, что позволяет верифицировать
// полноту доставки без дублей.
func redisIntegrationEvent(idx int) plugin.ThreatEvent {
	return plugin.ThreatEvent{
		IP:      "10.10.0." + strconv.Itoa(idx),
		Level:   "THREAT",
		Score:   idx,
		Reason:  "stress:redis-integration",
		Modules: []string{"integration"},
	}
}

// TestRedisIntegration_PushPopSmoke проверяет базовый happy path: Push
// кладёт событие, Pop забирает его в FIFO порядке, поля сохраняются.
// Это интеграционный smoke-тест для catch-all регрессий в JSON-сериализации
// и конфигурации Redis-клиента.
func TestRedisIntegration_PushPopSmoke(t *testing.T) {
	q := newRedisIntegrationQueue(t)
	ctx := context.Background()

	want := plugin.ThreatEvent{
		IP:      "192.0.2.42",
		Level:   "WARN",
		Score:   100,
		Reason:  "smoke",
		Modules: []string{"smoke"},
	}

	if err := q.Push(ctx, want); err != nil {
		t.Fatalf("Push: %v", err)
	}
	if l := q.Len(); l != 1 {
		t.Errorf("Len after Push: got %d, want 1", l)
	}

	got, err := q.Pop(ctx)
	if err != nil {
		t.Fatalf("Pop: %v", err)
	}
	if got.IP != want.IP || got.Score != want.Score || got.Level != want.Level {
		t.Errorf("Pop got %+v, want %+v", got, want)
	}
	if l := q.Len(); l != 0 {
		t.Errorf("Len after Pop: got %d, want 0", l)
	}
}

// TestRedisIntegration_SharedStateBetweenReplicas моделирует кросс-процессный
// (или кросс-репличный) сценарий: writer кладёт события в Redis-ключ,
// reader с другим RedisQueue-инстансом (но тем же ключом) их забирает.
// Это критическая инварианта Redis-бэкенда — данные должны быть расшарены
// между инстансами очереди в пределах одного Redis.
//
// Writer закрывает свой queue после записи, reader (на отдельном клиенте)
// забирает все события — это полностью воспроизводит сценарий «реплика A
// накапливает, реплика B забирает».
func TestRedisIntegration_SharedStateBetweenReplicas(t *testing.T) {
	raw, ok := redisIntegrationURL(t)
	if !ok {
		t.SkipNow()
	}
	// Один writer + один reader на ОДНОМ ключе — минимальный кейс
	// «шаринга состояния».
	key := "arxsentinel:queue:integration:shared:" + uniqueIntegrationKey()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		opts, _ := redis.ParseURL(raw)
		c := redis.NewClient(opts)
		_ = c.Del(ctx, key).Err()
		_ = c.Close()
	})

	writer, err := NewRedisQueue(raw, key)
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	reader, err := NewRedisQueue(raw, key)
	if err != nil {
		t.Fatalf("reader: %v", err)
	}
	t.Cleanup(func() {
		_ = writer.Close()
		_ = reader.Close()
	})

	const total = 50
	ctx := context.Background()
	for i := 0; i < total; i++ {
		if err := writer.Push(ctx, redisIntegrationEvent(i+1)); err != nil {
			t.Fatalf("writer.Push %d: %v", i, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("writer.Close: %v", err)
	}

	// Writer закрыт — но reader на другом инстансе читает все 50 событий.
	seen := make(map[string]bool, total)
	for i := 0; i < total; i++ {
		event, err := reader.Pop(ctx)
		if err != nil {
			t.Fatalf("reader.Pop %d: %v", i, err)
		}
		if seen[event.IP] {
			t.Fatalf("reader.Pop %d: duplicate IP %s", i, event.IP)
		}
		seen[event.IP] = true
	}
	if len(seen) != total {
		t.Errorf("reader total unique IPs: got %d, want %d", len(seen), total)
	}
}

// TestRedisIntegration_PushAfterCloseIsRejected проверяет, что Push
// после Close возвращает ErrQueueClosed немедленно. Это контракт
// Queue interface — executor'ы полагаются на нём для graceful shutdown.
func TestRedisIntegration_PushAfterCloseIsRejected(t *testing.T) {
	q := newRedisIntegrationQueue(t)
	ctx := context.Background()

	if err := q.Push(ctx, redisIntegrationEvent(1)); err != nil {
		t.Fatalf("Push before Close: %v", err)
	}

	if err := q.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Push после Close.
	if err := q.Push(ctx, redisIntegrationEvent(2)); !errors.Is(err, ErrQueueClosed) {
		t.Errorf("Push after Close: got %v, want ErrQueueClosed", err)
	}

	// Pop после Close — тоже ErrQueueClosed, не блокируется.
	if _, err := q.Pop(ctx); !errors.Is(err, ErrQueueClosed) {
		t.Errorf("Pop after Close: got %v, want ErrQueueClosed", err)
	}
}

// TestRedisIntegration_ConcurrentAccess проверяет, что конкурентные
// Push и Pop не теряют события и не дублируют их. Несколько writer'ов
// пушат, один reader в цикле забирает всё до пустоты. Len() в конце == 0.
func TestRedisIntegration_ConcurrentAccess(t *testing.T) {
	q := newRedisIntegrationQueue(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const writers = 4
	const eventsPerWriter = 100
	const total = writers * eventsPerWriter

	var pushed atomic.Int64
	var popped atomic.Int64
	var pusherWg, popperWg sync.WaitGroup

	// Producers
	for w := 0; w < writers; w++ {
		pusherWg.Add(1)
		go func(w int) {
			defer pusherWg.Done()
			for i := 0; i < eventsPerWriter; i++ {
				idx := w*eventsPerWriter + i + 1
				if err := q.Push(ctx, redisIntegrationEvent(idx)); err != nil {
					if ctx.Err() != nil {
						return
					}
					t.Errorf("push idx=%d: %v", idx, err)
					return
				}
				pushed.Add(1)
			}
		}(w)
	}

	// Single consumer сбрасывает всё до total.
	popperWg.Add(1)
	go func() {
		defer popperWg.Done()
		for popped.Load() < int64(total) {
			popCtx, popCancel := context.WithTimeout(ctx, 500*time.Millisecond)
			if _, err := q.Pop(popCtx); err != nil {
				popCancel()
				if ctx.Err() != nil {
					return
				}
				// timeout — допустимо, если writer'ы ещё не догнали.
				continue
			}
			popCancel()
			popped.Add(1)
		}
	}()

	pusherWg.Wait()
	popperWg.Wait()
	cancel()

	if p := pushed.Load(); p != int64(total) {
		t.Errorf("pushed: got %d, want %d", p, total)
	}
	if p := popped.Load(); p != int64(total) {
		t.Errorf("popped: got %d, want %d", p, total)
	}
	if l := q.Len(); l != 0 {
		t.Errorf("Len after drain: got %d, want 0", l)
	}
}
