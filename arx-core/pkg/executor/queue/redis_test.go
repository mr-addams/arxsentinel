// ========================== Module: queue/redis_test ============================
//   Integration tests for RedisQueue. All tests skip when Redis is not available
//   on localhost:6379.
//
//   Gate B (Flow 083 / Task 3.3 / RESOLVED-D): payloads are opaque []byte;
//   tests marshal a local jsonFields fixture before Push. Core tests do not
//   import the product threat.ThreatEvent.
// ================================================================================

package queue

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func redisAvailable() bool {
	c := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	defer c.Close()
	return c.Ping(context.Background()).Err() == nil
}

func newRedisQueueForTest(t *testing.T) *RedisQueue {
	t.Helper()
	q, err := NewRedisQueue("redis://localhost:6379/0", "arxsentinel:queue:test")
	if err != nil {
		t.Fatalf("NewRedisQueue: %v", err)
	}
	t.Cleanup(func() {
		q.client.Del(context.Background(), q.key)
		q.Close()
	})
	return q
}

func TestRedisQueue_PushPop(t *testing.T) {
	if !redisAvailable() {
		t.Skip("Redis not available")
	}

	q := newRedisQueueForTest(t)
	ctx := context.Background()

	payload, err := json.Marshal(jsonFields{
		IP:    "192.0.2.1",
		Score: 10,
		Level: "WARN",
	})
	if err != nil {
		t.Fatalf("test fixture marshal: %v", err)
	}

	if err := q.Push(ctx, payload); err != nil {
		t.Fatalf("Push: %v", err)
	}

	got, err := q.Pop(ctx)
	if err != nil {
		t.Fatalf("Pop: %v", err)
	}

	var decoded jsonFields
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("Pop payload decode: %v (bytes: %q)", err, got)
	}
	if decoded.IP != "192.0.2.1" || decoded.Score != 10 || decoded.Level != "WARN" {
		t.Errorf("Pop got %+v, want IP=192.0.2.1 Score=10 Level=WARN", decoded)
	}
}

func TestRedisQueue_PopCancelled(t *testing.T) {
	if !redisAvailable() {
		t.Skip("Redis not available")
	}

	q := newRedisQueueForTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := q.Pop(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Pop expected context.Canceled, got %v", err)
	}
}

func TestRedisQueue_Len(t *testing.T) {
	if !redisAvailable() {
		t.Skip("Redis not available")
	}

	q := newRedisQueueForTest(t)
	ctx := context.Background()

	payload1, _ := json.Marshal(jsonFields{IP: "10.0.0.1", Score: 5, Level: "INFO"})
	payload2, _ := json.Marshal(jsonFields{IP: "10.0.0.2", Score: 15, Level: "THREAT"})

	if l := q.Len(); l != 0 {
		t.Errorf("Len before push: got %d, want 0", l)
	}

	if err := q.Push(ctx, payload1); err != nil {
		t.Fatalf("Push: %v", err)
	}
	if err := q.Push(ctx, payload2); err != nil {
		t.Fatalf("Push: %v", err)
	}

	if l := q.Len(); l != 2 {
		t.Errorf("Len after 2 pushes: got %d, want 2", l)
	}
}

func TestRedisQueue_Close(t *testing.T) {
	if !redisAvailable() {
		t.Skip("Redis not available")
	}

	q := newRedisQueueForTest(t)
	ctx := context.Background()

	// Close is idempotent — call twice
	if err := q.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := q.Close(); err != nil {
		t.Errorf("second Close (idempotent): %v", err)
	}

	// Push after Close returns ErrQueueClosed
	closedPayload, _ := json.Marshal(jsonFields{IP: "10.0.0.1"})
	if err := q.Push(ctx, closedPayload); !errors.Is(err, ErrQueueClosed) {
		t.Errorf("Push after Close: expected ErrQueueClosed, got %v", err)
	}

	// Pop after Close returns ErrQueueClosed
	_, err := q.Pop(ctx)
	if !errors.Is(err, ErrQueueClosed) {
		t.Errorf("Pop after Close: expected ErrQueueClosed, got %v", err)
	}

	// Timed Pop after Close should also be fast (not block 1s)
	ctxTimed, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	_, err = q.Pop(ctxTimed)
	if !errors.Is(err, ErrQueueClosed) {
		t.Errorf("Pop after Close with timeout: expected ErrQueueClosed, got %v", err)
	}
}
