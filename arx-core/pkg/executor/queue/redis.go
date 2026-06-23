// ========================== Module: queue/redis =================================
//   Redis-backed queue for k8s, cloud, and multi-replica deployments.
//   Events survive process restarts and are shared across replicas.
//
//   WHAT IS HERE:
//     RedisQueue — implements Queue via Redis list (LPUSH/BRPOP)
//     NewRedisQueue — create client from URL, validate connection
//
//   KEY SCHEMA: arxsentinel:queue:<executor_name> (passed by caller via EffectiveKey)
//   SERIALIZATION: opaque []byte — caller (Formatter on the sink side, executor
//     on the consumer side) owns the wire schema.
//
//   CONCURRENCY:
//     Push and Pop are safe for concurrent use (redis client is goroutine-safe).
//     Close is idempotent via sync.Once. q.done signals shutdown to Pop loop.
//
//   Phase 2.2: payload is opaque []byte. See queue.go for rationale.
// ================================================================================

package queue

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisQueue implements Queue backed by a Redis list (LPUSH / BRPOP).
// Events survive process restarts and are shared across replicas.
type RedisQueue struct {
	client *redis.Client
	key    string
	done   chan struct{}
	once   sync.Once
}

// NewRedisQueue creates a RedisQueue from a Redis URL and list key.
// The URL is parsed via redis.ParseURL; an error is returned if parsing fails.
func NewRedisQueue(url string, key string) (*RedisQueue, error) {
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("queue: parse redis url: %w", err)
	}
	client := redis.NewClient(opts)
	return &RedisQueue{
		client: client,
		key:    key,
		done:   make(chan struct{}),
	}, nil
}

// Push stores the payload bytes onto the Redis list via LPUSH.
func (q *RedisQueue) Push(ctx context.Context, payload []byte) error {
	select {
	case <-q.done:
		return ErrQueueClosed
	default:
	}
	return q.client.LPush(ctx, q.key, payload).Err()
}

// Pop blocks until a payload is available, the context is cancelled, or Close is called.
func (q *RedisQueue) Pop(ctx context.Context) ([]byte, error) {
	for {
		select {
		case <-q.done:
			return nil, ErrQueueClosed
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		result, err := q.client.BRPop(ctx, time.Second, q.key).Result()
		if errors.Is(err, redis.Nil) {
			continue
		}
		if err != nil {
			select {
			case <-q.done:
				return nil, ErrQueueClosed
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}
			return nil, fmt.Errorf("queue: brpop: %w", err)
		}

		return []byte(result[1]), nil
	}
}

// Len returns the number of events in the Redis list via LLEN.
func (q *RedisQueue) Len() int {
	n, err := q.client.LLen(context.Background(), q.key).Result()
	if err != nil {
		return 0
	}
	return int(n)
}

// Close signals shutdown to Pop and closes the underlying Redis connection.
// Idempotent via sync.Once.
func (q *RedisQueue) Close() error {
	q.once.Do(func() {
		close(q.done)
		q.client.Close()
	})
	return nil
}