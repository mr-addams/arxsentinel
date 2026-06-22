// ========================== Module: queue/redis =================================
//   Redis-backed queue for k8s, cloud, and multi-replica deployments.
//   Events survive process restarts and are shared across replicas.
//
//   WHAT IS HERE:
//     RedisQueue — implements Queue via Redis list (LPUSH/BRPOP)
//     NewRedisQueue — create client from URL, validate connection
//
//   KEY SCHEMA: arxsentinel:queue:<executor_name> (passed by caller via EffectiveKey)
//   SERIALIZATION: JSON marshal/unmarshal of plugin.ThreatEvent
//
//   CONCURRENCY:
//     Push and Pop are safe for concurrent use (redis client is goroutine-safe).
//     Close is idempotent via sync.Once. q.done signals shutdown to Pop loop.
// ================================================================================

package queue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/mr-addams/arx-core/pkg/plugin"
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

// Push serializes the event as JSON and pushes it onto the Redis list via LPUSH.
// Returns ErrQueueClosed if Close has been called.
func (q *RedisQueue) Push(ctx context.Context, event plugin.ThreatEvent) error {
	select {
	case <-q.done:
		return ErrQueueClosed
	default:
	}
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("queue: marshal threat event: %w", err)
	}
	return q.client.LPush(ctx, q.key, data).Err()
}

// Pop blocks until an event is available, the context is cancelled, or Close is called.
// Internally it calls BRPOP with a 1-second timeout in a loop so that shutdown
// and context cancellation are promptly detected.
func (q *RedisQueue) Pop(ctx context.Context) (plugin.ThreatEvent, error) {
	for {
		select {
		case <-q.done:
			return plugin.ThreatEvent{}, ErrQueueClosed
		case <-ctx.Done():
			return plugin.ThreatEvent{}, ctx.Err()
		default:
		}

		result, err := q.client.BRPop(ctx, time.Second, q.key).Result()
		if errors.Is(err, redis.Nil) {
			continue
		}
		if err != nil {
			select {
			case <-q.done:
				return plugin.ThreatEvent{}, ErrQueueClosed
			case <-ctx.Done():
				return plugin.ThreatEvent{}, ctx.Err()
			default:
			}
			return plugin.ThreatEvent{}, fmt.Errorf("queue: brpop: %w", err)
		}

		var event plugin.ThreatEvent
		if err := json.Unmarshal([]byte(result[1]), &event); err != nil {
			return plugin.ThreatEvent{}, fmt.Errorf("queue: unmarshal threat event: %w", err)
		}
		return event, nil
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
