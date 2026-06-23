// ========================== Module: queue/memory ================================
//   In-memory bounded queue backed by a buffered channel.
//
//   WHAT IS HERE:
//     NewMemoryQueue — constructor, bufferSize ≤ 0 defaults to 1000
//     MemoryQueue    — implements Queue via channel + closed sentinel channel
//
//   WHAT IS NOT HERE:
//     Persistence (bbolt.go), external queue (redis.go)
//
//   CONCURRENCY:
//     Push and Pop are safe for concurrent use.
//     Close is idempotent (sync.Once). q.ch is never closed — only q.closed
//     signals shutdown. This avoids "send on closed channel" panics.
//
//   Phase 2.2: payload is opaque []byte. See queue.go for rationale.
// ================================================================================

package queue

import (
	"context"
	"sync"
)

// MemoryQueue implements Queue using a bounded buffered channel. Safe for concurrent use.
type MemoryQueue struct {
	ch        chan []byte
	closeOnce sync.Once
	closed    chan struct{}
}

// NewMemoryQueue returns a MemoryQueue with the given buffer size. If bufferSize ≤ 0, defaults to 1000.
func NewMemoryQueue(bufferSize int) *MemoryQueue {
	if bufferSize <= 0 {
		bufferSize = 1000
	}
	return &MemoryQueue{
		ch:     make(chan []byte, bufferSize),
		closed: make(chan struct{}),
	}
}

func (q *MemoryQueue) Push(ctx context.Context, payload []byte) error {
	select {
	case <-q.closed:
		return ErrQueueClosed
	case q.ch <- payload:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		return ErrQueueFull
	}
}

func (q *MemoryQueue) Pop(ctx context.Context) ([]byte, error) {
	select {
	case <-q.closed:
		// Drain any events buffered before Close() was called. Push is no longer
		// possible after q.closed fires, so q.ch is stable — no race here.
		select {
		case payload := <-q.ch:
			return payload, nil
		default:
			return nil, ErrQueueClosed
		}
	case payload := <-q.ch:
		return payload, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (q *MemoryQueue) Len() int {
	return len(q.ch)
}

func (q *MemoryQueue) Close() error {
	// q.ch is intentionally never closed — closing it would cause panic in Push if a sender
	// is mid-select. q.closed serves as the sole shutdown signal for both Push and Pop.
	q.closeOnce.Do(func() {
		close(q.closed)
	})
	return nil
}