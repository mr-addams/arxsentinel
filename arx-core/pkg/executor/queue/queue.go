// ========================== Module: queue =======================================
//   Pluggable event queue interface between pipeline sinks and executors.
//
//   WHAT IS HERE:
//     Queue interface — Push/Pop/Len/Close
//     ErrQueueFull, ErrQueueClosed sentinel errors
//
//   WHAT IS NOT HERE:
//     Implementations (memory.go, bbolt.go, redis.go)
//
//   USAGE:
//     Executors call Pop(ctx) in their Run loop. Pipeline sinks call Push(ctx, event).
//     After Close(), both Push and Pop return ErrQueueClosed.
// ================================================================================

package queue

import (
	"context"
	"errors"

	"github.com/mr-addams/arx-core/pkg/plugin"
)

// ErrQueueFull is returned by Push when the queue buffer is at capacity.
var ErrQueueFull = errors.New("queue: queue is full")

// ErrQueueClosed is returned by Push or Pop after Close has been called.
var ErrQueueClosed = errors.New("queue: queue is closed")

// Queue is a pluggable backend for event delivery between pipeline sinks
// and executors. Implementations must be safe for concurrent use.
//
// After Close, both Push and Pop must return an error (e.g. ErrQueueClosed).
// Callers should not interact with a Queue after Close.
type Queue interface {
	Push(ctx context.Context, event plugin.ThreatEvent) error
	Pop(ctx context.Context) (plugin.ThreatEvent, error)
	Len() int
	Close() error
}
