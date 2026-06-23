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
//     Executors call Pop(ctx) in their Run loop. Pipeline sinks call Push(ctx, bytes).
//     After Close(), both Push and Pop return ErrQueueClosed.
//
//   Phase 2.2 (Flow 083 / RESOLVED-Q3b / RESOLVED-Q9):
//     The queue payload is now opaque bytes (the serialized event). Core
//     does not type-interpret the payload — each side (formatter on the
//     sink, executor on the consumer) owns its own wire schema and JSON-
//     decodes the bytes into its product type. JSON encoding is the
//     canonical wire form here because it survives a process restart
//     cleanly via the persistent backends (bbolt, redis) and round-trips
//     through external plugin subprocesses.
// ================================================================================

package queue

import (
	"context"
	"errors"
)

// ErrQueueFull is returned by Push when the queue buffer is at capacity.
var ErrQueueFull = errors.New("queue: queue is full")

// ErrQueueClosed is returned by Push or Pop after Close has been called.
var ErrQueueClosed = errors.New("queue: queue is closed")

// Queue is a pluggable backend for opaque-payload delivery between pipeline
// sinks and executors. Implementations must be safe for concurrent use.
//
// Phase 2.2: payloads are opaque []byte (already serialized by a Formatter
// on the sink side). The queue never inspects the bytes — that is the
// formatter and executor's responsibility. This makes the queue trivially
// generic across threat-event shapes, audit-event shapes, and any future
// event family.
//
// After Close, both Push and Pop must return an error (e.g. ErrQueueClosed).
// Callers should not interact with a Queue after Close.
type Queue interface {
	Push(ctx context.Context, payload []byte) error
	Pop(ctx context.Context) ([]byte, error)
	Len() int
	Close() error
}