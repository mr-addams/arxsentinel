// ========================== pkg/executor — Named Channel Hub =============================
//   In-process singleton that connects named Sink queues to Executor source queues.
//   Pipeline sinks call RegisterSink(name, bufferSize) → get Queue for Push.
//   Executors call GetSource(name) → get Queue, call Pop(ctx).
//   On shutdown, pipeline calls Unregister(name) → calls Queue.Close() and removes it.
//
//   WHAT IS HERE:
//     NamedChannelHub — global singleton behind package-level functions
//     RegisterSink    — create a named MemoryQueue, return Queue for Push
//     RegisterSinkWithQueue — register a custom Queue (for bbolt/redis)
//     GetSource       — return Queue for Pop
//     Unregister      — close Queue and delete from map
//
//   WHAT IS NOT HERE:
//     Executor lifecycle  — handled by main.go calling GetSource + Run()
//     Pipeline lifecycle  — handled by pipeline calling RegisterSink + Write
//
//   WHY SINGLETON:
//     No DI framework, no middleware, no config wiring. Two call sites (pipeline and executor)
//     that never import each other. Singleton is the simplest correct bridge.
//
//   THREAD SAFETY:
//     RWMutex — RegisterSink/RegisterSinkWithQueue/Unregister take write lock,
//     GetSource takes read lock.

package executor

import (
	"fmt"
	"sync"

	"github.com/mr-addams/arxsentinel/pkg/executor/queue"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

// DefaultBufferSize is used when RegisterSink is called with bufferSize <= 0.
const DefaultBufferSize = 1000

var (
	hubMu      sync.RWMutex
	hubQueues  = map[string]queue.Queue{}
)

// RegisterSink creates a new MemoryQueue with the given name and buffer size.
// Returns the Queue for Push.
// Returns an error if a queue with the same name is already registered.
func RegisterSink(name string, bufferSize int) (queue.Queue, error) {
	if bufferSize <= 0 {
		bufferSize = DefaultBufferSize
	}
	hubMu.Lock()
	defer hubMu.Unlock()
	if _, exists := hubQueues[name]; exists {
		return nil, fmt.Errorf("namedhub: sink %q already registered", name)
	}
	q := queue.NewMemoryQueue(bufferSize)
	hubQueues[name] = q
	return q, nil
}

// RegisterSinkWithQueue registers a pre-configured Queue for the given name.
// Useful when the caller wants a custom backend (bbolt, redis) instead of memory.
// Returns an error if a queue with the same name is already registered.
func RegisterSinkWithQueue(name string, q queue.Queue) error {
	hubMu.Lock()
	defer hubMu.Unlock()
	if _, exists := hubQueues[name]; exists {
		return fmt.Errorf("namedhub: sink %q already registered", name)
	}
	hubQueues[name] = q
	return nil
}

// GetSource returns the Queue for a previously registered name.
// The caller uses Queue.Pop(ctx) to consume events.
// Returns an error if no queue with the given name is registered.
func GetSource(name string) (queue.Queue, error) {
	hubMu.RLock()
	defer hubMu.RUnlock()
	q, exists := hubQueues[name]
	if !exists {
		return nil, fmt.Errorf("namedhub: source %q not found", name)
	}
	return q, nil
}

// Unregister closes the Queue with the given name and removes it from the map.
// After Unregister, Push and Pop return ErrQueueClosed.
func Unregister(name string) {
	hubMu.Lock()
	defer hubMu.Unlock()
	if q, exists := hubQueues[name]; exists {
		q.Close()
		delete(hubQueues, name)
	}
}

// Ensure queue.Queue satisfies plugin.EventSource at compile time.
var _ plugin.EventSource = (queue.Queue)(nil)
