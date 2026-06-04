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
	hubMu     sync.RWMutex
	hubQueues = map[string]queue.Queue{}
	// hubRefs counts how many sinks share each named queue.
	// Unregister only closes the queue when the last sink deregisters.
	hubRefs = map[string]int{}
)

// RegisterSink returns the MemoryQueue for the given name, creating it if needed.
// Fan-in: multiple streams may register the same name and all push to one queue.
// The queue is only closed when the last caller calls Unregister.
func RegisterSink(name string, bufferSize int) (queue.Queue, error) {
	if bufferSize <= 0 {
		bufferSize = DefaultBufferSize
	}
	hubMu.Lock()
	defer hubMu.Unlock()
	if q, exists := hubQueues[name]; exists {
		hubRefs[name]++
		return q, nil
	}
	q := queue.NewMemoryQueue(bufferSize)
	hubQueues[name] = q
	hubRefs[name] = 1
	return q, nil
}

// RegisterSinkWithQueue registers a pre-configured Queue for the given name.
// If the name is already registered, the existing queue is reused (fan-in);
// the provided q is ignored and the ref count is incremented.
func RegisterSinkWithQueue(name string, q queue.Queue) error {
	hubMu.Lock()
	defer hubMu.Unlock()
	if _, exists := hubQueues[name]; exists {
		hubRefs[name]++
		return nil
	}
	hubQueues[name] = q
	hubRefs[name] = 1
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

// Unregister decrements the ref count for the named queue.
// The queue is closed and removed only when the last registered sink unregisters.
func Unregister(name string) {
	hubMu.Lock()
	defer hubMu.Unlock()
	if hubRefs[name] > 1 {
		hubRefs[name]--
		return
	}
	if q, exists := hubQueues[name]; exists {
		q.Close()
		delete(hubQueues, name)
		delete(hubRefs, name)
	}
}

// Ensure queue.Queue satisfies plugin.EventSource at compile time.
var _ plugin.EventSource = (queue.Queue)(nil)
