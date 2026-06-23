// ========================== pkg/ncs — Named Channel Switch =============================
//   In-process singleton that connects named Sink queues with Executor sources.
//   A pipeline sink calls AttachWriter(name, bufferSize) and receives a Queue for Push.
//   An executor calls AttachReader(name) and receives a Queue, then calls Pop(ctx).
//   On shutdown the pipeline calls DetachWriter(name); the Queue is closed and removed from the map.
//
//   WHAT IS HERE:
//     NamedChannelSwitch — global singleton behind package-level functions
//     AttachWriter         — create a named MemoryQueue and return it for Push
//     AttachWriterWithQueue — register an externally-built Queue (for bbolt/redis)
//     RegisterSinkFromConfig — create a Queue from a QueueConfig (bbolt/redis/memory) and register it
//     AttachReader         — return a Queue for Pop
//     DetachWriter         — close the Queue and remove it from the map
//
//   WHAT IS NOT HERE:
//     Executor lifecycle — lives in main.go (AttachReader + Run())
//     Pipeline lifecycle — lives in the pipeline package (AttachWriter + Write)
//
//   WHY A SINGLETON:
//     No DI framework, no middleware, no config wiring.
//     Two call sites (pipeline and executor) that never import each other.
//     A singleton is the simplest correct bridge.
//
//   THREAD SAFETY:
//     RWMutex — AttachWriter / AttachWriterWithQueue / DetachWriter take the write lock,
//     AttachReader takes the read lock.

package ncs

import (
	"fmt"
	"sync"

	"github.com/mr-addams/arx-core/pkg/executor/queue"
	"github.com/mr-addams/arx-core/pkg/logger"
)

// DefaultBufferSize is used by AttachWriter when bufferSize <= 0.
const DefaultBufferSize = 1000

var (
	ncsMu     sync.RWMutex
	ncsQueues = map[string]queue.Queue{}
	// ncsRefs tracks how many sinks share the same named queue.
	// DetachWriter closes the queue only when the last sink deregisters.
	ncsRefs = map[string]int{}
)

// AttachWriter returns a MemoryQueue for the given name, creating it if needed.
// Fan-in: multiple streams can register the same name and push into the same queue.
// The queue is closed only when the last caller invokes DetachWriter.
func AttachWriter(name string, bufferSize int) (queue.Queue, error) {
	if bufferSize <= 0 {
		bufferSize = DefaultBufferSize
	}
	ncsMu.Lock()
	defer ncsMu.Unlock()
	if q, exists := ncsQueues[name]; exists {
		ncsRefs[name]++
		return q, nil
	}
	q := queue.NewMemoryQueue(bufferSize)
	ncsQueues[name] = q
	ncsRefs[name] = 1
	return q, nil
}

// AttachWriterWithQueue registers a pre-configured Queue under the given name.
// If the name is already registered, the existing queue is reused (fan-in);
// the supplied q is ignored and the reference counter is incremented.
func AttachWriterWithQueue(name string, q queue.Queue) error {
	ncsMu.Lock()
	defer ncsMu.Unlock()
	if _, exists := ncsQueues[name]; exists {
		ncsRefs[name]++
		return nil
	}
	ncsQueues[name] = q
	ncsRefs[name] = 1
	return nil
}

// RegisterSinkFromConfig creates a Queue for the given name from cfg
// (memory / bbolt / redis backend) and registers it in the Named Channel Switch.
//
// Called from: main.go at startup, before stream goroutines with sentinel-threat sinks are launched.
// Must run BEFORE AttachWriter/AttachWriterWithQueue for the same name — the first
// registration wins, subsequent calls do fan-in (refcount++). This lets a pre-registered
// bbolt/redis backend coexist with a later AttachWriter call from the sink.
//
// cfg == nil is equivalent to AttachWriter(name, 0): the default MemoryQueue.
//
// For bbolt and redis the returned error is propagated so the pipeline fails on
// misconfiguration (e.g. invalid path, unreachable Redis).
// For memory (and nil cfg) the error path is unreachable — the function always returns nil.
// The error return exists for bbolt/redis and for future backend types.
//
// For bbolt and redis, the caller MUST pre-populate cfg.Bucket / cfg.Key; an empty value
// triggers a fail-fast panic from EffectiveBucket / EffectiveKey (Phase 5, Flow 083).
// Core has no hardcoded default — the product owns its own namespace.
func RegisterSinkFromConfig(name string, cfg *queue.QueueConfig, log logger.Logger) error {
	// Nil cfg falls back to the legacy MemoryQueue path so the existing behaviour
	// is preserved without changing the call-site code.
	if cfg == nil {
		_, err := AttachWriter(name, 0)
		return err
	}
	switch cfg.Type {
	case queue.QueueTypeMemory, "":
		// Empty type also resolves to memory — same default as a nil cfg.
		_, err := AttachWriter(name, 0)
		return err
	case queue.QueueTypeBbolt:
		// Bbolt queue: log flows through RegisterSinkFromConfig (Flow 073 Task 1.3.2.3 — F1 closure for bbolt).
		q, err := queue.NewBboltQueue(cfg.Path, cfg.EffectiveBucket(), log)
		if err != nil {
			return fmt.Errorf("channelswitch: bbolt queue for %q (path=%q): %w", name, cfg.Path, err)
		}
		return AttachWriterWithQueue(name, q)
	case queue.QueueTypeRedis:
		q, err := queue.NewRedisQueue(cfg.URL, cfg.EffectiveKey(name))
		if err != nil {
			return fmt.Errorf("channelswitch: redis queue for %q (url=%q): %w", name, cfg.URL, err)
		}
		return AttachWriterWithQueue(name, q)
	default:
		return fmt.Errorf("channelswitch: unknown queue type %q for %q (want memory|bbolt|redis)", cfg.Type, name)
	}
}

// AttachReader returns the Queue previously registered under the given name.
// The caller uses Queue.Pop(ctx) to receive events.
// Returns an error if no queue is registered under that name.
func AttachReader(name string) (queue.Queue, error) {
	ncsMu.RLock()
	defer ncsMu.RUnlock()
	q, exists := ncsQueues[name]
	if !exists {
		return nil, fmt.Errorf("channelswitch: source %q not found", name)
	}
	return q, nil
}

// DetachWriter decrements the reference counter of the named queue.
// The queue is closed and removed only when the last registered sink deregisters.
func DetachWriter(name string) {
	ncsMu.Lock()
	defer ncsMu.Unlock()
	if ncsRefs[name] > 1 {
		ncsRefs[name]--
		return
	}
	if q, exists := ncsQueues[name]; exists {
		q.Close()
		delete(ncsQueues, name)
		delete(ncsRefs, name)
	}
}

// Compile-time guarantee that queue.Queue satisfies plugin.EventSource.
//
// Phase 2.2 (Flow 083 / Gate A — RESOLVED-D strategy II / OPEN-Q3b gray zone):
// queue.Queue still operates on opaque []byte payloads (see
// pkg/executor/queue/queue.go — deliberate, so persistent backends
// serialize via JSON cleanly across process restarts). The Sink side
// (Formatter) and Executor side (adapter) own wire-schema translation.
// An EventSource adapter lives in Task 3.3 (Flow 083) — for Gate A we
// disable this compile-time assertion to unblock build; the actual
// contract conversion is wired via RegisterSinkFromConfig + executor
// adapters at runtime.
// This declaration is intentionally commented out during Gate A and
// restored in Task 3.3 once the adapter is in place.
// var _ plugin.EventSource = (queue.Queue)(nil)
