// ========================== pkg/executor — Named Channel Hub =============================
//   In-process singleton that connects named Sink channels to Executor source channels.
//   Pipeline sinks call RegisterSink(name, bufferSize) → get write-only chan<- ThreatEvent.
//   Executors call GetSource(name) → get read-only <-chan ThreatEvent.
//   On shutdown, pipeline calls Unregister(name) → closes the channel and removes it.
//
//   WHAT IS HERE:
//     NamedChannelHub — global singleton behind package-level functions
//     RegisterSink    — create a named buffered channel, return write side
//     GetSource       — return read side of an existing named channel
//     Unregister      — close channel and delete from map
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
//     RWMutex — RegisterSink/Unregister take write lock, GetSource takes read lock.

package executor

import (
	"fmt"
	"sync"

	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

// DefaultBufferSize is used when RegisterSink is called with bufferSize <= 0.
const DefaultBufferSize = 1000

var (
	hubMu     sync.RWMutex
	hubChans  = map[string]chan plugin.ThreatEvent{}
)

// RegisterSink creates a new buffered channel with the given name and buffer size.
// Returns the write-only side of the channel.
// Returns an error if a channel with the same name is already registered.
func RegisterSink(name string, bufferSize int) (chan<- plugin.ThreatEvent, error) {
	if bufferSize <= 0 {
		bufferSize = DefaultBufferSize
	}
	hubMu.Lock()
	defer hubMu.Unlock()
	if _, exists := hubChans[name]; exists {
		return nil, fmt.Errorf("namedhub: sink %q already registered", name)
	}
	ch := make(chan plugin.ThreatEvent, bufferSize)
	hubChans[name] = ch
	return ch, nil
}

// GetSource returns the read-only side of a previously registered channel.
// Returns an error if no channel with the given name is registered.
func GetSource(name string) (<-chan plugin.ThreatEvent, error) {
	hubMu.RLock()
	defer hubMu.RUnlock()
	ch, exists := hubChans[name]
	if !exists {
		return nil, fmt.Errorf("namedhub: source %q not found", name)
	}
	return ch, nil
}

// Unregister closes the channel with the given name and removes it from the map.
// After Unregister, sending to the channel will panic — callers must ensure
// no goroutines are writing before calling Unregister.
func Unregister(name string) {
	hubMu.Lock()
	defer hubMu.Unlock()
	if ch, exists := hubChans[name]; exists {
		close(ch)
		delete(hubChans, name)
	}
}
