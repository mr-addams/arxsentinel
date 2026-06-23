// ========================== pkg/plugin — Executor interface ==============================
//   Executor enforces actions triggered by threat events (e.g., block IPs via external API).
//
//   WHAT IS HERE:
//     EventSource  — minimal consumer interface (Pop) to avoid circular imports.
//     ExecutorStats — generic counters shared by all Executor implementations.
//     Executor      — public interface: Name, EventQueue, Close, Stats.
//
//   WHAT IS NOT HERE:
//     Executor implementations live in their own packages (with exec as the generic fallback).
//     Registry (pkg/executor/registry.go) — separate package.
//
//   DISTINCTION FROM SINK:
//     Sink is passive (write event to a destination).
//     Executor is active and stateful: it may hold a ban list, manage TTL timers,
//     call external APIs with retry logic, and auto-reverse actions (auto-unban).
//     Mixing the two would leak executor-specific state into the Sink interface.
//
//   Run is called in its own goroutine. The source is an EventSource — typically a
//   queue.Queue from pkg/executor/queue but defined here as an interface to avoid
//   circular imports (pkg/executor/queue imports pkg/plugin for Event, so plugin
//   cannot import queue back).
//
//   Phase 2.2 (Flow 083 / RESOLVED-Q9): EventSource.Pop returns the generic
//   *plugin.Event. Executor implementations type-assert Event.Payload to their
//   product-owned type (typically *product.ThreatEvent) inside Run.

package plugin

import "context"

// EventSource is the consumer side of an event queue. Executors call Pop in their
// Run loop. Defined in plugin to avoid circular import: pkg/executor/queue imports
// pkg/plugin for *Event, so plugin cannot import queue back.
//
// Implementations: queue.MemoryQueue, queue.BboltQueue, queue.RedisQueue.
type EventSource interface {
	Pop(ctx context.Context) (*Event, error)
}

// ExecutorStats — generic operational counters emitted by an Executor.
//
// Executed: successful Execute() calls (event was acted upon).
// Skipped:  events ignored by the executor (e.g., below min_level, already banned).
// Errors:   Execute() calls that returned a non-nil error.
// Swept:    automatically reversed actions (e.g., expired TTL bans removed by sweep).
//
//	Only executors with auto-reverse semantics populate this.
//
// Implementation-specific counters (e.g., CF API retries, dedup hits) belong in
// the executor's own log output, not here. Stats is for pipeline-level visibility.
type ExecutorStats struct {
	Executed int64
	Skipped  int64
	Errors   int64
	Swept    int64
}

// Executor — public interface for autonomous enforcement actions.
//
// Flow #043 changes: Executor receives events via EventSource (Pop) instead of a
// raw <-chan. Named Channel Switch provides a queue.Queue which satisfies EventSource.
// Run() is called as a goroutine and returns when ctx is cancelled.
//
// Phase 2.2 (Flow 083): events popped from EventSource are generic *plugin.Event;
// the executor type-asserts Payload to its product-owned type inside Run.
//
// Implementations are responsible for:
//   - Startup sync (e.g., loading current ban list from remote API).
//   - Deduplication (e.g., skipping already-banned IPs).
//   - TTL management (e.g., auto-unban after configured duration).
//   - Retry / circuit-breaker logic on external API failures.
//   - Batch accumulation and flush (when applicable).
//
// Run receives *Event values via Pop and must be safe for concurrent access only
// via the EventSource — no external goroutines call methods on the Executor after Run() starts.
type Executor interface {
	Name() string
	Type() string
	Run(ctx context.Context, source EventSource) error
	Manifest() Manifest
	Stats() ExecutorStats
}