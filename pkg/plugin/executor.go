// ========================== pkg/plugin — Executor interface ==============================
//   Executor enforces actions triggered by threat events (e.g., block IPs via external API).
//
//   WHAT IS HERE:
//     ExecutorStats — generic counters shared by all Executor implementations.
//     Executor      — public interface: Name, Execute, Close, Stats.
//
//   WHAT IS NOT HERE:
//     Executor implementations (cloudflare/, exec fallback) — each lives in its own package.
//     Registry (pkg/executor/registry.go) — separate package.
//
//   DISTINCTION FROM SINK:
//     Sink is passive (write event to a destination).
//     Executor is active and stateful: it may hold a ban list, manage TTL timers,
//     call external APIs with retry logic, and auto-reverse actions (auto-unban).
//     Mixing the two would leak executor-specific state into the Sink interface.
//
//   Execute is called after all Sinks have written the event.
//   A slow Executor blocks the pipeline goroutine — implementations that call
//   external APIs must budget their latency or queue internally.

package plugin

import "context"

// ExecutorStats — generic operational counters emitted by an Executor.
//
// Executed: successful Execute() calls (event was acted upon).
// Skipped:  events ignored by the executor (e.g., below min_level, already banned).
// Errors:   Execute() calls that returned a non-nil error.
//
// Implementation-specific counters (e.g., CF API retries, dedup hits) belong in
// the executor's own log output, not here. Stats is for pipeline-level visibility.
type ExecutorStats struct {
	Executed int64
	Skipped  int64
	Errors   int64
}

// Executor — public interface for stateful enforcement actions.
//
// Implementations are responsible for:
//   - Startup sync (e.g., loading current ban list from remote API).
//   - Deduplication (e.g., skipping already-banned IPs).
//   - TTL management (e.g., auto-unban after configured duration).
//   - Retry / circuit-breaker logic on external API failures.
//
// Execute receives a fully-scored ThreatEvent from the pipeline.
// Returning a non-nil error increments the Errors counter and is logged by the pipeline;
// it does not stop the pipeline or prevent other executors from running.
type Executor interface {
	Name() string
	Execute(ctx context.Context, event ThreatEvent) error
	Close() error
	Stats() ExecutorStats
}
