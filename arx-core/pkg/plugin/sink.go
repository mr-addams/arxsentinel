// ========================== pkg/plugin — Sink interface ==================================
//   Public contract for threat event outputs.
//
//   WHAT IS HERE:
//     - SinkStats — operational counters emitted by Sink implementations
//     - Sink      — interface any output implementation must satisfy
//
//   WHAT IS NOT HERE:
//     - FileSink, StdoutSink (pkg/sink/{file,stdout})
//     - Fan-out logic (engine in pkg/runtime)
//
//   DEPENDENCY RULE:
//     pkg/plugin → stdlib only.
//
//   Phase 2.2 (Flow 083 / RESOLVED-Q9 / RESOLVED-Z12):
//     The Sink contract is generalized to a generic *plugin.Event. Concrete
//     threat-event shaping lives in a Formatter (interface in pkg/sink/format);
//     the engine NEVER inspects Event.Payload — that is the owning plugin's
//     responsibility. Sinks dispatch to an injected Formatter that knows how
//     to render the payload bytes.

package plugin

import (
	"context"
	"time"
)

// SinkStats — operational counters emitted by a Sink.
type SinkStats struct {
	EventsWritten int64 // events successfully written
	Dropped       int64 // events dropped (e.g. buffer full for async sinks)
	Errors        int64 // write errors
}

// ThreatEvent — fully-populated threat event delivered to all Sinks after scoring.
//
// GATE A (Flow 083 / Task 2.2 / RESOLVED-D strategy II):
// ThreatEvent is a TEMPORARY resident of pkg/plugin. It remains here so that
// pkg/sink/format/*.go and downstream callers compile under the new
// *plugin.Event contract without forcing a full dissolution. The struct is
// expected to migrate to the product namespace and be replaced with a
// formatter-injected payload in Gate B (Task 3.3, Flow 083 RESOLVED-D).
// Sinks must type-assert Event.Payload.(*ThreatEvent) during Gate A.
type ThreatEvent struct {
	Timestamp  time.Time
	Level      string
	Stream     string
	Source     string
	SourceType string
	IP         string
	Score      int
	Modules    []string
	Reason     string
	RawLine    string
}

// Sink — public interface for any threat event destination.
//
// Write is called synchronously for every WARN/THREAT event.
// Phase 1 Sinks (file, stdout) are synchronous and fast.
// Phase 2+ async Sinks must be non-blocking internally.
//
// Implement this interface to route threat events anywhere.
//
// Phase 2.2 (Flow 083): the event argument is the generic *plugin.Event. The
// envelope is the transport metadata the engine may read for metrics/routing;
// the payload is opaque to the sink — it is the owning plugin's responsibility
// (e.g. via a Formatter) to render concrete bytes from the payload. See
// pkg/sink/format.Formatter for the serializer contract; product Formatter
// impls land in Phase 3.3 (Flow 083).
type Sink interface {
	// Name returns a human-readable identifier used in logs and metrics.
	// Convention: "file:/var/log/threats.log", "stdout", "splunk:https://...".
	Name() string

	// Write delivers an event to this sink.
	// Must be safe for concurrent calls.
	//
	// ctx allows the caller to cancel an in-flight delivery (e.g. shutdown).
	// Implementations should respect ctx cancellation where the underlying
	// I/O is blocking (network Push, external process send). For non-blocking
	// sinks (file, stdout) ctx is informational and may be ignored.
	Write(ctx context.Context, event *Event) error

	// Close flushes any buffered data and releases resources.
	Close() error

	// Manifest returns plugin metadata (name, version, dependencies).
	Manifest() Manifest

	// Stats returns a point-in-time snapshot of operational counters.
	Stats() SinkStats
}