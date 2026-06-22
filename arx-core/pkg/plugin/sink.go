// ========================== pkg/plugin — Sink interface ==================================
//   Public contract for threat event outputs.
//
//   WHAT IS HERE:
//     - ThreatEvent — structured event passed to every Sink after scoring
//     - SinkStats   — operational counters emitted by Sink implementations
//     - Sink        — interface any output implementation must satisfy
//
//   WHAT IS NOT HERE:
//     - FileSink, StdoutSink (internal/core/output/)
//     - Fan-out logic (pipeline in cmd/arxsentinel/main.go)
//
//   DEPENDENCY RULE:
//     pkg/plugin → stdlib only.

package plugin

import (
	"context"
	"time"
)

// ThreatEvent — fully-populated threat event delivered to all Sinks after scoring.
//
// Source and SourceType are filled by the pipeline from the Source that produced
// the log line. RawLine is populated only when logging.debug == true — omit it
// in production Sink output to avoid leaking raw HTTP data.
type ThreatEvent struct {
	Timestamp  time.Time // time of the log entry (from LogEntry.Time)
	Level      string    // "WARN" or "THREAT"
	Stream     string    // stream name; empty in single-stream mode
	Source     string    // source name: "file:/path" or "stdin"
	SourceType string    // source kind: "file", "stdin", "http", ...
	IP         string    // client IP that triggered the event
	Score      int       // total accumulated threat score
	Modules    []string  // detectors that contributed (e.g. ["probe", "rate"])
	Reason     string    // combined reason string: "probe:env:3,rate:142rps"
	RawLine    string    // original log line; empty unless logging.debug == true
}

// SinkStats — operational counters emitted by a Sink.
type SinkStats struct {
	EventsWritten int64 // events successfully written
	Dropped       int64 // events dropped (e.g. buffer full for async sinks)
	Errors        int64 // write errors
}

// Sink — public interface for any threat event destination.
//
// Write is called synchronously for every WARN/THREAT event.
// Phase 1 Sinks (file, stdout) are synchronous and fast.
// Phase 2+ async Sinks must be non-blocking internally.
//
// Implement this interface to route threat events anywhere.
type Sink interface {
	// Name returns a human-readable identifier used in logs and metrics.
	// Convention: "file:/var/log/threats.log", "stdout", "splunk:https://...".
	Name() string

	// Write delivers a threat event to this sink.
	// Must be safe for concurrent calls.
	//
	// ctx allows the caller to cancel an in-flight delivery (e.g. shutdown).
	// Implementations should respect ctx cancellation where the underlying
	// I/O is blocking (network Push, external process send). For non-blocking
	// sinks (file, stdout) ctx is informational and may be ignored.
	Write(ctx context.Context, event ThreatEvent) error

	// Close flushes any buffered data and releases resources.
	Close() error

	// Manifest returns plugin metadata (name, version, dependencies).
	Manifest() Manifest

	// Stats returns a point-in-time snapshot of operational counters.
	Stats() SinkStats
}
