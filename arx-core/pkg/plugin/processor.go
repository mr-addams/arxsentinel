// ========================== pkg/plugin — Processor interface =============================
//   Processor enriches or filters a LogEntry. Every plugin in the pipeline
//   (Source, Detector, Sink) implements this interface so the framework can
//   call them uniformly.
//
//   Semantics:
//     - Process returns a (potentially modified) LogEntry on success.
//     - Process returns (nil, nil) to signal "drop this entry" (gate/filter).
//     - Process returns an error ONLY on actual processing failure, never for
//       filter logic (that is (nil, nil)).
//
//   WHAT IS HERE:
//     - Processor interface
//
//   WHAT IS NOT HERE:
//     - Source / Sink / Detector interfaces with extra lifecycle methods
//       (source.go, sink.go, detector.go)

package plugin

import "context"

// Processor enriches or filters a log entry.
type Processor interface {
	// Name returns the plugin's human-readable name, used in logs and metrics.
	Name() string

	// Process enriches or filters a log entry.
	// Returns (nil, nil) to drop the entry (gate/filter semantics).
	// Returns an error only on processing failure, not for filter logic.
	// The ctx parameter carries the pipeline lifecycle — implementations must
	// respect ctx.Done() for cancellation and use ctx for derived deadlines.
	Process(ctx context.Context, entry *LogEntry) (*LogEntry, error)

	// Manifest returns the plugin's identity and data contract.
	Manifest() Manifest
}
