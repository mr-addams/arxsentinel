// ========================== pkg/plugin — Processor interface =============================
//   Processor enriches or filters a pipeline event. Every plugin in the
//   pipeline (Source, Detector, Sink) implements this interface so the
//   framework can call them uniformly.
//
//   Semantics:
//     - Process returns a (potentially modified) Event on success.
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

// Processor enriches or filters a pipeline event.
//
// Phase 2.2 (Flow 083 / RESOLVED-Q9): Process operates on the generic
// *plugin.Event. The Payload may be replaced (e.g. a scorer that wraps
// parser.LogEntry into a product-owned ThreatEvent); the Envelope may
// also be updated (e.g. Envelope.Level set to "THREAT" after scoring).
// The returned *Event is the same value object the caller should propagate.
type Processor interface {
	// Name returns the plugin's human-readable name, used in logs and metrics.
	Name() string

	// Process enriches or filters an event.
	// Returns (nil, nil) to drop the entry (gate/filter semantics).
	// Returns an error only on processing failure, not for filter logic.
	// The ctx parameter carries the pipeline lifecycle — implementations must
	// respect ctx.Done() for cancellation and use ctx for derived deadlines.
	Process(ctx context.Context, entry *Event) (*Event, error)

	// Manifest returns the plugin's identity and data contract.
	Manifest() Manifest
}