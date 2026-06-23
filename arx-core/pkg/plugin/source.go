// ========================== pkg/plugin — Source interface ================================
//   Public contract for log line input sources.
//
//   WHAT IS HERE:
//     - Source — interface any input implementation must satisfy
//
//   WHAT IS NOT HERE:
//     - FileSource, StdinSource (arx-core/pkg/source/)
//     - Merge fan-in (arx-core/pkg/input/merge.go)
//
//   DEPENDENCY RULE:
//     pkg/plugin → stdlib only.
//
//   Phase 2.2 (Flow 083 / RESOLVED-Q9):
//     Sources emit the generic *plugin.Event on their output channel. The
//     parser-owned LogEntry lives inside Event.Payload; the source fills
//     Envelope (Source/SourceType/Stream/Timestamp) at construction time.
//     Level is left empty — the product scorer assigns it later.
//     See pkg/parser.WrapLogEntry for the canonical conversion.

package plugin

import "context"

// Source — public interface for any log line input.
//
// Each Source owns its Parser and delivers parsed *plugin.Event values
// (wrapping the parser-owned LogEntry as Payload, with a transport Envelope).
// Run blocks until ctx is cancelled or an unrecoverable error occurs.
// Close releases file handles and other OS resources; it is always called
// by the pipeline regardless of whether Run returned an error.
//
// Implement this interface to add a custom input source to arxsentinel.
type Source interface {
	// Name returns a human-readable identifier used in logs and metrics.
	// Convention: "file:/path/to/access.log", "stdin", "http://:9514".
	Name() string

	// Run starts reading and sends events to out.
	// Must return when ctx is Done. Must not close out — the Merge function owns it.
	// Drop policy: non-blocking send; dropped entries increment Stats().Dropped.
	Run(ctx context.Context, out chan<- *Event) error

	// Close releases resources. Called after Run returns.
	Close() error

	// Manifest returns plugin metadata (name, version, dependencies).
	Manifest() Manifest

	// Stats returns a point-in-time snapshot of operational counters.
	Stats() SourceStats
}