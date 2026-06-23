// ========================== pkg/plugin — shared types ====================================
//   Public data types shared between Sources, Sinks, Detectors, and the pipeline.
//   This package depends only on stdlib — external developers can import it
//   without pulling in any arxsentinel-internal dependencies.
//
//   WHAT IS HERE:
//     - SourceStats — counters emitted by Source implementations
//
//   WHAT IS NOT HERE:
//     - LogEntry (parser/types.go — moved to its owning package, Flow 083 Phase 3)
//     - Source / Sink interfaces (source.go, sink.go)
//     - Detector interface (detector.go)
//     - Implementations (internal/)
//
//   DEPENDENCY RULE:
//     pkg/plugin → stdlib only. Never import internal/.

package plugin

// SourceStats — operational counters emitted by a Source.
// Pulled by the pipeline for STATS log entries and Prometheus metrics.
type SourceStats struct {
	LinesRead   int64 // total lines received from the underlying source
	ParseErrors int64 // lines that failed to parse
	Dropped     int64 // lines dropped due to full merge buffer (D3)
}
