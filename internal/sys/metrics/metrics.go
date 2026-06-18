// ========================== Module sys/metrics =========================================
//   Prometheus metrics for ArxSentinel.
//
//   WHAT IS HERE:
//     - Metrics struct — holds all registered prometheus collectors
//     - New(reg) — creates and registers metrics with the given registerer
//     - Package-level functions (RecordLine, RecordThreat, ...) — delegate to default instance
//     - Init() — initializes the default instance with prometheus.DefaultRegisterer
//
//   DESIGN:
//     Metrics struct + New(registerer) pattern allows tests to use an isolated
//     prometheus.NewRegistry() without touching the global default registry.
//     Production code calls Init() once at startup, then uses package-level functions.
//
//     All metrics carry "stream" and "pipeline" labels for multi-pipeline isolation.
//     Legacy single-pipeline configs use pipeline="" (empty string label value),
//     which keeps backward compat with existing Grafana dashboards.
//
//     C3 — label cardinality: metrics with dynamic labels (source, sink, reason)
//     support explicit cleanup via DeleteLabelValues. Callers must call the
//     cleanup methods when config changes at SIGHUP to prevent unbounded
//     cardinality growth. The "reason" label in outputDropped is restricted
//     to a fixed set of known constants (Reason*).
//
//   WHAT IS NOT HERE:
//     - HTTP server for /metrics endpoint (main.go)
//     - Metric incrementation logic (main.go)

package metrics

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Level constants for RecordThreat — prevent silent label typos.
const (
	LevelThreat = "THREAT"
	LevelWarn   = "WARN"
)

// Reason constants for RecordOutputDropped — restricts cardinality of "reason" label (C3).
const (
	ReasonBufferFull = "buffer_full" // Buffer full, entry dropped
	ReasonWriteErr   = "write_err"   // Sink write error
	ReasonShutdown   = "shutdown"    // Dropped during shutdown drain
	ReasonStale      = "stale"       // Entry expired before processing
	ReasonUnknown    = "unknown"     // Catch-all for unexpected reasons
)

// Metrics holds all Prometheus collectors for ArxSentinel.
// Consumer: main.go (metrics exposition), pipeline (increment).
type Metrics struct {
	linesProcessed *prometheus.CounterVec // YAML: — internal counter. Consumer: pipeline.processEntries
	threats        *prometheus.CounterVec // YAML: — internal counter. Consumer: pipeline.processEntries
	detectorHits   *prometheus.CounterVec // YAML: — internal counter. Consumer: pipeline.processEntries
	trackedIPs     *prometheus.GaugeVec   // YAML: — internal gauge. Consumer: metrics.UpdateGauges
	suspiciousIPs  *prometheus.GaugeVec   // YAML: — internal gauge. Consumer: metrics.UpdateGauges
	// Universal I/O counters (Flow #030).
	inputLines    *prometheus.CounterVec // YAML: — per-source counter. Consumer: pipeline.runSource
	outputEvents  *prometheus.CounterVec // YAML: — per-sink counter. Consumer: pipeline.runSink
	outputDropped *prometheus.CounterVec // YAML: — per-sink drop counter. Consumer: pipeline.runSink
	// Blocklist freshness gauge (062/Task 4.1).
	blocklistLastRefresh *prometheus.GaugeVec // YAML: — per-list gauge. Consumer: blocklist.fetchAndUpdate
}

// New creates and registers all metrics with reg.
// Pass prometheus.DefaultRegisterer in production; prometheus.NewRegistry() in tests.
// Called from: Init, tests.
//
// Blocking — MustRegister panics on duplicate metrics; panics are fatal.
func New(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		linesProcessed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "arx_sentinel_lines_processed_total",
			Help: "Total number of log lines processed.",
		}, []string{"stream", "pipeline"}),
		threats: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "arx_sentinel_threats_total",
			Help: "Total threat log entries written, by severity level.",
		}, []string{"stream", "pipeline", "level"}),
		detectorHits: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "arx_sentinel_detector_hits_total",
			Help: "Total detector hits, by detector name.",
		}, []string{"stream", "pipeline", "detector"}),
		trackedIPs: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "arx_sentinel_tracked_ips",
			Help: "Current number of IPs tracked in memory.",
		}, []string{"stream", "pipeline"}),
		suspiciousIPs: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "arx_sentinel_suspicious_ips",
			Help: "Current number of IPs with a non-zero suspicion score.",
		}, []string{"stream", "pipeline"}),
		inputLines: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "arxsentinel_input_lines_total",
			Help: "Total log lines read from sources, by stream, pipeline, source, and source_type.",
		}, []string{"stream", "pipeline", "source", "source_type"}),
		outputEvents: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "arxsentinel_output_events_total",
			Help: "Total threat events written to sinks, by stream, pipeline, sink, and sink_type.",
		}, []string{"stream", "pipeline", "sink", "sink_type"}),
		outputDropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "arxsentinel_output_dropped_total",
			Help: "Total threat events dropped at sinks, by stream, pipeline, sink, and reason.",
		}, []string{"stream", "pipeline", "sink", "reason"}),
		blocklistLastRefresh: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "arxsentinel_blocklist_last_refresh_timestamp_seconds",
			Help: "Unix timestamp of last successful blocklist refresh, by list name.",
		}, []string{"list"}),
	}
	reg.MustRegister(
		m.linesProcessed,
		m.threats,
		m.detectorHits,
		m.trackedIPs,
		m.suspiciousIPs,
		m.inputLines,
		m.outputEvents,
		m.outputDropped,
		m.blocklistLastRefresh,
	)
	return m
}

// RecordLine increments the processed-lines counter for the given stream and pipeline.
// Legacy auto-wrapped pipelines pass pipeline="" for backward compat.
// Called from: pipeline.processEntries. Non-blocking.
func (m *Metrics) RecordLine(stream, pipeline string) {
	m.linesProcessed.WithLabelValues(stream, pipeline).Inc()
}

// RecordThreat increments the threat counter for the given stream, pipeline and level ("THREAT" or "WARN").
// Called from: pipeline.processEntries. Non-blocking.
func (m *Metrics) RecordThreat(stream, pipeline, level string) {
	m.threats.WithLabelValues(stream, pipeline, level).Inc()
}

// RecordDetectorHit increments the hit counter for the given stream, pipeline and detector name.
// Called from: pipeline.processEntries. Non-blocking.
func (m *Metrics) RecordDetectorHit(stream, pipeline, detector string) {
	m.detectorHits.WithLabelValues(stream, pipeline, detector).Inc()
}

// UpdateGauges sets the current tracked-IP and suspicious-IP counts for the given stream and pipeline.
// Called from: main.go (periodic tick via runStream). Non-blocking.
func (m *Metrics) UpdateGauges(stream, pipeline string, tracked, suspicious int) {
	m.trackedIPs.WithLabelValues(stream, pipeline).Set(float64(tracked))
	m.suspiciousIPs.WithLabelValues(stream, pipeline).Set(float64(suspicious))
}

// RecordInputLine increments the per-source line counter.
// Called from: pipeline.runSource. Non-blocking.
func (m *Metrics) RecordInputLine(stream, pipeline, source, sourceType string) {
	m.inputLines.WithLabelValues(stream, pipeline, source, sourceType).Inc()
}

// RecordOutputEvent increments the per-sink event counter on successful Write.
// Called from: pipeline.runSink. Non-blocking.
func (m *Metrics) RecordOutputEvent(stream, pipeline, sink, sinkType string) {
	m.outputEvents.WithLabelValues(stream, pipeline, sink, sinkType).Inc()
}

// RecordOutputDropped increments the dropped counter (Phase 2: async sinks with internal buffers).
// reason must be one of the Reason* constants (C3 cardinality control).
// Called from: pipeline.runSink. Non-blocking.
func (m *Metrics) RecordOutputDropped(stream, pipeline, sink, reason string) {
	m.outputDropped.WithLabelValues(stream, pipeline, sink, reason).Inc()
}

// RecordBlocklistRefresh records the current Unix timestamp for a blocklist refresh (062/Task 4.1).
// Called from: blocklist.fetchAndUpdate after successful CompileStrings. Non-blocking.
func (m *Metrics) RecordBlocklistRefresh(listName string) {
	m.blocklistLastRefresh.WithLabelValues(listName).Set(float64(timeNow().Unix()))
}

// CleanupSourceLabels removes all label combinations for the given source from inputLines (C3).
// Called from: SIGHUP handler when a source is removed from config.
// Non-blocking but may cause subsequent WithLabelValues calls for the removed source to
// allocate new time series — that is acceptable for SIGHUP-frequency cleanup.
func (m *Metrics) CleanupSourceLabels(stream, pipeline, source, sourceType string) {
	m.inputLines.DeleteLabelValues(stream, pipeline, source, sourceType)
}

// CleanupSinkLabels removes all label combinations for the given sink from outputEvents only (C3).
// outputDropped has a different label signature (includes "reason") and requires a separate
// CleanupDroppedLabels call — see that method for details.
// Called from: SIGHUP handler when a sink is removed from config.
func (m *Metrics) CleanupSinkLabels(stream, pipeline, sink, sinkType string) {
	m.outputEvents.DeleteLabelValues(stream, pipeline, sink, sinkType)
}

// CleanupDroppedLabels removes all label combinations for the given sink+reason from outputDropped (C3).
func (m *Metrics) CleanupDroppedLabels(stream, pipeline, sink, reason string) {
	m.outputDropped.DeleteLabelValues(stream, pipeline, sink, reason)
}

// CleanupBlocklistLabels removes the gauge entry for the given list name (C3).
// Called from: SIGHUP handler when a list is removed from config.
func (m *Metrics) CleanupBlocklistLabels(listName string) {
	m.blocklistLastRefresh.DeleteLabelValues(listName)
}

// timeNow is overridden in tests.
//
//nolint:gochecknoglobals // clock injection for deterministic tests
var timeNow = time.Now

// ── Package-level default instance ─────────────────────────────────────────────────────

// defPtr is the package-level default instance.
// Stored via atomic.Pointer so Load/Store are race-free without a mutex.
// nil before Init() — package-level functions no-op silently in that state.
var (
	defPtr   atomic.Pointer[Metrics]
	initOnce sync.Once
)

// Init initializes the default metrics instance against prometheus.DefaultRegisterer.
// Safe to call multiple times — only the first call has effect (sync.Once).
// Called from: main.go at startup. Blocking.
func Init() {
	initOnce.Do(func() {
		defPtr.Store(New(prometheus.DefaultRegisterer))
	})
}

// RecordLine increments the processed-lines counter on the default instance.
// Called from: pipeline.processEntries. Non-blocking.
func RecordLine(stream, pipeline string) {
	if m := defPtr.Load(); m != nil {
		m.RecordLine(stream, pipeline)
	}
}

// RecordThreat increments the threat counter on the default instance.
// Called from: pipeline.processEntries. Non-blocking.
func RecordThreat(stream, pipeline, level string) {
	if m := defPtr.Load(); m != nil {
		m.RecordThreat(stream, pipeline, level)
	}
}

// RecordDetectorHit increments the detector hit counter on the default instance.
// Called from: pipeline.processEntries. Non-blocking.
func RecordDetectorHit(stream, pipeline, detector string) {
	if m := defPtr.Load(); m != nil {
		m.RecordDetectorHit(stream, pipeline, detector)
	}
}

// UpdateGauges updates tracked/suspicious IP gauges on the default instance.
// Called from: main.go (periodic tick). Non-blocking.
func UpdateGauges(stream, pipeline string, tracked, suspicious int) {
	if m := defPtr.Load(); m != nil {
		m.UpdateGauges(stream, pipeline, tracked, suspicious)
	}
}

// RecordInputLine increments the per-source line counter on the default instance.
// Called from: pipeline.runSource. Non-blocking.
func RecordInputLine(stream, pipeline, source, sourceType string) {
	if m := defPtr.Load(); m != nil {
		m.RecordInputLine(stream, pipeline, source, sourceType)
	}
}

// RecordOutputEvent increments the per-sink event counter on the default instance.
// Called from: pipeline.runSink. Non-blocking.
func RecordOutputEvent(stream, pipeline, sink, sinkType string) {
	if m := defPtr.Load(); m != nil {
		m.RecordOutputEvent(stream, pipeline, sink, sinkType)
	}
}

// RecordOutputDropped increments the dropped counter on the default instance.
// Called from: pipeline.runSink. Non-blocking.
func RecordOutputDropped(stream, pipeline, sink, reason string) {
	if m := defPtr.Load(); m != nil {
		m.RecordOutputDropped(stream, pipeline, sink, reason)
	}
}

// RecordBlocklistRefresh records the current Unix timestamp for a blocklist refresh on the default instance.
// Called from: blocklist.fetchAndUpdate after successful CompileStrings. Non-blocking.
func RecordBlocklistRefresh(listName string) {
	if m := defPtr.Load(); m != nil {
		m.RecordBlocklistRefresh(listName)
	}
}
