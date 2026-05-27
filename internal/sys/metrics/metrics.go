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
//   WHAT IS NOT HERE:
//     - HTTP server for /metrics endpoint (main.go)
//     - Metric incrementation logic (main.go)

package metrics

import (
	"sync"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
)

// Level constants for RecordThreat — prevent silent label typos.
const (
	LevelThreat = "THREAT"
	LevelWarn   = "WARN"
)

// Metrics holds all Prometheus collectors for ArxSentinel.
type Metrics struct {
	linesProcessed *prometheus.CounterVec
	threats        *prometheus.CounterVec
	detectorHits   *prometheus.CounterVec
	trackedIPs     *prometheus.GaugeVec
	suspiciousIPs  *prometheus.GaugeVec
	// Universal I/O counters (Flow #030).
	inputLines    *prometheus.CounterVec
	outputEvents  *prometheus.CounterVec
	outputDropped *prometheus.CounterVec
}

// New creates and registers all metrics with reg.
// Pass prometheus.DefaultRegisterer in production; prometheus.NewRegistry() in tests.
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
	}
	m.inputLines = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "arxsentinel_input_lines_total",
		Help: "Total log lines read from sources, by stream, pipeline, source, and source_type.",
	}, []string{"stream", "pipeline", "source", "source_type"})
	m.outputEvents = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "arxsentinel_output_events_total",
		Help: "Total threat events written to sinks, by stream, pipeline, sink, and sink_type.",
	}, []string{"stream", "pipeline", "sink", "sink_type"})
	m.outputDropped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "arxsentinel_output_dropped_total",
		Help: "Total threat events dropped at sinks, by stream, pipeline, sink, and reason.",
	}, []string{"stream", "pipeline", "sink", "reason"})
	reg.MustRegister(
		m.linesProcessed,
		m.threats,
		m.detectorHits,
		m.trackedIPs,
		m.suspiciousIPs,
		m.inputLines,
		m.outputEvents,
		m.outputDropped,
	)
	return m
}

// RecordLine increments the processed-lines counter for the given stream and pipeline.
// Legacy auto-wrapped pipelines pass pipeline="" for backward compat.
func (m *Metrics) RecordLine(stream, pipeline string) {
	m.linesProcessed.WithLabelValues(stream, pipeline).Inc()
}

// RecordThreat increments the threat counter for the given stream, pipeline and level ("THREAT" or "WARN").
func (m *Metrics) RecordThreat(stream, pipeline, level string) {
	m.threats.WithLabelValues(stream, pipeline, level).Inc()
}

// RecordDetectorHit increments the hit counter for the given stream, pipeline and detector name.
func (m *Metrics) RecordDetectorHit(stream, pipeline, detector string) {
	m.detectorHits.WithLabelValues(stream, pipeline, detector).Inc()
}

// UpdateGauges sets the current tracked-IP and suspicious-IP counts for the given stream and pipeline.
func (m *Metrics) UpdateGauges(stream, pipeline string, tracked, suspicious int) {
	m.trackedIPs.WithLabelValues(stream, pipeline).Set(float64(tracked))
	m.suspiciousIPs.WithLabelValues(stream, pipeline).Set(float64(suspicious))
}

// RecordInputLine increments the per-source line counter.
func (m *Metrics) RecordInputLine(stream, pipeline, source, sourceType string) {
	m.inputLines.WithLabelValues(stream, pipeline, source, sourceType).Inc()
}

// RecordOutputEvent increments the per-sink event counter on successful Write.
func (m *Metrics) RecordOutputEvent(stream, pipeline, sink, sinkType string) {
	m.outputEvents.WithLabelValues(stream, pipeline, sink, sinkType).Inc()
}

// RecordOutputDropped increments the dropped counter (Phase 2: async sinks with internal buffers).
func (m *Metrics) RecordOutputDropped(stream, pipeline, sink, reason string) {
	m.outputDropped.WithLabelValues(stream, pipeline, sink, reason).Inc()
}

// defPtr is the package-level default instance.
// Stored via atomic.Pointer so Load/Store are race-free without a mutex.
// nil before Init() — package-level functions no-op silently in that state.
var (
	defPtr   atomic.Pointer[Metrics]
	initOnce sync.Once
)

// Init initializes the default metrics instance against prometheus.DefaultRegisterer.
// Safe to call multiple times — only the first call has effect (sync.Once).
func Init() {
	initOnce.Do(func() {
		defPtr.Store(New(prometheus.DefaultRegisterer))
	})
}

// RecordLine increments the processed-lines counter on the default instance.
func RecordLine(stream, pipeline string) {
	if m := defPtr.Load(); m != nil {
		m.RecordLine(stream, pipeline)
	}
}

// RecordThreat increments the threat counter on the default instance.
func RecordThreat(stream, pipeline, level string) {
	if m := defPtr.Load(); m != nil {
		m.RecordThreat(stream, pipeline, level)
	}
}

// RecordDetectorHit increments the detector hit counter on the default instance.
func RecordDetectorHit(stream, pipeline, detector string) {
	if m := defPtr.Load(); m != nil {
		m.RecordDetectorHit(stream, pipeline, detector)
	}
}

// UpdateGauges updates tracked/suspicious IP gauges on the default instance.
func UpdateGauges(stream, pipeline string, tracked, suspicious int) {
	if m := defPtr.Load(); m != nil {
		m.UpdateGauges(stream, pipeline, tracked, suspicious)
	}
}

// RecordInputLine increments the per-source line counter on the default instance.
func RecordInputLine(stream, pipeline, source, sourceType string) {
	if m := defPtr.Load(); m != nil {
		m.RecordInputLine(stream, pipeline, source, sourceType)
	}
}

// RecordOutputEvent increments the per-sink event counter on the default instance.
func RecordOutputEvent(stream, pipeline, sink, sinkType string) {
	if m := defPtr.Load(); m != nil {
		m.RecordOutputEvent(stream, pipeline, sink, sinkType)
	}
}

// RecordOutputDropped increments the dropped counter on the default instance.
func RecordOutputDropped(stream, pipeline, sink, reason string) {
	if m := defPtr.Load(); m != nil {
		m.RecordOutputDropped(stream, pipeline, sink, reason)
	}
}
