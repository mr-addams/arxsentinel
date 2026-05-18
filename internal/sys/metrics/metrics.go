// ========================== Module sys/metrics =========================================
//   Prometheus metrics for nginx-sentinel.
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
//     All metrics carry a "stream" label for multi-stream isolation.
//     Single-stream (backward compat) uses stream="" (empty string label value).
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

// Metrics holds all Prometheus collectors for nginx-sentinel.
type Metrics struct {
	linesProcessed *prometheus.CounterVec
	threats        *prometheus.CounterVec
	detectorHits   *prometheus.CounterVec
	trackedIPs     *prometheus.GaugeVec
	suspiciousIPs  *prometheus.GaugeVec
}

// New creates and registers all metrics with reg.
// Pass prometheus.DefaultRegisterer in production; prometheus.NewRegistry() in tests.
func New(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		linesProcessed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "nginx_sentinel_lines_processed_total",
			Help: "Total number of log lines processed.",
		}, []string{"stream"}),
		threats: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "nginx_sentinel_threats_total",
			Help: "Total threat log entries written, by severity level.",
		}, []string{"stream", "level"}),
		detectorHits: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "nginx_sentinel_detector_hits_total",
			Help: "Total detector hits, by detector name.",
		}, []string{"stream", "detector"}),
		trackedIPs: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "nginx_sentinel_tracked_ips",
			Help: "Current number of IPs tracked in memory.",
		}, []string{"stream"}),
		suspiciousIPs: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "nginx_sentinel_suspicious_ips",
			Help: "Current number of IPs with a non-zero suspicion score.",
		}, []string{"stream"}),
	}
	reg.MustRegister(
		m.linesProcessed,
		m.threats,
		m.detectorHits,
		m.trackedIPs,
		m.suspiciousIPs,
	)
	return m
}

// RecordLine increments the processed-lines counter for the given stream.
func (m *Metrics) RecordLine(stream string) { m.linesProcessed.WithLabelValues(stream).Inc() }

// RecordThreat increments the threat counter for the given stream and level ("THREAT" or "WARN").
func (m *Metrics) RecordThreat(stream, level string) {
	m.threats.WithLabelValues(stream, level).Inc()
}

// RecordDetectorHit increments the hit counter for the given stream and detector name.
func (m *Metrics) RecordDetectorHit(stream, detector string) {
	m.detectorHits.WithLabelValues(stream, detector).Inc()
}

// UpdateGauges sets the current tracked-IP and suspicious-IP counts for the given stream.
func (m *Metrics) UpdateGauges(stream string, tracked, suspicious int) {
	m.trackedIPs.WithLabelValues(stream).Set(float64(tracked))
	m.suspiciousIPs.WithLabelValues(stream).Set(float64(suspicious))
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
func RecordLine(stream string) {
	if m := defPtr.Load(); m != nil {
		m.RecordLine(stream)
	}
}

// RecordThreat increments the threat counter on the default instance.
func RecordThreat(stream, level string) {
	if m := defPtr.Load(); m != nil {
		m.RecordThreat(stream, level)
	}
}

// RecordDetectorHit increments the detector hit counter on the default instance.
func RecordDetectorHit(stream, detector string) {
	if m := defPtr.Load(); m != nil {
		m.RecordDetectorHit(stream, detector)
	}
}

// UpdateGauges updates tracked/suspicious IP gauges on the default instance.
func UpdateGauges(stream string, tracked, suspicious int) {
	if m := defPtr.Load(); m != nil {
		m.UpdateGauges(stream, tracked, suspicious)
	}
}
