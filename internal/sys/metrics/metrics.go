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
//   WHAT IS NOT HERE:
//     - HTTP server for /metrics endpoint (main.go, Task 8.2)
//     - Metric incrementation logic (main.go, Task 8.3)

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
	linesProcessed prometheus.Counter
	threats        *prometheus.CounterVec
	detectorHits   *prometheus.CounterVec
	trackedIPs     prometheus.Gauge
	suspiciousIPs  prometheus.Gauge
}

// New creates and registers all metrics with reg.
// Pass prometheus.DefaultRegisterer in production; prometheus.NewRegistry() in tests.
func New(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		linesProcessed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "nginx_sentinel_lines_processed_total",
			Help: "Total number of log lines processed.",
		}),
		threats: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "nginx_sentinel_threats_total",
			Help: "Total threat log entries written, by severity level.",
		}, []string{"level"}),
		detectorHits: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "nginx_sentinel_detector_hits_total",
			Help: "Total detector hits, by detector name.",
		}, []string{"detector"}),
		trackedIPs: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "nginx_sentinel_tracked_ips",
			Help: "Current number of IPs tracked in memory.",
		}),
		suspiciousIPs: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "nginx_sentinel_suspicious_ips",
			Help: "Current number of IPs with a non-zero suspicion score.",
		}),
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

// RecordLine increments the processed-lines counter.
func (m *Metrics) RecordLine() { m.linesProcessed.Inc() }

// RecordThreat increments the threat counter for the given level ("THREAT" or "WARN").
func (m *Metrics) RecordThreat(level string) { m.threats.WithLabelValues(level).Inc() }

// RecordDetectorHit increments the hit counter for the named detector.
func (m *Metrics) RecordDetectorHit(detector string) { m.detectorHits.WithLabelValues(detector).Inc() }

// UpdateGauges sets the current tracked-IP and suspicious-IP counts.
func (m *Metrics) UpdateGauges(tracked, suspicious int) {
	m.trackedIPs.Set(float64(tracked))
	m.suspiciousIPs.Set(float64(suspicious))
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
func RecordLine() {
	if m := defPtr.Load(); m != nil {
		m.RecordLine()
	}
}

// RecordThreat increments the threat counter on the default instance.
func RecordThreat(level string) {
	if m := defPtr.Load(); m != nil {
		m.RecordThreat(level)
	}
}

// RecordDetectorHit increments the detector hit counter on the default instance.
func RecordDetectorHit(detector string) {
	if m := defPtr.Load(); m != nil {
		m.RecordDetectorHit(detector)
	}
}

// UpdateGauges updates tracked/suspicious IP gauges on the default instance.
func UpdateGauges(tracked, suspicious int) {
	if m := defPtr.Load(); m != nil {
		m.UpdateGauges(tracked, suspicious)
	}
}
