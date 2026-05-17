package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// newTest returns a Metrics instance backed by a fresh isolated registry.
// Each test gets its own registry so calls don't bleed between tests.
func newTest(t *testing.T) *Metrics {
	t.Helper()
	return New(prometheus.NewRegistry())
}

func TestRecordLine(t *testing.T) {
	m := newTest(t)
	m.RecordLine()
	m.RecordLine()
	if got := testutil.ToFloat64(m.linesProcessed); got != 2 {
		t.Errorf("linesProcessed = %v, want 2", got)
	}
}

func TestRecordThreat(t *testing.T) {
	m := newTest(t)
	m.RecordThreat("THREAT")
	m.RecordThreat("THREAT")
	m.RecordThreat("WARN")

	if got := testutil.ToFloat64(m.threats.WithLabelValues("THREAT")); got != 2 {
		t.Errorf("threats{THREAT} = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.threats.WithLabelValues("WARN")); got != 1 {
		t.Errorf("threats{WARN} = %v, want 1", got)
	}
}

func TestRecordDetectorHit(t *testing.T) {
	m := newTest(t)
	m.RecordDetectorHit("probe")
	m.RecordDetectorHit("probe")
	m.RecordDetectorHit("probe")
	m.RecordDetectorHit("rate")

	if got := testutil.ToFloat64(m.detectorHits.WithLabelValues("probe")); got != 3 {
		t.Errorf("detectorHits{probe} = %v, want 3", got)
	}
	if got := testutil.ToFloat64(m.detectorHits.WithLabelValues("rate")); got != 1 {
		t.Errorf("detectorHits{rate} = %v, want 1", got)
	}
}

func TestUpdateGauges(t *testing.T) {
	m := newTest(t)
	m.UpdateGauges(10, 2)
	if got := testutil.ToFloat64(m.trackedIPs); got != 10 {
		t.Errorf("trackedIPs = %v, want 10", got)
	}
	if got := testutil.ToFloat64(m.suspiciousIPs); got != 2 {
		t.Errorf("suspiciousIPs = %v, want 2", got)
	}

	// Verify gauges overwrite, not accumulate.
	m.UpdateGauges(5, 0)
	if got := testutil.ToFloat64(m.trackedIPs); got != 5 {
		t.Errorf("trackedIPs after update = %v, want 5", got)
	}
	if got := testutil.ToFloat64(m.suspiciousIPs); got != 0 {
		t.Errorf("suspiciousIPs after reset = %v, want 0", got)
	}
}
