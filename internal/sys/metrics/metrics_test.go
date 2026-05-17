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
	m.RecordLine("site1")
	m.RecordLine("site1")
	m.RecordLine("site2")
	if got := testutil.ToFloat64(m.linesProcessed.WithLabelValues("site1")); got != 2 {
		t.Errorf("linesProcessed{site1} = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.linesProcessed.WithLabelValues("site2")); got != 1 {
		t.Errorf("linesProcessed{site2} = %v, want 1", got)
	}
}

func TestRecordThreat(t *testing.T) {
	m := newTest(t)
	m.RecordThreat("site1", "THREAT")
	m.RecordThreat("site1", "THREAT")
	m.RecordThreat("site1", "WARN")
	m.RecordThreat("site2", "THREAT")

	if got := testutil.ToFloat64(m.threats.WithLabelValues("site1", "THREAT")); got != 2 {
		t.Errorf("threats{site1,THREAT} = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.threats.WithLabelValues("site1", "WARN")); got != 1 {
		t.Errorf("threats{site1,WARN} = %v, want 1", got)
	}
	// site2 counter must be isolated from site1.
	if got := testutil.ToFloat64(m.threats.WithLabelValues("site2", "THREAT")); got != 1 {
		t.Errorf("threats{site2,THREAT} = %v, want 1", got)
	}
}

func TestRecordDetectorHit(t *testing.T) {
	m := newTest(t)
	m.RecordDetectorHit("site1", "probe")
	m.RecordDetectorHit("site1", "probe")
	m.RecordDetectorHit("site1", "probe")
	m.RecordDetectorHit("site1", "rate")
	m.RecordDetectorHit("site2", "probe")

	if got := testutil.ToFloat64(m.detectorHits.WithLabelValues("site1", "probe")); got != 3 {
		t.Errorf("detectorHits{site1,probe} = %v, want 3", got)
	}
	if got := testutil.ToFloat64(m.detectorHits.WithLabelValues("site1", "rate")); got != 1 {
		t.Errorf("detectorHits{site1,rate} = %v, want 1", got)
	}
	// site2 must not inherit site1 counts.
	if got := testutil.ToFloat64(m.detectorHits.WithLabelValues("site2", "probe")); got != 1 {
		t.Errorf("detectorHits{site2,probe} = %v, want 1", got)
	}
}

func TestUpdateGauges(t *testing.T) {
	m := newTest(t)
	m.UpdateGauges("site1", 10, 2)
	if got := testutil.ToFloat64(m.trackedIPs.WithLabelValues("site1")); got != 10 {
		t.Errorf("trackedIPs{site1} = %v, want 10", got)
	}
	if got := testutil.ToFloat64(m.suspiciousIPs.WithLabelValues("site1")); got != 2 {
		t.Errorf("suspiciousIPs{site1} = %v, want 2", got)
	}

	// Gauges overwrite, not accumulate.
	m.UpdateGauges("site1", 5, 0)
	if got := testutil.ToFloat64(m.trackedIPs.WithLabelValues("site1")); got != 5 {
		t.Errorf("trackedIPs{site1} after update = %v, want 5", got)
	}
	if got := testutil.ToFloat64(m.suspiciousIPs.WithLabelValues("site1")); got != 0 {
		t.Errorf("suspiciousIPs{site1} after reset = %v, want 0", got)
	}
}

func TestStreamIsolation(t *testing.T) {
	m := newTest(t)
	m.RecordLine("a")
	m.RecordLine("a")
	m.RecordLine("b")
	m.UpdateGauges("a", 7, 3)
	m.UpdateGauges("b", 1, 0)

	if got := testutil.ToFloat64(m.linesProcessed.WithLabelValues("a")); got != 2 {
		t.Errorf("linesProcessed{a} = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.linesProcessed.WithLabelValues("b")); got != 1 {
		t.Errorf("linesProcessed{b} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.trackedIPs.WithLabelValues("a")); got != 7 {
		t.Errorf("trackedIPs{a} = %v, want 7", got)
	}
	if got := testutil.ToFloat64(m.trackedIPs.WithLabelValues("b")); got != 1 {
		t.Errorf("trackedIPs{b} = %v, want 1", got)
	}
}
