// ========================== internal/sys/metrics — metrics_test.go =========
//   Tests for MetricsCollector: Prometheus metrics, labels, aggregation.

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
	m.RecordLine("site1", "api")
	m.RecordLine("site1", "api")
	m.RecordLine("site1", "admin")
	m.RecordLine("site2", "")
	if got := testutil.ToFloat64(m.linesProcessed.WithLabelValues("site1", "api")); got != 2 {
		t.Errorf("linesProcessed{site1,api} = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.linesProcessed.WithLabelValues("site1", "admin")); got != 1 {
		t.Errorf("linesProcessed{site1,admin} = %v, want 1", got)
	}
	// Legacy pipeline="" label must be independent.
	if got := testutil.ToFloat64(m.linesProcessed.WithLabelValues("site2", "")); got != 1 {
		t.Errorf("linesProcessed{site2,\"\"} = %v, want 1", got)
	}
}

func TestRecordThreat(t *testing.T) {
	m := newTest(t)
	m.RecordThreat("site1", "api", "THREAT")
	m.RecordThreat("site1", "api", "THREAT")
	m.RecordThreat("site1", "api", "WARN")
	m.RecordThreat("site1", "admin", "THREAT")
	m.RecordThreat("site2", "", "THREAT")

	if got := testutil.ToFloat64(m.threats.WithLabelValues("site1", "api", "THREAT")); got != 2 {
		t.Errorf("threats{site1,api,THREAT} = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.threats.WithLabelValues("site1", "api", "WARN")); got != 1 {
		t.Errorf("threats{site1,api,WARN} = %v, want 1", got)
	}
	// Different pipeline within same stream must be isolated.
	if got := testutil.ToFloat64(m.threats.WithLabelValues("site1", "admin", "THREAT")); got != 1 {
		t.Errorf("threats{site1,admin,THREAT} = %v, want 1", got)
	}
	// Legacy pipeline="" must be independent.
	if got := testutil.ToFloat64(m.threats.WithLabelValues("site2", "", "THREAT")); got != 1 {
		t.Errorf("threats{site2,\"\",THREAT} = %v, want 1", got)
	}
}

func TestRecordDetectorHit(t *testing.T) {
	m := newTest(t)
	m.RecordDetectorHit("site1", "api", "probe")
	m.RecordDetectorHit("site1", "api", "probe")
	m.RecordDetectorHit("site1", "api", "rate")
	m.RecordDetectorHit("site1", "admin", "probe")
	m.RecordDetectorHit("site2", "", "probe")

	if got := testutil.ToFloat64(m.detectorHits.WithLabelValues("site1", "api", "probe")); got != 2 {
		t.Errorf("detectorHits{site1,api,probe} = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.detectorHits.WithLabelValues("site1", "api", "rate")); got != 1 {
		t.Errorf("detectorHits{site1,api,rate} = %v, want 1", got)
	}
	// Pipeline isolation: admin pipeline must not inherit api counts.
	if got := testutil.ToFloat64(m.detectorHits.WithLabelValues("site1", "admin", "probe")); got != 1 {
		t.Errorf("detectorHits{site1,admin,probe} = %v, want 1", got)
	}
	// Legacy pipeline="".
	if got := testutil.ToFloat64(m.detectorHits.WithLabelValues("site2", "", "probe")); got != 1 {
		t.Errorf("detectorHits{site2,\"\",probe} = %v, want 1", got)
	}
}

func TestUpdateGauges(t *testing.T) {
	m := newTest(t)
	m.UpdateGauges("site1", "api", 10, 2)
	if got := testutil.ToFloat64(m.trackedIPs.WithLabelValues("site1", "api")); got != 10 {
		t.Errorf("trackedIPs{site1,api} = %v, want 10", got)
	}
	if got := testutil.ToFloat64(m.suspiciousIPs.WithLabelValues("site1", "api")); got != 2 {
		t.Errorf("suspiciousIPs{site1,api} = %v, want 2", got)
	}

	// Gauges overwrite, not accumulate.
	m.UpdateGauges("site1", "api", 5, 0)
	if got := testutil.ToFloat64(m.trackedIPs.WithLabelValues("site1", "api")); got != 5 {
		t.Errorf("trackedIPs{site1,api} after update = %v, want 5", got)
	}
	if got := testutil.ToFloat64(m.suspiciousIPs.WithLabelValues("site1", "api")); got != 0 {
		t.Errorf("suspiciousIPs{site1,api} after reset = %v, want 0", got)
	}
}

func TestStreamIsolation(t *testing.T) {
	m := newTest(t)
	m.RecordLine("a", "pipe1")
	m.RecordLine("a", "pipe1")
	m.RecordLine("b", "pipe1")
	m.UpdateGauges("a", "pipe1", 7, 3)
	m.UpdateGauges("b", "pipe1", 1, 0)

	if got := testutil.ToFloat64(m.linesProcessed.WithLabelValues("a", "pipe1")); got != 2 {
		t.Errorf("linesProcessed{a,pipe1} = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.linesProcessed.WithLabelValues("b", "pipe1")); got != 1 {
		t.Errorf("linesProcessed{b,pipe1} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.trackedIPs.WithLabelValues("a", "pipe1")); got != 7 {
		t.Errorf("trackedIPs{a,pipe1} = %v, want 7", got)
	}
	if got := testutil.ToFloat64(m.trackedIPs.WithLabelValues("b", "pipe1")); got != 1 {
		t.Errorf("trackedIPs{b,pipe1} = %v, want 1", got)
	}
}

// TestPipelineIsolation verifies that two pipelines within the same stream
// maintain independent counters — the key invariant of Task 4.
func TestPipelineIsolation(t *testing.T) {
	m := newTest(t)
	m.RecordLine("nginx", "api")
	m.RecordLine("nginx", "api")
	m.RecordLine("nginx", "admin")
	m.UpdateGauges("nginx", "api", 10, 1)
	m.UpdateGauges("nginx", "admin", 3, 0)

	if got := testutil.ToFloat64(m.linesProcessed.WithLabelValues("nginx", "api")); got != 2 {
		t.Errorf("linesProcessed{nginx,api} = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.linesProcessed.WithLabelValues("nginx", "admin")); got != 1 {
		t.Errorf("linesProcessed{nginx,admin} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.trackedIPs.WithLabelValues("nginx", "api")); got != 10 {
		t.Errorf("trackedIPs{nginx,api} = %v, want 10", got)
	}
	if got := testutil.ToFloat64(m.trackedIPs.WithLabelValues("nginx", "admin")); got != 3 {
		t.Errorf("trackedIPs{nginx,admin} = %v, want 3", got)
	}
}

// TestLegacyPipelineEmptyLabel verifies that legacy auto-wrapped pipelines (pipeline="")
// produce valid Prometheus label values without panic or registration errors.
func TestLegacyPipelineEmptyLabel(t *testing.T) {
	m := newTest(t)
	// Should not panic — empty string is a valid Prometheus label value.
	m.RecordLine("nginx", "")
	m.RecordThreat("nginx", "", "THREAT")
	m.RecordDetectorHit("nginx", "", "probe")
	m.UpdateGauges("nginx", "", 5, 1)
	m.RecordInputLine("nginx", "", "file:/access.log", "file")
	m.RecordOutputEvent("nginx", "", "stdout", "stdout")
	m.RecordOutputDropped("nginx", "", "stdout", "buffer_full")

	if got := testutil.ToFloat64(m.linesProcessed.WithLabelValues("nginx", "")); got != 1 {
		t.Errorf("linesProcessed{nginx,\"\"} = %v, want 1", got)
	}
}
