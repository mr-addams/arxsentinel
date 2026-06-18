// ========================== internal/sys/metrics — metrics_test.go =========
//   Tests for MetricsCollector: Prometheus metrics, labels, aggregation.

package metrics

import (
	"testing"
	"time"

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

// TestRecordBlocklistRefresh verifies that the blocklist gauge is set correctly (Task 1.6).
func TestRecordBlocklistRefresh(t *testing.T) {
	m := newTest(t)
	now := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	timeNow = func() time.Time { return now }
	defer func() { timeNow = time.Now }()

	m.RecordBlocklistRefresh("bad_ips")
	m.RecordBlocklistRefresh("bad_ua")

	if got := testutil.ToFloat64(m.blocklistLastRefresh.WithLabelValues("bad_ips")); got != float64(now.Unix()) {
		t.Errorf("bad_ips timestamp = %v, want %v", got, now.Unix())
	}
	if got := testutil.ToFloat64(m.blocklistLastRefresh.WithLabelValues("bad_ua")); got != float64(now.Unix()) {
		t.Errorf("bad_ua timestamp = %v, want %v", got, now.Unix())
	}
}

// TestRecordBlocklistRefreshOverwrite verifies that a second refresh updates the timestamp.
func TestRecordBlocklistRefreshOverwrite(t *testing.T) {
	m := newTest(t)
	timeNow = func() time.Time { return time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { timeNow = time.Now })

	m.RecordBlocklistRefresh("bad_ips")
	timeNow = func() time.Time { return time.Date(2026, 6, 18, 13, 0, 0, 0, time.UTC) }
	m.RecordBlocklistRefresh("bad_ips")

	// Must reflect the later timestamp (gauge overwrites).
	if got := testutil.ToFloat64(m.blocklistLastRefresh.WithLabelValues("bad_ips")); got != float64(time.Date(2026, 6, 18, 13, 0, 0, 0, time.UTC).Unix()) {
		t.Errorf("overwritten timestamp = %v, want %v", got, time.Date(2026, 6, 18, 13, 0, 0, 0, time.UTC).Unix())
	}
}

// TestCleanupSourceLabels verifies that DeleteLabelValues removes stale source labels (C3).
func TestCleanupSourceLabels(t *testing.T) {
	m := newTest(t)
	m.RecordInputLine("site1", "api", "old_source", "file")
	m.RecordInputLine("site1", "api", "old_source", "file")

	// Verify counter exists before cleanup.
	if got := testutil.ToFloat64(m.inputLines.WithLabelValues("site1", "api", "old_source", "file")); got != 2 {
		t.Fatalf("before cleanup = %v, want 2", got)
	}

	// Cleanup and verify the time series is removed.
	m.CleanupSourceLabels("site1", "api", "old_source", "file")

	// After DeleteLabelValues, calling WithLabelValues creates a new series with zero value.
	if got := testutil.ToFloat64(m.inputLines.WithLabelValues("site1", "api", "old_source", "file")); got != 0 {
		t.Errorf("after cleanup = %v, want 0 (new zero series)", got)
	}
}

// TestCleanupSinkLabels verifies that DeleteLabelValues removes stale sink labels (C3).
func TestCleanupSinkLabels(t *testing.T) {
	m := newTest(t)
	m.RecordOutputEvent("site1", "api", "old_sink", "stdout")
	m.RecordOutputEvent("site1", "api", "old_sink", "stdout")
	m.RecordOutputDropped("site1", "api", "old_sink", ReasonBufferFull)

	// Verify counters exist before cleanup.
	if got := testutil.ToFloat64(m.outputEvents.WithLabelValues("site1", "api", "old_sink", "stdout")); got != 2 {
		t.Fatalf("outputEvents before cleanup = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.outputDropped.WithLabelValues("site1", "api", "old_sink", ReasonBufferFull)); got != 1 {
		t.Fatalf("outputDropped before cleanup = %v, want 1", got)
	}

	m.CleanupSinkLabels("site1", "api", "old_sink", "stdout")
	m.CleanupDroppedLabels("site1", "api", "old_sink", ReasonBufferFull)

	if got := testutil.ToFloat64(m.outputEvents.WithLabelValues("site1", "api", "old_sink", "stdout")); got != 0 {
		t.Errorf("outputEvents after cleanup = %v, want 0", got)
	}
	if got := testutil.ToFloat64(m.outputDropped.WithLabelValues("site1", "api", "old_sink", ReasonBufferFull)); got != 0 {
		t.Errorf("outputDropped after cleanup = %v, want 0", got)
	}
}

// TestCleanupBlocklistLabels verifies that blocklist gauge entries can be cleaned up (C3).
func TestCleanupBlocklistLabels(t *testing.T) {
	m := newTest(t)
	timeNow = func() time.Time { return time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC) }
	defer func() { timeNow = time.Now }()

	m.RecordBlocklistRefresh("temp_list")

	if got := testutil.ToFloat64(m.blocklistLastRefresh.WithLabelValues("temp_list")); got == 0 {
		t.Fatal("before cleanup should be non-zero")
	}

	m.CleanupBlocklistLabels("temp_list")

	if got := testutil.ToFloat64(m.blocklistLastRefresh.WithLabelValues("temp_list")); got != 0 {
		t.Errorf("after cleanup = %v, want 0", got)
	}
}

// TestReasonConstants verifies that reason constants have the expected values (C3).
func TestReasonConstants(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"ReasonBufferFull", ReasonBufferFull, "buffer_full"},
		{"ReasonWriteErr", ReasonWriteErr, "write_err"},
		{"ReasonShutdown", ReasonShutdown, "shutdown"},
		{"ReasonStale", ReasonStale, "stale"},
		{"ReasonUnknown", ReasonUnknown, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != tt.want {
				t.Errorf("%s = %q, want %q", tt.name, tt.value, tt.want)
			}
		})
	}
}

// TestLevelConstants verifies level constant values.
func TestLevelConstants(t *testing.T) {
	if LevelThreat != "THREAT" {
		t.Errorf("LevelThreat = %q, want THREAT", LevelThreat)
	}
	if LevelWarn != "WARN" {
		t.Errorf("LevelWarn = %q, want WARN", LevelWarn)
	}
}
