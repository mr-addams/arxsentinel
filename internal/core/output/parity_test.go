// ========================== internal/core/output — parity_test.go ============================
//   Parity guard: FormatFailban (internal/threat/format) must
//   produce byte-identical output to FormatThreatLine (logger.go) for Fail2Ban
//   filter compatibility.
//
//   This test lives in internal/core/output (not in internal/threat/format)
//   because ADR-002 forbids pkg->internal imports even in test files, and the
//   product-side FormatThreatLine (in this package) is the legacy reference
//   for the wire format. internal->product is allowed.
//
//   Gate B (Flow 083 / Task 3.3): FormatFailban moved to product
//   (internal/threat/format); this test now imports it from
//   the new location. The byte-level invariant is preserved.

package output_test

import (
	"strings"
	"testing"
	"time"

	threatformat "github.com/mr-addams/arxsentinel/internal/threat/format"
	"github.com/mr-addams/arxsentinel/internal/core/output"
	"github.com/mr-addams/arxsentinel/internal/threat"
)

func TestFormatFailban_IdenticalToFormatThreatLine(t *testing.T) {
	ts := time.Date(2026, 4, 5, 14, 33, 12, 0, time.UTC)
	testEvent := threat.ThreatEvent{
		Timestamp:  ts,
		Level:      "THREAT",
		Stream:     "frontend",
		Source:     "file:/var/log/nginx/access.log",
		SourceType: "file",
		IP:         "1.2.3.4",
		Score:      85,
		Modules:    []string{"probe", "bad_bot"},
		Reason:     "probe:env:3,bad_bot:known",
	}

	failban := threatformat.FormatFailban(testEvent)
	legacy := output.FormatThreatLine(testEvent.IP, testEvent.Score, testEvent.Level, testEvent.Modules, testEvent.Reason)

	// Timestamps differ because FormatThreatLine uses time.Now() while FormatFailban
	// uses e.Timestamp. Compare everything after the timestamp prefix.
	failbanSuffix := strings.SplitN(failban, " ", 2)[1]
	legacySuffix := strings.SplitN(legacy, " ", 2)[1]
	if failbanSuffix != legacySuffix {
		t.Errorf("format mismatch with FormatThreatLine:\nfailban suffix: %q\nlegacy suffix:  %q", failbanSuffix, legacySuffix)
	}
}
