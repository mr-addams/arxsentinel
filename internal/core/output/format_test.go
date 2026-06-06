// ========================== internal/core/output — format_test.go =========
//   Tests for OutputFormat: JSON, CSV, text formatting.

package output_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mr-addams/arxsentinel/internal/core/output"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

var (
	ts        = time.Date(2026, 4, 5, 14, 33, 12, 0, time.UTC)
	testEvent = plugin.ThreatEvent{
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
)

func TestFormatFailban(t *testing.T) {
	got := output.FormatFailban(testEvent)

	// Must match the format produced by FormatThreatLine (logger.go) —
	// verified byte-by-byte so Fail2Ban filter regex is never silently broken.
	want := `2026-04-05T14:33:12Z THREAT 1.2.3.4 score=85 modules=probe,bad_bot reason="probe:env:3,bad_bot:known"`
	if got != want {
		t.Errorf("FormatFailban:\ngot:  %q\nwant: %q", got, want)
	}
}

func TestFormatFailban_IdenticalToFormatThreatLine(t *testing.T) {
	// Guard: FormatFailban must produce the same output as the legacy FormatThreatLine
	// so Fail2Ban filters continue to work after the pipeline migration in Task 5.
	failban := output.FormatFailban(testEvent)
	legacy := output.FormatThreatLine(testEvent.IP, testEvent.Score, testEvent.Level, testEvent.Modules, testEvent.Reason)

	// Timestamps differ because FormatThreatLine uses time.Now() while FormatFailban
	// uses e.Timestamp. Compare everything after the timestamp prefix.
	failbanSuffix := strings.SplitN(failban, " ", 2)[1]
	legacySuffix := strings.SplitN(legacy, " ", 2)[1]
	if failbanSuffix != legacySuffix {
		t.Errorf("format mismatch with FormatThreatLine:\nfailban suffix: %q\nlegacy suffix:  %q", failbanSuffix, legacySuffix)
	}
}

func TestFormatJSON_AllFields(t *testing.T) {
	e := testEvent
	e.RawLine = "raw log line"

	b, err := output.FormatJSON(e)
	if err != nil {
		t.Fatal(err)
	}

	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	checks := map[string]any{
		"timestamp":   "2026-04-05T14:33:12Z",
		"level":       "THREAT",
		"stream":      "frontend",
		"source":      "file:/var/log/nginx/access.log",
		"source_type": "file",
		"ip":          "1.2.3.4",
		"score":       float64(85),
		"reason":      "probe:env:3,bad_bot:known",
		"raw_line":    "raw log line",
	}
	for key, want := range checks {
		got, ok := m[key]
		if !ok {
			t.Errorf("missing key %q", key)
			continue
		}
		if got != want {
			t.Errorf("key %q: got %v, want %v", key, got, want)
		}
	}

	// modules must be a JSON array with the right values.
	rawModules, ok := m["modules"]
	if !ok {
		t.Fatal("missing key modules")
	}
	modules, ok := rawModules.([]any)
	if !ok {
		t.Fatalf("modules must be array, got %T", rawModules)
	}
	if len(modules) != 2 || modules[0] != "probe" || modules[1] != "bad_bot" {
		t.Errorf("unexpected modules: %v", modules)
	}
}

func TestFormatJSON_NoRawLine(t *testing.T) {
	// RawLine == "" — the field must be absent from the JSON output (omitempty).
	b, err := output.FormatJSON(testEvent)
	if err != nil {
		t.Fatal(err)
	}

	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if _, exists := m["raw_line"]; exists {
		t.Error("raw_line must be absent when ThreatEvent.RawLine is empty")
	}
}

// ++++++++++++++++++++++++++ TestFormatSentinelThreat ++++++++++++++++++++++++++++++++++++++

// TestFormatSentinelThreat verifies the JSON structure and valid JSON output.
func TestFormatSentinelThreat(t *testing.T) {
	e := testEvent
	e.RawLine = "" // sentinel-threat format never includes raw_line

	b, err := output.FormatSentinelThreat(e, "frontend")
	if err != nil {
		t.Fatal(err)
	}

	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	checks := map[string]any{
		"ts":      "2026-04-05T14:33:12Z",
		"ip":      "1.2.3.4",
		"score":   float64(85),
		"level":   "THREAT",
		"reason":  "probe:env:3,bad_bot:known",
		"source":  "frontend",
	}
	for key, want := range checks {
		got, ok := m[key]
		if !ok {
			t.Errorf("missing key %q", key)
			continue
		}
		if got != want {
			t.Errorf("key %q: got %v, want %v", key, got, want)
		}
	}

	// modules must be a JSON array
	rawModules, ok := m["modules"]
	if !ok {
		t.Fatal("missing key modules")
	}
	modules, ok := rawModules.([]any)
	if !ok {
		t.Fatalf("modules must be array, got %T", rawModules)
	}
	if len(modules) != 2 || modules[0] != "probe" || modules[1] != "bad_bot" {
		t.Errorf("unexpected modules: %v", modules)
	}
}

func TestFormatJSON_TimestampRFC3339(t *testing.T) {
	b, err := output.FormatJSON(testEvent)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"timestamp":"2026-04-05T14:33:12Z"`) {
		t.Errorf("timestamp not in RFC3339 UTC: %s", b)
	}
}
