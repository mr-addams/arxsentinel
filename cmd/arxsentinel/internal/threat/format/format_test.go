//go:build ignore

// ========================== cmd/arxsentinel/internal/threat/format/format_test =====
//   Tests for ThreatEvent serialization in the product namespace.
//
//   Phase 2.2 (Flow 083 / RESOLVED-Q12): moved verbatim from
//   arx-core/pkg/sink/format/format_test.go. The tests assert the same
//   byte-level output as before, so existing Fail2Ban filters and JSON
//   fixtures keep matching after the contract generalisation.

package format_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mr-addams/arx-core/pkg/plugin"

	threatformat "github.com/mr-addams/arxsentinel/internal/threat/format"
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
	got := threatformat.FormatFailban(testEvent)

	want := `2026-04-05T14:33:12Z THREAT 1.2.3.4 score=85 modules=probe,bad_bot reason="probe:env:3,bad_bot:known"`
	if got != want {
		t.Errorf("FormatFailban:\ngot:  %q\nwant: %q", got, want)
	}
}

func TestFormatJSON_AllFields(t *testing.T) {
	e := testEvent
	e.RawLine = "raw log line"

	b, err := threatformat.FormatJSON(e)
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
	b, err := threatformat.FormatJSON(testEvent)
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

func TestFormatSentinelThreat(t *testing.T) {
	e := testEvent
	e.RawLine = ""

	b, err := threatformat.FormatSentinelThreat(e, "frontend")
	if err != nil {
		t.Fatal(err)
	}

	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	checks := map[string]any{
		"ts":     "2026-04-05T14:33:12Z",
		"ip":     "1.2.3.4",
		"score":  float64(85),
		"level":  "THREAT",
		"reason": "probe:env:3,bad_bot:known",
		"source": "frontend",
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
	b, err := threatformat.FormatJSON(testEvent)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"timestamp":"2026-04-05T14:33:12Z"`) {
		t.Errorf("timestamp not in RFC3339 UTC: %s", b)
	}
}

// ++++++++++++++++++++++++++ Formatter impl smoke tests ++++++++++++++++++++++++++++++++++

// TestFormatter_FormatThroughEnvelope гарантирует что Formatter impls извлекают
// payload правильно — пишем ThreatEvent в Envelope.Payload, вызываем Format,
// проверяем output. Phase 2.2 boundary check.
func TestFormatter_FormatThroughEnvelope(t *testing.T) {
	ev := &plugin.Event{
		Envelope: plugin.Envelope{
			Timestamp:  ts,
			Level:      "THREAT",
			Stream:     "frontend",
			Source:     "file:/var/log/nginx/access.log",
			SourceType: "file",
		},
		Payload: testEvent,
	}

	// JSONFormatter.
	jb, err := (&threatformat.JSONFormatter{}).Format(ev)
	if err != nil {
		t.Fatalf("JSONFormatter.Format: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(jb, &m); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if got := m["level"]; got != "THREAT" {
		t.Errorf("level: got %v, want THREAT", got)
	}

	// FailbanFormatter.
	fb, err := (&threatformat.FailbanFormatter{}).Format(ev)
	if err != nil {
		t.Fatalf("FailbanFormatter.Format: %v", err)
	}
	if !strings.Contains(string(fb), "score=85") {
		t.Errorf("expected failban line to contain score=85, got %q", string(fb))
	}

	// SentinelFormatter.
	sb, err := (&threatformat.SentinelFormatter{StreamName: "frontend"}).Format(ev)
	if err != nil {
		t.Fatalf("SentinelFormatter.Format: %v", err)
	}
	if !strings.Contains(string(sb), `"source":"frontend"`) {
		t.Errorf("expected sentinel threat line to contain source=frontend, got %q", string(sb))
	}

	// Negative: wrong payload type → error (fail-fast).
	bad := &plugin.Event{Payload: "not a ThreatEvent"}
	if _, err := (&threatformat.JSONFormatter{}).Format(bad); err == nil {
		t.Error("expected error for non-ThreatEvent payload, got nil")
	}
}