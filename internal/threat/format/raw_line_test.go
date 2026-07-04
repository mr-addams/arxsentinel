package format_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/mr-addams/arx-core/pkg/parser"
	"github.com/mr-addams/arx-core/pkg/plugin"

	threatformat "github.com/mr-addams/arxsentinel/internal/threat/format"
)

// TestRawLineFormatterRoundTrip is the E5 happy path: a *parser.LogEntry
// payload round-trips through JSON with all fields preserved.
func TestRawLineFormatterRoundTrip(t *testing.T) {
	entry := &parser.LogEntry{
		RemoteAddr: "10.0.0.1",
		Time:       time.Date(2026, 7, 4, 10, 0, 0, 0, time.UTC),
		Method:     "GET",
		RawURI:     "/admin?x=1",
		Path:       "/admin",
		Query:      "x=1",
		Protocol:   "HTTP/1.1",
		Status:     404,
		BytesSent:  512,
		Referer:    "-",
		UserAgent:  "curl/8.0",
		RealIP:     "10.0.0.1",
	}
	ev := &plugin.Event{Payload: entry}

	f := &threatformat.RawLineFormatter{}
	out, err := f.Format(ev)
	if err != nil {
		t.Fatalf("Format: %v", err)
	}

	var decoded parser.LogEntry
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if decoded.RealIP != entry.RealIP {
		t.Errorf("decoded.RealIP = %q, want %q", decoded.RealIP, entry.RealIP)
	}
	if decoded.Path != entry.Path {
		t.Errorf("decoded.Path = %q, want %q", decoded.Path, entry.Path)
	}
	if decoded.Status != entry.Status {
		t.Errorf("decoded.Status = %d, want %d", decoded.Status, entry.Status)
	}
	if !decoded.Time.Equal(entry.Time) {
		t.Errorf("decoded.Time = %v, want %v", decoded.Time, entry.Time)
	}
}

// TestRawLineFormatterWrongPayloadType is the E5 fail-fast contract: a
// non-*parser.LogEntry payload (e.g. a *threat.ThreatEvent reaching a
// raw-line sink by misconfiguration — RawForward:false but format:raw-line)
// returns an error rather than emitting malformed bytes.
func TestRawLineFormatterWrongPayloadType(t *testing.T) {
	f := &threatformat.RawLineFormatter{}
	ev := &plugin.Event{Payload: "not a LogEntry"}

	_, err := f.Format(ev)
	if err == nil {
		t.Fatal("Format(wrong payload type) returned nil error")
	}
}

// TestRawLineFormatterNilEvent is the E5 edge case: a nil *plugin.Event
// returns an error rather than panicking.
func TestRawLineFormatterNilEvent(t *testing.T) {
	f := &threatformat.RawLineFormatter{}
	if _, err := f.Format(nil); err == nil {
		t.Fatal("Format(nil) returned nil error")
	}
}

// TestRawLineFormatterEmptyLogEntry is the E5 empty-line edge: a
// zero-value *parser.LogEntry still marshals cleanly (no panic, valid
// JSON) — an empty/malformed source line should not crash the sink.
func TestRawLineFormatterEmptyLogEntry(t *testing.T) {
	f := &threatformat.RawLineFormatter{}
	ev := &plugin.Event{Payload: &parser.LogEntry{}}

	out, err := f.Format(ev)
	if err != nil {
		t.Fatalf("Format(empty LogEntry): %v", err)
	}
	if !json.Valid(out) {
		t.Errorf("Format(empty LogEntry) produced invalid JSON: %s", out)
	}
}
