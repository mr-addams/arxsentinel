// ====== Module: pkg/sink/stdout — Tests ======
//   Unit tests for StdoutSink: JSON/fail2ban output, concurrent writes, formatter validation.
//
//   Gate B (Flow 083 / Task 3.3 / RESOLVED-D): the sink consumes generic
//   *plugin.Event and serializes via an injected Formatter; tests wrap the
//   fixture fakeThreatPayload in *plugin.Event{Payload: &ev} to match the
//   contract. The Formatter impls in pkg/sink/format accept the generic
//   event and know how to render their bytes; core tests do not import
//   the product threat.ThreatEvent.

package stdout_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/mr-addams/arx-core/pkg/sink/format"
	"github.com/mr-addams/arx-core/pkg/sink/stdout"
)

// fakeThreatPayload is a local test-only struct that mirrors the wire-shape
// of the product-owned threat.ThreatEvent. JSON encoding/decoding
// round-trips through this struct identically to the production payload.
type fakeThreatPayload struct {
	Timestamp  time.Time
	Level      string
	Stream     string
	Source     string
	SourceType string
	IP         string
	Score      int
	Modules    []string
	Reason     string
}

// testJSONFormatter is a minimal Formatter impl for the sink test — it
// JSON-encodes the payload struct as-is. Core tests cannot import the
// product threat-format package, so we wire our own stub that exercises
// the same code path (sink → formatter.Format → bytes → file).
type testJSONFormatter struct{}

func (testJSONFormatter) Format(ev *plugin.Event) ([]byte, error) {
	return json.Marshal(ev.Payload)
}

// testFailbanFormatter mimics the Fail2Ban line format the production
// FailbanFormatter produces — used by the sink test to verify the sink
// forwards formatted bytes to the writer unchanged.
type testFailbanFormatter struct{}

func (testFailbanFormatter) Format(ev *plugin.Event) ([]byte, error) {
	te, ok := ev.Payload.(*fakeThreatPayload)
	if !ok {
		return nil, nil
	}
	return []byte(time.Time{}.Format(time.RFC3339) +
		" " + te.Level + " " + te.IP), nil
}

// Compile-time guards: the stub formatters satisfy the Format interface.
var (
	_ format.Formatter = testJSONFormatter{}
	_ format.Formatter = testFailbanFormatter{}
)

var (
	ts        = time.Date(2026, 4, 5, 14, 33, 12, 0, time.UTC)
	testEvent = fakeThreatPayload{
		Timestamp:  ts,
		Level:      "THREAT",
		Stream:     "frontend",
		Source:     "file:/var/log/nginx/access.log",
		SourceType: "file",
		IP:         "1.2.3.4",
		Score:      85,
		Modules:    []string{"probe", "rate"},
		Reason:     `probe:env:3,rate:142rps`,
	}
)

// wrapEvent превращает test fixture в *plugin.Event — Phase 2.2/Gate B helper.
func wrapEvent(e fakeThreatPayload) *plugin.Event {
	return &plugin.Event{Envelope: plugin.Envelope{Stream: e.Stream}, Payload: &e}
}

func newTestStdoutSink(f format.Formatter) (*stdout.StdoutSink, *os.File, *os.File, error) {
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, nil, nil, err
	}
	sink, err := stdout.NewStdoutSinkWithWriter(pw, f)
	if err != nil {
		pr.Close()
		pw.Close()
		return nil, nil, nil, err
	}
	return sink, pr, pw, nil
}

func TestStdoutSink_WritesJSON(t *testing.T) {
	sink, pr, pw, err := newTestStdoutSink(testJSONFormatter{})
	if err != nil {
		t.Fatal(err)
	}

	if err := sink.Write(context.Background(), wrapEvent(testEvent)); err != nil {
		t.Fatalf("Write() error: %v", err)
	}
	pw.Close()

	var buf [4096]byte
	n, _ := pr.Read(buf[:])
	pr.Close()

	line := strings.TrimSpace(string(buf[:n]))
	if !strings.HasPrefix(line, "{") {
		t.Fatalf("expected JSON, got: %q", line)
	}

	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("invalid JSON: %v\nline: %q", err, line)
	}
	if m["IP"] != "1.2.3.4" {
		t.Errorf("want IP=1.2.3.4, got %v", m["IP"])
	}
}

func TestStdoutSink_WritesFailban(t *testing.T) {
	sink, pr, pw, err := newTestStdoutSink(testFailbanFormatter{})
	if err != nil {
		t.Fatal(err)
	}

	if err := sink.Write(context.Background(), wrapEvent(testEvent)); err != nil {
		t.Fatalf("Write() error: %v", err)
	}
	pw.Close()

	var buf [4096]byte
	n, _ := pr.Read(buf[:])
	pr.Close()

	line := strings.TrimSpace(string(buf[:n]))
	if !strings.Contains(line, "THREAT 1.2.3.4") {
		t.Errorf("unexpected output: %q", line)
	}
}

func TestStdoutSink_ConcurrentWrites(t *testing.T) {
	sink, pr, pw, err := newTestStdoutSink(testJSONFormatter{})
	if err != nil {
		t.Fatal(err)
	}

	const workers = 10
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e := fakeThreatPayload{
				Timestamp: testEvent.Timestamp,
				Level:     "WARN",
				IP:        "5.5.5.5",
				Score:     50,
				Modules:   []string{"rate"},
				Reason:    "rate:50rps",
			}
			_ = sink.Write(context.Background(), wrapEvent(e))
		}()
	}
	wg.Wait()
	pw.Close()
	pr.Close()

	stats := sink.Stats()
	if stats.EventsWritten != workers {
		t.Errorf("want EventsWritten=%d, got %d", workers, stats.EventsWritten)
	}
	if stats.Errors != 0 {
		t.Errorf("want Errors=0, got %d", stats.Errors)
	}
}

func TestStdoutSink_NilFormatter(t *testing.T) {
	// Phase 2.2: nil Formatter is a programmer error caught at New() time.
	_, err := stdout.NewStdoutSink(nil)
	if err == nil {
		t.Fatal("want error for nil formatter, got nil")
	}
}

func TestStdoutSink_Manifest(t *testing.T) {
	sink, err := stdout.NewStdoutSink(testJSONFormatter{})
	if err != nil {
		t.Fatal(err)
	}
	m := sink.Manifest()
	if m.PluginID != "stdout" {
		t.Errorf("want PluginID=stdout, got %q", m.PluginID)
	}
	if m.Role != "sink" {
		t.Errorf("want Role=sink, got %q", m.Role)
	}
}
