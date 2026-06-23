// ====== Module: pkg/sink/stdout — Tests ======
//   Unit tests for StdoutSink: JSON/fail2ban output, concurrent writes, formatter validation.
//
//   Phase 2.2 (Flow 083 / Task 2.2 / RESOLVED-Z12): the sink consumes generic
//   *plugin.Event and serializes via an injected Formatter; tests wrap the
//   fixture ThreatEvent in *plugin.Event{Payload: &ev} to match the contract.

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
		Modules:    []string{"probe", "rate"},
		Reason:     `probe:env:3,rate:142rps`,
	}
)

// wrapEvent превращает ThreatEvent в *plugin.Event — Phase 2.2 Gate A helper.
func wrapEvent(e plugin.ThreatEvent) *plugin.Event {
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
	sink, pr, pw, err := newTestStdoutSink(&format.JSONFormatter{})
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
	if m["ip"] != "1.2.3.4" {
		t.Errorf("want ip=1.2.3.4, got %v", m["ip"])
	}
}

func TestStdoutSink_WritesFailban(t *testing.T) {
	sink, pr, pw, err := newTestStdoutSink(&format.FailbanFormatter{})
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
	sink, pr, pw, err := newTestStdoutSink(&format.JSONFormatter{})
	if err != nil {
		t.Fatal(err)
	}

	const workers = 10
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e := plugin.ThreatEvent{
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
	sink, err := stdout.NewStdoutSink(&format.JSONFormatter{})
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
