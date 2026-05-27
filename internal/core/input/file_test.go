package input_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/mr-addams/arxsentinel/internal/core/input"
	"github.com/mr-addams/arxsentinel/internal/core/parser"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

// ── helpers ───────────────────────────────────────────────────────────────────────────────

// validLine is a well-formed combined+real_ip nginx access log line.
const validLine = `1.2.3.4 - - [02/Apr/2026:00:26:49 +0000] "GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0" "1.2.3.4"` + "\n"

// invalidLine triggers a ParseError.
const invalidLine = "not a log line\n"

// combinedParser wraps CombinedParser for convenience.
func combinedParser() parser.Parser { return &parser.CombinedParser{} }

// nopLog discards log output in tests.
func nopLog(_, _, _ string) {}

// ── FileSource tests ──────────────────────────────────────────────────────────────────────

func TestFileSource_ReadsLines(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "access-*.log")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	f.Close()

	src, err := input.NewFileSource(path, combinedParser(), 5*time.Second, nopLog)
	if err != nil {
		t.Fatal(err)
	}

	out := make(chan *plugin.LogEntry, 8)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	go func() {
		_ = src.Run(ctx, out)
	}()

	// Write lines after a short delay to give TailReader time to open and watch the file.
	time.Sleep(100 * time.Millisecond)

	f2, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f2.WriteString(validLine + validLine)
	f2.Close()

	// Wait for entries to arrive.
	var got []*plugin.LogEntry
	deadline := time.After(2 * time.Second)
loop:
	for {
		select {
		case e := <-out:
			got = append(got, e)
			if len(got) == 2 {
				break loop
			}
		case <-deadline:
			break loop
		}
	}

	if len(got) != 2 {
		t.Fatalf("want 2 entries, got %d", len(got))
	}
	for _, e := range got {
		if e.RealIP != "1.2.3.4" {
			t.Errorf("unexpected IP %q", e.RealIP)
		}
	}
}

func TestFileSource_StopOnCtxCancel(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "access-*.log")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	f.Close()

	src, err := input.NewFileSource(path, combinedParser(), 5*time.Second, nopLog)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan *plugin.LogEntry, 8)

	done := make(chan error, 1)
	go func() {
		done <- src.Run(ctx, out)
	}()

	// Give TailReader time to start.
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run() returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run() did not return after ctx cancel")
	}
}

func TestFileSource_ParseError(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "access-*.log")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	f.Close()

	src, err := input.NewFileSource(path, combinedParser(), 5*time.Second, nopLog)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	out := make(chan *plugin.LogEntry, 8)
	go func() { _ = src.Run(ctx, out) }()

	time.Sleep(100 * time.Millisecond)

	// Write one invalid + one valid line.
	f2, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f2.WriteString(invalidLine + validLine)
	f2.Close()

	// Only one valid entry should arrive; parse error is counted, not forwarded.
	var got []*plugin.LogEntry
	deadline := time.After(2 * time.Second)
loop:
	for {
		select {
		case e := <-out:
			got = append(got, e)
			if len(got) == 1 {
				break loop
			}
		case <-deadline:
			break loop
		}
	}

	if len(got) != 1 {
		t.Fatalf("want 1 valid entry, got %d", len(got))
	}

	// Allow a brief moment for the counter to settle.
	time.Sleep(50 * time.Millisecond)
	stats := src.Stats()
	if stats.ParseErrors != 1 {
		t.Errorf("want ParseErrors=1, got %d", stats.ParseErrors)
	}
}

func TestFileSource_InvalidPath(t *testing.T) {
	// Empty path must be rejected at construction time, not at Run().
	_, err := input.NewFileSource("", combinedParser(), 5*time.Second, nopLog)
	if err == nil {
		t.Fatal("want error for empty path, got nil")
	}
}
