package input_test

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/mr-addams/arxsentinel/internal/core/input"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

// injectReader creates a StdinSource with a custom reader for testing.
// StdinSource.r is package-private — we use the exported test helper.
func newTestStdinSource(r io.Reader) *input.StdinSource {
	return input.NewStdinSourceWithReader(r, combinedParser(), nopLog)
}

func TestStdinSource_ReadsLines(t *testing.T) {
	data := strings.NewReader(validLine + validLine)
	src := newTestStdinSource(data)

	out := make(chan *plugin.LogEntry, 8)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := src.Run(ctx, out)
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}

	close(out)
	var got []*plugin.LogEntry
	for e := range out {
		got = append(got, e)
	}

	if len(got) != 2 {
		t.Fatalf("want 2 entries, got %d", len(got))
	}
}

func TestStdinSource_StopOnEOF(t *testing.T) {
	// Empty reader immediately returns EOF.
	src := newTestStdinSource(strings.NewReader(""))
	out := make(chan *plugin.LogEntry, 8)

	done := make(chan error, 1)
	go func() {
		done <- src.Run(context.Background(), out)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run() returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run() did not return on EOF")
	}
}

func TestStdinSource_StopOnCtxCancel(t *testing.T) {
	// Pipe that never closes — Run should exit on ctx cancel.
	pr, pw := io.Pipe()
	defer pw.Close()

	src := newTestStdinSource(pr)
	out := make(chan *plugin.LogEntry, 8)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- src.Run(ctx, out)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run() returned error after cancel: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run() did not return after ctx cancel")
	}
}

func TestStdinSource_ParseError(t *testing.T) {
	data := strings.NewReader(invalidLine + validLine)
	src := newTestStdinSource(data)

	out := make(chan *plugin.LogEntry, 8)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_ = src.Run(ctx, out)
	close(out)

	var got []*plugin.LogEntry
	for e := range out {
		got = append(got, e)
	}

	if len(got) != 1 {
		t.Fatalf("want 1 valid entry, got %d", len(got))
	}
	stats := src.Stats()
	if stats.ParseErrors != 1 {
		t.Errorf("want ParseErrors=1, got %d", stats.ParseErrors)
	}
}
