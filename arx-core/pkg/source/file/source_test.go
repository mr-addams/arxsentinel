// ========================== pkg/source/file — tests ==========================================
//   Tests: ReadsLines, StopOnCtxCancel, ParseError, InvalidPath.

package file_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/mr-addams/arx-core/pkg/parser"
	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/mr-addams/arx-core/pkg/source/file"
)

const validLine = `1.2.3.4 - - [02/Apr/2026:00:26:49 +0000] "GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0" "1.2.3.4"` + "\n"

const invalidLine = "not a log line\n"

func combinedParser() parser.Parser { return &parser.CombinedParser{} }

func nopLog(_, _, _ string) {}

func TestFileSource_ReadsLines(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "access-*.log")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	f.Close()

	src, err := file.NewFileSource(path, combinedParser(), 5*time.Second, nopLog)
	if err != nil {
		t.Fatal(err)
	}

	out := make(chan *plugin.Event, 8)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	go func() {
		_ = src.Run(ctx, out)
	}()

	time.Sleep(100 * time.Millisecond)

	f2, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f2.WriteString(validLine + validLine)
	f2.Close()

	var got []*parser.LogEntry
	deadline := time.After(2 * time.Second)
loop:
	for {
		select {
		case ev := <-out:
			got = append(got, parser.UnwrapLogEntry(ev))
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

	src, err := file.NewFileSource(path, combinedParser(), 5*time.Second, nopLog)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan *plugin.Event, 8)

	done := make(chan error, 1)
	go func() {
		done <- src.Run(ctx, out)
	}()

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

	src, err := file.NewFileSource(path, combinedParser(), 5*time.Second, nopLog)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	out := make(chan *plugin.Event, 8)
	go func() { _ = src.Run(ctx, out) }()

	time.Sleep(100 * time.Millisecond)

	f2, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f2.WriteString(invalidLine + validLine)
	f2.Close()

	var got []*parser.LogEntry
	deadline := time.After(2 * time.Second)
loop:
	for {
		select {
		case ev := <-out:
			got = append(got, parser.UnwrapLogEntry(ev))
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

	time.Sleep(50 * time.Millisecond)
	stats := src.Stats()
	if stats.ParseErrors != 1 {
		t.Errorf("want ParseErrors=1, got %d", stats.ParseErrors)
	}
}

func TestFileSource_InvalidPath(t *testing.T) {
	_, err := file.NewFileSource("", combinedParser(), 5*time.Second, nopLog)
	if err == nil {
		t.Fatal("want error for empty path, got nil")
	}
}
