package output_test

import (
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/mr-addams/arxsentinel/internal/core/output"
)

func TestFileSink_WritesFailban(t *testing.T) {
	path := t.TempDir() + "/threats.log"
	sink, err := output.NewFileSink(path, "fail2ban")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	if err := sink.Write(testEvent); err != nil {
		t.Fatalf("Write() error: %v", err)
	}
	_ = sink.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(data))
	wantSuffix := `THREAT 1.2.3.4 score=85 modules=probe,bad_bot reason="probe:env:3,bad_bot:known"`
	if !strings.HasSuffix(line, wantSuffix) {
		t.Errorf("unexpected line:\n  got:  %q\n  want suffix: %q", line, wantSuffix)
	}
}

func TestFileSink_WritesJSON(t *testing.T) {
	path := t.TempDir() + "/threats.json"
	sink, err := output.NewFileSink(path, "json")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	if err := sink.Write(testEvent); err != nil {
		t.Fatalf("Write() error: %v", err)
	}
	_ = sink.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := strings.TrimSpace(string(data))
	if !strings.HasPrefix(s, "{") || !strings.HasSuffix(s, "}") {
		t.Errorf("want JSON object, got: %q", s)
	}
	if !strings.Contains(s, `"ip":"1.2.3.4"`) {
		t.Errorf("JSON missing ip field: %q", s)
	}
}

func TestFileSink_Reload(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/threats.log"

	sink, err := output.NewFileSink(path, "fail2ban")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	// Write before reload.
	if err := sink.Write(testEvent); err != nil {
		t.Fatalf("Write before reload: %v", err)
	}

	// Simulate logrotate: rename the current file.
	rotated := path + ".1"
	if err := os.Rename(path, rotated); err != nil {
		t.Fatal(err)
	}

	// Reload must reopen the file (creating a new one at the original path).
	if err := sink.Reload(); err != nil {
		t.Fatalf("Reload() error: %v", err)
	}

	// Write after reload — must go to the new file.
	if err := sink.Write(testEvent); err != nil {
		t.Fatalf("Write after reload: %v", err)
	}
	_ = sink.Close()

	newData, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(newData) == 0 {
		t.Error("new file is empty after reload + write")
	}
}

func TestFileSink_InvalidFormat(t *testing.T) {
	_, err := output.NewFileSink(t.TempDir()+"/f.log", "unknown")
	if err == nil {
		t.Fatal("want error for unknown format, got nil")
	}
}

func TestFileSink_EmptyPath(t *testing.T) {
	_, err := output.NewFileSink("", "fail2ban")
	if err == nil {
		t.Fatal("want error for empty path, got nil")
	}
}

func TestFileSink_ConcurrentWrites(t *testing.T) {
	path := t.TempDir() + "/threats.log"
	sink, err := output.NewFileSink(path, "fail2ban")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	const workers = 10
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = sink.Write(testEvent)
		}()
	}
	wg.Wait()

	stats := sink.Stats()
	if stats.EventsWritten != workers {
		t.Errorf("want EventsWritten=%d, got %d", workers, stats.EventsWritten)
	}
	if stats.Errors != 0 {
		t.Errorf("want Errors=0, got %d", stats.Errors)
	}
}

func TestFileSink_Stats(t *testing.T) {
	path := t.TempDir() + "/threats.log"
	sink, err := output.NewFileSink(path, "fail2ban")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	_ = sink.Write(testEvent)
	_ = sink.Write(testEvent)

	stats := sink.Stats()
	if stats.EventsWritten != 2 {
		t.Errorf("want EventsWritten=2, got %d", stats.EventsWritten)
	}
	if stats.Errors != 0 {
		t.Errorf("want Errors=0, got %d", stats.Errors)
	}
}
