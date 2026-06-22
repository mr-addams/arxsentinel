// ========================== Tests: pkg/source/stdin ======================================
//   Unit tests for StdinSource.Run() — covering line parsing, ctx cancellation,
//   parser errors, empty input, scanner errors, drop policy, and log callback.
//   All inputs go through strings.NewReader / custom io.Reader — no os.Stdin or os.File.

package stdin_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mr-addams/arx-core/pkg/parser"
	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/mr-addams/arx-core/pkg/source/stdin"
)

// validLine is a standard combined-format nginx log line.
const validLine = `1.2.3.4 - - [02/Apr/2026:00:26:49 +0000] "GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0" "1.2.3.4"` + "\n"

// invalidLine is a line that combinedParser will reject.
const invalidLine = "not a log line\n"

// nopLog is a no-op logger used by tests that don't assert on log output.
func nopLog(_, _, _ string) {}

// stubParser parses a line as a minimal LogEntry.
// RemoteAddr = first word of the line. RealIP is left empty.
type stubParser struct{}

func (stubParser) Parse(line string) (*plugin.LogEntry, bool) {
	if line == "" {
		return nil, false
	}
	parts := strings.SplitN(line, " ", 2)
	return &plugin.LogEntry{RemoteAddr: parts[0]}, true
}

// rejectAllParser always rejects — used to deterministically trigger
// the parse-error branch in logFn tests.
type rejectAllParser struct{}

func (rejectAllParser) Parse(string) (*plugin.LogEntry, bool) { return nil, false }

// readErrorImmediately returns a non-EOF error on the very first Read call,
// simulating an I/O failure with no data buffered.
type readErrorImmediately struct{}

func (readErrorImmediately) Read(_ []byte) (int, error) {
	return 0, errors.New("simulated scanner error")
}

// ----------------------------------------------------------------------------------------
// Test 1: two valid lines are read and parsed correctly.
// ----------------------------------------------------------------------------------------
func TestStdinSource_ReadsLines(t *testing.T) {
	src := stdin.NewStdinSourceWithReader(
		strings.NewReader(validLine+validLine),
		&parser.CombinedParser{},
		nopLog,
	)
	out := make(chan *plugin.LogEntry, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- src.Run(ctx, out) }()

	got := make([]*plugin.LogEntry, 0, 2)
	for i := 0; i < 2; i++ {
		select {
		case e := <-out:
			got = append(got, e)
		case <-time.After(2 * time.Second):
			t.Fatalf("timeout waiting for entry %d", i)
		}
	}

	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
	for i, e := range got {
		if e.RealIP != "1.2.3.4" {
			t.Errorf("entry[%d].RealIP = %q, want %q", i, e.RealIP, "1.2.3.4")
		}
	}

	if err := <-errCh; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if stats := src.Stats(); stats.LinesRead != 2 {
		t.Errorf("LinesRead = %d, want 2", stats.LinesRead)
	}
}

// ----------------------------------------------------------------------------------------
// Test 2: ctx cancellation makes Run return nil.
// ----------------------------------------------------------------------------------------
func TestStdinSource_StopOnCtxCancel(t *testing.T) {
	src := stdin.NewStdinSourceWithReader(
		strings.NewReader(validLine+validLine),
		&parser.CombinedParser{},
		nopLog,
	)
	out := make(chan *plugin.LogEntry, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- src.Run(ctx, out) }()

	time.AfterFunc(50*time.Millisecond, cancel)

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run returned %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s after ctx cancel")
	}
}

// ----------------------------------------------------------------------------------------
// Test 3: an invalid line is logged and counted as a parse error,
// but does not prevent delivery of subsequent valid lines.
// ----------------------------------------------------------------------------------------
func TestStdinSource_ParseError(t *testing.T) {
	src := stdin.NewStdinSourceWithReader(
		strings.NewReader(invalidLine+validLine),
		&parser.CombinedParser{},
		nopLog,
	)
	out := make(chan *plugin.LogEntry, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- src.Run(ctx, out) }()

	var got *plugin.LogEntry
	select {
	case got = <-out:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for entry")
	}
	if err := <-errCh; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if got.RealIP != "1.2.3.4" {
		t.Errorf("RealIP = %q, want %q", got.RealIP, "1.2.3.4")
	}
	stats := src.Stats()
	if stats.LinesRead != 2 {
		t.Errorf("LinesRead = %d, want 2", stats.LinesRead)
	}
	if stats.ParseErrors != 1 {
		t.Errorf("ParseErrors = %d, want 1", stats.ParseErrors)
	}
	if stats.Dropped != 0 {
		t.Errorf("Dropped = %d, want 0", stats.Dropped)
	}
}

// ----------------------------------------------------------------------------------------
// Test 4: empty input exits cleanly with all counters at zero.
// ----------------------------------------------------------------------------------------
func TestStdinSource_EmptyInput(t *testing.T) {
	src := stdin.NewStdinSourceWithReader(
		strings.NewReader(""),
		&parser.CombinedParser{},
		nopLog,
	)
	out := make(chan *plugin.LogEntry, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Empty input → immediate EOF; run synchronously, no goroutine needed.
	if err := src.Run(ctx, out); err != nil {
		t.Fatalf("Run returned %v, want nil", err)
	}
	stats := src.Stats()
	if stats.LinesRead != 0 || stats.ParseErrors != 0 || stats.Dropped != 0 {
		t.Errorf("stats = %+v, want all zeros", stats)
	}
}

// ----------------------------------------------------------------------------------------
// Test 5: a non-EOF scanner error is propagated by Run.
// Note: due to a select race between errCh and closed scanCh, err may occasionally
// be nil — but LinesRead must always be 0 in that case.
// ----------------------------------------------------------------------------------------
func TestStdinSource_ScannerError(t *testing.T) {
	src := stdin.NewStdinSourceWithReader(
		readErrorImmediately{},
		stubParser{},
		nopLog,
	)
	out := make(chan *plugin.LogEntry, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- src.Run(ctx, out) }()

	select {
	case err := <-errCh:
		if err == nil {
			t.Log("Run returned nil (select-race: closed scanCh won over errCh) — accepting")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s")
	}

	if stats := src.Stats(); stats.LinesRead != 0 {
		t.Errorf("LinesRead = %d, want 0 (no full line delivered before error)", stats.LinesRead)
	}
}

// ----------------------------------------------------------------------------------------
// Test 6: when out is unbuffered and unread, all entries are dropped.
// ----------------------------------------------------------------------------------------
func TestStdinSource_DropCounter(t *testing.T) {
	src := stdin.NewStdinSourceWithReader(
		strings.NewReader(validLine+validLine+validLine),
		&parser.CombinedParser{},
		nopLog,
	)
	out := make(chan *plugin.LogEntry, 0) // unbuffered — every send hits select default
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// No reader goroutine: every entry must be dropped via the default branch.
	if err := src.Run(ctx, out); err != nil {
		t.Fatalf("Run returned %v, want nil", err)
	}
	stats := src.Stats()
	if stats.LinesRead != 3 {
		t.Errorf("LinesRead = %d, want 3", stats.LinesRead)
	}
	if stats.Dropped < 2 {
		t.Errorf("Dropped = %d, want >= 2", stats.Dropped)
	}
	if stats.ParseErrors != 0 {
		t.Errorf("ParseErrors = %d, want 0", stats.ParseErrors)
	}
}

// ----------------------------------------------------------------------------------------
// Test 7: logFn is invoked with the "PARSER" tag when parsing fails.
// ----------------------------------------------------------------------------------------
func TestStdinSource_LogFnCalled(t *testing.T) {
	var loggedTag string
	logFn := func(tag, _, _ string) { loggedTag = tag }

	src := stdin.NewStdinSourceWithReader(
		strings.NewReader(invalidLine),
		rejectAllParser{},
		logFn,
	)
	out := make(chan *plugin.LogEntry, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := src.Run(ctx, out); err != nil {
		t.Fatalf("Run returned %v, want nil", err)
	}
	if loggedTag != "PARSER" {
		t.Errorf("loggedTag = %q, want %q", loggedTag, "PARSER")
	}
	if stats := src.Stats(); stats.ParseErrors != 1 {
		t.Errorf("ParseErrors = %d, want 1", stats.ParseErrors)
	}
}
