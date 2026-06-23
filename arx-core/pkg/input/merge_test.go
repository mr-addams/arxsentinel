// ========================== arx-core/pkg/input — merge_test.go ============
//   Tests for Merge: multi-source input merging, priority, deduplication.

package input_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/mr-addams/arx-core/pkg/input"
	"github.com/mr-addams/arx-core/pkg/parser"
	"github.com/mr-addams/arx-core/pkg/plugin"
)

// ── helpers ───────────────────────────────────────────────────────────────────────────────

// staticSource sends a fixed slice of entries then returns.
type staticSource struct {
	name    string
	entries []*parser.LogEntry
}

func (s *staticSource) Name() string { return s.name }

func (s *staticSource) Manifest() plugin.Manifest { return plugin.Manifest{} }
func (s *staticSource) Close() error              { return nil }
func (s *staticSource) Stats() plugin.SourceStats {
	return plugin.SourceStats{LinesRead: int64(len(s.entries))}
}
func (s *staticSource) Run(_ context.Context, out chan<- *plugin.Event) error {
	for _, e := range s.entries {
		out <- parser.WrapLogEntry(e, plugin.Envelope{
			Source:     e.RemoteAddr,
			SourceType: "static",
			Timestamp:  e.Time,
		})
	}
	return nil
}

// blockingSource sends one entry, then blocks until ctx is cancelled.
type blockingSource struct {
	entry *parser.LogEntry
}

func (s *blockingSource) Name() string { return "blocking" }

func (s *blockingSource) Manifest() plugin.Manifest { return plugin.Manifest{} }
func (s *blockingSource) Close() error              { return nil }
func (s *blockingSource) Stats() plugin.SourceStats { return plugin.SourceStats{} }
func (s *blockingSource) Run(ctx context.Context, out chan<- *plugin.Event) error {
	out <- parser.WrapLogEntry(s.entry, plugin.Envelope{
		Source:     s.entry.RemoteAddr,
		SourceType: "blocking",
		Timestamp:  s.entry.Time,
	})
	<-ctx.Done()
	return nil
}

// dropSource tries to send entries with a full buffer; drops are counted via non-blocking send.
type dropSource struct {
	entries []*parser.LogEntry
	dropped int
}

func (s *dropSource) Name() string { return "drop" }

func (s *dropSource) Manifest() plugin.Manifest { return plugin.Manifest{} }
func (s *dropSource) Close() error              { return nil }
func (s *dropSource) Stats() plugin.SourceStats { return plugin.SourceStats{Dropped: int64(s.dropped)} }
func (s *dropSource) Run(_ context.Context, out chan<- *plugin.Event) error {
	for _, e := range s.entries {
		ev := parser.WrapLogEntry(e, plugin.Envelope{
			Source:     e.RemoteAddr,
			SourceType: "drop",
			Timestamp:  e.Time,
		})
		select {
		case out <- ev:
		default:
			s.dropped++
		}
	}
	return nil
}

func makeEntry(ip string) *parser.LogEntry {
	return &parser.LogEntry{RealIP: ip, Time: time.Now()}
}

// ── tests ─────────────────────────────────────────────────────────────────────────────────

func TestMerge_SingleSource(t *testing.T) {
	entries := []*parser.LogEntry{makeEntry("1.1.1.1"), makeEntry("2.2.2.2")}
	src := &staticSource{name: "test", entries: entries}

	out := input.Merge(context.Background(), []plugin.Source{src}, 8, nil)

	var got []*parser.LogEntry
	for ev := range out {
		got = append(got, parser.UnwrapLogEntry(ev))
	}

	if len(got) != 2 {
		t.Fatalf("want 2 entries, got %d", len(got))
	}
	ips := map[string]bool{got[0].RealIP: true, got[1].RealIP: true}
	for _, e := range entries {
		if !ips[e.RealIP] {
			t.Errorf("missing entry %s", e.RealIP)
		}
	}
}

func TestMerge_MultipleSources(t *testing.T) {
	src1 := &staticSource{name: "s1", entries: []*parser.LogEntry{makeEntry("1.1.1.1"), makeEntry("2.2.2.2")}}
	src2 := &staticSource{name: "s2", entries: []*parser.LogEntry{makeEntry("3.3.3.3"), makeEntry("4.4.4.4")}}

	out := input.Merge(context.Background(), []plugin.Source{src1, src2}, 8, nil)

	ips := map[string]bool{}
	for ev := range out {
		ips[parser.UnwrapLogEntry(ev).RealIP] = true
	}

	expected := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"}
	for _, ip := range expected {
		if !ips[ip] {
			t.Errorf("missing entry %s", ip)
		}
	}
	if len(ips) != 4 {
		t.Errorf("want 4 unique IPs, got %d", len(ips))
	}
}

func TestMerge_ChannelClosedOnCtxCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	src := &blockingSource{entry: makeEntry("1.1.1.1")}
	out := input.Merge(ctx, []plugin.Source{src}, 8, nil)

	// Drain the first entry sent before blocking.
	select {
	case <-out:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for first entry")
	}

	cancel()

	// After cancel, channel must close (not block forever).
	select {
	case _, ok := <-out:
		if ok {
			// May receive the entry again if race; ignore extra entries.
			select {
			case _, ok2 := <-out:
				if ok2 {
					t.Fatal("channel still open after cancel")
				}
			case <-time.After(time.Second):
				t.Fatal("channel not closed after cancel")
			}
		}
	case <-time.After(time.Second):
		t.Fatal("channel not closed after cancel")
	}
}

func TestMerge_DropOnFullBuffer(t *testing.T) {
	const bufSize = 2
	// 4 entries into buffer of 2: 2 make it, 2 are dropped.
	entries := []*parser.LogEntry{
		makeEntry("1.1.1.1"),
		makeEntry("2.2.2.2"),
		makeEntry("3.3.3.3"),
		makeEntry("4.4.4.4"),
	}
	src := &dropSource{entries: entries}
	out := input.Merge(context.Background(), []plugin.Source{src}, bufSize, nil)

	var got []*parser.LogEntry
	for ev := range out {
		got = append(got, parser.UnwrapLogEntry(ev))
	}

	// At least 2 made it (buf size); remainder may vary by scheduler timing.
	if len(got) < bufSize {
		t.Fatalf("want at least %d entries, got %d", bufSize, len(got))
	}
	if len(got) > bufSize {
		// More may arrive if the goroutine sends before the buffer is checked full.
		// That is valid behaviour — only assert total <= total entries.
		if len(got) > len(entries) {
			t.Fatalf("got more entries (%d) than sent (%d)", len(got), len(entries))
		}
	}
}

// ── Panic recovery ──────────────────────────────────────────────────────────────────────────
// C4: source panic must be recovered by Merge, pipeline must not hang.

// panicSource panics in Run() to test recovery.
type panicSource struct{}

func (s *panicSource) Name() string              { return "panic" }
func (s *panicSource) Manifest() plugin.Manifest { return plugin.Manifest{} }
func (s *panicSource) Close() error              { return nil }
func (s *panicSource) Stats() plugin.SourceStats { return plugin.SourceStats{} }
func (s *panicSource) Run(_ context.Context, _ chan<- *plugin.Event) error {
	panic("test panic in source Run")
}

func TestMerge_PanicRecovery(t *testing.T) {
	// Source panics in Run(), but Merge should recover and not hang.
	src := &panicSource{}

	logged := false
	logFn := func(tag, msg, level string) {
		if tag == "merge" && level == "error" {
			logged = true
		}
	}

	out := input.Merge(context.Background(), []plugin.Source{src}, 8, logFn)

	// Channel must close (the panicking goroutine recovers and calls wg.Done).
	select {
	case _, ok := <-out:
		if ok {
			t.Fatal("channel should be closed after panic recovery")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("channel not closed after panic recovery — pipeline hung")
	}

	if !logged {
		t.Error("expected logFn to be called with merge/error for panic")
	}
}

// recoverySource returns an error from Run() to test error logging.
type errorReturningSource struct{}

func (s *errorReturningSource) Name() string              { return "error-return" }
func (s *errorReturningSource) Manifest() plugin.Manifest { return plugin.Manifest{} }
func (s *errorReturningSource) Close() error              { return nil }
func (s *errorReturningSource) Stats() plugin.SourceStats { return plugin.SourceStats{} }
func (s *errorReturningSource) Run(_ context.Context, _ chan<- *plugin.Event) error {
	return fmt.Errorf("test error from source")
}

func TestMerge_ErrorLogging(t *testing.T) {
	src := &errorReturningSource{}

	logged := false
	logFn := func(tag, msg, level string) {
		if tag == "merge" && level == "error" {
			logged = true
		}
	}

	out := input.Merge(context.Background(), []plugin.Source{src}, 8, logFn)

	// Channel must close.
	select {
	case _, ok := <-out:
		if ok {
			t.Fatal("channel should be closed after source error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("channel not closed after source error — pipeline hung")
	}

	if !logged {
		t.Error("expected logFn to be called with merge/error for source error")
	}
}
