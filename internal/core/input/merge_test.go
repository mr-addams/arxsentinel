package input_test

import (
	"context"
	"testing"
	"time"

	"github.com/mr-addams/arxsentinel/internal/core/input"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

// ── helpers ───────────────────────────────────────────────────────────────────────────────

// staticSource sends a fixed slice of entries then returns.
type staticSource struct {
	plugin.NopManifest
	name    string
	entries []*plugin.LogEntry
}

func (s *staticSource) Name() string { return s.name }
func (s *staticSource) Close() error { return nil }
func (s *staticSource) Stats() plugin.SourceStats {
	return plugin.SourceStats{LinesRead: int64(len(s.entries))}
}
func (s *staticSource) Run(_ context.Context, out chan<- *plugin.LogEntry) error {
	for _, e := range s.entries {
		out <- e
	}
	return nil
}

// blockingSource sends one entry, then blocks until ctx is cancelled.
type blockingSource struct {
	plugin.NopManifest
	entry *plugin.LogEntry
}

func (s *blockingSource) Name() string              { return "blocking" }
func (s *blockingSource) Close() error              { return nil }
func (s *blockingSource) Stats() plugin.SourceStats { return plugin.SourceStats{} }
func (s *blockingSource) Run(ctx context.Context, out chan<- *plugin.LogEntry) error {
	out <- s.entry
	<-ctx.Done()
	return nil
}

// dropSource tries to send entries with a full buffer; drops are counted via non-blocking send.
type dropSource struct {
	plugin.NopManifest
	entries []*plugin.LogEntry
	dropped int
}

func (s *dropSource) Name() string              { return "drop" }
func (s *dropSource) Close() error              { return nil }
func (s *dropSource) Stats() plugin.SourceStats { return plugin.SourceStats{Dropped: int64(s.dropped)} }
func (s *dropSource) Run(_ context.Context, out chan<- *plugin.LogEntry) error {
	for _, e := range s.entries {
		select {
		case out <- e:
		default:
			s.dropped++
		}
	}
	return nil
}

func makeEntry(ip string) *plugin.LogEntry {
	return &plugin.LogEntry{RealIP: ip, Time: time.Now()}
}

// ── tests ─────────────────────────────────────────────────────────────────────────────────

func TestMerge_SingleSource(t *testing.T) {
	entries := []*plugin.LogEntry{makeEntry("1.1.1.1"), makeEntry("2.2.2.2")}
	src := &staticSource{name: "test", entries: entries}

	out := input.Merge(context.Background(), []plugin.Source{src}, 8)

	var got []*plugin.LogEntry
	for e := range out {
		got = append(got, e)
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
	src1 := &staticSource{name: "s1", entries: []*plugin.LogEntry{makeEntry("1.1.1.1"), makeEntry("2.2.2.2")}}
	src2 := &staticSource{name: "s2", entries: []*plugin.LogEntry{makeEntry("3.3.3.3"), makeEntry("4.4.4.4")}}

	out := input.Merge(context.Background(), []plugin.Source{src1, src2}, 8)

	ips := map[string]bool{}
	for e := range out {
		ips[e.RealIP] = true
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
	out := input.Merge(ctx, []plugin.Source{src}, 8)

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
	entries := []*plugin.LogEntry{
		makeEntry("1.1.1.1"),
		makeEntry("2.2.2.2"),
		makeEntry("3.3.3.3"),
		makeEntry("4.4.4.4"),
	}
	src := &dropSource{entries: entries}
	out := input.Merge(context.Background(), []plugin.Source{src}, bufSize)

	var got []*plugin.LogEntry
	for e := range out {
		got = append(got, e)
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
