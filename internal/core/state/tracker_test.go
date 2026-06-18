// ========================== Tests state/tracker =========================================

package state

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/mr-addams/arxsentinel/internal/core/parser"
	"github.com/mr-addams/arxsentinel/internal/sys/config"
)

// ========================== Helper functions ===================================

// makeConfig returns a minimal config for tests.
func makeConfig(maxIPs int) config.Config {
	cfg := config.Config{}
	cfg.State.MaxTrackedIPs = maxIPs
	cfg.State.GCInterval = config.Duration(60 * time.Second)
	cfg.Scoring.ObservationWindow = config.Duration(300 * time.Second)
	cfg.Detectors.Rate.Window = config.Duration(60 * time.Second)
	return cfg
}

// makeEntry creates a LogEntry with the given IP, method, path, and status.
func makeEntry(ip, method, path string, status int) *parser.LogEntry {
	return &parser.LogEntry{
		RealIP: ip,
		Method: method,
		Path:   path,
		Status: status,
		Time:   time.Now(),
	}
}

// ========================== Tests Update ==============================================

// TestTrackerUpdateNewIP verifies that a new IP is created with correct initial counters.
func TestTrackerUpdateNewIP(t *testing.T) {
	tr := NewTracker(makeConfig(1000), nil)

	st := tr.Update(makeEntry("1.2.3.4", "GET", "/index.html", 200))

	if st == nil {
		t.Fatal("Update returned nil")
	}
	if st.IP != "1.2.3.4" {
		t.Errorf("IP: expected 1.2.3.4, got %s", st.IP)
	}
	if st.TotalRequests != 1 {
		t.Errorf("TotalRequests: expected 1, got %d", st.TotalRequests)
	}
	if tr.Len() != 1 {
		t.Errorf("Len: expected 1, got %d", tr.Len())
	}
}

// TestTrackerUpdateSameIP verifies counter accumulation on repeated requests.
func TestTrackerUpdateSameIP(t *testing.T) {
	tr := NewTracker(makeConfig(1000), nil)
	ip := "1.2.3.4"

	tr.Update(makeEntry(ip, "GET", "/page1", 200))
	tr.Update(makeEntry(ip, "GET", "/page2", 404))
	tr.Update(makeEntry(ip, "GET", "/page3", 404))

	st := tr.Update(makeEntry(ip, "GET", "/page4", 200))

	if st.TotalRequests != 4 {
		t.Errorf("TotalRequests: expected 4, got %d", st.TotalRequests)
	}
	if st.Requests404 != 2 {
		t.Errorf("Requests404: expected 2, got %d", st.Requests404)
	}
	if tr.Len() != 1 {
		t.Errorf("Len: must remain 1, got %d", tr.Len())
	}
}

// TestTrackerMultipleIPs verifies independence of states for different IPs.
func TestTrackerMultipleIPs(t *testing.T) {
	tr := NewTracker(makeConfig(1000), nil)

	tr.Update(makeEntry("1.1.1.1", "GET", "/", 200))
	tr.Update(makeEntry("2.2.2.2", "GET", "/", 404))
	tr.Update(makeEntry("1.1.1.1", "GET", "/about", 200))

	if tr.Len() != 2 {
		t.Errorf("Len: expected 2, got %d", tr.Len())
	}
	st1 := tr.Update(makeEntry("1.1.1.1", "GET", "/contact", 200))
	if st1.TotalRequests != 3 {
		t.Errorf("1.1.1.1 TotalRequests: expected 3, got %d", st1.TotalRequests)
	}
	st2 := tr.Update(makeEntry("2.2.2.2", "GET", "/login", 200))
	if st2.TotalRequests != 2 {
		t.Errorf("2.2.2.2 TotalRequests: expected 2, got %d", st2.TotalRequests)
	}
	if st2.Requests404 != 1 {
		t.Errorf("2.2.2.2 Requests404: expected 1, got %d", st2.Requests404)
	}
}

// ========================== Ring buffer tests ============================

// TestRingBufferOrder verifies chronological order of paths before the buffer is full.
func TestRingBufferOrder(t *testing.T) {
	tr := NewTracker(makeConfig(1000), nil)
	ip := "1.2.3.4"

	paths := []string{"/a", "/b", "/c", "/d", "/e"}
	for _, p := range paths {
		tr.Update(makeEntry(ip, "GET", p, 200))
	}

	st := tr.Update(makeEntry(ip, "GET", "/f", 200))
	recent := st.RecentPaths()

	// Last 6 paths must be in the correct order
	expected := append(paths, "/f")
	if len(recent) != len(expected) {
		t.Fatalf("RecentPaths length: expected %d, got %d", len(expected), len(recent))
	}
	for i, p := range expected {
		if recent[i] != p {
			t.Errorf("RecentPaths[%d]: expected %q, got %q", i, p, recent[i])
		}
	}
}

// TestRingBufferWrap verifies correct ring buffer operation after it wraps around.
func TestRingBufferWrap(t *testing.T) {
	tr := NewTracker(makeConfig(1000), nil)
	ip := "1.2.3.4"

	// Fill the buffer + a few extra paths on top
	overCount := 5
	total := pathBufSize + overCount

	for i := 0; i < total; i++ {
		tr.Update(makeEntry(ip, "GET", fmt.Sprintf("/path/%d", i), 200))
	}

	st := tr.Update(makeEntry(ip, "GET", "/final", 200))
	recent := st.RecentPaths()

	// Buffer must contain exactly pathBufSize elements
	if len(recent) != pathBufSize {
		t.Fatalf("RecentPaths length after wrap: expected %d, got %d", pathBufSize, len(recent))
	}

	// Last element — most recent path
	if recent[pathBufSize-1] != "/final" {
		t.Errorf("last element: expected /final, got %q", recent[pathBufSize-1])
	}

	// First overCount+1 paths (0..overCount) are evicted; first valid is /path/(overCount+1).
	// Total records: pathBufSize+overCount (loop) + 1 (/final) = pathBufSize+overCount+1.
	// pathPos = (pathBufSize+overCount+1) % pathBufSize = overCount+1.
	expectedFirst := fmt.Sprintf("/path/%d", overCount+1)
	if recent[0] != expectedFirst {
		t.Errorf("first element: expected %q, got %q", expectedFirst, recent[0])
	}
}

// ========================== GC eviction tests =========================================

// TestGCEviction verifies that GC removes inactive IPs past their retention window.
func TestGCEviction(t *testing.T) {
	tr := NewTracker(makeConfig(1000), nil)

	// Add an IP with LastSeen in the past (older than retention)
	tr.Update(makeEntry("old.ip", "GET", "/", 200))
	// Mutation under write lock — safe when t.Parallel() is added in the future
	tr.mu.Lock()
	tr.states["old.ip"].LastSeen = time.Now().Add(-400 * time.Second) // older than ObservationWindow(300s)
	tr.mu.Unlock()

	// Add a fresh IP
	tr.Update(makeEntry("new.ip", "GET", "/", 200))

	deleted, _ := tr.runGC()

	if deleted != 1 {
		t.Errorf("GC: expected 1 deleted entry, got %d", deleted)
	}
	if tr.Len() != 1 {
		t.Errorf("Len after GC: expected 1, got %d", tr.Len())
	}
	// Verify that old.ip is the one deleted
	if tr.Has("old.ip") {
		t.Error("old.ip must be deleted by GC")
	}
	if !tr.Has("new.ip") {
		t.Error("new.ip must remain after GC")
	}
}

// TestGCNoEviction verifies that GC does not touch active IPs.
func TestGCNoEviction(t *testing.T) {
	tr := NewTracker(makeConfig(1000), nil)

	tr.Update(makeEntry("1.1.1.1", "GET", "/", 200))
	tr.Update(makeEntry("2.2.2.2", "GET", "/", 200))

	deleted, _ := tr.runGC()

	if deleted != 0 {
		t.Errorf("GC: expected 0 deletions, got %d", deleted)
	}
	if tr.Len() != 2 {
		t.Errorf("Len after GC: expected 2, got %d", tr.Len())
	}
}

// TestRunGCContext verifies that RunGC shuts down cleanly on context cancellation.
func TestRunGCContext(t *testing.T) {
	tr := NewTracker(makeConfig(1000), nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		tr.RunGC(ctx, 10*time.Millisecond)
		close(done)
	}()

	cancel()

	select {
	case <-done:
		// success
	case <-time.After(500 * time.Millisecond):
		t.Fatal("RunGC did not exit after context cancellation")
	}
}

// ========================== LRU eviction tests ========================================

// TestLRUEviction verifies that when maxIPs is exceeded the least recently used IP is evicted.
func TestLRUEviction(t *testing.T) {
	maxIPs := 3
	tr := NewTracker(makeConfig(maxIPs), nil)

	// Add maxIPs+1 distinct IPs
	tr.Update(makeEntry("a.a.a.a", "GET", "/", 200)) // LRU candidate (oldest)
	tr.Update(makeEntry("b.b.b.b", "GET", "/", 200))
	tr.Update(makeEntry("c.c.c.c", "GET", "/", 200))
	tr.Update(makeEntry("d.d.d.d", "GET", "/", 200)) // 4th — must evict a.a.a.a

	if tr.Len() != maxIPs {
		t.Errorf("Len after eviction: expected %d, got %d", maxIPs, tr.Len())
	}
	if tr.Has("a.a.a.a") {
		t.Error("a.a.a.a must be evicted as LRU")
	}
}

// TestLRURecentAccessProtection verifies that a recent access to an IP protects it from eviction.
func TestLRURecentAccessProtection(t *testing.T) {
	maxIPs := 2
	tr := NewTracker(makeConfig(maxIPs), nil)

	tr.Update(makeEntry("a.a.a.a", "GET", "/", 200)) // first
	tr.Update(makeEntry("b.b.b.b", "GET", "/", 200)) // second

	// Access a.a.a.a — move it to the head of the LRU
	tr.Update(makeEntry("a.a.a.a", "GET", "/page", 200))

	// Add a third — must evict b.b.b.b (LRU)
	tr.Update(makeEntry("c.c.c.c", "GET", "/", 200))

	if tr.Len() != maxIPs {
		t.Errorf("Len: expected %d, got %d", maxIPs, tr.Len())
	}
	if tr.Has("b.b.b.b") {
		t.Error("b.b.b.b must be evicted as LRU")
	}
	if !tr.Has("a.a.a.a") {
		t.Error("a.a.a.a must remain — it was recently updated")
	}
}

// ========================== Sliding window rate tests =================================

// TestRateCounterGapInOneToTwoWindows verifies correct window shift when gap ∈ (w, 2w).
// This is the boundary case of the two-counter algorithm: prevCount is carried from the previous window.
// The test documents a known limitation (possible false positive with burst + silence + burst).
func TestRateCounterGapInOneToTwoWindows(t *testing.T) {
	cfg := makeConfig(1000)
	tr := NewTracker(cfg, nil)
	ip := "1.2.3.4"

	w := time.Duration(cfg.Detectors.Rate.Window)

	// First request — initialize the window
	e1 := makeEntry(ip, "GET", "/", 200)
	e1.Time = time.Now()
	tr.mu.Lock()
	st := &IPState{IP: ip, FirstSeen: e1.Time}
	tr.states[ip] = st
	st.lruElem = tr.lru.PushFront(st)
	tr.updateRateLocked(st, e1.Time)
	tr.mu.Unlock()

	if st.rateCurrCount != 1 {
		t.Fatalf("after first request currCount=%d, expected 1", st.rateCurrCount)
	}

	// Gap = 1.5*w — falls into the elapsed ∈ (w, 2w) branch
	t1 := e1.Time.Add(w + w/2)
	tr.mu.Lock()
	tr.updateRateLocked(st, t1)
	tr.mu.Unlock()

	// After shift: prevCount=1 (old currCount), currCount=1, rateWindowStart advanced
	if st.ratePrevCount != 1 {
		t.Errorf("after gap=1.5w: prevCount=%d, expected 1", st.ratePrevCount)
	}
	if st.rateCurrCount != 1 {
		t.Errorf("after gap=1.5w: currCount=%d, expected 1", st.rateCurrCount)
	}
	if st.rateWindowStart.IsZero() {
		t.Error("rateWindowStart must not be zero after shift")
	}

	// Next request immediately after — must fall into default (elapsed < w)
	t2 := t1.Add(time.Second)
	tr.mu.Lock()
	tr.updateRateLocked(st, t2)
	tr.mu.Unlock()

	if st.rateCurrCount != 2 {
		t.Errorf("after request 1s later: currCount=%d, expected 2", st.rateCurrCount)
	}
}

// ========================== Benchmarks =================================================

// BenchmarkTrackerUpdate measures the throughput of Tracker.Update with a single goroutine.
// Creates a realistic LogEntry and cycles over 1000 distinct IPs to avoid excessive branching
// and approach real-world usage patterns.
func BenchmarkTrackerUpdate(b *testing.B) {
	tr := NewTracker(makeConfig(10000), nil)

	// Pre-generate entries with distinct IPs — realistic load: many unique visitors
	entries := make([]*parser.LogEntry, 1000)
	for i := range entries {
		entries[i] = &parser.LogEntry{
			RealIP: fmt.Sprintf("10.0.%d.%d", i/256, i%256),
			Method: "GET",
			Path:   "/index.html",
			Status: 200,
			Time:   time.Now(),
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tr.Update(entries[i%len(entries)])
	}
}

// ========================== ScoreAccess tests =========================================

// TestScoreAccess verifies the detector.ScoreAccess implementation via IPState.
func TestScoreAccess(t *testing.T) {
	tr := NewTracker(makeConfig(1000), nil)
	st := tr.Update(makeEntry("1.2.3.4", "GET", "/", 200))

	if st.GetScore() != 0 {
		t.Errorf("initial score: expected 0, got %d", st.GetScore())
	}
	if !st.GetScoreUpdatedAt().IsZero() {
		t.Error("ScoreUpdatedAt must be zero on initialization")
	}

	now := time.Now()
	st.SetScore(42, now)

	if st.GetScore() != 42 {
		t.Errorf("score after SetScore: expected 42, got %d", st.GetScore())
	}
	if !st.GetScoreUpdatedAt().Equal(now) {
		t.Error("ScoreUpdatedAt was not updated")
	}
}
