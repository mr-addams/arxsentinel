// ========================== Module state/tracker ========================================
//   In-memory storage of state per IP address.
//   Foundation for all detectors — they read state through the detector.IPView interface.
//
//   WHAT IS HERE:
//     - IPState — state of a single IP: counters, ring buffer of paths,
//       sliding-window rate, accumulated score
//     - Tracker — thread-safe storage with LRU eviction at max_tracked_ips
//     - GC — background goroutine cleaning up inactive IPs on a timer (Task 2.2)
//
//   WHAT IS NOT HERE:
//     - Path classification (page/asset) — done by detectors themselves (Flow #4)
//     - Detection logic and scoring — core/detector, core/scorer
//
//   IMPLEMENTS INTERFACES:
//     *IPState → detector.IPView (state read by detectors)
//     *IPState → detector.ScoreAccess (score read/write by scorer)
//     Explicit import of detector/ is not needed — Go duck typing.
//
//   THREAD SAFETY:
//     Update() and gc() are protected by write lock.
//     RunGC() runs in a separate goroutine, operates via ticker.
//     Caller after Update() holds *IPState — GC will not delete an active IP
//     (LastSeen is updated, retention threshold not crossed).
//
//   MEMORY (estimate for max_tracked_ips=100k):
//     IPState ≈ 1.2 KB (struct) + paths ≈ 64×20B = 1.3 KB → ~260 MB for 100k IPs.
//     Acceptable for a security daemon. If memory is tight — reduce pathBufSize.

package state

import (
	"container/list"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/mr-addams/arxsentinel/internal/sys/config"
	"github.com/mr-addams/arx-core/pkg/parser"
)

// pathBufSize — depth of the path ring buffer per IP.
// hardcoded: internal memory constraint, not a behavioral parameter.
// 64 paths is enough for the probe detector (triggers immediately) and
// the crawler detector (pattern visible within 5–10 requests).
const pathBufSize = 64

// ========================== IPState =================================================

// IPState — state of a single IP address.
//
// YAML: (computed, not stored) — no direct config mapping. Consumer: all detectors.
//
// Lifecycle:
//
//	created → first Update(entry) for this IP
//	active  → LastSeen is updated on every Update
//	deleted → GC when LastSeen < now-retention OR LRU eviction at max_tracked_ips
type IPState struct {
	IP        string    // IP address from LogEntry.RealIP. Consumer: all detectors.
	FirstSeen time.Time // First request timestamp. Consumer: metrics, logging.
	LastSeen  time.Time // Last request timestamp, updated on every Update. Consumer: GC, detectors.

	TotalRequests int // Internal — total request counter. Consumer: metrics, rate detector.
	Requests404   int // Internal — 404 count for bruteforce ratio (Flow #6.1). Consumer: to be added.

	// ── Path ring buffer ──────────────────────────────────────────────────────────
	pathBuf  [pathBufSize]string // Internal — ring buffer, last pathBufSize paths. Consumer: probe detector, crawler detector.
	pathPos  int                 // Internal — next write position in ring buffer. Consumer: Update, RecentPaths.
	pathFull bool                // Internal — true when buffer filled at least once (pathPos wrapped). Consumer: RecentPaths.

	// pathCache caches the result of RecentPaths() to avoid make+copy on every detector call.
	// pathDirty is set to true in Update() after writing to pathBuf; cleared in RecentPaths().
	// Safe without locks: pipeline is single-threaded, Update() and RecentPaths() never interleave.
	pathCache []string // Internal — cached RecentPaths result. Consumer: RecentPaths.
	pathDirty bool     // Internal — true when pathBuf written but cache not rebuilt. Consumer: RecentPaths.

	// ── Sliding window rate counters ──────────────────────────────────────────────────
	rateWindowStart time.Time // Internal — start of current rate counting window. Consumer: ApproxRate, updateRateLocked.
	rateCurrCount   int       // Internal — requests in current window. Consumer: ApproxRate, updateRateLocked.
	ratePrevCount   int       // Internal — requests in previous window. Consumer: ApproxRate, updateRateLocked.

	// ── Score ─────────────────────────────────────────────────────────────────────────
	score          int       // Internal — accumulated score with linear decay. Consumer: scorer (via ScoreAccess).
	scoreUpdatedAt time.Time // Internal — last score update timestamp. Consumer: scorer (via ScoreAccess).

	// LRU list element — for Tracker use only. Do not modify manually.
	lruElem *list.Element // Internal — linked list element for LRU eviction. Consumer: Tracker.updateRateLocked, evictLRULocked.
}

// ++++++++++++++++++++++++++ Implementation of detector.IPView +++++++++++++++++++++++++++

func (s *IPState) GetIP() string         { return s.IP }
func (s *IPState) GetTotalRequests() int { return s.TotalRequests }
func (s *IPState) GetRequests404() int   { return s.Requests404 }

// RecentPaths returns the most recent paths in chronological order (oldest → newest).
// Returns cached slice — caller does not own the returned []string.
//
// Called from: detectors (probe, crawler) via IPView.
// Non-blocking: pipeline is single-threaded.
func (s *IPState) RecentPaths() []string {
	if !s.pathDirty {
		return s.pathCache
	}
	// Rebuild cache from ring buffer
	var result []string
	if !s.pathFull {
		result = make([]string, s.pathPos)
		copy(result, s.pathBuf[:s.pathPos])
	} else {
		// Buffer full: pathPos points to the oldest element (next to be overwritten)
		result = make([]string, pathBufSize)
		n := copy(result, s.pathBuf[s.pathPos:])
		copy(result[n:], s.pathBuf[:s.pathPos])
	}
	s.pathCache = result
	s.pathDirty = false
	return result
}

// ApproxRate returns the approximate request rate per second over the given window.
// Two-counter sliding window algorithm.
//
// Called from: rate detector via IPView.
// Non-blocking.
func (s *IPState) ApproxRate(window time.Duration) float64 {
	if window <= 0 || s.rateWindowStart.IsZero() {
		return 0
	}
	now := time.Now()
	elapsed := now.Sub(s.rateWindowStart)
	windowSec := window.Seconds()

	if elapsed >= 2*window {
		// Both counting windows are fully stale
		return 0
	}
	if elapsed >= window {
		// Current window ended; prevCount — data from the previous window
		overshot := elapsed - window
		fraction := float64(overshot) / float64(window)
		approx := float64(s.rateCurrCount) * (1 - fraction)
		return approx / windowSec
	}
	// Standard case: within the current window
	fraction := float64(elapsed) / float64(window)
	approx := float64(s.ratePrevCount)*(1-fraction) + float64(s.rateCurrCount)
	return approx / windowSec
}

// ++++++++++++++++++++++++++ Implementation of detector.ScoreAccess +++++++++++++++++++++

func (s *IPState) GetScore() int                { return s.score }
func (s *IPState) GetScoreUpdatedAt() time.Time { return s.scoreUpdatedAt }
func (s *IPState) SetScore(score int, at time.Time) {
	s.score = score
	s.scoreUpdatedAt = at
}

// ========================== Tracker =================================================

// Tracker — thread-safe storage of IP states with LRU eviction.
//
// YAML: state.max_tracked_ips, state.gc_interval, detectors.rate.window, scoring.observation_window.
// Consumer: pipeline (main.go), detectors (via IPView/ScoreAccess).
type Tracker struct {
	mu     sync.RWMutex
	states map[string]*IPState // Internal — IP address to IPState map. Consumer: Update, GetStats, Len, Has.
	lru    *list.List          // Internal — LRU list, front=most recent, back=LRU candidate. Consumer: Update, evictLRULocked.

	maxIPs     int           // YAML: state.max_tracked_ips, default 100000 — max tracked IPs before LRU eviction. Consumer: Update.
	rateWindow time.Duration // YAML: detectors.rate.window, default 60s — sliding window for rate counting. Consumer: updateRateLocked, ApproxRate.
	retention  time.Duration // YAML: scoring.observation_window — GC retention threshold. Consumer: runGC.

	logFn func(tag, msg, level string) // Internal — debug/info logger from main.go. Consumer: Update, RunGC, evictLRULocked.
}

// NewTracker creates a Tracker from config.
//
// Called from: cmd/arxsentinel.main (pipeline setup).
// Non-blocking.
func NewTracker(cfg config.Config, logFn func(tag, msg, level string)) *Tracker {
	rw := time.Duration(cfg.Detectors.Rate.Window)
	if rw <= 0 {
		// Fallback here, not in updateRateLocked — avoid polluting hot path under write lock
		rw = 60 * time.Second
	}
	return &Tracker{
		states:     make(map[string]*IPState),
		lru:        list.New(),
		maxIPs:     cfg.State.MaxTrackedIPs,
		rateWindow: rw,
		retention:  time.Duration(cfg.Scoring.ObservationWindow),
		logFn:      logFn,
	}
}

// Update updates the IP state from a log entry and returns a pointer to IPState.
// Thread-safe. Called from the main pipeline for each line.
//
// Returns: *IPState implementing detector.IPView and detector.ScoreAccess.
//
// Called from: pipeline (main.go process loop).
// Blocking: acquires write lock.
func (t *Tracker) Update(entry *parser.LogEntry) *IPState {
	t.mu.Lock()
	defer t.mu.Unlock()

	st, exists := t.states[entry.RealIP]
	if !exists {
		// Eviction before adding: otherwise the map momentarily holds maxIPs+1 entries.
		// With maxIPs=1 the previous code kept 2 IPs in memory instead of 1.
		if len(t.states) >= t.maxIPs {
			t.evictLRULocked()
		}
		st = &IPState{
			IP:        entry.RealIP,
			FirstSeen: entry.Time,
		}
		t.states[entry.RealIP] = st
		st.lruElem = t.lru.PushFront(st)
	} else {
		// IP is active — move to the front of LRU
		t.lru.MoveToFront(st.lruElem)
	}

	// ── Update counters ───────────────────────────────────────────────────────────
	st.LastSeen = entry.Time
	st.TotalRequests++

	if entry.Status == 404 {
		st.Requests404++
	}

	// ── Path ring buffer ─────────────────────────────────────────────────────────
	st.pathBuf[st.pathPos] = entry.Path
	st.pathPos = (st.pathPos + 1) % pathBufSize
	if !st.pathFull && st.pathPos == 0 {
		// pathPos wrapped to 0 — buffer filled for the first time
		st.pathFull = true
	}
	st.pathDirty = true

	// ── Sliding window rate counter ───────────────────────────────────────────────────
	t.updateRateLocked(st, entry.Time)

	return st
}

// updateRateLocked updates sliding window rate counters.
// Called only under write lock from Update.
//
// Internal — no config mapping. Consumer: Update.
func (t *Tracker) updateRateLocked(st *IPState, reqTime time.Time) {
	w := t.rateWindow // always > 0 — fallback set in NewTracker

	if st.rateWindowStart.IsZero() {
		// First request from this IP — initialize window
		st.rateWindowStart = reqTime
		st.rateCurrCount = 1
		return
	}

	elapsed := reqTime.Sub(st.rateWindowStart)
	switch {
	case elapsed >= 2*w:
		// Both windows stale — start fresh
		st.rateWindowStart = reqTime
		st.rateCurrCount = 1
		st.ratePrevCount = 0
	case elapsed >= w:
		// Current window ended — shift.
		// rateWindowStart.Add(w): new window starts exactly w after the previous one,
		// not from reqTime — otherwise we lose part of elapsed for the next request.
		st.ratePrevCount = st.rateCurrCount
		st.rateCurrCount = 1
		st.rateWindowStart = st.rateWindowStart.Add(w)
	default:
		st.rateCurrCount++
	}
}

// evictLRULocked removes the least recently used IP (tail of the LRU list).
// Called only under write lock from Update.
//
// Internal — no config mapping. Consumer: Update.
func (t *Tracker) evictLRULocked() {
	oldest := t.lru.Back()
	if oldest == nil {
		return
	}
	st := oldest.Value.(*IPState)
	delete(t.states, st.IP)
	t.lru.Remove(oldest)
	if t.logFn != nil {
		t.logFn("GC", fmt.Sprintf("[GC] LRU eviction: %s (requests=%d)", st.IP, st.TotalRequests), "debug")
	}
}

// ========================== Statistics ==================================================

// Stats — snapshot of tracker state for periodic logging.
//
// Internal — not in config. Consumer: metrics loop (main.go).
type Stats struct {
	TrackedIPs    int   // Current number of tracked IPs. Consumer: metrics, logging.
	TotalRequests int64 // Sum of TotalRequests across all IPs. Consumer: metrics, logging.
	Suspicious    int   // IPs with Score > 0 (accumulated at least one point). Consumer: metrics.
}

// GetStats returns a statistics snapshot under read lock.
// Do not call from the hot path — iterates over all IPs under RLock.
//
// Called from: metrics loop (main.go).
// Non-blocking: read lock only.
func (t *Tracker) GetStats() Stats {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var s Stats
	s.TrackedIPs = len(t.states)
	for _, st := range t.states {
		s.TotalRequests += int64(st.TotalRequests)
		if st.GetScore() > 0 {
			s.Suspicious++
		}
	}
	return s
}

// Reconfigure applies new config parameters after SIGHUP.
// GC goroutine may read retention/rateWindow → write lock is required.
//
// Called from: SIGHUP handler (main.go).
// Blocking: write lock.
func (t *Tracker) Reconfigure(cfg config.Config) {
	rw := time.Duration(cfg.Detectors.Rate.Window)
	if rw <= 0 {
		rw = 60 * time.Second
	}
	t.mu.Lock()
	t.retention = time.Duration(cfg.Scoring.ObservationWindow)
	t.rateWindow = rw
	t.mu.Unlock()
}

// Len returns the number of tracked IPs (thread-safe).
//
// Called from: metrics, tests.
// Non-blocking: read lock only.
func (t *Tracker) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.states)
}

// Has returns true if the IP is tracked (thread-safe).
// Used in tests instead of direct access to tr.states — safe with t.Parallel().
//
// Called from: tests.
// Non-blocking: read lock only.
func (t *Tracker) Has(ip string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	_, ok := t.states[ip]
	return ok
}

// GetState returns the IPState for the given IP, or nil if not tracked.
// Read-only lookup — does not create a new entry.
// Used by WAF ScoreFunc to apply score deltas from rule hits.
//
// Called from: WAF ScoreFunc closure (processor_security.go).
// Non-blocking: read lock only.
func (t *Tracker) GetState(ip string) *IPState {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.states[ip]
}

// ========================== GC ======================================================

// RunGC starts the background goroutine for garbage collecting inactive IPs.
// Removes IPs with LastSeen older than retention (= scoring.observation_window).
//
// Pattern: ticker + ctx.Done() + logger via callback (telegram-bot patterns.md §2 GC).
//
// Called from: cmd/arxsentinel.main (go tracker.RunGC).
// Non-blocking: runs in separate goroutine.
func (t *Tracker) RunGC(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	if t.logFn != nil {
		t.logFn("GC", fmt.Sprintf("garbage collector started (interval=%v, retention=%v)", interval, t.retention), "info")
	}

	for {
		select {
		case <-ctx.Done():
			if t.logFn != nil {
				t.logFn("GC", "garbage collector stopped", "info")
			}
			return
		case <-ticker.C:
			startedAt := time.Now().UTC()
			deleted, remaining, d := t.runGC()
			if t.logFn != nil && deleted > 0 {
				t.logFn("GC", fmt.Sprintf("deleted %d inactive IPs, remaining %d (started_at=%s, duration=%v)", deleted, remaining, startedAt.Format(time.RFC3339), d), "info")
			}
		}
	}
}

// runGC executes a single garbage collection cycle.
// Returns (deleted, remaining, duration) under a single write lock.
//
// Called from: RunGC (GC goroutine).
// Blocking: write lock.
func (t *Tracker) runGC() (int, int, time.Duration) {
	start := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()

	threshold := time.Now().Add(-t.retention)

	deleted := 0
	for ip, st := range t.states {
		if st.LastSeen.Before(threshold) {
			if st.lruElem != nil {
				t.lru.Remove(st.lruElem)
			}
			delete(t.states, ip)
			deleted++
		}
	}
	return deleted, len(t.states), time.Since(start)
}
