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

	"github.com/mr-addams/arxsentinel/internal/core/parser"
	"github.com/mr-addams/arxsentinel/internal/sys/config"
)

// pathBufSize — depth of the path ring buffer per IP.
// hardcoded: internal memory constraint, not a behavioral parameter.
// 64 paths is enough for the probe detector (triggers immediately) and
// the crawler detector (pattern visible within 5–10 requests).
const pathBufSize = 64

// ========================== IPState =================================================

// IPState — state of a single IP address.
//
// Fields are read by detectors via detector.IPView / detector.ScoreAccess —
// both interfaces are implemented by the methods below without explicit import of the detector package.
//
// Lifecycle:
//   created → first Update(entry) for this IP
//   active  → LastSeen is updated on every Update
//   deleted → GC when LastSeen < now-retention OR LRU eviction at max_tracked_ips
type IPState struct {
	IP        string
	FirstSeen time.Time
	LastSeen  time.Time

	TotalRequests int
	Requests404   int // for bruteforce ratio (Flow #6.1)

	// ── Path ring buffer ──────────────────────────────────────────────────────────
	// Stores the last pathBufSize request paths in chronological order.
	// pathPos = next write position; pathFull = buffer filled at least once.
	pathBuf  [pathBufSize]string
	pathPos  int
	pathFull bool

	// pathCache caches the result of RecentPaths() to avoid make+copy on every detector call.
	// pathDirty is set to true in Update() after writing to pathBuf; cleared in RecentPaths().
	// Safe without locks: pipeline is single-threaded, Update() and RecentPaths() never interleave.
	pathCache []string
	pathDirty bool

	// ── Sliding window rate counters ──────────────────────────────────────────────────
	// Two counters for the sliding window: avoids storing N thousands of timestamps.
	// Formula: approxRate = (prevCount*(1-elapsed/window) + currCount) / window.
	// Source: standard sliding window log counter algorithm.
	rateWindowStart time.Time
	rateCurrCount   int
	ratePrevCount   int

	// ── Score ─────────────────────────────────────────────────────────────────────────
	// Accumulated score with linear decay. Updated by scorer via SetScore.
	// Private fields: external access only through GetScore/GetScoreUpdatedAt/SetScore.
	score          int
	scoreUpdatedAt time.Time

	// LRU list element — for Tracker use only. Do not modify manually.
	lruElem *list.Element
}

// ++++++++++++++++++++++++++ Implementation of detector.IPView +++++++++++++++++++++++++++

func (s *IPState) GetIP() string           { return s.IP }
func (s *IPState) GetTotalRequests() int   { return s.TotalRequests }
func (s *IPState) GetRequests404() int     { return s.Requests404 }

// RecentPaths returns the most recent paths in chronological order (oldest → newest).
// The returned slice is owned by IPState — safe to read within a single pipeline tick
// (between two consecutive Update() calls). Pipeline is single-threaded, so Update()
// and RecentPaths() never interleave, and pathCache is not invalidated mid-read.
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
//
// Two-counter sliding window algorithm:
//   approx = prevCount*(1-elapsed/window) + currCount
//   rate = approx / window.Seconds()
//
// Accuracy ±10% compared to exact sliding window log.
// Non-blocking — called from scoring pipeline without acquiring the mutex.
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

func (s *IPState) GetScore() int               { return s.score }
func (s *IPState) GetScoreUpdatedAt() time.Time { return s.scoreUpdatedAt }
func (s *IPState) SetScore(score int, at time.Time) {
	s.score = score
	s.scoreUpdatedAt = at
}

// ========================== Tracker =================================================

// Tracker — thread-safe storage of IP states.
//
// LRU eviction: when maxIPs is exceeded, remove the least recently used IP.
// GC eviction: on a timer, remove IPs with LastSeen older than retention.
//
// Concurrent access:
//   - Main pipeline: Update + scorer.Evaluate in a single goroutine
//   - GC goroutine: RunGC in a separate goroutine
//   - Both paths acquire write lock → serialized
type Tracker struct {
	mu     sync.RWMutex
	states map[string]*IPState
	lru    *list.List // Front = most recently used, Back = LRU candidate

	maxIPs     int
	rateWindow time.Duration // from config.Detectors.Rate.Window — for sliding window
	retention  time.Duration // from config.Scoring.ObservationWindow — for GC

	logFn func(tag, msg, level string) // injected from main.go
}

// NewTracker creates a Tracker from config.
// logFn is passed from main.go — core/ does not import sys/utils directly.
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
//
// Thread-safe. Called from the main pipeline for each line.
// The returned *IPState implements detector.IPView and detector.ScoreAccess —
// can be passed directly to scorer.Evaluate without type assertion in main.go.
//
// THREAD SAFETY OF THE RETURNED *IPState:
//   IPState methods (GetScore, SetScore, RecentPaths, etc.) are called by the caller
//   WITHOUT acquiring the Tracker mutex — this is safe because:
//     1. Pipeline is single-threaded: Update + scorer.Evaluate execute sequentially
//        in a single main goroutine.
//     2. GC (RunGC) removes entries from the map but does not modify *IPState fields —
//        the caller's local pointer remains valid (Go GC won't collect the object
//        while there is a live reference).
//     3. GC will not delete an active IP: LastSeen is updated in Update, the retention
//        threshold has not been crossed yet.
//   This assumption must remain valid in Flow #4 when detectors start actively reading
//   *IPState. If writes from multiple goroutines are needed — add a separate mutex to IPState.
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
// Algorithm: two-counter sliding window.
// KNOWN LIMITATION: when gap ∈ (w, 2w) prevCount holds data from
// the previous window (before gap). ApproxRate assumes uniform distribution —
// bursty traffic may cause false positives (~1–1.5x).
// Acceptable for the rate detector: a false WARN is better than a missed attack.
// Algorithm is used in production rate limiters (Cloudflare, nginx).
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
type Stats struct {
	TrackedIPs    int   // current number of tracked IPs
	TotalRequests int64 // sum of TotalRequests across all IPs
	Suspicious    int   // IPs with Score > 0 (accumulated at least one point)
}

// GetStats returns a statistics snapshot under read lock.
// Do not call from the hot path — iterates over all IPs under RLock.
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
// Called from main.go in the case <-reloadCh block — between pipeline lines,
// so there is no concurrent access with Update (single-threaded pipeline).
// GC goroutine may read retention/rateWindow → write lock is required.
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
func (t *Tracker) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.states)
}

// Has returns true if the IP is tracked (thread-safe).
// Used in tests instead of direct access to tr.states — safe with t.Parallel().
func (t *Tracker) Has(ip string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	_, ok := t.states[ip]
	return ok
}

// ========================== GC ======================================================

// RunGC starts the background goroutine for garbage collecting inactive IPs.
//
// Removes IPs with LastSeen older than retention (= scoring.observation_window).
// interval comes from config.State.GCInterval — passed from main.go.
//
// Pattern from telegram-bot (patterns.md §2 GC):
//   ticker + ctx.Done() + logger via callback.
//
// Usage: go tracker.RunGC(ctx, time.Duration(cfg.State.GCInterval))
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
			deleted, remaining := t.runGC()
			if t.logFn != nil && deleted > 0 {
				t.logFn("GC", fmt.Sprintf("deleted %d inactive IPs, remaining %d", deleted, remaining), "info")
			}
		}
	}
}

// runGC executes a single garbage collection cycle.
// Removes IPs that have been inactive longer than retention.
// Returns (deleted, remaining) — both numbers captured under a single write lock,
// so the log "deleted N, remaining M" accurately describes the state after this cycle.
//
// threshold is computed inside the lock: Reconfigure() may update t.retention
// from the main goroutine while the GC goroutine has not yet acquired the mutex.
func (t *Tracker) runGC() (int, int) {
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
	return deleted, len(t.states)
}
