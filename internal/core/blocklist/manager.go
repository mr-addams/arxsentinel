// ========================== blocklist/manager ==========================================
//   Manager is the sole owner of all blocklist patterns, refresh goroutines,
//   and the optional bbolt database. Detectors call Match() — they never fetch
//   or store patterns themselves.
//
//   WHAT IS HERE:
//     Config / ListConfig / SourceConfig  — configuration structs
//     Manager       — singleton per application; created once in main()
//     NewManager    — creates Manager and starts per-list refresh goroutines
//     Update        — SIGHUP: replaces goroutines with new config, same *Manager pointer
//     Match         — thread-safe O(text_len) lookup via Aho-Corasick
//     Close         — cancels all goroutines; bbolt closed if open
//
//   GOROUTINE LIFECYCLE (per list):
//     startList() starts one goroutine per ListConfig.
//     Goroutine: load bbolt cache → fetch from network → ticker refresh.
//     Update() cancels all per-list goroutines and starts new ones.
//     Close() cancels all per-list goroutines.
//
//   THREAD SAFETY:
//     Manager.mu (RWMutex) protects the lists map.
//     listState.mu (RWMutex) protects the matcher inside each list.
//     Match() holds Manager.mu.RLock + listState.mu.RLock — safe for concurrent use.
//
//   BBOLT:
//     One DB file. One bucket per list name. Key "patterns" → newline-joined strings.
//     If storage path is empty (""), bbolt is not used (in-memory only).
//
//   Implemented: Flow #025, Task 2.

package blocklist

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rrethy/ahocorasick"
	bolt "go.etcd.io/bbolt"

	"github.com/mr-addams/arxsentinel/internal/sys/utils"
)

// fetchSizeLimit caps the response body — protects against memory exhaustion
// if an upstream source sends an unreasonably large response.
const fetchSizeLimit = 10 << 20 // 10 MB

// boltPatternsKey is the bbolt key inside each list's bucket.
var boltPatternsKey = []byte("patterns")

// ── Config ────────────────────────────────────────────────────────────────────────────

// SourceConfig describes one upstream URL and its parse format.
type SourceConfig struct {
	URL    string `yaml:"url"`
	Format string `yaml:"format"` // "plain_text" or "nginx_map"
}

// ListConfig describes one named blocklist: refresh cadence and one or more sources.
// Enabled defaults to true when omitted from YAML (zero value false is overridden by
// manager.NewManager — lists without an explicit enabled:false are treated as active).
type ListConfig struct {
	Name            string         `yaml:"name"`
	Enabled         *bool          `yaml:"enabled"` // nil = default true; explicit false = skip list
	RefreshInterval Duration       `yaml:"refresh_interval"`
	Sources         []SourceConfig `yaml:"sources"`
}

// Config is the top-level blocklist configuration embedded in the application config.
type Config struct {
	Storage string       `yaml:"storage"` // "" = in-memory only; path = bbolt file
	Lists   []ListConfig `yaml:"lists"`
}

// Duration is a time.Duration that unmarshals from YAML strings like "24h", "30m".
// Reuses the same type used by config.Duration — replicated here to keep the blocklist
// package self-contained (no import cycle with sys/config).
type Duration time.Duration

func (d *Duration) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(dur)
	return nil
}

// ── listState ─────────────────────────────────────────────────────────────────────────

// listState holds the live Aho-Corasick automaton and the per-list goroutine cancel.
type listState struct {
	mu      sync.RWMutex
	matcher *ahocorasick.Matcher // nil until first successful load
	cancel  context.CancelFunc
}

func (s *listState) setMatcher(m *ahocorasick.Matcher) {
	s.mu.Lock()
	s.matcher = m
	s.mu.Unlock()
}

func (s *listState) getMatcher() *ahocorasick.Matcher {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.matcher
}

// ── Manager ───────────────────────────────────────────────────────────────────────────

// Manager owns all blocklist data. Create once in main() via NewManager; pass to
// detectors via SharedResources. On SIGHUP call Update() — same pointer, new goroutines.
type Manager struct {
	mu     sync.RWMutex
	lists  map[string]*listState
	db     *bolt.DB
	client *http.Client
}

// NewManager creates a Manager and starts per-list refresh goroutines.
// ctx must be appCtx so goroutines stop on SIGTERM.
// Blocks only to open bbolt (if configured); network fetches happen in background.
func NewManager(ctx context.Context, cfg Config) *Manager {
	m := &Manager{
		lists:  make(map[string]*listState),
		client: &http.Client{Timeout: 30 * time.Second},
	}

	if cfg.Storage != "" {
		db, err := bolt.Open(cfg.Storage, 0600, &bolt.Options{Timeout: 2 * time.Second})
		if err != nil {
			utils.Log("BLOCKLIST", fmt.Sprintf("bbolt open error (%s): %v — using in-memory only", cfg.Storage, err), "warn")
		} else {
			m.db = db
		}
	}

	active := 0
	for _, lc := range cfg.Lists {
		if listEnabled(lc) {
			m.startList(ctx, lc)
			active++
		}
	}

	utils.Log("BLOCKLIST", fmt.Sprintf("manager started: %d lists, storage=%q", active, cfg.Storage), "info")
	return m
}

// Update replaces all per-list goroutines with goroutines running the new config.
// Called by the SIGHUP fan-out goroutine in main() — exactly once per reload.
// If the storage path changed, the old bbolt is closed and a new one is opened.
func (m *Manager) Update(ctx context.Context, cfg Config) {
	m.mu.Lock()

	// Cancel all running per-list goroutines.
	for _, s := range m.lists {
		s.cancel()
	}
	m.lists = make(map[string]*listState)

	// Reopen bbolt if the storage path changed.
	if cfg.Storage != "" {
		if m.db == nil || m.db.Path() != cfg.Storage {
			if m.db != nil {
				_ = m.db.Close()
				m.db = nil
			}
			db, err := bolt.Open(cfg.Storage, 0600, &bolt.Options{Timeout: 2 * time.Second})
			if err != nil {
				utils.Log("BLOCKLIST", fmt.Sprintf("SIGHUP: bbolt open error (%s): %v — using in-memory only", cfg.Storage, err), "warn")
			} else {
				m.db = db
			}
		}
	} else if m.db != nil {
		_ = m.db.Close()
		m.db = nil
	}

	m.mu.Unlock()

	// Start new per-list goroutines (outside the lock — startList acquires its own lock).
	active := 0
	for _, lc := range cfg.Lists {
		if listEnabled(lc) {
			m.startList(ctx, lc)
			active++
		}
	}

	utils.Log("BLOCKLIST", fmt.Sprintf("manager updated: %d lists", active), "info")
}

// Match returns true if text contains any pattern from the named list.
// Returns false if the list does not exist or has not been loaded yet (graceful degradation).
// Never panics. Safe for concurrent use.
func (m *Manager) Match(list string, text string) bool {
	m.mu.RLock()
	s, ok := m.lists[list]
	m.mu.RUnlock()

	if !ok {
		return false
	}

	matcher := s.getMatcher()
	if matcher == nil {
		return false
	}

	return len(matcher.FindAllString(text)) > 0
}

// MatchResult returns the first matched pattern from the named list, or ("", false) if no match.
// Returns ("", false) if the list does not exist or has not been loaded yet (graceful degradation).
// Never panics. Safe for concurrent use.
func (m *Manager) MatchResult(list string, text string) (string, bool) {
	m.mu.RLock()
	s, ok := m.lists[list]
	m.mu.RUnlock()

	if !ok {
		return "", false
	}

	matcher := s.getMatcher()
	if matcher == nil {
		return "", false
	}

	results := matcher.FindAllString(text)
	if len(results) > 0 {
		return string(results[0].Word), true
	}
	return "", false
}

// Close cancels all per-list goroutines and closes the bbolt database.
// After Close, Match always returns false.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, s := range m.lists {
		s.cancel()
	}
	m.lists = make(map[string]*listState)

	if m.db != nil {
		_ = m.db.Close()
		m.db = nil
	}
}

// ── Per-list goroutine ────────────────────────────────────────────────────────────────

// startList registers a new listState and starts its refresh goroutine.
// Must not be called with m.mu held.
func (m *Manager) startList(ctx context.Context, cfg ListConfig) {
	listCtx, cancel := context.WithCancel(ctx)
	state := &listState{cancel: cancel}

	m.mu.Lock()
	m.lists[cfg.Name] = state
	m.mu.Unlock()

	go func() {
		// Fast path: load persisted patterns before first network fetch so
		// the automaton is available immediately on restart when bbolt is configured.
		if patterns := m.loadFromBolt(cfg.Name); len(patterns) > 0 {
			state.setMatcher(ahocorasick.CompileStrings(patterns))
			utils.Log("BLOCKLIST", fmt.Sprintf("list %q: loaded %d patterns from store", cfg.Name, len(patterns)), "info")
		}

		m.fetchAndUpdate(listCtx, cfg, state)

		ticker := time.NewTicker(time.Duration(cfg.RefreshInterval))
		defer ticker.Stop()
		for {
			select {
			case <-listCtx.Done():
				return
			case <-ticker.C:
				m.fetchAndUpdate(listCtx, cfg, state)
			}
		}
	}()
}

// fetchAndUpdate fetches all sources for a list, merges patterns, rebuilds the automaton,
// and persists to bbolt. On total failure, the existing automaton is preserved.
func (m *Manager) fetchAndUpdate(ctx context.Context, cfg ListConfig, state *listState) {
	var all []string
	seen := make(map[string]struct{})
	anyLoaded := false

	for _, src := range cfg.Sources {
		if src.URL == "" {
			continue
		}
		parser, err := NewParser(src.Format)
		if err != nil {
			utils.Log("BLOCKLIST", fmt.Sprintf("list %q source %q: invalid format %q: %v", cfg.Name, src.URL, src.Format, err), "warn")
			continue
		}

		data, err := m.fetch(ctx, src.URL)
		if err != nil {
			utils.Log("BLOCKLIST", fmt.Sprintf("list %q source %q: fetch error: %v — skipping", cfg.Name, src.URL, err), "warn")
			continue
		}

		patterns, err := parser.Parse(data)
		if err != nil {
			utils.Log("BLOCKLIST", fmt.Sprintf("list %q source %q: parse error: %v — skipping", cfg.Name, src.URL, err), "warn")
			continue
		}

		// Fallback: if PlainTextParser produced no results, try NginxMapParser.
		// Handles cases where the source switches format without a config change.
		if len(patterns) == 0 {
			// Fallback: plain_text parser produced no results — try nginx_map.
			fbParser := NginxMapParser{}
			if fb, fbErr := fbParser.Parse(data); fbErr == nil && len(fb) > 0 {
				patterns = fb
				utils.Log("BLOCKLIST", fmt.Sprintf("list %q source %q: plain_text empty, nginx_map fallback: %d patterns", cfg.Name, src.URL, len(fb)), "info")
			}
		}

		for _, p := range patterns {
			if _, dup := seen[p]; !dup {
				seen[p] = struct{}{}
				all = append(all, p)
			}
		}
		if len(patterns) > 0 {
			utils.Log("BLOCKLIST", fmt.Sprintf("list %q source %q: %d patterns", cfg.Name, src.URL, len(patterns)), "info")
			anyLoaded = true
		}
	}

	if !anyLoaded {
		utils.Log("BLOCKLIST", fmt.Sprintf("list %q: all sources failed — keeping previous patterns", cfg.Name), "warn")
		return
	}

	m.saveToBolt(cfg.Name, all)

	var matcher *ahocorasick.Matcher
	if len(all) > 0 {
		matcher = ahocorasick.CompileStrings(all)
	}
	state.setMatcher(matcher)
	utils.Log("BLOCKLIST", fmt.Sprintf("list %q: automaton rebuilt (%d patterns)", cfg.Name, len(all)), "info")
}

// fetch downloads a URL and returns the body capped at fetchSizeLimit.
func (m *Manager) fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	return io.ReadAll(io.LimitReader(resp.Body, fetchSizeLimit))
}

// ── bbolt helpers ─────────────────────────────────────────────────────────────────────

// loadFromBolt reads persisted patterns for a list from bbolt.
// Returns nil if bbolt is not configured or no patterns are stored.
func (m *Manager) loadFromBolt(listName string) []string {
	m.mu.RLock()
	db := m.db
	m.mu.RUnlock()

	if db == nil {
		return nil
	}

	var patterns []string
	_ = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(listName))
		if b == nil {
			return nil
		}
		raw := b.Get(boltPatternsKey)
		if len(raw) == 0 {
			return nil
		}
		for _, line := range bytes.Split(raw, []byte("\n")) {
			if s := string(line); s != "" {
				patterns = append(patterns, s)
			}
		}
		return nil
	})
	return patterns
}

// saveToBolt persists patterns for a list to bbolt.
// No-op if bbolt is not configured or patterns is empty.
func (m *Manager) saveToBolt(listName string, patterns []string) {
	m.mu.RLock()
	db := m.db
	m.mu.RUnlock()

	if db == nil || len(patterns) == 0 {
		return
	}

	if err := db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(listName))
		if err != nil {
			return err
		}
		return b.Put(boltPatternsKey, []byte(strings.Join(patterns, "\n")))
	}); err != nil {
		utils.Log("BLOCKLIST", fmt.Sprintf("list %q: bbolt save error: %v", listName, err), "warn")
	}
}

// listEnabled reports whether a list should be started.
// nil Enabled pointer means the field was omitted from YAML — default is enabled.
func listEnabled(lc ListConfig) bool {
	return lc.Enabled == nil || *lc.Enabled
}
