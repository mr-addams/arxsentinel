// ========================== BadBot pattern storage =====================================
//   PatternStore — interface for persisting and loading UA/referrer pattern lists.
//
//   WHAT IS HERE:
//     PatternStore  — interface (Load, Save, Close)
//     MemoryStore   — in-memory only, no persistence between restarts
//     BboltStore    — persists patterns to a bbolt database file
//     newPatternStore — factory: "" path → MemoryStore, non-empty path → BboltStore
//
//   WHY BBOLT IS OPTIONAL:
//     MemoryStore is sufficient when the daemon starts quickly and the network is available.
//     BboltStore eliminates the startup network fetch when refresh_interval is 24h:
//     on restart the automaton is built from the cached patterns before the first tick.
//
//   BBOLT SCHEMA:
//     bucket: "patterns"
//     key "ua"  → newline-joined lowercase UA pattern strings
//     key "ref" → newline-joined lowercase referrer pattern strings

package detector

import (
	"bytes"
	"sync"

	bolt "go.etcd.io/bbolt"
)

var patternsBucket = []byte("patterns")
var keyUA = []byte("ua")
var keyRef = []byte("ref")

// PatternStore persists and loads the raw pattern lists used to build Aho-Corasick automata.
type PatternStore interface {
	// Load returns cached UA and referrer patterns, or empty slices if none are stored yet.
	Load() (ua []string, ref []string, err error)
	// Save replaces stored patterns with new values.
	Save(ua []string, ref []string) error
	// Close releases resources (no-op for MemoryStore).
	Close() error
}

// ── MemoryStore ───────────────────────────────────────────────────────────────────────

// MemoryStore keeps patterns in memory only. Patterns are empty on first Load after restart.
type MemoryStore struct {
	mu  sync.RWMutex
	ua  []string
	ref []string
}

func (s *MemoryStore) Load() ([]string, []string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ua := make([]string, len(s.ua))
	ref := make([]string, len(s.ref))
	copy(ua, s.ua)
	copy(ref, s.ref)
	return ua, ref, nil
}

func (s *MemoryStore) Save(ua []string, ref []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ua = make([]string, len(ua))
	s.ref = make([]string, len(ref))
	copy(s.ua, ua)
	copy(s.ref, ref)
	return nil
}

func (s *MemoryStore) Close() error { return nil }

// ── BboltStore ────────────────────────────────────────────────────────────────────────

// BboltStore persists patterns to a bbolt database file.
// Patterns survive restarts — the automaton can be built before the first network fetch.
type BboltStore struct {
	db *bolt.DB
}

// newBboltStore opens (or creates) the bbolt database at path.
func newBboltStore(path string) (*BboltStore, error) {
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		return nil, err
	}
	// Ensure bucket exists so Load never errors on a fresh DB.
	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(patternsBucket)
		return err
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &BboltStore{db: db}, nil
}

func (s *BboltStore) Load() ([]string, []string, error) {
	var ua, ref []string
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(patternsBucket)
		if b == nil {
			return nil
		}
		ua = splitLines(b.Get(keyUA))
		ref = splitLines(b.Get(keyRef))
		return nil
	})
	return ua, ref, err
}

func (s *BboltStore) Save(ua []string, ref []string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(patternsBucket)
		if err := b.Put(keyUA, joinLines(ua)); err != nil {
			return err
		}
		return b.Put(keyRef, joinLines(ref))
	})
}

func (s *BboltStore) Close() error { return s.db.Close() }

// ── Factory ───────────────────────────────────────────────────────────────────────────

// newPatternStore returns a BboltStore when path is non-empty, otherwise a MemoryStore.
func newPatternStore(path string) (PatternStore, error) {
	if path == "" {
		return &MemoryStore{}, nil
	}
	return newBboltStore(path)
}

// ── Helpers ───────────────────────────────────────────────────────────────────────────

// joinLines serializes a string slice to newline-separated bytes for bbolt storage.
func joinLines(patterns []string) []byte {
	if len(patterns) == 0 {
		return nil
	}
	var buf bytes.Buffer
	for i, p := range patterns {
		if i > 0 {
			buf.WriteByte('\n')
		}
		buf.WriteString(p)
	}
	return buf.Bytes()
}

// splitLines deserializes newline-separated bytes from bbolt into a string slice.
// Returns an empty slice for nil/empty input.
func splitLines(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	parts := bytes.Split(data, []byte("\n"))
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if len(p) > 0 {
			result = append(result, string(p))
		}
	}
	return result
}
