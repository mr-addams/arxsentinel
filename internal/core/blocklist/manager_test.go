package blocklist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// ── helpers ───────────────────────────────────────────────────────────────────────────

// waitForMatcher polls until list's matcher is non-nil or deadline passes.
// Returns true if matcher became available in time.
func waitForMatcher(m *Manager, list string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if m.Match(list, "probe") || matcherLoaded(m, list) {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return matcherLoaded(m, list)
}

// matcherLoaded returns true if the named list has a non-nil matcher.
func matcherLoaded(m *Manager, list string) bool {
	m.mu.RLock()
	s, ok := m.lists[list]
	m.mu.RUnlock()
	if !ok {
		return false
	}
	return s.getMatcher() != nil
}

// newTestServer returns an httptest.Server that serves the given body once per request.
func newTestServer(body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
}

// testConfig builds a minimal Config pointing at the given server URL.
func testConfig(listName, serverURL string, interval time.Duration) Config {
	return Config{
		Lists: []ListConfig{
			{
				Name:            listName,
				RefreshInterval: Duration(interval),
				Sources: []SourceConfig{
					{URL: serverURL, Format: "plain_text"},
				},
			},
		},
	}
}

// ── Match ─────────────────────────────────────────────────────────────────────────────

func TestManager_Match_UA(t *testing.T) {
	srv := newTestServer("ahrefsbot\nsemrushbot\nmj12bot\n")
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := NewManager(ctx, testConfig("ua", srv.URL, time.Hour))
	defer m.Close()

	if !waitForMatcher(m, "ua", 3*time.Second) {
		t.Fatal("matcher not loaded within timeout")
	}

	cases := []struct {
		text string
		want bool
	}{
		{"mozilla/5.0 (compatible; ahrefsbot/7.0)", true},
		{"mj12bot/v1.4.8", true},
		{"mozilla/5.0 (windows nt 10.0; win64; x64) chrome/120", false},
		{"", false},
	}
	for _, tc := range cases {
		got := m.Match("ua", tc.text)
		if got != tc.want {
			t.Errorf("Match(%q) = %v, want %v", tc.text, got, tc.want)
		}
	}
}

func TestManager_Match_UnknownList(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := NewManager(ctx, Config{Lists: []ListConfig{}})
	defer m.Close()

	// Unknown list must return false, no panic.
	if m.Match("nonexistent", "sometext") {
		t.Error("Match on unknown list should return false")
	}
}

func TestManager_Match_NotLoaded(t *testing.T) {
	// List is configured but the server blocks, so patterns never load within the test.
	// Match must return false gracefully.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Block until request is cancelled — simulates slow upstream.
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := NewManager(ctx, testConfig("slow", srv.URL, time.Hour))
	defer m.Close()

	// Do not wait — patterns have not loaded yet.
	if m.Match("slow", "ahrefsbot") {
		t.Error("Match before load should return false")
	}
}

// ── Update ────────────────────────────────────────────────────────────────────────────

func TestManager_Update_NewList(t *testing.T) {
	srv := newTestServer("ahrefsbot\n")
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start with empty config.
	m := NewManager(ctx, Config{Lists: []ListConfig{}})
	defer m.Close()

	// Update adds a new list.
	m.Update(ctx, testConfig("newlist", srv.URL, time.Hour))

	if !waitForMatcher(m, "newlist", 3*time.Second) {
		t.Fatal("new list matcher not loaded after Update")
	}

	if !m.Match("newlist", "ahrefsbot") {
		t.Error("Match on newly added list should return true")
	}
}

func TestManager_Update_SameConfig(t *testing.T) {
	// Update with the same config must restart goroutines — automaton should reload.
	var hitCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitCount.Add(1)
		w.Write([]byte("ahrefsbot\n"))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := testConfig("list", srv.URL, time.Hour)
	m := NewManager(ctx, cfg)
	defer m.Close()

	if !waitForMatcher(m, "list", 3*time.Second) {
		t.Fatal("matcher not loaded after initial NewManager")
	}
	firstHits := hitCount.Load()

	m.Update(ctx, cfg)

	if !waitForMatcher(m, "list", 3*time.Second) {
		t.Fatal("matcher not loaded after Update")
	}

	// After Update, goroutines restarted → at least one more fetch.
	if hitCount.Load() <= firstHits {
		t.Errorf("Update should have triggered a new fetch; hits before=%d, after=%d", firstHits, hitCount.Load())
	}
}

// ── Fetch error handling ──────────────────────────────────────────────────────────────

func TestManager_Fetch_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := NewManager(ctx, testConfig("ua", srv.URL, time.Hour))
	defer m.Close()

	// Give it time to attempt (and fail) the fetch.
	time.Sleep(100 * time.Millisecond)

	// Matcher must be nil (no patterns loaded) — not a panic.
	if m.Match("ua", "ahrefsbot") {
		t.Error("Match should return false when fetch failed")
	}
}

func TestManager_Fetch_NetworkError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Port 1 is unreachable without network privileges.
	m := NewManager(ctx, testConfig("ua", "http://127.0.0.1:1", time.Hour))
	defer m.Close()

	time.Sleep(100 * time.Millisecond)

	if m.Match("ua", "ahrefsbot") {
		t.Error("Match should return false when network is unreachable")
	}
}

// ── bbolt persistence ─────────────────────────────────────────────────────────────────

func TestManager_BboltPersistence(t *testing.T) {
	srv := newTestServer("ahrefsbot\nsemrushbot\n")
	defer srv.Close()

	dbPath := filepath.Join(t.TempDir(), "test.db")

	ctx, cancel := context.WithCancel(context.Background())

	cfg := Config{
		Storage: dbPath,
		Lists: []ListConfig{{
			Name:            "ua",
			RefreshInterval: Duration(time.Hour),
			Sources:         []SourceConfig{{URL: srv.URL, Format: "plain_text"}},
		}},
	}

	// First run: fetch from network → persisted to bbolt.
	m := NewManager(ctx, cfg)
	if !waitForMatcher(m, "ua", 3*time.Second) {
		t.Fatal("matcher not loaded in first run")
	}
	cancel()
	m.Close()

	// Second run: server is gone — patterns must load from bbolt.
	srv.Close()

	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()

	m2 := NewManager(ctx2, cfg)
	defer m2.Close()

	if !waitForMatcher(m2, "ua", 3*time.Second) {
		t.Fatal("matcher not loaded from bbolt in second run")
	}

	if !m2.Match("ua", "ahrefsbot") {
		t.Error("patterns loaded from bbolt should match")
	}
}

// ── Close ─────────────────────────────────────────────────────────────────────────────

func TestManager_Close(t *testing.T) {
	srv := newTestServer("ahrefsbot\n")
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := NewManager(ctx, testConfig("ua", srv.URL, time.Hour))

	if !waitForMatcher(m, "ua", 3*time.Second) {
		t.Fatal("matcher not loaded before Close")
	}

	m.Close()

	// After Close, lists map is empty → Match must return false, no panic.
	if m.Match("ua", "ahrefsbot") {
		t.Error("Match after Close should return false")
	}
}

// ── bbolt not configured ──────────────────────────────────────────────────────────────

func TestManager_NoBbolt_InMemoryOnly(t *testing.T) {
	srv := newTestServer("ahrefsbot\n")
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// No Storage field — in-memory only.
	m := NewManager(ctx, testConfig("ua", srv.URL, time.Hour))
	defer m.Close()

	if !waitForMatcher(m, "ua", 3*time.Second) {
		t.Fatal("matcher not loaded")
	}

	m.mu.RLock()
	hasDB := m.db != nil
	m.mu.RUnlock()

	if hasDB {
		t.Error("db should be nil when Storage is empty")
	}

	if !m.Match("ua", "ahrefsbot") {
		t.Error("in-memory match should work")
	}
}

// ── bbolt bad path ────────────────────────────────────────────────────────────────────

func TestManager_BboltBadPath_FallsBackToMemory(t *testing.T) {
	srv := newTestServer("ahrefsbot\n")
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	badPath := filepath.Join(t.TempDir(), "nonexistent_dir", "test.db")
	_ = os.Remove(badPath)

	cfg := Config{
		Storage: badPath,
		Lists: []ListConfig{{
			Name:            "ua",
			RefreshInterval: Duration(time.Hour),
			Sources:         []SourceConfig{{URL: srv.URL, Format: "plain_text"}},
		}},
	}

	m := NewManager(ctx, cfg)
	defer m.Close()

	// Even with bad bbolt path, in-memory fetch must still work.
	if !waitForMatcher(m, "ua", 3*time.Second) {
		t.Fatal("matcher not loaded even after bbolt failure")
	}

	if !m.Match("ua", "ahrefsbot") {
		t.Error("in-memory match should still work when bbolt fails to open")
	}
}

// ── listEnabled ───────────────────────────────────────────────────────────────────────

func TestListEnabled(t *testing.T) {
	yes := true
	no := false

	cases := []struct {
		name    string
		enabled *bool
		want    bool
	}{
		{"nil means enabled by default", nil, true},
		{"explicit true", &yes, true},
		{"explicit false", &no, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lc := ListConfig{Name: "test", Enabled: tc.enabled}
			if got := listEnabled(lc); got != tc.want {
				t.Errorf("listEnabled = %v, want %v", got, tc.want)
			}
		})
	}
}

// ── source URL reachability ───────────────────────────────────────────────────────────

// TestBlocklistSourceURLs verifies that every enabled source URL in config.yaml
// returns HTTP 200. Skipped in short mode (-test.short) to keep CI fast on offline runners.
func TestBlocklistSourceURLs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	// Resolve config.yaml relative to this file's package root.
	cfgPath := "../../../config.yaml"
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("cannot read config.yaml: %v", err)
	}

	// Parse only the blocklists section we care about.
	type rawSource struct {
		URL string `yaml:"url"`
	}
	type rawList struct {
		Name    string      `yaml:"name"`
		Enabled *bool       `yaml:"enabled"`
		Sources []rawSource `yaml:"sources"`
	}
	type rawCfg struct {
		Blocklists struct {
			Lists []rawList `yaml:"lists"`
		} `yaml:"blocklists"`
	}

	var cfg rawCfg
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("cannot parse config.yaml: %v", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}

	for _, list := range cfg.Blocklists.Lists {
		lc := ListConfig{Name: list.Name, Enabled: list.Enabled}
		if !listEnabled(lc) {
			t.Logf("list %q: enabled=false, skipping URL checks", list.Name)
			continue
		}
		for _, src := range list.Sources {
			src := src
			t.Run(list.Name+"/"+src.URL, func(t *testing.T) {
				resp, err := client.Head(src.URL)
				if err != nil {
					t.Fatalf("HEAD %s: %v", src.URL, err)
				}
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Errorf("HEAD %s: got %d, want 200", src.URL, resp.StatusCode)
				}
			})
		}
	}
}
