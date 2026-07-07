// ========================== Package opnsense — tests ==========================
//   Unit tests for OpnsenseExecutor: config validation, immediate per-event
//   add (no batching), expired-sweep, min-level filter, dedup, sync-existing,
//   and registry registration.
//
//   Mirrors pkg/executorplugins/openwrt/executor_test.go structure
//   (testOpnsense helper + testEventSource), adapted to OPNsense's REST API
//   wire format (alias_util/add, alias_util/delete, alias_util/list).

package opnsense

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mr-addams/arx-core/pkg/dedup"
	"github.com/mr-addams/arx-core/pkg/executor"
	"github.com/mr-addams/arx-core/pkg/logger"
	"github.com/mr-addams/arx-core/pkg/plugin"

	"github.com/mr-addams/arxsentinel/internal/threat"
)

// ++++++++++++++++++++++++++ Mock OPNsense server +++++++++++++++++++++++++++++

// mockOpnsenseState holds the in-memory alias_util state for a test.
// `entries` mirrors the alias content returned by list and updated by
// add/delete (the real firewall persists the alias; here we track it
// in-process for assertion convenience).
type mockOpnsenseState struct {
	mu      sync.Mutex
	entries []string
	// call counters — exported via Counts()
	addCalls     atomic.Int64
	delCalls     atomic.Int64
	listCalls    atomic.Int64
	badAuthCalls atomic.Int64
}

func newMockOpnsenseState() *mockOpnsenseState {
	return &mockOpnsenseState{}
}

// Counts returns a snapshot of alias_util call counters. Used by tests to
// assert "exactly one add call per accepted event" and "exactly one delete
// call per expired IP".
type mockOpnsenseCounts struct {
	Add     int64
	Del     int64
	List    int64
	BadAuth int64
}

func (s *mockOpnsenseState) Counts() mockOpnsenseCounts {
	return mockOpnsenseCounts{
		Add:     s.addCalls.Load(),
		Del:     s.delCalls.Load(),
		List:    s.listCalls.Load(),
		BadAuth: s.badAuthCalls.Load(),
	}
}

// mockOpnsenseHandler returns a http.HandlerFunc that emulates OPNsense
// alias_util endpoints. The handler is stateless w.r.t. mutable request
// state — all mutable state lives in the *mockOpnsenseState argument.
func mockOpnsenseHandler(state *mockOpnsenseState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Decode Authorization: Basic header manually so badAuthCalls
		// increments even when credentials are malformed. http.Request's
		// BasicAuth() silently returns ok=false for malformed auth, but
		// we want to count the attempt explicitly.
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Basic ") {
			state.badAuthCalls.Add(1)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		encoded := strings.TrimPrefix(auth, "Basic ")
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			state.badAuthCalls.Add(1)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) != 2 || parts[0] != "testkey" || parts[1] != "secret" {
			state.badAuthCalls.Add(1)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// The alias name is the last path segment; path.Base handles
		// both plain and URL-encoded aliases in the request path.
		alias := path.Base(r.URL.Path)
		_ = alias

		switch {
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/firewall/alias_util/add/"):
			body, _ := io.ReadAll(r.Body)
			var req struct {
				Address string `json:"address"`
			}
			if err := json.Unmarshal(body, &req); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
			state.mu.Lock()
			state.entries = append(state.entries, req.Address)
			state.mu.Unlock()
			state.addCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"result":"saved"}`))

		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/firewall/alias_util/delete/"):
			body, _ := io.ReadAll(r.Body)
			var req struct {
				Address string `json:"address"`
			}
			if err := json.Unmarshal(body, &req); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
			state.mu.Lock()
			filtered := state.entries[:0]
			for _, e := range state.entries {
				if e != req.Address {
					filtered = append(filtered, e)
				}
			}
			state.entries = filtered
			state.mu.Unlock()
			state.delCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"result":"saved"}`))

		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/firewall/alias_util/list/"):
			state.mu.Lock()
			content := strings.Join(state.entries, "\n")
			state.mu.Unlock()
			state.listCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			resp := map[string]string{"content": content}
			_ = json.NewEncoder(w).Encode(resp)

		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}
}

// ++++++++++++++++++++++++++ Test helpers ++++++++++++++++++++++++++++++++++++++

// testOpnsense creates a fresh executor backed by an httptest OPNsense mock
// server. The handler is the standard mockOpnsenseHandler; tests that need
// to inspect call counts reach for the returned *mockOpnsenseState.
func testOpnsense(t *testing.T, opts ...func(*Config)) (*httptest.Server, *mockOpnsenseState, *OpnsenseExecutor) {
	t.Helper()
	state := newMockOpnsenseState()
	ts := httptest.NewServer(mockOpnsenseHandler(state))
	t.Cleanup(ts.Close)

	// HTTPClient.baseURL builds scheme://cfg.Host:cfg.Port, so cfg.Host must
	// be the bare hostname (no port) and cfg.Port must point at the httptest
	// listener. ts.URL is http://127.0.0.1:<random> — extract host:port and split.
	host, port, err := splitHostPort(ts.URL)
	if err != nil {
		t.Fatalf("parse httptest URL %q: %v", ts.URL, err)
	}

	cfg := Config{
		Host:        host,
		Port:        port,
		Scheme:      "http",
		APIKey:      "testkey",
		APISecret:   "secret",
		AliasName:   "blocklist",
		TLSVerify:   false,
		TTL:         1 * time.Hour,
		MinLevel:    "THREAT",
		DedupWindow: 0,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	exec := &OpnsenseExecutor{
		cfg:      cfg,
		client:   NewHTTPClient(cfg),
		banned:   make(map[string]banRecord),
		logger:   logger.Nop,
		dedupWin: dedup.NewWindow(cfg.DedupWindow),
	}
	return ts, state, exec
}

// splitHostPort extracts bare host and numeric port from a URL like
// http://127.0.0.1:39167. Returned values plug directly into Config.Host
// and Config.Port.
func splitHostPort(rawURL string) (string, int, error) {
	// Trim scheme — Config.Scheme is set independently.
	s := strings.TrimPrefix(rawURL, "http://")
	s = strings.TrimPrefix(s, "https://")
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

// ++++++++++++++++++++++++++ TestParseConfig ++++++++++++++++++++++++++++++++++
func TestParseConfig(t *testing.T) {
	// Required field missing → error (host is tested here; the validator
	// checks all required fields, one representative failure is enough).
	missing := map[string]any{
		"api_key":    "k",
		"api_secret": "s",
		"alias_name": "blocklist",
		"ttl":        "1h",
	}
	if _, err := parseConfig(missing); err == nil {
		t.Error("expected error for missing host")
	}

	// Defaults — minimal valid config.
	// OPNsense defaults are HTTPS-oriented, unlike openwrt's HTTP default.
	min, err := parseConfig(map[string]any{
		"host":       "fw.lan",
		"api_key":    "k",
		"api_secret": "s",
		"alias_name": "blocklist",
		"ttl":        "1h",
	})
	if err != nil {
		t.Fatalf("parseConfig minimal: %v", err)
	}
	if min.Port != 443 {
		t.Errorf("default port = %d, want 443", min.Port)
	}
	if min.Scheme != "https" {
		t.Errorf("default scheme = %q, want \"https\"", min.Scheme)
	}
	if !min.TLSVerify {
		t.Error("default tls_verify = false, want true")
	}
	if min.MinLevel != "THREAT" {
		t.Errorf("default min_level = %q, want THREAT", min.MinLevel)
	}
	if min.DedupWindow != 0 {
		t.Errorf("default dedup_window = %s, want 0", min.DedupWindow)
	}

	// TTL must be > 0.
	if _, err := parseConfig(map[string]any{
		"host":       "fw.lan",
		"api_key":    "k",
		"api_secret": "s",
		"alias_name": "blocklist",
		"ttl":        "0s",
	}); err == nil {
		t.Error("expected error for ttl=0")
	}

	// Invalid scheme.
	if _, err := parseConfig(map[string]any{
		"host":       "fw.lan",
		"api_key":    "k",
		"api_secret": "s",
		"alias_name": "blocklist",
		"ttl":        "1h",
		"scheme":     "ftp",
	}); err == nil {
		t.Error("expected error for invalid scheme")
	}

	// Invalid min_level.
	if _, err := parseConfig(map[string]any{
		"host":       "fw.lan",
		"api_key":    "k",
		"api_secret": "s",
		"alias_name": "blocklist",
		"ttl":        "1h",
		"min_level":  "FOO",
	}); err == nil {
		t.Error("expected error for invalid min_level")
	}
}

// ++++++++++++++++++++++++++ TestAddEntryOnEvent +++++++++++++++++++++++++++++

func TestAddEntryOnEvent(t *testing.T) {
	_, state, exec := testOpnsense(t)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-time.After(300 * time.Millisecond)
		cancel()
	}()

	err := exec.Run(ctx, &testEventSource{
		events: []*plugin.Event{
			{Payload: &threat.ThreatEvent{IP: "1.2.3.4", Level: "THREAT"}},
		},
	})
	if err != nil && err != context.Canceled {
		t.Fatalf("Run returned unexpected error: %v", err)
	}

	c := state.Counts()
	if c.Add != 1 {
		t.Errorf("expected 1 add call for 1 event, got %d", c.Add)
	}
	if c.Del != 0 {
		t.Errorf("expected 0 delete calls, got %d", c.Del)
	}
	if c.List < 1 {
		t.Errorf("expected at least 1 list call from syncExisting, got %d", c.List)
	}
	if c.BadAuth != 0 {
		t.Errorf("expected 0 bad auth calls, got %d", c.BadAuth)
	}

	exec.mu.Lock()
	_, banned := exec.banned["1.2.3.4"]
	exec.mu.Unlock()
	if !banned {
		t.Error("expected 1.2.3.4 in banned map after Run")
	}
	if got := exec.stats.executed.Load(); got != 1 {
		t.Errorf("expected executed counter = 1, got %d", got)
	}
	if got := exec.stats.skipped.Load(); got != 0 {
		t.Errorf("expected skipped counter = 0, got %d", got)
	}
}

// ++++++++++++++++++++++++++ TestSweepDeletesExpired ++++++++++++++++++++++++++

func TestSweepDeletesExpired(t *testing.T) {
	_, state, exec := testOpnsense(t, func(c *Config) { c.TTL = 1 * time.Hour })

	// Pre-seed the banned map with an entry whose expireAt is in the past.
	// This simulates "TTL elapsed" without waiting wall-clock time.
	past := time.Now().Add(-1 * time.Minute)
	exec.mu.Lock()
	exec.banned["9.9.9.9"] = banRecord{
		ip:       "9.9.9.9",
		addedAt:  past.Add(-1 * time.Hour),
		expireAt: past,
	}
	exec.mu.Unlock()

	exec.sweep(context.Background())

	c := state.Counts()
	if c.Del != 1 {
		t.Errorf("expected 1 delete call for 1 expired IP, got %d", c.Del)
	}
	if c.Add != 0 {
		t.Errorf("expected 0 add calls, got %d", c.Add)
	}

	exec.mu.Lock()
	_, stillBanned := exec.banned["9.9.9.9"]
	exec.mu.Unlock()
	if stillBanned {
		t.Error("expected 9.9.9.9 to be swept out of banned map")
	}
	if got := exec.stats.swept.Load(); got != 1 {
		t.Errorf("expected swept counter = 1, got %d", got)
	}
}

// ++++++++++++++++++++++++++ TestMinLevelFilter +++++++++++++++++++++++++++++++

func TestMinLevelFilter(t *testing.T) {
	_, state, exec := testOpnsense(t, func(c *Config) { c.MinLevel = "THREAT" })

	if err := exec.syncExisting(context.Background()); err != nil {
		t.Fatalf("syncExisting: %v", err)
	}

	if exec.meetsMinLevel("INFO") {
		t.Error("INFO should not meet THREAT min_level")
	}
	if exec.meetsMinLevel("WARN") {
		t.Error("WARN should not meet THREAT min_level")
	}
	if !exec.meetsMinLevel("THREAT") {
		t.Error("THREAT should meet THREAT min_level")
	}
	if exec.meetsMinLevel("UNKNOWN") {
		t.Error("UNKNOWN level should never meet any min_level")
	}

	// Drive Run() with an under-threshold event and check the skipped
	// counter advances. The goroutine inside Run blocks on Pop until
	// ctx is cancelled, so we use a short timeout to keep the test fast.
	before := exec.stats.skipped.Load()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = exec.Run(ctx, &testEventSource{ //nolint:errcheck
		events: []*plugin.Event{
			{Payload: &threat.ThreatEvent{IP: "1.2.3.4", Level: "WARN"}},
		},
	})
	after := exec.stats.skipped.Load()
	if after-before != 1 {
		t.Errorf("expected 1 skipped event, got %d (before=%d, after=%d)", after-before, before, after)
	}
	if got := exec.stats.executed.Load(); got != 0 {
		t.Errorf("expected executed counter = 0, got %d", got)
	}
	if c := state.Counts(); c.Add != 0 {
		t.Errorf("expected 0 add calls for under-threshold event, got %d", c.Add)
	}
}

// ++++++++++++++++++++++++++ TestIsDuplicate ++++++++++++++++++++++++++++++++++

func TestIsDuplicate(t *testing.T) {
	// DedupWindow must be > 0 to exercise the window path: dedup.NewWindow(0)
	// disables dedup entirely (Mark is a no-op, Contains always false).
	_, _, exec := testOpnsense(t, func(c *Config) { c.DedupWindow = 1 * time.Hour })

	if err := exec.syncExisting(context.Background()); err != nil {
		t.Fatalf("syncExisting: %v", err)
	}

	// Fresh IP — not a duplicate.
	if exec.isDuplicate("1.2.3.4") {
		t.Error("expected fresh IP 1.2.3.4 to NOT be a duplicate")
	}

	// Banned-map path: add it manually and check isDuplicate returns true.
	now := time.Now()
	exec.mu.Lock()
	exec.banned["1.2.3.4"] = banRecord{
		ip:       "1.2.3.4",
		addedAt:  now,
		expireAt: now.Add(1 * time.Hour),
	}
	exec.mu.Unlock()
	if !exec.isDuplicate("1.2.3.4") {
		t.Error("expected 1.2.3.4 to be a duplicate via banned map")
	}

	// Dedup-window path: remove from banned map, Mark in dedup window,
	// and check isDuplicate still returns true (window survives sweep).
	exec.mu.Lock()
	delete(exec.banned, "1.2.3.4")
	exec.mu.Unlock()
	exec.dedupWin.Mark("1.2.3.4")
	if !exec.isDuplicate("1.2.3.4") {
		t.Error("expected 1.2.3.4 to be a duplicate via dedup window")
	}

	// Unrelated IP — still fresh.
	if exec.isDuplicate("5.6.7.8") {
		t.Error("expected 5.6.7.8 to NOT be a duplicate")
	}
}

// ++++++++++++++++++++++++++ TestSyncExisting +++++++++++++++++++++++++++++++++

func TestSyncExisting(t *testing.T) {
	// Pre-seed the mock with two existing entries — they should land in
	// the executor's banned map with TTL=now+cfg.TTL on the next sync.
	state := newMockOpnsenseState()
	state.entries = []string{"10.0.0.1", "10.0.0.2"}
	ts := httptest.NewServer(mockOpnsenseHandler(state))
	t.Cleanup(ts.Close)

	host, port, err := splitHostPort(ts.URL)
	if err != nil {
		t.Fatalf("parse httptest URL %q: %v", ts.URL, err)
	}
	cfg := Config{
		Host:      host,
		Port:      port,
		Scheme:    "http",
		APIKey:    "testkey",
		APISecret: "secret",
		AliasName: "blocklist",
		TTL:       1 * time.Hour,
		MinLevel:  "THREAT",
	}
	exec := &OpnsenseExecutor{
		cfg:      cfg,
		client:   NewHTTPClient(cfg),
		banned:   make(map[string]banRecord),
		logger:   logger.Nop,
		dedupWin: dedup.NewWindow(0),
	}

	if err := exec.syncExisting(context.Background()); err != nil {
		t.Fatalf("syncExisting: %v", err)
	}

	exec.mu.Lock()
	defer exec.mu.Unlock()
	if len(exec.banned) != 2 {
		t.Errorf("expected 2 banned entries after sync, got %d", len(exec.banned))
	}
	for _, ip := range []string{"10.0.0.1", "10.0.0.2"} {
		rec, ok := exec.banned[ip]
		if !ok {
			t.Errorf("expected %s in banned map", ip)
			continue
		}
		// expireAt must be approximately now+TTL (1h) — tolerate the
		// time elapsed during the HTTP roundtrip.
		expected := time.Now().Add(1 * time.Hour)
		delta := rec.expireAt.Sub(expected)
		if delta < -5*time.Second || delta > 5*time.Second {
			t.Errorf("expireAt for %s off by %s from now+TTL", ip, delta)
		}
	}
}

// ++++++++++++++++++++++++++ TestOpnsenseRegistration +++++++++++++++++++++++++

func TestOpnsenseRegistration(t *testing.T) {
	found := false
	for _, name := range executor.Names() {
		if name == "opnsense" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'opnsense' in executor.Names(), not found")
	}
}

// ++++++++++++++++++++++++++ testEventSource ++++++++++++++++++++++++++++++++++

// testEventSource mirrors the openwrt test helper — delivers pre-defined
// events and blocks on ctx.Done once exhausted. Used by tests to drive Run()
// without standing up a real EventSource.
type testEventSource struct {
	events []*plugin.Event
	idx    int
}

func (s *testEventSource) Pop(ctx context.Context) (*plugin.Event, error) {
	if s.idx >= len(s.events) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ev := s.events[s.idx]
	s.idx++
	return ev, nil
}
