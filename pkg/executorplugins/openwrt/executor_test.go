// ========================== Package openwrt — tests ==========================
//   Unit tests for OpenwrtExecutor: config validation, batched flush (single
//   commit + single reload per cycle), expired-sweep, min-level filter,
//   dedup, sync-existing, and registry registration.
//
//   Gate B (Flow 095 / Task 4.1): mirrors pkg/executorplugins/mikrotik/
//   executor_test.go structure (testMikroTik helper + testEventSource),
//   adapted to the uhttpd-mod-ubus JSON-RPC 2.0 wire format.

package openwrt

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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

// ++++++++++++++++++++++++++ Mock ubus server +++++++++++++++++++++++++++++++++

// mockUbusState holds the in-memory uhttpd-mod-ubus state for a test.
// `entries` mirrors the UCI ipset list — used by uci.get in ListEntries
// and updated by uci.add_list / uci.del_list (the real router persists
// to /etc/config/firewall on commit; here we skip the persistence step
// and track it in-process for assertion convenience).
type mockUbusState struct {
	mu      sync.Mutex
	entries []string
	// call counters — exported via Counts()
	addListCalls  atomic.Int64
	delListCalls  atomic.Int64
	commitCalls   atomic.Int64
	reloadCalls   atomic.Int64
	listGetCalls  atomic.Int64
	loginCalls    atomic.Int64
}

func newMockUbusState() *mockUbusState {
	return &mockUbusState{}
}

// Counts returns a snapshot of ubus call counters. Used by tests to
// assert "exactly one commit + one reload per flush cycle".
type ubusCounts struct {
	AddList  int64
	DelList  int64
	Commit   int64
	Reload   int64
	ListGet  int64
	Login    int64
}

func (s *mockUbusState) Counts() ubusCounts {
	return ubusCounts{
		AddList: s.addListCalls.Load(),
		DelList: s.delListCalls.Load(),
		Commit:  s.commitCalls.Load(),
		Reload:  s.reloadCalls.Load(),
		ListGet: s.listGetCalls.Load(),
		Login:   s.loginCalls.Load(),
	}
}

// ubusRequest is the subset of the JSON-RPC 2.0 envelope we need to
// inspect: object + method from the ubus "call" wrapper, plus the args.
type ubusRequest struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      int            `json:"id"`
	Method  string         `json:"method"`
	Params  []any          `json:"params"`
	args    map[string]any // parsed from Params[3] when shape matches
}

// mockUbusHandler returns a http.HandlerFunc that emulates uhttpd-mod-ubus.
// The handler is stateless w.r.t. the request (only reads the envelope) —
// all mutable state lives in the *mockUbusState argument.
func mockUbusHandler(state *mockUbusState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/ubus" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req ubusRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		// params layout: [sessionID, object, method, args]
		if len(req.Params) < 4 {
			http.Error(w, "bad params", http.StatusBadRequest)
			return
		}
		object, _ := req.Params[1].(string)
		method, _ := req.Params[2].(string)
		if args, ok := req.Params[3].(map[string]any); ok {
			req.args = args
		}

		// Dispatch: build a [code, data] response array.
		var data any

		switch {
		case object == "session" && method == "login":
			state.loginCalls.Add(1)
			data = map[string]any{"ubus_rpc_session": "testsession"}

		case object == "uci" && method == "add_list":
			state.addListCalls.Add(1)
			state.mu.Lock()
			if values, ok := req.args["values"].([]any); ok {
				for _, v := range values {
					if s, ok := v.(string); ok {
						state.entries = append(state.entries, s)
					}
				}
			}
			state.mu.Unlock()
			data = map[string]any{}

		case object == "uci" && method == "del_list":
			state.delListCalls.Add(1)
			state.mu.Lock()
			if values, ok := req.args["values"].([]any); ok {
				toDel := make(map[string]struct{}, len(values))
				for _, v := range values {
					if s, ok := v.(string); ok {
						toDel[s] = struct{}{}
					}
				}
				filtered := state.entries[:0]
				for _, e := range state.entries {
					if _, drop := toDel[e]; !drop {
						filtered = append(filtered, e)
					}
				}
				state.entries = filtered
			}
			state.mu.Unlock()
			data = map[string]any{}

		case object == "uci" && method == "commit":
			state.commitCalls.Add(1)
			data = map[string]any{}

		case object == "uci" && method == "get":
			state.listGetCalls.Add(1)
			state.mu.Lock()
			// Return a snapshot copy — the caller may mutate it.
			snapshot := make([]string, len(state.entries))
			copy(snapshot, state.entries)
			state.mu.Unlock()
			data = map[string]any{"value": snapshot}

		case object == "rc" && method == "init":
			state.reloadCalls.Add(1)
			data = map[string]any{}

		default:
			http.Error(w, "unknown method", http.StatusNotFound)
			return
		}

		result := []any{0, data}
		resp := map[string]any{
			"jsonrpc": "2.0",
			"id":      req.ID,
			"result":  result,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// ++++++++++++++++++++++++++ Test helpers ++++++++++++++++++++++++++++++++++++

// testOpenwrt creates a fresh executor backed by an httptest ubus mock
// server. The handler is the standard mockUbusHandler; tests that need
// to inspect call counts reach for the returned *mockUbusState.
func testOpenwrt(t *testing.T, opts ...func(*Config)) (*httptest.Server, *mockUbusState, *OpenwrtExecutor) {
	t.Helper()
	state := newMockUbusState()
	ts := httptest.NewServer(mockUbusHandler(state))
	t.Cleanup(ts.Close)

	// httpClient.baseURL builds scheme://cfg.Host:cfg.Port/ubus, so cfg.Host
	// must be the bare hostname (no port) and cfg.Port must point at the
	// httptest listener. ts.URL is http://127.0.0.1:<random> — extract
	// host:port and split.
	host, port, err := splitHostPort(ts.URL)
	if err != nil {
		t.Fatalf("parse httptest URL %q: %v", ts.URL, err)
	}

	cfg := Config{
		Host:           host,
		Port:           port,
		Scheme:         "http",
		Username:       "root",
		Password:       "secret",
		IPSetName:      "blocklist",
		TTL:            1 * time.Hour,
		SessionTimeout: 5 * time.Minute,
		BatchSize:      10,
		FlushInterval:  30 * time.Second,
		MinLevel:       "THREAT",
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	exec := &OpenwrtExecutor{
		name:     "test",
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
	// Required fields missing → error
	missing := map[string]any{
		"username":    "root",
		"password":    "secret",
		"ipset_name":  "blocklist",
		"ttl":         "1h",
	}
	if _, err := parseConfig(missing); err == nil {
		t.Error("expected error for missing host")
	}

	// Defaults — minimal valid config
	min, err := parseConfig(map[string]any{
		"host":       "router.lan",
		"username":   "root",
		"password":   "secret",
		"ipset_name": "blocklist",
		"ttl":        "1h",
	})
	if err != nil {
		t.Fatalf("parseConfig minimal: %v", err)
	}
	if min.Port != 80 {
		t.Errorf("default port = %d, want 80", min.Port)
	}
	if min.Scheme != "http" {
		t.Errorf("default scheme = %q, want \"http\"", min.Scheme)
	}
	if min.SessionTimeout != 5*time.Minute {
		t.Errorf("default session_timeout = %s, want 5m", min.SessionTimeout)
	}
	if min.BatchSize != 10 {
		t.Errorf("default batch_size = %d, want 10", min.BatchSize)
	}
	if min.FlushInterval != 30*time.Second {
		t.Errorf("default flush_interval = %s, want 30s", min.FlushInterval)
	}
	if min.MinLevel != "THREAT" {
		t.Errorf("default min_level = %q, want THREAT", min.MinLevel)
	}

	// Invalid scheme
	if _, err := parseConfig(map[string]any{
		"host":       "router.lan",
		"username":   "root",
		"password":   "secret",
		"ipset_name": "blocklist",
		"ttl":        "1h",
		"scheme":     "ftp",
	}); err == nil {
		t.Error("expected error for invalid scheme")
	}

	// Invalid min_level
	if _, err := parseConfig(map[string]any{
		"host":       "router.lan",
		"username":   "root",
		"password":   "secret",
		"ipset_name": "blocklist",
		"ttl":        "1h",
		"min_level":  "FOO",
	}); err == nil {
		t.Error("expected error for invalid min_level")
	}

	// TTL must be > 0
	if _, err := parseConfig(map[string]any{
		"host":       "router.lan",
		"username":   "root",
		"password":   "secret",
		"ipset_name": "blocklist",
		"ttl":        "0s",
	}); err == nil {
		t.Error("expected error for ttl=0")
	}
}

// ++++++++++++++++++++++++++ TestFlushAddsAndCommitsReload +++++++++++++++++++

func TestFlushAddsAndCommitsReload(t *testing.T) {
	_, state, exec := testOpenwrt(t)

	if err := exec.syncExisting(context.Background()); err != nil {
		t.Fatalf("syncExisting: %v", err)
	}

	// Flush with two new IPs. Cycle must issue:
	//   - 1 x uci.add_list (batch)
	//   - 1 x uci.commit
	//   - 1 x rc.init reload
	// Crucially NOT one add+commit+reload per IP.
	exec.flush(context.Background(), []string{"1.2.3.4", "5.6.7.8"})

	c := state.Counts()
	if c.AddList != 1 {
		t.Errorf("expected 1 add_list call, got %d", c.AddList)
	}
	if c.Commit != 1 {
		t.Errorf("expected 1 commit call, got %d", c.Commit)
	}
	if c.Reload != 1 {
		t.Errorf("expected 1 reload call, got %d", c.Reload)
	}
	if c.DelList != 0 {
		t.Errorf("expected 0 del_list calls (no expired entries), got %d", c.DelList)
	}

	// The mock records the add_list values in its entries slice — verify
	// the two IPs were applied to the in-memory ipset state.
	exec.mu.Lock()
	defer exec.mu.Unlock()
	for _, ip := range []string{"1.2.3.4", "5.6.7.8"} {
		if _, ok := exec.banned[ip]; !ok {
			t.Errorf("expected %s in banned map after flush", ip)
		}
	}
}

// ++++++++++++++++++++++++++ TestFlushSweepsExpired +++++++++++++++++++++++++++

func TestFlushSweepsExpired(t *testing.T) {
	_, state, exec := testOpenwrt(t, func(c *Config) { c.TTL = 1 * time.Hour })

	// Pre-seed the banned map with an entry whose expireAt is in the past.
	// This simulates "TTL elapsed" without waiting wall-clock time.
	past := time.Now().Add(-1 * time.Minute)
	exec.banned["9.9.9.9"] = banRecord{
		ip:       "9.9.9.9",
		addedAt:  past.Add(-1 * time.Hour),
		expireAt: past,
	}

	exec.flush(context.Background(), nil)

	c := state.Counts()
	if c.DelList != 1 {
		t.Errorf("expected 1 del_list call, got %d", c.DelList)
	}
	if c.Commit != 1 {
		t.Errorf("expected 1 commit call (sweep-only cycle), got %d", c.Commit)
	}
	if c.Reload != 1 {
		t.Errorf("expected 1 reload call (sweep-only cycle), got %d", c.Reload)
	}
	if c.AddList != 0 {
		t.Errorf("expected 0 add_list calls (no pending), got %d", c.AddList)
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

// ++++++++++++++++++++++++++ TestMinLevelFilter ++++++++++++++++++++++++++++++

func TestMinLevelFilter(t *testing.T) {
	_, _, exec := testOpenwrt(t, func(c *Config) { c.MinLevel = "THREAT" })

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
}

// ++++++++++++++++++++++++++ TestIsDuplicate ++++++++++++++++++++++++++++++++++

func TestIsDuplicate(t *testing.T) {
	// DedupWindow must be > 0 to exercise the window path: dedup.NewWindow(0)
	// disables dedup entirely (Mark is a no-op, Contains always false).
	_, _, exec := testOpenwrt(t, func(c *Config) { c.DedupWindow = 1 * time.Hour })

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

// ++++++++++++++++++++++++++ TestSyncExisting ++++++++++++++++++++++++++++++++

func TestSyncExisting(t *testing.T) {
	// Pre-seed the mock with two existing entries — they should land in
	// the executor's banned map with TTL=now+cfg.TTL on the next sync.
	state := newMockUbusState()
	state.entries = []string{"10.0.0.1", "10.0.0.2"}
	ts := httptest.NewServer(mockUbusHandler(state))
	t.Cleanup(ts.Close)

	host, port, err := splitHostPort(ts.URL)
	if err != nil {
		t.Fatalf("parse httptest URL %q: %v", ts.URL, err)
	}
	cfg := Config{
		Host:      host,
		Port:      port,
		Scheme:    "http",
		Username:  "root",
		Password:  "secret",
		IPSetName: "blocklist",
		TTL:       1 * time.Hour,
		MinLevel:  "THREAT",
	}
	exec := &OpenwrtExecutor{
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
		// expireAt must be approximately now+TTL (1h) — give a generous
		// tolerance to absorb the time elapsed during the HTTP roundtrip.
		expected := time.Now().Add(1 * time.Hour)
		delta := rec.expireAt.Sub(expected)
		if delta < -5*time.Second || delta > 5*time.Second {
			t.Errorf("expireAt for %s off by %s from now+TTL", ip, delta)
		}
	}
}

// ++++++++++++++++++++++++++ TestOpenwrtRegistration ++++++++++++++++++++++++++

func TestOpenwrtRegistration(t *testing.T) {
	found := false
	for _, name := range executor.Names() {
		if name == "openwrt" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'openwrt' in executor.Names(), not found")
	}
}

// testEventSource mirrors the mikrotik test helper — delivers pre-defined
// events and blocks on ctx.Done once exhausted. Used by TestMinLevelFilter
// to drive Run() without standing up a real EventSource.
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
