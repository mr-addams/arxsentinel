package detector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mr-addams/nginx-sentinel/internal/core/parser"
	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
)

// ── Helpers ───────────────────────────────────────────────────────────────────────────

// newTestDetector creates a BadBotDetector with pre-loaded patterns (no network, no goroutine).
func newTestDetector(t *testing.T, ua, ref []string, checkRef bool) *BadBotDetector {
	t.Helper()
	cfg := config.BadBotConfig{
		Enabled:       true,
		Score:         60,
		CheckUA:       true,
		CheckReferrer: checkRef,
	}
	d := &BadBotDetector{cfg: cfg, store: &MemoryStore{}}
	d.rebuild(ua, ref)
	return d
}

// stubIPView satisfies the IPView interface with zero values.
type stubIPView struct{}

func (s stubIPView) GetIP() string             { return "1.2.3.4" }
func (s stubIPView) GetTotalRequests() int      { return 0 }
func (s stubIPView) GetRequests404() int        { return 0 }
func (s stubIPView) RecentPaths() []string      { return nil }
func (s stubIPView) ApproxRate(_ time.Duration) float64 { return 0 }

// ── Detect: UA matching ───────────────────────────────────────────────────────────────

func TestDetect_UA_Match(t *testing.T) {
	d := newTestDetector(t, []string{"ahrefsbot", "semrushbot"}, nil, false)
	entry := &parser.LogEntry{UserAgent: "Mozilla/5.0 (compatible; AhrefsBot/7.0)"}

	res := d.Detect(stubIPView{}, entry)

	if res.Score != 60 {
		t.Errorf("Score: want 60, got %d", res.Score)
	}
	if res.Module != "badbot" {
		t.Errorf("Module: want badbot, got %q", res.Module)
	}
	if !strings.HasPrefix(res.Reason, "ua:") {
		t.Errorf("Reason: want ua:..., got %q", res.Reason)
	}
}

func TestDetect_UA_NoMatch(t *testing.T) {
	d := newTestDetector(t, []string{"ahrefsbot", "semrushbot"}, nil, false)
	entry := &parser.LogEntry{UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120"}

	res := d.Detect(stubIPView{}, entry)

	if res.Score != 0 {
		t.Errorf("Score: want 0, got %d", res.Score)
	}
}

func TestDetect_UA_CaseInsensitive(t *testing.T) {
	// Patterns are stored lowercase; UA matching must be case-insensitive.
	d := newTestDetector(t, []string{"ahrefsbot"}, nil, false)
	entry := &parser.LogEntry{UserAgent: "AHREFSBOT/7.0"}

	res := d.Detect(stubIPView{}, entry)

	if res.Score != 60 {
		t.Errorf("Score: want 60 (case-insensitive match), got %d", res.Score)
	}
}

func TestDetect_UA_Empty(t *testing.T) {
	d := newTestDetector(t, []string{"ahrefsbot"}, nil, false)

	for _, ua := range []string{"", "-"} {
		entry := &parser.LogEntry{UserAgent: ua}
		res := d.Detect(stubIPView{}, entry)
		if res.Score != 0 {
			t.Errorf("UA=%q: want Score=0, got %d", ua, res.Score)
		}
	}
}

// ── Detect: Referrer matching ─────────────────────────────────────────────────────────

func TestDetect_Referrer_Match(t *testing.T) {
	d := newTestDetector(t, nil, []string{"semalt"}, true)
	entry := &parser.LogEntry{
		UserAgent: "Mozilla/5.0",
		Referer:   "http://semalt.com/",
	}

	res := d.Detect(stubIPView{}, entry)

	if res.Score != 60 {
		t.Errorf("Score: want 60, got %d", res.Score)
	}
	if !strings.HasPrefix(res.Reason, "ref:") {
		t.Errorf("Reason: want ref:..., got %q", res.Reason)
	}
}

func TestDetect_Referrer_Disabled(t *testing.T) {
	// check_referrer=false → referrer must never trigger even with matching patterns.
	d := newTestDetector(t, nil, []string{"semalt"}, false)
	entry := &parser.LogEntry{
		UserAgent: "Mozilla/5.0",
		Referer:   "http://semalt.com/",
	}

	res := d.Detect(stubIPView{}, entry)

	if res.Score != 0 {
		t.Errorf("Score: want 0 (referrer check disabled), got %d", res.Score)
	}
}

func TestDetect_Referrer_Empty(t *testing.T) {
	d := newTestDetector(t, nil, []string{"semalt"}, true)

	for _, ref := range []string{"", "-"} {
		entry := &parser.LogEntry{UserAgent: "Mozilla/5.0", Referer: ref}
		res := d.Detect(stubIPView{}, entry)
		if res.Score != 0 {
			t.Errorf("Referer=%q: want Score=0, got %d", ref, res.Score)
		}
	}
}

// ── Detect: nil automaton ─────────────────────────────────────────────────────────────

func TestDetect_NilMatcher_NoScore(t *testing.T) {
	// Before patterns are loaded the automaton is nil — must return Score=0, no panic.
	d := &BadBotDetector{
		cfg: config.BadBotConfig{Enabled: true, Score: 60, CheckUA: true},
	}
	entry := &parser.LogEntry{UserAgent: "AhrefsBot/7.0"}

	res := d.Detect(stubIPView{}, entry)

	if res.Score != 0 {
		t.Errorf("Score: want 0 (nil matcher), got %d", res.Score)
	}
}

// ── Parse: plain-text format ──────────────────────────────────────────────────────────

func TestParseList_Basic(t *testing.T) {
	input := []byte("AhrefsBot\nSemrushBot\nMJ12bot\n")
	got := parseList(input)
	want := []string{"ahrefsbot", "semrushbot", "mj12bot"}
	if !strSliceEqual(got, want) {
		t.Errorf("want %v, got %v", want, got)
	}
}

func TestParseList_SkipsCommentsAndEmpty(t *testing.T) {
	input := []byte("# comment\nAhrefsBot\n\n  \nMJ12bot\n# another comment\n")
	got := parseList(input)
	want := []string{"ahrefsbot", "mj12bot"}
	if !strSliceEqual(got, want) {
		t.Errorf("want %v, got %v", want, got)
	}
}

func TestParseList_Lowercase(t *testing.T) {
	input := []byte("AhrefsBot\nSEMRUSHBOT\n")
	got := parseList(input)
	for _, p := range got {
		if p != strings.ToLower(p) {
			t.Errorf("pattern %q is not lowercase", p)
		}
	}
}

func TestParseList_Empty(t *testing.T) {
	if got := parseList([]byte("")); len(got) != 0 {
		t.Errorf("want empty, got %v", got)
	}
}

// ── Parse: nginx map format ───────────────────────────────────────────────────────────

func TestParseNginxMap_Basic(t *testing.T) {
	input := []byte(`"~*(?:\b)AhrefsBot(?:\b)"    3;` + "\n" +
		`"~*(?:\b)SemrushBot(?:\b)"   3;`)
	got := parseNginxMap(input)
	want := []string{"ahrefsbot", "semrushbot"}
	if !strSliceEqual(got, want) {
		t.Errorf("want %v, got %v", want, got)
	}
}

func TestParseNginxMap_NoMatch(t *testing.T) {
	// Plain-text input — nginx regex must not match anything.
	input := []byte("AhrefsBot\nSemrushBot\n")
	got := parseNginxMap(input)
	if len(got) != 0 {
		t.Errorf("want empty for plain-text input, got %v", got)
	}
}

// ── Fetch and rebuild via httptest ────────────────────────────────────────────────────

func TestFetchAndRebuild_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ahrefsbot\nsemrushbot\nmj12bot\n"))
	}))
	defer srv.Close()

	cfg := config.BadBotConfig{
		Enabled: true,
		Score:   60,
		CheckUA: true,
		Sources: []config.BadBotSource{{Name: "test", UAURL: srv.URL}},
	}
	d := &BadBotDetector{cfg: cfg, store: &MemoryStore{}}

	d.fetchAndRebuild(context.Background())

	d.mu.RLock()
	hasUA := d.uaMatcher != nil
	d.mu.RUnlock()

	if !hasUA {
		t.Fatal("uaMatcher must be non-nil after successful fetch")
	}

	// Verify match works.
	entry := &parser.LogEntry{UserAgent: "AhrefsBot/7.0"}
	res := d.Detect(stubIPView{}, entry)
	if res.Score != 60 {
		t.Errorf("Score after fetch: want 60, got %d", res.Score)
	}
}

func TestFetchAndRebuild_KeepsOldOnHTTPError(t *testing.T) {
	// First build automata with known patterns.
	uaPatterns := []string{"ahrefsbot"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := config.BadBotConfig{
		Enabled: true,
		Score:   60,
		CheckUA: true,
		Sources: []config.BadBotSource{{Name: "test", UAURL: srv.URL}},
	}
	d := &BadBotDetector{cfg: cfg, store: &MemoryStore{}}
	d.rebuild(uaPatterns, nil)

	d.fetchAndRebuild(context.Background())

	// Old automata must still be in place.
	entry := &parser.LogEntry{UserAgent: "AhrefsBot/7.0"}
	res := d.Detect(stubIPView{}, entry)
	if res.Score != 60 {
		t.Errorf("Score after HTTP error: want 60 (old automata kept), got %d", res.Score)
	}
}

func TestFetchAndRebuild_KeepsOldOnNetworkError(t *testing.T) {
	uaPatterns := []string{"ahrefsbot"}

	cfg := config.BadBotConfig{
		Enabled: true,
		Score:   60,
		CheckUA: true,
		Sources: []config.BadBotSource{{Name: "test", UAURL: "http://127.0.0.1:1"}}, // unreachable
	}
	d := &BadBotDetector{cfg: cfg, store: &MemoryStore{}}
	d.rebuild(uaPatterns, nil)

	d.fetchAndRebuild(context.Background())

	entry := &parser.LogEntry{UserAgent: "AhrefsBot/7.0"}
	res := d.Detect(stubIPView{}, entry)
	if res.Score != 60 {
		t.Errorf("Score after network error: want 60 (old automata kept), got %d", res.Score)
	}
}

// ── Integration: goroutine lifecycle ──────────────────────────────────────────────────

func TestNewBadBotDetector_CancelStopsGoroutine(t *testing.T) {
	// Serve a known UA list so the goroutine can complete its first fetch.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ahrefsbot\n"))
	}))
	defer srv.Close()

	cfg := config.BadBotConfig{
		Enabled:         true,
		Score:           60,
		CheckUA:         true,
		RefreshInterval: config.Duration(time.Hour),
		Sources:         []config.BadBotSource{{Name: "test", UAURL: srv.URL}},
	}

	ctx, cancel := context.WithCancel(context.Background())
	d := NewBadBotDetector(ctx, cfg)

	// Wait for first fetch to complete.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		d.mu.RLock()
		loaded := d.uaMatcher != nil
		d.mu.RUnlock()
		if loaded {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Cancel context — goroutine must exit (store.Close is called).
	cancel()

	// Detector still works after cancel (automata are in memory).
	entry := &parser.LogEntry{UserAgent: "AhrefsBot/7.0"}
	res := d.Detect(stubIPView{}, entry)
	if res.Score != 60 {
		t.Errorf("Score after cancel: want 60, got %d", res.Score)
	}
}
