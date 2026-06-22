// ========================== Registry tests ==============================================
//   Tests for the pkg/detector registry: Register, Build, Names.
//   Also tests that built-in detectors (registered via init()) produce working instances.

package detector_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mr-addams/arxsentinel/pkg/detector"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

// ── Registry unit tests ───────────────────────────────────────────────────────────────

// TestRegistry_Names verifies the registry is populated and that Names()
// returns a sorted, duplicate-free, non-empty list.
// It intentionally does not assert the full set of detector names, because
// individual detectors are registered via blank imports in cmd/arxsentinel
// plugins files; pkg/detector tests only check registry infrastructure.
func TestRegistry_Names(t *testing.T) {
	names := detector.Names()

	if len(names) == 0 {
		t.Fatal("Names() returned empty slice, expected at least one registered detector")
	}

	seen := make(map[string]struct{}, len(names))
	for i, n := range names {
		if n == "" {
			t.Errorf("Names()[%d] is empty string", i)
			continue
		}
		if _, ok := seen[n]; ok {
			t.Errorf("Names() contains duplicate %q at index %d", n, i)
		}
		seen[n] = struct{}{}
	}

	// Verify sorted order.
	for i := 1; i < len(names); i++ {
		if names[i] < names[i-1] {
			t.Errorf("Names() not sorted: %q < %q at index %d", names[i], names[i-1], i)
		}
	}
}

// TestRegistry_Build_Disabled verifies that Build returns (nil, nil) for a disabled detector.
func TestRegistry_Build_Disabled(t *testing.T) {
	cfg := detector.DetectorConfig{Enabled: false}
	d, err := detector.Build(context.Background(), "probe", cfg, nil)
	if err != nil {
		t.Fatalf("Build(disabled) error = %v, want nil", err)
	}
	if d != nil {
		t.Fatalf("Build(disabled) detector = %v, want nil", d)
	}
}

// TestRegistry_Build_Unknown verifies that Build returns an error for an unregistered name.
func TestRegistry_Build_Unknown(t *testing.T) {
	cfg := detector.DetectorConfig{Enabled: true}
	d, err := detector.Build(context.Background(), "nonexistent_detector_xyz", cfg, nil)
	if err == nil {
		t.Fatal("Build(unknown) expected error, got nil")
	}
	if d != nil {
		t.Fatalf("Build(unknown) returned non-nil detector: %v", d)
	}
}

// ── Built-in detector smoke tests ─────────────────────────────────────────────────────

// TestRateDetector_ViaRegistry builds a rate detector and verifies it triggers
// on a simulated high request rate.
func TestRateDetector_ViaRegistry(t *testing.T) {
	cfg := detector.DetectorConfig{
		Enabled: true,
		Params: map[string]interface{}{
			"threshold": 10,
			"window":    "60s",
			"score":     25,
		},
	}
	d, err := detector.Build(context.Background(), "rate", cfg, nil)
	if err != nil {
		t.Fatalf("Build(rate) error: %v", err)
	}
	if d.Name() != "rate" {
		t.Errorf("Name() = %q, want %q", d.Name(), "rate")
	}

	// 20 req/60s ≈ 0.333 rps — exceeds threshold of 10/60 ≈ 0.167 rps.
	highRate := newStubView(0, 0, nil, 20.0/60.0)
	result := d.Detect(highRate, &plugin.LogEntry{})
	if result.Score == 0 {
		t.Error("rate detector should trigger on high rate, got score=0")
	}

	// Low rate should not trigger.
	lowRate := newStubView(0, 0, nil, 1.0/60.0)
	result2 := d.Detect(lowRate, &plugin.LogEntry{})
	if result2.Score != 0 {
		t.Errorf("rate detector should not trigger on low rate, got score=%d", result2.Score)
	}
}

// TestBruteforceDetector_ViaRegistry verifies triggering on a high 404 ratio.
func TestBruteforceDetector_ViaRegistry(t *testing.T) {
	cfg := detector.DetectorConfig{
		Enabled: true,
		Params: map[string]interface{}{
			"min_requests":    10,
			"ratio_threshold": 0.6,
			"score":           30,
		},
	}
	d, err := detector.Build(context.Background(), "bruteforce", cfg, nil)
	if err != nil {
		t.Fatalf("Build(bruteforce) error: %v", err)
	}
	if d.Name() != "bruteforce" {
		t.Errorf("Name() = %q, want %q", d.Name(), "bruteforce")
	}

	// 9 of 10 requests are 404 → 90% → should trigger.
	sv := newStubView(10, 9, nil, 0)
	result := d.Detect(sv, &plugin.LogEntry{})
	if result.Score == 0 {
		t.Error("bruteforce should trigger on 90% 404 ratio, got score=0")
	}

	// Below min_requests — should not trigger.
	sv2 := newStubView(5, 4, nil, 0)
	result2 := d.Detect(sv2, &plugin.LogEntry{})
	if result2.Score != 0 {
		t.Errorf("bruteforce should not trigger below min_requests, got score=%d", result2.Score)
	}
}

// TestUADetector_ViaRegistry verifies scanner and empty UA detection.
func TestUADetector_ViaRegistry(t *testing.T) {
	cfg := detector.DetectorConfig{Enabled: true}
	d, err := detector.Build(context.Background(), "ua", cfg, nil)
	if err != nil {
		t.Fatalf("Build(ua) error: %v", err)
	}
	if d.Name() != "ua" {
		t.Errorf("Name() = %q, want %q", d.Name(), "ua")
	}

	sv := newStubView(0, 0, nil, 0)
	cases := []struct {
		ua        string
		wantScore bool
	}{
		{"", true},             // empty UA
		{"-", true},            // nginx empty placeholder
		{"Nuclei/2.9.4", true}, // scanner
		{"Mozilla/5.0", false}, // legitimate browser
	}
	for _, tc := range cases {
		entry := &plugin.LogEntry{UserAgent: tc.ua}
		result := d.Detect(sv, entry)
		if tc.wantScore && result.Score == 0 {
			t.Errorf("ua detector: UA=%q should score, got 0", tc.ua)
		}
		if !tc.wantScore && result.Score != 0 {
			t.Errorf("ua detector: UA=%q should not score, got %d", tc.ua, result.Score)
		}
	}
}

// TestBadBotDetector_ViaRegistry verifies matching with a mock Matcher.
func TestBadBotDetector_ViaRegistry(t *testing.T) {
	cfg := detector.DetectorConfig{
		Enabled: true,
		Params:  map[string]interface{}{"check_ua": true, "score": 60},
	}
	shared := &stubShared{matcher: &stubMatcher{matchUA: "badbotua"}}
	d, err := detector.Build(context.Background(), "badbot", cfg, shared)
	if err != nil {
		t.Fatalf("Build(badbot) error: %v", err)
	}
	if d.Name() != "badbot" {
		t.Errorf("Name() = %q, want %q", d.Name(), "badbot")
	}

	sv := newStubView(0, 0, nil, 0)

	// Matching UA should trigger and include pattern in Reason.
	result := d.Detect(sv, &plugin.LogEntry{UserAgent: "badbotua"})
	if result.Score == 0 {
		t.Error("badbot should score on matched UA, got 0")
	}
	if !strings.HasPrefix(result.Reason, "ua=") {
		t.Errorf("badbot Reason should start with 'ua=', got %q", result.Reason)
	}

	// Non-matching UA should not trigger.
	result2 := d.Detect(sv, &plugin.LogEntry{UserAgent: "Mozilla/5.0"})
	if result2.Score != 0 {
		t.Errorf("badbot should not score on clean UA, got %d", result2.Score)
	}
}

// TestBadBotDetector_NilShared verifies graceful degradation when SharedResources is nil.
func TestBadBotDetector_NilShared(t *testing.T) {
	cfg := detector.DetectorConfig{Enabled: true}
	d, err := detector.Build(context.Background(), "badbot", cfg, nil)
	if err != nil {
		t.Fatalf("Build(badbot, nil shared) error: %v", err)
	}
	if d == nil {
		t.Fatal("Build(badbot, nil shared) returned nil detector")
	}
	sv := newStubView(0, 0, nil, 0)
	result := d.Detect(sv, &plugin.LogEntry{UserAgent: "some-bot/1.0"})
	if result.Score != 0 {
		t.Errorf("badbot with nil shared should not score, got %d", result.Score)
	}
}

// TestCrawlerDetector_ViaRegistry verifies sequential numeric path detection.
func TestCrawlerDetector_ViaRegistry(t *testing.T) {
	cfg := detector.DetectorConfig{
		Enabled: true,
		Params:  map[string]interface{}{"min_sequential": 3, "score": 20},
	}
	d, err := detector.Build(context.Background(), "crawler", cfg, nil)
	if err != nil {
		t.Fatalf("Build(crawler) error: %v", err)
	}
	if d.Name() != "crawler" {
		t.Errorf("Name() = %q, want %q", d.Name(), "crawler")
	}

	// 3 consecutive pages → should trigger.
	sv := newStubView(0, 0, []string{"/page/1", "/page/2", "/page/3"}, 0)
	result := d.Detect(sv, &plugin.LogEntry{})
	if result.Score == 0 {
		t.Error("crawler should trigger on 3 sequential pages, got score=0")
	}

	// Non-sequential paths → should not trigger.
	sv2 := newStubView(0, 0, []string{"/about", "/contact", "/blog"}, 0)
	result2 := d.Detect(sv2, &plugin.LogEntry{})
	if result2.Score != 0 {
		t.Errorf("crawler should not trigger on non-sequential paths, got score=%d", result2.Score)
	}
}

// TestOverflowDetector_ViaRegistry verifies URL length and WAF bypass detection.
func TestOverflowDetector_ViaRegistry(t *testing.T) {
	cfg := detector.DetectorConfig{
		Enabled: true,
		Params: map[string]interface{}{
			"max_url_length":    20,
			"suspicious_params": []interface{}{"exec", "eval"},
			"score":             30,
		},
	}
	d, err := detector.Build(context.Background(), "overflow", cfg, nil)
	if err != nil {
		t.Fatalf("Build(overflow) error: %v", err)
	}
	if d.Name() != "overflow" {
		t.Errorf("Name() = %q, want %q", d.Name(), "overflow")
	}

	sv := newStubView(0, 0, nil, 0)

	// URL longer than max_url_length → should trigger.
	longURL := "/" + string(make([]byte, 30)) // 31 bytes > 20
	result := d.Detect(sv, &plugin.LogEntry{Path: longURL})
	if result.Score == 0 {
		t.Error("overflow should trigger on long URL, got score=0")
	}

	// WAF bypass keyword → should trigger.
	result2 := d.Detect(sv, &plugin.LogEntry{Path: "/api", Query: "cmd=exec+bash"})
	if result2.Score == 0 {
		t.Error("overflow should trigger on suspicious param, got score=0")
	}

	// Normal short URL without keywords → should not trigger.
	result3 := d.Detect(sv, &plugin.LogEntry{Path: "/index.html"})
	if result3.Score != 0 {
		t.Errorf("overflow should not trigger on clean URL, got score=%d", result3.Score)
	}
}

// TestNoAssetDetector_ViaRegistry verifies detection of page-only traffic.
func TestNoAssetDetector_ViaRegistry(t *testing.T) {
	cfg := detector.DetectorConfig{
		Enabled: true,
		Params: map[string]interface{}{
			"min_page_requests":     3,
			"asset_ratio_threshold": 0.1,
			"score":                 20,
		},
	}
	d, err := detector.Build(context.Background(), "noasset", cfg, nil)
	if err != nil {
		t.Fatalf("Build(noasset) error: %v", err)
	}
	if d.Name() != "noasset" {
		t.Errorf("Name() = %q, want %q", d.Name(), "noasset")
	}

	// Only page requests (no assets) → should trigger.
	sv := newStubView(0, 0, []string{"/", "/about", "/blog"}, 0)
	result := d.Detect(sv, &plugin.LogEntry{})
	if result.Score == 0 {
		t.Error("noasset should trigger when no assets loaded, got score=0")
	}

	// Mix of pages and assets (ratio above threshold) → should not trigger.
	sv2 := newStubView(0, 0, []string{"/", "/style.css", "/app.js"}, 0)
	result2 := d.Detect(sv2, &plugin.LogEntry{})
	if result2.Score != 0 {
		t.Errorf("noasset should not trigger with adequate asset ratio, got score=%d", result2.Score)
	}

	// Below min_page_requests → should not trigger.
	sv3 := newStubView(0, 0, []string{"/only-one-page"}, 0)
	result3 := d.Detect(sv3, &plugin.LogEntry{})
	if result3.Score != 0 {
		t.Errorf("noasset should not trigger below min_page_requests, got score=%d", result3.Score)
	}
}

// TestRateDetector_InvalidParams verifies that invalid rate detector params
// (window=0 or threshold=0) return an error from Build, not a disabled detector.
func TestRateDetector_InvalidParams(t *testing.T) {
	for _, tc := range []struct {
		name   string
		params map[string]interface{}
	}{
		{"zero_window", map[string]interface{}{"window": "0s", "threshold": 100}},
		{"zero_threshold", map[string]interface{}{"window": "60s", "threshold": 0}},
		{"negative_window", map[string]interface{}{"window": "-10s", "threshold": 100}},
		{"negative_threshold", map[string]interface{}{"window": "60s", "threshold": -1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := detector.DetectorConfig{Enabled: true, Params: tc.params}
			_, err := detector.Build(context.Background(), "rate", cfg, nil)
			if err == nil {
				t.Fatalf("Build(rate, %s) expected error, got nil", tc.name)
			}
		})
	}
}

// TestRateDetector_ValidParams verifies that a valid rate detector is created and scores correctly.
func TestRateDetector_ValidParams(t *testing.T) {
	cfg := detector.DetectorConfig{
		Enabled: true,
		Params: map[string]interface{}{
			"window":    "60s",
			"threshold": 100,
			"score":     25,
		},
	}
	d, err := detector.Build(context.Background(), "rate", cfg, nil)
	if err != nil {
		t.Fatalf("Build(rate, valid) error: %v", err)
	}
	if d == nil {
		t.Fatal("Build(rate, valid) returned nil")
	}

	// Below threshold (50 req/s in 60s window = 3000) — no score
	sv1 := newStubView(0, 0, nil, 50) // ApproxRate=50 < thresholdRPS=100/60≈1.67? No, let me recalculate
	// thresholdRPS = 100 / 60 ≈ 1.67. rate=50 > 1.67 → should trigger
	_ = sv1

	// Actually use correct values: thresholdRPS = 100/60 ≈ 1.67
	// Rate 0.5 req/s → no score
	svLow := newStubView(0, 0, nil, 0.5)
	result := d.Detect(svLow, &plugin.LogEntry{})
	if result.Score != 0 {
		t.Errorf("low rate should not score, got %d", result.Score)
	}

	// Rate 100 req/s → score 25
	svHigh := newStubView(0, 0, nil, 100)
	result = d.Detect(svHigh, &plugin.LogEntry{})
	if result.Score != 25 {
		t.Errorf("high rate should score 25, got %d", result.Score)
	}
}

// ── Stubs and mocks ───────────────────────────────────────────────────────────────────

// stubView implements plugin.IPView for test use.
type stubView struct {
	total    int
	count404 int
	paths    []string
	rate     float64
}

// newStubView creates a stubView with the given field values.
func newStubView(total, count404 int, paths []string, rate float64) plugin.IPView {
	return &stubView{total: total, count404: count404, paths: paths, rate: rate}
}

func (s *stubView) GetIP() string                      { return "1.2.3.4" }
func (s *stubView) GetTotalRequests() int              { return s.total }
func (s *stubView) GetRequests404() int                { return s.count404 }
func (s *stubView) RecentPaths() []string              { return s.paths }
func (s *stubView) ApproxRate(_ time.Duration) float64 { return s.rate }

// stubMatcher matches a single hardcoded UA string.
type stubMatcher struct{ matchUA string }

func (m *stubMatcher) Match(list, text string) bool {
	return list == "badbot-ua" && text == m.matchUA
}

func (m *stubMatcher) MatchResult(list, text string) (string, bool) {
	if list == "badbot-ua" && text == m.matchUA {
		return text, true
	}
	return "", false
}

// stubShared wraps a Matcher into a SharedResources implementation.
type stubShared struct{ matcher detector.Matcher }

func (s *stubShared) Blocklist() detector.Matcher { return s.matcher }
