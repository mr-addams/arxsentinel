// ========================== BadBot detector tests ========================================
//   Smoke tests for the migrated badbot detector sub-package.

package badbot_test

import (
	"context"
	"strings"
	"testing"
	"time"

	_ "github.com/mr-addams/arxsentinel/pkg/detector/badbot"

	detector "github.com/mr-addams/arxsentinel/pkg/detector"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

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

// TestBadBotDetector_Referrer verifies optional Referer matching.
func TestBadBotDetector_Referrer(t *testing.T) {
	cfg := detector.DetectorConfig{
		Enabled: true,
		Params:  map[string]interface{}{"check_referrer": true, "score": 42},
	}
	shared := &stubShared{matcher: &stubMatcher{matchRef: "badref"}}
	d, err := detector.Build(context.Background(), "badbot", cfg, shared)
	if err != nil {
		t.Fatalf("Build(badbot, referrer) error: %v", err)
	}
	sv := newStubView(0, 0, nil, 0)
	result := d.Detect(sv, &plugin.LogEntry{Referer: "badref"})
	if result.Score != 42 {
		t.Errorf("badbot should score on matched Referer, got %d", result.Score)
	}
	if !strings.HasPrefix(result.Reason, "ref=") {
		t.Errorf("badbot Reason should start with 'ref=', got %q", result.Reason)
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

func newStubView(total, count404 int, paths []string, rate float64) plugin.IPView {
	return &stubView{total: total, count404: count404, paths: paths, rate: rate}
}

func (s *stubView) GetIP() string                      { return "1.2.3.4" }
func (s *stubView) GetTotalRequests() int              { return s.total }
func (s *stubView) GetRequests404() int                { return s.count404 }
func (s *stubView) RecentPaths() []string              { return s.paths }
func (s *stubView) ApproxRate(_ time.Duration) float64 { return s.rate }

// stubMatcher matches a single hardcoded UA and/or Referer string.
type stubMatcher struct{ matchUA, matchRef string }

func (m *stubMatcher) Match(list, text string) bool {
	if list == "badbot-ua" && text == m.matchUA {
		return true
	}
	if list == "badbot-ref" && text == m.matchRef {
		return true
	}
	return false
}

func (m *stubMatcher) MatchResult(list, text string) (string, bool) {
	if list == "badbot-ua" && text == m.matchUA {
		return text, true
	}
	if list == "badbot-ref" && text == m.matchRef {
		return text, true
	}
	return "", false
}

// stubShared wraps a Matcher into a SharedResources implementation.
type stubShared struct{ matcher detector.Matcher }

func (s *stubShared) Blocklist() detector.Matcher { return s.matcher }
