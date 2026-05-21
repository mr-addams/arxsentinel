package detector

import (
	"testing"
	"time"

	"github.com/mr-addams/arxsentinel/internal/core/parser"
	"github.com/mr-addams/arxsentinel/internal/sys/config"
)

// ── Stub Matcher ──────────────────────────────────────────────────────────────────────

// stubMatcher implements Matcher for testing.
// matchUA controls whether Match("badbot-ua", ...) returns true.
// matchRef controls whether Match("badbot-ref", ...) returns true.
type stubMatcher struct {
	matchUA  bool
	matchRef bool
}

func (s *stubMatcher) Match(list string, _ string) bool {
	switch list {
	case "badbot-ua":
		return s.matchUA
	case "badbot-ref":
		return s.matchRef
	}
	return false
}

// ── Stub IPView ───────────────────────────────────────────────────────────────────────

// stubIPView satisfies the IPView interface with zero values.
type stubIPView struct{}

func (s stubIPView) GetIP() string                  { return "1.2.3.4" }
func (s stubIPView) GetTotalRequests() int           { return 0 }
func (s stubIPView) GetRequests404() int             { return 0 }
func (s stubIPView) RecentPaths() []string           { return nil }
func (s stubIPView) ApproxRate(_ time.Duration) float64 { return 0 }

// ── Helpers ───────────────────────────────────────────────────────────────────────────

func newTestDetector(cfg config.BadBotConfig, mgr Matcher) *BadBotDetector {
	return NewBadBotDetector(cfg, mgr)
}

func defaultCfg() config.BadBotConfig {
	return config.BadBotConfig{
		Enabled:       true,
		Score:         60,
		CheckUA:       true,
		CheckReferrer: false,
	}
}

// ── Detect: UA matching ───────────────────────────────────────────────────────────────

func TestDetect_UA_Match(t *testing.T) {
	d := newTestDetector(defaultCfg(), &stubMatcher{matchUA: true})
	entry := &parser.LogEntry{UserAgent: "Mozilla/5.0 (compatible; AhrefsBot/7.0)"}

	res := d.Detect(stubIPView{}, entry)

	if res.Score != 60 {
		t.Errorf("Score: want 60, got %d", res.Score)
	}
	if res.Module != "badbot" {
		t.Errorf("Module: want badbot, got %q", res.Module)
	}
	if res.Reason != "ua-match" {
		t.Errorf("Reason: want ua-match, got %q", res.Reason)
	}
}

func TestDetect_UA_NoMatch(t *testing.T) {
	d := newTestDetector(defaultCfg(), &stubMatcher{matchUA: false})
	entry := &parser.LogEntry{UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120"}

	res := d.Detect(stubIPView{}, entry)

	if res.Score != 0 {
		t.Errorf("Score: want 0, got %d", res.Score)
	}
}

func TestDetect_UA_CaseInsensitive(t *testing.T) {
	// Verify that Detect lowercases the UA before passing it to Match.
	// The stub records the text it receives so we can check it.
	var received string
	mgr := &captureMatcher{fn: func(list, text string) bool {
		if list == "badbot-ua" {
			received = text
		}
		return false
	}}

	d := newTestDetector(defaultCfg(), mgr)
	entry := &parser.LogEntry{UserAgent: "AHREFSBOT/7.0"}
	d.Detect(stubIPView{}, entry)

	if received != "ahrefsbot/7.0" {
		t.Errorf("UA passed to Match: want %q (lowercase), got %q", "ahrefsbot/7.0", received)
	}
}

func TestDetect_UA_Empty(t *testing.T) {
	// Empty or "-" UA must be skipped — Match must not be called.
	called := false
	mgr := &captureMatcher{fn: func(_, _ string) bool {
		called = true
		return false
	}}

	d := newTestDetector(defaultCfg(), mgr)

	for _, ua := range []string{"", "-"} {
		called = false
		entry := &parser.LogEntry{UserAgent: ua}
		res := d.Detect(stubIPView{}, entry)
		if res.Score != 0 {
			t.Errorf("UA=%q: want Score=0, got %d", ua, res.Score)
		}
		if called {
			t.Errorf("UA=%q: Match must not be called for empty/dash UA", ua)
		}
	}
}

// ── Detect: Referrer matching ─────────────────────────────────────────────────────────

func TestDetect_Referrer_Match(t *testing.T) {
	cfg := defaultCfg()
	cfg.CheckReferrer = true
	// UA does not match so the referrer path is reached.
	d := newTestDetector(cfg, &stubMatcher{matchUA: false, matchRef: true})
	entry := &parser.LogEntry{
		UserAgent: "Mozilla/5.0",
		Referer:   "http://semalt.com/",
	}

	res := d.Detect(stubIPView{}, entry)

	if res.Score != 60 {
		t.Errorf("Score: want 60, got %d", res.Score)
	}
	if res.Reason != "ref-match" {
		t.Errorf("Reason: want ref-match, got %q", res.Reason)
	}
}

func TestDetect_Referrer_Disabled(t *testing.T) {
	// check_referrer=false — referrer must never trigger even if Match would return true.
	cfg := defaultCfg()
	cfg.CheckReferrer = false
	d := newTestDetector(cfg, &stubMatcher{matchUA: false, matchRef: true})
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
	// Empty or "-" referrer must be skipped.
	cfg := defaultCfg()
	cfg.CheckReferrer = true
	refCalled := false
	mgr := &captureMatcher{fn: func(list, _ string) bool {
		if list == "badbot-ref" {
			refCalled = true
		}
		return false
	}}

	d := newTestDetector(cfg, mgr)

	for _, ref := range []string{"", "-"} {
		refCalled = false
		entry := &parser.LogEntry{UserAgent: "Mozilla/5.0", Referer: ref}
		res := d.Detect(stubIPView{}, entry)
		if res.Score != 0 {
			t.Errorf("Referer=%q: want Score=0, got %d", ref, res.Score)
		}
		if refCalled {
			t.Errorf("Referer=%q: Match(badbot-ref) must not be called for empty/dash referer", ref)
		}
	}
}

// ── Detect: graceful degradation ──────────────────────────────────────────────────────

func TestDetect_MatcherReturnsFalse_NoScore(t *testing.T) {
	// When the Manager has not loaded patterns yet, Match returns false.
	// Detector must return Score=0 without panic.
	d := newTestDetector(defaultCfg(), &stubMatcher{matchUA: false})
	entry := &parser.LogEntry{UserAgent: "AhrefsBot/7.0"}

	res := d.Detect(stubIPView{}, entry)

	if res.Score != 0 {
		t.Errorf("Score: want 0 (matcher returns false), got %d", res.Score)
	}
}

// ── captureMatcher helper ─────────────────────────────────────────────────────────────

// captureMatcher calls fn for every Match invocation, allowing tests to inspect arguments.
type captureMatcher struct {
	fn func(list, text string) bool
}

func (c *captureMatcher) Match(list, text string) bool {
	return c.fn(list, text)
}
