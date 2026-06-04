// ========================== Tests whitelist/matcher ====================================
//   Covers Task 3.1 (MatchBot) and Task 3.4 (IsWhitelistedIP, IsWhitelistedUA).
//
//   Test data:
//     - Config with two bots: google (Googlebot, AdsBot-Google) and bing (bingbot)
//     - Custom whitelist: IP "10.0.0.1", CIDR "192.168.1.0/24", UA substring "healthcheck"

package whitelist

import (
	"testing"

	"github.com/mr-addams/arxsentinel/internal/sys/config"
)

// ========================== Fixtures ==================================================

// testConfig returns a minimal config with two bots and a custom whitelist.
// Extracted as a helper — all tests share a single base, changes in one place.
func testConfig() config.WhitelistConfig {
	return config.WhitelistConfig{
		Bots: []config.BotConfig{
			{
				Name:        "google",
				UAPatterns:  []string{"Googlebot", "AdsBot-Google"},
				RDNSDomains: []string{".googlebot.com", ".google.com"},
			},
			{
				Name:        "bing",
				UAPatterns:  []string{"bingbot"},
				RDNSDomains: []string{".search.msn.com"},
			},
		},
		Custom: config.CustomWhitelistConfig{
			IPs:          []string{"10.0.0.1"},
			CIDRs:        []string{"192.168.1.0/24"},
			UASubstrings: []string{"healthcheck", "monitoring"},
		},
	}
}

// mustNewMatcher creates a Matcher from the test config.
// t.Fatal on error — the test cannot continue without a valid Matcher.
func mustNewMatcher(t *testing.T) *Matcher {
	t.Helper()
	m, err := NewMatcher(testConfig())
	if err != nil {
		t.Fatalf("NewMatcher: unexpected error: %v", err)
	}
	return m
}

// ========================== NewMatcher ================================================

func TestNewMatcher_ValidConfig(t *testing.T) {
	m := mustNewMatcher(t)
	if m == nil {
		t.Fatal("NewMatcher returned nil")
	}
}

func TestNewMatcher_InvalidCIDR(t *testing.T) {
	cfg := testConfig()
	cfg.Custom.CIDRs = []string{"not-a-cidr"}
	_, err := NewMatcher(cfg)
	if err == nil {
		t.Fatal("NewMatcher must return an error for an invalid CIDR")
	}
}

func TestNewMatcher_EmptyBots(t *testing.T) {
	// Empty bot list — not an error, MatchBot will simply always return false
	cfg := testConfig()
	cfg.Bots = nil
	m, err := NewMatcher(cfg)
	if err != nil {
		t.Fatalf("NewMatcher with empty bots: %v", err)
	}
	_, _, matched := m.MatchBot("Googlebot/2.1")
	if matched {
		t.Error("MatchBot: with an empty bot list must return matched=false")
	}
}

// ========================== Task 3.1 — MatchBot =======================================

func TestMatchBot_GoogleUA(t *testing.T) {
	m := mustNewMatcher(t)
	botName, _, matched := m.MatchBot("Googlebot/2.1 (+http://www.google.com/bot.html)")
	if !matched {
		t.Error("MatchBot: Googlebot must match")
	}
	if botName != "google" {
		t.Errorf("MatchBot: expected bot %q, got %q", "google", botName)
	}
}

func TestMatchBot_AdsBotGoogle(t *testing.T) {
	// AdsBot-Google — second pattern for the google bot
	m := mustNewMatcher(t)
	botName, _, matched := m.MatchBot("AdsBot-Google (+http://www.google.com/adsbot.html)")
	if !matched {
		t.Error("MatchBot: AdsBot-Google must match")
	}
	if botName != "google" {
		t.Errorf("MatchBot: expected %q, got %q", "google", botName)
	}
}

func TestMatchBot_Bingbot(t *testing.T) {
	m := mustNewMatcher(t)
	botName, _, matched := m.MatchBot("Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)")
	if !matched {
		t.Error("MatchBot: bingbot must match")
	}
	if botName != "bing" {
		t.Errorf("MatchBot: expected %q, got %q", "bing", botName)
	}
}

func TestMatchBot_BotCfgReturned(t *testing.T) {
	// Verifier (Task 3.2) uses botCfg.RDNSDomains and VerifyMethod —
	// verify that the correct config entry is returned, not a zero struct
	m := mustNewMatcher(t)
	_, botCfg, matched := m.MatchBot("Googlebot/2.1")
	if !matched {
		t.Fatal("MatchBot: Googlebot did not match")
	}
	if len(botCfg.RDNSDomains) == 0 {
		t.Error("MatchBot: botCfg.RDNSDomains must not be empty for google")
	}
}

func TestMatchBot_CurlNotMatched(t *testing.T) {
	// curl — not a legitimate bot, must not match
	m := mustNewMatcher(t)
	_, _, matched := m.MatchBot("curl/8.7.1")
	if matched {
		t.Error("MatchBot: curl must not match")
	}
}

func TestMatchBot_EmptyUA(t *testing.T) {
	m := mustNewMatcher(t)
	_, _, matched := m.MatchBot("")
	if matched {
		t.Error("MatchBot: empty UA must not match")
	}
}

func TestMatchBot_ArbitraryUA(t *testing.T) {
	m := mustNewMatcher(t)
	_, _, matched := m.MatchBot("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	if matched {
		t.Error("MatchBot: a regular browser UA must not match")
	}
}

func TestMatchBot_CaseSensitive(t *testing.T) {
	// "googlebot" in lower case — must not match (pattern "Googlebot" is capitalised)
	// Real Googlebot writes "Googlebot" with a capital G — this is Google's contract.
	m := mustNewMatcher(t)
	_, _, matched := m.MatchBot("googlebot/2.1")
	if matched {
		t.Error("MatchBot: matching must be case-sensitive, 'googlebot' must not match pattern 'Googlebot'")
	}
}

// ========================== Task 3.4 — IsWhitelistedIP ================================

func TestIsWhitelistedIP_ExactMatch(t *testing.T) {
	m := mustNewMatcher(t)
	if !m.IsWhitelistedIP("10.0.0.1") {
		t.Error("IsWhitelistedIP: IP 10.0.0.1 must be in the whitelist")
	}
}

func TestIsWhitelistedIP_ExactNoMatch(t *testing.T) {
	m := mustNewMatcher(t)
	if m.IsWhitelistedIP("10.0.0.2") {
		t.Error("IsWhitelistedIP: IP 10.0.0.2 must not be in the whitelist")
	}
}

func TestIsWhitelistedIP_CIDRMatch(t *testing.T) {
	m := mustNewMatcher(t)
	// 192.168.1.100 is within 192.168.1.0/24
	if !m.IsWhitelistedIP("192.168.1.100") {
		t.Error("IsWhitelistedIP: 192.168.1.100 must be within CIDR 192.168.1.0/24")
	}
}

func TestIsWhitelistedIP_CIDRBoundary(t *testing.T) {
	m := mustNewMatcher(t)
	// .1 — first host in /24 (network address .0 is not a host, but net.IPNet.Contains returns it)
	if !m.IsWhitelistedIP("192.168.1.1") {
		t.Error("IsWhitelistedIP: 192.168.1.1 must be within CIDR 192.168.1.0/24")
	}
	// .254 — last host in /24
	if !m.IsWhitelistedIP("192.168.1.254") {
		t.Error("IsWhitelistedIP: 192.168.1.254 must be within CIDR 192.168.1.0/24")
	}
}

func TestIsWhitelistedIP_CIDRNoMatch(t *testing.T) {
	m := mustNewMatcher(t)
	// 192.168.2.1 — different subnet
	if m.IsWhitelistedIP("192.168.2.1") {
		t.Error("IsWhitelistedIP: 192.168.2.1 must not be within CIDR 192.168.1.0/24")
	}
}

func TestIsWhitelistedIP_InvalidIP(t *testing.T) {
	m := mustNewMatcher(t)
	if m.IsWhitelistedIP("not-an-ip") {
		t.Error("IsWhitelistedIP: invalid IP must not match")
	}
}

func TestIsWhitelistedIP_EmptyIP(t *testing.T) {
	m := mustNewMatcher(t)
	if m.IsWhitelistedIP("") {
		t.Error("IsWhitelistedIP: empty IP must not match")
	}
}

// ========================== Task 3.4 — IsWhitelistedUA ================================

func TestIsWhitelistedUA_Healthcheck(t *testing.T) {
	m := mustNewMatcher(t)
	if !m.IsWhitelistedUA("my-healthcheck/1.0") {
		t.Error("IsWhitelistedUA: UA containing substring 'healthcheck' must match")
	}
}

func TestIsWhitelistedUA_Monitoring(t *testing.T) {
	m := mustNewMatcher(t)
	if !m.IsWhitelistedUA("Prometheus monitoring-agent/2.3") {
		t.Error("IsWhitelistedUA: UA containing substring 'monitoring' must match")
	}
}

func TestIsWhitelistedUA_NoMatch(t *testing.T) {
	m := mustNewMatcher(t)
	if m.IsWhitelistedUA("Mozilla/5.0 (compatible; Googlebot/2.1)") {
		t.Error("IsWhitelistedUA: Googlebot UA does not contain custom substrings")
	}
}

func TestIsWhitelistedUA_EmptyUA(t *testing.T) {
	m := mustNewMatcher(t)
	if m.IsWhitelistedUA("") {
		t.Error("IsWhitelistedUA: empty UA must not match")
	}
}

func TestIsWhitelistedUA_EmptySubstrings(t *testing.T) {
	// No custom UA substrings in config — nothing matches
	cfg := testConfig()
	cfg.Custom.UASubstrings = nil
	m, err := NewMatcher(cfg)
	if err != nil {
		t.Fatalf("NewMatcher: unexpected error: %v", err)
	}
	if m.IsWhitelistedUA("healthcheck") {
		t.Error("IsWhitelistedUA: with empty substring list there must be no matches")
	}
}

// ========================== Flow 049 — IsWhitelistedPath ================================

func TestIsWhitelistedPath_ExactMatch(t *testing.T) {
	cfg := testConfig()
	cfg.Custom.Paths = []string{"/ws"}
	m, err := NewMatcher(cfg)
	if err != nil {
		t.Fatalf("NewMatcher: unexpected error: %v", err)
	}
	if !m.IsWhitelistedPath("/ws") {
		t.Error("IsWhitelistedPath: exact match '/ws' must return true")
	}
}

func TestIsWhitelistedPath_PrefixMatch(t *testing.T) {
	cfg := testConfig()
	cfg.Custom.Paths = []string{"/ws"}
	m, err := NewMatcher(cfg)
	if err != nil {
		t.Fatalf("NewMatcher: unexpected error: %v", err)
	}
	if !m.IsWhitelistedPath("/ws/chat") {
		t.Error("IsWhitelistedPath: prefix match '/ws/chat' must return true")
	}
}

func TestIsWhitelistedPath_QueryMatch(t *testing.T) {
	cfg := testConfig()
	cfg.Custom.Paths = []string{"/ws"}
	m, err := NewMatcher(cfg)
	if err != nil {
		t.Fatalf("NewMatcher: unexpected error: %v", err)
	}
	if !m.IsWhitelistedPath("/ws?token=x") {
		t.Error("IsWhitelistedPath: query match '/ws?token=x' must return true")
	}
}

func TestIsWhitelistedPath_NoMatch(t *testing.T) {
	cfg := testConfig()
	cfg.Custom.Paths = []string{"/ws"}
	m, err := NewMatcher(cfg)
	if err != nil {
		t.Fatalf("NewMatcher: unexpected error: %v", err)
	}
	if m.IsWhitelistedPath("/wstest") {
		t.Error("IsWhitelistedPath: '/wstest' must NOT match '/ws' prefix")
	}
}

func TestIsWhitelistedPath_EmptyPath(t *testing.T) {
	cfg := testConfig()
	cfg.Custom.Paths = []string{"/ws"}
	m, err := NewMatcher(cfg)
	if err != nil {
		t.Fatalf("NewMatcher: unexpected error: %v", err)
	}
	if m.IsWhitelistedPath("") {
		t.Error("IsWhitelistedPath: empty path must return false")
	}
}

func TestIsWhitelistedPath_EmptyPathsConfig(t *testing.T) {
	cfg := testConfig()
	cfg.Custom.Paths = nil
	m, err := NewMatcher(cfg)
	if err != nil {
		t.Fatalf("NewMatcher: unexpected error: %v", err)
	}
	if m.IsWhitelistedPath("/ws") {
		t.Error("IsWhitelistedPath: with empty paths config must return false")
	}
}
