// ========================== Module whitelist/matcher ====================================
//   UA matching against legitimate bot patterns and custom whitelist by IP/CIDR/UA.
//
//   WHAT IS HERE:
//     - Matcher — struct, initialized once from config
//     - MatchBot(ua) → (botName, botCfg, matched) — Task 3.1
//     - IsWhitelistedIP(ip) bool   — custom whitelist by IP and CIDR — Task 3.4
//     - IsWhitelistedUA(ua) bool   — custom whitelist by UA substring — Task 3.4
//
//   WHAT IS NOT HERE:
//     - DNS verification → verifier.go (Tasks 3.2, 3.5)
//     - Result cache → ipcache.go (Task 3.3)
//
//   MatchBot ALGORITHM:
//     Iterate over bots from config; for each — iterate over UAPatterns.
//     strings.Contains — case-sensitive (bot UAs have a fixed casing).
//     First match wins — bot order in config sets priority.
//
//   IsWhitelistedIP ALGORITHM:
//     1. Exact match in map[string]struct{} — O(1)
//     2. Iterate over pre-compiled *net.IPNet — O(n) by number of CIDRs
//     Pre-compilation in NewMatcher: net.ParseCIDR is called once at startup.
//
//   Implements: Task 3.1 (MatchBot) + Task 3.4 (IsWhitelistedIP, IsWhitelistedUA).

package whitelist

import (
	"fmt"
	"net"
	"strings"

	"github.com/mr-addams/arxsentinel/internal/sys/config"
)

// ========================== Matcher ===================================================

// Matcher holds pre-processed data for fast UA/IP/CIDR matching.
//
// Lifecycle:
//   nil      → before NewMatcher is called
//   *Matcher → after NewMatcher, used until daemon shutdown
//   rebuild  → on SIGHUP (Task 7.1) — a new instance is created from the new config
type Matcher struct {
	bots []config.BotConfig // bot list from config — order defines match priority

	// custom whitelist — pre-processed for O(1) / O(n) lookup
	customIPs    map[string]struct{} // exact IP addresses
	customCIDRs  []*net.IPNet        // pre-compiled subnets
	customUASubs []string            // UA substrings (used in strings.Contains)
}

// NewMatcher creates a Matcher from config.
// Returns an error if any CIDR in whitelist.custom.cidrs is invalid.
// Called from main.go at startup and on SIGHUP.
func NewMatcher(cfg config.WhitelistConfig) (*Matcher, error) {
	// ── CIDR pre-compilation ──────────────────────────────────────────────────────────
	// net.ParseCIDR is called once at startup — expensive parsing removed from hot path.
	cidrs := make([]*net.IPNet, 0, len(cfg.Custom.CIDRs))
	for _, cidr := range cfg.Custom.CIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR in whitelist.custom.cidrs %q: %w", cidr, err)
		}
		cidrs = append(cidrs, ipNet)
	}

	// ── Exact IP index — O(1) lookup ──────────────────────────────────────────────────
	// map[string]struct{} instead of slice: every IP is checked on every log line.
	ips := make(map[string]struct{}, len(cfg.Custom.IPs))
	for _, ip := range cfg.Custom.IPs {
		ips[ip] = struct{}{}
	}

	// Copy slice headers — do not share underlying array with config.
	// On SIGHUP (Task 7.1) a new Matcher is created from the new config;
	// the old Matcher keeps running until the pipeline switches over.
	// Without copying — old and new Matcher would read from the same underlying array.
	// BotConfig contains only strings and []string — Go strings are immutable, deep
	// copy is not needed; only the top-level slice header is copied.
	bots := append([]config.BotConfig(nil), cfg.Bots...)
	uaSubs := append([]string(nil), cfg.Custom.UASubstrings...)

	return &Matcher{
		bots:         bots,
		customIPs:    ips,
		customCIDRs:  cidrs,
		customUASubs: uaSubs,
	}, nil
}

// ========================== Task 3.1 — UA Matcher =====================================

// MatchBot checks the UA against legitimate bot patterns from config.
//
// Returns:
//   botName — bot identifier (e.g. "google", "bing")
//   botCfg  — full bot config record (needed by Verifier for rdns_domains and verify_method)
//   matched — true if a match was found
//
// Algorithm: strings.Contains, case-sensitive — search bot UAs have a fixed casing
// defined in vendor documentation (RFC-like specifications per vendor).
// Empty UA returns matched=false immediately — no need to iterate over patterns.
func (m *Matcher) MatchBot(ua string) (botName string, botCfg config.BotConfig, matched bool) {
	if ua == "" {
		return "", config.BotConfig{}, false
	}
	for _, bot := range m.bots {
		for _, pattern := range bot.UAPatterns {
			if strings.Contains(ua, pattern) {
				return bot.Name, bot, true
			}
		}
	}
	return "", config.BotConfig{}, false
}

// ========================== Task 3.4 — Custom Whitelist ================================

// IsWhitelistedIP returns true if ip is in the custom whitelist (exact IP or CIDR).
//
// Check order:
//   1. Exact match — O(1) map lookup
//   2. CIDR — O(n) over pre-compiled subnets
// Exact check first: most whitelists contain individual IPs, not subnets.
//
// An invalid ip (not parsed by net.ParseIP) does not match any CIDR — returns false.
func (m *Matcher) IsWhitelistedIP(ip string) bool {
	// ── Exact match ───────────────────────────────────────────────────────────────────
	if _, ok := m.customIPs[ip]; ok {
		return true
	}

	// ── CIDR check ────────────────────────────────────────────────────────────────────
	if len(m.customCIDRs) == 0 {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		// Invalid IP cannot belong to any subnet
		return false
	}
	for _, cidr := range m.customCIDRs {
		if cidr.Contains(parsed) {
			return true
		}
	}
	return false
}

// IsWhitelistedUA returns true if ua contains any of the custom UA substrings.
//
// Case-sensitive — custom whitelist assumes precisely known UAs of monitoring tools,
// load balancer health checks, and internal services. Fuzzy matching creates a risk
// of accidentally skipping scanners with a similar UA.
func (m *Matcher) IsWhitelistedUA(ua string) bool {
	if ua == "" {
		return false
	}
	for _, sub := range m.customUASubs {
		if strings.Contains(ua, sub) {
			return true
		}
	}
	return false
}
