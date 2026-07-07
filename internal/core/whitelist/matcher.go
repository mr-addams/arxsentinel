// ========================== Module whitelist/matcher ====================================
//
//	UA matching against legitimate bot patterns and custom whitelist by IP/CIDR/UA.
//
//	WHAT IS HERE:
//	  - Matcher — struct, initialized once from config
//	  - MatchBot(ua) → (botName, botCfg, matched) — Task 3.1
//	  - IsWhitelistedIP(ip) bool   — custom whitelist by IP and CIDR — Task 3.4
//	  - IsWhitelistedUA(ua) bool   — custom whitelist by UA substring — Task 3.4
//	  - IsWhitelistedPath(path) bool — custom whitelist by URL path prefix — Flow 049
//
//	WHAT IS NOT HERE:
//	  - DNS verification → verifier.go (Tasks 3.2, 3.5)
//	  - Result cache → ipcache.go (Task 3.3)
//
//	MatchBot ALGORITHM:
//	  Iterate over bots from config; for each — iterate over UAPatterns.
//	  strings.Contains — case-sensitive (bot UAs have a fixed casing).
//	  First match wins — bot order in config sets priority.
//
//	IsWhitelistedIP ALGORITHM:
//	  1. Exact match in map[string]struct{} — O(1)
//	  2. Iterate over pre-compiled *net.IPNet — O(n) by number of CIDRs
//	  Pre-compilation in NewMatcher: net.ParseCIDR is called once at startup.
//
//	Implements: Task 3.1 (MatchBot) + Task 3.4 (IsWhitelistedIP, IsWhitelistedUA).
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
// YAML: whitelist.bots[], whitelist.custom.*
// Consumer: matcher.go (MatchBot, IsWhitelisted*), verifier.go (via Verifier).
type Matcher struct {
	bots []config.BotConfig // YAML: whitelist.bots[] — bot list, order defines match priority. Consumer: MatchBot.

	// custom whitelist — pre-processed for O(1) / O(n) lookup
	customIPs    map[string]struct{} // YAML: whitelist.custom.ips[] — exact IP whitelist. Consumer: IsWhitelistedIP.
	customCIDRs  []*net.IPNet        // YAML: whitelist.custom.cidrs[] — pre-compiled CIDRs. Consumer: IsWhitelistedIP.
	customUASubs []string            // YAML: whitelist.custom.ua_substrings[] — UA substring whitelist. Consumer: IsWhitelistedUA.
	customPaths  []string            // YAML: whitelist.custom.paths[] — path prefix whitelist. Consumer: IsWhitelistedPath.
}

// NewMatcher creates a Matcher from config.
// Returns an error if any CIDR in whitelist.custom.cidrs is invalid.
//
// Called from: cmd/arxsentinel.main (pipeline setup), SIGHUP handler (Task 7.1).
// Non-blocking.
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
	paths := append([]string(nil), cfg.Custom.Paths...)

	return &Matcher{
		bots:         bots,
		customIPs:    ips,
		customCIDRs:  cidrs,
		customUASubs: uaSubs,
		customPaths:  paths,
	}, nil
}

// ========================== Task 3.1 — UA Matcher =====================================

// MatchBot checks the UA against legitimate bot patterns from config.
// Algorithm: strings.Contains, case-sensitive — bot UAs have fixed casing in vendor docs.
// Empty UA returns matched=false immediately.
//
// Called from: verifier.go (DNS verification loop).
// Non-blocking.
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
// Check order: exact match (O(1)) → CIDR check (O(n)). Exact check first.
//
// Called from: verifier.go (DNS verification loop).
// Non-blocking.
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
// Case-sensitive — custom whitelist assumes precisely known UAs.
//
// Called from: verifier.go (DNS verification loop).
// Non-blocking.
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

// IsWhitelistedPath returns true if path matches any entry in whitelist.custom.paths.
// Exact prefix match: path must START WITH the configured entry.
//
// Called from: verifier.go (DNS verification loop).
// Non-blocking.
func (m *Matcher) IsWhitelistedPath(path string) bool {
	if path == "" {
		return false
	}
	for _, p := range m.customPaths {
		if p == "" {
			continue
		}
		if path == p || strings.HasPrefix(path, p+"/") || strings.HasPrefix(path, p+"?") {
			return true
		}
	}
	return false
}
