// ========================== Module whitelist/verifier ===================================
//   rDNS + fDNS verification of legitimate bots (Googlebot, Bingbot, etc.).
//   Fake bot detection: UA matched a bot pattern, but DNS verification failed.
//
//   WHAT IS HERE:
//     - Resolver — interface for DNS lookups (injected for testability)
//     - Verifier — struct with cache and injected Resolver
//     - Verify(ctx, ip, botCfg) → (verified, isFakeBot) — Task 3.2
//     - isFakeBot=true → caller adds FakeBotScore — Task 3.5
//
//   WHAT IS NOT HERE:
//     - UA matching → matcher.go
//     - Cache TTL → ipcache.go
//
//   VERIFY ALGORITHM (method "rdns" and "rdns_ipjson"):
//     1. Cache hit? → return immediately
//     2. PTR lookup (rDNS): ip → hostname
//     3. Check hostname suffix against botCfg.RDNSDomains
//     4. A/AAAA lookup (fDNS): hostname → IPs
//     5. Confirm the original IP is among the A/AAAA responses
//     6. Store result in cache, return
//
//   METHOD "ip_ranges":
//     Stub: returns verified=true without DNS.
//     Facebook/Twitter/Telegram publish IP ranges — implementation in v0.2+.
//
//   FAKE BOT (Task 3.5):
//     Verify is called only when MatchBot returned matched=true.
//     If verified=false — this is a fake bot: UA matched, DNS failed.
//     isFakeBot=true signals the pipeline to add cfg.Whitelist.FakeBotScore to the IP score.
//
//   Implements: Task 3.2 (Verify) + Task 3.5 (isFakeBot).

package whitelist

import (
	"context"
	"strings"

	"github.com/mr-addams/arxsentinel/internal/sys/config"
)

// ========================== Resolver interface =========================================

// Resolver abstracts DNS lookups for testability.
// *net.Resolver satisfies this interface without modification.
//
// Injected via NewVerifier — production passes &net.Resolver{PreferGo: true},
// tests pass a mockResolver with pre-defined responses.
type Resolver interface {
	// LookupAddr performs a PTR lookup (rDNS): IP → list of hostnames.
	// addr is passed as "1.2.3.4" or "2001:db8::1".
	LookupAddr(ctx context.Context, addr string) ([]string, error)

	// LookupHost performs an A/AAAA lookup (fDNS): hostname → list of IPs.
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// ========================== Verifier ==================================================

// Verifier performs rDNS+fDNS verification of legitimate bot IP addresses.
//
// Lifecycle:
//   nil       → before NewVerifier is called
//   *Verifier → after NewVerifier, used for the daemon's lifetime
//   on SIGHUP (Task 7.1) — a new instance is created with the same cache (cache survives reload)
type Verifier struct {
	cache    *IPCache
	resolver Resolver
	logFn    func(tag, msg, level string) // injected from main.go — core/ does not import sys/utils
}

// NewVerifier creates a Verifier.
// cache is passed from outside — on SIGHUP the cache is preserved (not reset on config reload).
// resolver — *net.Resolver{PreferGo: true} in production, mock in tests.
// logFn — utils.Log from main.go.
func NewVerifier(cache *IPCache, resolver Resolver, logFn func(tag, msg, level string)) *Verifier {
	return &Verifier{
		cache:    cache,
		resolver: resolver,
		logFn:    logFn,
	}
}

// ========================== Verify ====================================================

// Verify checks whether ip is a legitimate bot according to botCfg.VerifyMethod.
//
// Called from the pipeline ONLY when MatchBot returned matched=true — meaning the UA
// already matched a bot pattern. Verify's job is to confirm or refute via DNS.
//
// Returns:
//   verified  — true if the IP passed DNS verification (legitimate bot)
//   isFakeBot — true if UA matched a bot but DNS failed (Task 3.5)
//               the pipeline must add cfg.Whitelist.FakeBotScore to the IP score
//
// Order: cache → DNS → cache.Set (only for rdns/rdns_ipjson) → return.
// A cache hit avoids DNS lookups on every log line for the same IP.
func (v *Verifier) Verify(ctx context.Context, ip string, botCfg config.BotConfig) (verified bool, isFakeBot bool) {
	// ── Cache hit ─────────────────────────────────────────────────────────────────────
	// isFakeBot is read directly from cache — cannot be derived from !verified:
	// for ip_ranges bots verified=false means "not checked", isFakeBot=false.
	if cachedVerified, cachedIsFakeBot, ok := v.cache.Get(ip); ok {
		return cachedVerified, cachedIsFakeBot
	}

	// ── DNS verification ──────────────────────────────────────────────────────────────
	switch botCfg.VerifyMethod {
	case "rdns", "rdns_ipjson":
		// rdns_ipjson differs only by checking IP ranges via the Google JSON API.
		// HTTP client for this — v0.2+. For now rdns_ipjson is handled as rdns.
		verified = v.verifyRDNS(ctx, ip, botCfg)
		// UA matched a bot pattern (Verify is only called when matched=true),
		// DNS failed → this is a fake bot → add FakeBotScore.
		isFakeBot = !verified
		// Cache the real DNS result — repeated lookups are not needed.
		v.cache.Set(ip, verified, isFakeBot)
	case "ip_ranges":
		// KNOWN LIMITATION (v0.2+): IP ranges for Facebook/Twitter/Telegram require
		// an HTTP client to download up-to-date ranges.
		// Until implemented — return verified=false, isFakeBot=false ("unknown"):
		//   verified=true  would be a lie — ranges were not checked.
		//   isFakeBot=true would be an unfair penalty — a real Facebook bot
		//   should not get FakeBotScore just because the feature is not yet implemented.
		//
		// Not cached: after ip_ranges is implemented in v0.2, cached (false,false)
		// with negative TTL would block verification of legitimate bots until TTL expires.
		verified = false
		isFakeBot = false
	default:
		// Unknown method — do not verify, do not penalize (broken config, not an attack).
		// Not cached: the result is meaningless, not worth keeping in cache.
		if v.logFn != nil {
			v.logFn("WHITELIST", "unknown verify_method: "+botCfg.VerifyMethod+" for bot "+botCfg.Name, "warn")
		}
		verified = false
		isFakeBot = false
	}

	return verified, isFakeBot
}

// ========================== rDNS verification =========================================

// verifyRDNS performs two-step DNS verification:
//   Step 1 (rDNS): IP → PTR → hostname
//   Step 2 (fDNS): hostname → A/AAAA → must contain the original IP
//
// Both steps are required: PTR alone is insufficient — anyone can set a PTR record
// for their own IP. The reverse check (fDNS) confirms the host actually resolves
// back to this IP.
//
// Additionally, the hostname suffix is checked against botCfg.RDNSDomains:
//   Googlebot → ".googlebot.com" or ".google.com"
//   Bingbot   → ".search.msn.com"
// Without this check an attacker could create PTR "evil.com" → IP,
// A: IP → "evil.com", and pass the double check without being Googlebot.
func (v *Verifier) verifyRDNS(ctx context.Context, ip string, botCfg config.BotConfig) bool {
	// ── Step 1: PTR lookup ────────────────────────────────────────────────────────────
	hostnames, err := v.resolver.LookupAddr(ctx, ip)
	if err != nil || len(hostnames) == 0 {
		if v.logFn != nil {
			v.logFn("WHITELIST", "PTR fail for "+ip+": no PTR record", "debug")
		}
		return false
	}

	// Iterate over all PTR records — an IP may have multiple hostnames.
	// One valid hostname is sufficient for verification to pass.
	for _, hostname := range hostnames {
		// Normalize: net.LookupAddr returns hostnames with a trailing dot ("foo.google.com.")
		hostname = strings.TrimSuffix(hostname, ".")

		// ── Check rDNS domain suffix ───────────────────────────────────────────────────
		if !matchesRDNSDomain(hostname, botCfg.RDNSDomains) {
			continue
		}

		// ── Step 2: A/AAAA lookup (fDNS) ──────────────────────────────────────────────
		addrs, err := v.resolver.LookupHost(ctx, hostname)
		if err != nil {
			if v.logFn != nil {
				v.logFn("WHITELIST", "fDNS fail for "+hostname+": "+err.Error(), "debug")
			}
			continue
		}

		// Confirm the original IP is among the A/AAAA responses
		for _, addr := range addrs {
			if addr == ip {
				if v.logFn != nil {
					v.logFn("WHITELIST", "verified "+ip+" as "+botCfg.Name+" ("+hostname+")", "debug")
				}
				return true
			}
		}
	}

	if v.logFn != nil {
		v.logFn("WHITELIST", "verification failed for "+ip+" (bot: "+botCfg.Name+")", "debug")
	}
	return false
}

// matchesRDNSDomain checks that hostname ends with one of the allowed rDNS suffixes.
//
// Suffix normalization: prepend a leading dot if absent.
// Without a dot, "evilgooglebot.com" would match the suffix "googlebot.com".
// The default config is correct (with dot), but normalization guards against operator typos.
//
// Empty RDNSDomains list (as for ip_ranges bots) — the method is not called for them,
// but there is a safety check: empty list → false (do not pass without checking).
func matchesRDNSDomain(hostname string, domains []string) bool {
	for _, domain := range domains {
		if !strings.HasPrefix(domain, ".") {
			domain = "." + domain
		}
		if strings.HasSuffix(hostname, domain) {
			return true
		}
	}
	return false
}
