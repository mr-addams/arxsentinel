// ========================== Tests whitelist/verifier ===================================
//   Covers Task 3.2 (Verify, rDNS verification) and Task 3.5 (isFakeBot).
//
//   All DNS queries go through mockResolver — tests are deterministic, no network required.

package whitelist

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mr-addams/arxsentinel/internal/sys/config"
)

// ========================== Mock Resolver =============================================

// mockResolver implements Resolver with pre-defined responses.
// addrs: ip → list of PTR hostnames (rDNS)
// hosts: hostname → list of IPs (fDNS)
// Missing key → "not found" error.
type mockResolver struct {
	addrs map[string][]string
	hosts map[string][]string
}

func (m *mockResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	if hostnames, ok := m.addrs[addr]; ok {
		return hostnames, nil
	}
	return nil, errors.New("no PTR record for " + addr)
}

func (m *mockResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if ips, ok := m.hosts[host]; ok {
		return ips, nil
	}
	return nil, errors.New("no A record for " + host)
}

// ========================== Fixtures ==================================================

// googleBotCfg — Googlebot config entry for tests.
var googleBotCfg = config.BotConfig{
	Name:         "google",
	UAPatterns:   []string{"Googlebot"},
	RDNSDomains:  []string{".googlebot.com", ".google.com"},
	VerifyMethod: "rdns",
}

// ipRangesBotCfg — bot with method=ip_ranges (Facebook/Twitter).
var ipRangesBotCfg = config.BotConfig{
	Name:         "facebook",
	UAPatterns:   []string{"facebookexternalhit"},
	RDNSDomains:  []string{},
	VerifyMethod: "ip_ranges",
}

// testIPCacheForVerifier creates a cache with long TTL — must not expire during the test.
func testIPCacheForVerifier() *IPCache {
	return NewIPCache(config.DNSCacheConfig{
		PositiveTTL:   config.Duration(time.Hour),
		NegativeTTL:   config.Duration(time.Hour),
		IPListRefresh: config.Duration(time.Hour),
	})
}

// ========================== Task 3.2 — Verify rDNS ====================================

func TestVerify_LegitimateGooglebot(t *testing.T) {
	// Scenario: genuine Googlebot — PTR → "crawl-66-249-66-1.googlebot.com.",
	// fDNS confirms the IP.
	resolver := &mockResolver{
		addrs: map[string][]string{
			"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."},
		},
		hosts: map[string][]string{
			"crawl-66-249-66-1.googlebot.com": {"66.249.66.1"},
		},
	}
	v := NewVerifier(testIPCacheForVerifier(), resolver, nil)

	verified, isFakeBot := v.Verify(context.Background(), "66.249.66.1", googleBotCfg)

	if !verified {
		t.Error("Verify: legitimate Googlebot must be verified=true")
	}
	if isFakeBot {
		t.Error("Verify: legitimate Googlebot must not be isFakeBot=true")
	}
}

func TestVerify_NoPTRRecord(t *testing.T) {
	// Scenario: arbitrary IP without a PTR record — not a bot.
	resolver := &mockResolver{
		addrs: map[string][]string{},
		hosts: map[string][]string{},
	}
	v := NewVerifier(testIPCacheForVerifier(), resolver, nil)

	verified, isFakeBot := v.Verify(context.Background(), "1.2.3.4", googleBotCfg)

	if verified {
		t.Error("Verify: IP without PTR must not be verified")
	}
	if !isFakeBot {
		t.Error("Verify: UA matched but DNS failed → isFakeBot=true (Task 3.5)")
	}
}

func TestVerify_PTRWrongDomain(t *testing.T) {
	// Scenario: PTR exists but hostname is not in googlebot.com / google.com
	resolver := &mockResolver{
		addrs: map[string][]string{
			"1.2.3.4": {"host.evil.com."},
		},
		hosts: map[string][]string{
			"host.evil.com": {"1.2.3.4"},
		},
	}
	v := NewVerifier(testIPCacheForVerifier(), resolver, nil)

	verified, isFakeBot := v.Verify(context.Background(), "1.2.3.4", googleBotCfg)

	if verified {
		t.Error("Verify: hostname outside rdns_domains must not be verified")
	}
	if !isFakeBot {
		t.Error("Verify: DNS fail → isFakeBot=true")
	}
}

func TestVerify_PTRCorrectDomainButFDNSMismatch(t *testing.T) {
	// Scenario: PTR points to googlebot.com but fDNS returns a different IP.
	// Classic attack: set PTR to googlebot.com for an attacker's IP,
	// but the fDNS of the host does not contain the attacker's IP.
	resolver := &mockResolver{
		addrs: map[string][]string{
			"1.2.3.4": {"crawl-66-249-66-1.googlebot.com."},
		},
		hosts: map[string][]string{
			"crawl-66-249-66-1.googlebot.com": {"66.249.66.1"}, // different IP!
		},
	}
	v := NewVerifier(testIPCacheForVerifier(), resolver, nil)

	verified, isFakeBot := v.Verify(context.Background(), "1.2.3.4", googleBotCfg)

	if verified {
		t.Error("Verify: fDNS mismatch — IP must not be verified")
	}
	if !isFakeBot {
		t.Error("Verify: isFakeBot=true on fDNS mismatch")
	}
}

func TestVerify_MultiplePTR_OneValid(t *testing.T) {
	// Scenario: multiple PTR records, one of them valid.
	// One valid record is sufficient for verification to pass.
	resolver := &mockResolver{
		addrs: map[string][]string{
			"66.249.66.1": {
				"host.evil.com.",
				"crawl-66-249-66-1.googlebot.com.", // valid
			},
		},
		hosts: map[string][]string{
			"crawl-66-249-66-1.googlebot.com": {"66.249.66.1"},
		},
	}
	v := NewVerifier(testIPCacheForVerifier(), resolver, nil)

	verified, isFakeBot := v.Verify(context.Background(), "66.249.66.1", googleBotCfg)

	if !verified {
		t.Error("Verify: with at least one valid PTR record — must be verified")
	}
	if isFakeBot {
		t.Error("Verify: verified=true → isFakeBot=false")
	}
}

// ========================== Task 3.2 — ip_ranges method ================================

func TestVerify_IPRangesMethod(t *testing.T) {
	// ip_ranges stub: verified=false, isFakeBot=false ("unknown").
	// Do not penalize a real Facebook bot until HTTP client is implemented (v0.2+).
	resolver := &mockResolver{} // DNS must not be called
	v := NewVerifier(testIPCacheForVerifier(), resolver, nil)

	verified, isFakeBot := v.Verify(context.Background(), "69.63.176.1", ipRangesBotCfg)

	if verified {
		t.Error("Verify: ip_ranges stub must return verified=false (not checked)")
	}
	if isFakeBot {
		t.Error("Verify: ip_ranges stub must return isFakeBot=false (do not penalize)")
	}
}

func TestVerify_UnknownMethod(t *testing.T) {
	// Unknown method — broken config, not an attack → verified=false, isFakeBot=false.
	cfg := config.BotConfig{
		Name:         "unknown",
		VerifyMethod: "magic",
	}
	resolver := &mockResolver{}
	v := NewVerifier(testIPCacheForVerifier(), resolver, nil)

	verified, isFakeBot := v.Verify(context.Background(), "1.2.3.4", cfg)

	if verified {
		t.Error("Verify: unknown method → verified=false")
	}
	if isFakeBot {
		t.Error("Verify: unknown method — broken config, not an attack → isFakeBot=false")
	}
}

// ========================== Task 3.2 — cache ============================================

func TestVerify_CacheHit_NoSecondDNS(t *testing.T) {
	// After the first Verify the cache must contain the result.
	// The second call must not touch the resolver (DNS is not called again).
	callCount := 0
	resolver := &mockResolver{
		addrs: map[string][]string{
			"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."},
		},
		hosts: map[string][]string{
			"crawl-66-249-66-1.googlebot.com": {"66.249.66.1"},
		},
	}

	// Wrapper for counting LookupAddr calls
	counting := &countingResolver{inner: resolver, count: &callCount}
	v := NewVerifier(testIPCacheForVerifier(), counting, nil)

	v.Verify(context.Background(), "66.249.66.1", googleBotCfg) // first — DNS
	v.Verify(context.Background(), "66.249.66.1", googleBotCfg) // second — cache

	if callCount != 1 {
		t.Errorf("Verify: LookupAddr must be called 1 time, called %d times", callCount)
	}
}

// countingResolver wraps mockResolver and counts LookupAddr calls.
type countingResolver struct {
	inner *mockResolver
	count *int
}

func (c *countingResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	*c.count++
	return c.inner.LookupAddr(ctx, addr)
}

func (c *countingResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return c.inner.LookupHost(ctx, host)
}

// ========================== Task 3.5 — Fake Bot ========================================

func TestVerify_FakeGooglebot_NoPTR(t *testing.T) {
	// Main scenario for Task 3.5: UA = "Googlebot" but IP does not verify.
	// isFakeBot=true — pipeline must add FakeBotScore.
	resolver := &mockResolver{} // no PTR for any IP
	v := NewVerifier(testIPCacheForVerifier(), resolver, nil)

	verified, isFakeBot := v.Verify(context.Background(), "185.177.72.23", googleBotCfg)

	if verified {
		t.Error("FakeBot: arbitrary IP must not be verified as Googlebot")
	}
	if !isFakeBot {
		t.Error("FakeBot: UA=Googlebot + DNS fail → isFakeBot=true")
	}
}

func TestVerify_FakeGooglebot_CachedResult(t *testing.T) {
	// After the first Verify(false) → cache stores verified=false.
	// Second Verify must return from cache verified=false, isFakeBot=true.
	resolver := &mockResolver{}
	v := NewVerifier(testIPCacheForVerifier(), resolver, nil)

	v.Verify(context.Background(), "185.177.72.23", googleBotCfg) // populates the cache
	verified, isFakeBot := v.Verify(context.Background(), "185.177.72.23", googleBotCfg)

	if verified {
		t.Error("FakeBot cached: must return verified=false")
	}
	if !isFakeBot {
		t.Error("FakeBot cached: cache verified=false → isFakeBot=true")
	}
}

// ========================== Test: matchesRDNSDomain normalization ========================

func TestMatchesRDNSDomain_NormalizesLeadingDot(t *testing.T) {
	// Suffixes without a leading dot must be normalized:
	//   "googlebot.com" → ".googlebot.com"
	// Without normalization "evilgooglebot.com" would match the suffix "googlebot.com".

	// Legitimate hostname — must match even if the suffix has no leading dot
	if !matchesRDNSDomain("crawl-66-249-66-1.googlebot.com", []string{"googlebot.com"}) {
		t.Error("legitimate googlebot.com must match suffix without leading dot")
	}

	// Malicious hostname — must NOT match
	if matchesRDNSDomain("crawl.evilgooglebot.com", []string{"googlebot.com"}) {
		t.Error("evilgooglebot.com must not match suffix googlebot.com")
	}

	// With leading dot — original behaviour is preserved
	if !matchesRDNSDomain("crawl-66-249-66-1.googlebot.com", []string{".googlebot.com"}) {
		t.Error("legitimate googlebot.com must match suffix .googlebot.com")
	}
	if matchesRDNSDomain("crawl.evilgooglebot.com", []string{".googlebot.com"}) {
		t.Error("evilgooglebot.com must not match suffix .googlebot.com")
	}
}
