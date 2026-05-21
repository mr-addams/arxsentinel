// ========================== Module whitelist/ipcache ====================================
//   Cache of DNS verification results with separate TTLs for positive/negative results.
//   Prevents repeated DNS lookups for already-verified IPs.
//
//   WHAT IS HERE:
//     - IPCache — in-memory cache with TTL expiry
//     - Positive TTL (verified=true) >> Negative TTL (verified=false)
//     - Lazy expiry: expired entries are removed on Get, not by a background goroutine
//
//   WHAT IS NOT HERE:
//     - DNS lookups → verifier.go
//     - UA/IP matching → matcher.go
//
//   LAZY EXPIRY vs background GC:
//     IPCache stores only bots — hundreds of IPs, not thousands.
//     A background goroutine adds complexity (shutdown, sync) without meaningful benefit.
//     Expired entries are evicted on the next Get — sufficient at this scale.
//
//   Implements: Task 3.3.

package whitelist

import (
	"sync"
	"time"

	"github.com/mr-addams/arxsentinel/internal/sys/config"
)

// ========================== IPCache ===================================================

// cacheEntry — a single cache record: verification result + expiry time.
// isFakeBot is stored explicitly — cannot be inferred from !verified:
// for ip_ranges bots verified=false means "not checked", not "DNS failed".
type cacheEntry struct {
	verified  bool
	isFakeBot bool
	expiresAt time.Time
}

// IPCache caches DNS verification results for bot IP addresses.
//
// Entry lifecycle:
//   miss      → Get returns ok=false → Verifier performs DNS lookup → Set
//   hit       → Get returns verified, ok=true
//   expired   → Get removes the entry, returns ok=false → re-verification
type IPCache struct {
	mu          sync.RWMutex
	entries     map[string]cacheEntry
	positiveTTL time.Duration // TTL for verified=true (legitimate bot)
	negativeTTL time.Duration // TTL for verified=false (fake or unknown)
}

// NewIPCache creates an IPCache from config.
// Called from main.go at startup and on SIGHUP (Task 7.1).
func NewIPCache(cfg config.DNSCacheConfig) *IPCache {
	return &IPCache{
		entries:     make(map[string]cacheEntry),
		positiveTTL: time.Duration(cfg.PositiveTTL),
		negativeTTL: time.Duration(cfg.NegativeTTL),
	}
}

// ========================== Get =======================================================

// Get returns the verification result from cache.
//
// ok=false means a cache miss: entry is absent or expired.
// On an expired entry — delete it under write lock so the next request
// does not find it again (lazy expiry).
//
// Two-phase lock (RLock → Lock on expiry):
//   Most calls — hit on a live entry → only RLock.
//   Only on expiry do we upgrade to write lock — a rare case.
func (c *IPCache) Get(ip string) (verified bool, isFakeBot bool, ok bool) {
	// ── Fast path: read lock ───────────────────────────────────────────────────────────
	c.mu.RLock()
	entry, found := c.entries[ip]
	c.mu.RUnlock()

	if !found {
		return false, false, false
	}

	if !time.Now().After(entry.expiresAt) {
		return entry.verified, entry.isFakeBot, true
	}

	// ── Slow path: entry found but expired — delete under write lock ──────────────────
	c.mu.Lock()
	// Re-check after acquiring write lock: between RUnlock and Lock
	// a concurrent Set may have updated the entry with a new expiresAt — don't delete a live entry.
	// If the entry is live — return the fresh value instead of a miss (TOCTOU fix).
	if e, still := c.entries[ip]; still {
		if !time.Now().After(e.expiresAt) {
			// Set managed to update the entry — return the fresh value instead of miss.
			c.mu.Unlock()
			return e.verified, e.isFakeBot, true
		}
		delete(c.entries, ip)
	}
	c.mu.Unlock()
	return false, false, false
}

// ========================== Set =======================================================

// Set stores the verification result in cache with a TTL depending on verified.
//
// Positive TTL (verified=true) is larger than negative (verified=false):
//   - A legitimate bot rarely changes IP → long cache reduces DNS load.
//   - Fake or unknown IP → short cache, so a retry re-verifies
//     (the IP may have moved to a legitimate bot).
//
// isFakeBot is stored explicitly — not derived from !verified on Get.
// This matters for ip_ranges bots: verified=false there means "not checked",
// not "DNS failed", so isFakeBot must be false for them.
func (c *IPCache) Set(ip string, verified bool, isFakeBot bool) {
	ttl := c.negativeTTL
	if verified {
		ttl = c.positiveTTL
	}

	c.mu.Lock()
	c.entries[ip] = cacheEntry{
		verified:  verified,
		isFakeBot: isFakeBot,
		expiresAt: time.Now().Add(ttl),
	}
	c.mu.Unlock()
}
