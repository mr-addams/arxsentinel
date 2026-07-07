// ========================== Module whitelist/ipcache ====================================
//
//	Cache of DNS verification results with separate TTLs for positive/negative results.
//	Prevents repeated DNS lookups for already-verified IPs.
//
//	WHAT IS HERE:
//	  - IPCache — in-memory cache with TTL expiry
//	  - Positive TTL (verified=true) >> Negative TTL (verified=false)
//	  - Lazy expiry: expired entries are removed on Get, not by a background goroutine
//
//	WHAT IS NOT HERE:
//	  - DNS lookups → verifier.go
//	  - UA/IP matching → matcher.go
//
//	LAZY EXPIRY vs background GC:
//	  IPCache stores only bots — hundreds of IPs, not thousands.
//	  A background goroutine adds complexity (shutdown, sync) without meaningful benefit.
//	  Expired entries are evicted on the next Get — sufficient at this scale.
//
//	Implements: Task 3.3.
package whitelist

import (
	"sync"
	"time"

	"github.com/mr-addams/arxsentinel/internal/sys/config"
)

// ========================== IPCache ===================================================

// cacheEntry stores verification result and expiry time for one IP.
//
// Internal — not in config. Consumer: IPCache.Get, IPCache.Set.
type cacheEntry struct {
	verified  bool      // Internal — DNS verification result. Consumer: Get, Set.
	isFakeBot bool      // Internal — true if bot is fake/harvester. Consumer: Get, Set.
	expiresAt time.Time // Internal — expiry timestamp. Consumer: Get.
}

// IPCache caches DNS verification results for bot IP addresses.
//
// YAML: whitelist.dns_cache.positive_ttl, whitelist.dns_cache.negative_ttl.
// Consumer: verifier.go (Get/Set), matcher.go (via Verifier).
type IPCache struct {
	mu          sync.RWMutex
	entries     map[string]cacheEntry // Internal — IP to cacheEntry map. Consumer: Get, Set.
	positiveTTL time.Duration         // YAML: whitelist.dns_cache.positive_ttl, default 24h. Consumer: Set.
	negativeTTL time.Duration         // YAML: whitelist.dns_cache.negative_ttl, default 5m. Consumer: Set.
}

// NewIPCache creates an IPCache from config.
//
// Called from: cmd/arxsentinel.main (pipeline setup), SIGHUP handler (Task 7.1).
// Non-blocking.
func NewIPCache(cfg config.DNSCacheConfig) *IPCache {
	return &IPCache{
		entries:     make(map[string]cacheEntry),
		positiveTTL: time.Duration(cfg.PositiveTTL),
		negativeTTL: time.Duration(cfg.NegativeTTL),
	}
}

// ========================== Get =======================================================

// Get returns the verification result from cache.
// ok=false means a cache miss: entry is absent or expired.
// On an expired entry — delete it under write lock so the next request does not find it again.
//
// Called from: verifier.go (DNS verification loop).
// Non-blocking: uses two-phase locking (RLock → Lock on expiry only).
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
// Positive TTL (verified=true) >> negative TTL (verified=false).
// isFakeBot is stored explicitly — not derived from !verified on Get.
//
// Called from: verifier.go (DNS verification loop).
// Non-blocking.
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
