// ========================== Tests whitelist/ipcache ====================================
//   Covers Task 3.3: Get (miss, hit, expiry), Set (positive/negative TTL).

package whitelist

import (
	"testing"
	"time"

	"github.com/mr-addams/arxsentinel/internal/sys/config"
)

// testCacheConfig returns a cache config with short TTLs for tests.
// Short TTLs allow verifying expiry without long sleeps.
func testCacheConfig() config.DNSCacheConfig {
	return config.DNSCacheConfig{
		PositiveTTL:   config.Duration(100 * time.Millisecond),
		NegativeTTL:   config.Duration(50 * time.Millisecond),
		IPListRefresh: config.Duration(time.Hour),
	}
}

// ========================== Get — miss ================================================

func TestIPCache_GetMiss_NotFound(t *testing.T) {
	c := NewIPCache(testCacheConfig())
	_, _, ok := c.Get("1.2.3.4")
	if ok {
		t.Error("Get: must return ok=false for a missing IP")
	}
}

// ========================== Set + Get — hit ===========================================

func TestIPCache_SetGet_Verified(t *testing.T) {
	c := NewIPCache(testCacheConfig())
	c.Set("1.2.3.4", true, false)

	verified, isFakeBot, ok := c.Get("1.2.3.4")
	if !ok {
		t.Fatal("Get: must return ok=true after Set")
	}
	if !verified {
		t.Error("Get: must return verified=true")
	}
	if isFakeBot {
		t.Error("Get: must return isFakeBot=false")
	}
}

func TestIPCache_SetGet_NotVerified(t *testing.T) {
	c := NewIPCache(testCacheConfig())
	c.Set("1.2.3.4", false, true)

	verified, isFakeBot, ok := c.Get("1.2.3.4")
	if !ok {
		t.Fatal("Get: must return ok=true after Set")
	}
	if verified {
		t.Error("Get: must return verified=false")
	}
	if !isFakeBot {
		t.Error("Get: must return isFakeBot=true")
	}
}

func TestIPCache_SetGet_IPRanges(t *testing.T) {
	// ip_ranges bot: verified=false, isFakeBot=false — "unknown", no penalty
	c := NewIPCache(testCacheConfig())
	c.Set("1.2.3.4", false, false)

	verified, isFakeBot, ok := c.Get("1.2.3.4")
	if !ok {
		t.Fatal("Get: must return ok=true after Set")
	}
	if verified {
		t.Error("Get: verified=false for ip_ranges bot")
	}
	if isFakeBot {
		t.Error("Get: isFakeBot=false for ip_ranges bot — do not penalize")
	}
}

// ========================== TTL expiry ================================================

func TestIPCache_PositiveTTLExpiry(t *testing.T) {
	c := NewIPCache(testCacheConfig())
	c.Set("1.2.3.4", true, false)

	// Wait for positive TTL to expire (100ms)
	time.Sleep(120 * time.Millisecond)

	_, _, ok := c.Get("1.2.3.4")
	if ok {
		t.Error("Get: entry must expire after positive TTL")
	}
}

func TestIPCache_NegativeTTLExpiry(t *testing.T) {
	c := NewIPCache(testCacheConfig())
	c.Set("1.2.3.4", false, true)

	// Wait for negative TTL to expire (50ms) — it is shorter than positive
	time.Sleep(70 * time.Millisecond)

	_, _, ok := c.Get("1.2.3.4")
	if ok {
		t.Error("Get: negative entry must expire before positive")
	}
}

func TestIPCache_PositiveOutlivesNegative(t *testing.T) {
	// positive TTL=100ms, negative TTL=50ms
	// Verify that the positive entry is still alive when the negative one has expired
	c := NewIPCache(testCacheConfig())
	c.Set("pos.ip", true, false)
	c.Set("neg.ip", false, true)

	time.Sleep(70 * time.Millisecond) // negative expired, positive still alive

	if _, _, ok := c.Get("neg.ip"); ok {
		t.Error("Get: negative entry must expire after 50ms")
	}
	if _, _, ok := c.Get("pos.ip"); !ok {
		t.Error("Get: positive entry must still be alive at 70ms (TTL=100ms)")
	}
}

// ========================== Overwrite =================================================

func TestIPCache_OverwriteEntry(t *testing.T) {
	// Set twice for the same IP — last value wins
	c := NewIPCache(testCacheConfig())
	c.Set("1.2.3.4", false, true)
	c.Set("1.2.3.4", true, false) // overwrite

	verified, isFakeBot, ok := c.Get("1.2.3.4")
	if !ok {
		t.Fatal("Get: must return ok=true")
	}
	if !verified {
		t.Error("Get: must return verified=true after overwrite")
	}
	if isFakeBot {
		t.Error("Get: must return isFakeBot=false after overwrite")
	}
}

// ========================== Lazy expiry removes entry ================================

func TestIPCache_ExpiredEntryRemoved(t *testing.T) {
	// After a Get on an expired entry it must be deleted from the map.
	// Indirect check: a second Get must return ok=false (not the stale value).
	c := NewIPCache(testCacheConfig())
	c.Set("1.2.3.4", true, false)
	time.Sleep(120 * time.Millisecond) // TTL expired

	_, _, ok1 := c.Get("1.2.3.4") // first Get — deletes the expired entry
	_, _, ok2 := c.Get("1.2.3.4") // second Get — miss (entry deleted)

	if ok1 || ok2 {
		t.Error("Get: expired entry must not be returned")
	}
}
