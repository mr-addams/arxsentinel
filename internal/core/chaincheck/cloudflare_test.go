package chaincheck

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newDisabledConfig returns a CloudflareConfig with Enabled=true but no remote sources
// and a very long refresh interval, so the background goroutine never fires during tests.
// Fallback CIDRs are loaded synchronously in NewCloudflareChecker.
func newDisabledSourcesConfig() CloudflareConfig {
	return CloudflareConfig{
		Enabled:         true,
		RefreshInterval: 24 * time.Hour, // long enough that ticker never fires in tests
		Sources:         nil,            // no remote fetch
	}
}

func TestCloudflareChecker_Fallback_KnownIP(t *testing.T) {
	cfg := newDisabledSourcesConfig()
	c := NewCloudflareChecker(context.Background(), cfg)
	defer c.Close()

	// 104.16.0.1 is inside 104.16.0.0/13 — a well-known Cloudflare range.
	matched, cidr := c.Contains(net.ParseIP("104.16.0.1"))
	if !matched {
		t.Fatal("Contains(104.16.0.1): expected true (fallback CF range), got false")
	}
	if cidr != "104.16.0.0/13" {
		t.Errorf("Contains(104.16.0.1): expected CIDR 104.16.0.0/13, got %s", cidr)
	}
}

func TestCloudflareChecker_Fallback_NonCF(t *testing.T) {
	cfg := newDisabledSourcesConfig()
	c := NewCloudflareChecker(context.Background(), cfg)
	defer c.Close()

	// 8.8.8.8 is Google DNS — not a Cloudflare address.
	matched, cidr := c.Contains(net.ParseIP("8.8.8.8"))
	if matched {
		t.Errorf("Contains(8.8.8.8): expected false, got true with CIDR %s", cidr)
	}
}

func TestCloudflareChecker_Fetch_UpdatesRanges(t *testing.T) {
	// httptest server returns a single test CIDR that is not in the fallback list.
	testCIDR := "1.2.3.0/24"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(testCIDR + "\n"))
	}))
	defer srv.Close()

	// Use a very short refresh interval so the first tick fires quickly.
	cfg := CloudflareConfig{
		Enabled:         true,
		RefreshInterval: 50 * time.Millisecond,
		Sources:         []string{srv.URL},
	}
	c := NewCloudflareChecker(context.Background(), cfg)
	defer c.Close()

	// The goroutine does an immediate fetch before the first tick, but we
	// need to give it a moment to complete the HTTP round-trip.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		matched, _ := c.Contains(net.ParseIP("1.2.3.4"))
		if matched {
			return // pass
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("Contains(1.2.3.4): expected true after fetch from test server, still false after 2s")
}

func TestCloudflareChecker_Fetch_KeepsOldOnError(t *testing.T) {
	// Server returns HTTP 500 — simulates a broken upstream source.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := CloudflareConfig{
		Enabled:         true,
		RefreshInterval: 50 * time.Millisecond,
		Sources:         []string{srv.URL},
	}
	c := NewCloudflareChecker(context.Background(), cfg)
	defer c.Close()

	// Give the goroutine time to attempt a fetch and fail.
	time.Sleep(200 * time.Millisecond)

	// Fallback CIDRs must still be intact — 104.16.0.1 must still match.
	matched, _ := c.Contains(net.ParseIP("104.16.0.1"))
	if !matched {
		t.Error("Contains(104.16.0.1): expected true (fallback preserved after failed fetch), got false")
	}
}

func TestCloudflareChecker_InvalidIP(t *testing.T) {
	cfg := newDisabledSourcesConfig()
	c := NewCloudflareChecker(context.Background(), cfg)
	defer c.Close()

	// Nil IP must never panic and must return false.
	matched, cidr := c.Contains(nil)
	if matched || cidr != "" {
		t.Errorf("Contains(nil): expected (false, \"\"), got (%v, %q)", matched, cidr)
	}
}

func TestCloudflareChecker_IsLoaded(t *testing.T) {
	cfg := newDisabledSourcesConfig()
	c := NewCloudflareChecker(context.Background(), cfg)
	defer c.Close()

	// IsLoaded must be true immediately after construction — no network request needed.
	if !c.IsLoaded() {
		t.Error("IsLoaded(): expected true after NewCloudflareChecker, got false")
	}
}
