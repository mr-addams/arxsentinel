// ========================== internal/core/chaincheck — checker_test.go =========
//   Tests for Checker: Init, Resolve, health checks.

package chaincheck

import (
	"context"
	"testing"
	"time"
)

// newTestChecker creates a Checker with fallback-only CloudflareChecker and standard BogonChecker.
// No network sources, no background refresh firing during tests.
func newTestChecker(cfEnabled, bogonEnabled bool) *Checker {
	cfg := Config{
		Cloudflare: CloudflareConfig{
			Enabled: cfEnabled,
			// 24h refresh interval — ticker never fires in unit tests.
			RefreshInterval: 0, // zero is fine; goroutine is only started when Enabled=true
		},
		Bogon: BogonConfig{
			Enabled: bogonEnabled,
		},
	}
	// Use a non-zero RefreshInterval only when cloudflare is enabled to avoid
	// a division-by-zero in time.NewTicker.
	if cfEnabled {
		cfg.Cloudflare.RefreshInterval = 24 * time.Hour
	}
	return NewChecker(context.Background(), cfg)
}

func TestChecker_CloudflareWins(t *testing.T) {
	c := newTestChecker(true, true)
	defer c.Close()

	// 104.16.0.1 is in the fallback Cloudflare range 104.16.0.0/13.
	result := c.Check("104.16.0.1")
	if result == nil {
		t.Fatal("Check(104.16.0.1): expected non-nil result, got nil")
	}
	if result.Kind != "cloudflare" {
		t.Errorf("Check(104.16.0.1): expected kind=cloudflare, got %q", result.Kind)
	}
	if result.IP != "104.16.0.1" {
		t.Errorf("Check(104.16.0.1): expected IP=104.16.0.1, got %q", result.IP)
	}
	if result.MatchedCIDR == "" {
		t.Error("Check(104.16.0.1): expected non-empty MatchedCIDR")
	}
}

func TestChecker_BogonWins(t *testing.T) {
	c := newTestChecker(false, true) // Cloudflare disabled, bogon enabled
	defer c.Close()

	result := c.Check("10.0.0.1")
	if result == nil {
		t.Fatal("Check(10.0.0.1): expected non-nil result, got nil")
	}
	if result.Kind != "bogon" {
		t.Errorf("Check(10.0.0.1): expected kind=bogon, got %q", result.Kind)
	}
	if result.MatchedCIDR != "10.0.0.0/8" {
		t.Errorf("Check(10.0.0.1): expected CIDR 10.0.0.0/8, got %q", result.MatchedCIDR)
	}
}

func TestChecker_CleanIP(t *testing.T) {
	c := newTestChecker(true, true)
	defer c.Close()

	// 8.8.8.8 is a legitimate public address — neither CF nor bogon.
	result := c.Check("8.8.8.8")
	if result != nil {
		t.Errorf("Check(8.8.8.8): expected nil, got %+v", result)
	}
}

func TestChecker_EmptyIP(t *testing.T) {
	c := newTestChecker(true, true)
	defer c.Close()

	// Empty string must return nil without panicking.
	result := c.Check("")
	if result != nil {
		t.Errorf("Check(\"\"): expected nil, got %+v", result)
	}
}

func TestChecker_UnparsableIP(t *testing.T) {
	c := newTestChecker(true, true)
	defer c.Close()

	// An unparsable string must return nil without panicking.
	result := c.Check("not-an-ip")
	if result != nil {
		t.Errorf("Check(\"not-an-ip\"): expected nil, got %+v", result)
	}
}

func TestChecker_DisabledCloudflare(t *testing.T) {
	// Cloudflare disabled — known CF IP must not be flagged.
	c := newTestChecker(false, true)
	defer c.Close()

	result := c.Check("104.16.0.1")
	if result != nil {
		t.Errorf("Check(104.16.0.1) with CF disabled: expected nil, got %+v", result)
	}
}

func TestChecker_DisabledBogon(t *testing.T) {
	// Bogon disabled — private range IP must not be flagged.
	c := newTestChecker(true, false)
	defer c.Close()

	result := c.Check("10.0.0.1")
	if result != nil {
		t.Errorf("Check(10.0.0.1) with bogon disabled: expected nil, got %+v", result)
	}
}

func TestChecker_BothDisabled(t *testing.T) {
	c := newTestChecker(false, false)
	defer c.Close()

	// Everything must return nil when both checkers are disabled.
	for _, ip := range []string{"104.16.0.1", "10.0.0.1", "8.8.8.8"} {
		if result := c.Check(ip); result != nil {
			t.Errorf("Check(%s) with both disabled: expected nil, got %+v", ip, result)
		}
	}
}

func TestChecker_NilClose(t *testing.T) {
	// Close on nil Checker must not panic.
	var c *Checker
	c.Close() // should not panic
}
