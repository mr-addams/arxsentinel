// ========================== Module chaincheck ============================================
//   Chain integrity detection: identifies Cloudflare or bogon IPs appearing as the
//   client IP in access logs, which signals infrastructure misconfiguration.
//   When a proxy chain is broken (e.g. real_ip_header not configured), all IP-based
//   detectors in ArxSentinel become blind — they score the wrong address.
//
//   WHAT IS HERE:
//     Checker       — orchestrates CloudflareChecker and BogonChecker per log entry
//     Config        — top-level configuration (Cloudflare + Bogon sub-sections)
//     BogonConfig   — enable/disable flag for bogon detection
//     CheckResult   — what was found: kind, ip, matched_cidr
//
//   WHAT IS NOT HERE:
//     Output writing — handled by the caller in the stream processing loop (main.go)
//     Detector pipeline — Checker does not implement detector.Detector;
//       it runs before the detector pipeline, not inside it

package chaincheck

import (
	"context"
	"net"
)

// CheckResult describes a single chain-integrity finding.
// Kind is always "cloudflare" or "bogon".
type CheckResult struct {
	Kind        string // "cloudflare" | "bogon"
	IP          string
	MatchedCIDR string // e.g. "104.16.0.0/13"
}

// BogonConfig holds the enable flag for bogon detection.
// The CIDR list is static and does not need additional configuration.
type BogonConfig struct {
	Enabled bool
}

// Config is the top-level configuration for the Checker.
type Config struct {
	Cloudflare CloudflareConfig
	Bogon      BogonConfig
}

// Checker orchestrates CloudflareChecker and BogonChecker.
// Either sub-checker may be nil when the corresponding feature is disabled in Config.
type Checker struct {
	// cf is nil when Config.Cloudflare.Enabled == false.
	cf *CloudflareChecker
	// bogon is nil when Config.Bogon.Enabled == false.
	bogon *BogonChecker
}

// NewChecker creates a Checker and starts the CloudflareChecker refresh goroutine if enabled.
// The goroutine stops when ctx is cancelled.
func NewChecker(ctx context.Context, cfg Config) *Checker {
	c := &Checker{}
	if cfg.Cloudflare.Enabled {
		c.cf = NewCloudflareChecker(ctx, cfg.Cloudflare)
	}
	if cfg.Bogon.Enabled {
		c.bogon = NewBogonChecker()
	}
	return c
}

// Check returns a non-nil *CheckResult if ip is a Cloudflare or bogon address.
// Cloudflare check runs first — a broken Cloudflare chain is the more critical finding.
// Returns nil if both checks pass (ip looks like a legitimate routable address).
// Returns nil if ip is empty or unparseable — never panics.
func (c *Checker) Check(ip string) *CheckResult {
	if ip == "" {
		return nil
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil
	}

	if c.cf != nil {
		if matched, cidr := c.cf.Contains(parsed); matched {
			return &CheckResult{
				Kind:        "cloudflare",
				IP:          ip,
				MatchedCIDR: cidr,
			}
		}
	}

	if c.bogon != nil {
		if matched, cidr := c.bogon.Contains(parsed); matched {
			return &CheckResult{
				Kind:        "bogon",
				IP:          ip,
				MatchedCIDR: cidr,
			}
		}
	}

	return nil
}

// Update replaces config and restarts internal goroutines.
// Called on SIGHUP to apply new configuration without restarting the process.
func (c *Checker) Update(ctx context.Context, cfg Config) {
	// CloudflareChecker requires goroutine management — delegate to it.
	if cfg.Cloudflare.Enabled {
		if c.cf != nil {
			c.cf.Update(ctx, cfg.Cloudflare)
		} else {
			// Cloudflare was disabled before but is now enabled — create the checker.
			c.cf = NewCloudflareChecker(ctx, cfg.Cloudflare)
		}
	} else if c.cf != nil {
		// Cloudflare was enabled but is now disabled — stop and discard.
		c.cf.Close()
		c.cf = nil
	}

	// BogonChecker is static — just replace or nil it based on the new flag.
	if cfg.Bogon.Enabled {
		if c.bogon == nil {
			c.bogon = NewBogonChecker()
		}
		// If bogon was already enabled, no action needed: the static list never changes.
	} else {
		c.bogon = nil
	}
}

// Close stops internal goroutines. Safe to call on a nil Checker.
func (c *Checker) Close() {
	if c == nil {
		return
	}
	if c.cf != nil {
		c.cf.Close()
	}
	// BogonChecker has no goroutine — nothing to close.
}
