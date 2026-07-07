// ========================== Module chaincheck/bogon ======================================
//
//	BogonChecker: static detection of non-routable / reserved IP ranges.
//	No goroutine, no network fetch — the list is immutable after construction.
//
//	WHAT IS HERE:
//	  BogonChecker  — compiled list of bogon/RFC1918/CGNAT CIDRs
//	  NewBogonChecker() — builds the checker once
//	  Contains()    — O(n) scan over ~13 entries; acceptable given the small list size
//
//	WHAT IS NOT HERE:
//	  Cloudflare detection (cloudflare.go)
//	  Orchestration / caller logic (checker.go)
//
//	COVERED RANGES:
//	  RFC 1918         — 10/8, 172.16/12, 192.168/16
//	  CGNAT            — 100.64/10
//	  Loopback         — 127/8, ::1/128
//	  Link-local       — 169.254/16, fe80::/10
//	  Documentation    — 192.0.2/24, 198.51.100/24, 203.0.113/24
//	  Unspecified/reserved — 0/8, 240/4
//	  IPv6 unique local — fc00::/7
package chaincheck

import (
	"net"
)

// bogonCIDRs is the static list of non-routable / reserved IP ranges.
// Compiled once at init time; never mutates during program lifetime.
// O(n) scan over this slice is acceptable because the list is tiny (~13 entries)
// and Contains() is called once per log line — not in a tight inner loop.
var bogonCIDRs = []string{
	// RFC 1918 — private address space
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	// CGNAT — Carrier-Grade NAT (RFC 6598); often appears in logs when
	// ISP-level NAT is the last hop before the origin server.
	"100.64.0.0/10",
	// Loopback — should never appear as a real client IP
	"127.0.0.0/8",
	"::1/128",
	// Link-local — autoconfiguration addresses, never routed between hosts
	"169.254.0.0/16",
	"fe80::/10",
	// Documentation ranges (RFC 5737 / RFC 3849) — reserved for examples;
	// if seen in production logs, something is clearly misconfigured
	"192.0.2.0/24",
	"198.51.100.0/24",
	"203.0.113.0/24",
	// Unspecified / reserved
	"0.0.0.0/8",
	"240.0.0.0/4",
	// IPv6 unique local (RFC 4193) — analogous to RFC 1918 for IPv6
	"fc00::/7",
}

// BogonChecker checks whether an IP belongs to non-routable / reserved ranges.
// Static list — no goroutine, no network fetch required.
// Thread-safe: nets slice is immutable after construction.
//
// Internal — not in config. Consumer: checker.go (ChainGuard).
type BogonChecker struct {
	nets []*net.IPNet // Internal — compiled bogon CIDRs, immutable. Consumer: Contains.
}

// NewBogonChecker compiles the static bogon CIDR list and returns a ready checker.
// Panics if any CIDR in the hardcoded list is malformed — programming error.
//
// Called from: checker.go (ChainGuard initialization).
// Non-blocking.
func NewBogonChecker() *BogonChecker {
	nets := make([]*net.IPNet, 0, len(bogonCIDRs))
	for _, cidr := range bogonCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			// Malformed hardcoded CIDR is always a programming error — panic is appropriate.
			panic("chaincheck: invalid bogon CIDR " + cidr + ": " + err.Error())
		}
		nets = append(nets, network)
	}
	return &BogonChecker{nets: nets}
}

// Contains reports whether ip is a bogon address.
// Returns (true, matchedCIDR) on match, (false, "") otherwise.
// A nil ip always returns false — no panic.
func (b *BogonChecker) Contains(ip net.IP) (bool, string) {
	if ip == nil {
		return false, ""
	}
	for _, network := range b.nets {
		if network.Contains(ip) {
			return true, network.String()
		}
	}
	return false, ""
}
