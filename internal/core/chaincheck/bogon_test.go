// ========================== internal/core/chaincheck — bogon_test.go ==========
//   Tests for BogonChecker: RFC1918, public IP detection.

package chaincheck

import (
	"net"
	"testing"
)

func TestBogonChecker_RFC1918(t *testing.T) {
	b := NewBogonChecker()
	cases := []struct {
		ip   string
		cidr string
	}{
		{"10.0.0.1", "10.0.0.0/8"},
		{"192.168.1.1", "192.168.0.0/16"},
		{"172.16.0.1", "172.16.0.0/12"},
		{"172.31.255.255", "172.16.0.0/12"},
	}
	for _, tc := range cases {
		matched, gotCIDR := b.Contains(net.ParseIP(tc.ip))
		if !matched {
			t.Errorf("Contains(%s): expected true, got false", tc.ip)
		}
		if gotCIDR != tc.cidr {
			t.Errorf("Contains(%s): expected CIDR %s, got %s", tc.ip, tc.cidr, gotCIDR)
		}
	}
}

func TestBogonChecker_CGNAT(t *testing.T) {
	b := NewBogonChecker()
	matched, cidr := b.Contains(net.ParseIP("100.64.0.1"))
	if !matched {
		t.Error("Contains(100.64.0.1): expected true, got false")
	}
	if cidr != "100.64.0.0/10" {
		t.Errorf("Contains(100.64.0.1): expected CIDR 100.64.0.0/10, got %s", cidr)
	}
}

func TestBogonChecker_Loopback(t *testing.T) {
	b := NewBogonChecker()

	matched, _ := b.Contains(net.ParseIP("127.0.0.1"))
	if !matched {
		t.Error("Contains(127.0.0.1): expected true, got false")
	}

	// IPv6 loopback
	matched, cidr := b.Contains(net.ParseIP("::1"))
	if !matched {
		t.Error("Contains(::1): expected true, got false")
	}
	if cidr != "::1/128" {
		t.Errorf("Contains(::1): expected CIDR ::1/128, got %s", cidr)
	}
}

func TestBogonChecker_Documentation(t *testing.T) {
	b := NewBogonChecker()
	cases := []struct {
		ip   string
		cidr string
	}{
		{"192.0.2.1", "192.0.2.0/24"},
		{"198.51.100.1", "198.51.100.0/24"},
		{"203.0.113.1", "203.0.113.0/24"},
	}
	for _, tc := range cases {
		matched, gotCIDR := b.Contains(net.ParseIP(tc.ip))
		if !matched {
			t.Errorf("Contains(%s): expected true, got false", tc.ip)
		}
		if gotCIDR != tc.cidr {
			t.Errorf("Contains(%s): expected CIDR %s, got %s", tc.ip, tc.cidr, gotCIDR)
		}
	}
}

func TestBogonChecker_LinkLocal(t *testing.T) {
	b := NewBogonChecker()
	matched, cidr := b.Contains(net.ParseIP("169.254.0.1"))
	if !matched {
		t.Error("Contains(169.254.0.1): expected true, got false")
	}
	if cidr != "169.254.0.0/16" {
		t.Errorf("Contains(169.254.0.1): expected CIDR 169.254.0.0/16, got %s", cidr)
	}
}

func TestBogonChecker_PublicIP(t *testing.T) {
	b := NewBogonChecker()
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "9.9.9.9"} {
		matched, _ := b.Contains(net.ParseIP(ip))
		if matched {
			t.Errorf("Contains(%s): expected false (public IP), got true", ip)
		}
	}
}

func TestBogonChecker_IPv6Bogon(t *testing.T) {
	b := NewBogonChecker()
	// fc00::/7 covers unique local addresses (RFC 4193)
	for _, ip := range []string{"fc00::1", "fd00::1", "fdff:ffff::1"} {
		matched, _ := b.Contains(net.ParseIP(ip))
		if !matched {
			t.Errorf("Contains(%s): expected true (IPv6 unique local), got false", ip)
		}
	}
}

func TestBogonChecker_NilIP(t *testing.T) {
	b := NewBogonChecker()
	// Nil IP must not panic and must return false.
	matched, cidr := b.Contains(nil)
	if matched || cidr != "" {
		t.Errorf("Contains(nil): expected (false, \"\"), got (%v, %q)", matched, cidr)
	}
}
