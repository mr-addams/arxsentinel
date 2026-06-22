// ========================== Tests for parser/combined module ================================
//   Unit tests for CombinedParser.Parse() and helper functions.
//
//   Covered scenarios:
//     - Normal IPv4 line
//     - Line with IPv6 address
//     - real_ip field with X-Forwarded-For chain ("ip1, ip2")
//     - Empty User-Agent ("-")
//     - URI with query string
//     - Real lines from example.access.log (bingbot, Googlebot, POST)
//     - Broken lines: empty, arbitrary text, truncated, binary garbage

package parser

import (
	"strings"
	"testing"
	"time"
)

// ========================== Parse: normal lines ====================================

func TestParse_Normal_IPv4(t *testing.T) {
	line := `20.48.232.178 - - [02/Apr/2026:00:26:49 +0000] "GET / HTTP/2.0" 200 66088 "-" "-" "20.48.232.178"`
	entry, ok := Parse(line)
	if !ok {
		t.Fatal("Parse returned false for a normal IPv4 line")
	}

	if entry.RemoteAddr != "20.48.232.178" {
		t.Errorf("RemoteAddr: got %q, want %q", entry.RemoteAddr, "20.48.232.178")
	}
	if entry.RemoteUser != "-" {
		t.Errorf("RemoteUser: got %q, want %q", entry.RemoteUser, "-")
	}
	if entry.Method != "GET" {
		t.Errorf("Method: got %q, want %q", entry.Method, "GET")
	}
	if entry.RawURI != "/" {
		t.Errorf("RawURI: got %q, want %q", entry.RawURI, "/")
	}
	if entry.Path != "/" {
		t.Errorf("Path: got %q, want %q", entry.Path, "/")
	}
	if entry.Query != "" {
		t.Errorf("Query: got %q, want %q", entry.Query, "")
	}
	if entry.Protocol != "HTTP/2.0" {
		t.Errorf("Protocol: got %q, want %q", entry.Protocol, "HTTP/2.0")
	}
	if entry.Status != 200 {
		t.Errorf("Status: got %d, want %d", entry.Status, 200)
	}
	if entry.BytesSent != 66088 {
		t.Errorf("BytesSent: got %d, want %d", entry.BytesSent, 66088)
	}
	if entry.Referer != "-" {
		t.Errorf("Referer: got %q, want %q", entry.Referer, "-")
	}
	if entry.UserAgent != "-" {
		t.Errorf("UserAgent: got %q, want %q", entry.UserAgent, "-")
	}
	if entry.RealIP != "20.48.232.178" {
		t.Errorf("RealIP: got %q, want %q", entry.RealIP, "20.48.232.178")
	}

	// Verify time: timezone offset +0000 → UTC
	expected := time.Date(2026, 4, 2, 0, 26, 49, 0, time.UTC)
	if !entry.Time.Equal(expected) {
		t.Errorf("Time: got %v, want %v", entry.Time, expected)
	}
}

func TestParse_Normal_IPv6(t *testing.T) {
	// IPv6 in remote_addr and real_ip — must not break the parser
	line := `2a01:4f8:c17:e26::1 - - [02/Apr/2026:00:26:49 +0000] "HEAD /news/page/ HTTP/2.0" 200 0 "https://parlament.ua" "WPMU DEV Broken Link Checker" "2a01:4f8:c17:e26::1"`
	entry, ok := Parse(line)
	if !ok {
		t.Fatal("Parse returned false for a line with IPv6")
	}
	if entry.RemoteAddr != "2a01:4f8:c17:e26::1" {
		t.Errorf("RemoteAddr: got %q, want %q", entry.RemoteAddr, "2a01:4f8:c17:e26::1")
	}
	if entry.Method != "HEAD" {
		t.Errorf("Method: got %q, want %q", entry.Method, "HEAD")
	}
	if entry.BytesSent != 0 {
		// HEAD always returns 0 body bytes
		t.Errorf("BytesSent: got %d, want 0 (HEAD)", entry.BytesSent)
	}
	if entry.RealIP != "2a01:4f8:c17:e26::1" {
		t.Errorf("RealIP: got %q, want %q", entry.RealIP, "2a01:4f8:c17:e26::1")
	}
}

// ========================== Parse: real_ip =============================================

func TestParse_RealIP_Chain(t *testing.T) {
	// Client behind proxy: nginx appended the real IP to the end of the chain.
	// We take the last — it was added by a trusted proxy, the first may be spoofed.
	line := `127.0.0.1 - - [02/Apr/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1000 "-" "curl/8.7.1" "127.0.0.1,185.177.72.23"`
	entry, ok := Parse(line)
	if !ok {
		t.Fatal("Parse returned false for a line with real_ip chain")
	}
	if entry.RealIP != "185.177.72.23" {
		t.Errorf("RealIP from chain without space: got %q, want %q", entry.RealIP, "185.177.72.23")
	}
}

func TestParse_RealIP_ChainWithSpaces(t *testing.T) {
	// Some proxies add a space after the comma: "ip1, ip2"
	line := `10.0.0.1 - - [02/Apr/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 500 "-" "Mozilla/5.0" "10.0.0.1, 185.177.72.23"`
	entry, ok := Parse(line)
	if !ok {
		t.Fatal("Parse returned false for chain with space")
	}
	if entry.RealIP != "185.177.72.23" {
		t.Errorf("RealIP from chain with space: got %q, want %q", entry.RealIP, "185.177.72.23")
	}
}

func TestParse_RealIP_Dash_FallbackToRemoteAddr(t *testing.T) {
	// real_ip == "-" → ngx_realip module is not configured, use remote_addr
	line := `93.184.216.34 - - [02/Apr/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 500 "-" "Mozilla/5.0" "-"`
	entry, ok := Parse(line)
	if !ok {
		t.Fatal("Parse returned false when real_ip = '-'")
	}
	if entry.RealIP != "93.184.216.34" {
		t.Errorf("RealIP fallback to RemoteAddr: got %q, want %q", entry.RealIP, "93.184.216.34")
	}
}

// ========================== Parse: URI and query string ==================================

func TestParse_URI_WithQuery(t *testing.T) {
	// overflow detector needs RawURI and Query separately
	line := `185.177.72.23 - - [02/Apr/2026:10:00:00 +0000] "GET /?bypass=aaaa&cmd=ls HTTP/1.1" 200 1000 "-" "curl/8.7.1" "185.177.72.23"`
	entry, ok := Parse(line)
	if !ok {
		t.Fatal("Parse returned false for URL with query")
	}
	if entry.RawURI != "/?bypass=aaaa&cmd=ls" {
		t.Errorf("RawURI: got %q, want %q", entry.RawURI, "/?bypass=aaaa&cmd=ls")
	}
	if entry.Path != "/" {
		t.Errorf("Path: got %q, want %q", entry.Path, "/")
	}
	if entry.Query != "bypass=aaaa&cmd=ls" {
		t.Errorf("Query: got %q, want %q", entry.Query, "bypass=aaaa&cmd=ls")
	}
}

func TestParse_URI_DeepPath(t *testing.T) {
	line := `66.249.66.160 - - [02/Apr/2026:00:26:55 +0000] "GET /news/category/politics/ HTTP/2.0" 200 49000 "-" "Googlebot/2.1" "66.249.66.160"`
	entry, ok := Parse(line)
	if !ok {
		t.Fatal("Parse returned false for deep path")
	}
	if entry.Path != "/news/category/politics/" {
		t.Errorf("Path: got %q, want %q", entry.Path, "/news/category/politics/")
	}
	if entry.Query != "" {
		t.Errorf("Query: got %q, want empty", entry.Query)
	}
}

// ========================== Parse: real lines from example.access.log ===============

func TestParse_Real_Bingbot(t *testing.T) {
	line := `207.46.13.155 - - [02/Apr/2026:00:26:54 +0000] "GET /news/page/ HTTP/2.0" 200 49933 "-" "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm) Chrome/116.0.1938.76 Safari/537.36" "207.46.13.155"`
	entry, ok := Parse(line)
	if !ok {
		t.Fatal("Parse returned false for bingbot line")
	}
	if entry.Status != 200 {
		t.Errorf("Status: got %d, want 200", entry.Status)
	}
	if !strings.Contains(entry.UserAgent, "bingbot") {
		t.Errorf("UserAgent does not contain 'bingbot': %q", entry.UserAgent)
	}
}

func TestParse_Real_POST(t *testing.T) {
	line := `14.234.202.25 - - [02/Apr/2026:00:27:04 +0000] "POST /wp-admin/admin-ajax.php HTTP/2.0" 200 20 "https://parlament.ua/ru/news/page/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" "14.234.202.25"`
	entry, ok := Parse(line)
	if !ok {
		t.Fatal("Parse returned false for POST line")
	}
	if entry.Method != "POST" {
		t.Errorf("Method: got %q, want POST", entry.Method)
	}
	if entry.Path != "/wp-admin/admin-ajax.php" {
		t.Errorf("Path: got %q, want /wp-admin/admin-ajax.php", entry.Path)
	}
	if entry.BytesSent != 20 {
		t.Errorf("BytesSent: got %d, want 20", entry.BytesSent)
	}
}

func TestParse_Real_HEAD_304(t *testing.T) {
	// 304 Not Modified: bytes_sent == 0
	line := `66.249.66.34 - - [02/Apr/2026:00:26:57 +0000] "GET /news/page/?amp=1 HTTP/2.0" 304 0 "-" "Googlebot/2.1" "66.249.66.34"`
	entry, ok := Parse(line)
	if !ok {
		t.Fatal("Parse returned false for 304 line")
	}
	if entry.Status != 304 {
		t.Errorf("Status: got %d, want 304", entry.Status)
	}
	if entry.BytesSent != 0 {
		t.Errorf("BytesSent: got %d, want 0", entry.BytesSent)
	}
	if entry.Query != "amp=1" {
		t.Errorf("Query: got %q, want %q", entry.Query, "amp=1")
	}
}

// ========================== Parse: broken lines =========================================

func TestParse_BrokenLines(t *testing.T) {
	// All these lines must gracefully return (nil, false) without panic
	cases := []struct {
		name string
		line string
	}{
		{"empty string", ""},
		{"arbitrary text", "not a log line at all"},
		{"truncated line", "192.168.1.1 - - [02/Apr/2026:00:00:00 +0000] \"GET /"},
		{"missing real_ip field", `192.168.1.1 - - [02/Apr/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "curl/8"`},
		{"binary garbage", "\x00\x01\x02\xff\xfe binary garbage \x80\x90"},
		{"line without time", `192.168.1.1 - - [] "GET / HTTP/1.1" 200 100 "-" "curl/8" "192.168.1.1"`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entry, ok := Parse(tc.line)
			if ok {
				t.Errorf("Parse returned true for broken line %q, entry: %+v", tc.name, entry)
			}
			if entry != nil {
				t.Errorf("Parse returned non-nil entry for broken line %q", tc.name)
			}
		})
	}
}

// ========================== extractRealIP: unit tests ==================================

func TestExtractRealIP(t *testing.T) {
	cases := []struct {
		name       string
		realIP     string
		remoteAddr string
		want       string
	}{
		{"single IP", "185.177.72.23", "127.0.0.1", "185.177.72.23"},
		{"chain without space", "127.0.0.1,185.177.72.23", "127.0.0.1", "185.177.72.23"},
		{"chain with space", "127.0.0.1, 185.177.72.23", "127.0.0.1", "185.177.72.23"},
		{"chain of three", "10.0.0.1,10.0.0.2,185.177.72.23", "10.0.0.1", "185.177.72.23"},
		{"dash → remoteAddr", "-", "93.184.216.34", "93.184.216.34"},
		{"empty → remoteAddr", "", "93.184.216.34", "93.184.216.34"},
		{"IPv6", "2a01:4f8:c17:e26::1", "2a01:4f8:c17:e26::1", "2a01:4f8:c17:e26::1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractRealIP(tc.realIP, tc.remoteAddr)
			if got != tc.want {
				t.Errorf("extractRealIP(%q, %q) = %q, want %q", tc.realIP, tc.remoteAddr, got, tc.want)
			}
		})
	}
}

// ========================== splitRequest: unit tests ===================================

func TestSplitRequest(t *testing.T) {
	cases := []struct {
		req      string
		method   string
		uri      string
		protocol string
	}{
		{"GET / HTTP/2.0", "GET", "/", "HTTP/2.0"},
		{"POST /api/data HTTP/1.1", "POST", "/api/data", "HTTP/1.1"},
		{"HEAD /page/?q=1 HTTP/2.0", "HEAD", "/page/?q=1", "HTTP/2.0"},
		{"DELETE /resource/123 HTTP/1.0", "DELETE", "/resource/123", "HTTP/1.0"},
		// Non-standard requests: return whole request as method, URI and proto are empty
		{"", "", "", ""},
		{"INVALID", "INVALID", "", ""},
	}

	for _, tc := range cases {
		m, u, p := splitRequest(tc.req)
		if m != tc.method || u != tc.uri || p != tc.protocol {
			t.Errorf("splitRequest(%q) = (%q, %q, %q), want (%q, %q, %q)",
				tc.req, m, u, p, tc.method, tc.uri, tc.protocol)
		}
	}
}
