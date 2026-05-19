// ========================== Module parser/combined =======================================
//   Parser for nginx combined log format + real_ip field.
//   Implements the Parser interface.
//
//   WHAT IS HERE:
//     - CombinedParser — implements Parser for the combined + real_ip format
//     - Parse(line) — package-level wrapper for backward compatibility (removed in v0.2)
//     - logLineRe, nginxTimeLayout — format constants
//     - extractRealIP(), splitRequest(), splitURI() — helpers
//
//   Log format (combined + real_ip):
//     $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
//     "$http_referer" "$http_user_agent" "$real_ip"
//
//   Example line:
//     20.48.232.178 - - [02/Apr/2026:00:26:49 +0000] "GET / HTTP/2.0" 200 66088 "-" "-" "20.48.232.178"
//
//   WHAT IS NOT HERE:
//     - LogEntry struct (parser.go — shared output type)
//     - Logging (sys/utils) — the caller decides how to log skips
//     - State aggregation (core/state)

package parser

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ========================== Helper constants ===================================

// logLineRe — regular expression for nginx combined log format + real_ip field.
//
// Using [^"]* instead of .* inside quotes and [^\]]* for time — guarantees O(n)
// without catastrophic backtracking on abnormally long lines (overflow attacks).
//
// Capture groups:
//
//	[1] remote_addr   [2] remote_user  [3] time_local    [4] request
//	[5] status        [6] bytes_sent   [7] http_referer  [8] http_user_agent  [9] real_ip
var logLineRe = regexp.MustCompile(
	`^(\S+) - (\S+) \[([^\]]+)\] "([^"]*)" (\d+) (\d+) "([^"]*)" "([^"]*)" "([^"]*)"$`,
)

// nginxTimeLayout — nginx time format (time_local) for time.Parse.
// Example: 02/Apr/2026:00:26:49 +0000
const nginxTimeLayout = "02/Jan/2006:15:04:05 -0700"

// haproxyTimeLayout — HAProxy time format: milliseconds, no timezone offset.
// Example: 18/May/2026:21:23:08.151
// Used as fallback in RegexParser when nginxTimeLayout fails (profiles.go haproxy-http).
const haproxyTimeLayout = "02/Jan/2006:15:04:05.000"

// ========================== CombinedParser ==========================================

// CombinedParser parses nginx combined log format lines with the real_ip field appended.
type CombinedParser struct{}

// Parse parses a single nginx combined log format + real_ip line.
// Returns (entry, true) on success, (nil, false) for an invalid line.
func (p *CombinedParser) Parse(line string) (*LogEntry, bool) {
	return parseCombined(line)
}

// ========================== Package-level wrapper (backward compat) ====================

// Parse is a package-level convenience wrapper kept for e2e_test.go compatibility.
// Removed once e2e tests are updated to use CombinedParser directly.
func Parse(line string) (*LogEntry, bool) {
	return parseCombined(line)
}

// ========================== Core parsing logic =========================================

func parseCombined(line string) (*LogEntry, bool) {
	m := logLineRe.FindStringSubmatch(line)
	if m == nil {
		return nil, false
	}

	// m[1]=remote_addr, m[2]=remote_user, m[3]=time_local, m[4]=request,
	// m[5]=status, m[6]=bytes_sent, m[7]=referer, m[8]=user_agent, m[9]=real_ip

	// ── Time parsing ────────────────────────────────────────────────────────────────
	t, err := time.Parse(nginxTimeLayout, m[3])
	if err != nil {
		// Invalid date means a broken line — not just an unexpected format
		return nil, false
	}

	// ── Numeric fields ─────────────────────────────────────────────────────────────────
	status, err := strconv.Atoi(m[5])
	if err != nil {
		return nil, false
	}

	bytes, err := strconv.ParseInt(m[6], 10, 64)
	if err != nil {
		return nil, false
	}

	// ── Request: method + URI + protocol ───────────────────────────────────────────────
	method, rawURI, proto := splitRequest(m[4])

	path, query := splitURI(rawURI)

	// ── RealIP: last IP in the X-Forwarded-For chain ────────────────────────────────────
	realIP := extractRealIP(m[9], m[1])

	return &LogEntry{
		RemoteAddr: m[1],
		RemoteUser: m[2],
		Time:       t,
		Method:     method,
		RawURI:     rawURI,
		Path:       path,
		Query:      query,
		Protocol:   proto,
		Status:     status,
		BytesSent:  bytes,
		Referer:    m[7],
		UserAgent:  m[8],
		RealIP:     realIP,
	}, true
}

// ========================== Helper functions =====================================

// splitRequest splits the $request string into method, full URI, and protocol.
// Standard format: "METHOD /path?query HTTP/x.y"
//
// URI is intentionally taken as parts[1] (not everything between method and protocol),
// because nginx logs URIs without spaces — space-in-URI is extremely rare and not supported.
// For non-standard format (fewer than 3 parts) we return the whole request as the method,
// so the entry is visible in logs for manual inspection.
func splitRequest(req string) (method, uri, proto string) {
	parts := strings.SplitN(req, " ", 3)
	if len(parts) != 3 {
		return req, "", ""
	}
	return parts[0], parts[1], parts[2]
}

// splitURI splits a URI into path and query string.
// "/path?key=val&foo=bar" → ("/path", "key=val&foo=bar")
// "/path"                 → ("/path", "")
func splitURI(uri string) (path, query string) {
	idx := strings.IndexByte(uri, '?')
	if idx < 0 {
		return uri, ""
	}
	return uri[:idx], uri[idx+1:]
}

// extractRealIP extracts the real client IP from the $real_ip field.
//
// The field may contain an X-Forwarded-For chain like "127.0.0.1, 185.177.72.23":
// the first IP is from the client (may be spoofed), the last is added by a trusted proxy.
// We take the last element as the most reliable source.
//
// When $real_ip == "-" (ngx_realip module is not configured) — we use RemoteAddr directly.
func extractRealIP(realIP, remoteAddr string) string {
	if realIP == "" || realIP == "-" {
		// real_ip module is not installed or not configured — fallback to TCP address
		return remoteAddr
	}
	if idx := strings.LastIndexByte(realIP, ','); idx >= 0 {
		// Chain: "ip1, ip2, ip3" → take ip3 and trim spaces
		return strings.TrimSpace(realIP[idx+1:])
	}
	return realIP
}
