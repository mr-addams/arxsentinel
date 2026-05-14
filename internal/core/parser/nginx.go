// ========================== Module parser/nginx =========================================
//   Parser for combined log format + real_ip field.
//   Extracts a structured LogEntry from an Nginx log line.
//
//   WHAT IS HERE:
//     - LogEntry — all log line fields + derived fields (Path, Query, RealIP)
//     - Parse(line) — parses a single line, graceful skip on broken line
//     - extractRealIP() — last IP from the X-Forwarded-For chain in the real_ip field
//
//   Log format (combined + real_ip):
//     $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
//     "$http_referer" "$http_user_agent" "$real_ip"
//
//   Example line:
//     20.48.232.178 - - [02/Apr/2026:00:26:49 +0000] "GET / HTTP/2.0" 200 66088 "-" "-" "20.48.232.178"
//
//   WHAT IS NOT HERE:
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

// ========================== LogEntry struct ==========================================

// LogEntry — structured record of a single nginx access.log line.
//
// RealIP — the preferred client IP: either from the $real_ip field (last in the chain),
// or RemoteAddr if $real_ip is not set. Used by all detectors.
// RemoteAddr is kept for audit purposes (may be a load balancer address).
type LogEntry struct {
	RemoteAddr string    // $remote_addr — TCP connection address (may be nginx-proxy or load balancer)
	RemoteUser string    // $remote_user — Basic Auth user; "-" for anonymous requests
	Time       time.Time // $time_local — time the request started processing on the server
	Method     string    // from $request — HTTP method (GET, POST, HEAD, ...)
	RawURI     string    // from $request — full URI including query string; used by overflow detector to measure length
	Path       string    // from $request — path without query string; used by probe detector and state tracker
	Query      string    // from $request — query string without "?"; used by overflow detector for parameter analysis
	Protocol   string    // from $request — HTTP version (HTTP/1.1, HTTP/2.0, HTTP/3.0)
	Status     int       // $status — HTTP response code
	BytesSent  int64     // $body_bytes_sent — response body bytes (0 for HEAD and 304)
	Referer    string    // $http_referer — string as-is; "-" if absent
	UserAgent  string    // $http_user_agent — string as-is; "-" if absent
	RealIP     string    // last IP from $real_ip; == RemoteAddr if real_ip field == "-"
}

// ========================== Public API ===============================================

// Parse parses a single nginx combined log format + real_ip line.
// Returns (entry, true) on success, (nil, false) for an invalid line.
//
// Called by the pipeline for each line from the tail-reader.
// Broken lines (binary garbage, truncated lines, non-standard format) are skipped
// without panic — logging the skip is left to the caller's discretion.
func Parse(line string) (*LogEntry, bool) {
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
