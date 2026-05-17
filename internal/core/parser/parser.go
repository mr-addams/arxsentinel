// ========================== Module parser ===============================================
//   Shared types and Parser interface for all log format implementations.
//
//   WHAT IS HERE:
//     - LogEntry — structured record of a single access log line (shared output type)
//     - Parser   — interface implemented by CombinedParser and JSONParser
//
//   WHAT IS NOT HERE:
//     - Parsing logic (combined.go, json.go)
//     - Logging (sys/utils)

package parser

import "time"

// Parser is the interface for all access log format parsers.
// Each implementation parses one log format and returns a LogEntry.
type Parser interface {
	Parse(line string) (*LogEntry, bool)
}

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
