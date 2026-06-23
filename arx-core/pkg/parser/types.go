// ========================== Module parser/types ========================================
//   Canonical data types owned by the parser package.
//
//   WHAT IS HERE:
//     - LogEntry — parsed record of a single access log line
//
//   WHAT IS NOT HERE:
//     - Parser interface (parser.go)
//     - Parsing logic (combined.go, json.go, regex.go, profiles.go)
//
//   History (Flow 083, Phase 3):
//     The canonical LogEntry used to live in pkg/plugin (after a prior move
//     from internal/core/parser in Flow 074). The Phase 3 dissolution keeps
//     the model with its owning plugin package: parser produces LogEntry,
//     so the struct lives in pkg/parser. pkg/plugin re-exports nothing —
//     every consumer of the structured record imports pkg/parser directly.
//
//   DEPENDENCY RULE:
//     pkg/parser → stdlib only. Event/Envelope bridge helpers (event_bridge.go)
//     are the only place that may import pkg/plugin, and only for the generic
//     transport envelope, never for the LogEntry struct.

package parser

import "time"

// LogEntry — structured record of a single access log line.
// Shared DTO between Sources (parse line → LogEntry) and the pipeline
// (processor chain → scoring step).
//
// Canonical definition lives in pkg/parser. Source implementations and the
// pipeline interact with the record through this type; pkg/plugin.Event
// carries it as Payload across runtime boundaries (see event_bridge.go).
type LogEntry struct {
	RemoteAddr string    // $remote_addr — TCP peer (may be proxy or load balancer)
	RemoteUser string    // $remote_user — Basic Auth user; "-" for anonymous
	Time       time.Time // $time_local — server-side request start time
	Method     string    // from $request — HTTP method
	RawURI     string    // from $request — full URI with query string
	Path       string    // from $request — path without query string
	Query      string    // from $request — query string without "?"
	Protocol   string    // from $request — HTTP version
	Status     int       // $status — HTTP response code
	BytesSent  int64     // $body_bytes_sent — response body size in bytes
	Referer    string    // $http_referer; "-" if absent
	UserAgent  string    // $http_user_agent; "-" if absent
	RealIP     string    // last IP from $real_ip; == RemoteAddr when real_ip field == "-"
	ChainIssue string    // filled by chaincheck processor: "<proxy-tag>:IP/CIDR" | "bogon:IP" | ""
}
