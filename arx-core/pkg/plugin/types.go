// ========================== pkg/plugin — shared types ====================================
//   Public data types shared between Sources, Sinks, Detectors, and the pipeline.
//   This package depends only on stdlib — external developers can import it
//   without pulling in any arxsentinel-internal dependencies.
//
//   WHAT IS HERE:
//     - LogEntry    — parsed record from any access log source (moved from internal/core/parser)
//     - SourceStats — counters emitted by Source implementations
//
//   WHAT IS NOT HERE:
//     - Source / Sink interfaces (source.go, sink.go)
//     - Detector interface (detector.go)
//     - Implementations (internal/)
//
//   DEPENDENCY RULE:
//     pkg/plugin → stdlib only. Never import internal/.

package plugin

import "time"

// LogEntry — structured record of a single access log line.
// Shared DTO between Sources (parse line → LogEntry) and the pipeline
// (whitelist → tracker → scorer).
//
// Moved from internal/core/parser to pkg/plugin so Source interface
// in this package can reference it without creating an import cycle.
// internal/core/parser re-exports the type as a type alias for backward compat.
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
	ChainIssue string    // filled by chaincheck processor: "cloudflare:IP/CIDR" | "bogon:IP" | ""
}

// SourceStats — operational counters emitted by a Source.
// Pulled by the pipeline for STATS log entries and Prometheus metrics.
type SourceStats struct {
	LinesRead   int64 // total lines received from the underlying source
	ParseErrors int64 // lines that failed to parse
	Dropped     int64 // lines dropped due to full merge buffer (D3)
}
