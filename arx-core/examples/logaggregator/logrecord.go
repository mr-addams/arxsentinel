// Package main contains the LogAggregator example.
//
// WHAT THIS FILE OWNS:
//   - LogRecord — the example's product-shaped payload type. It demonstrates
//     that arx-core runtime never inspects Event.Payload: the type lives here,
//     defined per-product, and flows through the pipeline as an opaque value.
//
// BOUNDARY PROOF:
//   - LogRecord is intentionally NOT imported from arx-core. The arx-core
//     contract says "Payload is plugin-owned"; this file is the canonical
//     example of that ownership.
package main

import "time"

// LogRecord — product-shaped payload produced by the filter LineProcessor
// and consumed by the JSON Formatter. Demonstrates that Event.Payload (typed
// as `any`) accepts any concrete type the product chooses to define.
type LogRecord struct {
	// Time is copied from the parser-owned LogEntry.Time (source observation
	// time, not construction time).
	Time time.Time

	// Host is the client IP that originated the request. LogEntry provides
	// both RemoteAddr (TCP peer) and RealIP (last hop from a trusted proxy);
	// we prefer RealIP and fall back to RemoteAddr inside the filter.
	Host string

	// Severity is a coarse tag derived from the HTTP status: 5xx → "ERROR",
	// 4xx → "WARN", anything else → "INFO". The tag is also written to
	// Envelope.Level so the engine can use it as an axis label.
	Severity string

	// Message is a single-line human-readable summary built from
	// Method + Path + Status. The substring filter (flag -substring) matches
	// against this field.
	Message string

	// RemoteAddr is the TCP peer address (verbatim from LogEntry.RemoteAddr).
	// Kept alongside Host for diagnostic parity with the parser-owned LogEntry.
	RemoteAddr string

	// Status is the HTTP response code (verbatim from LogEntry.Status).
	Status int

	// Path is the request path without query string (verbatim from LogEntry.Path).
	Path string
}