// ========================== Module parser/json ==========================================
//   Parser for nginx JSON log format.
//   Implements the Parser interface.
//
//   WHAT IS HERE:
//     - JSONParser — implements Parser for user-configurable JSON log format
//     - Field mapping via JSONFieldsConfig: nginx JSON key → LogEntry field
//     - Graceful handling of missing/unknown fields and broken JSON
//
//   Expected nginx log_format example:
//     log_format json_log escape=json '{"remote_addr":"$remote_addr",'
//       '"time_iso8601":"$time_iso8601","request":"$request",'
//       '"status":"$status","bytes_sent":"$bytes_sent",'
//       '"http_referer":"$http_referer","http_user_agent":"$http_user_agent",'
//       '"real_ip":"$real_ip"}';
//
//   WHAT IS NOT HERE:
//     - LogEntry struct (parser.go — shared output type)
//     - CombinedParser (combined.go)
//     - Logging — caller handles skips

package parser

import (
	"encoding/json"
	"strconv"
	"time"
)

// iso8601Layouts — nginx $time_iso8601 format variants tried in order.
// "+00:00" (with colon) is the most common; "+0000" (without colon) appears on some
// Linux locales. time.RFC3339 only covers the colon form, so we list both explicitly.
var iso8601Layouts = []string{
	"2006-01-02T15:04:05-07:00", // +HH:MM — most common nginx output
	"2006-01-02T15:04:05-0700",  // +HHMM  — seen on some Linux locales
}

// ========================== JSONParser =============================================

// JSONParser parses nginx access log lines in JSON format.
// Field names are configurable via JSONFieldsConfig to match any nginx log_format.
//
// YAML: parser.json — JSON field mapping for nginx JSON log_format.
// Consumer: parser.NewJSONParser, pipeline (profiles.go).
type JSONParser struct {
	fields JSONFieldsConfig // YAML: parser.json — field key mapping. Consumer: Parse.
}

// NewJSONParser creates a JSONParser using the provided field mapping.
//
// Called from: parser (profiles.go), config loader (internal/sys/config via alias).
// Non-blocking.
func NewJSONParser(fields JSONFieldsConfig) *JSONParser {
	return &JSONParser{fields: fields}
}

// Parse parses a single JSON-formatted nginx access log line.
// Returns (entry, true) on success, (nil, false) for invalid or unparseable input.
// Unknown JSON keys are silently ignored — only the mapped fields are consumed.
//
// Called from: pipeline (profiles.go).
// Non-blocking.
func (p *JSONParser) Parse(line string) (*LogEntry, bool) {
	var raw map[string]any
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return nil, false
	}

	f := p.fields

	remoteAddr := stringField(raw, f.RemoteAddr)
	timeStr := stringField(raw, f.Time)
	request := stringField(raw, f.Request)
	statusStr := stringField(raw, f.Status)
	bytesStr := stringField(raw, f.BytesSent)
	referer := stringField(raw, f.Referer)
	userAgent := stringField(raw, f.UserAgent)
	realIPRaw := stringField(raw, f.RealIP)

	// ── Time ────────────────────────────────────────────────────────────────────────
	var t time.Time
	var timeErr error
	for _, layout := range iso8601Layouts {
		t, timeErr = time.Parse(layout, timeStr)
		if timeErr == nil {
			break
		}
	}
	if timeErr != nil {
		return nil, false
	}

	// ── Status ──────────────────────────────────────────────────────────────────────
	status, err := strconv.Atoi(statusStr)
	if err != nil {
		return nil, false
	}

	// ── Bytes ───────────────────────────────────────────────────────────────────────
	var bytesSent int64
	if bytesStr != "" && bytesStr != "-" {
		bytesSent, err = strconv.ParseInt(bytesStr, 10, 64)
		if err != nil {
			return nil, false
		}
	}

	// ── Request: method + URI + protocol ────────────────────────────────────────────
	method, rawURI, proto := splitRequest(request)
	path, query := splitURI(rawURI)

	// ── RealIP ──────────────────────────────────────────────────────────────────────
	realIP := extractRealIP(realIPRaw, remoteAddr)

	return &LogEntry{
		RemoteAddr: remoteAddr,
		Time:       t,
		Method:     method,
		RawURI:     rawURI,
		Path:       path,
		Query:      query,
		Protocol:   proto,
		Status:     status,
		BytesSent:  bytesSent,
		Referer:    referer,
		UserAgent:  userAgent,
		RealIP:     realIP,
	}, true
}

// ========================== Helper ================================================

// stringField reads a string value from a JSON map by key.
// Handles both string and numeric JSON values (nginx logs status/bytes as strings or numbers).
// Returns "" for missing or unsupported types.
//
// Internal — no config mapping. Consumer: JSONParser.Parse.
func stringField(m map[string]any, key string) string {
	if key == "" {
		return ""
	}
	v, ok := m[key]
	if !ok {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case float64:
		// JSON numbers unmarshal as float64. float64 represents integers exactly up to 2^53.
		// Values within that range are formatted as integers; larger values as decimals.
		const maxExactInt = 1 << 53
		if val >= -maxExactInt && val <= maxExactInt && val == float64(int64(val)) {
			return strconv.FormatInt(int64(val), 10)
		}
		return strconv.FormatFloat(val, 'f', 0, 64)
	default:
		return ""
	}
}
