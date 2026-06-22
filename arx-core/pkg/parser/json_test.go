// ========================== Tests for parser/json module ====================================
//   Unit tests for JSONParser.Parse().
//
//   Covered scenarios:
//     - Standard nginx JSON line with default field mapping
//     - Custom field names via JSONFieldsConfig
//     - Numeric status/bytes as JSON numbers (not strings)
//     - real_ip chain → extractRealIP
//     - Missing optional field → graceful skip (zero value)
//     - Unknown extra JSON fields → silently ignored
//     - Broken JSON → (nil, false)
//     - Missing required field (status) → (nil, false)

package parser

import (
	"testing"
	"time"
)

// defaultFields returns the standard nginx JSON field mapping used in tests.
func defaultFields() JSONFieldsConfig {
	return JSONFieldsConfig{
		RemoteAddr: "remote_addr",
		Time:       "time_iso8601",
		Request:    "request",
		Status:     "status",
		BytesSent:  "bytes_sent",
		Referer:    "http_referer",
		UserAgent:  "http_user_agent",
		RealIP:     "real_ip",
	}
}

// ========================== Standard line ============================================

func TestJSONParse_Standard(t *testing.T) {
	line := `{"remote_addr":"1.2.3.4","time_iso8601":"2026-04-02T00:26:49+00:00","request":"GET /news/ HTTP/2.0","status":"200","bytes_sent":"66088","http_referer":"-","http_user_agent":"Mozilla/5.0","real_ip":"1.2.3.4"}`
	p := NewJSONParser(defaultFields())
	entry, ok := p.Parse(line)
	if !ok {
		t.Fatal("Parse returned false for a valid JSON line")
	}

	if entry.RemoteAddr != "1.2.3.4" {
		t.Errorf("RemoteAddr: got %q, want %q", entry.RemoteAddr, "1.2.3.4")
	}
	if entry.Method != "GET" {
		t.Errorf("Method: got %q, want GET", entry.Method)
	}
	if entry.Path != "/news/" {
		t.Errorf("Path: got %q, want /news/", entry.Path)
	}
	if entry.Protocol != "HTTP/2.0" {
		t.Errorf("Protocol: got %q, want HTTP/2.0", entry.Protocol)
	}
	if entry.Status != 200 {
		t.Errorf("Status: got %d, want 200", entry.Status)
	}
	if entry.BytesSent != 66088 {
		t.Errorf("BytesSent: got %d, want 66088", entry.BytesSent)
	}
	if entry.UserAgent != "Mozilla/5.0" {
		t.Errorf("UserAgent: got %q, want Mozilla/5.0", entry.UserAgent)
	}
	if entry.RealIP != "1.2.3.4" {
		t.Errorf("RealIP: got %q, want 1.2.3.4", entry.RealIP)
	}

	wantTime := time.Date(2026, 4, 2, 0, 26, 49, 0, time.UTC)
	if !entry.Time.Equal(wantTime) {
		t.Errorf("Time: got %v, want %v", entry.Time, wantTime)
	}
}

// ========================== Numeric status/bytes (JSON numbers) =======================

func TestJSONParse_NumericFields(t *testing.T) {
	// nginx may emit status and bytes_sent as numbers, not quoted strings
	line := `{"remote_addr":"5.6.7.8","time_iso8601":"2026-04-02T10:00:00+00:00","request":"GET / HTTP/1.1","status":404,"bytes_sent":512,"http_referer":"-","http_user_agent":"curl/8","real_ip":"5.6.7.8"}`
	p := NewJSONParser(defaultFields())
	entry, ok := p.Parse(line)
	if !ok {
		t.Fatal("Parse returned false for numeric status/bytes")
	}
	if entry.Status != 404 {
		t.Errorf("Status: got %d, want 404", entry.Status)
	}
	if entry.BytesSent != 512 {
		t.Errorf("BytesSent: got %d, want 512", entry.BytesSent)
	}
}

// ========================== Custom field names ========================================

func TestJSONParse_CustomFields(t *testing.T) {
	fields := JSONFieldsConfig{
		RemoteAddr: "client",
		Time:       "ts",
		Request:    "req",
		Status:     "code",
		BytesSent:  "size",
		Referer:    "ref",
		UserAgent:  "ua",
		RealIP:     "ip",
	}
	line := `{"client":"9.10.11.12","ts":"2026-05-01T12:00:00+00:00","req":"POST /api HTTP/1.1","code":"201","size":"0","ref":"-","ua":"myapp/1.0","ip":"9.10.11.12"}`
	p := NewJSONParser(fields)
	entry, ok := p.Parse(line)
	if !ok {
		t.Fatal("Parse returned false with custom field names")
	}
	if entry.RemoteAddr != "9.10.11.12" {
		t.Errorf("RemoteAddr: got %q, want 9.10.11.12", entry.RemoteAddr)
	}
	if entry.Method != "POST" {
		t.Errorf("Method: got %q, want POST", entry.Method)
	}
	if entry.Status != 201 {
		t.Errorf("Status: got %d, want 201", entry.Status)
	}
}

// ========================== real_ip chain ============================================

func TestJSONParse_RealIPChain(t *testing.T) {
	line := `{"remote_addr":"127.0.0.1","time_iso8601":"2026-04-02T00:00:00+00:00","request":"GET / HTTP/1.1","status":"200","bytes_sent":"100","http_referer":"-","http_user_agent":"-","real_ip":"10.0.0.1, 185.177.72.23"}`
	p := NewJSONParser(defaultFields())
	entry, ok := p.Parse(line)
	if !ok {
		t.Fatal("Parse returned false for real_ip chain")
	}
	if entry.RealIP != "185.177.72.23" {
		t.Errorf("RealIP: got %q, want 185.177.72.23", entry.RealIP)
	}
}

// ========================== Unknown extra fields (ignored) ============================

func TestJSONParse_UnknownFieldsIgnored(t *testing.T) {
	// Extra fields not in the mapping must not cause a failure
	line := `{"remote_addr":"1.1.1.1","time_iso8601":"2026-04-02T00:00:00+00:00","request":"GET / HTTP/1.1","status":"200","bytes_sent":"0","http_referer":"-","http_user_agent":"-","real_ip":"1.1.1.1","upstream_time":"0.123","pipe":".","unknown_extra":"value"}`
	p := NewJSONParser(defaultFields())
	_, ok := p.Parse(line)
	if !ok {
		t.Fatal("Parse returned false when extra unknown fields are present")
	}
}

// ========================== Broken / invalid input ====================================

func TestJSONParse_BrokenInput(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"empty string", ""},
		{"plain text", "not json at all"},
		{"truncated json", `{"remote_addr":"1.2.3.4"`},
		{"missing status", `{"remote_addr":"1.2.3.4","time_iso8601":"2026-04-02T00:00:00+00:00","request":"GET / HTTP/1.1","bytes_sent":"0","http_referer":"-","http_user_agent":"-","real_ip":"1.2.3.4"}`},
		{"invalid time", `{"remote_addr":"1.2.3.4","time_iso8601":"not-a-time","request":"GET / HTTP/1.1","status":"200","bytes_sent":"0","http_referer":"-","http_user_agent":"-","real_ip":"1.2.3.4"}`},
	}

	p := NewJSONParser(defaultFields())
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entry, ok := p.Parse(tc.line)
			if ok {
				t.Errorf("Parse returned true for invalid input %q", tc.name)
			}
			if entry != nil {
				t.Errorf("Parse returned non-nil entry for invalid input %q", tc.name)
			}
		})
	}
}

// ========================== URI with query string =====================================

func TestJSONParse_URIWithQuery(t *testing.T) {
	line := `{"remote_addr":"2.3.4.5","time_iso8601":"2026-04-02T00:00:00+00:00","request":"GET /search?q=test&lang=en HTTP/1.1","status":"200","bytes_sent":"1024","http_referer":"-","http_user_agent":"-","real_ip":"2.3.4.5"}`
	p := NewJSONParser(defaultFields())
	entry, ok := p.Parse(line)
	if !ok {
		t.Fatal("Parse returned false for URI with query")
	}
	if entry.Path != "/search" {
		t.Errorf("Path: got %q, want /search", entry.Path)
	}
	if entry.Query != "q=test&lang=en" {
		t.Errorf("Query: got %q, want q=test&lang=en", entry.Query)
	}
	if entry.RawURI != "/search?q=test&lang=en" {
		t.Errorf("RawURI: got %q, want /search?q=test&lang=en", entry.RawURI)
	}
}
