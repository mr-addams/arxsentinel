// ========================== internal/core/parser — regex_test.go ==========
//   Tests for RegexParser: patterns, matching, error handling.

package parser

import (
	"testing"
)

// combinedPattern mimics nginx combined log format for regex parser tests.
const combinedPattern = `(?P<remote_addr>\S+) \S+ (?P<remote_user>\S+) \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d+) (?P<bytes_sent>\d+) "(?P<http_referer>[^"]*)" "(?P<http_user_agent>[^"]*)"`

// proxyPattern includes real_ip for reverse-proxy log format tests.
const proxyPattern = `(?P<remote_addr>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d+) (?P<bytes_sent>\d+) "(?P<http_referer>[^"]*)" "(?P<http_user_agent>[^"]*)" "(?P<real_ip>[^"]*)"`

// minimalPattern has only the mandatory groups — no optional fields.
const minimalPattern = `(?P<remote_addr>\S+) \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d+) (?P<bytes_sent>\d+)`

func TestNewRegexParser_ValidPattern(t *testing.T) {
	_, err := NewRegexParser(combinedPattern)
	if err != nil {
		t.Fatalf("NewRegexParser: unexpected error: %v", err)
	}
}

func TestNewRegexParser_InvalidRegex(t *testing.T) {
	_, err := NewRegexParser(`(?P<remote_addr>[unclosed`)
	if err == nil {
		t.Fatal("NewRegexParser: want error for invalid regex, got nil")
	}
}

func TestNewRegexParser_MissingMandatoryGroup(t *testing.T) {
	// Pattern without remote_addr must fail construction.
	_, err := NewRegexParser(`(?P<status>\d+) (?P<bytes_sent>\d+) "(?P<request>[^"]*)" \[(?P<time>[^\]]+)\]`)
	if err == nil {
		t.Fatal("NewRegexParser: want error for missing remote_addr group, got nil")
	}
}

func TestRegexParser_ParseCombinedLine(t *testing.T) {
	p, err := NewRegexParser(combinedPattern)
	if err != nil {
		t.Fatalf("NewRegexParser: %v", err)
	}

	line := `1.2.3.4 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/5.0"`
	entry, ok := p.Parse(line)
	if !ok {
		t.Fatal("Parse: want ok=true, got false")
	}

	if entry.RemoteAddr != "1.2.3.4" {
		t.Errorf("RemoteAddr: want %q, got %q", "1.2.3.4", entry.RemoteAddr)
	}
	if entry.Method != "GET" {
		t.Errorf("Method: want %q, got %q", "GET", entry.Method)
	}
	if entry.Path != "/apache_pb.gif" {
		t.Errorf("Path: want %q, got %q", "/apache_pb.gif", entry.Path)
	}
	if entry.Status != 200 {
		t.Errorf("Status: want 200, got %d", entry.Status)
	}
	if entry.BytesSent != 2326 {
		t.Errorf("BytesSent: want 2326, got %d", entry.BytesSent)
	}
	if entry.UserAgent != "Mozilla/5.0" {
		t.Errorf("UserAgent: want %q, got %q", "Mozilla/5.0", entry.UserAgent)
	}
	// RealIP must fall back to RemoteAddr when real_ip group is absent.
	if entry.RealIP != "1.2.3.4" {
		t.Errorf("RealIP fallback: want %q, got %q", "1.2.3.4", entry.RealIP)
	}
}

func TestRegexParser_ParseWithRealIP(t *testing.T) {
	p, err := NewRegexParser(proxyPattern)
	if err != nil {
		t.Fatalf("NewRegexParser: %v", err)
	}

	line := `10.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "POST /login HTTP/1.1" 401 512 "-" "curl/7.68" "5.6.7.8"`
	entry, ok := p.Parse(line)
	if !ok {
		t.Fatal("Parse: want ok=true, got false")
	}

	if entry.RemoteAddr != "10.0.0.1" {
		t.Errorf("RemoteAddr: want %q, got %q", "10.0.0.1", entry.RemoteAddr)
	}
	// RealIP must be taken from the real_ip group, not RemoteAddr.
	if entry.RealIP != "5.6.7.8" {
		t.Errorf("RealIP: want %q, got %q", "5.6.7.8", entry.RealIP)
	}
	if entry.Status != 401 {
		t.Errorf("Status: want 401, got %d", entry.Status)
	}
}

func TestRegexParser_ParseMalformedLine(t *testing.T) {
	p, err := NewRegexParser(combinedPattern)
	if err != nil {
		t.Fatalf("NewRegexParser: %v", err)
	}

	_, ok := p.Parse("this is not a log line at all")
	if ok {
		t.Fatal("Parse: want ok=false for malformed line, got true")
	}
}

func TestRegexParser_ParseEmptyLine(t *testing.T) {
	p, err := NewRegexParser(combinedPattern)
	if err != nil {
		t.Fatalf("NewRegexParser: %v", err)
	}

	_, ok := p.Parse("")
	if ok {
		t.Fatal("Parse: want ok=false for empty line, got true")
	}
}

func TestRegexParser_MinimalPattern_OptionalFieldsEmpty(t *testing.T) {
	// Pattern without optional groups must produce empty strings, not crash.
	p, err := NewRegexParser(minimalPattern)
	if err != nil {
		t.Fatalf("NewRegexParser: %v", err)
	}

	line := `1.2.3.4 [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.1" 200 1024`
	entry, ok := p.Parse(line)
	if !ok {
		t.Fatal("Parse: want ok=true, got false")
	}
	if entry.Referer != "" {
		t.Errorf("Referer: want empty, got %q", entry.Referer)
	}
	if entry.UserAgent != "" {
		t.Errorf("UserAgent: want empty, got %q", entry.UserAgent)
	}
}

func TestRegexParser_ParseQueryString(t *testing.T) {
	p, err := NewRegexParser(combinedPattern)
	if err != nil {
		t.Fatalf("NewRegexParser: %v", err)
	}

	line := `1.2.3.4 - - [10/Oct/2000:13:55:36 -0700] "GET /search?q=test&page=2 HTTP/1.1" 200 512 "-" "-"`
	entry, ok := p.Parse(line)
	if !ok {
		t.Fatal("Parse: want ok=true, got false")
	}
	if entry.Path != "/search" {
		t.Errorf("Path: want %q, got %q", "/search", entry.Path)
	}
	if entry.Query != "q=test&page=2" {
		t.Errorf("Query: want %q, got %q", "q=test&page=2", entry.Query)
	}
}
