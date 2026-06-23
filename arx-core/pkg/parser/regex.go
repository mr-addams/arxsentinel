// ========================== Module parser/regex ==========================================
//   Parser for arbitrary text log formats via a Go regex with named capture groups.
//   Implements the Parser interface.
//
//   WHAT IS HERE:
//     - RegexParser — implements Parser using a user-supplied compiled regex
//     - NewRegexParser(pattern) — constructor; validates mandatory groups at startup
//     - Parse(line) — extracts LogEntry from a single log line
//
//   Named group contract (Decision 1):
//     Mandatory: remote_addr, time, request, status, bytes_sent
//     Optional:  http_referer, http_user_agent, real_ip
//     Unknown groups are silently ignored.
//
//   Time parsing uses the same nginxTimeLayout as CombinedParser.
//   If the time field does not match nginxTimeLayout, time.Time{} is used —
//   detectors that do not use time still work.
//
//   WHAT IS NOT HERE:
//     - LogEntry struct (parser.go)
//     - CombinedParser / JSONParser (separate files)

package parser

import (
	"fmt"
	"regexp"
	"strconv"
	"time"
)

// mandatoryGroups lists named capture groups that must be present in the pattern.
// Absence of any of these causes NewRegexParser to return an error.
var mandatoryGroups = []string{"remote_addr", "time", "request", "status", "bytes_sent"}

// RegexParser implements Parser using a compiled regex with named capture groups.
//
// Internal — not exposed via config. Consumer: profiles.go (profile constructors).
type RegexParser struct {
	re      *regexp.Regexp // Compiled regex pattern. Consumer: Parse.
	indices map[string]int // Internal — group name to subexpression index. Consumer: Parse.
}

// NewRegexParser compiles pattern and verifies all mandatory named groups are present.
// Returns an error if the regex is invalid or a mandatory group is missing.
// Callers should treat this as a fatal startup error.
//
// Called from: profiles.go (profile constructors).
// Non-blocking.
func NewRegexParser(pattern string) (*RegexParser, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("regex parser: invalid pattern: %w", err)
	}

	// Build group-name → index map from the compiled regex.
	indices := make(map[string]int, len(re.SubexpNames()))
	for i, name := range re.SubexpNames() {
		if name != "" {
			indices[name] = i
		}
	}

	// Verify all mandatory groups are present.
	for _, g := range mandatoryGroups {
		if _, ok := indices[g]; !ok {
			return nil, fmt.Errorf("regex parser: mandatory named group %q missing from pattern", g)
		}
	}

	return &RegexParser{re: re, indices: indices}, nil
}

// Parse extracts a LogEntry from a single log line.
// Returns (nil, false) if the line does not match the pattern.
//
// Called from: pipeline (main.go parser loop).
// Non-blocking.
func (p *RegexParser) Parse(line string) (*LogEntry, bool) {
	m := p.re.FindStringSubmatch(line)
	if m == nil {
		return nil, false
	}

	get := func(name string) string {
		if i, ok := p.indices[name]; ok {
			return m[i]
		}
		return ""
	}

	// time — try nginxTimeLayout first, then haproxyTimeLayout (milliseconds, no tz).
	// Zero value on mismatch is non-fatal — detectors that skip time (probe, ua, etc.) still work.
	var t time.Time
	if raw := get("time"); raw != "" {
		if t, _ = time.Parse(nginxTimeLayout, raw); t.IsZero() {
			t, _ = time.Parse(haproxyTimeLayout, raw)
		}
	}

	method, rawURI, proto := splitRequest(get("request"))
	path, query := splitURI(rawURI)

	status, _ := strconv.Atoi(get("status"))
	bytesSent, _ := strconv.ParseInt(get("bytes_sent"), 10, 64)

	remoteAddr := get("remote_addr")
	realIP := extractRealIP(get("real_ip"), remoteAddr)

	return &LogEntry{
		RemoteAddr: remoteAddr,
		RemoteUser: get("remote_user"),
		Time:       t,
		Method:     method,
		RawURI:     rawURI,
		Path:       path,
		Query:      query,
		Protocol:   proto,
		Status:     status,
		BytesSent:  bytesSent,
		Referer:    get("http_referer"),
		UserAgent:  get("http_user_agent"),
		RealIP:     realIP,
	}, true
}
