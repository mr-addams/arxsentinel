// ========================== Module parser/profiles ======================================
//   Built-in server profiles: preconfigured parsers for common HTTP servers.
//   Each profile wraps an existing parser (RegexParser) with server-specific settings.
//
//   WHAT IS HERE:
//     - Profiles map: profile name → factory function
//     - AvailableProfiles(): sorted list for error messages
//     - Four profiles: apache, caddy, traefik, haproxy-http
//
//   Design note (Decision 2 deviation):
//     DECISIONS.md planned caddy and traefik as JSONParser profiles.
//     In practice, Caddy v2 JSON uses nested objects and Traefik JSON splits
//     the request into method/path/proto — neither maps cleanly to JSONParser's
//     single-field "request" contract.
//     All four profiles use RegexParser instead.
//     Deploy examples (deploy/examples/<server>/) show the server-side config
//     that produces logs matching the profile's pattern.
//
//   WHAT IS NOT HERE:
//     - Parser interface (parser.go)
//     - buildParser dispatch (main.go)

package parser

import (
	"sort"
	"strings"
)

// apacheCLFPattern matches Apache Combined Log Format.
// Also used for Caddy (configured to emit CLF) and Traefik (CLF default).
//
// bytes_sent captured as \S+ — Apache logs "-" for zero-body responses;
// strconv.ParseInt ignores the error and returns 0.
//
// No end anchor ($) — Traefik appends extra fields (duration, router, service)
// after the User-Agent; the trailing content is safely ignored.
const apacheCLFPattern = `^(?P<remote_addr>\S+) \S+ (?P<remote_user>\S+) \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d+) (?P<bytes_sent>\S+)(?: "(?P<http_referer>[^"]*)" "(?P<http_user_agent>[^"]*)")?`

// haproxyHTTPPattern matches HAProxy access logs produced by "option httplog" (no syslog prefix).
//
// HAProxy time includes milliseconds: "01/Nov/2022:10:11:12.456"
// This does not match nginxTimeLayout; time.Parse fails silently → time.Time{} (non-fatal).
// Detectors that do not inspect timestamp still work correctly.
//
// Format after time: frontend~ backend/server timers status bytes req_cookie resp_cookie
//                    term_state actconn queue "request"
const haproxyHTTPPattern = `^(?P<remote_addr>[^:]+):\d+ \[(?P<time>[^\]]+)\] \S+ \S+ \S+ (?P<status>\d+) (?P<bytes_sent>\d+) \S+ \S+ \S+ \S+ \S+ "(?P<request>[^"]*)"`

// Profiles maps built-in profile names to parser factory functions.
// Priority in buildParser: profile → log_format → default combined (Decision 1).
// Adding a new profile requires only a new entry here — main.go is not touched.
var Profiles = map[string]func() (Parser, error){
	"apache":       apacheProfile,
	"caddy":        caddyProfile,
	"traefik":      traefikProfile,
	"haproxy-http": haproxyHTTPProfile,
}

func apacheProfile() (Parser, error) {
	return NewRegexParser(apacheCLFPattern)
}

// caddyProfile uses Apache CLF pattern.
// Configure Caddy v2 with the transform-encoder plugin to output CLF format;
// see deploy/examples/caddy/ for the Caddyfile configuration.
func caddyProfile() (Parser, error) {
	return NewRegexParser(apacheCLFPattern)
}

// traefikProfile uses Apache CLF pattern without end anchor.
// Traefik appends extra fields (duration_ms, captured headers, router, service, retries)
// after the User-Agent; the pattern's lack of $ silently ignores them.
// Configure Traefik with accessLog enabled (default format is common/CLF).
func traefikProfile() (Parser, error) {
	return NewRegexParser(apacheCLFPattern)
}

func haproxyHTTPProfile() (Parser, error) {
	return NewRegexParser(haproxyHTTPPattern)
}

// AvailableProfiles returns a sorted, comma-separated list of known profile names.
// Used in error messages when an unknown profile is specified in config.
func AvailableProfiles() string {
	names := make([]string, 0, len(Profiles))
	for k := range Profiles {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}
