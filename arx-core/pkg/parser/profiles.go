// ========================== Module parser/profiles ======================================
//   Built-in server profiles: preconfigured parsers for common HTTP servers.
//   Each profile wraps an existing parser (RegexParser) with server-specific settings.
//
//   WHAT IS HERE:
//     - Profiles map: profile name → factory function
//     - AvailableProfiles(): sorted list for error messages
//     - Five profiles: apache, caddy, traefik, haproxy-http, litespeed
//
//   Design note (Decision 2 deviation):
//     DECISIONS.md planned caddy and traefik as JSONParser profiles.
//     In practice, Caddy v2 JSON uses nested objects and Traefik JSON splits
//     the request into method/path/proto — neither maps cleanly to JSONParser's
//     single-field "request" contract.
//     All five profiles use RegexParser instead.
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
// Also used for Caddy (configured to emit CLF), Traefik (CLF default), and LiteSpeed / OpenLiteSpeed.
//
// bytes_sent captured as \S+ — Apache logs "-" for zero-body responses;
// strconv.ParseInt ignores the error and returns 0.
//
// No end anchor ($) — Traefik appends extra fields (duration, router, service)
// after the User-Agent; the trailing content is safely ignored.
const apacheCLFPattern = `^(?P<remote_addr>\S+) \S+ (?P<remote_user>\S+) \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d+) (?P<bytes_sent>\S+)(?: "(?P<http_referer>[^"]*)" "(?P<http_user_agent>[^"]*)")?`

// haproxyHTTPPattern matches HAProxy access logs in the httplog-derived format.
// The format ends with a quoted request; an optional quoted User-Agent field follows
// when HAProxy is configured with http-request capture + log-format UA extension.
//
// HAProxy time includes milliseconds: "01/Nov/2022:10:11:12.456"
// Parsed via haproxyTimeLayout fallback in RegexParser — all detectors including rate work.
//
// Format after time: frontend~ backend/server timers status bytes req_cookie resp_cookie
//
//	term_state actconn queue "request" ["user-agent"]
const haproxyHTTPPattern = `^(?P<remote_addr>[^:]+):\d+ \[(?P<time>[^\]]+)\] \S+ \S+ \S+ (?P<status>\d+) (?P<bytes_sent>\d+) \S+ \S+ \S+ \S+ \S+ "(?P<request>[^"]*)"(?: "(?P<http_user_agent>[^"]*)")?`

// Profiles maps built-in profile names to parser factory functions.
// Priority in buildParser: profile → log_format → default combined (Decision 1).
// Adding a new profile requires only a new entry here — main.go is not touched.
//
// Internal — not exposed via config. Consumer: profiles.go (this file).
var Profiles = map[string]func() (Parser, error){
	"apache":       apacheProfile,
	"caddy":        caddyProfile,
	"traefik":      traefikProfile,
	"haproxy-http": haproxyHTTPProfile,
	"litespeed":    litespeedProfile,
}

// apacheProfile creates a RegexParser for Apache Combined Log Format.
// Also used for Caddy (CLF) and Traefik (CLF default).
//
// Called from: AvailableProfiles, config loader (internal/sys/config).
// Non-blocking.
func apacheProfile() (Parser, error) {
	return NewRegexParser(apacheCLFPattern)
}

// caddyProfile creates a RegexParser for Caddy v2 CLF format.
// Configure Caddy v2 with the transform-encoder plugin to output CLF format;
// see deploy/examples/caddy/ for the Caddyfile configuration.
//
// Called from: AvailableProfiles, config loader (internal/sys/config).
// Non-blocking.
func caddyProfile() (Parser, error) {
	return NewRegexParser(apacheCLFPattern)
}

// traefikProfile creates a RegexParser for Traefik CLF format without end anchor.
// Traefik appends extra fields (duration_ms, captured headers, router, service, retries)
// after the User-Agent; the pattern's lack of $ silently ignores them.
// Configure Traefik with accessLog enabled (default format is common/CLF).
//
// Called from: AvailableProfiles, config loader (internal/sys/config).
// Non-blocking.
func traefikProfile() (Parser, error) {
	return NewRegexParser(apacheCLFPattern)
}

// haproxyHTTPProfile creates a RegexParser for HAProxy HTTP access logs.
//
// Called from: AvailableProfiles, config loader (internal/sys/config).
// Non-blocking.
func haproxyHTTPProfile() (Parser, error) {
	return NewRegexParser(haproxyHTTPPattern)
}

// litespeedProfile creates a RegexParser for LiteSpeed/OpenLiteSpeed CLF format.
// Both LSWS and OLS emit Apache CLF by default — no server-side log format changes required.
//
// Real IP behind a proxy: enable "Use Client IP in Header" in the WebAdmin panel
// (or <useIpInProxyHeader>1</useIpInProxyHeader> in httpd_config.xml).
// The server then writes the client IP into %h directly — RealIP == RemoteAddr in sentinel.
//
// Default log path: /usr/local/lsws/logs/access.log
// VirtualHost log:  /usr/local/lsws/logs/<vhostname>/access.log
//
// Called from: AvailableProfiles, config loader (internal/sys/config).
// Non-blocking.
func litespeedProfile() (Parser, error) {
	return NewRegexParser(apacheCLFPattern)
}

// AvailableProfiles returns a sorted, comma-separated list of known profile names.
// Used in error messages when an unknown profile is specified in config.
//
// Called from: config loader (internal/sys/config).
// Non-blocking.
func AvailableProfiles() string {
	names := make([]string, 0, len(Profiles))
	for k := range Profiles {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}
