// ========================== blocklist/parser ==========================================
//
//	Pattern list parsers for blocklist sources.
//
//	WHAT IS HERE:
//	  Parser       — interface: Parse(data []byte) ([]string, error)
//	  PlainTextParser — one pattern per line, # comments and blank lines skipped
//	  NginxMapParser  — extracts names from nginx map format (?:\b)...(?:\b)
//	  NewParser    — factory by format name ("plain_text", "nginx_map")
//
//	WHAT IS NOT HERE:
//	  HTTP fetch logic (Manager fetches, Parser only parses bytes)
//	  Storage (bbolt) — that is Manager's concern
//
//	Migrated from internal/core/detector/badbot.go (parseList, parseNginxMap).
//	Implemented: Flow #025, Task 1.
package blocklist

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

// nginxPatternRe extracts the bot/referrer name from nginx map entries like:
//
//	"~*(?:\b)AhrefsBot(?:\b)"    3;
var nginxPatternRe = regexp.MustCompile(`\(\?:\\b\)(.+?)\(\?:\\b\)`)

// unescapeRegexRe strips regex escapes of the form `\X` where X is a non-alphanumeric
// character. For example, `\.` → `.`, `\/` → `/`, `\\` → `\`. Applied during
// normalization — patterns from upstream sources often arrive in regex form, while
// the detector matches via substring through Aho-Corasick.
var unescapeRegexRe = regexp.MustCompile(`\\([^A-Za-z0-9])`)

// normalizePatternForSubstring converts a regex pattern from an upstream source into
// a clean substring literal suitable for Aho-Corasick matching.
//
// Why this is needed: upstream lists such as mitchellkrogza/nginx-ultimate-bad-bot-blocker
// store patterns in regex form (with escaping and anchors). The blocklist detector
// performs substring matching (Aho-Corasick, see Manager.Match/MatchResult), not
// regex. Without normalization, the pattern `1h4x\.com` (with an escaped dot) will
// never match the real UA `1h4x.com` — neither as regex nor as literal.
//
// Transformations (order matters):
//  1. Strip backslash regex escapes: `\X` → `X` for X not in [A-Za-z0-9].
//  2. Remove leading/trailing anchors: leading `^`, trailing `$`.
//  3. Remove wildcards `.*` and `.+` (including in the middle — a simple heuristic
//     acceptable for typical bot lists, which rarely use `.*` meaningfully in the
//     middle; complex constructs like `(?:a|b).*c` are not deeply parsed).
//  4. Final trim of spaces and wildcards at the ends.
//
// The function is pure, deterministic, and does not log. It does not drop patterns —
// even unrecognised regex fragments remain in a form suitable for substring matching
// (e.g. `prefix.*suffix` → `prefixsuffix`).
//
// Not called for an empty string (the caller filters empty strings earlier).
func normalizePatternForSubstring(p string) string {
	// Step 1: strip regex escapes.
	p = unescapeRegexRe.ReplaceAllString(p, "$1")

	// Step 2: remove leading `^` and trailing `$` (substring does not need anchors).
	p = strings.TrimLeft(p, "^")
	p = strings.TrimRight(p, "$")

	// Step 3: remove wildcards `.*` and `.+` (including in the middle).
	// Allow greedy replacement — a simple heuristic is better than a complex parser.
	for {
		prev := p
		p = strings.ReplaceAll(p, ".*", "")
		p = strings.ReplaceAll(p, ".+", "")
		if p == prev {
			break
		}
	}

	// Step 4: trim spaces and residual anchors at the ends.
	// Dots, asterisks, pluses, and question marks are intentionally NOT trimmed — they may be
	// a legitimate part of the literal after escape removal (e.g. `1.0`).
	p = strings.TrimSpace(p)
	p = strings.Trim(p, "^$")

	return p
}

// Parser parses raw bytes from a blocklist source into a slice of lowercase patterns.
// Implementations must be stateless and safe for concurrent use.
//
// Internal — not exposed via config. Consumer: NewParser.
type Parser interface {
	Parse(data []byte) ([]string, error)
}

// NewParser returns a Parser for the given format name.
// Supported: "plain_text", "nginx_map".
// Unknown format returns an error — fail early, before any network fetch.
//
// Called from: fetchAndUpdate (manager.go).
// Non-blocking.
func NewParser(format string) (Parser, error) {
	switch format {
	case "plain_text":
		return PlainTextParser{}, nil
	case "nginx_map":
		return NginxMapParser{}, nil
	default:
		return nil, fmt.Errorf("unknown blocklist format %q; supported: plain_text, nginx_map", format)
	}
}

// ── PlainTextParser ───────────────────────────────────────────────────────────────────

// PlainTextParser parses blocklists where each non-empty, non-comment line is a pattern.
// Lines starting with '#' and blank lines are skipped.
// Patterns are lowercased for case-insensitive Aho-Corasick matching.
type PlainTextParser struct{}

// Parse splits data by newline and returns all valid patterns, lowercased.
//
// Before lowercasing, normalizePatternForSubstring is applied: upstream plain_text
// lists often contain regex patterns (with escaping and anchors), while the
// detector performs substring matching.
//
// Called from: fetchAndUpdate (manager.go).
// Non-blocking.
func (PlainTextParser) Parse(data []byte) ([]string, error) {
	var result []string
	for _, line := range bytes.Split(data, []byte("\n")) {
		s := strings.TrimSpace(string(line))
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		// Normalize regex→literal before lowercasing so Aho-Corasick receives clean literals.
		s = normalizePatternForSubstring(s)
		if s == "" {
			continue
		}
		result = append(result, strings.ToLower(s))
	}
	return result, nil
}

// ── NginxMapParser ────────────────────────────────────────────────────────────────────

// NginxMapParser extracts patterns from nginx map format used in globalblacklist.conf.
// Matches entries of the form:
//
//	"~*(?:\b)AhrefsBot(?:\b)"    3;
//
// Used as a fallback when a source uses nginx map format instead of plain text.
// Patterns are lowercased for case-insensitive Aho-Corasick matching.
type NginxMapParser struct{}

// Parse extracts all (?:\b)..(?:\b) captures and returns them lowercased.
//
// Before lowercasing, normalizePatternForSubstring is applied: even in the nginx-map
// format the group may contain regex-escaped characters.
//
// Called from: fetchAndUpdate (manager.go).
// Non-blocking.
func (NginxMapParser) Parse(data []byte) ([]string, error) {
	matches := nginxPatternRe.FindAllSubmatch(data, -1)
	result := make([]string, 0, len(matches))
	for _, m := range matches {
		if len(m) > 1 {
			s := normalizePatternForSubstring(string(m[1]))
			if s == "" {
				continue
			}
			result = append(result, strings.ToLower(s))
		}
	}
	return result, nil
}
