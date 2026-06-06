// ========================== blocklist/parser ==========================================
//   Pattern list parsers for blocklist sources.
//
//   WHAT IS HERE:
//     Parser       — interface: Parse(data []byte) ([]string, error)
//     PlainTextParser — one pattern per line, # comments and blank lines skipped
//     NginxMapParser  — extracts names from nginx map format (?:\b)...(?:\b)
//     NewParser    — factory by format name ("plain_text", "nginx_map")
//
//   WHAT IS NOT HERE:
//     HTTP fetch logic (Manager fetches, Parser only parses bytes)
//     Storage (bbolt) — that is Manager's concern
//
//   Migrated from internal/core/detector/badbot.go (parseList, parseNginxMap).
//   Implemented: Flow #025, Task 1.

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
// Called from: fetchAndUpdate (manager.go).
// Non-blocking.
func (PlainTextParser) Parse(data []byte) ([]string, error) {
	var result []string
	for _, line := range bytes.Split(data, []byte("\n")) {
		s := strings.TrimSpace(string(line))
		if s == "" || strings.HasPrefix(s, "#") {
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
// Called from: fetchAndUpdate (manager.go).
// Non-blocking.
func (NginxMapParser) Parse(data []byte) ([]string, error) {
	matches := nginxPatternRe.FindAllSubmatch(data, -1)
	result := make([]string, 0, len(matches))
	for _, m := range matches {
		if len(m) > 1 {
			result = append(result, strings.ToLower(string(m[1])))
		}
	}
	return result, nil
}
