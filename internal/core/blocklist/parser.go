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

// unescapeRegexRe снимает regex-эскейпы вида `\X`, где X — не алфавитно-цифровой
// символ. Например, `\.` → `.`, `\/` → `/`, `\\` → `\`. Применяется на стадии
// нормализации — паттерны из upstream-списков часто приходят в regex-форме, а
// детектор матчит substring'ом через Aho-Corasick.
var unescapeRegexRe = regexp.MustCompile(`\\([^A-Za-z0-9])`)

// normalizePatternForSubstring приводит regex-паттерн из upstream-источника к
// чистому substring-литералу, пригодному для матчинга Aho-Corasick.
//
// Зачем это нужно: upstream-списки вроде mitchellkrogza/nginx-ultimate-bad-bot-blocker
// хранят шаблоны в regex-форме (с экранированием и якорями). Blocklist-детектор
// выполняет substring-матч (Aho-Corasick, см. Manager.Match/MatchResult), а не
// regex. Без нормализации паттерн `1h4x\.com` (с экранированной точкой) никогда
// не совпадёт с реальным UA `1h4x.com` — ни в виде regex, ни в виде literal.
//
// Трансформации (порядок важен):
//  1. Снять regex-эскейпы бэкслэшем: `\X` → `X` для X не [A-Za-z0-9].
//  2. Убрать ведущие/трейлинговые якоря: `^` в начале, `$` в конце.
//  3. Убрать wildcards `.*` и `.+` (включая посередине — простая эвристика,
//     приемлемая для типичных bot-листов, которые редко используют `.*` осмысленно
//     в середине; сложные конструкции типа `(?:a|b).*c` не разбираются глубоко).
//  4. Финальный trim пробелов и wildcards на концах.
//
// Функция чистая, детерминированная, без логирования. Не отбрасывает паттерны —
// даже нераспознанные regex-фрагменты остаются в виде, пригодном для substring-match
// (например, `prefix.*suffix` → `prefixsuffix`).
//
// Не вызывается для пустой строки (вызывающий код фильтрует пустые строки раньше).
func normalizePatternForSubstring(p string) string {
	// Шаг 1: снять regex-эскейпы.
	p = unescapeRegexRe.ReplaceAllString(p, "$1")

	// Шаг 2: убрать leading `^` и trailing `$` (substring не нуждается в якорях).
	p = strings.TrimLeft(p, "^")
	p = strings.TrimRight(p, "$")

	// Шаг 3: убрать wildcards `.*` и `.+` (включая в середине).
	// Допускаем жадную замену — простая эвристика лучше, чем сложный парсер.
	for {
		prev := p
		p = strings.ReplaceAll(p, ".*", "")
		p = strings.ReplaceAll(p, ".+", "")
		if p == prev {
			break
		}
	}

	// Шаг 4: trim пробелов и остаточных якорей на концах.
	// Точки/звёздочки/плюсы/вопросы намеренно НЕ триммим — они могут быть
	// легитимной частью литерала после снятия эскейпов (например, `1.0`).
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
// Перед lowercase применяется normalizePatternForSubstring: upstream plain_text-
// списки часто содержат regex-паттерны (с экранированием и якорями), а детектор
// выполняет substring-матч.
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
		// Нормализуем regex→literal до lowercase, чтобы Aho-Corasick получил чистые литералы.
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
// Перед lowercase применяется normalizePatternForSubstring: даже в nginx-map
// формате группа может содержать regex-эскейпленные символы.
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
