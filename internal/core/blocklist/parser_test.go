// ========================== internal/core/blocklist — parser_test.go ========
//   Tests for AhoCorasickParser: pattern parsing, matching, reload.

package blocklist

import (
	"strings"
	"testing"
)

// ── NewParser factory ─────────────────────────────────────────────────────────────────

func TestNewParser_KnownFormats(t *testing.T) {
	for _, format := range []string{"plain_text", "nginx_map"} {
		p, err := NewParser(format)
		if err != nil {
			t.Errorf("NewParser(%q): unexpected error: %v", format, err)
		}
		if p == nil {
			t.Errorf("NewParser(%q): got nil parser", format)
		}
	}
}

func TestNewParser_UnknownFormat(t *testing.T) {
	_, err := NewParser("csv")
	if err == nil {
		t.Error("NewParser(unknown): expected error, got nil")
	}
	if !strings.Contains(err.Error(), "csv") {
		t.Errorf("error should mention the unknown format, got: %v", err)
	}
}

// ── PlainTextParser ───────────────────────────────────────────────────────────────────

func TestPlainTextParser_Basic(t *testing.T) {
	input := []byte("AhrefsBot\nSemrushBot\nMJ12bot\n")
	p := PlainTextParser{}
	got, err := p.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"ahrefsbot", "semrushbot", "mj12bot"}
	if !strSliceEqual(got, want) {
		t.Errorf("want %v, got %v", want, got)
	}
}

func TestPlainTextParser_SkipsCommentsAndBlankLines(t *testing.T) {
	input := []byte("# comment\nAhrefsBot\n\n  \nMJ12bot\n# another\n")
	p := PlainTextParser{}
	got, err := p.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"ahrefsbot", "mj12bot"}
	if !strSliceEqual(got, want) {
		t.Errorf("want %v, got %v", want, got)
	}
}

func TestPlainTextParser_Lowercase(t *testing.T) {
	input := []byte("AhrefsBot\nSEMRUSHBOT\n")
	p := PlainTextParser{}
	got, err := p.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, s := range got {
		if s != strings.ToLower(s) {
			t.Errorf("pattern %q is not lowercase", s)
		}
	}
}

func TestPlainTextParser_Empty(t *testing.T) {
	p := PlainTextParser{}
	got, err := p.Parse([]byte(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("want empty, got %v", got)
	}
}

func TestPlainTextParser_OnlyComments(t *testing.T) {
	input := []byte("# this is all comments\n# nothing here\n")
	p := PlainTextParser{}
	got, err := p.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("want empty for comment-only input, got %v", got)
	}
}

// ── NginxMapParser ────────────────────────────────────────────────────────────────────

func TestNginxMapParser_Basic(t *testing.T) {
	input := []byte(
		`"~*(?:\b)AhrefsBot(?:\b)"    3;` + "\n" +
			`"~*(?:\b)SemrushBot(?:\b)"   3;`,
	)
	p := NginxMapParser{}
	got, err := p.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"ahrefsbot", "semrushbot"}
	if !strSliceEqual(got, want) {
		t.Errorf("want %v, got %v", want, got)
	}
}

func TestNginxMapParser_NoMatchOnPlainText(t *testing.T) {
	// Plain-text input must not produce false positives in nginx parser.
	input := []byte("AhrefsBot\nSemrushBot\n")
	p := NginxMapParser{}
	got, err := p.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("want empty for plain-text input, got %v", got)
	}
}

func TestNginxMapParser_Empty(t *testing.T) {
	p := NginxMapParser{}
	got, err := p.Parse([]byte(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("want empty, got %v", got)
	}
}

func TestNginxMapParser_Lowercase(t *testing.T) {
	input := []byte(`"~*(?:\b)AHREFSBOT(?:\b)"    3;`)
	p := NginxMapParser{}
	got, err := p.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, s := range got {
		if s != strings.ToLower(s) {
			t.Errorf("pattern %q is not lowercase", s)
		}
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────────────

func strSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ── normalizePatternForSubstring ──────────────────────────────────────────────────────
//
// Цель этих тестов — зафиксировать поведение нормализации regex→literal для
// substring-матча. Источник регрессии: mitchellkrogza/nginx-ultimate-bad-bot-blocker
// выдаёт паттерны с regex-эскейпами (`1h4x\.com`, `^BotName$`, и т.п.), а
// blocklist-детектор матчит их через Aho-Corasick как литералы.

func TestNormalize_UnescapesCommonRegexChars(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		// Кейс из багрепорта — должен снимать экранирование точки.
		{`1h4x\.com`, "1h4x.com"},
		{`\.`, "."},
		{`\/`, "/"},
		{`\-`, "-"},
		{`\\`, `\`},
		// Несколько эскейпов в одной строке.
		{`a\.b\/c`, "a.b/c"},
		// Idempotent: уже чистый паттерн не меняется.
		{"~BotName~", "~BotName~"},
		// Якоря снимаются (lowercase — ответственность Parse, не normalize).
		{`^BadBot$`, "BadBot"},
		// Wildcards в середине убираются (простая эвристика; сложные regex
		// вроде (?:a|b) НЕ разбираются — паттерн остаётся после снятия эскейпов).
		{`prefix.*suffix`, "prefixsuffix"},
		// Трейлинговый `.*$` снимается полностью.
		{`^.*BadBot.*$`, "BadBot"},
		// Алфано-цифровой символ после `\` не трогается (это легитимный
		// regex-эскейп в PCRE, не должно разбираться как substring).
		{`foo\wbar`, `foo\wbar`},
	}
	for _, tc := range cases {
		got := normalizePatternForSubstring(tc.in)
		if got != tc.want {
			t.Errorf("normalizePatternForSubstring(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalize_Idempotent(t *testing.T) {
	// Повторный вызов нормализации не меняет результат.
	inputs := []string{
		"ahrefsbot",
		"1h4x.com",
		"~botname~",
		"prefix-suffix",
	}
	for _, in := range inputs {
		once := normalizePatternForSubstring(in)
		twice := normalizePatternForSubstring(once)
		if once != twice {
			t.Errorf("not idempotent: %q -> %q -> %q", in, once, twice)
		}
	}
}

func TestPlainTextParser_AppliesNormalization(t *testing.T) {
	// Сквозной кейс: Parse должен привести regex-паттерн `1h4x\.com` к
	// литералу `1h4x.com`, пригодному для substring-матча.
	input := []byte(`1h4x\.com` + "\n" + `AhrefsBot` + "\n")
	p := PlainTextParser{}
	got, err := p.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"1h4x.com", "ahrefsbot"}
	if !strSliceEqual(got, want) {
		t.Errorf("want %v, got %v", want, got)
	}
}

func TestNginxMapParser_AppliesNormalization(t *testing.T) {
	// Даже в nginx-map формате содержимое группы нормализуется.
	input := []byte(`"~*(?:\b)1h4x\.com(?:\b)"    3;` + "\n")
	p := NginxMapParser{}
	got, err := p.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"1h4x.com"}
	if !strSliceEqual(got, want) {
		t.Errorf("want %v, got %v", want, got)
	}
}

func TestPlainTextParser_DropsEmptyAfterNormalize(t *testing.T) {
	// Паттерн, состоящий только из wildcards/якорей, должен быть отброшен,
	// а не превращён в пустую строку в результате.
	input := []byte(`^.*$` + "\n" + `RealBot` + "\n")
	p := PlainTextParser{}
	got, err := p.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"realbot"}
	if !strSliceEqual(got, want) {
		t.Errorf("want %v, got %v", want, got)
	}
}
