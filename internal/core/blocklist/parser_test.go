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
