// ========================== Tests output/warnings ========================================

package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mr-addams/nginx-sentinel/internal/core/chaincheck"
)

// ========================== Test helpers =============================================

func newTestWriter(t *testing.T) (*WarningsWriter, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "warnings.log")
	w, err := NewWarningsWriter(path)
	if err != nil {
		t.Fatalf("NewWarningsWriter: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w, path
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	return string(data)
}

// ========================== Tests WarningsWriter =====================================

// TestWarningsWriter_WriteCloudflare verifies that a cloudflare result produces a line
// containing all required fields with the correct label.
func TestWarningsWriter_WriteCloudflare(t *testing.T) {
	w, path := newTestWriter(t)

	result := &chaincheck.CheckResult{
		Kind:        "cloudflare",
		IP:          "1.2.3.4",
		MatchedCIDR: "104.16.0.0/13",
	}
	if err := w.WriteChainWarning(result, "/var/log/nginx/access.log"); err != nil {
		t.Fatalf("WriteChainWarning: %v", err)
	}
	_ = w.Close()

	content := readFile(t, path)

	for _, want := range []string{
		"CHAIN_WARN",
		"cloudflare-ip-as-client",
		"ip=1.2.3.4",
		"cidr=104.16.0.0/13",
		"log=/var/log/nginx/access.log",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("line does not contain %q: %s", want, content)
		}
	}
}

// TestWarningsWriter_WriteBogon verifies that a bogon result produces a line
// containing all required fields with the "bogon-ip-as-client" label.
func TestWarningsWriter_WriteBogon(t *testing.T) {
	w, path := newTestWriter(t)

	result := &chaincheck.CheckResult{
		Kind:        "bogon",
		IP:          "10.0.0.1",
		MatchedCIDR: "10.0.0.0/8",
	}
	if err := w.WriteChainWarning(result, "/var/log/apache/access.log"); err != nil {
		t.Fatalf("WriteChainWarning: %v", err)
	}
	_ = w.Close()

	content := readFile(t, path)

	for _, want := range []string{
		"CHAIN_WARN",
		"bogon-ip-as-client",
		"ip=10.0.0.1",
		"cidr=10.0.0.0/8",
		"log=/var/log/apache/access.log",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("line does not contain %q: %s", want, content)
		}
	}
}

// TestWarningsWriter_Append verifies that two WriteChainWarning calls produce two lines,
// each terminated with a newline character.
func TestWarningsWriter_Append(t *testing.T) {
	w, path := newTestWriter(t)

	results := []*chaincheck.CheckResult{
		{Kind: "cloudflare", IP: "1.2.3.4", MatchedCIDR: "104.16.0.0/13"},
		{Kind: "bogon", IP: "10.0.0.1", MatchedCIDR: "10.0.0.0/8"},
	}
	for _, r := range results {
		if err := w.WriteChainWarning(r, "/var/log/nginx/access.log"); err != nil {
			t.Fatalf("WriteChainWarning: %v", err)
		}
	}
	_ = w.Close()

	content := readFile(t, path)
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")

	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d:\n%s", len(lines), content)
	}

	// Each line must end with \n — check raw content has trailing newlines.
	// TrimRight removed the final newline; verify the split produced exactly 2 non-empty lines.
	for i, line := range lines {
		if line == "" {
			t.Errorf("line %d is empty", i+1)
		}
	}

	// Verify the original content has two newline terminators.
	if strings.Count(content, "\n") != 2 {
		t.Errorf("expected 2 newlines in file content, got %d", strings.Count(content, "\n"))
	}
}

// TestWarningsWriter_Reopen verifies that Reopen does not lose data:
// records written before and after Reopen both appear in the file.
func TestWarningsWriter_Reopen(t *testing.T) {
	w, path := newTestWriter(t)

	before := &chaincheck.CheckResult{Kind: "cloudflare", IP: "1.1.1.1", MatchedCIDR: "104.16.0.0/13"}
	after := &chaincheck.CheckResult{Kind: "bogon", IP: "10.0.0.2", MatchedCIDR: "10.0.0.0/8"}

	if err := w.WriteChainWarning(before, "/before.log"); err != nil {
		t.Fatalf("WriteChainWarning before reopen: %v", err)
	}

	if err := w.Reopen(); err != nil {
		t.Fatalf("Reopen: %v", err)
	}

	if err := w.WriteChainWarning(after, "/after.log"); err != nil {
		t.Fatalf("WriteChainWarning after reopen: %v", err)
	}
	_ = w.Close()

	content := readFile(t, path)

	// Both records must be in the file — Reopen appends, does not truncate.
	if !strings.Contains(content, "ip=1.1.1.1") {
		t.Errorf("record written before Reopen not found: %s", content)
	}
	if !strings.Contains(content, "ip=10.0.0.2") {
		t.Errorf("record written after Reopen not found: %s", content)
	}
}
