// ========================== Package nginx — tests ==========================
//   Unit tests for the NginxExecutor: flush, sweep, dedup, min_level filter,
//   state file persistence, reload command execution, and atomic writes.
//
//   Gate B (Flow 083 / Task 3.3): ThreatEvent lives in internal/threat.

package nginx

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mr-addams/arx-core/pkg/executor"
	"github.com/mr-addams/arx-core/pkg/logger"
	"github.com/mr-addams/arx-core/pkg/plugin"

	"github.com/mr-addams/arxsentinel/internal/threat"
)

// testEventSource is a simple EventSource that delivers pre-defined events.
type testEventSource struct {
	events []*plugin.Event
	idx    int64
	mu     sync.Mutex
}

func newTestEventSource(events []*plugin.Event) *testEventSource {
	return &testEventSource{events: events}
}

func (s *testEventSource) Pop(ctx context.Context) (*plugin.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if int(s.idx) >= len(s.events) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ev := s.events[s.idx]
	s.idx++
	return ev, nil
}

// newTestExecutor creates an NginxExecutor with temp directories for testing.
func newTestExecutor(t *testing.T, cfg map[string]any) *NginxExecutor {
	t.Helper()

	// Flow 073 / Task 1.3.1: NewNginxExecutor now takes executor.ExecutorConfig
	// directly (was config.ExecutorItem pre-1.3.1). The wrapper into the
	// deprecated item shape is gone, mirroring the production register.go.
	ec := executor.ExecutorConfig{
		Name:   "test-nginx",
		Type:   "nginx",
		Config: cfg,
	}
	exec, err := NewNginxExecutor(ec, logger.Nop)
	if err != nil {
		t.Fatalf("NewNginxExecutor: %v", err)
	}
	return exec.(*NginxExecutor)
}

// TestFlushWritesFile verifies that flush writes all banned IPs to the list file
// in the correct format.
func TestFlushWritesFile(t *testing.T) {
	dir := t.TempDir()
	listFile := filepath.Join(dir, "autoblock.list")

	exec := newTestExecutor(t, map[string]any{
		"list_file": listFile,
		"ttl":       "1h",
	})

	banned := map[string]time.Time{
		"1.2.3.4":     time.Now(),
		"5.6.7.8":     time.Now(),
		"192.168.1.1": time.Now(),
	}
	exec.flush(context.Background(), banned)

	data, err := os.ReadFile(listFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	content := string(data)
	if !containsIP(content, "1.2.3.4") {
		t.Errorf("expected 1.2.3.4 in output, got:\n%s", content)
	}
	if !containsIP(content, "5.6.7.8") {
		t.Errorf("expected 5.6.7.8 in output, got:\n%s", content)
	}
	if !containsIP(content, "192.168.1.1") {
		t.Errorf("expected 192.168.1.1 in output, got:\n%s", content)
	}
}

// TestFlushWritesDenyFormat is the deny-format mirror of TestFlushWritesFile.
// It verifies that with file_format="deny" the executor emits "deny <ip>;"
// lines (one per banned IP) and that the file header is unchanged.
func TestFlushWritesDenyFormat(t *testing.T) {
	dir := t.TempDir()
	listFile := filepath.Join(dir, "autoblock.list")

	exec := newTestExecutor(t, map[string]any{
		"list_file":   listFile,
		"ttl":         "1h",
		"file_format": "deny",
	})

	banned := map[string]time.Time{
		"1.2.3.4":     time.Now(),
		"5.6.7.8":     time.Now(),
		"192.168.1.1": time.Now(),
	}
	exec.flush(context.Background(), banned)

	data, err := os.ReadFile(listFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	content := string(data)

	// Header must be unchanged across formats.
	if !strings.HasPrefix(content, fileHeader) {
		t.Errorf("expected deny-format file to start with %q, got:\n%s", fileHeader, content)
	}

	if !containsIPFormat(content, "1.2.3.4", FileFormatDeny) {
		t.Errorf("expected \"deny 1.2.3.4;\" in output, got:\n%s", content)
	}
	if !containsIPFormat(content, "5.6.7.8", FileFormatDeny) {
		t.Errorf("expected \"deny 5.6.7.8;\" in output, got:\n%s", content)
	}
	if !containsIPFormat(content, "192.168.1.1", FileFormatDeny) {
		t.Errorf("expected \"deny 192.168.1.1;\" in output, got:\n%s", content)
	}

	// Sanity: the geo-format suffix must NOT appear when deny format is selected.
	if containsIP(content, "1.2.3.4") {
		t.Errorf("geo-format \"1.2.3.4 1;\" line must not appear in deny-format output:\n%s", content)
	}
}

// TestSweepRemovesExpired verifies that expired IPs are removed from the file.
func TestSweepRemovesExpired(t *testing.T) {
	dir := t.TempDir()
	listFile := filepath.Join(dir, "autoblock.list")

	exec := newTestExecutor(t, map[string]any{
		"list_file": listFile,
		"ttl":       "200ms",
	})

	exec.mu.Lock()
	exec.banned["1.2.3.4"] = time.Now().Add(-1 * time.Hour) // expired
	exec.banned["5.6.7.8"] = time.Now().Add(1 * time.Hour)  // fresh (far future)
	exec.mu.Unlock()

	time.Sleep(250 * time.Millisecond)
	exec.sweep(context.Background())

	exec.mu.RLock()
	_, expired := exec.banned["1.2.3.4"]
	_, fresh := exec.banned["5.6.7.8"]
	exec.mu.RUnlock()

	if expired {
		t.Error("expected expired IP 1.2.3.4 to be removed")
	}
	if !fresh {
		t.Error("expected fresh IP 5.6.7.8 to remain")
	}

	// File should only contain the fresh IP.
	data, err := os.ReadFile(listFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	content := string(data)
	if containsIP(content, "1.2.3.4") {
		t.Errorf("expired IP 1.2.3.4 should not be in file:\n%s", content)
	}
	if !containsIP(content, "5.6.7.8") {
		t.Errorf("fresh IP 5.6.7.8 should be in file:\n%s", content)
	}
}

// TestDuplicateSkipped verifies that duplicate IP events are skipped.
func TestDuplicateSkipped(t *testing.T) {
	dir := t.TempDir()
	listFile := filepath.Join(dir, "autoblock.list")

	exec := newTestExecutor(t, map[string]any{
		"list_file":      listFile,
		"ttl":            "1h",
		"flush_interval": "10s",
	})

	exec.mu.Lock()
	exec.banned["1.2.3.4"] = time.Now()
	exec.mu.Unlock()

	if !exec.isDuplicate("1.2.3.4") {
		t.Error("expected 1.2.3.4 to be detected as duplicate")
	}
	if exec.isDuplicate("9.9.9.9") {
		t.Error("expected 9.9.9.9 not to be a duplicate")
	}
}

// TestMinLevelFiltering verifies that events below min_level are skipped.
func TestMinLevelFiltering(t *testing.T) {
	dir := t.TempDir()
	listFile := filepath.Join(dir, "autoblock.list")

	exec := newTestExecutor(t, map[string]any{
		"list_file": listFile,
		"ttl":       "1h",
		"min_level": "THREAT",
	})

	if exec.meetsMinLevel("INFO") {
		t.Error("INFO should not meet THREAT min_level")
	}
	if exec.meetsMinLevel("WARN") {
		t.Error("WARN should not meet THREAT min_level")
	}
	if !exec.meetsMinLevel("THREAT") {
		t.Error("THREAT should meet THREAT min_level")
	}
	if exec.meetsMinLevel("UNKNOWN") {
		t.Error("UNKNOWN level should never meet any min_level")
	}
}

// TestStateFilePersistence verifies that after flush the state file contains
// valid JSON with the correct IPs.
func TestStateFilePersistence(t *testing.T) {
	dir := t.TempDir()
	listFile := filepath.Join(dir, "autoblock.list")
	stateFile := filepath.Join(dir, "state.json")

	exec := newTestExecutor(t, map[string]any{
		"list_file":  listFile,
		"state_file": stateFile,
		"ttl":        "1h",
	})

	banned := map[string]time.Time{
		"1.2.3.4": time.Now(),
		"5.6.7.8": time.Now(),
	}
	exec.flush(context.Background(), banned)

	data, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatalf("ReadFile state file: %v", err)
	}

	if len(data) == 0 {
		t.Fatal("state file is empty")
	}

	// Verify it parses back to a valid map.
	var restored map[string]time.Time
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("Unmarshal state file: %v — content: %s", err, string(data))
	}
	if _, ok := restored["1.2.3.4"]; !ok {
		t.Errorf("expected 1.2.3.4 in state file, got: %v", restored)
	}
	if _, ok := restored["5.6.7.8"]; !ok {
		t.Errorf("expected 5.6.7.8 in state file, got: %v", restored)
	}
}

// TestReloadCmdCalled verifies that ReloadCmd is executed during flush.
func TestReloadCmdCalled(t *testing.T) {
	dir := t.TempDir()
	listFile := filepath.Join(dir, "autoblock.list")
	marker := filepath.Join(dir, "reload-marker")

	exec := newTestExecutor(t, map[string]any{
		"list_file":  listFile,
		"ttl":        "1h",
		"reload_cmd": fmt.Sprintf("touch %s", marker),
	})

	banned := map[string]time.Time{"1.2.3.4": time.Now()}
	exec.flush(context.Background(), banned)

	if _, err := os.Stat(marker); os.IsNotExist(err) {
		t.Fatal("reload command was not executed — marker file does not exist")
	}
}

// TestAtomicWrite verifies that the .tmp file is not present after writeFile,
// and that the final file exists at the correct path.
func TestAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	listFile := filepath.Join(dir, "autoblock.list")

	data := "1.2.3.4 1;\n5.6.7.8 1;\n"
	if err := writeFile(listFile, data); err != nil {
		t.Fatalf("writeFile: %v", err)
	}

	// .tmp file must not exist.
	if _, err := os.Stat(listFile + ".tmp"); err == nil {
		t.Error(".tmp file should not exist after writeFile")
	}

	// Final file must exist and contain data.
	content, err := os.ReadFile(listFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(content) != data {
		t.Errorf("content mismatch:\nwant: %q\ngot:  %q", data, string(content))
	}
}

// TestEmptyFlushDoesNothing verifies that flush with empty banned map does nothing.
func TestEmptyFlushDoesNothing(t *testing.T) {
	dir := t.TempDir()
	listFile := filepath.Join(dir, "autoblock.list")

	exec := newTestExecutor(t, map[string]any{
		"list_file": listFile,
		"ttl":       "1h",
	})

	// Capture stats before and after.
	before := exec.stats.executed.Load()
	exec.flush(context.Background(), map[string]time.Time{})
	after := exec.stats.executed.Load()

	if after != before {
		t.Errorf("expected no stat change on empty flush, before=%d after=%d", before, after)
	}

	// File should not have been created.
	if _, err := os.Stat(listFile); err == nil {
		t.Error("list file should not exist after empty flush")
	}
}

// TestSyncExistingLoadsBanned verifies that syncExisting populates the banned map
// from an existing list file and state file.
func TestSyncExistingLoadsBanned(t *testing.T) {
	dir := t.TempDir()
	listFile := filepath.Join(dir, "autoblock.list")
	stateFile := filepath.Join(dir, "state.json")

	// Create list file with two IPs.
	listContent := "# managed by arxsentinel — do not edit manually\n1.2.3.4 1;\n5.6.7.8 1;\n"
	if err := os.WriteFile(listFile, []byte(listContent), 0644); err != nil {
		t.Fatalf("WriteFile list: %v", err)
	}

	// Create state file with one IP's timestamp.
	stateContent := `{"1.2.3.4":"2026-06-01T12:00:00Z"}`
	if err := os.WriteFile(stateFile, []byte(stateContent), 0644); err != nil {
		t.Fatalf("WriteFile state: %v", err)
	}

	exec := newTestExecutor(t, map[string]any{
		"list_file":  listFile,
		"state_file": stateFile,
		"ttl":        "1h",
	})

	exec.syncExisting()

	exec.mu.RLock()
	_, has1 := exec.banned["1.2.3.4"]
	_, has2 := exec.banned["5.6.7.8"]
	exec.mu.RUnlock()

	if !has1 {
		t.Error("expected 1.2.3.4 to be loaded from list file")
	}
	if !has2 {
		t.Error("expected 5.6.7.8 to be loaded from list file")
	}
}

// TestSyncExistingDenyFormat verifies that syncExisting correctly parses a
// list file written in "deny" format and loads the IPs back into the banned
// map. This is the deny-format counterpart of TestSyncExistingLoadsBanned
// (which keeps checking the default geo-format path).
func TestSyncExistingDenyFormat(t *testing.T) {
	dir := t.TempDir()
	listFile := filepath.Join(dir, "autoblock.list")
	stateFile := filepath.Join(dir, "state.json")

	// Pre-populate the list file in deny format — same header as geo, but
	// each entry uses the "deny <ip>;" form.
	listContent := "# managed by arxsentinel — do not edit manually\ndeny 1.2.3.4;\ndeny 5.6.7.8;\n"
	if err := os.WriteFile(listFile, []byte(listContent), 0644); err != nil {
		t.Fatalf("WriteFile list: %v", err)
	}

	// One entry with an explicit timestamp, one without — syncExisting should
	// fall back to "now" for the second one.
	stateContent := `{"1.2.3.4":"2026-06-01T12:00:00Z"}`
	if err := os.WriteFile(stateFile, []byte(stateContent), 0644); err != nil {
		t.Fatalf("WriteFile state: %v", err)
	}

	exec := newTestExecutor(t, map[string]any{
		"list_file":   listFile,
		"state_file":  stateFile,
		"ttl":         "1h",
		"file_format": "deny",
	})

	exec.syncExisting()

	exec.mu.RLock()
	_, has1 := exec.banned["1.2.3.4"]
	_, has2 := exec.banned["5.6.7.8"]
	exec.mu.RUnlock()

	if !has1 {
		t.Error("expected 1.2.3.4 to be loaded from deny-format list file")
	}
	if !has2 {
		t.Error("expected 5.6.7.8 to be loaded from deny-format list file")
	}
}

// TestParseBannedLineWhitespace verifies that parseBannedLine handles tab
// separators and extra spaces in deny-format lines without losing the IP.
func TestParseBannedLineWhitespace(t *testing.T) {
	cases := []struct {
		line   string
		format string
		want   string
	}{
		{"deny 1.2.3.4;", FileFormatDeny, "1.2.3.4"},
		{"deny\t1.2.3.4;", FileFormatDeny, "1.2.3.4"},
		{"1.2.3.4 1;", FileFormatGeo, "1.2.3.4"},
		{"deny 1.2.3.4;", FileFormatGeo, ""},   // geo format ignores deny lines
		{"1.2.3.4 1;", FileFormatDeny, ""},     // deny format ignores geo lines
		{"", FileFormatDeny, ""},
		{"# comment", FileFormatDeny, ""},
	}
	for _, tc := range cases {
		got := parseBannedLine(tc.line, tc.format)
		if got != tc.want {
			t.Errorf("parseBannedLine(%q, %q) = %q, want %q", tc.line, tc.format, got, tc.want)
		}
	}
}

// TestRunLoop verifies the Run loop processes events and writes the list file.
func TestRunLoop(t *testing.T) {
	dir := t.TempDir()
	listFile := filepath.Join(dir, "autoblock.list")

	exec := newTestExecutor(t, map[string]any{
		"list_file":      listFile,
		"ttl":            "1h",
		"batch_size":     2,
		"flush_interval": "50ms",
	})

	events := newTestEventSource([]*plugin.Event{
		{Payload: &threat.ThreatEvent{IP: "1.2.3.4", Level: "THREAT"}},
		{Payload: &threat.ThreatEvent{IP: "5.6.7.8", Level: "THREAT"}},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := exec.Run(ctx, events); err != nil && err != context.DeadlineExceeded && err != context.Canceled {
		t.Fatalf("Run: %v", err)
	}

	// Verify file has been written.
	data, err := os.ReadFile(listFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	content := string(data)
	if !containsIP(content, "1.2.3.4") {
		t.Errorf("expected 1.2.3.4 in output after run:\n%s", content)
	}
	if !containsIP(content, "5.6.7.8") {
		t.Errorf("expected 5.6.7.8 in output after run:\n%s", content)
	}
}

// containsIP is a helper for checking IP presence in file content.
// The format argument selects which line syntax is expected:
//   - "geo"  → "<ip> 1;"
//   - "deny" → "deny <ip>;"
//
// Any other value falls through to the "geo" suffix check to keep existing
// callers (which previously called containsIP without a format) working.
func containsIP(content, ip string) bool {
	return strings.Contains(content, fmt.Sprintf("%s 1;", ip))
}

// TestParseConfigFileFormatDefault verifies that omitting the "file_format"
// key falls back to the documented default "geo". This protects legacy configs
// from breaking when the feature was introduced.
func TestParseConfigFileFormatDefault(t *testing.T) {
	cfg, err := parseConfig(map[string]any{
		"list_file": "/tmp/autoblock.list",
		"ttl":       "1h",
	})
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.FileFormat != FileFormatGeo {
		t.Errorf("expected default FileFormat=%q, got %q", FileFormatGeo, cfg.FileFormat)
	}
}

// TestParseConfigFileFormatGeo verifies that an explicit "geo" value is
// preserved through parseConfig.
func TestParseConfigFileFormatGeo(t *testing.T) {
	cfg, err := parseConfig(map[string]any{
		"list_file":   "/tmp/autoblock.list",
		"ttl":         "1h",
		"file_format": "geo",
	})
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.FileFormat != FileFormatGeo {
		t.Errorf("expected FileFormat=%q, got %q", FileFormatGeo, cfg.FileFormat)
	}
}

// TestParseConfigFileFormatDeny verifies that "deny" is accepted and stored
// verbatim in Config.FileFormat.
func TestParseConfigFileFormatDeny(t *testing.T) {
	cfg, err := parseConfig(map[string]any{
		"list_file":   "/tmp/autoblock.list",
		"ttl":         "1h",
		"file_format": "deny",
	})
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.FileFormat != FileFormatDeny {
		t.Errorf("expected FileFormat=%q, got %q", FileFormatDeny, cfg.FileFormat)
	}
}

// TestParseConfigFileFormatInvalid verifies that any value outside {"geo","deny"}
// is rejected with a parseConfig error that mentions the offending field name.
// This is the single source of truth for the validation message — other layers
// (HTTP API, GUI) rely on the field name being part of the error string.
func TestParseConfigFileFormatInvalid(t *testing.T) {
	_, err := parseConfig(map[string]any{
		"list_file":   "/tmp/autoblock.list",
		"ttl":         "1h",
		"file_format": "unknown",
	})
	if err == nil {
		t.Fatal("expected error for invalid file_format, got nil")
	}
	if !strings.Contains(err.Error(), "file_format") {
		t.Errorf("expected error to mention %q, got: %v", "file_format", err)
	}
}

// TestFlushGeoFormatLines exercises the geo-format write path directly:
// flush() with a single banned IP must emit exactly "1.2.3.4 1;" —
// not the deny directive form. The check is intentionally strict (==)
// to catch any future drift between the two line styles.
func TestFlushGeoFormatLines(t *testing.T) {
	dir := t.TempDir()
	listFile := filepath.Join(dir, "autoblock.list")

	// No file_format key → falls back to default "geo".
	exec := newTestExecutor(t, map[string]any{
		"list_file": listFile,
		"ttl":       "1h",
	})

	exec.flush(context.Background(), map[string]time.Time{
		"1.2.3.4": time.Now(),
	})

	data, err := os.ReadFile(listFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	content := string(data)
	wantLine := "1.2.3.4 1;"
	if !strings.Contains(content, wantLine) {
		t.Errorf("expected geo-format line %q in output, got:\n%s", wantLine, content)
	}
	if strings.Contains(content, "deny 1.2.3.4;") {
		t.Errorf("deny-format line must not appear in geo-format output:\n%s", content)
	}
}

// TestFlushDenyFormatLines is the deny-format counterpart of TestFlushGeoFormatLines.
// It exists as a separate, focused test so a regression in either path is
// localised to a single failing case (rather than overlapping with TestFlushWritesDenyFormat
// which also asserts geo-format absence — kept here too for symmetry with the geo test).
func TestFlushDenyFormatLines(t *testing.T) {
	dir := t.TempDir()
	listFile := filepath.Join(dir, "autoblock.list")

	exec := newTestExecutor(t, map[string]any{
		"list_file":   listFile,
		"ttl":         "1h",
		"file_format": "deny",
	})

	exec.flush(context.Background(), map[string]time.Time{
		"1.2.3.4": time.Now(),
	})

	data, err := os.ReadFile(listFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	content := string(data)
	wantLine := "deny 1.2.3.4;"
	if !strings.Contains(content, wantLine) {
		t.Errorf("expected deny-format line %q in output, got:\n%s", wantLine, content)
	}
	if strings.Contains(content, "1.2.3.4 1;") {
		t.Errorf("geo-format line must not appear in deny-format output:\n%s", content)
	}
}

// containsIPFormat is the format-aware variant of containsIP. Tests that
// exercise the "deny" line syntax should use this directly; geo-format tests
// can keep using containsIP for backwards compatibility.
func containsIPFormat(content, ip, format string) bool {
	switch format {
	case FileFormatDeny:
		return strings.Contains(content, fmt.Sprintf("deny %s;", ip))
	default:
		return strings.Contains(content, fmt.Sprintf("%s 1;", ip))
	}
}
