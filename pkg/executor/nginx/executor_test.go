// ========================== Package nginx — tests ==========================
//   Unit tests for the NginxExecutor: flush, sweep, dedup, min_level filter,
//   state file persistence, reload command execution, and atomic writes.

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

	"github.com/mr-addams/arxsentinel/pkg/executor"
	"github.com/mr-addams/arx-core/pkg/logger"
	"github.com/mr-addams/arx-core/pkg/plugin"
)

// testEventSource is a simple EventSource that delivers pre-defined events.
type testEventSource struct {
	events []plugin.ThreatEvent
	idx    int64
	mu     sync.Mutex
}

func newTestEventSource(events []plugin.ThreatEvent) *testEventSource {
	return &testEventSource{events: events}
}

func (s *testEventSource) Pop(ctx context.Context) (plugin.ThreatEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if int(s.idx) >= len(s.events) {
		<-ctx.Done()
		return plugin.ThreatEvent{}, ctx.Err()
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

	events := newTestEventSource([]plugin.ThreatEvent{
		{IP: "1.2.3.4", Level: "THREAT"},
		{IP: "5.6.7.8", Level: "THREAT"},
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
func containsIP(content, ip string) bool {
	return strings.Contains(content, fmt.Sprintf("%s 1;", ip))
}
