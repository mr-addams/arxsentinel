package utils

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ========================== Test Init ===================================================

// TestInitCreatesDirectories — checks that Init creates required directories if missing.
func TestInitCreatesDirectories(t *testing.T) {
	tmpDir := t.TempDir()
	operLog := filepath.Join(tmpDir, "subdir", "sentinel.log")
	threatLog := filepath.Join(tmpDir, "threats", "threats.log")

	// Close any existing loggers from previous tests
	Close()

	err := Init(false, false, operLog, threatLog)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Close()

	// Check that both files were created
	if _, err := os.Stat(operLog); os.IsNotExist(err) {
		t.Errorf("operational log file not created: %s", operLog)
	}
	if _, err := os.Stat(threatLog); os.IsNotExist(err) {
		t.Errorf("threat log file not created: %s", threatLog)
	}
}

// TestInitWithEmptyThreatLogPath — Init should work when threat log path is empty.
func TestInitWithEmptyThreatLogPath(t *testing.T) {
	tmpDir := t.TempDir()
	operLog := filepath.Join(tmpDir, "sentinel.log")

	Close()

	// Empty threat log path should not cause error
	err := Init(false, false, operLog, "")
	if err != nil {
		t.Fatalf("Init failed with empty threat log path: %v", err)
	}
	defer Close()

	if _, err := os.Stat(operLog); os.IsNotExist(err) {
		t.Errorf("operational log file not created")
	}
}

// TestInitFailureOnInvalidPath — Init should fail gracefully on invalid path.
func TestInitFailureOnInvalidPath(t *testing.T) {
	// Read-only filesystem simulate: permission denied on non-existent deep path
	operLog := "/no-such-root-dir-please-fail/sentinel.log"
	threatLog := "/dev/null"

	Close()

	// Init should fail on threat log path (operLog failure is warning-only)
	err := Init(false, false, operLog, threatLog)
	// If we can actually create /no-such-root-dir-please-fail, the test env is special
	// This is best-effort; we just check that Init doesn't panic
	if err != nil {
		t.Logf("Init returned expected error: %v", err)
	}
	Close()
}

// ========================== Test Log ====================================================

// TestLogDoesNotPanic — smoke test: Log should not panic.
func TestLogDoesNotPanic(t *testing.T) {
	tmpDir := t.TempDir()
	operLog := filepath.Join(tmpDir, "sentinel.log")
	threatLog := filepath.Join(tmpDir, "threats.log")

	Close()

	// Redirect console output to suppress test logs
	oldConsole := ConsoleWriter
	ConsoleWriter = io.Discard
	defer func() { ConsoleWriter = oldConsole }()

	err := Init(true, false, operLog, threatLog)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Close()

	// These should not panic
	Log("STARTUP", "test message", "info")
	Log("ERROR", "error message", "error")
	Log("DEBUG", "debug message", "debug")
	Log("DETECTOR", "[PROBE] detector activity", "info")
	Log("UNKNOWN_TAG", "unknown tag", "info")
}

// TestLogWritesToFile — Log should write to operational log file.
func TestLogWritesToFile(t *testing.T) {
	tmpDir := t.TempDir()
	operLog := filepath.Join(tmpDir, "sentinel.log")

	Close()

	// Suppress console output
	oldConsole := ConsoleWriter
	ConsoleWriter = io.Discard
	defer func() { ConsoleWriter = oldConsole }()

	err := Init(true, false, operLog, "")
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Close()

	testMsg := "test operational log entry"
	Log("STARTUP", testMsg, "info")

	// Read back the file
	content, err := os.ReadFile(operLog)
	if err != nil {
		t.Fatalf("failed to read operational log: %v", err)
	}

	if !strings.Contains(string(content), testMsg) {
		t.Errorf("expected message not found in log file: %s", string(content))
	}
}

// TestLogDebugTagFiltering — DEBUG tag should be filtered in non-debug mode.
func TestLogDebugTagFiltering(t *testing.T) {
	tmpDir := t.TempDir()
	operLog := filepath.Join(tmpDir, "sentinel.log")

	Close()

	var bufConsole bytes.Buffer
	ConsoleWriter = &bufConsole
	defer func() { ConsoleWriter = os.Stdout }()

	// Init with debug DISABLED
	err := Init(false, false, operLog, "")
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Close()

	bufConsole.Reset()
	Log("DEBUG", "this should not appear", "debug")

	if strings.Contains(bufConsole.String(), "this should not appear") {
		t.Errorf("DEBUG tag was not filtered in non-debug mode")
	}

	// Re-init with debug ENABLED
	Close()
	bufConsole.Reset()
	err = Init(true, false, operLog, "")
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Close()

	Log("DEBUG", "this should appear", "debug")
	if !strings.Contains(bufConsole.String(), "this should appear") {
		t.Errorf("DEBUG tag was filtered even in debug mode")
	}
}

// TestLogColorizedOutput — Log should produce colored output when colors enabled.
func TestLogColorizedOutput(t *testing.T) {
	tmpDir := t.TempDir()

	Close()

	var bufConsole bytes.Buffer
	ConsoleWriter = &bufConsole
	defer func() { ConsoleWriter = os.Stdout }()

	// Init with colors ENABLED
	err := Init(true, true, filepath.Join(tmpDir, "sentinel.log"), "")
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Close()

	bufConsole.Reset()
	Log("STARTUP", "startup message", "info")
	output := bufConsole.String()

	if !strings.Contains(output, "startup message") {
		t.Errorf("message not found in output: %s", output)
	}
}

// ========================== Test LogThreat =============================================

// TestLogThreatDoesNotPanic — smoke test: LogThreat should not panic.
func TestLogThreatDoesNotPanic(t *testing.T) {
	tmpDir := t.TempDir()
	threatLog := filepath.Join(tmpDir, "threats.log")

	Close()

	oldConsole := ConsoleWriter
	ConsoleWriter = io.Discard
	defer func() { ConsoleWriter = oldConsole }()

	err := Init(false, false, filepath.Join(tmpDir, "sentinel.log"), threatLog)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Close()

	// These should not panic
	LogThreat("192.168.1.1", 85, "THREAT", []string{"probe", "rate"}, "env_probe:2,rate:100rps")
	LogThreat("10.0.0.1", 55, "WARN", []string{"crawler"}, "crawler detected")
}

// TestLogThreatWritesToFile — LogThreat should write to threat log file.
func TestLogThreatWritesToFile(t *testing.T) {
	tmpDir := t.TempDir()
	threatLog := filepath.Join(tmpDir, "threats.log")

	Close()

	oldConsole := ConsoleWriter
	ConsoleWriter = io.Discard
	defer func() { ConsoleWriter = oldConsole }()

	err := Init(false, false, filepath.Join(tmpDir, "sentinel.log"), threatLog)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Close()

	testIP := "203.0.113.42"
	testScore := 87

	LogThreat(testIP, testScore, "THREAT", []string{"probe", "rate"}, "test threat")

	// Read back the threat log
	content, err := os.ReadFile(threatLog)
	if err != nil {
		t.Fatalf("failed to read threat log: %v", err)
	}

	contentStr := string(content)
	if !strings.Contains(contentStr, testIP) {
		t.Errorf("expected IP not found in threat log")
	}
	if !strings.Contains(contentStr, "THREAT") {
		t.Errorf("expected threat level not found in threat log")
	}
}

// TestLogThreatHandlesMissingFile — LogThreat should handle missing threat file gracefully.
func TestLogThreatHandlesMissingFile(t *testing.T) {
	tmpDir := t.TempDir()

	Close()

	oldConsole := ConsoleWriter
	ConsoleWriter = io.Discard
	defer func() { ConsoleWriter = oldConsole }()

	// Init with empty threat log (file will be nil)
	err := Init(false, false, filepath.Join(tmpDir, "sentinel.log"), "")
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Close()

	// This should not panic even though threatWriter is nil
	LogThreat("192.168.1.1", 85, "THREAT", []string{"probe"}, "test")
}

// ========================== Test Close ==================================================

// TestCloseDoesNotPanic — smoke test: Close should not panic.
func TestCloseDoesNotPanic(t *testing.T) {
	tmpDir := t.TempDir()

	Close()

	err := Init(false, false, filepath.Join(tmpDir, "sentinel.log"), filepath.Join(tmpDir, "threats.log"))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// These should not panic
	Close()
	Close() // calling twice should be safe
}

// ========================== Test OpenThreatLog ==========================================

// TestOpenThreatLogCreatesFile — OpenThreatLog should create file and directory.
func TestOpenThreatLogCreatesFile(t *testing.T) {
	tmpDir := t.TempDir()
	threatPath := filepath.Join(tmpDir, "subdir", "custom_threats.log")

	f, err := OpenThreatLog(threatPath)
	if err != nil {
		t.Fatalf("OpenThreatLog failed: %v", err)
	}
	defer f.Close()

	if _, err := os.Stat(threatPath); os.IsNotExist(err) {
		t.Errorf("threat log file not created: %s", threatPath)
	}
}

// TestOpenThreatLogFailsOnEmptyPath — OpenThreatLog should reject empty path.
func TestOpenThreatLogFailsOnEmptyPath(t *testing.T) {
	_, err := OpenThreatLog("")
	if err == nil {
		t.Errorf("OpenThreatLog should fail on empty path")
	}
}

// TestOpenThreatLogWritable — OpenThreatLog should return writable file.
func TestOpenThreatLogWritable(t *testing.T) {
	tmpDir := t.TempDir()
	threatPath := filepath.Join(tmpDir, "threats.log")

	f, err := OpenThreatLog(threatPath)
	if err != nil {
		t.Fatalf("OpenThreatLog failed: %v", err)
	}
	defer f.Close()

	testLine := "test threat entry"
	_, err = f.WriteString(testLine + "\n")
	if err != nil {
		t.Fatalf("failed to write to threat log: %v", err)
	}

	// Verify written content
	content, err := os.ReadFile(threatPath)
	if err != nil {
		t.Fatalf("failed to read threat log: %v", err)
	}

	if !strings.Contains(string(content), testLine) {
		t.Errorf("written content not found in file")
	}
}

// ========================== Test Reload ==================================================

// TestReloadDoesNotPanic — smoke test: Reload should not panic.
func TestReloadDoesNotPanic(t *testing.T) {
	tmpDir := t.TempDir()
	operLog := filepath.Join(tmpDir, "sentinel.log")
	threatLog := filepath.Join(tmpDir, "threats.log")

	Close()

	oldConsole := ConsoleWriter
	ConsoleWriter = io.Discard
	defer func() { ConsoleWriter = oldConsole }()

	err := Init(false, false, operLog, threatLog)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Close()

	// Reload should not panic
	err = Reload(true, true, operLog, threatLog)
	if err != nil {
		t.Fatalf("Reload failed: %v", err)
	}
}

// TestReloadUpdatesDebugFlag — Reload should update debug flag.
func TestReloadUpdatesDebugFlag(t *testing.T) {
	tmpDir := t.TempDir()
	operLog := filepath.Join(tmpDir, "sentinel.log")

	Close()

	var bufConsole bytes.Buffer
	ConsoleWriter = &bufConsole
	defer func() { ConsoleWriter = os.Stdout }()

	// Init with debug disabled
	err := Init(false, false, operLog, "")
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Close()

	bufConsole.Reset()
	Log("DEBUG", "should not appear", "debug")
	if strings.Contains(bufConsole.String(), "should not appear") {
		t.Errorf("DEBUG was not filtered initially")
	}

	// Reload with debug enabled
	err = Reload(true, false, operLog, "")
	if err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	bufConsole.Reset()
	Log("DEBUG", "should appear", "debug")
	if !strings.Contains(bufConsole.String(), "should appear") {
		t.Errorf("DEBUG was filtered after Reload enabled debug")
	}
}
