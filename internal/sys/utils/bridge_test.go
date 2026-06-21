package utils

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mr-addams/arxsentinel/pkg/logger"
)

// ========================== Test AsLogger bridge (Flow 072 Task 1.2.6) ===================
//
// The bridge is a thin pass-through to utils.Log. We verify the delegation contract
// via two angles:
//   1. Type-level: AsLogger() returns a non-nil logger.Logger implementation.
//   2. Behaviour-level: Log() calls land in utils.Log (captured via ConsoleWriter swap,
//      matching the test idiom already established in logging_test.go).

// TestAsLogger_ReturnsNonNilLogger — AsLogger must never return nil; cmd relies on
// unconditional forwarding.
func TestAsLogger_ReturnsNonNilLogger(t *testing.T) {
	l := AsLogger()
	if l == nil {
		t.Fatal("AsLogger returned nil")
	}
}

// TestAsLogger_ImplementsLoggerInterface — compile-time guard: the returned value must
// satisfy pkg/logger.Logger. The `var _ logger.Logger = AsLogger()` style is heavier
// than we need here; the smoke call below exercises the same contract.
func TestAsLogger_ImplementsLoggerInterface(t *testing.T) {
	var l logger.Logger = AsLogger()
	if l == nil {
		t.Fatal("AsLogger does not satisfy pkg/logger.Logger (got nil)")
	}
}

// TestAsLogger_DelegatesToLog — capture ConsoleWriter and confirm that Log() invoked
// through the bridge writes tag and msg into the captured output. This is the
// end-to-end delegation test: bridge.Log → utils.Log → ConsoleWriter.
//
// We use a tag ("TESTBRIDGE") that is not in logColors/debugOnlyTags/quietTags so the
// line is not filtered out (matches the UNKNOWN_TAG pattern in TestLogDoesNotPanic).
func TestAsLogger_DelegatesToLog(t *testing.T) {
	tmpDir := t.TempDir()
	operLog := filepath.Join(tmpDir, "sentinel.log")
	threatLog := filepath.Join(tmpDir, "threats.log")

	Close()

	// Capture console output through the public ConsoleWriter hook. This is the
	// same idiom used in logging_test.go (TestLogDebugTagFiltering,
	// TestLogColorizedOutput) — no private-state reflection needed.
	var bufConsole bytes.Buffer
	oldConsole := ConsoleWriter
	ConsoleWriter = &bufConsole
	defer func() { ConsoleWriter = oldConsole }()

	// Init with debug=true so we are sure TESTBRIDGE passes any quietTags-style
	// filter; TESTBRIDGE is not in any filter map anyway, but be explicit.
	err := Init(true, false, operLog, threatLog)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Close()

	bridge := AsLogger()
	const wantTag = "TESTBRIDGE"
	const wantMsg = "Flow 072 Task 1.2.6 smoke"

	bridge.Log(wantTag, wantMsg, "info")

	out := bufConsole.String()
	if !strings.Contains(out, wantTag) {
		t.Errorf("bridge.Log output missing tag %q; got: %q", wantTag, out)
	}
	if !strings.Contains(out, wantMsg) {
		t.Errorf("bridge.Log output missing message %q; got: %q", wantMsg, out)
	}

	// Second call to verify the bridge value is reusable (not consumed by first call).
	bufConsole.Reset()
	bridge.Log(wantTag, "second call", "warning")
	if !strings.Contains(bufConsole.String(), "second call") {
		t.Errorf("second bridge.Log did not delegate; got: %q", bufConsole.String())
	}
}

// TestAsLogger_DelegatesToOperationalFile — verify the bridge path also reaches the
// operational log file (sentinel.log), not just the console. Log writes to the file
// before colour formatting, and we read it back to confirm tag + msg presence.
func TestAsLogger_DelegatesToOperationalFile(t *testing.T) {
	tmpDir := t.TempDir()
	operLog := filepath.Join(tmpDir, "sentinel.log")

	Close()

	oldConsole := ConsoleWriter
	ConsoleWriter = io.Discard
	defer func() { ConsoleWriter = oldConsole }()

	err := Init(true, false, operLog, "")
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Close()

	bridge := AsLogger()
	const wantTag = "BRIDGEFILE"
	const wantMsg = "file-side delegation"
	bridge.Log(wantTag, wantMsg, "info")

	content, err := os.ReadFile(operLog)
	if err != nil {
		t.Fatalf("read operational log: %v", err)
	}
	contentStr := string(content)
	if !strings.Contains(contentStr, wantTag) {
		t.Errorf("operational log missing tag %q; got: %q", wantTag, contentStr)
	}
	if !strings.Contains(contentStr, wantMsg) {
		t.Errorf("operational log missing message %q; got: %q", wantMsg, contentStr)
	}
}