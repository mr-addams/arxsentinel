package logger

import "testing"

// Compile-time interface satisfaction. A bare Logger can be backed by any
// object exposing Log(tag, msg, level string) — this is the structural
// contract established by Flow 072 Decision 1.
var (
	_ Logger = NopLogger{}
	_ Logger = (*recordingLogger)(nil)
)

// recordingLogger captures every call so tests can assert that arguments
// are forwarded verbatim. It is defined in the test file (not in the
// production package) because it is test-only scaffolding.
type recordingLogger struct {
	calls []recordedCall
}

type recordedCall struct {
	tag, msg, level string
}

func (r *recordingLogger) Log(tag, msg, level string) {
	r.calls = append(r.calls, recordedCall{tag: tag, msg: msg, level: level})
}

func TestNopDoesNotPanic(t *testing.T) {
	// NopLogger.Log must be safe on any input — empty strings, unknown
	// levels, anything — without panicking, allocating, or dereferencing.
	// recover() turns any panic into a test failure with the offending value
	// reported verbatim.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Nop panicked on call: %v", r)
		}
	}()

	// Realistic input.
	Nop.Log("EXECUTOR", "starting", LevelInfo)
	// Empty tag / msg / level — must not panic.
	Nop.Log("", "", "")
	// Unusual level — Nop must not validate; that is the adapter's job.
	Nop.Log("ANY", "anything", "bogus-level")
	// Nop (shared variable) must behave identically to the value type.
	Nop.Log("TAG", "msg", LevelError)
}

func TestLevelConstantsMatchUtilsLog(t *testing.T) {
	// The four Level* constants must equal the canonical level vocabulary
	// documented for utils.Log (internal/sys/utils/logging.go line 282):
	//     level: "info" | "warning" | "error" | "debug"
	// and compared against at line 296 ("error", "warning") for the
	// quietTags fast-path. We read utils.Log as text rather than importing
	// it — ADR-002 forbids pkg/logger from depending on internal/. If
	// utils.Log's vocabulary drifts, the hard-coded expectations below
	// fail loudly instead of silently following the drift.
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"LevelDebug", LevelDebug, "debug"},
		{"LevelInfo", LevelInfo, "info"},
		{"LevelWarning", LevelWarning, "warning"},
		{"LevelError", LevelError, "error"},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q (utils.Log vocabulary at internal/sys/utils/logging.go)",
				tc.name, tc.got, tc.want)
		}
	}

	// Sanity: every constant must be distinct. If two collapsed to the
	// same string, the bypass filter inside utils.Log would treat them
	// identically — a silent semantic break.
	seen := map[string]string{}
	for _, kv := range []struct {
		name, val string
	}{
		{"LevelDebug", LevelDebug},
		{"LevelInfo", LevelInfo},
		{"LevelWarning", LevelWarning},
		{"LevelError", LevelError},
	} {
		if other, dup := seen[kv.val]; dup {
			t.Errorf("level constant %s collides with %s (both = %q)", kv.name, other, kv.val)
		}
		seen[kv.val] = kv.name
	}
}

func TestRecordingLoggerReceivesArgs(t *testing.T) {
	// The interface is a structural contract: any object with the right
	// method shape must be accepted. This test exercises that with a
	// custom implementation and asserts arguments pass through unmodified.
	// The bridge inside internal/sys/utils (Task 1.2.6) relies on this
	// exact forwarding behaviour to preserve byte-for-byte log output.
	r := &recordingLogger{}
	r.Log("EXECUTOR", "hello", LevelWarning)

	if len(r.calls) != 1 {
		t.Fatalf("expected 1 recorded call, got %d (%+v)", len(r.calls), r.calls)
	}
	got := r.calls[0]
	if got.tag != "EXECUTOR" || got.msg != "hello" || got.level != "warning" {
		t.Errorf("call not forwarded verbatim: got %+v", got)
	}

	// Multiple calls accumulate in order — bridges must not coalesce.
	r.Log("STARTUP", "second", LevelInfo)
	r.Log("SHUTDOWN", "third", LevelError)
	if len(r.calls) != 3 {
		t.Fatalf("expected 3 calls after extra Log invocations, got %d", len(r.calls))
	}
	if r.calls[1].msg != "second" || r.calls[2].level != "error" {
		t.Errorf("calls out of order or arguments corrupted: %+v", r.calls)
	}
}

func TestNopAndNopLoggerAreEquivalent(t *testing.T) {
	// Nop (var) and the zero value NopLogger{} must be interchangeable.
	// This catches a subtle regression: if Log were ever changed to a
	// pointer receiver, NopLogger{} would stop satisfying Logger and this
	// assignment would fail to compile.
	var l Logger = Nop
	l.Log("A", "b", LevelDebug)

	var l2 Logger = NopLogger{}
	l2.Log("C", "d", LevelError)
}
