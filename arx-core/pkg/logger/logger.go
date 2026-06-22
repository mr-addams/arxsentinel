// ========================== Module: pkg/logger =========================================
//   Operational logger contract for the arx-core libraries (Phase 1.2 of the
//   arxsentinel -> arx-core split). This is the single Logger interface that
//   pkg/ packages depend on, instead of importing internal/sys/utils.Log
//   directly. The pkg -> internal dependency was what blocked publishing
//   pkg/ as a standalone library.
//
//   WHAT IS HERE:
//     - Logger interface: a single Log(tag, msg, level string) method
//     - NopLogger implementation (zero-cost no-op) and the shared Nop variable
//     - String level constants that match utils.Log's level vocabulary
//
//   WHAT IS NOT HERE:
//     - No formatting, colors, timestamps, file output — the adapter's job
//     - No arxsentinel-specific vocabulary (no threat / executor / sentinel)
//     - No imports from internal/ — this is the ADR-002 boundary in code
//     - No Logf / LogWithFields — kept minimal on purpose (Simplicity First)

package logger

// Level constants. String values match the canonical level vocabulary documented
// for utils.Log (internal/sys/utils/logging.go line 282: "info" | "warning" |
// "error" | "debug"). Keeping them as plain untyped strings — rather than a
// typed Level — preserves byte-for-byte behaviour when an adapter forwards
// them to utils.Log.
//
// Note: some callers in the wider codebase pass "warn" instead of "warning".
// That is a pre-existing caller inconsistency, not part of utils.Log's
// vocabulary, and is outside the scope of this package.
const (
	LevelDebug   = "debug"
	LevelInfo    = "info"
	LevelWarning = "warning"
	LevelError   = "error"
)

// Logger is the operational logger contract used by pkg/ packages.
//
// Tag is a free-form category string chosen by the caller (the OUTER/INNER tag
// vocabulary lives in internal/sys/utils — this package does not know it).
// Msg is the human-readable body. Level is one of the Level* constants above;
// the implementation decides what to do with it (filtering, coloring, etc.).
type Logger interface {
	Log(tag, msg, level string)
}

// NopLogger is the zero-cost no-op implementation. It is the zero value and
// the safe fallback for callers that pass nil to a constructor: factory
// functions in pkg/ replace nil with Nop rather than calling a global
// utility.Log, which would re-introduce the pkg -> internal dependency we
// are removing (see Flow 072 Decision 2).
type NopLogger struct{}

// Log satisfies the Logger interface and does nothing. The empty body is
// inlined by the compiler; there is no allocation and no observable cost
// in the hot path.
func (NopLogger) Log(string, string, string) {}

// Nop is the conventional shared instance. Use it as the default when a
// caller explicitly declines to inject a real logger (e.g. in unit tests,
// or as the nil-replacement inside pkg/ factory constructors).
var Nop = NopLogger{}
