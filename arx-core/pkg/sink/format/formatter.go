// ========================== pkg/sink/format — formatter.go =============================
//   Formatter interface and concrete wrappers around package-level Format* functions.
//
//   Decision 5 (Revised: 2026-06-22) in DECISIONS.md:
//     ThreatLogger / WarningsWriter are Product-side (stateful file-handling,
//     warnings.go imports internal/core/chaincheck — would break ADR-002 if moved).
//     They remain in internal/core/output.
//
//     The shared, format-only surface moves to pkg/sink/format and is exposed
//     via a minimal Formatter interface — so sinks depend on the interface,
//     not on the concrete package-level functions, enabling future test mocks
//     and alternative serializers without touching sink code (Karpathy:
//     Simplicity First — single-method interface, no state).

package format

import "github.com/mr-addams/arx-core/pkg/plugin"

// Formatter — minimal interface for ThreatEvent serialization.
// Single method on purpose: keeping the interface narrow makes it cheap to
// implement for tests and future formats (csv, syslog, etc.).
type Formatter interface {
	Format(event *plugin.ThreatEvent) ([]byte, error)
}

// FailbanFormatter — wraps FormatFailban (Fail2Ban-compatible line, byte-identical
// to FormatThreatLine in logger.go so existing filters keep matching).
type FailbanFormatter struct{}

func (f *FailbanFormatter) Format(event *plugin.ThreatEvent) ([]byte, error) {
	return []byte(FormatFailban(*event)), nil
}

// JSONFormatter — wraps FormatJSON (D7 envelope).
type JSONFormatter struct{}

func (f *JSONFormatter) Format(event *plugin.ThreatEvent) ([]byte, error) {
	return FormatJSON(*event)
}

// SentinelFormatter — wraps FormatSentinelThreat (sentinel-threat transport).
// Holds StreamName because the underlying function requires it as a parameter;
// constructing the formatter once per sink avoids passing it on every call.
type SentinelFormatter struct {
	StreamName string
}

func (f *SentinelFormatter) Format(event *plugin.ThreatEvent) ([]byte, error) {
	return FormatSentinelThreat(*event, f.StreamName)
}
