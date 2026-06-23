// ========================== pkg/plugin — Envelope transport metadata ======================
//   Envelope carries the transport-level metadata that the runtime engine is
//   allowed to inspect for routing, observability and metrics (per Flow 083
//   principle P1: "engine owns only what it processes"). It deliberately does
//   NOT carry plugin-owned data (scoring output, parser output, etc.) — those
//   live in the plugin-owned opaque Payload, never on Envelope.
//
//   WHAT IS HERE:
//     - Envelope — value struct of transport metadata (Timestamp/Stream/Source/
//       SourceType/Level)
//     - NewEnvelope — constructor that timestamps the envelope at creation
//
//   WHAT IS NOT HERE:
//     - Event {Envelope; Payload any} — lives in event.go
//     - Product-specific event fields (score, modules, reason) — out of scope
//
//   DEPENDENCY RULE:
//     pkg/plugin → stdlib only.

package plugin

import "time"

// Envelope carries transport metadata for a single event flowing through the
// pipeline. The runtime reads Envelope fields to emit observability signals
// (metric axis labels, per-event counters) and to make routing decisions along
// the pipeline. Product-shaped data must never appear on Envelope — place it
// in the plugin-owned Payload instead (see Event in event.go).
//
// Envelope is a value type: copy on every read, no internal synchronization,
// safe for concurrent access by virtue of being immutable-by-convention after
// construction.
type Envelope struct {
	// Timestamp is the wall-clock time of the source observation, not the time
	// of envelope construction. Sources populate it from the underlying log
	// record (e.g. LogEntry.Time); downstream stages preserve it verbatim.
	Timestamp time.Time

	// Stream is the pipeline stream name (StreamSpec.Name). Set once by the
	// engine from the static EventContext at pipeline start; downstream
	// processors and sinks treat it as read-only.
	Stream string

	// Source identifies the origin of the event — e.g. "file:/var/log/app/events.log",
	// "stdin", "http:0.0.0.0:8080". Set by the engine from EventContext.SourceName.
	Source string

	// SourceType classifies the origin transport: "file", "stdin", "http",
	// "syslog", "sentinel", etc. Set by the engine from EventContext.SourceType.
	SourceType string

	// Level is an opaque severity tag attached by the source or a downstream
	// processor. The engine treats Level as a string axis label — it does not
	// interpret or require any specific vocabulary. Plugins that gate on Level
	// (e.g. conditional sinks, severity-driven routing) agree on their own
	// tag set; pkg/plugin imposes none.
	Level string
}

// NewEnvelope constructs an Envelope with Timestamp set to the current time.
// Stream, Source, SourceType and Level are populated by the caller (typically
// the engine from EventContext, or the source plugin for early observations).
//
// Use this constructor when a plugin needs to mint a fresh envelope without
// copying every field explicitly. The Timestamp parameter is reserved for
// callers that already hold a source-derived timestamp and want to override
// "now" — pass time.Now() when in doubt.
func NewEnvelope(stream, source, sourceType, level string, ts time.Time) Envelope {
	return Envelope{
		Timestamp:  ts,
		Stream:     stream,
		Source:     source,
		SourceType: sourceType,
		Level:      level,
	}
}
