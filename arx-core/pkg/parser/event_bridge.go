// ========================== pkg/parser — LogEntry ↔ Event bridge ==========================
//   Single conversion point between parser-owned LogEntry and the generic
//   plugin.Event that downstream runtime stages will adopt (Flow 083, Phase 2).
//
//   WHAT IS HERE:
//     - WrapLogEntry   — produces *plugin.Event carrying LogEntry as Payload
//     - UnwrapLogEntry — recovers *LogEntry from *plugin.Event via type assertion
//
//   WHAT IS NOT HERE:
//     - Parsing logic (combined.go, json.go)
//     - Product-specific event construction (ThreatEvent wrappers, scorers)
//
//   DEPENDENCY RULE:
//     pkg/parser → pkg/plugin (Event/Envelope) + stdlib only.
//
//   Why a dedicated bridge file:
//     LogEntry is parser-owned (P2: models live with their owning plugins);
//     Event is the generic transport envelope (P1/P3). Every stage that moves
//     LogEntry across the runtime boundary MUST funnel through Wrap/Unwrap so
//     Payload convention (*LogEntry) is enforced in exactly one place. This
//     keeps the type-assertion contract uniform across source emitters, product
//     detectors, product processors and sinks.
//
//   Envelope ownership (per Phase 2 godoc contract):
//     The caller of WrapLogEntry is responsible for filling the Envelope fields
//     that identify the event transport:
//       - Source     — origin descriptor (e.g. "file:/var/log/app/events.log")
//       - SourceType — origin transport class ("file", "stdin", "http", ...)
//       - Stream     — pipeline stream name (StreamSpec.Name)
//       - Timestamp  — source observation time (NOT construction time)
//     Level MUST be left empty at Wrap time. Level is an opaque severity tag
//     populated later by the product scorer after scoring, so it is the
//     scorer's responsibility to assign event.Envelope.Level on the wrapped
//     Event, never WrapLogEntry's.
//
//   Payload shape:
//     Both Wrap and Unwrap agree on the single canonical form: Payload is
//     always *LogEntry (pointer). Use that form uniformly — storing a value
//     type or a different concrete pointer will fail the Unwrap assertion
//     deliberately (fail-fast, RESOLVED-Q3b).

package parser

import (
	"fmt"

	"github.com/mr-addams/arx-core/pkg/plugin"
)

// WrapLogEntry builds a *plugin.Event that carries the parser-owned LogEntry
// as its opaque Payload, framed by the supplied transport Envelope.
//
// Callers MUST populate the Envelope's Source / SourceType / Stream / Timestamp
// fields (see file-level godoc for ownership rules). Leave Envelope.Level empty;
// the product scorer assigns it later based on scoring outcome.
//
// The returned *plugin.Event is the only sanctioned form for moving LogEntry
// across the runtime boundary; downstream stages that need LogEntry call
// UnwrapLogEntry on it.
func WrapLogEntry(le *LogEntry, env plugin.Envelope) *plugin.Event {
	return &plugin.Event{
		Envelope: env,
		Payload:  le,
	}
}

// UnwrapLogEntry recovers the parser-owned *LogEntry from a *plugin.Event via
// a strict type assertion on Payload. The canonical Payload form is *LogEntry
// (set by WrapLogEntry); any other concrete type or a nil Payload triggers a
// fail-fast panic.
//
// Rationale for panic over error return: the Payload convention is enforced
// at the Wrap site, so a mismatch at Unwrap indicates a programmer error
// (wrong producer, schema drift, or a future refactor that lost the pointer
// form). Hiding it behind an error return would let a miswired pipeline run
// silently and produce empty sinks — fail-fast surfaces the bug at the first
// observation (RESOLVED-Q3b).
func UnwrapLogEntry(ev *plugin.Event) *LogEntry {
	if ev == nil {
		panic("parser.UnwrapLogEntry: nil event")
	}
	if ev.Payload == nil {
		// Separate branch: a nil Payload (e.g. WrapLogEntry called with nil le,
		// or an Event constructed by hand without going through Wrap) is
		// distinct from a wrong-type Payload. Reporting it as a type mismatch
		// misleads debugging — surface the real cause directly.
		panic("parser.UnwrapLogEntry: payload is nil, expected *parser.LogEntry")
	}
	le, ok := ev.Payload.(*LogEntry)
	if !ok {
		panic(fmt.Sprintf("parser.UnwrapLogEntry: payload is %T, expected *parser.LogEntry", ev.Payload))
	}
	return le
}
