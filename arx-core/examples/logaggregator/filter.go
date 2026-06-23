package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/mr-addams/arx-core/pkg/parser"
	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/mr-addams/arx-core/pkg/runtime"
)

// FilterProcessor is the LineProcessor and LineProcessorFactory for the
// LogAggregator example.
//
// runtime.Run requires the factory value to ALSO satisfy LineProcessor
// (engine.go does a type-assert on entry and fails fast otherwise). One
// type implementing both is the documented contract — we keep them together
// because the filter is stateless: state is unused, Reload is a no-op.
type FilterProcessor struct {
	// minSeverity, when non-empty, drops every record whose Severity is
	// strictly below this tag. Order: DEBUG < INFO < WARN < ERROR.
	// Empty disables the gate.
	minSeverity string

	// substring, when non-empty, drops every record whose Message does not
	// contain this substring. Empty disables the gate.
	substring string
}

// severityRank maps the supported severity tags to a total ordering used by
// the min-severity gate. Unknown tags rank below the lowest known tag so the
// gate defaults to permissive.
var severityRank = map[string]int{
	"DEBUG": 0,
	"INFO":  1,
	"WARN":  2,
	"ERROR": 3,
}

// severityFromStatus derives a severity tag from the HTTP status code.
// 5xx → ERROR, 4xx → WARN, anything else → INFO. This is a coarse,
// product-shaped decision based on HTTP semantics; the example is a
// generic log aggregator and does not classify by request shape.
func severityFromStatus(status int) string {
	switch {
	case status >= 500:
		return "ERROR"
	case status >= 400:
		return "WARN"
	default:
		return "INFO"
	}
}

// Build implements runtime.LineProcessorFactory. The example is stateless,
// so we return nil state — the engine never inspects ProcessorState, only
// passes it through to Process on each call.
func (f *FilterProcessor) Build(streamName, pipeName string, pipeIdx int, shared runtime.SharedResources) (runtime.ProcessorState, error) {
	return nil, nil
}

// Reload implements runtime.LineProcessorFactory. We have no per-pipeline
// state, so reload is a no-op: return the previous state unchanged.
func (f *FilterProcessor) Reload(old runtime.ProcessorState, ctx context.Context) (runtime.ProcessorState, error) {
	return old, nil
}

// Process implements runtime.LineProcessor.
//
// The engine delivers *plugin.Event with Payload set to whatever the source
// produced. The LogAggregator wires the syslog source, which emits a
// parser-owned *parser.LogEntry wrapped by parser.WrapLogEntry. We do a safe
// type-assert (ok=false on a wrong-type payload) and Skip on mismatch so a
// misconfigured pipeline never panics in the example.
func (f *FilterProcessor) Process(ctx context.Context, entry *plugin.Event, state runtime.ProcessorState, evctx runtime.EventContext) runtime.Action {
	if entry == nil {
		return runtime.Action{Skip: true}
	}
	le, ok := entry.Payload.(*parser.LogEntry)
	if !ok {
		// Source emitted an unexpected payload type — drop silently rather
		// than panic. A real product would log this; the example keeps the
		// hot path allocation-free.
		return runtime.Action{Skip: true}
	}

	record := buildRecord(le)

	// Severity gate: drop records whose severity is strictly below the floor.
	if f.minSeverity != "" {
		min, hasMin := severityRank[f.minSeverity]
		got, hasGot := severityRank[record.Severity]
		if hasMin && hasGot && got < min {
			return runtime.Action{Skip: true}
		}
	}

	// Substring gate: drop records whose Message does not contain the needle.
	// case-sensitive on purpose — matches shell-grep ergonomics.
	if f.substring != "" && !strings.Contains(record.Message, f.substring) {
		return runtime.Action{Skip: true}
	}

	// Build the output Event. The engine reads Envelope.Level for metrics
	// and forwards the whole event to every sink. We fill Stream from the
	// static EventContext (the source left it empty by convention) and
	// preserve Source/SourceType/Timestamp from the inbound envelope.
	out := &plugin.Event{
		Envelope: plugin.Envelope{
			Timestamp:  entry.Envelope.Timestamp,
			Stream:     evctx.StreamName,
			Source:     entry.Envelope.Source,
			SourceType: entry.Envelope.SourceType,
			Level:      record.Severity,
		},
		Payload: record,
	}
	return runtime.Action{Payload: out}
}

// buildRecord maps a parser-owned LogEntry to the example's LogRecord.
// Field-by-field copy; severity is derived from Status.
func buildRecord(le *parser.LogEntry) *LogRecord {
	host := le.RealIP
	if host == "" {
		host = le.RemoteAddr
	}
	return &LogRecord{
		Time:       le.Time,
		Host:       host,
		Severity:   severityFromStatus(le.Status),
		Message:    fmt.Sprintf("%s %s %d", le.Method, le.Path, le.Status),
		RemoteAddr: le.RemoteAddr,
		Status:     le.Status,
		Path:       le.Path,
	}
}