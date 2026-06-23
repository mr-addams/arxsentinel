// ========================== internal/threat/format =====================
//   Product-side ThreatEvent formatters (Flow 083, Gate B).
//
//   WHAT IS HERE:
//     - formatThreatPayload — extract *threat.ThreatEvent from *plugin.Event.Payload
//       in one place, with fail-fast semantics on a wrong payload type.
//     - FormatFailban / FormatJSON / FormatSentinelThreat — concrete serialization
//       helpers, byte-compatible with the previous pkg/sink/format versions (so
//       existing Fail2Ban filters and integration fixtures keep matching).
//     - FailbanFormatter / JSONFormatter / SentinelFormatter — Formatter
//       implementations that core sinks (file / stdout / sentinel) consume
//       through injection at pipeline assembly time.
//
//   WHAT IS NOT HERE:
//     - The Formatter interface itself — that lives in pkg/sink/format (core).
//     - ThreatEvent type — owned by internal/threat (module-root internal/,
//       reachable from pkg/executorplugins/*) since Gate B (Flow 083,
//       Task 3.3, RESOLVED-Q2 product-ownership). The concrete payload
//       lives in this product package, not in arx-core.
//
//   Gate B (Flow 083 / RESOLVED-Z12 / RESOLVED-Q5b):
//     These impls were activated in Gate B after ThreatEvent migrated from
//     arx-core/pkg/plugin to internal/threat. The package-level Format*
//     functions and the Formatter impls below own every byte of
//     product-shaped output (Score / Modules / Reason / RawLine); the
//     Formatter interface in pkg/sink/format stays neutral in core.
//
//   DEPENDENCY RULE:
//     imports only arx-core/pkg/plugin (Event/Envelope) and the local
//     internal/threat package (ThreatEvent). No boundary violations —
//     verified by rg.

package format

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/mr-addams/arx-core/pkg/plugin"

	"github.com/mr-addams/arxsentinel/internal/threat"
)

// formatThreatPayload extracts the *threat.ThreatEvent stored in
// Event.Payload and returns it by value (the wire formats are value-shaped).
//
// Why pointer-form Payload (engine pushes &threat.ThreatEvent{...}): the
// canonical Event.Payload convention is *T (see pkg/plugin/event.go and the
// Phase 2.2 generalised contracts). This is the only place we type-assert
// it — core sinks no longer do so after Gate B.
//
// Why fail-fast on a type mismatch: the Payload convention is enforced by
// the product scorer (the only producer of ThreatEvent). A wrong concrete
// type at this sink boundary is a programming error — surfacing it here
// keeps the failure mode local to the sink rather than producing empty
// output. RESOLVED-Q3b-style "fail fast on mismatch".
func formatThreatPayload(ev *plugin.Event) (threat.ThreatEvent, error) {
	if ev == nil {
		return threat.ThreatEvent{}, fmt.Errorf("threat/format: nil event")
	}
	te, ok := ev.Payload.(*threat.ThreatEvent)
	if !ok {
		return threat.ThreatEvent{}, fmt.Errorf(
			"threat/format: expected payload *threat.ThreatEvent, got %T", ev.Payload)
	}
	return *te, nil
}

// jsonEnvelope mirrors the JSON structure defined in D7 (DECISIONS.md of Flow 081).
// raw_line is omitted when empty via `omitempty`.
type jsonEnvelope struct {
	Timestamp  string   `json:"timestamp"`
	Level      string   `json:"level"`
	Stream     string   `json:"stream,omitempty"`
	Source     string   `json:"source,omitempty"`
	SourceType string   `json:"source_type,omitempty"`
	IP         string   `json:"ip"`
	Score      int      `json:"score"`
	Modules    []string `json:"modules"`
	Reason     string   `json:"reason"`
	RawLine    string   `json:"raw_line,omitempty"`
}

// sentinelThreatLine is the JSON format for sentinel-threat transport.
// Used both by FormatSentinelThreat (output) and the consumer side
// (cmd/arxsentinel/queue_event_source.Pop and arx-core/pkg/source/sentinel).
//
// Wire format: JSON object with the same field names as the Go ThreatEvent
// struct (no json tags needed — encoding/json uses Go field names by
// default, and the consumer decodes back into threat.ThreatEvent with the
// same field names).
type sentinelThreatLine struct {
	TS      string   `json:"ts"`
	IP      string   `json:"ip"`
	Score   int      `json:"score"`
	Level   string   `json:"level"`
	Modules []string `json:"modules"`
	Reason  string   `json:"reason"`
	Source  string   `json:"source"`
}

// FormatFailban formats a ThreatEvent as a Fail2Ban-compatible log line.
// Byte-identical to the previous FormatThreatLine in logger.go — Fail2Ban
// filter must match all formats.
func FormatFailban(e threat.ThreatEvent) string {
	timestamp := e.Timestamp.UTC().Format(time.RFC3339)
	modulesStr := strings.Join(e.Modules, ",")
	return fmt.Sprintf("%s %s %s score=%d modules=%s reason=%q",
		timestamp, e.Level, e.IP, e.Score, modulesStr, e.Reason)
}

// FormatJSON marshals a ThreatEvent to a JSON envelope (D7).
//
// raw_line is included only when e.RawLine is non-empty — omit it in production
// to avoid leaking raw HTTP data into logs. Include it for debug mode analysis.
func FormatJSON(e threat.ThreatEvent) ([]byte, error) {
	env := jsonEnvelope{
		Timestamp:  e.Timestamp.UTC().Format(time.RFC3339),
		Level:      e.Level,
		Stream:     e.Stream,
		Source:     e.Source,
		SourceType: e.SourceType,
		IP:         e.IP,
		Score:      e.Score,
		Modules:    e.Modules,
		Reason:     e.Reason,
		RawLine:    e.RawLine,
	}
	return json.Marshal(env)
}

// FormatSentinelThreat marshals a ThreatEvent to a sentinel-threat JSON line.
// Minimal transport format — only fields needed for re-ban.
func FormatSentinelThreat(e threat.ThreatEvent, streamName string) ([]byte, error) {
	ts := e.Timestamp.UTC().Format(time.RFC3339)
	line := sentinelThreatLine{
		TS:      ts,
		IP:      e.IP,
		Score:   e.Score,
		Level:   e.Level,
		Modules: e.Modules,
		Reason:  e.Reason,
		Source:  streamName,
	}
	return json.Marshal(line)
}

// FailbanFormatter — wraps FormatFailban (Fail2Ban-compatible line).
type FailbanFormatter struct{}

// Format serializes the event payload as a Fail2Ban line.
func (f *FailbanFormatter) Format(ev *plugin.Event) ([]byte, error) {
	te, err := formatThreatPayload(ev)
	if err != nil {
		return nil, err
	}
	return []byte(FormatFailban(te)), nil
}

// JSONFormatter — wraps FormatJSON (D7 envelope).
type JSONFormatter struct{}

// Format serializes the event payload as a JSON envelope.
func (f *JSONFormatter) Format(ev *plugin.Event) ([]byte, error) {
	te, err := formatThreatPayload(ev)
	if err != nil {
		return nil, err
	}
	return FormatJSON(te)
}

// SentinelFormatter — wraps FormatSentinelThreat (sentinel-threat transport).
// Holds StreamName because the underlying function requires it as a parameter;
// constructing the formatter once per sink avoids passing it on every call.
type SentinelFormatter struct {
	StreamName string
}

// Format serializes the event payload as a sentinel-threat JSON line.
func (f *SentinelFormatter) Format(ev *plugin.Event) ([]byte, error) {
	te, err := formatThreatPayload(ev)
	if err != nil {
		return nil, err
	}
	return FormatSentinelThreat(te, f.StreamName)
}