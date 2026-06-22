// ========================== pkg/sink/format =============================================
//   ThreatEvent formatting: Fail2Ban line, JSON envelope, sentinel-threat line.
//
//   WHAT IS HERE:
//     - FormatFailban       — formats ThreatEvent as a Fail2Ban-compatible line
//     - FormatJSON          — formats ThreatEvent as a JSON envelope
//     - FormatSentinelThreat — formats ThreatEvent as sentinel-threat transport line
//     - Formatter interface  — minimal serializer surface (Decision 5 in DECISIONS.md)
//
//   WHAT IS NOT HERE:
//     - FileSink, StdoutSink (file.go, stdout.go)
//     - ThreatLogger / WarningsWriter — Product-side, stateful file-handling,
//       live in internal/core/output (logger.go, warnings.go). ADR-002 constraint:
//       warnings.go imports internal/core/chaincheck, so the package cannot move.
//
//   FAIL2BAN FORMAT (byte-compatible with FormatThreatLine in logger.go):
//     2026-04-05T14:33:12Z THREAT 1.2.3.4 score=85 modules=probe,rate reason="..."
//
//   JSON FORMAT (D7 in DECISIONS.md):
//     {"timestamp":"...","level":"THREAT","stream":"frontend","source":"file:/path",
//      "source_type":"file","ip":"1.2.3.4","score":85,"modules":["probe"],
//      "reason":"...","raw_line":"..."(omit when empty)}

package format

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/mr-addams/arx-core/pkg/plugin"
)

// FormatFailban formats a ThreatEvent as a Fail2Ban-compatible log line.
// Byte-identical to FormatThreatLine() in logger.go — Fail2Ban filter must match all formats.
//
// Called from: sink plugins (file.go, stdout.go), pipeline (main.go).
// Non-blocking.
func FormatFailban(e plugin.ThreatEvent) string {
	timestamp := e.Timestamp.UTC().Format(time.RFC3339)
	modulesStr := strings.Join(e.Modules, ",")
	return fmt.Sprintf("%s %s %s score=%d modules=%s reason=%q",
		timestamp, e.Level, e.IP, e.Score, modulesStr, e.Reason)
}

// jsonEnvelope mirrors the JSON structure defined in D7 (DECISIONS.md).
// raw_line is omitted when empty via `omitempty`.
//
// Internal — not in config. Consumer: FormatJSON.
type jsonEnvelope struct {
	Timestamp  string   `json:"timestamp"`             // Internal — RFC3339 timestamp. Consumer: FormatJSON.
	Level      string   `json:"level"`                 // Internal — threat level. Consumer: FormatJSON.
	Stream     string   `json:"stream,omitempty"`      // Internal — stream name. Consumer: FormatJSON.
	Source     string   `json:"source,omitempty"`      // Internal — source path. Consumer: FormatJSON.
	SourceType string   `json:"source_type,omitempty"` // Internal — source type. Consumer: FormatJSON.
	IP         string   `json:"ip"`                    // Internal — IP address. Consumer: FormatJSON.
	Score      int      `json:"score"`                 // Internal — accumulated score. Consumer: FormatJSON.
	Modules    []string `json:"modules"`               // Internal — triggered detector names. Consumer: FormatJSON.
	Reason     string   `json:"reason"`                // Internal — human-readable reason. Consumer: FormatJSON.
	RawLine    string   `json:"raw_line,omitempty"`    // Internal — raw log line for debug. Consumer: FormatJSON.
}

// sentinelThreatLine is the JSON format for sentinel-threat transport.
// Used both by FormatSentinelThreat (output) and SentinelThreatSource (input).
//
// Internal — not in config. Consumer: FormatSentinelThreat, SentinelThreatSource.
type sentinelThreatLine struct {
	TS      string   `json:"ts"`      // Internal — RFC3339 timestamp. Consumer: FormatSentinelThreat.
	IP      string   `json:"ip"`      // Internal — IP address. Consumer: FormatSentinelThreat.
	Score   int      `json:"score"`   // Internal — accumulated score. Consumer: FormatSentinelThreat.
	Level   string   `json:"level"`   // Internal — threat level. Consumer: FormatSentinelThreat.
	Modules []string `json:"modules"` // Internal — triggered detector names. Consumer: FormatSentinelThreat.
	Reason  string   `json:"reason"`  // Internal — human-readable reason. Consumer: FormatSentinelThreat.
	Source  string   `json:"source"`  // Internal — source stream name. Consumer: FormatSentinelThreat.
}

// FormatSentinelThreat marshals a ThreatEvent to a sentinel-threat JSON line.
// Minimal transport format — only fields needed for re-ban.
//
// Called from: sink plugins, pipeline (main.go).
// Non-blocking.
func FormatSentinelThreat(e plugin.ThreatEvent, streamName string) ([]byte, error) {
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

// FormatJSON marshals a ThreatEvent to a JSON envelope (D7).
//
// raw_line is included only when e.RawLine is non-empty — omit it in production
// to avoid leaking raw HTTP data into logs. Include it for debug mode analysis.
func FormatJSON(e plugin.ThreatEvent) ([]byte, error) {
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
