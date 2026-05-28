// ========================== Module output/format ========================================
//   ThreatEvent formatting: Fail2Ban line and JSON envelope.
//
//   WHAT IS HERE:
//     - FormatFailban — formats ThreatEvent as a Fail2Ban-compatible line
//     - FormatJSON    — formats ThreatEvent as a JSON envelope
//
//   WHAT IS NOT HERE:
//     - FileSink, StdoutSink (file.go, stdout.go)
//     - ThreatLogger backward-compat wrapper (logger.go)
//
//   FAIL2BAN FORMAT (byte-compatible with FormatThreatLine in logger.go):
//     2026-04-05T14:33:12Z THREAT 1.2.3.4 score=85 modules=probe,rate reason="..."
//
//   JSON FORMAT (D7 in DECISIONS.md):
//     {"timestamp":"...","level":"THREAT","stream":"frontend","source":"file:/path",
//      "source_type":"file","ip":"1.2.3.4","score":85,"modules":["probe"],
//      "reason":"...","raw_line":"..."(omit when empty)}

package output

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

// FormatFailban formats a ThreatEvent as a Fail2Ban-compatible log line.
//
// The format is byte-identical to FormatThreatLine() in logger.go and
// LogThreat() in sys/utils — Fail2Ban filter regex must match all three.
// stream and source fields are intentionally omitted — Fail2Ban only needs
// the timestamp, level, and IP.
// Regex in deploy/fail2ban/filter.d/arxsentinel.conf must match this format —
// update the filter in the same commit if the format changes.
func FormatFailban(e plugin.ThreatEvent) string {
	timestamp := e.Timestamp.UTC().Format(time.RFC3339)
	modulesStr := strings.Join(e.Modules, ",")
	return fmt.Sprintf("%s %s %s score=%d modules=%s reason=%q",
		timestamp, e.Level, e.IP, e.Score, modulesStr, e.Reason)
}

// jsonEnvelope mirrors the JSON structure defined in D7 (DECISIONS.md).
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
