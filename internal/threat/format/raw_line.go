// ========================== internal/threat/format/raw_line ================
//
//	RawLineFormatter — Distributed NCS raw-forward wire format (Flow 093).
//
//	WHAT IS HERE:
//	  RawLineFormatter — Formatter impl for a sentinel-threat sink whose
//	  upstream pipeline has PipelineConfig.RawForward: true (see
//	  cmd/arxsentinel/processor_security.go). Serializes the
//	  *parser.LogEntry payload as-is (JSON), no scoring fields — there is
//	  none yet, the remote node's own detector chain produces the verdict.
//
//	WHAT IS NOT HERE:
//	  - The scored-event formatters (FailbanFormatter / JSONFormatter /
//	    SentinelFormatter) — format.go.
//	  - The receiving side's decode (arx-core pkg/source/sentinel, mode:
//	    raw) — this file only produces bytes, it does not consume them.
//
//	WIRE FORMAT:
//	  Plain JSON encoding of *parser.LogEntry's exported fields
//	  (RemoteAddr, Time, Method, Path, Status, ... — see arx-core
//	  pkg/parser/types.go). No envelope wrapper: the receiving
//	  "type: sentinel, mode: raw" source re-derives its own Envelope
//	  (Source/SourceType/Stream/Timestamp) from queue metadata and Time,
//	  exactly as pkg/source/sentinel's default (threat) mode does for the
//	  scored-event path today.
package format

import (
	"encoding/json"
	"fmt"

	"github.com/mr-addams/arx-core/pkg/parser"
	"github.com/mr-addams/arx-core/pkg/plugin"
)

// RawLineFormatter serializes a RawForward pipeline's *parser.LogEntry
// payload as JSON. Stateless — unlike SentinelFormatter it needs no
// StreamName field; the raw LogEntry carries no stream identity of its
// own (that is Envelope's job, reconstructed on the receiving side from
// queue/transport metadata, not embedded in the wire bytes here).
type RawLineFormatter struct{}

// Format implements format.Formatter. Fails fast on a payload type
// mismatch (RESOLVED-Q3b-style, matching formatThreatPayload's
// contract in format.go) — a non-*parser.LogEntry payload reaching a
// raw-line sink means the pipeline is misconfigured (RawForward:false
// but format:raw-line, or vice versa), a wiring bug worth surfacing
// immediately rather than silently emitting malformed bytes.
func (f *RawLineFormatter) Format(ev *plugin.Event) ([]byte, error) {
	if ev == nil {
		return nil, fmt.Errorf("threat/format: raw-line: nil event")
	}
	entry, ok := ev.Payload.(*parser.LogEntry)
	if !ok {
		return nil, fmt.Errorf(
			"threat/format: raw-line: expected payload *parser.LogEntry, got %T (pipeline missing raw_forward: true?)", ev.Payload)
	}
	return json.Marshal(entry)
}
